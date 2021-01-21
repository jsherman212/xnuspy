# xnuspy

![alt text](https://github.com/jsherman212/xnuspy/blob/master/open1_hook.png)

<sup>Output from the kernel log after compiling and running `example/open1_hook.c`</sup>

xnuspy is a pongoOS module which installs a new system call, `xnuspy_ctl`,
allowing you to hook kernel functions from userspace. It supports iOS 13.x and
14.x on checkra1n 0.12.2 and up. 4K devices are not supported.

Requires `libusb`: `brew install libusb`

# Building
Run `make` in the top level directory. It'll build the loader and the module.
If you want debug output from xnuspy to the kernel log, run `XNUSPY_DEBUG=1 make`.

# Usage
After you've built everything, have checkra1n boot your device to a pongo
shell: `/Applications/checkra1n.app/Contents/MacOS/checkra1n -p`

In the same directory you built the loader and the module, do
`loader/loader module/xnuspy`. After doing that, xnuspy will do its thing and
in a few seconds your device will boot. `loader` will wait a couple more
seconds after issuing `xnuspy-getkernelv` in case SEPROM needs to be exploited.

# Known Issues
Sometimes a couple of my phones would get stuck at "Booting" after checkra1n's KPF
runs. I have yet to figure out what causes this, but if it happens, try again.
Also, if the device hangs after `bootx`, try again. Finally, marking the
compiled `xnuspy_ctl` code as executable on my iPhone X running iOS 13.3.1 is
a bit spotty, but succeeds 100% of the time on my other phones. If you panic
with a kernel instruction fetch abort when you execute your hook program,
try again.

# xnuspy_ctl
xnuspy will patch an `enosys` system call to point to `xnuspy_ctl_tramp`.
This is a small trampoline which marks the compiled `xnuspy_ctl` code as
executable and branches to it. You can find `xnuspy_ctl`'s implementation at
`module/el1/xnuspy_ctl/xnuspy_ctl.c` and examples in the `example` directory.
That directory also contains `xnuspy_ctl.h`, a header which defines constants for
`xnuspy_ctl`. It is meant to be included in all programs which call it.

You can use `sysctlbyname` to figure out which system call was patched:

```
size_t oldlen = sizeof(long);
long SYS_xnuspy_ctl = 0;
sysctlbyname("kern.xnuspy_ctl_callnum", &SYS_xnuspy_ctl, &oldlen, NULL, 0);
```

This system call takes four arguments, `flavor`, `arg1`, `arg2`, and `arg3`.
The flavor can either be `XNUSPY_CHECK_IF_PATCHED`, `XNUSPY_INSTALL_HOOK`,
`XNUSPY_REGISTER_DEATH_CALLBACK`, `XNUSPY_CALL_HOOKME`, or `XNUSPY_CACHE_READ`.
The meaning of the next three arguments depend on the flavor.

## `XNUSPY_CHECK_IF_PATCHED`
This exists so you can check if `xnuspy_ctl` is present. Invoking it with this
flavor will cause it to return `999`. The values of the other arguments are
ignored.

## `XNUSPY_INSTALL_HOOK`
I designed this flavor to match [`MSHookFunction`](http://www.cydiasubstrate.com/api/c/MSHookFunction/)'s API.
`arg1` is the *UNSLID* address of the kernel function you wish to hook. If you
supply a slid address, you will most likely panic. `arg2` is a pointer to your
ABI-compatible replacement function. `arg3` is a pointer for `xnuspy_ctl` to
`copyout` the address of a trampoline that represents the original kernel
function. This can be `NULL` if you don't intend to call the original.

## `XNUSPY_REGISTER_DEATH_CALLBACK`
This flavor allows you to register an optional "death callback", a function xnuspy
will call when your hook program exits. It gives you a chance to clean up anything
you created from your kernel hooks. If you created any kernel threads, you would
tell them to terminate in this function.

Your callback is not invoked asynchronously, so if you block, you're preventing
xnuspy's garbage collection thread from executing.

`arg1` is a pointer to your callback function. The values of the other arguments
are ignored.

## `XNUSPY_CALL_HOOKME`
`hookme` is a small assembly stub which xnuspy exports through the xnuspy cache
for you to hook. Invoking `xnuspy_ctl` with this flavor will cause `hookme` to
get called, providing a way for you to easily gain kernel code execution without
having to hook an actual kernel function.

There are no arguments for this flavor.

## `XNUSPY_CACHE_READ`
This flavor gives you a way to read from the xnuspy cache. It contains many useful
things like `kprintf`, `current_proc`, `kernel_thread_start`, and the kernel slide
so you don't have to find them yourself. For a complete list of cache IDs, check
out `example/xnuspy_ctl.h`. 

`arg1` is one of the cache IDs defined in `xnuspy_ctl.h` and `arg2` is a
pointer for `xnuspy_ctl` to `copyout` the address or value of what you requested.

### Errors
For all flavors except `XNUSPY_CHECK_IF_PATCHED`, `0` is returned on success.
Upon error, `-1` is returned and `errno` is set. `XNUSPY_CHECK_IF_PATCHED`
does not return any errors.

#### Errors Pertaining to `XNUSPY_INSTALL_HOOK`
`errno` is set to...
- `EEXIST` if:
  - A hook already exists for the unslid kernel function denoted by `arg1`.
- `ENOMEM` if:
  - `kalloc_canblock` or `kalloc_external` returned `NULL`.
- `ENOSPC` if:
  - There are no free `xnuspy_tramp` structs, a data structure internal to
xnuspy. This shouldn't happen unless you're hooking hundreds of kernel functions
*at the same time*. If you need more function hooks, check out the section about
limits under "Important Information".
- `EFAULT` if:
  - `current_map()->hdr.vme_start` is not a pointer to the calling processes'
Mach-O header.
- `ENOENT` if:
  - `map_caller_segments` was unable to find `__TEXT` and `__DATA` for the
calling process.
- `EIO` if:
  - `mach_make_memory_entry_64` did not return a memory entry for the entirety
of the calling processes' `__TEXT` and `__DATA` segments.

`errno` also depends on the return value of `vm_map_wire_external`,
`mach_vm_map_external`, `copyin`, `copyout`, and if applicable, the one-time
initialization function. An `errno` of `10000` represents a `kern_return_t`
value that I haven't yet taken into account for (and a message is printed
to the kernel log about it if you compiled with `XNUSPY_DEBUG=1`).

If this flavor returns an error, the target kernel function was not hooked.
If you passed a non-`NULL` pointer for `arg3`, it may or may not have been
initialized. It's unsafe to use if it was.

#### Errors Pertaining to `XNUSPY_REGISTER_DEATH_CALLBACK`
`errno` is set to...
- `ENOENT` if:
  - The calling process hasn't hooked any kernel functions.

If this flavor returns an error, your death callback was not registered.

#### Errors Pertaining to `XNUSPY_CALL_HOOKME`
`errno` is set to...
- `ENOTSUP` if:
  - `hookme` is too far away from the memory containing the `xnuspy_tramp`
structures. This is determined inside of pongoOS, and can only happen if
xnuspy had to fallback to unused code already inside of the kernelcache.
In this case, calling `hookme` would almost certainly cause a kernel panic,
and you'll have to figure out another kernel function to hook.

If this flavor returns an error, `hookme` was not called.

#### Errors Pertaining to `XNUSPY_CACHE_READ`
`errno` is set to...
- `EINVAL` if:
  - The constant denoted by `arg1` does not represent anything in the cache.
  - `arg1` was `KALLOC_EXTERNAL`, but the kernel is iOS 13.x.
  - `arg1` was `KALLOC_CANBLOCK`, but the kernel is iOS 14.x.
  - `arg1` was `KFREE_EXT`, but the kernel is iOS 13.x.
  - `arg1` was `KFREE_ADDR`, but the kernel is iOS 14.x.

`errno` also depends on the return value of `copyout` and if applicable, the
return value of the one-time initialization function.

If this flavor returns an error, the pointer you passed for `arg2` was not
initialized.

# Important Information

### Common Pitfalls
While writing replacement functions, it was easy to forget that I was writing
kernel code. Here's a couple things to keep in mind when you're writing hooks:

- *You cannot execute any userspace code that lives outside your program's
`__TEXT` segment*. You will panic if, for example, you accidentally call `printf`
instead of `kprintf`. You need to re-implement any libc function you wish to call.
You can create function pointers to other kernel functions and call those, though.
- *Many macros commonly used in userspace code are unsafe for the kernel.* For
example, `PAGE_SIZE` expands to `vm_page_size`, not a constant. You need to
disable PAN (on A10+, which I also don't recommend doing) before reading this 
variable or you will panic.
- *Just to be safe, don't compile your hook programs with compiler optimizations.*

Skimming https://developer.apple.com/library/archive/documentation/Darwin/Conceptual/KernelProgramming/style/style.html is also recommended.

### Debugging Kernel Panics
Bugs are inevitable when writing code, so eventually you're going to cause a
kernel panic. A panic doesn't necessarily mean there's a bug with xnuspy, so
before opening an issue, please make sure that you still panic when you do
nothing but call the original function and return its value (if needed). If
you still panic, then it's likely an xnuspy bug (and please open an issue),
but if not, there's something wrong with your replacement.

Since xnuspy does not actually redirect execution to EL0 pages, debugging
a panic isn't as straightforward. Open up `module/el1/xnuspy_ctl/xnuspy_ctl.c`,
and right before the only call to `kwrite_instr` in `xnuspy_install_hook`,
add a call to `IOSleep` for a couple seconds. This is done to make sure there's
enough time before the device panics for logs to propagate. Re-compile xnuspy with
`XNUSPY_DEBUG=1 make -B` and load the module again. After loading the module,
if you haven't already, compile `klog` from `klog/`. Upload it to your device
and do `stdbuf -o0 ./klog | grep shared_mapping_kva`. Run your hook program again
and watch for a line from `klog` that looks like this:

`shared_mapping_kva: dist 0x7af4 uaddr 0x104797af4 umh 0x104790000 kmh 0xfffffff00c90c000`

If you're installing more than one hook, there will be more than one occurrence.
In that case, `dist` and `uaddr` will vary, but `umh` and `kmh` won't. `kmh`
points to the beginning of the kernel's mapping of your program's `__TEXT` segment.
Throw your hook program into your favorite disassembler and rebase it so its Mach-O
header is at the address of `kmh`. For IDA Pro, that's `Edit -> Segments -> Rebase
program...` with `Image base` bubbled. After your device panics and reboots again,
if there are addresses which correspond to the kernel's mapping of your replacement
in the panic log, they will match up with the disassembly. If there are none, then
you probably have some sort of subtle memory corruption inside your replacement.

xnuspy also has no way of knowing if a kernel thread is still executing (or will
execute) on the kernel's mapping of your program's `__TEXT` segment after your
hooks are uninstalled. One of the things xnuspy does to deal with this is to not
deallocate this mapping immediately after your hook program dies. Instead, it's
added to the end of a queue. Once xnuspy's garbage collection thread notices a
set limit has been exceeded regarding how many pages worth of mappings are held
in that queue, it will start to deallocate from the front of the queue and will
continue until that limit is no longer exceeded. By default, this limit is 1 MB,
or 64 pages.

While this does help enormously, the larger the `__TEXT` and `__DATA` segments
of your hook program become, the less likely xnuspy wins this race. If you are
panicking regularly and have a somewhat large hook program, try increasing
this limit by adding `XNUSPY_LEAKED_PAGE_LIMIT=n` before `make`. This will set
this limit to `n` pages rather than 64.

### Limits
xnuspy reserves one page of static kernel memory before XNU boots for its `xnuspy_tramp`
structs, letting you simultaneously hook around 225 kernel functions. If you want
more, you can add `XNUSPY_TRAMP_PAGES=n` before `make`. This will tell xnuspy to
reserve `n` pages of static memory for `xnuspy_tramp` structures. However, if
xnuspy has to fall back to unused code already inside the kernelcache, then this
is ignored. When this happens is detailed in "How It Works".

### Logging
For some reason, logs from `os_log_with_args` don't show up in the stream
outputted from the command line tool `oslog`. Logs from `kprintf` don't
make it there either, but they *can* be seen with `dmesg`. However, `dmesg`
isn't a live feed, so I wrote `klog`, a tool which shows `kprintf` logs
in real time. Find it in `klog/`. I strongly recommend using that instead
of spamming `dmesg` for your `kprintf` messages.

### Hook Uninstallation
xnuspy will manage this for you. Once a process exits, all the kernel hooks
that were installed by that process are uninstalled within a second or so.

### Hookable Kernel Functions
Most function hooking frameworks have some minimum length that makes a given
function hookable. xnuspy has this limit *only* if you plan to call the original
function *and* the first instruction of the hooked function is not `B`. In this
case, the minimum length is eight bytes. Otherwise, there is no minimum length.

xnuspy uses `X16` and `X17` for its trampolines, so kernel functions which
expect those to persist across function calls cannot be hooked (there aren't
many which expect this). If the function you want to hook begins with `BL`,
and you intend to call the original, you can only do so if executing the
original function does not modify `X17`.

### Thread-safety
`xnuspy_ctl` will perform one-time initialization the first time it is called
after a fresh boot. This is the only part of xnuspy which is raceable since
I can't statically initialize the read/write lock I use. After the first call
returns, any future calls are guarenteed to be thread-safe.

# How It Works
This is simplified, but it captures the main idea well. A function hook in xnuspy
is a structure that resides on writeable, executable kernel memory. In most cases,
this is memory returned by `alloc_static` inside of pongoOS. It can be boiled down
to this:


```
struct {
	uint64_t replacement;
	uint32_t tramp[2];
	uint32_t orig[10];
};
```

Where `replacement` is the kernel virtual address (elaborated on later) of the
replacement function, `tramp` is a small trampoline that re-directs execution to
`replacement`, and `orig` is a larger, more complicated trampoline that represents
the original function.

Before a function is hooked, xnuspy creates a shared user-kernel mapping of the
calling processes' `__TEXT` and `__DATA` segments (as well as any segment in
between those, if any). `__TEXT` is shared so you can call other functions from
your hooks. `__DATA` is shared so changes to global variables are seen by both
EL1 and EL0. This is done only once per process.

Since this mapping is a one-to-one copy of `__TEXT` and `__DATA`, it's easy to
figure out the address of the user's replacement function on it. Given the address of
the calling processes' Mach-O header `u`, the address of the start of the
shared mapping `k`, and the address of the user's replacement function `r`, we
apply the following formula: `replacement = k + (r - u)`

After that, `replacement` is the kernel virtual address of the user's replacement
function on the shared mapping and is written to the function hook structure.
xnuspy does not re-direct execution to the EL0 address of the replacement
function because that's extremely unsafe: not only does that put us at the
mercy of the scheduler, it gives us no control over the scenario where a process
with a kernel hook dies while a kernel thread is still executing on the
replacement.

Finally, the shared mapping is marked as executable and a unconditional
immediate branch (`B`) is assembled. It directs execution to the start of `tramp`,
and is what replaces the first instruction of the now-hooked kernel function.
Unfortunately, this limits us from branching to hook structures more than 128 MB away
from a given kernel function. xnuspy does check for this scenario before booting
and falls back to unused code already in the kernelcache for the hook structures
to reside on instead if it finds that this could happen.

# Device Security
This module completely neuters KTRR/AMCC lockdown and KPP. I don't
recommend using this on a daily driver.

# Other Notes
I do my best to make sure the patchfinders work, so if something isn't working
please open an issue.

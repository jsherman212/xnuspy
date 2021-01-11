# xnuspy

xnuspy is a pongoOS module which installs a new system call, `xnuspy_ctl`,
allowing you to hook kernel functions from userspace. It supports iOS 13.x and
14.x on checkra1n 0.12.2 and up.

Requires `libusb`: `brew install libusb`

# Building
Run `make` in the top level directory. It'll build the loader and the module.
If you want debug output from xnuspy to the kernel log, run`XNUSPY_DEBUG=1 make`.

# Usage
After you've built everything, have checkra1n boot your device to a pongo
shell: `/Applications/checkra1n.app/Contents/MacOS/checkra1n -p`

In the same directory you built the loader and the module, do
`loader/loader module/xnuspy`. After doing that, xnuspy will do its thing and
in a few seconds your device will boot. `loader` will wait a couple more
seconds after issuing `xnuspy-getkernelv` in case SEPROM needs to be exploited.

# xnuspy_ctl
xnuspy will patch the first `enosys` system call to point to `xnuspy_ctl_tramp`.
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
The flavor can either be `XNUSPY_CHECK_IF_PATCHED`, `XNUSPY_INSTALL_HOOK` or
`XNUSPY_CACHE_READ`. The meaning of the next three arguments depend on the
flavor.

## `XNUSPY_CHECK_IF_PATCHED`
This exists so you can check if `xnuspy_ctl` is present. Invoking it with this
flavor will cause it to return `999`. The values of the other arguments are
ignored.

## `XNUSPY_INSTALL_HOOK`
I designed this flavor to match `MSHookFunction`'s API. `arg1` is the *UNSLID*
address of the kernel function you wish to hook. If you supply a slid address,
you will most likely panic. `arg2` is a pointer to your ABI-compatible replacement
function. `arg3` is a pointer for `xnuspy_ctl` to `copyout` the address of a
trampoline that represents the original kernel function. This can be NULL if
you don't intend to call the original.

## `XNUSPY_CACHE_READ`
`arg1` is one of the constants defined in `xnuspy_ctl.h` and `arg2` is a
pointer for `xnuspy_ctl` to `copyout` the address or value of what you requested.
The cache contains many useful things like `kprintf`, `current_proc`, and the
kernel slide so you don't have to look for them yourself.

For `XNUSPY_INSTALL_HOOK` and `XNUSPY_CACHE_READ`, `0` is returned on success.

### Errors
Upon error, `-1` is returned and `errno` is set. `XNUSPY_CHECK_IF_PATCHED`
does not return any errors.

#### Errors Pertaining to `XNUSPY_INSTALL_HOOK`
`errno` is set to...
- `EEXIST` if:
  - A hook already exists for the unslid kernel function denoted by `arg1`.
- `ENOMEM` if:
  - `kalloc_canblock` or `kalloc_external` returned `NULL`.
- `ENOSPC` if:
  - There are no free `xnuspy_tramp` structs or reflector pages. These data
structures are internal to xnuspy. This should never happen unless you are
hooking hundreds of kernel functions at the same time.
- `ENOENT` if:
  - `map_caller_segments` was unable to find `__TEXT` and `__DATA` for the
calling process.
- `EIO` if:
  - `mach_make_memory_entry_64` did not return a memory entry for the entirety
of the calling processes' `__TEXT` and `__DATA` segments.

`errno` also depends on the return value of `vm_map_wire_external`,
`vm_map_unwire`, `vm_deallocate`, `mach_make_memory_entry_64`,
`mach_vm_map_external`, `copyin`, `copyout`, and if applicable, the one-time
initialization function. An `errno` of `10000` represents a `kern_return_t`
value that I haven't yet taken into account for.

If this flavor returns an error, the target kernel function was not hooked.
If you passed a non-NULL pointer for `arg3`, it may or may not have been
initialized. It's unsafe to use if it was.

#### Errors Pertaining to `XNUSPY_CACHE_READ`
`errno` is set to...
- `EINVAL` if:
  - The constant denoted by `arg1` does not represent anything in the cache.

`errno` also depends on the return value of `copyout` and if applicable, the
return value of the one-time initialization function.

If this flavor returns an error, the pointer you passed for `arg2` was not
initialized.

# Important Information

### Common Pitfalls
While writing replacement functions, it was easy to forget that I was writing
kernel code. Here's a couple things to keep in mind when you're writing hooks:

- *You cannot execute any code that lives outside your program's `__TEXT`
segment*. You will panic if, for example, you accidentally call `printf`
instead of `kprintf`. You need to re-implement any libc function you wish to call.
- *Many macros commonly used in userspace code are unsafe for the kernel.* For
example, `PAGE_SIZE` expands to `vm_page_size`, not a constant. You need to
disable PAN (on A10+, which I also don't recommend doing) before reading this 
variable or you will panic.

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
add a call to `IOSleep` for a couple seconds. Re-compile xnuspy with
`XNUSPY_DEBUG=1 make -B` and load the module again. After loading the module,
if you haven't already, compile `klog` from `tools/`. Upload it to your device
and do `stdbuf -o0 ./klog | grep find_replacement_kva`. Run your hook program again
and watch for a line from `klog` that looks like this:

`find_replacement_kva: dist 0x780c replacement 0x100cd780c umh 0x100cd0000 kmh 0xfffffff0311c0000`.

If you're installing more than one hook, there will be more than one occurrence.
In that case, `dist` and `replacement` will vary, but `umh` and `kmh` won't.
Throw your hook program into your favorite disassembler and rebase it so its Mach-O
header is at the address of `kmh`. For IDA Pro, that's `Edit -> Segments -> Rebase
program...` with `Image base` bubbled. After your device panics and reboots again,
if there are addresses which correspond to the kernel's mapping of your replacement
in the panic log, they will match up with the disassembly. If there are none, then
you probably have some sort of subtle memory corruption inside your replacement.

### Hook Uninstallation
xnuspy will manage this for you. Once a process exits, all the kernel hooks
that were installed by that process are uninstalled within a second or so.

### Hookable Kernel Functions
Most function hooking frameworks have some minimum length that makes a given
function hookable. xnuspy has this limit *only* if you plan to call the original
function. In this case, the minimum length is eight bytes. Otherwise, there
is no minimum length.

Additionally, xnuspy uses `X16` and `X17` for its trampolines, so kernel functions
which expect those to persist across function calls cannot be hooked.

### Thread-safety
`xnuspy_ctl` will perform one-time initialization the first time it is called
after a fresh boot. This is the only part of xnuspy which is raceable since
I can't statically initialize the read/write lock I use. After the first call
returns, any future calls are guarenteed to be thread-safe.

# How It Works
This is simplified, but it captures the main idea well. Check out `xnuspy_ctl`'s
source code for more information.

In order to hook a kernel function, xnuspy will generate a small trampoline to
jump to its replacement. After, it will create a shared user-kernel mapping of
the calling processes' `__TEXT` and `__DATA` segments. `__TEXT` is shared so
you can call other functions from your hooks. `__DATA` is shared so changes to
global variables are seen by both EL1 and EL0. This is done only once per
process. The kernel virtual address of the replacement function on this mapping
is figured out and is saved right before the address of the replacement
trampoline. Finally, an unconditional immediate branch from the kernel
function to the replacement trampoline is assembled and is what replaces the
first instruction of that function.

# Device Security
This module completely neuters KTRR/AMCC lockdown and KPP. I don't
recommend using this on a daily driver.

# Other Notes
I do my best to make sure the patchfinders work, so if something isn't working
please open an issue.

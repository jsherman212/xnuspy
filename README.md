# xnuspy

xnuspy is a pongoOS module which installs a new system call, `xnuspy_ctl`,
allowing you to hook kernel functions from userspace. It supports iOS 13.x and
14.x on checkra1n 0.11.0 and up. Devices with a 4K page size are not
supported because I don't have any that boot.

Requires `libusb`: `brew install libusb`

Requires `perl`: `brew install perl`

# Building
Run `make` in the top level directory. It'll build the loader and the module.

# Usage
After you've built everything, have checkra1n boot your device to a pongo
shell: `/Applications/checkra1n.app/Contents/MacOS/checkra1n -p`

In the same directory you built the loader and the module, do
`loader/loader module/xnuspy`. xnuspy will run its patchfinders and install
`xnuspy_ctl` and in a few seconds your device will boot. `loader` will wait a
couple more seconds after issuing `xnuspy-getkernelv` in case SEPROM needs
to be exploited.

# xnuspy_ctl
`xnuspy` will patch the first `enosys` system call to point to `xnuspy_ctl`.
You can find its implementation at `module/el1/xnuspy_ctl/xnuspy_ctl.c` and
examples in the `example` directory. That directory also contains
`xnuspy_ctl.h`. This header defines constants for `xnuspy_ctl` and is meant
to be included in all programs which call it.

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
trampoline that represents the original kernel function. This can be NULL if you don't intend to call the original.

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

`errno` also depends on the return value of `vm_map_wire_kernel`,
`vm_map_unwire`, `vm_deallocate`, `mach_make_memory_entry_64`,
`mach_vm_map_external`, and `copyout`. An `errno` of `10000` represents a
`kern_return_t` value that I haven't yet taken into account for.

If this flavor returns an error, the target kernel function was not hooked.
The pointer you passed for `arg3` may or may not have been initialized, but if
it was, it's unsafe to use.

#### Errors Pertaining to `XNUSPY_CACHE_READ`
`errno` is set to...
- `EINVAL` if:
  - The constant denoted by `arg1` does not represent anything in the cache.

`errno` also depends on the return value of `copyout`.

If this flavor returns an error, the pointer you passed for `arg2` was not
initialized.

# Debugging Panics
When you write your replacement function, you are writing kernel code. You
will panic if you cause any sort of memory corruption, dereference a bad
pointer, etc. You need to make sure the functions you call/pointers you
dereference from your replacement can be done safely in the context of your
hooked function (do I need to take a lock before doing something with some
object? should I really be calling `kprintf` inside of a `kalloc` hook?).
You cannot execute any user code that lives outside of your program's `__TEXT`
segment from your replacement. Many macros that are safe for userspace are
unsafe for your replacement. Macros like `PAGE_SIZE` actually evaluate to a
stub when I compile with clang. If you do panic, it may not be a bug with
xnuspy. Before opening an issue, please make sure that you still panic when
you do nothing but call the original function and return its value (if needed).
If you still panic, then it's most likely a bug with xnuspy. If you don't panic,
then there's a bug in your replacement code. In this case, I recommend double
checking your replacement code and throwing the binary inside your favorite
disassembler to figure out how clang compiled it.

# Important Information
### Hook Uninstallation
xnuspy will manage this for you. Once a process exits, all the kernel hooks
that were installed by that process are uninstalled within a couple seconds of
exiting.

### Hookable Kernel Functions
Most function hooking frameworks have some minimum length that makes a given
function hookable. xnuspy has this limit *only* if you plan to call the original
function. In this case, the minimum length is eight bytes. Otherwise, there
is no minimum length.

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
is figured out and is saved right before the replacement trampoline. Finally,
an unconditional immediate branch from the kernel function to the replacement
trampoline is assembled and is what replaces the first instruction of that
function.

# Device Security
This module completely neuters KTRR/AMCC lockdown and KPP. I don't
recommend using this on a daily driver.

# Other Notes
I do my best to make sure the patchfinders work, so if something isn't working
please open an issue.

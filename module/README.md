Directory structure:

common/
- miscellaneous functions and headers

el1/
- kernel code

el3/
- KPP patchfinder/patches for A9 and below

pf/
- patchfinder code for the kernel

preboot_hook.c
- patches the first `_enosys` sysent to point to the code in
`el1/xnuspy_ctl_tramp.s`

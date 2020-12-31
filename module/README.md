Directory structure:

common/
- miscellaneous functions and headers

el1/
- kernel code

pf/
- patchfinder code

preboot_hook.c
- patches the first `_enosys` sysent to point to the code in
`el1/xnuspy_ctl_tramp.s`

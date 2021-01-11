Directory structure:

common/
- miscellaneous functions and headers

el1/
- kernel code

el3/
- KPP patchfinder for A9 and its variants

pf/
- patchfinder code for the kernel

preboot_hook.c
- sets everything up for xnuspy_ctl and installs it

xnuspy.c
- gets kernel version, either exploits SEPROM, patches KPP, or neither, and
launches xnuspy's patchfinders

Directory structure:

13/
- patchfinder code for iOS 13.x

14/
- patchfinder code for iOS 14.x

disas.c
- contrary to the file name, assembler and disassembler

macho.c
- functions to work with Mach-O files

offsets.h
- offsets needed for the xnuspy cache and the C part of the kernel code

pf_common.h
- definition for `struct pf` and macros related to its initialization

pfs.h
- array of `pf` structs which represent xnuspy's patchfinders

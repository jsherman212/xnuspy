OBJECT_FILES = debug.o libc.o mem.o pte.o tramp.o

ASM_DEP = ../../common/asm.o
EXTERNAL_DEPS = externs.h ../../common/xnuspy_structs.h

CFLAGS += -mkernel -Wswitch-enum

ifeq ($(XNUSPY_DEBUG), 1)
	CFLAGS += -DXNUSPY_DEBUG
endif

ifneq ($(XNUSPY_LEAKED_PAGE_LIMIT), )
	CFLAGS += -DXNUSPY_LEAKED_PAGE_LIMIT=$(XNUSPY_LEAKED_PAGE_LIMIT)
endif

LDFLAGS = -Xlinker -kext 

all : $(OBJECT_FILES) xnuspy_ctl

# %.o will match all object files, so in case someone's clang decides to
# leave a leftover xnuspy_ctl.o I do it like this
debug.o : debug.c debug.h $(EXTERNAL_DEPS)
	$(CC) $(CFLAGS) debug.c -c

libc.o : libc.c libc.h $(EXTERNAL_DEPS)
	$(CC) $(CFLAGS) libc.c -c

mem.o : mem.c mem.h $(EXTERNAL_DEPS)
	$(CC) $(CFLAGS) mem.c -c

pte.o : pte.c pte.h $(EXTERNAL_DEPS)
	$(CC) $(CFLAGS) pte.c -c

tramp.o : tramp.c tramp.h $(ASM_DEP) $(EXTERNAL_DEPS)
	$(CC) $(CFLAGS) tramp.c -c

xnuspy_ctl : $(OBJECT_FILES) $(ASM_DEP) $(EXTERNAL_DEPS) xnuspy_ctl.c
	$(CC) $(CFLAGS) $(LDFLAGS) $(OBJECT_FILES) $(ASM_DEP) xnuspy_ctl.c \
		-o xnuspy_ctl

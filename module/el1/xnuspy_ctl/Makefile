OBJECT_FILES = debug.o libc.o mem.o pte.o tramp.o utils.o wrappers.o

ASM_DEP = ../../common/asm.o
EXTERNAL_DEPS = $(RP)/include/xnuspy/el1/externs.h \
				$(RP)/include/xnuspy/xnuspy_ctl.h \
				$(RP)/include/xnuspy/xnuspy_structs.h

CFLAGS += -mkernel -Wswitch-enum

ifeq ($(XNUSPY_DEBUG), 1)
	CFLAGS += -DXNUSPY_DEBUG
endif

ifeq ($(XNUSPY_SERIAL), 1)
	CFLAGS += -DXNUSPY_SERIAL
endif

ifneq ($(XNUSPY_LEAKED_PAGE_LIMIT), )
	CFLAGS += -DXNUSPY_LEAKED_PAGE_LIMIT=$(XNUSPY_LEAKED_PAGE_LIMIT)
endif

LDFLAGS = -Xlinker -kext 

all : $(OBJECT_FILES) xnuspy_ctl

# %.o will match all object files, so in case someone's clang decides to
# leave a leftover xnuspy_ctl.o I do it like this
debug.o : debug.c $(RP)/include/xnuspy/el1/debug.h $(EXTERNAL_DEPS)
	$(CC) $(CFLAGS) debug.c -c

libc.o : libc.c $(RP)/include/xnuspy/el1/libc.h $(EXTERNAL_DEPS)
	$(CC) $(CFLAGS) libc.c -c

mem.o : mem.c $(RP)/include/xnuspy/el1/mem.h $(EXTERNAL_DEPS)
	$(CC) $(CFLAGS) mem.c -c

pte.o : pte.c $(RP)/include/xnuspy/el1/pte.h $(EXTERNAL_DEPS)
	$(CC) $(CFLAGS) pte.c -c

tramp.o : tramp.c $(RP)/include/xnuspy/el1/tramp.h $(ASM_DEP) $(EXTERNAL_DEPS)
	$(CC) $(CFLAGS) tramp.c -c

utils.o : utils.c $(RP)/include/xnuspy/el1/utils.h $(EXTERNAL_DEPS)
	$(CC) $(CFLAGS) utils.c -c

wrappers.o : wrappers.c $(RP)/include/xnuspy/el1/wrappers.h $(EXTERNAL_DEPS)
	$(CC) $(CFLAGS) wrappers.c -c

xnuspy_ctl : $(OBJECT_FILES) $(ASM_DEP) $(EXTERNAL_DEPS) xnuspy_ctl.c
	$(CC) $(CFLAGS) $(LDFLAGS) $(OBJECT_FILES) $(ASM_DEP) xnuspy_ctl.c \
		-o xnuspy_ctl

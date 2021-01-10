CFLAGS += -mkernel

ifeq ($(XNUSPY_DEBUG), 1)
	CFLAGS += -DXNUSPY_DEBUG
endif

LDFLAGS = -Xlinker -kext

all : asm.o debug.o mem.o pte.o tramp.o xnuspy_ctl

asm.o : asm.c asm.h externs.h
	$(CC) $(CFLAGS) asm.c -c

debug.o : debug.c debug.h externs.h
	$(CC) $(CFLAGS) debug.c -c

mem.o : mem.c mem.h externs.h
	$(CC) $(CFLAGS) mem.c -c

pte.o : pte.c pte.h externs.h
	$(CC) $(CFLAGS) pte.c -c

tramp.o : tramp.c tramp.h externs.h
	$(CC) $(CFLAGS) tramp.c -c

xnuspy_ctl : xnuspy_ctl.c asm.o debug.o mem.o pte.o tramp.o externs.h \
	../../common/xnuspy_structs.h
	$(CC) $(CFLAGS) $(LDFLAGS) asm.o debug.o mem.o pte.o tramp.o xnuspy_ctl.c -o xnuspy_ctl

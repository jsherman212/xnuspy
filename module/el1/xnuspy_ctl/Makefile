CFLAGS += -mkernel# -Os
LDFLAGS = -Xlinker -kext

# XXX compress later

all : asm.o mem.o pte.o xnuspy_ctl

asm.o : asm.c asm.h externs.h
	$(CC) $(CFLAGS) asm.c -c

mem.o : mem.c mem.h externs.h
	$(CC) $(CFLAGS) mem.c -c

pte.o : pte.c pte.h externs.h
	$(CC) $(CFLAGS) pte.c -c

xnuspy_ctl : xnuspy_ctl.c asm.o mem.o pte.o externs.h
	$(CC) $(CFLAGS) $(LDFLAGS) asm.o mem.o pte.o xnuspy_ctl.c -o xnuspy_ctl

CFLAGS += -mkernel# -Os
LDFLAGS = -Xlinker -kext

# XXX compress later

all : mem.o pte.o xnuspy_ctl

mem.o : mem.c mem.h externs.h
	$(CC) $(CFLAGS) mem.c -c

pte.o : pte.c pte.h externs.h
	$(CC) $(CFLAGS) pte.c -c

xnuspy_ctl : xnuspy_ctl.c mem.o pte.o externs.h
	$(CC) $(CFLAGS) $(LDFLAGS) mem.o pte.o xnuspy_ctl.c -o xnuspy_ctl

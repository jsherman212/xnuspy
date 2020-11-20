CFLAGS += -mkernel
LDFLAGS = -Xlinker -kext

# XXX compress later

all : mem.o pte.o xnuspy_ctl

mem.o : mem.c mem.h
	$(CC) $(CFLAGS) mem.c -c

pte.o : pte.c pte.h
	$(CC) $(CFLAGS) pte.c -c

xnuspy_ctl : xnuspy_ctl.c mem.o pte.o common.h
	$(CC) $(CFLAGS) $(LDFLAGS) mem.o pte.o xnuspy_ctl.c -o xnuspy_ctl

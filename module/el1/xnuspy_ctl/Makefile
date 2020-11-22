CFLAGS += -mkernel# -Os
LDFLAGS = -Xlinker -kext

# XXX compress later

all : mem.o hwbp.o pte.o xnuspy_ctl

mem.o : mem.c mem.h externs.h
	$(CC) $(CFLAGS) mem.c -c

hwbp.o : hwbp.c hwbp.h
	$(CC) $(CFLAGS) hwbp.c -c

pte.o : pte.c pte.h externs.h
	$(CC) $(CFLAGS) pte.c -c

xnuspy_ctl : xnuspy_ctl.c mem.o hwbp.o pte.o externs.h
	$(CC) $(CFLAGS) $(LDFLAGS) mem.o hwbp.o pte.o xnuspy_ctl.c -o xnuspy_ctl

CFLAGS += -mkernel
LDFLAGS = -Xlinker -kext

xnuspy_ctl : xnuspy_ctl.c common.h
	$(CC) $(CFLAGS) $(LDFLAGS) xnuspy_ctl.c -o xnuspy_ctl

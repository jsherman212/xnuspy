SDK = $(shell xcrun --sdk iphoneos --show-sdk-path)
CC = $(shell xcrun --sdk $(SDK) --find clang)
CFLAGS = -isysroot $(SDK) -arch arm64 -fno-stack-protector -D_FORTIFY_SOURCE=0
CFLAGS += -Wno-deprecated-declarations

# If user invokes make in this directory, $(RP) will not be defined
ifndef RP
	CFLAGS += -I../include
else
	CFLAGS += -I$(RP)/include
endif

XNUSPY_HEADER = ../include/xnuspy/xnuspy_ctl.h

all : open1_hook user_client_monitor kernel_thread kaddr_of_port shmem

.PHONY : upload

upload : open1_hook user_client_monitor kernel_thread kaddr_of_port shmem
	rsync -sz -e 'ssh -p 2222' open1_hook root@localhost:/var/root
	rsync -sz -e 'ssh -p 2222' user_client_monitor root@localhost:/var/root
	rsync -sz -e 'ssh -p 2222' kernel_thread root@localhost:/var/root
	rsync -sz -e 'ssh -p 2222' kaddr_of_port root@localhost:/var/root
	rsync -sz -e 'ssh -p 2222' shmem root@localhost:/var/root

open1_hook : open1_hook.c $(XNUSPY_HEADER)
	$(CC) $(CFLAGS) open1_hook.c -o open1_hook
	ldid -S../ent.xml ./open1_hook

user_client_monitor : user_client_monitor.c $(XNUSPY_HEADER)
	$(CC) $(CFLAGS) user_client_monitor.c -o user_client_monitor
	ldid -S../ent.xml ./user_client_monitor

kernel_thread : kernel_thread.c $(XNUSPY_HEADER)
	$(CC) $(CFLAGS) kernel_thread.c -o kernel_thread
	ldid -S../ent.xml ./kernel_thread

kaddr_of_port : kaddr_of_port.c $(XNUSPY_HEADER)
	$(CC) $(CFLAGS) kaddr_of_port.c -o kaddr_of_port
	ldid -S../ent.xml ./kaddr_of_port

shmem : shmem.c $(XNUSPY_HEADER)
	$(CC) $(CFLAGS) shmem.c -o shmem
	ldid -S../ent.xml ./shmem

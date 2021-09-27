SDK = $(shell xcrun --sdk iphoneos --show-sdk-path)
CC = $(shell xcrun --sdk $(SDK) --find clang)
CFLAGS = -isysroot $(SDK) -arch arm64

all : klog

.PHONY : upload

upload : klog
	rsync -sz -e 'ssh -p 2222' klog root@localhost:/var/root

klog : klog.c
	$(CC) $(CFLAGS) klog.c -o klog
	ldid -S../ent.xml ./klog

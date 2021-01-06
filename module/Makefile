CC = clang
SDK = $(shell xcrun --sdk iphoneos --show-sdk-path)
CFLAGS = -isysroot $(SDK) -arch arm64 -Wno-string-plus-int -fno-stack-protector
CFLAGS += -D_FORTIFY_SOURCE=0 -nostdlib
LDFLAGS = -Xlinker -kext

export CC
export CFLAGS

TARGET_DIRS = common el1 el3 pf

all : $(TARGET_DIRS) preboot_hook.o xnuspy

.PHONY : target_dirs $(TARGET_DIRS)

target_dirs : $(TARGET_DIRS)

$(TARGET_DIRS) :
	$(MAKE) -C $@

OBJECT_FILES = $(shell find ./common ./pf ./el3 -type f -name "*.o")
INSTR_FILES = $(shell find ./el1 -type f -name "*_instrs.h")

preboot_hook.o : $(INSTR_FILES) preboot_hook.c preboot_hook.h \
	common/xnuspy_structs.h
	$(CC) $(CFLAGS) preboot_hook.c -c

xnuspy : $(OBJECT_FILES) xnuspy.c preboot_hook.o common/common.h \
	pf/offsets.h pf/pfs.h
	$(CC) $(CFLAGS) $(LDFLAGS) $(OBJECT_FILES) preboot_hook.o xnuspy.c -o xnuspy

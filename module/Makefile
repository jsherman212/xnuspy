SDK = $(shell xcrun --sdk iphoneos --show-sdk-path)
CC = $(shell xcrun --sdk $(SDK) --find clang)
CFLAGS = -isysroot $(SDK) -arch arm64 -Wno-string-plus-int -fno-stack-protector
CFLAGS += -Wno-shorten-64-to-32 -D_FORTIFY_SOURCE=0 -nostdlib
CFLAGS += -DXNUSPY_PRIVATE -I$(RP)/include
LDFLAGS = -Xlinker -kext
OPDUMP = $(RP)/opdump/opdump

export CC
export CFLAGS
export OPDUMP
export SDK

TARGET_DIRS = common el1 el3 pf

all : $(TARGET_DIRS) preboot_hook.o xnuspy

.PHONY : target_dirs $(TARGET_DIRS)

target_dirs : $(TARGET_DIRS)

$(TARGET_DIRS) :
	$(MAKE) -C $@

OBJECT_FILES = $(shell find ./common ./pf ./el3 -type f -name "*.o")
INSTR_FILES = $(shell find $(RP)/include/xnuspy/el1 -type f -name "*_instrs.h")

ifneq ($(XNUSPY_TRAMP_PAGES), )
preboot_hook.o : CFLAGS += -DXNUSPY_TRAMP_PAGES=$(XNUSPY_TRAMP_PAGES)
endif

preboot_hook.o : $(INSTR_FILES) preboot_hook.c \
	$(RP)/include/common/preboot_hook.h \
	$(RP)/include/xnuspy/xnuspy_structs.h
	$(CC) $(CFLAGS) preboot_hook.c -c

xnuspy : $(OBJECT_FILES) xnuspy.c preboot_hook.o \
	$(RP)/include/common/common.h \
	$(RP)/include/pf/offsets.h \
	$(RP)/include/pf/pfs.h \
	$(RP)/include/xnuspy/xnuspy_structs.h
	$(CC) $(CFLAGS) $(LDFLAGS) $(OBJECT_FILES) preboot_hook.o xnuspy.c -o xnuspy

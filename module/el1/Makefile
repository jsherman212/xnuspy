ASM_INSTR_HDRS = $(patsubst %.s, %_instrs.h, $(wildcard *.s))
TARGET_DIRS = xnuspy_ctl

all : $(ASM_INSTR_HDRS) target_dirs

# The asm sources for this project are independent of each other, so we don't
# need to recompile all of them if one changes, unlike svc_stalker
%_instrs.h : %.s %.h ../common/xnuspy_cache.h
	chmod +x ./hookgen.pl
	./hookgen.pl $(subst .s,,$<)

.PHONY : target_dirs $(TARGET_DIRS)

target_dirs : $(TARGET_DIRS)

$(TARGET_DIRS) :
	$(MAKE) -C $@

ASM_SRCS = $(wildcard *.s)
ASM_HDRS = $(patsubst %.s, %.h, $(ASM_SRCS))
ASM_INSTR_HDRS = $(patsubst %.s, %_instrs.h, $(ASM_SRCS))

TARGET_DIRS = xnuspy_ctl

all : $(ASM_INSTR_HDRS) target_dirs

$(ASM_INSTR_HDRS) : $(ASM_SRCS) $(ASM_HDRS) \
	../common/xnuspy_cache.h
	$(shell chmod +x ./hookgen.pl)
	$(shell ./hookgen.pl hook_system_check_sysctlbyname_hook)
	$(shell ./hookgen.pl xnuspy_ctl_tramp)

.PHONY : target_dirs $(TARGET_DIRS)

target_dirs : $(TARGET_DIRS)

$(TARGET_DIRS) :
	$(MAKE) -C $@

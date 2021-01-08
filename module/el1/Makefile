ASM_INSTR_HDRS = $(patsubst %.s, %_instrs.h, $(wildcard *.s))
TARGET_DIRS = xnuspy_ctl

all : $(ASM_INSTR_HDRS) target_dirs

%_instrs.h : %.s %.h ../common/xnuspy_cache.h
	$(eval OUTFILE = $(subst .s,,$<))
	$(CC) -arch arm64 -e _$(OUTFILE) $< -o $(OUTFILE)
	$(OPDUMP) -td -i ./$(OUTFILE) -a $(OUTFILE) -o $(OUTFILE)_instrs.h
	# rm ./$(OUTFILE)

.PHONY : target_dirs $(TARGET_DIRS)

target_dirs : $(TARGET_DIRS)

$(TARGET_DIRS) :
	$(MAKE) -C $@

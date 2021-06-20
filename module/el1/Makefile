ASM_INSTR_HDRS = $(patsubst %.s, $(RP)/include/xnuspy/el1/%_instrs.h, $(wildcard *.s))
TARGET_DIRS = xnuspy_ctl

all : $(ASM_INSTR_HDRS) target_dirs

$(RP)/include/xnuspy/el1/%_instrs.h : %.s %.h \
	$(RP)/include/asm/asm_support.h $(RP)/include/xnuspy/xnuspy_cache.h
	$(eval OUTFILE = $(subst .s,,$<))
	$(CC) -arch arm64 -isysroot $(SDK) -I$(RP)/include -e _$(OUTFILE) $< -o $(OUTFILE)
	$(OPDUMP) -td -i ./$(OUTFILE) -a $(OUTFILE) -o $(OUTFILE)_instrs.h
	mv $(OUTFILE)_instrs.h $(RP)/include/xnuspy/el1/

.PHONY : target_dirs $(TARGET_DIRS)

target_dirs : $(TARGET_DIRS)

$(TARGET_DIRS) :
	$(MAKE) -C $@

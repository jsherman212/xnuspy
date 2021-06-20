DST = $(RP)/include/xnuspy/el3

all : kpp kpp.o

# kpp : kpp.s ../common/asm_support.h
kpp : kpp.s $(RP)/include/asm/asm_support.h
	$(CC) -arch arm64 -isysroot $(SDK) -I$(RP)/include -e _kpp0 kpp.s -o kpp
	$(OPDUMP) -td -i ./kpp -a kpp_patches -o $(DST)/kpp_patches.h

# kpp.o : ../common/common.h kpp.c kpp.h kpp_patches.h
kpp.o : $(RP)/include/common/common.h kpp.c \
	$(RP)/include/xnuspy/el3/kpp.h $(DST)/kpp_patches.h
	$(CC) $(CFLAGS) kpp.c -c

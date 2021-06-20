all : asm.o common.o

asm.o : asm.c $(RP)/include/asm/asm.h
	$(CC) $(CFLAGS) asm.c -c

common.o : common.c $(RP)/include/common/common.h
	$(CC) $(CFLAGS) common.c -c

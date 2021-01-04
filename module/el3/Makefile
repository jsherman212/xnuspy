CC = clang

XNUSPY_EL3_FLAGS = -arch arm64 -ffreestanding -e _xnuspy_el3_entry_tramp
XNUSPY_EL3_FLAGS += -Wl,-order_file,./order

all : xnuspy_el3

# the second one is for the actual on device EL3
# the lines below that are for pongo on qemu

xnuspy_el3 : int.s xnuspy_el3.c
	$(CC) $(XNUSPY_EL3_FLAGS) int.s xnuspy_el3.c -o xnuspy_el3
	../../opdump/opdump -i ./xnuspy_el3 -o xnuspy_el3.bin -r
	#../../opdump/opdump -i ./xnuspy_el3 -o xnuspy_el3_opcodes -t
	#./hookgen.pl xnuspy_el3_opcodes
	#cp ./xnuspy_el3_opcodes.h ~/iOS/Pongo\ Builds/pongoOS-QEMU/build/xnuspy_el3_opcodes.h

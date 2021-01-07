all : kpp kpp.o

kpp : kpp.s
	$(CC) -arch arm64 -e _kpp0 kpp.s -o kpp
	$(OPDUMP) -td -i ./kpp -a kpp_patches -o kpp_patches.h

kpp.o : ../common/common.h ../common/pongo.h kpp.c kpp.h kpp_patches.h
	$(CC) $(CFLAGS) kpp.c -c

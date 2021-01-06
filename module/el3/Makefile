kpp.o : ../common/common.h ../common/pongo.h kpp.c kpp.h
	$(CC) $(CFLAGS) kpp.c -c

kpp : kpp.s kpp.o
	$(CC) -arch arm64 -e _kpp0 kpp.s -o kpp
	../../opdump/opdump -i ./kpp -a kpp_patches -r

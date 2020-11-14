TARGET_DIRS = 13 14

all : disas.o macho.o $(TARGET_DIRS)

disas.o : disas.c disas.h
	$(CC) $(CFLAGS) disas.c -c

macho.o : macho.c macho.h
	$(CC) $(CFLAGS) macho.c -c

target_dirs : $(TARGET_DIRS)

.PHONY : all target_dirs $(TARGET_DIRS)

$(TARGET_DIRS) :
	$(MAKE) -C $@

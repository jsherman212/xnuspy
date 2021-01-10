TARGET_DIRS = 13 14

all : macho.o $(TARGET_DIRS)

macho.o : macho.c macho.h
	$(CC) $(CFLAGS) macho.c -c

target_dirs : $(TARGET_DIRS)

.PHONY : all target_dirs $(TARGET_DIRS)

$(TARGET_DIRS) :
	$(MAKE) -C $@

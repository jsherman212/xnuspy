TARGET_DIRS = 13 14 15

all : $(TARGET_DIRS)

target_dirs : $(TARGET_DIRS)

.PHONY : target_dirs $(TARGET_DIRS)

$(TARGET_DIRS) :
	$(MAKE) -C $@

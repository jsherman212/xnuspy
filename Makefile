RP = $(realpath $(shell pwd))

export RP

TARGET_DIRS = loader opdump module

all : $(TARGET_DIRS)

.PHONY: all $(TARGET_DIRS)

$(TARGET_DIRS) :
	$(MAKE) -C $@

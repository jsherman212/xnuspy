CC = clang
CFLAGS = -g
LDFLAGS = -lusb-1.0

ifeq ($(XNUSPY_SERIAL), 1)
	CFLAGS += -DXNUSPY_SERIAL
endif

TARGET = loader

SOURCES = loader.c

$(TARGET) : $(SOURCES)
	$(CC) $(CFLAGS) $(LDFLAGS) $(SOURCES) -o $(TARGET)

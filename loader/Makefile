CC = clang
CFLAGS = -g
LDFLAGS = -lusb-1.0

TARGET = loader

SOURCES = loader.c

$(TARGET) : $(SOURCES)
	$(CC) $(CFLAGS) $(LDFLAGS) $(SOURCES) -o $(TARGET)

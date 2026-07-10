CC = clang
CFLAGS = -Wall -Wextra -Wpedantic
LDLIBS = -lpcap

TARGET = nids
SOURCE = src/main.c

$(TARGET): $(SOURCE)
	$(CC) $(CFLAGS) $(SOURCE) $(LDLIBS) -o $(TARGET)

clean:
	rm -f $(TARGET)
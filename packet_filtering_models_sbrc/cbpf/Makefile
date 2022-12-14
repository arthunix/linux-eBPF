.PHONY : clean

LDFLAGS	= -lpcap
FLAGS = -std=gnu11 -Iinclude
CFLAGS = -O2 -pedantic -Wall -Wextra -Wno-unused-variable -Wno-unused-parameter -Wno-unused-function

SOURCES = $(shell echo *.c)
HEADERS = $(shell echo *.h)
OBJECTS = $(SOURCES:.c=.o)

TARGET=socket_filter

all: $(TARGET)

clean:
	rm -f *.o *.so $(TARGET)

$(TARGET):$(OBJECTS)
	$(CC) $(CPPFLAGS) $(OBJECTS) -o $@ $(LDFLAGS)

.PHONY : clean

LDFLAGS= -lpcap
FLAGS        = -std=gnu99 -Iinclude
CFLAGS       = -O2 -pedantic -Wall -Wextra

SOURCES = $(shell echo *.c)
HEADERS = $(shell echo *.h)
OBJECTS=$(SOURCES:.c=.o)

TARGET=filter_user_space_no_bpf

all: $(TARGET)

clean:
	rm -f *.o *.so

$(TARGET):$(OBJECTS)
	$(CC) $(CPPFLAGS) $(OBJECTS) -o $@ $(LDFLAGS)

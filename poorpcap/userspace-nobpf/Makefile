.PHONY : clean

LDFLAGS=
FLAGS        = -std=gnu99 -Iinclude
CFLAGS       = -O2 -pedantic -Wall -Wextra

SOURCES = $(shell echo *.c)
HEADERS = $(shell echo *.h)
OBJECTS=$(SOURCES:.c=.o) /libpcap/build/libpcap.so

TARGET=filter_user_space_no_bpf

makelibpcap:
	cd libpcap
	mkdir build
	cd build
	cmake
	make
	cd ../..

all: $(TARGET)

clean:
	rm -f *.o *.so
	rm -rf libpcap/build

$(TARGET):$(OBJECTS)
	$(CC) $(CPPFLAGS) $(OBJECTS) -o $@ $(LDFLAGS)

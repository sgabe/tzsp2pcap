# Configurable variables
TARGET = tzsp2pcap
CFLAGS += -std=c99 -D_DEFAULT_SOURCE -Wall -Wextra -pedantic -O2 -g
LIBS = -lpcap
DESTDIR ?= /usr/local

BUILD_VER := 0.2.0
BUILD_REV := $(shell git rev-parse --short HEAD)
BUILD_DATE ?= $(shell git log --pretty=format:%ct -1)

docker:
	docker build \
		--build-arg BUILD_VER=$(BUILD_VER) \
		--build-arg BUILD_REV=$(BUILD_REV) \
		--build-arg BUILD_DATE=$(BUILD_DATE) \
		--no-cache -t sgabe/tzsp2pcap:$(BUILD_VER) .

tzsp2pcap: tzsp2pcap.c
	$(CC) -o $@ $(CFLAGS) $(LDFLAGS) $< $(LIBS)

.PHONY: clean all install uninstall

all: $(TARGET)

install: $(TARGET)
	install -s -m 755 $< $(DESTDIR)/bin

uninstall:
	rm -f $(DESTDIR)/bin/$(TARGET)

clean:
	rm -f $(TARGET)

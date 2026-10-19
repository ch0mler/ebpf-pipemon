CLANG ?= clang
BPFTOOL ?= bpftool
CC ?= cc
BUILD_DIR := build
ARCH_INCLUDE := /usr/include/$(shell $(CC) -dumpmachine)
LIBBPF_CFLAGS := $(shell pkg-config --cflags libbpf)
LIBBPF_LIBS := $(shell pkg-config --libs libbpf)

.PHONY: all clean

all: $(BUILD_DIR)/pipe-monitor

$(BUILD_DIR):
	mkdir -p $@

$(BUILD_DIR)/pipe_monitor.bpf.o: src/pipe_monitor.bpf.c src/pipe_event.h | $(BUILD_DIR)
	$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_x86 -Wall -Werror \
		-I$(ARCH_INCLUDE) -Isrc -c $< -o $@

$(BUILD_DIR)/pipe_monitor.skel.h: $(BUILD_DIR)/pipe_monitor.bpf.o
	$(BPFTOOL) gen skeleton $< > $@

$(BUILD_DIR)/pipe-monitor: src/pipe_monitor.c src/pipe_event.h $(BUILD_DIR)/pipe_monitor.skel.h
	$(CC) -g -O2 -Wall -Wextra -Werror $(LIBBPF_CFLAGS) -I$(BUILD_DIR) -Isrc \
		src/pipe_monitor.c -o $@ $(LIBBPF_LIBS)

clean:
	rm -rf $(BUILD_DIR)

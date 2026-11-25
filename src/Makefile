# SPDX-License-Identifier: GPL-3.0-or-later
# raat-endpoint
#   make            host build (system alsa-lib), output in build/host/
#   make armhf      static armhf build with the Linaro 8.2 toolchain, build/armhf/
#   make test       replay test against the host build (needs the captures)
#   make test-armhf the same test, armhf binary under qemu-arm

# directory holding arm-linux-gnueabihf-gcc (e.g. Arm GNU 8.2-2018.08)
TOOLCHAIN ?= $(dir $(shell command -v arm-linux-gnueabihf-gcc 2>/dev/null))
TARGET ?= host
BUILD := build/$(TARGET)

ifeq ($(TARGET),armhf)
CC := $(TOOLCHAIN)/arm-linux-gnueabihf-gcc
STRIP := $(TOOLCHAIN)/arm-linux-gnueabihf-strip
ALSA_PREFIX ?= $(CURDIR)/build/armhf-deps
ARCHFLAGS := -mcpu=cortex-a7 -mfpu=neon-vfpv4 -mfloat-abi=hard
EXTRA_CFLAGS := -I$(ALSA_PREFIX)/include
LDFLAGS += -static
LDLIBS := $(ALSA_PREFIX)/lib/libasound.a -lm -lpthread -lrt
else
CC ?= cc
STRIP ?= strip
ARCHFLAGS :=
EXTRA_CFLAGS :=
LDLIBS := -lasound -lm -lpthread
endif

OPT ?= -O2
CFLAGS := -std=c11 $(OPT) -g -Wall -Wextra -Wno-unused-parameter $(ARCHFLAGS) $(EXTRA_CFLAGS) -I.
# Lua 5.3.6 as its own Makefile builds it, minus dlopen (static build, no C modules).
LUA_CFLAGS := -std=gnu99 $(OPT) -g -DLUA_COMPAT_5_2 -DLUA_USE_POSIX $(ARCHFLAGS) -w

SRCS := main.c util.c loop.c ll.c platform.c stream.c output.c session.c lbuffer.c \
	lstream.c luv.c loutput.c devserver.c manager.c sood.c
LUA_DIR := third_party/lua-5.3.6
LUA_SRCS := $(filter-out $(LUA_DIR)/lua.c $(LUA_DIR)/luac.c,$(wildcard $(LUA_DIR)/*.c))
CJSON_SRCS := third_party/cjson/cJSON.c

OBJS := $(SRCS:%.c=$(BUILD)/%.o) $(LUA_SRCS:%.c=$(BUILD)/%.o) $(CJSON_SRCS:%.c=$(BUILD)/%.o)
BIN := $(BUILD)/raat-endpoint

UNIT := $(BUILD)/test_stream

all: $(BIN) $(UNIT)

$(UNIT): tests/test_stream.c $(BUILD)/stream.o $(BUILD)/util.o $(BUILD)/third_party/cjson/cJSON.o
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(LDLIBS)

$(BIN): $(OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(OBJS) $(LDLIBS)
	$(STRIP) -o $@.stripped $@

$(BUILD)/third_party/lua-5.3.6/%.o: third_party/lua-5.3.6/%.c
	@mkdir -p $(dir $@)
	$(CC) $(LUA_CFLAGS) -c -o $@ $<

$(BUILD)/third_party/cjson/%.o: third_party/cjson/%.c
	@mkdir -p $(dir $@)
	$(CC) -std=c89 $(OPT) -g $(ARCHFLAGS) -w -c -o $@ $<

$(BUILD)/%.o: %.c $(wildcard *.h)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c -o $@ $<

build/armhf-deps/lib/libasound.a:
	deps/build-alsa-armhf.sh $(TOOLCHAIN) $(CURDIR)/build/armhf-deps

armhf: build/armhf-deps/lib/libasound.a
	$(MAKE) TARGET=armhf

test: all
	build/host/test_stream
	python3 tests/replay.py build/host/raat-endpoint

test-armhf: armhf
	qemu-arm build/armhf/test_stream
	python3 tests/replay.py --qemu qemu-arm build/armhf/raat-endpoint

clean:
	rm -rf build/host build/armhf build/asan

.PHONY: all armhf test test-armhf clean

# SPDX-License-Identifier: GPL-3.0-or-later
# raat-endpoint
#   make                          host build (binary + libraat-endpoint.so + raatflector)
#   make PIPEWIRE=0               host build without PipeWire support
#   make RAATFLECTOR=1            enable RAATflector L3 VPN client support
#   make lib                      build only libraat-endpoint.so
#   make raatflector              build only the raatflector server binary
#   make armhf                    static armhf build with Linaro 8.2, build/armhf/
#   make test                     unit + replay tests against the host build
#   make test-armhf               the same test, armhf binary under qemu-arm

# directory holding arm-linux-gnueabihf-gcc (e.g. Arm GNU 8.2-2018.08)
TOOLCHAIN ?= $(dir $(shell command -v arm-linux-gnueabihf-gcc 2>/dev/null))
TARGET ?= host
BUILD := build/$(TARGET)

RAATFLECTOR ?= 0

ifeq ($(TARGET),armhf)
PIPEWIRE ?= 0
CC := $(TOOLCHAIN)/arm-linux-gnueabihf-gcc
STRIP := $(TOOLCHAIN)/arm-linux-gnueabihf-strip
ALSA_PREFIX ?= $(CURDIR)/build/armhf-deps
ARCHFLAGS := -mcpu=cortex-a7 -mfpu=neon-vfpv4 -mfloat-abi=hard
EXTRA_CFLAGS := -I$(ALSA_PREFIX)/include
LDFLAGS += -static
LDLIBS := $(ALSA_PREFIX)/lib/libasound.a -lm -lpthread -lrt
PICFLAGS :=
else
PIPEWIRE ?= $(shell pkg-config --exists libpipewire-0.3 2>/dev/null && echo 1 || echo 0)
CC ?= cc
STRIP ?= strip
ARCHFLAGS :=
EXTRA_CFLAGS :=
LDLIBS := -lasound -lm -lpthread
PICFLAGS := -fPIC -fvisibility=hidden
endif

ifeq ($(PIPEWIRE),1)
EXTRA_CFLAGS += -DENABLE_PIPEWIRE $(shell pkg-config --cflags libpipewire-0.3)
LDLIBS += $(shell pkg-config --libs libpipewire-0.3)
endif

ifeq ($(RAATFLECTOR),1)
EXTRA_CFLAGS += -DENABLE_RAATFLECTOR
endif

OPT ?= -O2
CFLAGS := -std=c11 $(OPT) -g -Wall -Wextra -Wno-unused-parameter $(ARCHFLAGS) $(PICFLAGS) $(EXTRA_CFLAGS) -I.
# Lua 5.3.6 as its own Makefile builds it, minus dlopen (static build, no C modules).
LUA_CFLAGS := -std=gnu99 $(OPT) -g -DLUA_COMPAT_5_2 -DLUA_USE_POSIX $(ARCHFLAGS) $(PICFLAGS) -w

LIB_SRCS := lib.c util.c loop.c ll.c platform.c stream.c output.c session.c lbuffer.c \
	lstream.c luv.c loutput.c devserver.c manager.c sood.c
ifeq ($(PIPEWIRE),1)
LIB_SRCS += pw_backend.c
endif
ifeq ($(RAATFLECTOR),1)
LIB_SRCS += raatflector.c
endif

LUA_DIR := third_party/lua-5.3.6
LUA_SRCS := $(filter-out $(LUA_DIR)/lua.c $(LUA_DIR)/luac.c,$(wildcard $(LUA_DIR)/*.c))
CJSON_SRCS := third_party/cjson/cJSON.c

LIB_OBJS := $(LIB_SRCS:%.c=$(BUILD)/%.o) $(LUA_SRCS:%.c=$(BUILD)/%.o) $(CJSON_SRCS:%.c=$(BUILD)/%.o)
MAIN_OBJ := $(BUILD)/main.o
BIN := $(BUILD)/raat-endpoint
LIB := $(BUILD)/libraat-endpoint.so
RF_BIN := $(BUILD)/raatflector
UNIT := $(BUILD)/test_stream
LIB_UNIT := $(BUILD)/test_lib

ifeq ($(TARGET),armhf)
all: $(BIN) $(UNIT) $(RF_BIN)
else
all: $(BIN) $(LIB) $(UNIT) $(LIB_UNIT) $(RF_BIN)
endif

$(UNIT): tests/test_stream.c $(BUILD)/stream.o $(BUILD)/util.o $(BUILD)/third_party/cjson/cJSON.o
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(LDLIBS)

$(LIB_UNIT): tests/test_lib.c $(LIB) raat_endpoint.h
	$(CC) -std=c11 $(OPT) -g -Wall -Wextra -I. -o $@ tests/test_lib.c -L$(BUILD) -lraat-endpoint -Wl,-rpath,'$$ORIGIN'

$(BIN): $(MAIN_OBJ) $(LIB_OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(MAIN_OBJ) $(LIB_OBJS) $(LDLIBS)
	$(STRIP) -o $@.stripped $@

$(LIB): $(LIB_OBJS)
	$(CC) -shared $(ARCHFLAGS) $(LDFLAGS) -Wl,-soname,libraat-endpoint.so -o $@ $(LIB_OBJS) $(LDLIBS)

$(RF_BIN): ../tools/raatflector.c raatflector_proto.h
	@mkdir -p $(dir $@)
	$(CC) -std=c11 $(OPT) -g -Wall -Wextra -Wno-unused-parameter $(ARCHFLAGS) $(LDFLAGS) -I. -o $@ ../tools/raatflector.c

$(BUILD)/third_party/lua-5.3.6/%.o: third_party/lua-5.3.6/%.c
	@mkdir -p $(dir $@)
	$(CC) $(LUA_CFLAGS) -c -o $@ $<

$(BUILD)/third_party/cjson/%.o: third_party/cjson/%.c
	@mkdir -p $(dir $@)
	$(CC) -std=c89 $(OPT) -g $(ARCHFLAGS) $(PICFLAGS) -w -c -o $@ $<

$(BUILD)/%.o: %.c $(wildcard *.h)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c -o $@ $<

lib: $(LIB)

raatflector: $(RF_BIN)

build/armhf-deps/lib/libasound.a:
	deps/build-alsa-armhf.sh $(TOOLCHAIN) $(CURDIR)/build/armhf-deps

armhf: build/armhf-deps/lib/libasound.a
	$(MAKE) TARGET=armhf

test: all
	build/host/test_stream
	build/host/test_lib
ifeq ($(RAATFLECTOR),1)
	python3 tests/test_raatflector.py build/host/raat-endpoint build/host/raatflector
endif
	python3 tests/replay.py build/host/raat-endpoint

test-armhf: armhf
	qemu-arm build/armhf/test_stream
	python3 tests/replay.py --qemu qemu-arm build/armhf/raat-endpoint

clean:
	rm -rf build/host build/armhf build/asan

.PHONY: all lib raatflector armhf test test-armhf clean

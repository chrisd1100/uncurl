UNAME_S = $(shell uname -s)
ARCH = $(shell uname -m)
NAME = libuncurl
PREFIX = uc

.m.o:
	$(CC) $(OCFLAGS)  -c -o $@ $<

OBJS = \
	src/http.o \
	src/net.o \
	src/tls.o \
	src/uncurl.o \
	src/ws.o

INCLUDES = \
	-Isrc \
	-Iinclude

DEFS = \
	-D_POSIX_C_SOURCE=200112L \
	-D_GNU_SOURCE

FLAGS = \
	-Wall \
	-Wextra \
	-Wshadow \
	-Wno-unused-parameter \
	-Wno-switch \
	-std=c99 \
	-fPIC

TEST_FLAGS = \
	-nodefaultlibs

TEST_LIBS = \
	-lc

ifdef DEBUG
FLAGS := $(FLAGS) -O0 -g
else
FLAGS := $(FLAGS) -O3 -fvisibility=hidden
endif

#############
### LINUX ###
#############
ifeq ($(UNAME_S), Linux)

TARGET = linux
endif

#############
### APPLE ###
#############
ifeq ($(UNAME_S), Darwin)

ifndef TARGET
TARGET = macosx
endif

ifndef ARCH
ARCH = x86_64
endif

ifeq ($(TARGET), macosx)
MIN_VER = 10.11
else
MIN_VER = 11.0
FLAGS := $(FLAGS) -fembed-bitcode
endif

FLAGS := $(FLAGS) \
	-m$(TARGET)-version-min=$(MIN_VER) \
	-isysroot $(shell xcrun --sdk $(TARGET) --show-sdk-path) \
	-arch $(ARCH)

endif

CFLAGS = $(INCLUDES) $(DEFS) $(FLAGS)
OCFLAGS = $(CFLAGS) -fobjc-arc

all: clean-build clear
	make objs -j4

objs: $(OBJS)
	mkdir -p bin/$(TARGET)/$(ARCH)
	$(AR) -crs bin/$(TARGET)/$(ARCH)/$(NAME).a $(OBJS)

test: clean-build clear
	make objs-test -j4

objs-test: $(OBJS) src/test.o
	$(CC) -o $(PREFIX)-test $(TEST_FLAGS) $(OBJS) src/test.o $(TEST_LIBS)
	./$(PREFIX)-test

###############
### ANDROID ###
###############

### Downloads ###
# https://developer.android.com/ndk/downloads -> Put in ~/android-ndk-xxx

ANDROID_NDK = $(HOME)/android-ndk-r21d

android: clear
	@$(ANDROID_NDK)/ndk-build -j4 \
		NDK_PROJECT_PATH=. \
		APP_BUILD_SCRIPT=Android.mk \
		APP_OPTIM=release \
		APP_PLATFORM=android-23 \
		--no-print-directory \
		| grep -v 'fcntl(): Operation not supported'

clean: clean-build
	@rm -rf bin
	@rm -rf obj
	@rm -f $(PREFIX)-test

clean-build:
	@rm -f $(OBJS)
	@rm -f $(NAME).so

clear:
	@clear

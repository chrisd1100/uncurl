CORES = $(shell getconf _NPROCESSORS_ONLN)
UNAME = $(shell uname -s)
ARCH = $(shell uname -m)

LIB_NAME = libuncurl
BIN_NAME = example

OBJS = \
	../src/uncurl.o \
	../src/net.o \
	../src/http.o \
	../src/tls.o \
	../src/ws.o

EXAMPLE_OBJ = \
	../example/example-ws.o

DEFS = \
	-D__UNIXY__ \
	-D_GNU_SOURCE

FLAGS = \
	-Wall \
	-Wextra \
	-Wno-unused-value \
	-fPIC \
	-O3

INCLUDES = \
	-I../include/

SYS_LIBS = \


ifeq ($(UNAME), Linux)
ifeq ($(ARCH), armv7l)

PLATFORM = rpi
SHARED_SUFFIX = so

endif
endif


ifeq ($(UNAME), Linux)
ifeq ($(ARCH), x86_64)

PLATFORM = linux
SHARED_SUFFIX = so

endif
endif

ifeq ($(UNAME), Darwin)

export MACOSX_DEPLOYMENT_TARGET=10.9

FLAGS := $(FLAGS) -D__MACOS__
PLATFORM = macos
SHARED_SUFFIX = dylib

endif


STATIC_LIBS = \
	../lib/$(PLATFORM)/libssl.a \
	../lib/$(PLATFORM)/libcrypto.a

CFLAGS = $(INCLUDES) $(DEFS) $(FLAGS) -std=c99


all: clean clear
	make -j$(CORES) lib

clean:
	rm -f $(OBJS) $(EXAMPLE_OBJ)
	rm -f $(LIB_NAME).a
	rm -f $(LIB_NAME).$(SHARED_SUFFIX)
	rm -f $(BIN_NAME)

clear:
	clear

ifdef SHARED
LD_COMMAND = \
	$(CC) \
	-shared \
	-o $(LIB_NAME).$(SHARED_SUFFIX) \
	$(OBJS) \
	$(STATIC_LIBS) \
	$(SYS_LIBS)

EXAMPLE_LD_COMMAND = \
	$(CC) \
	-o $(BIN_NAME) \
	-L./ \
	-luncurl \
	$(EXAMPLE_OBJ)

else
LD_COMMAND = \
	ar -r $(LIB_NAME).a $(OBJS)

EXAMPLE_LD_COMMAND = \
	$(CC) \
	-o $(BIN_NAME) \
	$(EXAMPLE_OBJ) \
	$(LIB_NAME).a \
	$(STATIC_LIBS) \
	$(SYS_LIBS)

endif

lib: $(OBJS)
	$(LD_COMMAND)

example: all $(EXAMPLE_OBJ)
	$(EXAMPLE_LD_COMMAND)

LIB_NAME = libuncurl

OBJS = \
	src/uncurl.o \
	src/net.o \
	src/http.o \
	src/tls.o \
	src/ws.o

INCLUDES = \
	-Iinclude

DEFS = \
	-D__UNIXY__ \
	-D_GNU_SOURCE

FLAGS = \
	-Wall \
	-Wextra \
	-Wno-unused-value \
	-fPIC \
	-std=c99 \
	-O3

CFLAGS = $(INCLUDES) $(DEFS) $(FLAGS)
ANDROID_NDK = $(HOME)/android-ndk-r21d

all: clean clear $(OBJS)
	ar -crs $(LIB_NAME).a $(OBJS)

android: clear
	@$(ANDROID_NDK)/ndk-build \
		NDK_PROJECT_PATH=. \
		APP_BUILD_SCRIPT=Android.mk \
		NDK_APPLICATION_MK=Application.mk \
		--no-print-directory \
		| grep -v 'fcntl(): Operation not supported'

clean:
	rm -f $(OBJS)
	rm -f $(LIB_NAME).a

clear:
	clear

### ANDROID ###

### Downloads ###
# https://developer.android.com/ndk/downloads -> Put in ~/android-ndk-xxx



LOCAL_PATH := $(call my-dir)
include $(CLEAR_VARS)

TARGET_OUT = bin/android/$(TARGET_ARCH_ABI)

FLAGS = \
	-Wall \
	-Wextra \
	-std=c99 \
	-fPIC

ifdef DEBUG
FLAGS := $(FLAGS) -O0 -g
else
FLAGS := $(FLAGS) -O3 -g0 -fvisibility=hidden
endif

LOCAL_MODULE_FILENAME := libuncurl
LOCAL_MODULE := libuncurl

LOCAL_C_INCLUDES := \
	src \
	include

DEFS = \
	-D_POSIX_C_SOURCE=200112L

LOCAL_CFLAGS = $(DEFS) $(FLAGS)

LOCAL_SRC_FILES := \
	src/http.c \
	src/net.c \
	src/tls.c \
	src/uncurl.c \
	src/ws.c

include $(BUILD_STATIC_LIBRARY)

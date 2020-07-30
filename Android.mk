LOCAL_PATH := $(call my-dir)
include $(CLEAR_VARS)

LOCAL_MODULE_FILENAME := libuncurl
LOCAL_MODULE := uncurl
LOCAL_C_INCLUDES := include

LOCAL_CFLAGS = \
	-D__UNIXY__ \
	-Wall \
	-Wextra \
	-Wno-unused-value \
	-fPIC \
	-O3

LOCAL_SRC_FILES := \
	src/uncurl.c \
	src/net.c \
	src/http.c \
	src/tls.c \
	src/ws.c

include $(BUILD_STATIC_LIBRARY)

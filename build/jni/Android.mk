LOCAL_PATH := $(call my-dir)
include $(CLEAR_VARS)

SOURCE_PATH := ../../src

LOCAL_MODULE_FILENAME := libuncurl
LOCAL_MODULE := uncurl
LOCAL_C_INCLUDES := ../include

LOCAL_CFLAGS = \
	-D__UNIXY__ \
	-Wall \
	-Wextra \
	-Wno-unused-value \
	-fPIC \
	-O3

LOCAL_SRC_FILES := \
	$(SOURCE_PATH)/uncurl.c \
	$(SOURCE_PATH)/net.c \
	$(SOURCE_PATH)/http.c \
	$(SOURCE_PATH)/tls.c \
	$(SOURCE_PATH)/ws.c \

include $(BUILD_STATIC_LIBRARY)

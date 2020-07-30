LIB_NAME = libuncurl

OBJS = \
	src/uncurl.obj \
	src/net.obj \
	src/http.obj \
	src/tls.obj \
	src/ws.obj

INCLUDES = \
	-Iinclude

DEFS = \
	-DWIN32_LEAN_AND_MEAN \
	-DWIN32 \
	-D__WINDOWS__

FLAGS = \
	/W4 \
	/O2 \
	/MT \
	/MP \
	/GS- \
	/nologo

CFLAGS = $(INCLUDES) $(DEFS) $(FLAGS)

all: clean clear $(OBJS)
	lib /out:$(LIB_NAME).lib /nologo *.obj

clean:
	del *.obj
	del $(LIB_NAME).lib

clear:
	cls

#check environment for 64 vs 32 bit windows, set vars dependently
!IF [if /I "%Platform%" EQU "x64" exit 1]
PLATFORM = windows
!ELSE
PLATFORM = windows32
!ENDIF

LIB_NAME = libuncurl
BIN_NAME = uncurl

OBJS = \
	../src/uncurl.obj \
	../src/net.obj \
	../src/http.obj \
	../src/tls.obj

SYS_LIBS = \
	libvcruntime.lib \
	libucrt.lib \
	libcmt.lib \
	kernel32.lib \
	user32.lib \
	ws2_32.lib \
	advapi32.lib

STATIC_LIBS = \
	libssl.lib \
	libcrypto.lib

LD_FLAGS = \
	/subsystem:console \
	/nodefaultlib \
	/nologo

LIB_PATHS = \
	/libpath:../lib/$(PLATFORM)/

INCLUDES = \
	-I../include/

DEFS = \
	-DWIN32_LEAN_AND_MEAN \
	-DWIN32 \
	-D__WINDOWS__

FLAGS = \
	/W4 \
	/O2 \
	/MT \
	/MP \
	/nologo

CFLAGS = $(INCLUDES) $(DEFS) $(FLAGS)

!ifdef SHARED
CFLAGS = $(CFLAGS) -DUNCURL_MAKE_SHARED
!endif

lib: clean clear $(OBJS)
!ifdef SHARED
	link \
	/dll \
	/out:$(LIB_NAME).dll \
	$(LD_FLAGS) \
	*.obj \
	$(LIB_PATHS) \
	$(STATIC_LIBS) \
	$(SYS_LIBS)
!else
	lib /out:$(LIB_NAME).lib /nologo *.obj
!endif

!ifdef SHARED
EXAMPLE_LIBS = \
	libvcruntime.lib \
	libucrt.lib \
	libcmt.lib \
	kernel32.lib \
	user32.lib \
	ws2_32.lib
!else
EXAMPLE_LIBS = \
	$(LIB_PATHS) \
	$(STATIC_LIBS) \
	$(SYS_LIBS)
!endif

example: lib ../src/example.obj
	link \
	/out:$(BIN_NAME).exe \
	$(LD_FLAGS) \
	example.obj \
	$(LIB_NAME).lib \
	$(EXAMPLE_LIBS)

clean:
	del *.obj
	del $(BIN_NAME).exe
	del $(LIB_NAME).lib
	del $(LIB_NAME).dll
	del $(LIB_NAME).exp

clear:
	cls

TARGET = windows
ARCH = %%Platform%%
NAME = uncurl
PREFIX = uc

OBJS = \
	src\http.obj \
	src\net.obj \
	src\tls.obj \
	src\uncurl.obj \
	src\ws.obj

INCLUDES = \
	-Isrc \
	-Iinclude

DEFS = \
	-DWIN32_LEAN_AND_MEAN \
	-DUNICODE

FLAGS = \
	/W4 \
	/MT \
	/MP \
	/volatile:iso \
	/nologo

LIB_FLAGS = \
	/nologo

TEST_FLAGS = \
	$(LIB_FLAGS) \
	/nodefaultlib \
	/subsystem:console

TEST_LIBS = \
	libvcruntime.lib \
	libucrt.lib \
	libcmt.lib \
	kernel32.lib \
	ws2_32.lib

!IFDEF DEBUG
FLAGS = $(FLAGS) /Ob0 /Zi
TEST_FLAGS = $(TEST_FLAGS) /debug
!ELSE
FLAGS = $(FLAGS) /O2 /Gy /GS- /Gw
!ENDIF

CFLAGS = $(INCLUDES) $(DEFS) $(FLAGS)

all: clean clear $(OBJS)
	mkdir bin\$(TARGET)\$(ARCH)
	lib /out:bin\$(TARGET)\$(ARCH)\$(NAME).lib $(LIB_FLAGS) *.obj

test: all src\test.obj
	link /out:$(PREFIX)-test.exe $(TEST_FLAGS) *.obj $(TEST_LIBS)
	$(PREFIX)-test.exe

clean:
	@-rmdir /s /q bin 2>nul
	@-del /q *.obj 2>nul
	@-del /q *.lib 2>nul
	@-del /q *.pdb 2>nul
	@-del /q $(PREFIX)-test.exe 2>nul

clear:
	@cls

BOFNAME := silent_harbor
COMINCLUDE := -I ./imports
LIBINCLUDE :=
CC_x64 := x86_64-w64-mingw32-gcc
CC_x86 := i686-w64-mingw32-gcc
STRIP_x64 := x86_64-w64-mingw32-strip
STRIP_x86 := i686-w64-mingw32-strip
OPTIONS := -masm=intel -Os -fno-builtin

all:
	$(CC_x64) -o $(BOFNAME).x64.o $(COMINCLUDE) -c go.c -DBOF $(OPTIONS)
	$(CC_x86) -o $(BOFNAME).x86.o $(COMINCLUDE) -c go.c -DBOF $(OPTIONS)
	$(STRIP_x64) --strip-unneeded $(BOFNAME).x64.o
	$(STRIP_x86) --strip-unneeded $(BOFNAME).x86.o

test:
	$(CC_x64) -o $(BOFNAME).x64.exe $(COMINCLUDE) -g go.c $(OPTIONS)
	$(CC_x86) -o $(BOFNAME).x86.exe $(COMINCLUDE) -g go.c $(OPTIONS)

clean:
	$(RM) $(BOFNAME).*.o
	$(RM) $(BOFNAME).*.exe

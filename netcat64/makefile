# Project: netcat64

CPP     = x86_64-w64-mingw32-g++
CC      = x86_64-w64-mingw32-gcc
RM      = rm -f

BIN     = nc64.exe
RES     = netcat64.res
OBJ     = getopt.o doexec.o netcat.o $(RES)
LINKOBJ = getopt.o doexec.o netcat.o $(RES)
LIBS    = -lkernel32 -luser32 -lwinmm -lws2_32 -liphlpapi -s 

CXXINCS  = 
INCS     = 
CXXFLAGS = $(CXXINCS) -Wall -fexpensive-optimizations -O3 -DWIN32 -DNDEBUG -D_CONSOLE -DTELNET -DGAPING_SECURITY_HOLE -DSSODEBUG -DSSOTTL -DSSOBC -DCRLF -DMULTICAST -DIPv6SSM -DFIXINVALCONN -DFIXRELISTENHOST -DURGPTR -DSSOKEEPALIVE 
CFLAGS   = $(INCS) -Wall -fexpensive-optimizations -O3 -DWIN32 -DNDEBUG -D_CONSOLE -DTELNET -DGAPING_SECURITY_HOLE -DSSODEBUG -DSSOTTL -DSSOBC -DCRLF -DMULTICAST -DIPv6SSM -DFIXINVALCONN -DFIXRELISTENHOST -DURGPTR -DSSOKEEPALIVE 

all: nc64.exe

.PHONY: all clean

clean:
	$(RM) $(OBJ) $(BIN) netcat.layout

$(BIN): $(OBJ)
	$(CC) $(LINKOBJ) -o "nc64.exe" $(LIBS)

netcat64.o: netcat64.c
	$(CC) -c netcat.c -o netcat.o $(CFLAGS)

doexec.o: doexec.c
	$(CC) -c doexec.c -o doexec.o $(CFLAGS)

netcat64.o: netcat64.c
	$(CC) -c getopt.c -o getopt.o $(CFLAGS)

netcat64.res: netcat64.rc 
	$(WINDRES) -i netcat64.rc --input-format=rc -o netcat64.res -O coff

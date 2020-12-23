@REM	Build script to compile Netcat on WIN64 using MinGW
@REM
@REM	Rodney Beede	(http://www.rodneybeede.com)
@REM
@REM	2020-12-22
@REM
@REM	Tested with tdm64-1 5.1.0

@REM	Adjust PATH so necessary dll's are accessible
SET PATH=%PATH%;C:\TDM-GCC-64\bin

SET COMPILER=C:\TDM-GCC-64\bin\x86_64-w64-mingw32-gcc.exe
SET LIB_DIR=C:\TDM-GCC-64\lib

@REM	not needed? SET COMPILE_OPTIONS=-c -Wall -fexpensive-optimizations -O3 -DWIN32 -DNDEBUG -D_CONSOLE -DTELNET -DGAPING_SECURITY_HOLE -DSSODEBUG -DSSOTTL -DSSOBC -DCRLF -DMULTICAST -DIPv6SSM -DFIXINVALCONN -DFIXRELISTENHOST -DURGPTR -DSSOKEEPALIVE
SET COMPILE_OPTIONS=-c

del *.o
del nc64.exe

"%COMPILER%" %COMPILE_OPTIONS% getopt.c

"%COMPILER%" %COMPILE_OPTIONS% doexec.c

"%COMPILER%" %COMPILE_OPTIONS% netcat.c

@REM Note that the -l libraries MUST come at the very end or linking will fail
"%COMPILER%" getopt.o doexec.o netcat.o --output nc64.exe -Wl,-L"%LIB_DIR%",-lkernel32,-luser32,-lwinmm,-lws2_32
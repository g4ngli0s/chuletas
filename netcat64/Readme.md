Compilar netcat para usar solamente en una versión de 64 bits de windows

Todo gracias a estos magníficos enlaces:

https://www.rodneybeede.com/security/compile_netcat_on_windows_using_mingw.html
https://github.com/vinsworldcom/NetCat64


x86_64-w64-mingw32-gcc -c getopt.c -Wall -fexpensive-optimizations -O3 -DWIN32 -DNDEBUG -D_CONSOLE -DTELNET -DGAPING_SECURITY_HOLE -DSSODEBUG -DSSOTTL -DSSOBC -DCRLF -DMULTICAST -DIPv6SSM -DFIXINVALCONN -DFIXRELISTENHOST -DURGPTR -DSSOKEEPALIVE

x86_64-w64-mingw32-gcc -c doexec.c -Wall -fexpensive-optimizations -O3 -DWIN32 -DNDEBUG -D_CONSOLE -DTELNET -DGAPING_SECURITY_HOLE -DSSODEBUG -DSSOTTL -DSSOBC -DCRLF -DMULTICAST -DIPv6SSM -DFIXINVALCONN -DFIXRELISTENHOST -DURGPTR -DSSOKEEPALIVE

x86_64-w64-mingw32-gcc -c netcat.c -Wall -fexpensive-optimizations -O3 -DWIN32 -DNDEBUG -D_CONSOLE -DTELNET -DGAPING_SECURITY_HOLE -DSSODEBUG -DSSOTTL -DSSOBC -DCRLF -DMULTICAST -DIPv6SSM -DFIXINVALCONN -DFIXRELISTENHOST -DURGPTR -DSSOKEEPALIVE

x86_64-w64-mingw32-gcc netcat.o getopt.o doexec.o -o nc64.exe -lkernel32 -luser32 -lwinmm -lws2_32 -liphlpapi -s 

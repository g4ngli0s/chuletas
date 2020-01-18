## **TÉCNICA BÁSICA PARA INYECTAR UNA DLL EN UN PROCESO**

**1.- Creación de una dll sencilla**

Para este ejemplo vamos a crear una dll muy simple que nos permita mostrar la inyección en el proceso mostrando un MessageBox.La dll va a ser la misma tanto para x86 como para x64, sólo hay que cambiar en el compilador que usemos la arquitectura. Si queremos hacerlo en modo comandos desde linux o macosx:

  - x86: 
  
  i686-w64-mingw32-gcc -c dllsimple.cpp -o dllsimple.o -D BUILD_DLL
  i686-w64-mingw32-gcc -o dllsimple.dll dllsimple.o -s -shared -Wl,--subsystem,windows
  
  - x64:
  
  x86_64-w64-mingw32-gcc -c dllsimple.cpp -o dllsimple.o -D BUILD_DLL
  x86_64-w64-mingw32-gcc -o dllsimple.dll dllsimple.o -s -shared -Wl,--subsystem,windows
  
**2.- Técnica CreateRemoteThread y LoadLibrary**


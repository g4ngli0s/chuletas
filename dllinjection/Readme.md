## **TÉCNICA BÁSICA PARA INYECTAR UNA DLL EN UN PROCESO DE WINDOWS**

**1.- Creación de una dll sencilla**

Para este ejemplo vamos a crear una [dll muy simple](https://github.com/g4ngli0s/chuletas/blob/master/dllinjection/dllsimple.cpp) que nos permita mostrar la inyección en el proceso mostrando un MessageBox. La dll va a ser la misma tanto para x86 como para x64, sólo hay que cambiar la arquitectura en el compilador que usemos. Si queremos hacerlo en modo comandos desde linux o macosx:

  - x86: 
  ```
  i686-w64-mingw32-gcc -c dllsimple.cpp -o dllsimple.o -D BUILD_DLL
  i686-w64-mingw32-gcc -o dllsimple.dll dllsimple.o -s -shared -Wl,--subsystem,windows
  ```
  - x64:
  ```
  x86_64-w64-mingw32-gcc -c dllsimple.cpp -o dllsimple.o -D BUILD_DLL
  x86_64-w64-mingw32-gcc -o dllsimple64.dll dllsimple.o -s -shared -Wl,--subsystem,windows
  ```
  Si queremos probar que la dll funciona, tan sencillo como:
  ```
  rundll32.exe dllsimple.dll,MsgDll
  ```
  
**2.- Técnica CreateRemoteThread y LoadLibrary**

Esta es la técnia más simple y más conocida. Hay muchas otras que quedan fuera de esta pequeña prueba. El [código de la inyección](https://github.com/g4ngli0s/chuletas/blob/master/dllinjection/inject.cpp) es el mismo para ambas arquitecturas (x86 y x64), al igual que en la dll sólo hay que cambiar la arquitectura en el compilador o bien utilizar estos comandos si estamos en linux o macosx:

  - x86: 
  ```
  i686-w64-mingw32-gcc -g inject.cpp -o inject.exe -lstdc++ -static
  ```
  - x64:
  ```
  x86_64-w64-mingw32-gcc -g inject.cpp -o inject64.exe -lstdc++ -static
  ```
He hecho una compilación estática para evitar problemas con las librerías compartidas que a veces no están instaladas en el sistema operativo donde se realiza la prueba. Queda claro que en este ejemplo no vamos a intentar inyectar mezclando arquitecturas, simplemente en un sistema operativo de 64 bits utilizaremos la libreria y el ejecutable de 64 bits, así como usaremos la librería y el ejecutable de 32 bits en un sistema operativo de 32 bits. Es una prueba de concepto simple, si quieres indagar más en el tema, he añadido en la siguiente sección unos enlaces interesantes sobre el tema. Creo que el código del inyector está sacado directamente de [esta web](https://www.unknowncheats.me/forum/c-and-c-/186709-dll-injector.html) y mejoras de los siguientes enlaces. Me quito el sombrero ante toda esa gente que comparte lo que sabe. ¡Muchas gracias! ¡Compartir es vivir!

**3.- Enlaces para profundizar en el tema**

http://blog.opensecurityresearch.com/2013/01/windows-dll-injection-basics.html

https://github.com/fdiskyou/injectAllTheThings

https://modexp.wordpress.com/2019/08/27/process-injection-apc/

http://www.infernodevelopment.com/simple-c-dll-loading-message-box

https://www.unknowncheats.me/forum/c-and-c-/186709-dll-injector.html

https://securityxploded.com/dll-injection-and-hooking.php

http://blog.opensecurityresearch.com/2013/01/windows-dll-injection-basics.html

https://www.flu-project.com/2018/01/dll-hijacking-aprendiendo-los-conceptos.html

https://www.codeproject.com/Articles/20084/A-More-Complete-DLL-Injection-Solution-Using-Creat

https://github.com/gfreivasc/jadi

https://www.youtube.com/watch?v=Gq6-1xrmFHQ

https://tyranidslair.blogspot.com/2019/08/windows-code-injection-bypassing-cig.html


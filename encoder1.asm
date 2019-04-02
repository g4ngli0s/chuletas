;flat assembler 1.73.04

format PE console
use32
entry start

start:
jmp starter

encoder:
    pop esi
    XOR EAX,EAX
    XOR EBX,EBX
    XOR ECX,ECX
    ADD ECX,0x4        ;lenght shellcode
    ADD EBX,0x21       ;rot-n (0x21 = 33)
    ADD EAX,0x77       ;first value to xor (0x77 = 119)

encode:
    PUSH DWORD [ESI]
    ADD [ESI],BL
    XOR BYTE [ESI],AL
    XOR EAX,EAX
    POP EAX
    INC ESI
    LOOP encode
    ;JMP shellcode
    xor eax, eax
    ret
   
starter:
    call encoder
shellcode: db 0x3d, 0x7d, 0xad, 0x1e

; 29 A3 B3 92 

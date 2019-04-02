;flat assembler 1.73.04

format PE console
use32
entry start

start:
jmp starter

decoder:
    pop esi
    XOR EAX,EAX
    XOR EBX,EBX
    XOR ECX,ECX
    ADD ECX,0x4        ;lenght shellcode
    ADD EBX,0x21       ;rot-n (0x21 = 33)
    ADD EAX,0x77       ;first value to xor (0x77 = 119)

decode:
    XOR BYTE [ESI],AL
    SUB [ESI],BL
    XOR EAX,EAX
    MOV AL,[ESI]
    INC ESI
    LOOP decode
    ;JMP shellcode
    xor eax, eax
    ret
   
starter:
    call decoder
shellcode: db 0x29, 0xA3, 0xB3, 0x92

; 3d, 7d, ad, 1e          

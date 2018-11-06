;Uso flat assembler para compilar y x32dbg para debugear
;Está basado en estas webs:
;https://idafchev.github.io/exploit/2017/09/26/writing_windows_shellcode.html
;https://securitycafe.ro/2016/02/15/introduction-to-windows-shellcode-development-part-3/

format PE console
use32
entry start

    start:
        push eax ; Save all registers
        push ebx
        push ecx
        push edx
        push esi
        push edi
        push ebp

    ;Find kernel32.dll base address
    xor ecx, ecx
    mov eax, [fs:ecx + 0x30]    ; EAX = PEB
    mov eax, [eax + 0xc]        ; EAX = PEB->Ldr
    mov esi, [eax + 0x14]       ; ESI = PEB->Ldr.InMemOrder
    lodsd                       ; EAX = Second module
    xchg eax, esi               ; EAX = ESI, ESI = EAX
    lodsd                       ; EAX = Third(kernel32)
    mov ebx, [eax + 0x10]       ; EBX = Base address
    
    
    ;Find the export table of kernel32.dll
    mov edx, [ebx + 0x3c]               ; EDX = DOS->e_lfanew
    add edx, ebx                        ; EDX = PE Header
    mov edx, [edx + 0x78]               ; EDX = Offset export table
    add edx, ebx                        ; EDX = Export table
    mov esi, [edx + 0x20]               ; ESI = Offset names table
    add esi, ebx                        ; ESI = Names table
    xor ecx, ecx                        ; EXC = 0
    
    Get_Function:
    
        inc ecx                                 ; Increment the ordinal
        lodsd                                   ; Get name offset
        add eax, ebx                            ; Get function name
        cmp dword [eax], 0x50746547             
        jnz Get_Function
        cmp dword [eax + 0x4], 0x41636f72       ; rocA
        jnz Get_Function
        cmp dword [eax + 0x8], 0x65726464       ; ddre
        jnz Get_Function
    
    ;Find the address of GetProcAddress function
    mov esi, [edx + 0x24]               ; ESI = Offset ordinals
    add esi, ebx                        ; ESI = Ordinals table
    mov cx, [esi + ecx * 2]             ; CX = Number of function
    dec ecx
    mov esi, [edx + 0x1c]               ; ESI = Offset address table
    add esi, ebx                        ; ESI = Address table
    mov edx, [esi + ecx * 4]            ; EDX = Pointer(offset)
    add edx, ebx                        ; EDX = GetProcAddress
    
    ;Find the LoadLibrary function address
    xor ecx, ecx                        ; ECX = 0
    push ebx                            ; Kernel32 base address
    push edx                            ; GetProcAddress
    push ecx                            ; 0
    push 0x41797261                     ; aryA
    push 0x7262694c                     ; Libr
    push 0x64616f4c                     ; Load
    push esp                            ; "LoadLibrary"
    push ebx                            ; Kernel32 base address
    call edx                            ; GetProcAddress(LL)
    
    ;Load user32.dll library
    
    add esp, 0xc                ; pop "LoadLibraryA"
    pop ecx                     ; ECX = 0
    push eax                    ; EAX = LoadLibraryA
    push ecx
    mov cx, 0x6c6c              ; ll
    push ecx
    push 0x642e3233             ; 32.d
    push 0x72657375             ; user
    push esp                    ; "user32.dll"
    call eax                    ; LoadLibrary("user32.dll")

    ;Get MessageBox function address
    add esp, 0x10                       ; Clean stack
    mov edx, [esp + 0x4]                ; EDX = GetProcAddress
    xor ecx, ecx                        ; ECX = 0
    push ecx
    mov ecx, 0x6141786f                ;oxAa
    push ecx
    sub dword [esp + 0x3], 0x61        ; Remove a
    push 0x42656761                     ; ageB
    push 0x7373654d                     ; Mess
    push esp                            ; "MessageBox"
    push eax                            ; user32.dll address
    call edx                            ; GetProc(SwapMouseButton)
 
    ;Call MessageBox function
    add esp, 0x14                       ; Cleanup stack
    xor ecx, ecx                        ; ECX = 0
    ;Save string messagebox in stack
    push ecx
    push 0x61746f4e                    ; atoN
    push ecx
    push 0x40                          ; MessageBox type
    xor edx, edx
    mov edx, esp
    add edx, 0x8                       ; EDX = Point to string "Nota"
    push edx
    push edx
    push ecx
    call eax                           ; MessageBox(0,"Nota",Nota",0x40)

    ;Get ExitProcess function address
    add esp, 0xc                   ; Clean stack
    pop edx                        ; GetProcAddress
    pop ebx                        ; kernel32.dll base address
    mov ecx, 0x61737365            ; essa
    push ecx
    sub dword [esp + 0x3], 0x61    ; Remove "a"
    push 0x636f7250                ; Proc
    push 0x74697845                ; Exit
    push esp
    push ebx                       ; kernel32.dll base address
    call edx                       ; GetProc(Exec)
    
    ;Call the ExitProcess function
    xor ecx, ecx                    ; ECX = 0
    push ecx                        ; Return code = 0
    call eax                        ; ExitProcess


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; Si quisieras meter el shellcode en un archivo de C
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

;#include "stdafx.h"
;#include <Windows.h>

;int main()
;{
;	char *shellcode = "\x50\x53\x51\x52\x56\x57\x55\x31\xc9\x64\x8b\x41\x30\x8b\x40\x0c\x8b\x70\x14\xad\x96\xad\x8b\x58\x10\x8b\x53\x3c\x01\xda\x8b\x52\x78\x01\xda\x8b\x72\x20\x01\xde\x31\xc9\x41\xad\x01\xd8\x81\x38\x47\x65\x74\x50\x75\xf4\x81\x78\x04\x72\x6f\x63\x41\x75\xeb\x81\x78\x08\x64\x64\x72\x65\x75\xe2\x8b\x72\x24\x01\xde\x66\x8b\x0c\x4e\x49\x8b\x72\x1c\x01\xde\x8b\x14\x8e\x01\xda\x31\xc9\x53\x52\x51\x68\x61\x72\x79\x41\x68\x4c\x69\x62\x72\x68\x4c\x6f\x61\x64\x54\x53\xff\xd2\x83\xc4\x0c\x59\x50\x51\x66\xb9\x6c\x6c\x51\x68\x33\x32\x2e\x64\x68\x75\x73\x65\x72\x54\xff\xd0\x83\xc4\x10\x8b\x54\x24\x04\x31\xc9\x51\xb9\x6f\x78\x41\x61\x51\x83\x6c\x24\x03\x61\x68\x61\x67\x65\x42\x68\x4d\x65\x73\x73\x54\x50\xff\xd2\x83\xc4\x14\x31\xc9\x51\x68\x4e\x6f\x74\x61\x51\x6a\x40\x31\xd2\x89\xe2\x83\xc2\x08\x52\x52\x51\xff\xd0\x83\xc4\x0c\x5a\x5b\xb9\x65\x73\x73\x61\x51\x83\x6c\x24\x03\x61\x68\x50\x72\x6f\x63\x68\x45\x78\x69\x74\x54\x53\xff\xd2\x31\xc9\x51\xff\xd0";
;
;	// Set memory as executable
;	DWORD old = 0;
;	BOOL ret = VirtualProtect(shellcode, strlen(shellcode), PAGE_EXECUTE_READWRITE, &old);
;
;	// Call the shellcode
;	__asm
;	{
;		jmp shellcode;
;	}
;
;	return 0;
;}




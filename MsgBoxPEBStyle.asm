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
    add esi, ebx                                ; ESI = Ordinals table
    mov cx, [esi + ecx * 2]             ; CX = Number of function
    dec ecx
    mov esi, [edx + 0x1c]               ; ESI = Offset address table
    add esi, ebx                                ; ESI = Address table
    mov edx, [esi + ecx * 4]    ; EDX = Pointer(offset)
    add edx, ebx                                ; EDX = GetProcAddress
    
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
    pop ecx                             ; ECX = 0
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
    ;mov ecx, 0x61786f42                        ; oxa 78 6f 42 65 67 61 73 73 65 4d
    ;push ecx
    ;sub dword [esp + 0x3], 0x61         ; Remove a
    push 0x41786f          ; oxA
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
    push 0x61746f4e             ; Nota 4e 6f 74 61
    push ecx                           ; true
    push 0x40                          ; MessageBox type
    xor edx, edx
    mov edx, esp
    add edx, 0x8
    push edx            ; Nota 4e 6f 74 61
    push edx             ; Nota 4e 6f 74 61
    push ecx
    call eax                            ;MessageBox(0,"","",0x40)

    ;Get ExitProcess function address
    add esp, 0xc                           ; Clean stack
    pop edx                       ; GetProcAddress
    pop ebx                    ; kernel32.dll base address
    mov ecx, 0x61737365                 ; essa
    push ecx
    sub dword [esp + 0x3], 0x61    ; Remove "a"
    push 0x636f7250                               ; Proc
    push 0x74697845                               ; Exit
    push esp
    push ebx                                        ; kernel32.dll base address
    call edx                                        ; GetProc(Exec)
    
    ;Call the ExitProcess function
    xor ecx, ecx                    ; ECX = 0
    push ecx                        ; Return code = 0
    call eax                        ; ExitProcess     

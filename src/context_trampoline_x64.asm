OPTION CASEMAP:NONE

PUBLIC hookkit_site_originals
PUBLIC hookkit_observe_pair
PUBLIC hookkit_observe_entry

.data
ALIGN 8
hookkit_site_originals QWORD 64 DUP(0)
hookkit_observe_pair   QWORD 0
hookkit_observe_entry  QWORD 0

.code

; Stack frame layout (Alloc = 1D8h bytes):
;   [rsp + 000h .. 01Fh] : 32-byte Win64 ABI shadow space
;   [rsp + 020h .. 1AFh] : CapturedRegisters (0x190 bytes)
;     [020h .. 11Fh]     : xmm0..xmm15 (16 * 16 bytes)
;     [120h .. 197h]     : gpr[0..14]  (rax,rcx,rdx,rbx,rbp,rsi,rdi,r8..r15)
;     [198h]             : rflags
;     [1A0h]             : original rsp (at trampoline entry, pointing to return address)
;     [1A8h]             : mxcsr (32-bit)
;     [1ACh]             : x87 FPU control word (zero-extended to 32-bit)
;   [rsp + 1D0h]         : scratch slot for target/return address
XMM_AT   EQU 020h
GPR_AT   EQU 120h
FLAGS_AT EQU 198h
RSP_AT   EQU 1A0h
MXCSR_AT EQU 1A8h
FPUCW_AT EQU 1ACh
SCRATCH_AT EQU 1D0h
FRAME_ALLOC EQU 1D8h

SAVE_STATE MACRO Alloc
    mov [rsp+GPR_AT+000h], rax
    pushfq
    pop rax
    mov [rsp+FLAGS_AT], rax
    cld
    lea rax, [rsp+Alloc]
    mov [rsp+RSP_AT], rax
    mov [rsp+GPR_AT+008h], rcx
    mov [rsp+GPR_AT+010h], rdx
    mov [rsp+GPR_AT+018h], rbx
    mov [rsp+GPR_AT+020h], rbp
    mov [rsp+GPR_AT+028h], rsi
    mov [rsp+GPR_AT+030h], rdi
    mov [rsp+GPR_AT+038h], r8
    mov [rsp+GPR_AT+040h], r9
    mov [rsp+GPR_AT+048h], r10
    mov [rsp+GPR_AT+050h], r11
    mov [rsp+GPR_AT+058h], r12
    mov [rsp+GPR_AT+060h], r13
    mov [rsp+GPR_AT+068h], r14
    mov [rsp+GPR_AT+070h], r15
    movdqu [rsp+XMM_AT+000h], xmm0
    movdqu [rsp+XMM_AT+010h], xmm1
    movdqu [rsp+XMM_AT+020h], xmm2
    movdqu [rsp+XMM_AT+030h], xmm3
    movdqu [rsp+XMM_AT+040h], xmm4
    movdqu [rsp+XMM_AT+050h], xmm5
    movdqu [rsp+XMM_AT+060h], xmm6
    movdqu [rsp+XMM_AT+070h], xmm7
    movdqu [rsp+XMM_AT+080h], xmm8
    movdqu [rsp+XMM_AT+090h], xmm9
    movdqu [rsp+XMM_AT+0A0h], xmm10
    movdqu [rsp+XMM_AT+0B0h], xmm11
    movdqu [rsp+XMM_AT+0C0h], xmm12
    movdqu [rsp+XMM_AT+0D0h], xmm13
    movdqu [rsp+XMM_AT+0E0h], xmm14
    movdqu [rsp+XMM_AT+0F0h], xmm15
    stmxcsr DWORD PTR [rsp+MXCSR_AT]
    mov DWORD PTR [rsp+FPUCW_AT], 0
    fnstcw WORD PTR [rsp+FPUCW_AT]
ENDM

RESTORE_STATE MACRO
    ldmxcsr DWORD PTR [rsp+MXCSR_AT]
    fldcw WORD PTR [rsp+FPUCW_AT]
    movdqu xmm0,  [rsp+XMM_AT+000h]
    movdqu xmm1,  [rsp+XMM_AT+010h]
    movdqu xmm2,  [rsp+XMM_AT+020h]
    movdqu xmm3,  [rsp+XMM_AT+030h]
    movdqu xmm4,  [rsp+XMM_AT+040h]
    movdqu xmm5,  [rsp+XMM_AT+050h]
    movdqu xmm6,  [rsp+XMM_AT+060h]
    movdqu xmm7,  [rsp+XMM_AT+070h]
    movdqu xmm8,  [rsp+XMM_AT+080h]
    movdqu xmm9,  [rsp+XMM_AT+090h]
    movdqu xmm10, [rsp+XMM_AT+0A0h]
    movdqu xmm11, [rsp+XMM_AT+0B0h]
    movdqu xmm12, [rsp+XMM_AT+0C0h]
    movdqu xmm13, [rsp+XMM_AT+0D0h]
    movdqu xmm14, [rsp+XMM_AT+0E0h]
    movdqu xmm15, [rsp+XMM_AT+0F0h]
    mov rcx, [rsp+GPR_AT+008h]
    mov rdx, [rsp+GPR_AT+010h]
    mov rbx, [rsp+GPR_AT+018h]
    mov rbp, [rsp+GPR_AT+020h]
    mov rsi, [rsp+GPR_AT+028h]
    mov rdi, [rsp+GPR_AT+030h]
    mov r8,  [rsp+GPR_AT+038h]
    mov r9,  [rsp+GPR_AT+040h]
    mov r10, [rsp+GPR_AT+048h]
    mov r11, [rsp+GPR_AT+050h]
    mov r12, [rsp+GPR_AT+058h]
    mov r13, [rsp+GPR_AT+060h]
    mov r14, [rsp+GPR_AT+068h]
    mov r15, [rsp+GPR_AT+070h]
    push QWORD PTR [rsp+FLAGS_AT]
    popfq
    mov rax, [rsp+GPR_AT+000h]
ENDM

HOOKKIT_PAIR_TRAMPOLINE MACRO Name, Site, Alloc
    LOCAL skip_entry_obs, skip_orig_before_restore, after_orig, skip_exit_obs
Name PROC FRAME
    lea rsp, [rsp-Alloc]
    .allocstack Alloc
    .endprolog
    SAVE_STATE Alloc
    mov rax, QWORD PTR [hookkit_observe_pair]
    test rax, rax
    jz skip_entry_obs
    mov ecx, Site
    xor edx, edx
    lea r8, [rsp+XMM_AT]
    call rax
skip_entry_obs:
    mov rax, QWORD PTR [hookkit_site_originals + Site*8]
    mov [rsp+SCRATCH_AT], rax
    test rax, rax
    jz skip_orig_before_restore
    RESTORE_STATE
    call QWORD PTR [rsp+SCRATCH_AT]
    jmp after_orig
skip_orig_before_restore:
    RESTORE_STATE
after_orig:
    SAVE_STATE Alloc
    mov rax, QWORD PTR [hookkit_observe_pair]
    test rax, rax
    jz skip_exit_obs
    mov ecx, Site
    mov edx, 1
    lea r8, [rsp+XMM_AT]
    call rax
skip_exit_obs:
    RESTORE_STATE
    mov rsp, [rsp+RSP_AT]
    ret
Name ENDP
ENDM

HOOKKIT_ENTRY_TRAMPOLINE MACRO Name, Site, Alloc
    LOCAL skip_obs, no_orig
Name PROC FRAME
    lea rsp, [rsp-Alloc]
    .allocstack Alloc
    .endprolog
    SAVE_STATE Alloc
    mov rax, QWORD PTR [hookkit_observe_entry]
    test rax, rax
    jz skip_obs
    mov ecx, Site
    lea rdx, [rsp+XMM_AT]
    call rax
skip_obs:
    mov rax, QWORD PTR [hookkit_site_originals + Site*8]
    mov [rsp+SCRATCH_AT], rax
    test rax, rax
    jz no_orig
    RESTORE_STATE
    mov r11, [rsp+SCRATCH_AT]
    mov rsp, [rsp+RSP_AT]
    jmp r11
no_orig:
    RESTORE_STATE
    mov rsp, [rsp+RSP_AT]
    ret
Name ENDP
ENDM

HOOKKIT_PAIR_TRAMPOLINE HookkitPairSite0, 0, FRAME_ALLOC
HOOKKIT_PAIR_TRAMPOLINE HookkitPairSite1, 1, FRAME_ALLOC
HOOKKIT_PAIR_TRAMPOLINE HookkitPairSite2, 2, FRAME_ALLOC
HOOKKIT_PAIR_TRAMPOLINE HookkitPairSite3, 3, FRAME_ALLOC
HOOKKIT_PAIR_TRAMPOLINE HookkitPairSite4, 4, FRAME_ALLOC
HOOKKIT_PAIR_TRAMPOLINE HookkitPairSite5, 5, FRAME_ALLOC
HOOKKIT_PAIR_TRAMPOLINE HookkitPairSite6, 6, FRAME_ALLOC
HOOKKIT_PAIR_TRAMPOLINE HookkitPairSite7, 7, FRAME_ALLOC

HOOKKIT_ENTRY_TRAMPOLINE HookkitEntrySite0, 0, FRAME_ALLOC
HOOKKIT_ENTRY_TRAMPOLINE HookkitEntrySite1, 1, FRAME_ALLOC
HOOKKIT_ENTRY_TRAMPOLINE HookkitEntrySite2, 2, FRAME_ALLOC
HOOKKIT_ENTRY_TRAMPOLINE HookkitEntrySite3, 3, FRAME_ALLOC
HOOKKIT_ENTRY_TRAMPOLINE HookkitEntrySite4, 4, FRAME_ALLOC
HOOKKIT_ENTRY_TRAMPOLINE HookkitEntrySite5, 5, FRAME_ALLOC
HOOKKIT_ENTRY_TRAMPOLINE HookkitEntrySite6, 6, FRAME_ALLOC
HOOKKIT_ENTRY_TRAMPOLINE HookkitEntrySite7, 7, FRAME_ALLOC

END

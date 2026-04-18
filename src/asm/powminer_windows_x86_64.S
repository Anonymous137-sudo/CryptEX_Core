.intel_syntax noprefix
.text
.p2align 4

#define ARG1 rcx
#define ARG2 rdx
#define ARG3 r8
#define ARG4 r9
.globl main
.def main; .scl 2; .type 32; .endef
.set JOB_SIZE, 168
.set RESULT_SIZE, 88
.set CALL_SHADOW_OFF, 0
.set JOB_BUF_OFF, 32
.set RESULT_BUF_OFF, 224
.set PREFIX_SCALAR_OFF, 320
.set CBUF_SCALAR_OFF, 520
.set DBUF_SCALAR_OFF, 560
.set BBUF_SCALAR_OFF, 608
.set PREFIX_VEC_OFF, 832
.set STATE_VEC_OFF, 1632
.set CBUF_VEC_OFF, 2432
.set DBUF_VEC_OFF, 2592
.set BBUF_VEC_OFF, 2752
.set SUFFIXBUF_OFF, 3552
.set STACK_ALLOC, 3592
.set JOB_HEADER_OFFSET, 8
.set JOB_TARGET_OFFSET, 88
.set JOB_START_NONCE_OFFSET, 152
.set JOB_NONCE_STEP_OFFSET, 156
.set JOB_MAX_ITER_OFFSET, 160
.set RESULT_MAGIC_OFFSET, 0
.set RESULT_STATUS_OFFSET, 8
.set RESULT_NONCE_OFFSET, 12
.set RESULT_ITERATIONS_OFFSET, 16
.set RESULT_HASH_OFFSET, 24

.macro THETA_APPLY col, cprev, cnext
    mov rax, qword ptr [rsi + \cnext]
    rol rax, 1
    xor rax, qword ptr [rsi + \cprev]
    xor qword ptr [rdi + \col], rax
    xor qword ptr [rdi + \col + 40], rax
    xor qword ptr [rdi + \col + 80], rax
    xor qword ptr [rdi + \col + 120], rax
    xor qword ptr [rdi + \col + 160], rax
.endm

.macro ROT_STORE src_off, dst_off, amt
    vmovdqu ymm0, ymmword ptr [r12 + \src_off]
    .if \amt == 0
        vmovdqu ymmword ptr [r15 + \dst_off], ymm0
    .else
        vpsllq ymm1, ymm0, \amt
        vpsrlq ymm0, ymm0, (64 - \amt)
        vpor ymm0, ymm0, ymm1
        vmovdqu ymmword ptr [r15 + \dst_off], ymm0
    .endif
.endm

main:
    mov r12d, ecx
    mov r13, rdx
    push rbp
    push rbx
    push r12
    push r13
    push r14
    push r15
    push rdi
    push rsi
    sub rsp, STACK_ALLOC
    mov rbp, r13

    cmp r12d, 3
    je Lhave_args
    mov eax, 1
    jmp Lmain_epilogue

Lhave_args:
    mov ARG1, qword ptr [rbp + 8]
    lea ARG2, [rip + Lmode_rb]
    call fopen
    test rax, rax
    jz Lfail
    mov r14, rax

    lea ARG1, [rsp + JOB_BUF_OFF]
    mov ARG2, 1
    mov ARG3, JOB_SIZE
    mov ARG4, r14
    call fread
    cmp rax, JOB_SIZE
    je Lclose_job
    mov ARG1, r14
    call fclose
    jmp Lfail

Lclose_job:
    mov ARG1, r14
    call fclose

    lea ARG1, [rsp + JOB_BUF_OFF]
    lea ARG2, [rip + Ljob_magic]
    mov ARG3, 8
    call memcmp
    test eax, eax
    je Lmagic_ok
    jmp Lfail

Lmagic_ok:
    lea rdi, [rsp + RESULT_BUF_OFF]
    xor eax, eax
    mov ecx, 12
    rep stosq

    mov rax, qword ptr [rip + Lresult_magic]
    mov qword ptr [rsp + RESULT_BUF_OFF + RESULT_MAGIC_OFFSET], rax

    lea rdi, [rsp + PREFIX_SCALAR_OFF]
    xor eax, eax
    mov ecx, 25
    rep stosq

    lea rsi, [rsp + JOB_BUF_OFF + JOB_HEADER_OFFSET]
    lea rdi, [rsp + PREFIX_SCALAR_OFF]
    mov ecx, 9
    rep movsq

    lea rdi, [rsp + PREFIX_SCALAR_OFF]
    lea rsi, [rsp + CBUF_SCALAR_OFF]
    lea rdx, [rsp + DBUF_SCALAR_OFF]
    lea rcx, [rsp + BBUF_SCALAR_OFF]
    call Lkeccakf_scalar

    call Lcpu_supports_avx2
    test eax, eax
    jz Lfail

    lea rsi, [rsp + PREFIX_SCALAR_OFF]
    lea rdi, [rsp + PREFIX_VEC_OFF]
    mov ecx, 25
Ldup_prefix_loop:
    vbroadcastsd ymm0, qword ptr [rsi]
    vmovdqu ymmword ptr [rdi], ymm0
    add rsi, 8
    add rdi, 32
    dec ecx
    jne Ldup_prefix_loop

    lea r14, [rsp + JOB_BUF_OFF + JOB_TARGET_OFFSET]
    mov r15d, dword ptr [rsp + JOB_BUF_OFF + JOB_HEADER_OFFSET + 72]
    mov ebx, dword ptr [rsp + JOB_BUF_OFF + JOB_NONCE_STEP_OFFSET]
    test ebx, ebx
    jne Lstep_ok
    mov ebx, 1
Lstep_ok:
    mov r12d, dword ptr [rsp + JOB_BUF_OFF + JOB_START_NONCE_OFFSET]
    mov r13, qword ptr [rsp + JOB_BUF_OFF + JOB_MAX_ITER_OFFSET]
    xor r11, r11

Lmine_loop:
    test r13, r13
    jz Ldo_batch
    cmp r11, r13
    jae Lwrite_result

Ldo_batch:
    lea rsi, [rsp + PREFIX_VEC_OFF]
    lea rdi, [rsp + STATE_VEC_OFF]
    mov ecx, 25
Lcopy_prefix_vec:
    vmovdqu ymm0, ymmword ptr [rsi]
    vmovdqu ymmword ptr [rdi], ymm0
    add rsi, 32
    add rdi, 32
    dec ecx
    jne Lcopy_prefix_vec

    mov eax, r15d
    mov edx, r12d
    shl rdx, 32
    or rax, rdx
    mov qword ptr [rsp + SUFFIXBUF_OFF + 0], rax

    mov eax, r15d
    lea edx, [r12 + rbx]
    shl rdx, 32
    or rax, rdx
    mov qword ptr [rsp + SUFFIXBUF_OFF + 8], rax

    mov eax, r15d
    lea edx, [r12 + rbx*2]
    shl rdx, 32
    or rax, rdx
    mov qword ptr [rsp + SUFFIXBUF_OFF + 16], rax

    mov eax, ebx
    lea edx, [r12 + rbx*2]
    add edx, eax
    mov eax, r15d
    shl rdx, 32
    or rax, rdx
    mov qword ptr [rsp + SUFFIXBUF_OFF + 24], rax

    vmovdqu ymm0, ymmword ptr [rsp + SUFFIXBUF_OFF]
    vpxor ymm0, ymm0, ymmword ptr [rsp + STATE_VEC_OFF + 0]
    vmovdqu ymmword ptr [rsp + STATE_VEC_OFF + 0], ymm0

    vpbroadcastq ymm1, qword ptr [rip + Lpad_suffix]
    vmovdqu ymm0, ymmword ptr [rsp + STATE_VEC_OFF + 32]
    vpxor ymm0, ymm0, ymm1
    vmovdqu ymmword ptr [rsp + STATE_VEC_OFF + 32], ymm0

    vpbroadcastq ymm1, qword ptr [rip + Lfinal_bit]
    vmovdqu ymm0, ymmword ptr [rsp + STATE_VEC_OFF + 256]
    vpxor ymm0, ymm0, ymm1
    vmovdqu ymmword ptr [rsp + STATE_VEC_OFF + 256], ymm0

    lea rdi, [rsp + STATE_VEC_OFF]
    lea rsi, [rsp + CBUF_VEC_OFF]
    lea rdx, [rsp + DBUF_VEC_OFF]
    lea rcx, [rsp + BBUF_VEC_OFF]
    call Lkeccakf4x_avx2

    mov r9, 4
    test r13, r13
    jz Lhave_remaining
    mov r9, r13
    sub r9, r11
    cmp r9, 4
    jbe Lhave_remaining
    mov r9, 4
Lhave_remaining:

    cmp r9, 1
    jb Lno_match
    lea rsi, [rsp + STATE_VEC_OFF + 0]
    mov rdi, r14
    mov ecx, 8
Lcmp_lane0:
    mov rax, qword ptr [rsi]
    bswap rax
    mov rdx, qword ptr [rdi]
    bswap rdx
    cmp rax, rdx
    jb Lfound_lane0
    ja Llane1_check
    add rsi, 32
    add rdi, 8
    dec ecx
    jne Lcmp_lane0
    jmp Lfound_lane0

Llane1_check:
    cmp r9, 2
    jb Lno_match
    lea rsi, [rsp + STATE_VEC_OFF + 8]
    mov rdi, r14
    mov ecx, 8
Lcmp_lane1:
    mov rax, qword ptr [rsi]
    bswap rax
    mov rdx, qword ptr [rdi]
    bswap rdx
    cmp rax, rdx
    jb Lfound_lane1
    ja Llane2_check
    add rsi, 32
    add rdi, 8
    dec ecx
    jne Lcmp_lane1
    jmp Lfound_lane1

Llane2_check:
    cmp r9, 3
    jb Lno_match
    lea rsi, [rsp + STATE_VEC_OFF + 16]
    mov rdi, r14
    mov ecx, 8
Lcmp_lane2:
    mov rax, qword ptr [rsi]
    bswap rax
    mov rdx, qword ptr [rdi]
    bswap rdx
    cmp rax, rdx
    jb Lfound_lane2
    ja Llane3_check
    add rsi, 32
    add rdi, 8
    dec ecx
    jne Lcmp_lane2
    jmp Lfound_lane2

Llane3_check:
    cmp r9, 4
    jb Lno_match
    lea rsi, [rsp + STATE_VEC_OFF + 24]
    mov rdi, r14
    mov ecx, 8
Lcmp_lane3:
    mov rax, qword ptr [rsi]
    bswap rax
    mov rdx, qword ptr [rdi]
    bswap rdx
    cmp rax, rdx
    jb Lfound_lane3
    ja Lno_match
    add rsi, 32
    add rdi, 8
    dec ecx
    jne Lcmp_lane3
    jmp Lfound_lane3

Lno_match:
    add r11, r9
    mov eax, ebx
    imul eax, r9d
    add r12d, eax
    jmp Lmine_loop

Lfound_lane0:
    mov dword ptr [rsp + RESULT_BUF_OFF + RESULT_STATUS_OFFSET], 1
    mov dword ptr [rsp + RESULT_BUF_OFF + RESULT_NONCE_OFFSET], r12d
    lea rax, [r11 + 1]
    mov qword ptr [rsp + RESULT_BUF_OFF + RESULT_ITERATIONS_OFFSET], rax
    lea rsi, [rsp + STATE_VEC_OFF + 0]
    lea rdi, [rsp + RESULT_BUF_OFF + RESULT_HASH_OFFSET]
    mov ecx, 8
Lcopy_hash0:
    mov rax, qword ptr [rsi]
    mov qword ptr [rdi], rax
    add rsi, 32
    add rdi, 8
    dec ecx
    jne Lcopy_hash0
    jmp Lwrite_result

Lfound_lane1:
    mov dword ptr [rsp + RESULT_BUF_OFF + RESULT_STATUS_OFFSET], 1
    mov eax, r12d
    add eax, ebx
    mov dword ptr [rsp + RESULT_BUF_OFF + RESULT_NONCE_OFFSET], eax
    lea rax, [r11 + 2]
    mov qword ptr [rsp + RESULT_BUF_OFF + RESULT_ITERATIONS_OFFSET], rax
    lea rsi, [rsp + STATE_VEC_OFF + 8]
    lea rdi, [rsp + RESULT_BUF_OFF + RESULT_HASH_OFFSET]
    mov ecx, 8
Lcopy_hash1:
    mov rax, qword ptr [rsi]
    mov qword ptr [rdi], rax
    add rsi, 32
    add rdi, 8
    dec ecx
    jne Lcopy_hash1
    jmp Lwrite_result

Lfound_lane2:
    mov dword ptr [rsp + RESULT_BUF_OFF + RESULT_STATUS_OFFSET], 1
    lea eax, [r12 + rbx*2]
    mov dword ptr [rsp + RESULT_BUF_OFF + RESULT_NONCE_OFFSET], eax
    lea rax, [r11 + 3]
    mov qword ptr [rsp + RESULT_BUF_OFF + RESULT_ITERATIONS_OFFSET], rax
    lea rsi, [rsp + STATE_VEC_OFF + 16]
    lea rdi, [rsp + RESULT_BUF_OFF + RESULT_HASH_OFFSET]
    mov ecx, 8
Lcopy_hash2:
    mov rax, qword ptr [rsi]
    mov qword ptr [rdi], rax
    add rsi, 32
    add rdi, 8
    dec ecx
    jne Lcopy_hash2
    jmp Lwrite_result

Lfound_lane3:
    mov dword ptr [rsp + RESULT_BUF_OFF + RESULT_STATUS_OFFSET], 1
    mov eax, ebx
    lea edx, [r12 + rbx*2]
    add edx, eax
    mov dword ptr [rsp + RESULT_BUF_OFF + RESULT_NONCE_OFFSET], edx
    lea rax, [r11 + 4]
    mov qword ptr [rsp + RESULT_BUF_OFF + RESULT_ITERATIONS_OFFSET], rax
    lea rsi, [rsp + STATE_VEC_OFF + 24]
    lea rdi, [rsp + RESULT_BUF_OFF + RESULT_HASH_OFFSET]
    mov ecx, 8
Lcopy_hash3:
    mov rax, qword ptr [rsi]
    mov qword ptr [rdi], rax
    add rsi, 32
    add rdi, 8
    dec ecx
    jne Lcopy_hash3

Lwrite_result:
    cmp dword ptr [rsp + RESULT_BUF_OFF + RESULT_STATUS_OFFSET], 0
    jne Literations_done
    mov qword ptr [rsp + RESULT_BUF_OFF + RESULT_ITERATIONS_OFFSET], r11
Literations_done:
    vzeroupper
    mov ARG1, qword ptr [rbp + 16]
    lea ARG2, [rip + Lmode_wb]
    call fopen
    test rax, rax
    jz Lfail
    mov r14, rax

    lea ARG1, [rsp + RESULT_BUF_OFF]
    mov ARG2, 1
    mov ARG3, RESULT_SIZE
    mov ARG4, r14
    call fwrite
    mov ARG1, r14
    call fclose
    xor eax, eax
    jmp Lmain_epilogue

Lfail:
    mov eax, 1

Lmain_epilogue:
    add rsp, STACK_ALLOC
    pop rsi
    pop rdi
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret

Lkeccakf_scalar:
    push rbx
    push r12
    push r13
    push r14
    push r15
    lea rbx, [rip + Lround_constants]
    mov r12, rcx
    lea r13, [rip + Lrho_left]
    lea r14, [rip + Lpi_dest]
    xor r15d, r15d
Lround_loop_scalar:
    mov rax, qword ptr [rdi + 0]
    xor rax, qword ptr [rdi + 40]
    xor rax, qword ptr [rdi + 80]
    xor rax, qword ptr [rdi + 120]
    xor rax, qword ptr [rdi + 160]
    mov qword ptr [rsi + 0], rax

    mov rax, qword ptr [rdi + 8]
    xor rax, qword ptr [rdi + 48]
    xor rax, qword ptr [rdi + 88]
    xor rax, qword ptr [rdi + 128]
    xor rax, qword ptr [rdi + 168]
    mov qword ptr [rsi + 8], rax

    mov rax, qword ptr [rdi + 16]
    xor rax, qword ptr [rdi + 56]
    xor rax, qword ptr [rdi + 96]
    xor rax, qword ptr [rdi + 136]
    xor rax, qword ptr [rdi + 176]
    mov qword ptr [rsi + 16], rax

    mov rax, qword ptr [rdi + 24]
    xor rax, qword ptr [rdi + 64]
    xor rax, qword ptr [rdi + 104]
    xor rax, qword ptr [rdi + 144]
    xor rax, qword ptr [rdi + 184]
    mov qword ptr [rsi + 24], rax

    mov rax, qword ptr [rdi + 32]
    xor rax, qword ptr [rdi + 72]
    xor rax, qword ptr [rdi + 112]
    xor rax, qword ptr [rdi + 152]
    xor rax, qword ptr [rdi + 192]
    mov qword ptr [rsi + 32], rax

    THETA_APPLY 0, 32, 8
    THETA_APPLY 8, 0, 16
    THETA_APPLY 16, 8, 24
    THETA_APPLY 24, 16, 32
    THETA_APPLY 32, 24, 0

    xor r8d, r8d
Lrhopi_loop_scalar:
    mov rax, qword ptr [rdi + r8*8]
    movzx ecx, byte ptr [r13 + r8]
    rol rax, cl
    movzx edx, byte ptr [r14 + r8]
    mov qword ptr [r12 + rdx*8], rax
    inc r8
    cmp r8d, 25
    jne Lrhopi_loop_scalar

    xor eax, eax
Lchi_row_loop_scalar:
    mov r8,  qword ptr [r12 + rax + 0]
    mov r9,  qword ptr [r12 + rax + 8]
    mov r10, qword ptr [r12 + rax + 16]
    mov r11, qword ptr [r12 + rax + 24]
    mov rdx, qword ptr [r12 + rax + 32]

    mov rcx, r9
    not rcx
    and rcx, r10
    xor rcx, r8
    mov qword ptr [rdi + rax + 0], rcx

    mov rcx, r10
    not rcx
    and rcx, r11
    xor rcx, r9
    mov qword ptr [rdi + rax + 8], rcx

    mov rcx, r11
    not rcx
    and rcx, rdx
    xor rcx, r10
    mov qword ptr [rdi + rax + 16], rcx

    mov rcx, rdx
    not rcx
    and rcx, r8
    xor rcx, r11
    mov qword ptr [rdi + rax + 24], rcx

    mov rcx, r8
    not rcx
    and rcx, r9
    xor rcx, rdx
    mov qword ptr [rdi + rax + 32], rcx

    add eax, 40
    cmp eax, 200
    jne Lchi_row_loop_scalar

    mov rax, qword ptr [rbx + r15*8]
    xor qword ptr [rdi + 0], rax

    inc r15d
    cmp r15d, 24
    jne Lround_loop_scalar

    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

Lcpu_supports_avx2:
    push rbx
    mov eax, 1
    cpuid
    bt ecx, 27
    jnc Lno_avx2
    bt ecx, 28
    jnc Lno_avx2
    xor ecx, ecx
    xgetbv
    and eax, 6
    cmp eax, 6
    jne Lno_avx2
    mov eax, 7
    xor ecx, ecx
    cpuid
    bt ebx, 5
    jnc Lno_avx2
    mov eax, 1
    pop rbx
    ret

Lno_avx2:
    xor eax, eax
    pop rbx
    ret

Lkeccakf4x_avx2:
    push rbx
    push r12
    push r13
    push r14
    push r15
    lea rbx, [rip + Lround_constants]
    mov r12, rdi
    mov r13, rsi
    mov r14, rdx
    mov r15, rcx
    xor eax, eax
Lround_loop_vec:
    vmovdqu ymm0,  ymmword ptr [r12 + 0]
    vpxor   ymm0,  ymm0, ymmword ptr [r12 + 160]
    vpxor   ymm0,  ymm0, ymmword ptr [r12 + 320]
    vpxor   ymm0,  ymm0, ymmword ptr [r12 + 480]
    vpxor   ymm0,  ymm0, ymmword ptr [r12 + 640]

    vmovdqu ymm1,  ymmword ptr [r12 + 32]
    vpxor   ymm1,  ymm1, ymmword ptr [r12 + 192]
    vpxor   ymm1,  ymm1, ymmword ptr [r12 + 352]
    vpxor   ymm1,  ymm1, ymmword ptr [r12 + 512]
    vpxor   ymm1,  ymm1, ymmword ptr [r12 + 672]

    vmovdqu ymm2,  ymmword ptr [r12 + 64]
    vpxor   ymm2,  ymm2, ymmword ptr [r12 + 224]
    vpxor   ymm2,  ymm2, ymmword ptr [r12 + 384]
    vpxor   ymm2,  ymm2, ymmword ptr [r12 + 544]
    vpxor   ymm2,  ymm2, ymmword ptr [r12 + 704]

    vmovdqu ymm3,  ymmword ptr [r12 + 96]
    vpxor   ymm3,  ymm3, ymmword ptr [r12 + 256]
    vpxor   ymm3,  ymm3, ymmword ptr [r12 + 416]
    vpxor   ymm3,  ymm3, ymmword ptr [r12 + 576]
    vpxor   ymm3,  ymm3, ymmword ptr [r12 + 736]

    vmovdqu ymm4,  ymmword ptr [r12 + 128]
    vpxor   ymm4,  ymm4, ymmword ptr [r12 + 288]
    vpxor   ymm4,  ymm4, ymmword ptr [r12 + 448]
    vpxor   ymm4,  ymm4, ymmword ptr [r12 + 608]
    vpxor   ymm4,  ymm4, ymmword ptr [r12 + 768]

    vmovdqu ymmword ptr [r13 + 0],   ymm0
    vmovdqu ymmword ptr [r13 + 32],  ymm1
    vmovdqu ymmword ptr [r13 + 64],  ymm2
    vmovdqu ymmword ptr [r13 + 96],  ymm3
    vmovdqu ymmword ptr [r13 + 128], ymm4

    vpsllq ymm10, ymm1, 1
    vpsrlq ymm11, ymm1, 63
    vpor   ymm5, ymm10, ymm11
    vpxor  ymm5, ymm5, ymm4

    vpsllq ymm10, ymm2, 1
    vpsrlq ymm11, ymm2, 63
    vpor   ymm6, ymm10, ymm11
    vpxor  ymm6, ymm6, ymm0

    vpsllq ymm10, ymm3, 1
    vpsrlq ymm11, ymm3, 63
    vpor   ymm7, ymm10, ymm11
    vpxor  ymm7, ymm7, ymm1

    vpsllq ymm10, ymm4, 1
    vpsrlq ymm11, ymm4, 63
    vpor   ymm8, ymm10, ymm11
    vpxor  ymm8, ymm8, ymm2

    vpsllq ymm10, ymm0, 1
    vpsrlq ymm11, ymm0, 63
    vpor   ymm9, ymm10, ymm11
    vpxor  ymm9, ymm9, ymm3

    vmovdqu ymmword ptr [r14 + 0],   ymm5
    vmovdqu ymmword ptr [r14 + 32],  ymm6
    vmovdqu ymmword ptr [r14 + 64],  ymm7
    vmovdqu ymmword ptr [r14 + 96],  ymm8
    vmovdqu ymmword ptr [r14 + 128], ymm9

    vmovdqu ymm10, ymmword ptr [r12 + 0]
    vpxor   ymm10, ymm10, ymm5
    vmovdqu ymmword ptr [r12 + 0], ymm10
    vmovdqu ymm10, ymmword ptr [r12 + 160]
    vpxor   ymm10, ymm10, ymm5
    vmovdqu ymmword ptr [r12 + 160], ymm10
    vmovdqu ymm10, ymmword ptr [r12 + 320]
    vpxor   ymm10, ymm10, ymm5
    vmovdqu ymmword ptr [r12 + 320], ymm10
    vmovdqu ymm10, ymmword ptr [r12 + 480]
    vpxor   ymm10, ymm10, ymm5
    vmovdqu ymmword ptr [r12 + 480], ymm10
    vmovdqu ymm10, ymmword ptr [r12 + 640]
    vpxor   ymm10, ymm10, ymm5
    vmovdqu ymmword ptr [r12 + 640], ymm10

    vmovdqu ymm10, ymmword ptr [r12 + 32]
    vpxor   ymm10, ymm10, ymm6
    vmovdqu ymmword ptr [r12 + 32], ymm10
    vmovdqu ymm10, ymmword ptr [r12 + 192]
    vpxor   ymm10, ymm10, ymm6
    vmovdqu ymmword ptr [r12 + 192], ymm10
    vmovdqu ymm10, ymmword ptr [r12 + 352]
    vpxor   ymm10, ymm10, ymm6
    vmovdqu ymmword ptr [r12 + 352], ymm10
    vmovdqu ymm10, ymmword ptr [r12 + 512]
    vpxor   ymm10, ymm10, ymm6
    vmovdqu ymmword ptr [r12 + 512], ymm10
    vmovdqu ymm10, ymmword ptr [r12 + 672]
    vpxor   ymm10, ymm10, ymm6
    vmovdqu ymmword ptr [r12 + 672], ymm10

    vmovdqu ymm10, ymmword ptr [r12 + 64]
    vpxor   ymm10, ymm10, ymm7
    vmovdqu ymmword ptr [r12 + 64], ymm10
    vmovdqu ymm10, ymmword ptr [r12 + 224]
    vpxor   ymm10, ymm10, ymm7
    vmovdqu ymmword ptr [r12 + 224], ymm10
    vmovdqu ymm10, ymmword ptr [r12 + 384]
    vpxor   ymm10, ymm10, ymm7
    vmovdqu ymmword ptr [r12 + 384], ymm10
    vmovdqu ymm10, ymmword ptr [r12 + 544]
    vpxor   ymm10, ymm10, ymm7
    vmovdqu ymmword ptr [r12 + 544], ymm10
    vmovdqu ymm10, ymmword ptr [r12 + 704]
    vpxor   ymm10, ymm10, ymm7
    vmovdqu ymmword ptr [r12 + 704], ymm10

    vmovdqu ymm10, ymmword ptr [r12 + 96]
    vpxor   ymm10, ymm10, ymm8
    vmovdqu ymmword ptr [r12 + 96], ymm10
    vmovdqu ymm10, ymmword ptr [r12 + 256]
    vpxor   ymm10, ymm10, ymm8
    vmovdqu ymmword ptr [r12 + 256], ymm10
    vmovdqu ymm10, ymmword ptr [r12 + 416]
    vpxor   ymm10, ymm10, ymm8
    vmovdqu ymmword ptr [r12 + 416], ymm10
    vmovdqu ymm10, ymmword ptr [r12 + 576]
    vpxor   ymm10, ymm10, ymm8
    vmovdqu ymmword ptr [r12 + 576], ymm10
    vmovdqu ymm10, ymmword ptr [r12 + 736]
    vpxor   ymm10, ymm10, ymm8
    vmovdqu ymmword ptr [r12 + 736], ymm10

    vmovdqu ymm10, ymmword ptr [r12 + 128]
    vpxor   ymm10, ymm10, ymm9
    vmovdqu ymmword ptr [r12 + 128], ymm10
    vmovdqu ymm10, ymmword ptr [r12 + 288]
    vpxor   ymm10, ymm10, ymm9
    vmovdqu ymmword ptr [r12 + 288], ymm10
    vmovdqu ymm10, ymmword ptr [r12 + 448]
    vpxor   ymm10, ymm10, ymm9
    vmovdqu ymmword ptr [r12 + 448], ymm10
    vmovdqu ymm10, ymmword ptr [r12 + 608]
    vpxor   ymm10, ymm10, ymm9
    vmovdqu ymmword ptr [r12 + 608], ymm10
    vmovdqu ymm10, ymmword ptr [r12 + 768]
    vpxor   ymm10, ymm10, ymm9
    vmovdqu ymmword ptr [r12 + 768], ymm10

    ROT_STORE 0,   0,   0
    ROT_STORE 32,  320, 1
    ROT_STORE 64,  640, 62
    ROT_STORE 96,  160, 28
    ROT_STORE 128, 480, 27
    ROT_STORE 160, 512, 36
    ROT_STORE 192, 32,  44
    ROT_STORE 224, 352, 6
    ROT_STORE 256, 672, 55
    ROT_STORE 288, 192, 20
    ROT_STORE 320, 224, 3
    ROT_STORE 352, 544, 10
    ROT_STORE 384, 64,  43
    ROT_STORE 416, 384, 25
    ROT_STORE 448, 704, 39
    ROT_STORE 480, 736, 41
    ROT_STORE 512, 256, 45
    ROT_STORE 544, 576, 15
    ROT_STORE 576, 96,  21
    ROT_STORE 608, 416, 8
    ROT_STORE 640, 448, 18
    ROT_STORE 672, 768, 2
    ROT_STORE 704, 288, 61
    ROT_STORE 736, 608, 56
    ROT_STORE 768, 128, 14

    vmovdqu ymm0, ymmword ptr [r15 + 0]
    vmovdqu ymm1, ymmword ptr [r15 + 32]
    vmovdqu ymm2, ymmword ptr [r15 + 64]
    vmovdqu ymm3, ymmword ptr [r15 + 96]
    vmovdqu ymm4, ymmword ptr [r15 + 128]
    vpandn  ymm5, ymm1, ymm2
    vpxor   ymm5, ymm5, ymm0
    vmovdqu ymmword ptr [r12 + 0], ymm5
    vpandn  ymm5, ymm2, ymm3
    vpxor   ymm5, ymm5, ymm1
    vmovdqu ymmword ptr [r12 + 32], ymm5
    vpandn  ymm5, ymm3, ymm4
    vpxor   ymm5, ymm5, ymm2
    vmovdqu ymmword ptr [r12 + 64], ymm5
    vpandn  ymm5, ymm4, ymm0
    vpxor   ymm5, ymm5, ymm3
    vmovdqu ymmword ptr [r12 + 96], ymm5
    vpandn  ymm5, ymm0, ymm1
    vpxor   ymm5, ymm5, ymm4
    vmovdqu ymmword ptr [r12 + 128], ymm5

    vmovdqu ymm0, ymmword ptr [r15 + 160]
    vmovdqu ymm1, ymmword ptr [r15 + 192]
    vmovdqu ymm2, ymmword ptr [r15 + 224]
    vmovdqu ymm3, ymmword ptr [r15 + 256]
    vmovdqu ymm4, ymmword ptr [r15 + 288]
    vpandn  ymm5, ymm1, ymm2
    vpxor   ymm5, ymm5, ymm0
    vmovdqu ymmword ptr [r12 + 160], ymm5
    vpandn  ymm5, ymm2, ymm3
    vpxor   ymm5, ymm5, ymm1
    vmovdqu ymmword ptr [r12 + 192], ymm5
    vpandn  ymm5, ymm3, ymm4
    vpxor   ymm5, ymm5, ymm2
    vmovdqu ymmword ptr [r12 + 224], ymm5
    vpandn  ymm5, ymm4, ymm0
    vpxor   ymm5, ymm5, ymm3
    vmovdqu ymmword ptr [r12 + 256], ymm5
    vpandn  ymm5, ymm0, ymm1
    vpxor   ymm5, ymm5, ymm4
    vmovdqu ymmword ptr [r12 + 288], ymm5

    vmovdqu ymm0, ymmword ptr [r15 + 320]
    vmovdqu ymm1, ymmword ptr [r15 + 352]
    vmovdqu ymm2, ymmword ptr [r15 + 384]
    vmovdqu ymm3, ymmword ptr [r15 + 416]
    vmovdqu ymm4, ymmword ptr [r15 + 448]
    vpandn  ymm5, ymm1, ymm2
    vpxor   ymm5, ymm5, ymm0
    vmovdqu ymmword ptr [r12 + 320], ymm5
    vpandn  ymm5, ymm2, ymm3
    vpxor   ymm5, ymm5, ymm1
    vmovdqu ymmword ptr [r12 + 352], ymm5
    vpandn  ymm5, ymm3, ymm4
    vpxor   ymm5, ymm5, ymm2
    vmovdqu ymmword ptr [r12 + 384], ymm5
    vpandn  ymm5, ymm4, ymm0
    vpxor   ymm5, ymm5, ymm3
    vmovdqu ymmword ptr [r12 + 416], ymm5
    vpandn  ymm5, ymm0, ymm1
    vpxor   ymm5, ymm5, ymm4
    vmovdqu ymmword ptr [r12 + 448], ymm5

    vmovdqu ymm0, ymmword ptr [r15 + 480]
    vmovdqu ymm1, ymmword ptr [r15 + 512]
    vmovdqu ymm2, ymmword ptr [r15 + 544]
    vmovdqu ymm3, ymmword ptr [r15 + 576]
    vmovdqu ymm4, ymmword ptr [r15 + 608]
    vpandn  ymm5, ymm1, ymm2
    vpxor   ymm5, ymm5, ymm0
    vmovdqu ymmword ptr [r12 + 480], ymm5
    vpandn  ymm5, ymm2, ymm3
    vpxor   ymm5, ymm5, ymm1
    vmovdqu ymmword ptr [r12 + 512], ymm5
    vpandn  ymm5, ymm3, ymm4
    vpxor   ymm5, ymm5, ymm2
    vmovdqu ymmword ptr [r12 + 544], ymm5
    vpandn  ymm5, ymm4, ymm0
    vpxor   ymm5, ymm5, ymm3
    vmovdqu ymmword ptr [r12 + 576], ymm5
    vpandn  ymm5, ymm0, ymm1
    vpxor   ymm5, ymm5, ymm4
    vmovdqu ymmword ptr [r12 + 608], ymm5

    vmovdqu ymm0, ymmword ptr [r15 + 640]
    vmovdqu ymm1, ymmword ptr [r15 + 672]
    vmovdqu ymm2, ymmword ptr [r15 + 704]
    vmovdqu ymm3, ymmword ptr [r15 + 736]
    vmovdqu ymm4, ymmword ptr [r15 + 768]
    vpandn  ymm5, ymm1, ymm2
    vpxor   ymm5, ymm5, ymm0
    vmovdqu ymmword ptr [r12 + 640], ymm5
    vpandn  ymm5, ymm2, ymm3
    vpxor   ymm5, ymm5, ymm1
    vmovdqu ymmword ptr [r12 + 672], ymm5
    vpandn  ymm5, ymm3, ymm4
    vpxor   ymm5, ymm5, ymm2
    vmovdqu ymmword ptr [r12 + 704], ymm5
    vpandn  ymm5, ymm4, ymm0
    vpxor   ymm5, ymm5, ymm3
    vmovdqu ymmword ptr [r12 + 736], ymm5
    vpandn  ymm5, ymm0, ymm1
    vpxor   ymm5, ymm5, ymm4
    vmovdqu ymmword ptr [r12 + 768], ymm5

    vpbroadcastq ymm5, qword ptr [rbx + rax*8]
    vmovdqu ymm0, ymmword ptr [r12 + 0]
    vpxor   ymm0, ymm0, ymm5
    vmovdqu ymmword ptr [r12 + 0], ymm0

    inc eax
    cmp eax, 24
    jne Lround_loop_vec

    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

.section .rdata,"dr"
Lmode_rb:
    .asciz "rb"
Lmode_wb:
    .asciz "wb"
Ljob_magic:
    .ascii "CRXPOW2!"
Lresult_magic:
    .ascii "CRXRES2!"
Lpad_suffix:
    .quad 0x0000000000000006
Lfinal_bit:
    .quad 0x8000000000000000
Lrho_left:
    .byte 0,1,62,28,27,36,44,6,55,20,3,10,43,25,39,41,45,15,21,8,18,2,61,56,14
Lpi_dest:
    .byte 0,10,20,5,15,16,1,11,21,6,7,17,2,12,22,23,8,18,3,13,14,24,9,19,4
    .byte 0,0,0,0,0,0,0
.p2align 3
Lround_constants:
    .quad 0x0000000000000001
    .quad 0x0000000000008082
    .quad 0x800000000000808a
    .quad 0x8000000080008000
    .quad 0x000000000000808b
    .quad 0x0000000080000001
    .quad 0x8000000080008081
    .quad 0x8000000000008009
    .quad 0x000000000000008a
    .quad 0x0000000000000088
    .quad 0x0000000080008009
    .quad 0x000000008000000a
    .quad 0x000000008000808b
    .quad 0x800000000000008b
    .quad 0x8000000000008089
    .quad 0x8000000000008003
    .quad 0x8000000000008002
    .quad 0x8000000000000080
    .quad 0x000000000000800a
    .quad 0x800000008000000a
    .quad 0x8000000080008081
    .quad 0x8000000000008080
    .quad 0x0000000080000001
    .quad 0x8000000080008008

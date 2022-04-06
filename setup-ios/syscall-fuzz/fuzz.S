.align 4
.global _fuzz_is_in_afl
_fuzz_is_in_afl:
    hint #0x30
    cmp x0, 0
    cset x0, ne
    ret

.align 4
.global _fuzz_set_thread
_fuzz_set_thread:
    hint #0x31
    ret

.align 4
.global _fuzzread
_fuzzread:
    stp x24, x23, [sp, -0x40]!
    stp x22, x21, [sp, 0x10]
    stp x20, x19, [sp, 0x20]
    stp x29, x30, [sp, 0x30]
    add x29, sp, 0x30
    mov x19, x0
    mov x20, x1
    mov x21, x2
    mov x22, #0
1:
    cmp x21, 0
    b.eq 1f
    mov x0, x19
    mov x1, x20
    mov x2, x21
    hint #0x32
    cmp x0, #0
    b.le 1f
    add x20, x20, x0
    add x22, x22, x0
    sub x21, x21, x0
    b 1b   
1:
    mov x0, x22
    ldp x29, x30, [sp, 0x30]
    ldp x20, x19, [sp, 0x20]
    ldp x22, x21, [sp, 0x10]
    ldp x24, x23, [sp], 0x40
    ret

.align 4
.global _fuzz_vm_stop
_fuzz_vm_stop:
    hint #0x33
    ret

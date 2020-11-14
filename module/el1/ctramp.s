    .align 4
    .globl _main

; "ctramp": execute this code to mark the compiled C code as executable before
; br to it
;
; we replaced an _enosys syscall with the address of this code, and because
; of that, we can clobber x3, x4, x5, x6, and x7
_main:
    ret
    ret

/* #include <stdint.h> */

/* ERET to EL1, execute some code, then issue an SMC */
static void el1_test(void){

}

__attribute__ ((noreturn)) void xnuspy_el3_entry(void *bootargs,
        void *entrypoint){
    /* asm volatile("mrs x2, CurrentEL"); */
    /* asm volatile("mrs x3, VBAR_EL3"); */

    volatile char *a = (volatile char *)0x41414141;
    *a = 0;
    asm volatile("b .");
    __builtin_unreachable();
}

/* See src/boot/jump_to_image.S from pongoOS source. We've been called from
 * jump_to_image_extended. For some reason, the second argument is put inside
 * x8 and x2 is zeroed.
 *
 * We issue an smc to elevate to EL3 before stealing away VBAR_EL3, because
 * pongo's exception vector table is still being used. */
__attribute__ ((naked, noreturn)) void xnuspy_el3_entry_tramp(void){
    asm(""
        "smc #0\n"
        "adrp x1, _xnuspy_el3_exc_vector@PAGE\n"
        "add x1, x1, _xnuspy_el3_exc_vector@PAGEOFF\n"
        "msr vbar_el3, x1\n"
        "mov x1, x8\n"
        "isb sy\n"
        "b _xnuspy_el3_entry\n"
       );
}

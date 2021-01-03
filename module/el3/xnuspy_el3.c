/* ERET to EL1, execute some code, then issue an SMC */
void el1_test_code(void){
    int a = 3;
    a--;
    int b = a + 3;
    asm volatile("mrs x8, CurrentEL");
    asm volatile("smc #0");
    asm volatile("mrs x8, CurrentEL");
    int c = 4;
    c++;
}

__attribute__ ((naked, noreturn)) static void el1_test(void){
    asm(""
        "adrp x0, _el1_test_code@PAGE\n"
        "add x0, x0, _el1_test_code@PAGEOFF\n"
        "msr elr_el3, x0\n"
        "mov x0, 0x3c4\n"
        "msr spsr_el3, x0\n"
        "mov x12, 0x3333\n"
        "isb sy\n"
        "eret\n"
        );
}

__attribute__ ((noreturn)) void xnuspy_el3_entry(void *bootargs,
        void *entrypoint){
    /* modify PC in debugger to get off of this */
    asm volatile("b .");

    el1_test();

    /* volatile char *a = (volatile char *)0x41414141; */
    /* *a = 0; */
    asm volatile("mov x0, 0x1111");
    asm volatile("b .");
    __builtin_unreachable();
}

/* See src/boot/jump_to_image.S from pongoOS source. We've been called from
 * jump_to_image_extended. For some reason, the second argument is put inside
 * x8 and x2 is zeroed.
 *
 * We issue an smc to elevate to EL3 before stealing away VBAR_EL3, because
 * pongo's exception vector table is still being used.
 *
 * TODO: configure CPTR_EL3 and the fp stuff so CPACR_EL1 accesses are still
 * trapped
 */
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

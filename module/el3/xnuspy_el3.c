/* #include <stdint.h> */

__attribute__ ((noreturn)) void xnuspy_el3_entry(void *bootargs,
        void *entrypoint){
    asm volatile("b .");
    __builtin_unreachable();
}

/* See src/boot/jump_to_image.S from pongoOS source. We've been called from
 * jump_to_image_extended. For some reason, the second argument is put inside
 * x8 and x2 is zeroed */
__attribute__ ((naked, noreturn)) void xnuspy_el3_entry_tramp(void){
    asm(""
        "mov x1, x8\n"
        "b _xnuspy_el3_entry\n"
       );
}

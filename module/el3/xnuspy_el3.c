typedef unsigned long   uintptr_t;
typedef unsigned long   uint64_t;
typedef unsigned int    uint32_t;
typedef unsigned short  uint16_t;
typedef unsigned char   uint8_t;

struct Boot_Video {
    unsigned long	v_baseAddr;	/* Base address of video memory */
    unsigned long	v_display;	/* Display Code (if Applicable */
    unsigned long	v_rowBytes;	/* Number of bytes per pixel row */
    unsigned long	v_width;	/* Width */
    unsigned long	v_height;	/* Height */
    unsigned long	v_depth;	/* Pixel Depth and other parameters */
};

typedef struct boot_args {
    uint16_t		Revision;			/* Revision of boot_args structure */
    uint16_t		Version;			/* Version of boot_args structure */
    uint64_t		virtBase;			/* Virtual base of memory */
    uint64_t		physBase;			/* Physical base of memory */
    uint64_t		memSize;			/* Size of memory */
    uint64_t		topOfKernelData;	/* Highest physical address used in kernel data area */
    struct Boot_Video Video;				/* Video Information */
    uint32_t		machineType;		/* Machine Type */
    void			*deviceTreeP;		/* Base of flattened device tree */
    uint32_t		deviceTreeLength;	/* Length of flattened tree */
    char			CommandLine[256];	/* Passed in command line */
    uint64_t		bootFlags;		/* Additional flags specified by the bootloader */
    uint64_t		memSizeActual;		/* Actual size of memory */
} boot_args;

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
    asm volatile("mrs x8, CurrentEL");
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

/* This only exists to write a message to the framebuffer */
__attribute__ ((noreturn)) void xnuspy_el3_entry(boot_args *bootargs,
        void *entrypoint){
    /* modify PC in debugger to get off of this */
    asm volatile("b .");

    el1_test();

    __builtin_unreachable();
}

#define MONITOR_SET_ENTRY   0x800
#define MONITOR_LOCKDOWN    0x801

void xnuspy_el3_sync_handler(uint64_t callnum, uint64_t arg1, uint64_t arg2,
        uint64_t arg3){
    uint64_t esr_el3;
    asm volatile("mrs %0, esr_el3" : "=r" (esr_el3));

    /* Safe to just bail when XNU does an explicit monitor call */
    if(esr_el3 == 0x5e000011)
        return;

    asm volatile(""
            "mov x8, 0x6b3\n"
            "msr scr_el3, x8\n"
            "msr cptr_el3, xzr\n"
            "mov x8, 0x300000\n"
            "msr cpacr_el1, x8\n"
            "mrs x8, elr_el3\n"
            "add x8, x8, 0x4\n"
            "msr elr_el3, x8\n"
            );
}

/* See src/boot/jump_to_image.S from pongoOS source. We've been called from
 * jump_to_image_extended. For some reason, the second argument is put inside
 * x8 and x2 is zeroed. x0 is a pointer to the kernel boot arguments. */
__attribute__ ((naked, noreturn)) void xnuspy_el3_entry_tramp(void){
    asm(""
        /* "b .\n" */
        "smc 0\n"
        "mrs x1, s3_0_c15_c13_0\n"
        "orr x1, x1, 0x1000\n"
        "msr s3_0_c15_c13_0, x1\n"
        "isb sy\n"
        "mrs x1, s3_0_c15_c3_0\n"
        "orr x1, x1, 0x10000\n"
        "msr s3_0_c15_c3_0, x1\n"
        "isb sy\n"
        "mrs x1, s3_0_c15_c5_0\n"
        "orr x1, x1, 0x7000000\n"
        "msr s3_0_c15_c5_0, x1\n"
        /* "isb sy\n" */
        /* XXX FOR IDA */
        /* "b .\n" */
        "adrp x1, _xnuspy_el3_exc_vector@PAGE\n"
        "add x1, x1, _xnuspy_el3_exc_vector@PAGEOFF\n"
        "msr vbar_el3, x1\n"
        /* "msr rvbar_el3, x1\n" */
        "mov x1, 0x631\n"
        "msr scr_el3, x1\n"
        "mov x1, 0x80000000\n"
        "msr hcr_el2, x1\n"
        /* "mov x1, 0x30D5180D\n" */
        /* "mov x1, 0x180d\n" */
        /* "movk x1, 0x30d5, lsl 16\n" */
        /* "msr sctlr_el3, x1\n" */
        /* "msr SPSel, 0x1\n" */
        "msr cptr_el3, xzr\n"
        "mov x1, 0x100000\n"
        "msr cpacr_el1, x1\n"
        /* "msr cptr_el3, x1\n" */
        /* "mov x1, 0x100000\n" */
        /* "msr cpacr_el1, x1\n" */
        /* "mov x1, x8\n" */
        "mov x1, 0x3c4\n"
        "msr spsr_el3, x1\n"
        "msr elr_el3, x8\n"
        /* "tlbi alle3\n" */
        "ic iallu\n"
        "tlbi alle3\n"
        "dsb sy\n"
        "isb sy\n"
        "mov x1, xzr\n"
        "mov x2, xzr\n"
        "mov x3, xzr\n"
        "mov x4, xzr\n"
        "mov x5, xzr\n"
        "mov x6, xzr\n"
        "mov x7, xzr\n"
        "mov x8, xzr\n"
        "mov x9, xzr\n"
        "mov x10, xzr\n"
        "mov x11, xzr\n"
        "mov x12, xzr\n"
        "mov x13, xzr\n"
        "mov x14, xzr\n"
        "mov x15, xzr\n"
        "mov x16, xzr\n"
        "mov x17, xzr\n"
        "mov x18, xzr\n"
        "mov x19, xzr\n"
        "mov x20, xzr\n"
        "mov x21, xzr\n"
        "mov x22, xzr\n"
        "mov x23, xzr\n"
        "mov x24, xzr\n"
        "mov x25, xzr\n"
        "mov x26, xzr\n"
        "mov x27, xzr\n"
        "mov x28, xzr\n"
        "mov x29, xzr\n"
        "mov x30, xzr\n"
        "eret\n"
        /* XXX FOR IDA */
        /* "b _xnuspy_el3_entry\n" */
       );
}

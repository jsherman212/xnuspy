#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <sys/sysctl.h>

#include "common/common.h"
#include "common/pongo.h"

#include "el1/ctramp_instrs.h"
#include "el1/hook_system_check_sysctlbyname_hook_instrs.h"

#include "pf/disas.h"
#include "pf/macho.h"
#include "pf/offsets.h"
#include "pf/pf_common.h"

void (*next_preboot_hook)(void);

void xnuspy_preboot_hook(void){
    printf("%s: hello\n", __func__);

    if(next_preboot_hook)
        next_preboot_hook();
}

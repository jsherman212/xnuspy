#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>

#include <pongo.h>

#include <asm/asm.h>
#include <common/common.h>
#include <pf/offsets.h>
#include <pf/pf_common.h>

/*
adrp
   op immlo       immhi
0b 1  11    10000 1111111111100001100 00000
0b 1  00    11111 0000000000000000000 11111 mask     = 0x9f00001f
0b 1  00    10000 0000000000000000000 00000 match    = 0x90000000

add
   sf op S        sh imm12        Rn    Rd
0b 1  0  0 100010 0  010011101000 00000 00000
0b 1  1  1 111111 0  000000000000 11111 11111 mask      = 0xff8003ff
0b 1  0  0 100010 0  000000000000 00000 00000 match     = 0x91000000

stp
   opc           L imm7    Rt2   Rn    Rt
0b 10  101 1 010 0 0000010 00001 11111 00000
0b 11  111 1 111 1 0000000 11111 11111 11111 mask   = 0xffc07fff
0b 10  101 1 010 0 0000000 00001 11111 00000 match  = 0xad0007e0

BL              _lck_rw_alloc_init
STR             X0, [X23,#_l2tp_udp_mtx@PAGEOFF]
CBZ             X0, loc_FFFFFFF008FC9C60
MOV             W0, #0
BL              _l2tp_udp_init_threads
MOV             X19, X0
CBNZ            W0, loc_FFFFFFF008FC9C70
MOV             W8, #1

bl
30 9C B3 97  
0x94000000

str
E0 CE 04 F9 -> 0xf904cee0 
   size          opc imm12        Rn    Rt
0b 11   111 0 01 00  000100110011 10111 00000
0b 11   111 1 11 11  000000000000 00000 11111 mask      = 0xffc0001f
0b 11   111 0 01 00  000000000000 00000 00000 match     = 0xf9000000

cbz
20 02 00 B4

mov (ignore)
00 00 80 52

bl (ignore)
2A 00 00 94  

mov (ignore)
F3 03 00 AA 

cbnz w0, n 
20 02 00 35

mov wn, n
28 00 80 52 = 0x52800028
   sf opc        hw imm16            Rd
0b 0  10  100101 00 0000000000000001 01000
0b 1  11  111111 00 0000000000000000 00000 mask     = 0xff800000
0b 0  10  100101 00 0000000000000000 00000 match    = 0x52800000


mrs x23, tpidr_el1
97 D0 38 D5 -> 0xd538d097

ldr x8, [x23, n]
E8 52 42 F9 = 0xf94252e8
   size          opc imm12        Rn    Rt
0b 11   111 0 01 01  000010010100 10111 01000
0b 11   111 1 11 11  000000000000 11111 11111 mask      = 0xffc003ff
0b 11   111 0 01 01  000000000000 10111 01000 match     = 0xf94002e8

cmp x8, x0
1F 01 00 EB -> 0xeb00011f

b.eq n
60 04 00 54 = 0x54000460
             imm19                 cond
0b 0101010 0 0000000000000100011 0 0000
0b 1111111 1 0000000000000000000 1 1111 mask    = 0xff00001f
0b 0101010 0 0000000000000000000 0 0000 match   = 0x54000000


LDR             X8, [X0,#0x18]
0xf9400c08

LDR             X9, [X8,#0x10]
09 09 40 F9 = 0xf9400909

LDR             W9, [X9]
29 01 40 B9 = 0xb9400129

CMP             W9, #0x1E               ignore
CCMP            W9, #2, #4, NE          ignore
B.NE            loc_FFFFFFF008288C0C    ignore 

MOV             X19, X0
0xaa0003f3

LDR             X20, [X8,#0x18]
0xf9400d14


add x8, x23, 1
E8 06 00 91  = 0x910006e8

cmp x8, 2
1F 09 00 F1 = 0xf100091f

b.lo 0x1c
A3 00 00 54 = 0x540000a3

mov x0, x23
E0 03 17 AA = 0xaa1703e0

bl <ipc_object_lock>
1A 6C FF 97 -> 0x97ff6c1a
0b 100101 11111111110110110000011010
0b 111111 00000000000000000000000000 mask   = 0xfc000000
0b 100101 00000000000000000000000000 match  = 0x94000000

mov x0, x23
E0 03 17 AA = 0xaa1703e0

bl <ipc_port_release_and_and_unlock>
A7 80 FF 97

BF 01 00 71 = 0x710001bf

   sf op S        sh imm12        Rn    Rd
0b 0  1  1 100010 0  000000000000 01101 11111
0b 0  1  1 111111 0  111111111111 00000 11111 mask      = 0x7fbffc1f
0b 0  1  1 100010 0  000000000000 00000 11111 match     = 0x7100001f

__ZN22AppleUSBHostUserClient12initWithTaskEP4taskPvj: _proc_name, _strlen
__ZN30IOUSBDeviceInterfaceUserClient12initWithTaskEP4taskPvj: same 



ADD     X0, SP, #0xD0+__str
add     x0, sp, *
E0 83 00 91 = 0x910083e0
   sf op S        sh imm12        Rn    Rd
0b 1  0  0 100010 0  000000100000 11111 00000
0b 1  1  1 111111 0  000000000000 11111 11111 mask      = 0xff8003ff
0b 1  0  0 100010 0  000000000000 11111 00000 match     = 0x910003e0

MOV     W1, #0x80
mov     w1, *
01 10 80 52 = 0x52801001
   sf opc        hw imm16            Rd
0b 0  10  100101 00 0000000010000000 00001
0b 1  11  111111 00 0000000000000000 11111 mask     = 0xff80001f
0b 0  10  100101 00 0000000000000000 00001 match    = 0x52800001

BL      _snprintf
bl      * 
82 16 B8 97 
mask   = 0xfc000000
match  = 0x94000000

ADD     X0, SP, #0xD0+__str
add     x0, sp, *
E0 83 00 91 = 0x910083e0
   sf op S        sh imm12        Rn    Rd
0b 1  0  0 100010 0  000000100000 11111 00000
0b 1  1  1 111111 0  000000000000 11111 11111 mask      = 0xff8003ff
0b 1  0  0 100010 0  000000000000 11111 00000 match     = 0x910003e0

BL      _strlen
bl      *
24 0B C3 97 
mask   = 0xfc000000
match  = 0x94000000

ADD     X1, X22, X0
add     x1, *, *
C1 02 00 8B = 0x8b0002c1
   sf op S       shift   Rm    imm6   Rn    Rd
0b 1  0  0 01011 00    0 00000 000000 10110 00001
0b 1  1  1 11111 11    1 00000 111111 00000 11111 mask      = 0xffe0fc1f
0b 1  0  0 01011 00    0 00000 000000 00000 00001 match     = 0x8b000001

SUB     W2, W21, W0
sub     w2, *, *
A2 02 00 4B = 0x4b0002a2
   sf op S       shift   Rm    imm6   Rn    Rd
0b 0  1  0 01011 00    0 00000 000000 10101 00010
0b 1  1  1 11111 11    1 00000 111111 00000 11111 mask      = 0xffe0fc1f
0b 0  1  0 01011 00    0 00000 000000 00000 00010 match     = 0x4b000002

MOV     X0, X20
mov     x0, *
E0 03 14 AA = 0xaa1403e0
   sf opc       shift N Rm    imm6   Rn    Rd
0b 1  01  01010 00    0 10100 000000 11111 00000
0b 1  11  11111 11    1 00000 111111 11111 11111 mask       = 0xffe0ffff
0b 1  01  01010 00    0 00000 000000 11111 00000 match      = 0xaa0003e0

BL      _proc_name
bl      *
AB 35 B7 97
mask   = 0xfc000000
match  = 0x94000000


__TEXT_EXEC:__text:FFFFFFF008370E5C                 MRS             X8, #0, c13, c0, #4
__TEXT_EXEC:__text:FFFFFFF008370E60                 LDR             X19, [X8,#0x498]
__TEXT_EXEC:__text:FFFFFFF008370E64                 LDR             X2, [X19,#0x3C8]
__TEXT_EXEC:__text:FFFFFFF008370E68                 CMP             X2, #0
__TEXT_EXEC:__text:FFFFFFF008370E6C                 ADRL            X8, _proc0



mrs x8, tpidr_el1
88 D0 38 D5 = 0xd538d088

ldr x19, [x8, #0x498]
13 4D 42 F9 -> 0xf9424d13
   size          opc imm12        Rn    Rt
0b 11   111 0 01 01  000010010011 01000 10011
0b 11   111 1 11 11  000000000000 11111 11111 mask      = 0xffc003ff
0b 11   111 0 01 01  000000000000 01000 10011 match     = 0xf9400113

ldr x2, [x19, #0x3c8]
62 E6 41 F9 -> 0xf941e662
   size          opc imm12        Rn    Rt
0b 11   111 0 01 01  000001111001 10011 00010
0b 11   111 1 11 11  000000000000 11111 11111 mask      = 0xffc003ff
0b 11   111 0 01 01  000000000000 10011 00010 match     = 0xf9400262

cmp x2, #0
5F 00 00 F1 = 0xf100005f

adrp x8, #0x1575000
A8 AB 00 B0 -> 0xb000aba8
   op immlo       immhi               Rd
0b 1  01    10000 0000000010101011101 01000
0b 1  00    11111 0000000000000000000 00000 mask    = 0x9f000000
0b 1  00    10000 0000000000000000000 00000 match   = 0x90000000

add x8, x8, #0x28
08 A1 00 91 -> 0x9100a108
   sf op S        sh imm12        Rn    Rd
0b 1  0  0 100010 0  000000101000 01000 01000
0b 1  1  1 111111 0  000000000000 00000 00000 mask      = 0xff800000
0b 1  0  0 100010 0  000000000000 00000 00000 match     = 0x91000000



BL              _vm_map_unwire_nested
27 1E 03 94 -> 0x94031e27
mask   = 0xfc000000
match  = 0x94000000

LDR             X0, [X19,#off_FFFFFFF0077A4058@PAGEOFF]
60 2E 40 F9 -> 0xf9402e60
   size          opc imm12        Rn    Rt
0b 11   111 0 01 01  000000001011 10011 00000
0b 11   111 1 11 11  000000000000 00000 11111 mask      = 0xffc0001f
0b 11   111 0 01 01  000000000000 00000 00000 match     = 0xf9400000

ADD             X4, SP, #0xA0+var_60
E4 03 01 91 -> 0x910103e4
   sf op S        sh imm12        Rn    Rd
0b 1  0  0 100010 0  000001000000 11111 00100
0b 1  1  1 111111 0  000000000000 11111 11111 mask      = 0xff8003ff
0b 1  0  0 100010 0  000000000000 11111 00100 match     = 0x910003e4

MOV             X1, X26
E1 03 1A AA -> 0xaa1a03e1
   sf opc       shift N Rm    imm6   Rn    Rd
0b 1  01  01010 00    0 11010 000000 11111 00001
0b 1  11  11111 11    1 00000 111111 11111 11111 mask       = 0xffe0ffff
0b 1  01  01010 00    0 00000 000000 11111 00001 match      = 0xaa0003e1

MOV             X2, X25
E2 03 19 AA -> 0xaa1903e2
   sf opc       shift N Rm    imm6   Rn    Rd
0b 1  01  01010 00    0 11001 000000 11111 00010
0b 1  11  11111 11    1 00000 111111 11111 11111 mask       = 0xffe0ffff
0b 1  01  01010 00    0 00000 000000 11111 00010 match      = 0xaa0003e2

MOV             W3, #1
23 00 80 52 = 0x52800023

BL              _vm_map_copyin_internal
5F 42 03 94 -> 0x9403425f
mask   = 0xfc000000
match  = 0x94000000



ADRP            X9, #_kernel_map@PAGE
49 9C FF D0 -> 0xd0ff9c49
   op immlo       immhi               Rd
0b 1  10    10000 1111111110011100010 01001
0b 1  00    11111 0000000000000000000 11111 mask = 0x9f00001f
match = 0x90000009

LDR             X0, [X9,#_kernel_map@PAGEOFF]
20 DD 44 F9 -> 0xf944dd20
   size          opc imm12        Rn    Rt
0b 11   111 0 01 01  000100110111 01001 00000
0b 11   111 1 11 11  000000000000 11111 11111 mask = 0xffc003ff
match = 0xf9400120

AND             X2, X8, #0x1FFFFFFC000
02 69 72 92 -> 0x92726902
   sf opc        N immr   imms   Rn    Rd
0b 1  00  100100 1 110010 011010 01000 00010
0b 1  11  111111 0 000000 000000 00000 11111 mask = 0xff80001f
match = 0x92000002

MOV             X1, X21
E1 03 15 AA -> 0xaa1503e1
   sf opc       shift N Rm    imm6   Rn    Rd
0b 1  01  01010 00    0 10101 000000 11111 00001
0b 1  11  11111 11    1 00000 111111 11111 11111 mask = 0xffe0ffff
match 0xaa0003e1

MOV             W3, #1
23 00 80 52 = 0x52800023 

BL              _kmem_alloc$XNU_INTERNAL
05 D0 E1 97 -> 0x97e1d005
mask   = 0xfc000000
match  = 0x94000000

   


0A 16 00 94 = BL * 
BL              _ipc_object_destroy

FF 12 00 F9 = 0xf90012ff
   size          opc imm12        Rn    Rt
0b 11   111 0 01 00  000000000100 10111 11111
0b 11   111 1 11 11  111111111111 00000 11111 mask      = 0xfffffc1f
0b 11   111 0 01 00  000000000100 00000 11111 match     = 0xf900101f
STR             XZR, [X23,#0x20]

FF 6E 01 39 = 0x39016eff
   size          opc imm12        Rn    Rt
0b 00   111 0 01 00  000001011011 10111 11111
0b 11   111 1 11 11  111111111111 00000 11111 mask      = 0xfffffc1f
0b 00   111 0 01 00  000001011011 00000 11111 match     = 0x39016c1f
STRB            WZR, [X23,#0x5B]

D6 00 00 B4 = 0xb40000d6
   sf        op imm19               Rt
0b 1  011010 0  0000000000000000110 10110
0b 1  111111 1  0000000000000000000 00000 mask      = 0xff000000
0b 1  011010 0  0000000000000000000 00000 match     = 0xb4000000
CBZ             X22, loc_FFFFFFF007C61070

48 E0 FF F0 = 0xf0ffe048
   op immlo       immhi               Rd
0b 1  11    10000 1111111111100000010 01000
0b 1  00    11111 0000000000000000000 11111 mask    = 0x9f00001f
0b 1  00    10000 0000000000000000000 01000 match   = 0x90000008
ADRP            X8, #_ipc_kernel_copy_map@PAGE

00 DD 40 F9 = 0xf940dd00
   size          opc imm12        Rn    Rt
0b 11   111 0 01 01  000000110111 01000 00000
0b 11   111 1 11 11  000000000000 11111 11111 mask      = 0xffc003ff
0b 11   111 0 01 01  000000000000 01000 00000 match     = 0xf9400100
LDR             X0, [X8,#_ipc_kernel_copy_map@PAGEOFF] ; target_task

E1 03 16 AA = 0xaa1603e1
   sf opc       shift N Rm    imm6   Rn    Rd
0b 1  01  01010 00    0 10110 000000 11111 00001
0b 1  11  11111 11    1 00000 111111 11111 11111 mask       = 0xffe0ffff
0b 1  01  01010 00    0 00000 000000 11111 00001 match      = 0xaa0003e1
MOV             X1, X22 ; address

E2 03 15 AA = 0xaa1503e2
   sf opc       shift N Rm    imm6   Rn    Rd
0b 1  01  01010 00    0 10101 000000 11111 00010    
0b 1  11  11111 11    1 00000 111111 11111 11111 mask       = 0xffe0ffff
0b 1  01  01010 00    0 00000 000000 11111 00010 match      = 0xaa0003e2
MOV             X2, X21 ; size

0D CD 05 94 = 0x9405cd0d
BL              _vm_deallocate



BL              _lck_mtx_lock
D9 65 06 94

LDR             X0, [X20,#(qword_FFFFFFF009A5A968 - 0xFFFFFFF009A5A950)]
80 0E 40 F9 = 0xf9400e80 
   size          opc imm12        Rn    Rt
0b 11   111 0 01 01  000000000011 10100 00000
0b 11   111 1 11 11  000000000000 00000 11111 mask      = 0xffc0001f
0b 11   111 0 01 01  000000000000 00000 00000 match     = 0xf9400000

BL              _ipc_port_copy_send
27 60 FF 97 = 0x97ff6027

MOV             X21, X0
F5 03 00 AA = 0xaa0003f5
   sf opc       shift N Rm    imm6   Rn    Rd
0b 1  01  01010 00    0 00000 000000 11111 10101
0b 1  11  11111 11    1 11111 111111 11111 00000 mask       = 0xffffffe0
0b 1  01  01010 00    0 00000 000000 11111 00000 match      = 0xaa0003e0

MOV             X0, X20
E0 03 14 AA = 0xaa1403e0
   sf opc       shift N Rm    imm6   Rn    Rd
0b 1  01  01010 00    0 10100 000000 11111 00000
0b 1  11  11111 11    1 00000 111111 11111 11111 mask       = 0xffe0ffff
0b 1  01  01010 00    0 00000 000000 11111 00000 match      = 0xaa0003e0

BL              _lck_mtx_unlock
EC 68 06 94 = 0x940668ec

STR             X21, [X19,#0x308]
75 86 01 F9 = 0xf9018675
   size          opc imm12        Rn    Rt
0b 11   111 0 01 00  000001100001 10011 10101
0b 11   111 1 11 11  000000000000 11111 11111 mask      = 0xffc003ff
0b 11   111 0 01 00  000000000000 10011 10101 match     = 0xf9000275

STR             XZR, [X19,#0x310]
7F 8A 01 F9 = 0xf9018a7f
   size          opc imm12        Rn    Rt
0b 11   111 0 01 00  000001100010 10011 11111
0b 11   111 1 11 11  000000000000 11111 11111 mask      = 0xffc003ff
0b 11   111 0 01 00  000000000000 10011 11111 match     = 0xf900027f

STR             XZR, [X19,#0x320]
7F 92 01 F9 = 0xf901927f
   size          opc imm12        Rn    Rt
0b 11   111 0 01 00  000001100100 10011 11111
0b 11   111 1 11 11  000000000000 11111 11111 mask      = 0xffc003ff
0b 11   111 0 01 00  000000000000 10011 11111 match     = 0xf900027f




adrp x23, n
B7 C6 00 90 = 0x9000c6b7
   op immlo       immhi               Rd
0b 1  00    10000 0000000011000110101 10111
0b 1  00    11111 0000000000000000000 00000 mask        = 0x9f000000
0b 1  00    10000 0000000000000000000 00000 match       = 0x90000000

add x23, x23, n
F7 E2 3D 91 = 0x913de2f7
   sf op S        sh imm12        Rn    Rd
0b 1  0  0 100010 0  111101111000 10111 10111
0b 1  1  1 111111 0  000000000000 00000 00000 mask      = 0xff800000
0b 1  0  0 100010 0  000000000000 00000 00000 match     = 0x91000000

MOV             X0, X23 ; lock
E0 03 17 AA = 0xaa1703e0
   sf opc       shift N Rm    imm6   Rn    Rd
0b 1  01  01010 00    0 10111 000000 11111 00000
0b 1  11  11111 11    1 00000 111111 11111 11111 mask       = 0xffe0ffff
0b 1  01  01010 00    0 00000 000000 11111 00000 match      = 0xaa0003e0

BL              _lck_mtx_lock
39 3A F1 97 = 0x97f13a39

LDR             W8, [X25,#0x1CC]
28 CF 41 B9 = 0xb941cf28
   size          opc imm12        Rn    Rt
0b 10   111 0 01 01  000001110011 11001 01000
0b 11   111 1 11 11  000000000000 11111 11111 mask      = 0xffc003ff
0b 10   111 0 01 01  000000000000 11001 01000 match     = 0xb9400328

ORR             W8, W8, #0x800
08 01 15 32 = 0x32150108
   sf           N immr   imms   Rn    Rd 
0b 0  01 100100 0 010101 000000 01000 01000  -> match exactly 

STR             W8, [X25,#0x1CC]
28 CF 01 B9 = 0xb901cf28
   size          opc imm12        Rn    Rt
0b 10   111 0 01 00  000001110011 11001 01000
0b 11   111 1 11 11  000000000000 11111 11111 mask      = 0xffc003ff
0b 10   111 0 01 00  000000000000 11001 01000 match     = 0xb9000328

MOV             X0, X23 ; lock
E0 03 17 AA = 0xaa1703e0
   sf opc       shift N Rm    imm6   Rn    Rd
0b 1  01  01010 00    0 10111 000000 11111 00000
0b 1  11  11111 11    1 00000 111111 11111 11111 mask       = 0xffe0ffff
0b 1  01  01010 00    0 00000 000000 11111 00000 match      = 0xaa0003e0

BL              _lck_mtx_unlock
4C 3D F1 97 = 0x97f13d4c

B6 BA 00 F0 = 0xf000bab6 & 0x9f000000
D6 22 1B 91 = 0x911b22d6 & 0xff8003e0
E0 03 16 AA = 0xaa1603e0 & 0xffe0ffff
C4 C5 F3 97 = 0x97f3c5c4 & 0xfc000000
28 C7 41 B9 = 0xb941c728 & 0xffc003ff
08 01 15 32 = 0x32150108 & 0xffffffff
28 C7 01 B9 = 0xb901c728 & 0xffc003ff
E0 03 16 AA = 0xaa1603e0 & 0xffe0ffff

lck_rw_lock_shared_to_exclusive
lck_rw_lock_exclusive
lck_grp_free

    

STP             XZR, XZR, [X19,#0x40]
7F 7E 04 A9 = 0xa9047e7f
   opc           L imm7    Rt2   Rn    Rt
0b 10  101 0 010 0 0001000 11111 10011 11111 
0b 11  111 1 111 1 0000000 11111 00000 11111 mask = 0xffc07c1f
match 0xa9007c1f

STR             XZR, [X19,#0x38]
7F 1E 00 F9 = 0xf9001e7f
   size          opc imm12        Rn    Rt
0b 11   111 0 01 00  000000000111 10011 11111
0b 11   111 1 11 11  000000000000 00000 11111 mask = 0xffc0001f
match = 0xf900001f

LDR             X0, [X19,#0xC8]
60 66 40 F9 = 0xf9406660
   size          opc imm12        Rn    Rt
0b 11   111 0 01 01  000000011001 10011 00000
0b 11   111 1 11 11  000000000000 00000 11111 mask = 0xffc0001f
match = 0xf9400000

BL              lck_grp_free
A8 43 EE 97 = 0x97ee43a8

LDR             X0, [X19,#0xB0]
60 5A 40 F9 = 0xf9405a60
   size          opc imm12        Rn    Rt
0b 11   111 0 01 01  000000010110 10011 00000
0b 11   111 1 11 11  000000000000 00000 11111 mask = 0xffc0001f
match = 0xf9400000

BL              lck_grp_free
A6 43 EE 97 = 0x97ee43a6

LDR             X0, [X19,#0xA8]
60 56 40 F9 = 0xf9405660

BL              lck_grp_free
A4 43 EE 97 = 0x97ee43a4

 
 
 
 

LDR             X8, [X20]
88 02 40 F9 = 0xf9400288
   size          opc imm12        Rn    Rt
0b 11   111 0 01 01  000000000000 10100 01000
0b 11   111 1 11 11  111111111111 00000 11111 mask      = 0xfffffc1f
0b 11   111 0 01 01  000000000000 00000 01000 match     = 0xf9400008

LDR             X8, [X8,#0x1E8]
08 F5 40 F9
   size          opc imm12        Rn    Rt
0b 11   111 0 01 01  000000111101 01000 01000 
0b 11   111 1 11 11  000000000000 11111 11111 mask      = 0xffc003ff
0b 11   111 0 01 01  000000000000 01000 01000 match     = 0xf9400108

MOV             X0, X20
E0 03 14 AA = 0xaa1403e0
   sf opc       shift N Rm    imm6   Rn    Rd
0b 1  01  01010 00    0 10100 000000 11111 00000
0b 1  11  11111 11    1 00000 111111 11111 11111 mask       = 0xffe0ffff
0b 1  01  01010 00    0 00000 000000 11111 00000 match      = 0xaa0003e0

MOV             X1, #0
01 00 80 D2 = 0xd2800001
   sf opc       shift N Rm    imm6   Rn    Rd
0b 1  10  10010 10    0 00000 000000 00000 00001 MATCH EXACTLY 

BLR             X8
00 01 3F D6 = 0xd63f0100 MATCH EXACTLY 

STR             X0, [SP,#0x60+var_60]
E0 03 00 F9 = 0xf90003e0
   size          opc imm12        Rn    Rt
0b 11   111 0 01 00  000000000000 11111 00000
0b 11   111 1 11 11  000000000000 11111 11111 mask      = 0xffc003ff
0b 11   111 0 01 00  000000000000 11111 00000 match     = 0xf90003e0

ADRL            X0, aStallingForDet ; "stalling for detach from %s\n"
(adrp)
00 84 FF 90 = 0x90ff8400
   op immlo       immhi               Rd
0b 1  00    10000 1111111110000100000 00000
0b 1  11    11111 0000000000000000000 11111 mask        = 0xff00001f
0b 1  00    10000 0000000000000000000 00000 match       = 0x90000000

ADD
00 20 1A 91 = 0x911a2000
   sf op S        sh imm12        Rn    Rd
0b 1  0  0 100010 0  011010001000 00000 00000
0b 1  1  1 111111 1  000000000000 11111 11111 mask      = 0xffc003ff
0b 1  0  0 100010 0  000000000000 00000 00000 match     = 0x91000000

BL              _IOLog
F2 C9 FF 97

68 02 40 F9 = 0xf9400268
08 F5 40 F9 
E0 03 13 AA
01 00 80 D2 
00 01 3F D6  
E0 03 00 F9 
20 94 FF 90
00 34 35 91

*/

uint64_t g_vm_map_unwire_nested_addr = 0;
uint64_t g_iolog_addr = 0;

bool ipc_port_release_send_finder_15(xnu_pf_patch_t *patch, 
        void *cacheable_stream){
    /* will land in _exception_deliver in iOS 15. There is a sequence
     * where they lock/release 4 IPC ports if they are non-null. This
     * patchfinder will take us here, then it's just a matter of
     * resolving the branches */
    xnu_pf_disable_patch(patch);

    uint32_t *opcode_stream = cacheable_stream;

    uint32_t *ipc_port_release_send_and_unlock = get_branch_dst_ptr(opcode_stream + 6);
    uint32_t *ipc_object_lock = get_branch_dst_ptr(opcode_stream + 4);

    g_ipc_port_release_send_addr = xnu_ptr_to_va(ipc_port_release_send_and_unlock);
    g_io_lock_addr = xnu_ptr_to_va(ipc_object_lock);

    puts("xnuspy: found ipc_port_release_send_and_unlock");
    puts("xnuspy: found ipc_object_lock");

    return true;
}

bool proc_name_snprintf_strlen_finder_15(xnu_pf_patch_t *patch,
        void *cacheable_stream){
    /* will land in AppleEmbeddedUSBDevice::setAuthenticationProperites */
    xnu_pf_disable_patch(patch);

    uint32_t *opcode_stream = cacheable_stream;

    uint32_t *snprintf = get_branch_dst_ptr(opcode_stream + 2);
    uint32_t *strlen = get_branch_dst_ptr(opcode_stream + 4);
    uint32_t *proc_name = get_branch_dst_ptr(opcode_stream + 8);

    g_snprintf_addr = xnu_ptr_to_va(snprintf);
    g_strlen_addr = xnu_ptr_to_va(strlen);
    g_proc_name_addr = xnu_ptr_to_va(proc_name);

    puts("xnuspy: found snprintf");
    puts("xnuspy: found strlen");
    puts("xnuspy: found proc_name");

    return true;
}

bool current_proc_finder_15(xnu_pf_patch_t *patch, void *cacheable_stream){
    /* will land directly at the start of _current_proc, or an 
     * inlined copy of it */

    uint32_t *opcode_stream = cacheable_stream;

    uint32_t *current_proc = opcode_stream - 3;

    uint32_t func_size = 0;
    while (*opcode_stream != 0xd65f03c0 /* ret */){
        func_size++;

        opcode_stream++;
    }

    /* definitely not the best patchfind, but _current_proc itself is
     * a very specific size (it's also the smallest match but this is
     * harder to check for). we get many matches on this patch as 
     * it's inlined in many places */
    if (func_size != 0x12){
        return false;
    }

    xnu_pf_disable_patch(patch);

    g_current_proc_addr = xnu_ptr_to_va(current_proc);

    puts("xnuspy: found current_proc");

    return true;
}

bool vm_map_unwire_nested_finder_15(xnu_pf_patch_t *patch, 
        void *cacheable_stream){
    /* will land in mach_port_space_info, on the _vm_map_unwire_nested call */
    xnu_pf_disable_patch(patch);

    uint32_t *opcode_stream = cacheable_stream;

    uint32_t *vm_map_unwire_nested = get_branch_dst_ptr(opcode_stream);

    g_vm_map_unwire_nested_addr = xnu_ptr_to_va(vm_map_unwire_nested);
    
    puts("xnuspy: found vm_map_unwire_nested");

    return true;
}

bool kernel_map_finder_15(xnu_pf_patch_t *patch, void *cacheable_stream){
    /* will land in _panic_kernel, on adrp/ldr for _kernel_map */
    xnu_pf_disable_patch(patch);

    uint32_t *opcode_stream = cacheable_stream;

    uint32_t *kernel_map = (uint32_t *)get_pc_rel_target(opcode_stream);

    g_kernel_map_addr = xnu_ptr_to_va(kernel_map);
    
    puts("xnuspy: found kernel_map");
    
    return true;
}

bool vm_deallocate_finder_15(xnu_pf_patch_t *patch, void *cacheable_stream){
    /* will land in ipc_kmsg_clean_partial. we can only 
     * search for 8 intructions at a time, so we check
     * for the 9th instruction (bl _vm_deallocate) */
    xnu_pf_disable_patch(patch);

    uint32_t *opcode_stream = cacheable_stream;

    if ((opcode_stream[8] & 0xfc000000) != 0x94000000){
        return false;
    }

    uint32_t *vm_deallocate = get_branch_dst_ptr(opcode_stream + 8);

    g_vm_deallocate_addr = xnu_ptr_to_va(vm_deallocate);

    puts("xnuspy: foudn vm_deallocate");

    return true;
}

/* NOTE: if this patch breaks see note in `proc_list_mlock_finder_15` */
bool lck_mtx_lock_unlock_finder_15(xnu_pf_patch_t *patch, void *cacheable_stream){
    /* will land at the end of ipc_task_init */
    xnu_pf_disable_patch(patch);

    uint32_t *opcode_stream = cacheable_stream;

    uint32_t *lck_mtx_lock = get_branch_dst_ptr(opcode_stream);
    uint32_t *lck_mtx_unlock = get_branch_dst_ptr(opcode_stream + 5);

    g_lck_mtx_lock_addr = xnu_ptr_to_va(lck_mtx_lock);
    g_lck_mtx_unlock_addr = xnu_ptr_to_va(lck_mtx_unlock);

    puts("xnuspy: found lck_mtx_lock");
    puts("xnuspy: found lck_mtx_unlock");

    return true;
}

/* NOTE: lock_mtx_{un}lock are also nearby, so could be integrated into this patch if necessary */
bool proc_list_mlock_finder_15(xnu_pf_patch_t *patch, void *cacheable_stream){
    /* will land in _posix_spawn. we can only search
     * for 8 instructions at a time, so we check for 
     * the 9th instruction (bl _lck_mtx_unlock) */
    xnu_pf_disable_patch(patch);
    
    uint32_t *opcode_stream = cacheable_stream;
    
    if ((opcode_stream[8] & 0xfc000000) != 0x94000000){
        return false;
    }

    uint32_t *proc_list_mlock = (uint32_t *)get_pc_rel_target(opcode_stream);

    g_proc_list_mlock_addr = xnu_ptr_to_va(proc_list_mlock);

    puts("xnuspy: found proc_list_mlock");

    return true;
}

bool lck_grp_free_finder_15(xnu_pf_patch_t *patch, void *cacheable_stream){
    /* will land in _mcache_destroy. we match a pattern 
     * of 3x calls to _lck_grp_free, so we can check
     * these BL's all point to the same place to ensure
     * we're looking at the right code */

    uint32_t *opcode_stream = cacheable_stream;

    uint32_t *branches[3] = { 
        get_branch_dst_ptr(opcode_stream + 3),
        get_branch_dst_ptr(opcode_stream + 5),
        get_branch_dst_ptr(opcode_stream + 7),
    };

    if (branches[0] != branches[1] ||
        branches[0] != branches[2])
        return false;

    xnu_pf_disable_patch(patch);

    uint32_t *lck_grp_free = get_branch_dst_ptr(opcode_stream + 3);
    
    g_lck_grp_free_addr = xnu_ptr_to_va(lck_grp_free);
    
    puts("xnuspy: found lck_grp_free");
    
    return true;
}

bool iolog_finder_15(xnu_pf_patch_t *patch, void *cacheable_stream){
    uint32_t *opcode_stream = cacheable_stream;

    /* check for BL */
    if ((opcode_stream[8] & 0xfc000000) != 0x94000000){
        return false;
    }

    /* somewhat unorthodox, but check the string matches 
     * a specific log message we're looking for. this 
     * stops us matching against other logging macro's, 
     * like kprintf, which may use a similar call site */

    const char *match_string = "%s: not registry member at registerService()";

    const char *str_ptr = (const char *)get_pc_rel_target(opcode_stream + 6);

    if (strncmp(str_ptr, match_string, strlen(match_string)) != 0){
        return false;
    }

    xnu_pf_disable_patch(patch);

    uint32_t *iolog_addr = get_branch_dst_ptr(opcode_stream + 8);

    g_iolog_addr = xnu_ptr_to_va(iolog_addr);
    
    puts("xnuspy: found iolog");

    return true;
}

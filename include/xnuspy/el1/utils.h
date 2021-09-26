#ifndef UTILS
#define UTILS

#include <stdbool.h>
#include <stdint.h>

#include <xnuspy/xnuspy_structs.h>

__attribute__ ((naked)) uint64_t current_thread(void);
struct _vm_map *current_map(void);
void vm_map_reference(void *);

bool is_15_x(void);
bool is_14_5_and_above(void);
bool is_14_x_and_above(void);
bool is_14_x_and_below(void);
bool is_14_x(void);
bool is_13_x(void);

void *get_proc_list_mlock(void);
void proc_list_lock(void);
void proc_list_unlock(void);

#endif

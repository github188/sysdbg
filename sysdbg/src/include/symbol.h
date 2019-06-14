#ifndef __SYSDBG_SYMBOLS_H
#define __SYSDBG_SYMBOLS_H

#include "common.h"
#include "proc.h"

typedef struct symbol_info{
    unsigned long addr;
    unsigned long offset;
    char func_name[FUNCNAME_SIZE];
    char filename[MAX_PATH];
} symbol_info_t;

symbol_info_t ** get_symbol_info(pid_t pid,
            void * const *array,
            int size);

char ** compat_backtrace_symbols(pid_t pid,
            void * const *array,
            int size);

int safe_backtrace_symbols(pid_t pid,
		void * const *array,
		int size,
		map_entry_t *head[], int item_num);
#endif

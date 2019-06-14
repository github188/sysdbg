/*
 * Output stack item with names for addresses in backtrace.
 *
 * History:
 *   2015/09/16 - [liuqinglin] Create
 *   2017/12/27 - [liyaqiang] Modify
 *
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "symbol.h"
#include "proc.h"
#include "elfxx.h"
#include "io.h"

int safe_backtrace_symbols(pid_t pid,
		void * const *array,
		int size,
		map_entry_t *head[], int item_num)
{
	int cnt;
	struct elf_image ei;
	symbol_info_t symbol_info;
	map_entry_t *cur;
	int ret;

	for (cnt = 0; cnt < size; cnt++) {
		cur = get_map_entry(head, item_num, (unsigned long)array[cnt]);
		if (!cur)
			continue;

		if (elf_map_image(&ei, cur->pathname) < 0)
			continue;

		symbol_info.addr = (unsigned long)array[cnt];
		strncpy(symbol_info.filename, cur->pathname, MAX_PATH - 1);

		ret = lookup_symbol(&ei, cur->start, cur->offset,
				symbol_info.addr,
				symbol_info.func_name,
				&(symbol_info.offset));

		munmap(ei.image, ei.size);

		if (ret < 0) {
			(symbol_info.func_name)[0] = '\0';
		}

		u_printf("<%s> (<%s> + %p) [%p]\n",
				symbol_info.filename,
				symbol_info.func_name,
				(void *)(symbol_info.offset),
				(void *)(symbol_info.addr));
	}
	return 0;
}

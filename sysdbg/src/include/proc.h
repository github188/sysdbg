/*
 * Proc filesystem process code.
 *
 * History:
 *   2015/09/18 - [liuqinglin] Create
 *
 */
#ifndef __SYSDBG_PROC_H_
#define __SYSDBG_PROC_H_

#include "common.h"

typedef struct map_entry {
	unsigned long start;
	unsigned long end;
	unsigned long inode;
	unsigned long long offset;
	char perms[5];
	char dev[7];
	char pathname[128];
}map_entry_t;

void maps_release(map_entry_t **phead);
int maps_read(int pid, map_entry_t *head[], int *item_num, map_entry_t *poll, int poll_size);

int valid_pc(map_entry_t *head[], int item_num, ptr_t addr);

map_entry_t * get_map_entry(map_entry_t *head[], int item_num,
		unsigned long addr);
int dump_maps(pid_t pid);
pid_t gettgid(pid_t pid);
int get_thread_name(int pid, char *pname);

#endif

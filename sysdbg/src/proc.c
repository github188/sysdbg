/*
 * Proc filesystem process code.
 *
 * History:
 *   2015/09/18 - [liuqinglin] Create
 *
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "proc.h"
#include "io.h"

#define INVALID_INDEX -1
static int find_insert_index(map_entry_t *head[], int item_num,
		map_entry_t *map_entry)
{
	int begin = 0;
	int end = item_num - 1;
	int idx = -1;

	while (begin <= end) {
		idx = (begin + end) / 2;
		if (head[idx]->start > map_entry->start)
			end = idx - 1;
		else
			begin = idx + 1;
	}
	if (head[idx]->start <= map_entry->start)
		idx++;
	return idx;
}

static int Bsearch(map_entry_t *head[], int item_num, unsigned long addr)
{
	int low = 0, high = item_num - 1, mid;
	if (head == NULL || item_num == 0)
		return INVALID_INDEX;

	while (low <= high) {
		mid = (low + high) / 2;
		if (head[mid]->start > addr)
			high = mid - 1;
		else if (head[mid]->end < addr)
			low = mid + 1;
		else if (head[mid]->start <= addr && addr <= head[mid]->end)
			return mid;
		else
			return INVALID_INDEX;
	}
	return INVALID_INDEX;
}

static int map_entry_insert(map_entry_t *phead[], int *item_num,
		map_entry_t *map_entry)
{
	int idx = -1;
	int i;

	if (NULL == phead)
		return *item_num;

	if(*item_num == 0) {
		phead[0] = map_entry;
		*item_num += 1;
	} else {
		idx = find_insert_index(phead, *item_num, map_entry);

		i = *item_num;
		while (i > idx) {
			phead[i] = phead[i-1];
			i--;
		}
		phead[idx] = map_entry;
		*item_num += 1;
	}

	return *item_num;
}

/*read /proc/pid/task/pid/maps, format is:
  address           perms offset  dev   inode   pathname
  08048000-08056000 r-xp 00000000 03:0c 64593   /usr/sbin/gpm
  08056000-08058000 rw-p 0000d000 03:0c 64593   /usr/sbin/gpm
  */
int maps_read(int pid, map_entry_t *head[], int *item_num, map_entry_t *poll, int poll_size)
{
	int fd = -1, i = 0;
	char line[BUFFER_SIZE] = {0};
	map_entry_t *tmp = NULL;
	char filename[sizeof("/proc/%d/task/%d/maps") + sizeof(int)*3*2];

	if (!head)
		return -1;

	sprintf(filename, "/proc/%d/task/%d/maps", getpid(), pid);

	fd = open(filename, O_RDONLY);
	if (fd < 0)
		return -2;

	while (-1 != safe_getline(fd, line, BUFFER_SIZE)) {
		if (i == poll_size)
			break;

		tmp = &poll[i++];
		if (!tmp)
			break;

		sscanf(line, "%lx-%lx %s %llx %s %lu %s\n",
				&(tmp->start), &(tmp->end),
				tmp->perms, &(tmp->offset),
				tmp->dev, &(tmp->inode),
				tmp->pathname);

		map_entry_insert(head, item_num, tmp);
	}

	close(fd);

	return 0;
}
map_entry_t * get_map_entry(map_entry_t *head[], int item_num, unsigned long addr)
{
	int idx = -1;

	idx = Bsearch(head, item_num, addr);

	if(idx == INVALID_INDEX)
		return NULL;

	return head[idx];
}

int valid_pc(map_entry_t *head[], int item_num, ptr_t addr)
{
	int idx = -1;

	idx = Bsearch(head, item_num, addr);

	if(idx == INVALID_INDEX)
		return 0;

	if (NULL != strchr(head[idx]->perms, 'x') && head[idx]->inode != 0)
		return 1;

	return 0;
}

int dump_maps(pid_t pid)
{
	int fd = -1;
	char buf[256] = {0};
	char filename[sizeof("/proc/%d/task/%d/maps") + sizeof(int)*3*2];

	sprintf(filename, "/proc/%d/task/%d/maps", getpid(), pid);

	fd = open(filename, O_RDONLY);
	if (fd < 0)
		return -1;

	u_printf("\n--------Process [%d] Maps-------\n", pid);

	while (read(fd, buf, sizeof(buf)-1) > 0) {
		u_printf("%s", buf);
		memset(buf, 0, sizeof(buf));
	}

	close(fd);

	return 0;
}

int get_thread_name(int pid, char *pname)
{
	char filename[sizeof("/proc/%d/task/%d/stat") + sizeof(int)*3*2];
	char buf[512] = {0};
	int length = 0; /* length of thread name */

	sprintf(filename, "/proc/%d/task/%d/stat", getpid(), pid);

	if(-1 == read2buf(filename, buf, 512))
		return -1;

	char *cp, *comm1;

	cp = strrchr(buf, ')'); /* split into "pid (cmd" and "<rest>" */
	if (NULL == cp)
		return -1;
	cp[0] = '\0';

	comm1 = strchr(buf, '(');
	if (NULL == comm1)
		return -1;

	length = cp - comm1;

	safe_strncpy(pname, comm1 + 1, min(length, 512));/*2: thread name*/

	return 0;
}

/* Return thread group id */
pid_t gettgid(pid_t pid)
{
	int fd = -1;
	char filename[sizeof("/proc/%d/task/%d/status") + sizeof(int) * 3 * 2];
	char line[BUFFER_SIZE] = {0}, *p = NULL;
	pid_t tgid = 0;

	sprintf(filename, "/proc/%d/task/%d/status", getpid(), pid);

	fd = open(filename, O_RDONLY);
	if (fd < 0)
		return 0;

	if (read(fd, line, BUFFER_SIZE-1) < 0) {
		close(fd);
		return 0;
	}

	close(fd);

	p = strstr(line, "Tgid");
	if (p == NULL)
		return 0;

	sscanf(p, "Tgid:\t%d\n", &tgid);

	return tgid;
}

/*
 * Backtrace
 *
 * History:
 *   2015/09/18 - [liuqinglin] Create
 *
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "sysdbg.h"
#include "common.h"
#include "io.h"
#include "proc.h"
#include "backtrace.h"
#include "symbol.h"

/*
 * backtrace by scanning the whole stack
 * If @pid is not the current pid call this function, you
 * must PTRACE_ATTACH the process first.
 *
 */
#define ITEM_MAX_NUM  1024
static map_entry_t *head[ITEM_MAX_NUM];
static map_entry_t  item_poll[ITEM_MAX_NUM];

int backtrace_unwind(void **array, int size,
		pid_t pid, regs_t *regs, map_entry_t *head[], int item_num)
{
	map_entry_t *stack = NULL;
	ptr_t curr_pc = regs->pc;
	int cnt = 0;
	int self = 0;

	if (!array || !size)
		return 0;

	stack = get_map_entry(head, item_num, regs->sp);
	if (!stack) {
		dbg("Not a valid sp:[%p].\n", regs->sp);
		return 0;
	}

	/* same thread group, can not ptrace */
	if (gettgid(pid) == getpid())
		self = 1;

	while(1) {
		if (valid_pc(head, item_num, curr_pc))
			array[cnt++] = (void *)curr_pc;

		if (cnt >= size)
			break;

		/* invalid sp */
		if (regs->sp < stack->start || regs->sp >= stack->end)
			break;

		if (self)
			curr_pc = *(ptr_t *)regs->sp;
		else
			curr_pc = ptrace(PTRACE_PEEKDATA, pid, (ptr_t *)regs->sp, 0);

		regs->sp += sizeof(ptr_t);
	}

	return cnt;
}

/* backtrace using frame-pointer
*/
int backtrace_fp(void **array, int size,
		pid_t pid, regs_t *regs, map_entry_t *head[], int item_num)
{
	map_entry_t *stack = NULL;
	int cnt = 0;
	ptr_t next_pc = regs->pc;
	ptr_t next_fp = regs->fp;

	if (!array || !size)
		return 0;

	stack = get_map_entry(head, item_num, regs->sp);
	if (!stack) {
		dbg("Not a valid sp:[%p].\n", regs->sp);
		return 0;
	}

	while(1) {
		if (valid_pc(head, item_num, next_pc))
			array[cnt++] = (void *)next_pc;

		if (cnt >= size)
			break;

		/* invalid sp */
		if (next_fp < stack->start || next_fp >= stack->end)
			break;

		arch_fp_step(pid, next_fp, &next_pc, &next_fp);

	}

	return cnt;
}

void dump_stack(pid_t pid, regs_t *regs, int flags)
{
	void *array[BACKTRACE_SIZE];
	char *prompt[BT_TYPES] = {0};
	size_t size[BT_TYPES] = {0};
	int cnt = 0;
	int item_num = 0;

	/* read the whole address space */
	memset(item_poll, 0, sizeof(item_poll));
	if (maps_read(pid, head, &item_num, item_poll, ITEM_MAX_NUM) < 0)
		return;

	if (flags & BT_EXTBL) {
		if (gettgid(pid) == getpid()) {
			prompt[cnt] = "extbl";
			memset(array, 0, sizeof(array));
			size[cnt] = backtrace(array, BACKTRACE_SIZE);
			u_printf("\n===========Call Trace(%s)==========\n", prompt[cnt]);
			u_printf("Obtained %zd stack frames:\n", size[cnt]);
			safe_backtrace_symbols(getpid(), array, size[cnt], head, item_num);
			cnt++;
		}
	}

	if (flags & BT_FP) {
		prompt[cnt] = "fp";
		memset(array, 0, sizeof(array));
		size[cnt] = backtrace_fp(array, BACKTRACE_SIZE, pid, regs, head, item_num);
		u_printf("\n===========Call Trace(%s)==========\n", prompt[cnt]);
		u_printf("Obtained %zd stack frames:\n", size[cnt]);
		safe_backtrace_symbols(pid, array, size[cnt], head, item_num);
		cnt++;
	}

	if (flags & BT_UNWIND) {
		prompt[cnt] = "unwind";
		memset(array, 0, sizeof(array));
		size[cnt] = backtrace_unwind(array, BACKTRACE_SIZE, pid, regs, head, item_num);
		u_printf("\n===========Call Trace(%s)==========\n", prompt[cnt]);
		u_printf("Obtained %zd stack frames:\n", size[cnt]);
		safe_backtrace_symbols(pid, array, size[cnt], head, item_num);
	}
	return;
}

/*
 * Internal stack unwind functions.
 *
 *
 * History:
 *   2015/09/18 - [liuqinglin] Create
 *
 */
#ifndef __SYSDBG_BACKTRACE_H__
#define __SYSDBG_BACKTRACE_H__

#include "arch_dep.h"

#define BT_EXTBL    0x01
#define BT_UNWIND   0x02
#define BT_FP       0x04
#define BT_MASK     0x07
#define BT_TYPES    0x03

void dump_stack(pid_t pid, regs_t *regs, int flags);

#if defined(__GLIBC__) && !defined(__UCLIBC__)
#include <execinfo.h>
#else

#ifdef	__cplusplus
extern "C" {
#endif

#ifdef __arm__

int internal_backtrace (void **array, int size);

#define backtrace(array, size)      \
    internal_backtrace(array, size)

#define backtrace_symbols(array, size)      \
    compat_backtrace_symbols(gettid(), array, size)

#else
static int backtrace(void **__array, int __size)
{
    return 0;
}

static char **backtrace_symbols(void *const *__array, int __size)
{
    return NULL;
}
#endif

#ifdef __cplusplus
}
#endif

#endif /* defined(__GLIBC__) && !defined(__UCLIBC__) */
#endif /* __SYSDBG_BACKTRACE_H__ */

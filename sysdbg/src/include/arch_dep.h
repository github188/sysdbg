/*
 * Arch-related stack unwind functions.
 *
 *
 * History:
 *   2015/09/18 - [liuqinglin] Create
 *
 */
#ifndef __SYSDBG_UNWIND_H__
#define __SYSDBG_UNWIND_H__

#include <ucontext.h>
#include "common.h"

typedef struct sys_regs {
    ptr_t fp;
    ptr_t sp;
    ptr_t pc;
} regs_t;

#ifndef arch_get_func_addr
# define arch_get_func_addr(addr, v)		(*(v) = addr, 0)
#endif

#if defined (__arm__) || defined (__aarch64__) ||   \
    defined (__i386__) || defined (__x86_64__) ||   \
    defined (__powerpc__)
    
extern void arch_dump_registers_sc(struct ucontext *ct);
extern void arch_get_regs_sc(struct ucontext *ct, regs_t *regs);
extern void arch_fp_step(pid_t pid,
            ptr_t curr_fp,
            ptr_t *next_pc,
            ptr_t *next_fp);
extern void arch_get_regs_ptrace(pid_t pid, struct sys_regs *regs);

#else
static void arch_dump_registers_sc(struct ucontext *ct){}
static void arch_get_regs_sc(struct ucontext *ct, regs_t *regs){}
static void arch_fp_step(pid_t pid,
            ptr_t curr_fp,
            ptr_t *next_pc,
            ptr_t *next_fp){}
static void arch_get_regs_ptrace(pid_t pid, struct sys_regs *regs){}

#endif

#endif /* __SYSDBG_UNWIND_H__ */

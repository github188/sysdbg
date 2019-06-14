/*
 *
 *
 * History:
 *   2015/09/16 - [liuqinglin] Create
 *
 */
#include <signal.h>
#include <sys/ucontext.h>
#include <sys/ptrace.h>

#include "io.h"
#include "proc.h"

#include "arch_dep.h"

/*
* @ct:signal context get from signal handler
*
*/
void arch_dump_registers_sc(struct ucontext *ct)
{
#if defined __powerpc__
    ptr_t *regs = (ptr_t*)ct->uc_mcontext.regs;

    u_printf("PC:%p, SP:%p, BP:%p\n",
        (ptr_t)regs[32],
        (ptr_t)*(ptr_t*)regs[1],
        (ptr_t)*(ptr_t*)regs[1]);
#endif

    return;
}

void arch_get_regs_sc(struct ucontext *ct, regs_t *regs)
{
    if (!regs)
        return;

#if  defined __powerpc__
    ptr_t *gregs = (ptr_t*)ct->uc_mcontext.regs;
    regs->sp = (ptr_t) *(ptr_t*)gregs[1];
    regs->fp = (ptr_t) *(ptr_t*)gregs[1];
    regs->pc = (ptr_t)gregs[32];
#endif

    return;
}

void arch_fp_step(pid_t pid,
            ptr_t curr_fp,
            ptr_t *next_pc,
            ptr_t *next_fp)
{
    *next_pc = 0;
    *next_fp = 0;

    if (gettgid(pid) == getpid()) {
        *next_pc = (ptr_t)*((ptr_t *)curr_fp + 1);
        *next_fp = (ptr_t)*((ptr_t *)curr_fp);
    } else {
        *next_pc = ptrace(PTRACE_PEEKDATA, pid, (ptr_t *)curr_fp + 1, 0);
        *next_fp = ptrace(PTRACE_PEEKDATA, pid, (ptr_t *)curr_fp, 0);
    }

    return;
}

void arch_get_regs_ptrace(pid_t pid, struct sys_regs *regs)
{
    if (!regs)
        return;

#if defined __powerpc__
    regs->fp = ptrace(PTRACE_PEEKUSER, pid, 1 * 4, 0);
    regs->sp = ptrace(PTRACE_PEEKDATA, pid, regs->fp, 0);
    regs->fp = regs->sp;
    regs->pc = ptrace(PTRACE_PEEKUSER, pid, 32 * 4, 0);
#endif

    return;
}

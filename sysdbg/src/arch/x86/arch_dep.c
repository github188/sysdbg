/*
 * Signal context process 
 * liuqinglin <liuqinglin@kedacom.com>
 *
 *
 * History:
 *   2015/09/16 - [liuqinglin] Create
 *
 */
#include <sys/ucontext.h>
#include <sys/reg.h>
#include <sys/ptrace.h>

#include "io.h"
#include "proc.h"

#include "arch_dep.h"

/* must define here again because of gcc bug */
#if defined __i386__

#ifndef REG_EIP
#define REG_EIP     14
#endif

#ifndef REG_ESP
#define REG_ESP     7
#endif

#ifndef REG_EBP
#define REG_EBP     6
#endif

#ifndef REG_EAX
#define REG_EAX     11
#endif

#ifndef REG_EBX
#define REG_EBX     8
#endif

#ifndef REG_ECX
#define REG_ECX     10
#endif

#ifndef REG_EDX
#define REG_EDX     9
#endif

#elif defined __x86_64__

#ifndef REG_RIP
#define REG_RIP     16
#endif

#ifndef REG_RSP
#define REG_RSP     15
#endif

#ifndef REG_RBP
#define REG_RBP     10
#endif

#ifndef REG_RAX
#define REG_RAX     13
#endif

#ifndef REG_RBX
#define REG_RBX     11
#endif

#ifndef REG_RCX
#define REG_RCX     14
#endif

#ifndef REG_RDX
#define REG_RDX     12
#endif

#endif


/*
* @ct:signal context get from signal handler
*
*/
void arch_dump_registers_sc(struct ucontext *ct)
{
    mcontext_t *mc = &ct->uc_mcontext;
    
#if  defined __i386__
    u_printf("EIP:%p, ESP:%p, EBP:%p\n"
            "EAX:%p, EBX:%p, ECX:%p, EDX:%p\n",
            mc->gregs[REG_EIP], mc->gregs[REG_ESP], mc->gregs[REG_EBP],
            mc->gregs[REG_EAX], mc->gregs[REG_EBX],
            mc->gregs[REG_ECX], mc->gregs[REG_EDX]);
#elif defined __x86_64__
    u_printf("RIP:%p, RSP:%p, RBP:%p\n"
            "RAX:%p, RBX:%p, RCX:%p, RDX:%p\n",
            mc->gregs[REG_RIP], mc->gregs[REG_RSP], mc->gregs[REG_RBP],
            mc->gregs[REG_RAX], mc->gregs[REG_RBX],
            mc->gregs[REG_RCX], mc->gregs[REG_RDX]);
#endif
}

void arch_get_regs_sc(struct ucontext *ct, regs_t *regs)
{
    mcontext_t *mc = &ct->uc_mcontext;
    if (!regs)
        return;
    
#if  defined __i386__
    regs->sp = mc->gregs[REG_ESP];
    regs->pc = mc->gregs[REG_EIP];
    regs->fp = mc->gregs[REG_EBP];
#elif   defined __x86_64__
    regs->sp = mc->gregs[REG_RSP];
    regs->pc = mc->gregs[REG_RIP];
    regs->fp = mc->gregs[REG_RBP];
#endif
    return ;
}

void arch_fp_step(pid_t pid,
            ptr_t curr_fp,
            ptr_t *next_pc,
            ptr_t *next_fp)
{
    *next_pc = 0;
    *next_fp = 0;
    
    if (gettgid(pid) == getpid()) {
        *next_pc = (ptr_t) *((ptr_t *)curr_fp + 1);
        *next_fp = (ptr_t) *((ptr_t *)curr_fp);
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
    
#if defined __i386__
    regs->fp = ptrace(PTRACE_PEEKUSER, pid, EBP * 4, 0);
    regs->sp = ptrace(PTRACE_PEEKUSER, pid, UESP * 4, 0);
    regs->pc = ptrace(PTRACE_PEEKUSER, pid, EIP * 4, 0);
#elif defined __x86_64__
    regs->fp = ptrace(PTRACE_PEEKUSER, pid, RBP * 8, 0);
    regs->sp = ptrace(PTRACE_PEEKUSER, pid, RSP * 8, 0);
    regs->pc = ptrace(PTRACE_PEEKUSER, pid, RIP * 8, 0);
#endif
}

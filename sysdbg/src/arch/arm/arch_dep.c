/*
 * Signal context process
 * liuqinglin <liuqinglin@kedacom.com>
 *
 *
 * History:
 *   2015/09/16 - [liuqinglin] Create
 *
 */
#include <signal.h>
#include <ucontext.h>
#include <sys/procfs.h>
#include <sys/ucontext.h>
#include <sys/uio.h>
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
	struct sigcontext* sc  = &ct->uc_mcontext;

#if  defined __arm__
	u_printf("PC:%p, LR:%p, SP:%p, FP:%p\n"
			"R0:%p, R1:%p, R2:%p, R3:%p, R4:%p\n",
			sc->arm_pc, sc->arm_lr, sc->arm_sp, sc->arm_fp,
			sc->arm_r0, sc->arm_r1, sc->arm_r2,
			sc->arm_r3, sc->arm_r4);
#elif   defined __aarch64__
	u_printf("PC:%p, LR:%p, SP:%p, FP:%p\n"
			"R0:%p, R1:%p, R2:%p, R3:%p, R4:%p\n"
			"R5:%p, R6:%p, R7:%p, R8:%p, R9:%p\n",
			sc->pc, sc->regs[30], sc->sp, sc->regs[29],
			sc->regs[0], sc->regs[1], sc->regs[2], sc->regs[3],
			sc->regs[4], sc->regs[5], sc->regs[6], sc->regs[7]);
#endif
}

void arch_get_regs_sc(struct ucontext *ct, regs_t *regs)
{
	struct sigcontext* sc  = &ct->uc_mcontext;
	if (!regs)
		return;

#if  defined __arm__
	regs->sp = sc->arm_sp;
	regs->pc = sc->arm_pc;
	regs->fp = sc->arm_fp;
#elif   defined __aarch64__
	regs->sp = sc->sp;
	regs->pc = sc->pc;
	regs->fp = sc->regs[29];
#endif
}

void arch_fp_step(pid_t pid,
		ptr_t curr_fp,
		ptr_t *next_pc,
		ptr_t *next_fp)
{
	*next_pc = 0;
	*next_fp = 0;

	if (gettgid(pid) == getpid()) {
		*next_pc = (ptr_t) *((ptr_t *)curr_fp);
		*next_fp = (ptr_t) *((ptr_t *)curr_fp - 1);
	} else {
		*next_pc = ptrace(PTRACE_PEEKDATA, pid, (ptr_t *)curr_fp, 0);
		*next_fp = ptrace(PTRACE_PEEKDATA, pid, (ptr_t *)curr_fp - 1, 0);
	}

	return;
}

void arch_get_regs_ptrace(pid_t pid, struct sys_regs *regs)
{
	elf_gregset_t gregs;
	struct iovec iovec __attribute((unused));

	if (!regs)
		return;

	iovec.iov_base = &gregs;
	iovec.iov_len = sizeof(gregs);

#if defined __arm__
	if (ptrace(PTRACE_GETREGS, pid, 0, &gregs) < 0)
		return;

	regs->fp = gregs[11];
	regs->sp = gregs[13];
	regs->pc = gregs[15];
#elif defined __aarch64__
	/* NT_PRSTATUS == 1 */
	if (ptrace (PTRACE_GETREGSET, pid, 1, &iovec) < 0)
		return;

	regs->fp = gregs[29];
	regs->sp = gregs[31];
	regs->pc = gregs[32];
#endif

	return;
}

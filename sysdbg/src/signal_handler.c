/*
 * Backtrace
 *
 * History:
 *   2015/09/18 - [liuqinglin] Create
 *
 */
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <signal.h>
#include <fcntl.h>
#include <ucontext.h>
#include <sys/wait.h>
#include <pthread.h>

#include "sysdbg.h"
#include "common.h"
#include "proc.h"
#include "io.h"
#include "backtrace.h"

#include "arch_dep.h"

#define DEFAULT_SIG_SIZE 11

static char __symbol_file[128] = "";			/* 符号表文件 */
char __crushdump_file[2][128];			/* 定向程序异常输出的文件 */
static int init_debug_flag = 0;

extern int init_debugthread();

static inline void print_except_header(int signo)
{
	pid_t pid;
	char thread_name[48] = {0};

	pid = (pid_t)gettid();

	get_thread_name(pid, thread_name);

	u_printf("\n=============== Exception Occur =================\n");
	u_printf("Version: %s\n", sysdbg_version());
	u_printf("Thread id: %d\n", pid);
	u_printf("Thread name:%s\n", thread_name);
	u_printf("Signal num: %d\n", signo);
	u_printf("Exception time: ");
	u_printf_time();
}

static void print_registers(struct ucontext *ct)
{
	u_printf("\n=============CPU registers=============\n");
	arch_dump_registers_sc(ct);
}

static void print_backtrace(struct ucontext *ct)
{
	regs_t regs;
	arch_get_regs_sc(ct, &regs);
	dump_stack(gettid(), &regs, BT_EXTBL | BT_UNWIND);
}

static void exception_action(int signo,
		siginfo_t* info, void* ct)
{
	print_except_header(signo);
	print_registers((struct ucontext *)ct);
	print_backtrace((struct ucontext *)ct);
	dump_maps(gettid());

	return ;
}

static void __prev_init(const char *symbol_file,
		const char *crushdump_file,
		int dumpfile_size,
		int flags)
{
	init_debug_flag = flags;
	/*default : init debugthread*/
	if (!(init_debug_flag & NF_NO_DEBUGTHREAD)) {
		init_debugthread();
	}

	if (NULL != symbol_file && 0 == access(symbol_file, R_OK | W_OK))
		strcpy(__symbol_file, symbol_file);
	if (NULL != crushdump_file) {
		memset(__crushdump_file, 0, sizeof(__crushdump_file));
		sprintf(__crushdump_file[0], "%s.0", crushdump_file);
		sprintf(__crushdump_file[1], "%s.1", crushdump_file);
	}
	if (0 < dumpfile_size)
		log_file_limit = dumpfile_size / 2;
}

static int install_signals(int *signals, int size)
{
	int i = 0;
	struct sigaction sigact;

	stack_t ss;
	ss.ss_sp = malloc(SIGSTKSZ);
	if (ss.ss_sp == NULL)
		return -1;

	ss.ss_flags = 0;
	ss.ss_size = SIGSTKSZ;
	if (sigaltstack (&ss, NULL) < 0) {
		free(ss.ss_sp);
		return -1;
	}

	sigemptyset(&sigact.sa_mask);
	memset(&sigact, 0, sizeof (struct sigaction));
	sigact.sa_flags = SA_ONESHOT | SA_SIGINFO;
	sigact.sa_sigaction = exception_action;

	for (i = 0; i < size; i++)
		sigaction(signals[i], &sigact, NULL);

	return 0;
}

int __init_sysdbg(const char *symbol_file,
		const char *crushdump_file,
		int dumpfile_size,
		int flags)
{
	int signals[DEFAULT_SIG_SIZE] = {
		SIGHUP, SIGINT, SIGQUIT, SIGILL, SIGTRAP, SIGABRT,
		SIGBUS, SIGFPE, SIGSEGV, SIGPWR, SIGSYS };

	__prev_init(symbol_file, crushdump_file, dumpfile_size, flags);

	return install_signals(signals, DEFAULT_SIG_SIZE);
}


int __init_sysdbg2(int signum,
		const char *symbol_file,
		const char *crushdump_file,
		int dumpfile_size,
		int flags)
{
	int signals[1] = {signum};

	__prev_init(symbol_file, crushdump_file, dumpfile_size, flags);

	return install_signals(signals, 1);
}

/*signum: a set of signals
 *size: the number of signals
 */
int __init_sysdbg3(int *signum,
		int size,
		const char *symbol_file,
		const char *crushdump_file,
		int dumpfile_size,
		int flags)
{

	__prev_init(symbol_file, crushdump_file, dumpfile_size, flags);

	return install_signals(signum, size);
}

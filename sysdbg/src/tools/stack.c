#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/ptrace.h>
#include <asm/ptrace.h>
#include <fcntl.h>
#include <getopt.h>

#include "common.h"
#include "elfparser.h"
#include "stack.h"

#include "arch_dep.h"
#include "backtrace.h"

static int __pid = 0;
static void __sig_int(int sig)
{
	if(0 != __pid){
		ptrace(PTRACE_DETACH, __pid, 0, 0);
		ptrace(PTRACE_CONT, __pid, 0, 0);
	}

	exit(-1);
}

static void print_regs(struct sys_regs * regs)
{
	printf("\n");
	printf("===================CPU registers==============================\n");
	printf("PC: %p        EBP: %p        ESP: %p\n", \
		  (void *)regs->pc, (void *)regs->fp, (void *)regs->sp);
}

/*show registers and call stack.
 *do backtrace using ebp or esp.
 */
int show_user_stack(int pid)
{
	struct sys_regs regs = {0};

    arch_get_regs_ptrace(pid, &regs);
    print_regs(&regs);

    dump_stack(pid, &regs, BT_FP | BT_UNWIND);
    
	return 0;
}

int stack_main(int argc, char *argv[])
{
	static struct option long_options[] = {
		{"pid",		required_argument,	0, 'p'},
		{0,		0,			0,  0 }
	};
	int param_error = 0;		/* parameters error flag */
	int char_option;		
	int check_pid = 0;
	int pid = 0;

	opterr = 0;			/* prevent the error message of getopt */
	while(1){
		char_option = getopt_long(argc, argv, "p:", long_options, NULL);
		if (char_option == -1)
			break;

		check_pid += char_option;
		switch(char_option){
			case 'p':
				pid = atoi(optarg);
				{
					char buf[8] = "";
					sprintf(buf, "%d", pid);
					if(strcmp(buf, optarg)){
						printf("Error: you input an invalid pid.\n");
						param_error = 1;
					}
				}
				break;
			case '?':
				printf("Error:option %c requires an argument\n",optopt);
				param_error = 1;
				break;
			default:
				param_error = 1;
				break;
		}
	}

	if(0 != argc - optind || 'p' != check_pid || param_error)
		goto stack_usage;

	if(THREAD_USER != get_thread_attr(pid)){
		printf("Error: process %d is not a valid user process\n", pid);
		return -1;
	}

	if(1 == pid){
		printf("Error: process can not be 1\n");
		return -1;
	}

	signal(SIGINT, __sig_int);
	__pid = pid;
    if(-1 == ptrace(PTRACE_ATTACH, pid, 0, 0) || errno){
		printf("Error: process %d can *not* attach, errno is %d\n", pid, errno);
		printf("Are you root?\n");
		return -1;
	}
	waitpid(pid, NULL, WUNTRACED);	
	
	show_user_stack(pid);
	
	if(-1 == ptrace(PTRACE_DETACH, pid, 0, 0)){
		printf("Error: failed to detach process %d, errno is %d\n",pid,errno);
	}

	return 0;

stack_usage:
	print_usage(USAGE_STACK);
	return -1;
}


#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <getopt.h>
#include <sys/wait.h>
#include <signal.h>
#include <sys/ptrace.h>
#include <errno.h>
#include <string.h>

#include "common.h"
#include "bind.h"
#include "stack.h"

static int __pid = 0;
static void __sig_int(int sig)
{
	if(0 != __pid){
		ptrace(PTRACE_DETACH, __pid, 0, 0);
		ptrace(PTRACE_CONT, __pid, 0, 0);
	}

	exit(-1);
}

int bind_main(int argc, char *argv[])
{
	static struct option long_options[] = {
		{"pid",		required_argument,	0, 'p'},
		{0,		0,			0,  0 }
	};
	int param_error = 0;		/* parameters error flag */
	int char_option;
	int check_pid = 0;
	int pid = 0;
	char input[16] = "";
	int has_attached = 0;        /*the attach status of the tracee*/
    char *fgets_ret __attribute__((unused));
	int status;

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

	if (0 != argc - optind || 'p' != check_pid || param_error) {
		print_usage(USAGE_BIND);
		return -1;
	}

	if(THREAD_USER != get_thread_attr(pid)){
		printf("process %d is not a valid process\n", pid);
		return -1;
	}

	signal(SIGINT, __sig_int);
	printf("debug pid is %d .\n", pid);
	__pid = pid;
	while(1) {
		printf("input command(stop | continue | stack | quit): ");
		memset(input, 0x0, 16);
		fgets_ret = fgets(input, 16, stdin);
		if('\n' == input[strlen(input) - 1])
			input[strlen(input) - 1] = 0x0;

		errno = 0;

		if(0 == strcmp(input, "stop")) {
			if(0 != has_attached){
				printf("The process %d has stopped.\n",pid);
				continue;
			}
			if(-1 == ptrace(PTRACE_ATTACH, pid, 0, 0)){
				printf("Process %d can *not* attach, errno is %d.\n",
						pid, errno);
				continue;
			}
			waitpid(pid, NULL, WUNTRACED);
			has_attached = 1;
			__pid = pid;
			printf("Stop pid: %d success.\n", pid);
		}

		if(0 == strcmp(input, "continue")) {
			if(0 == has_attached){
				printf("The process %d has detached. \n",pid);
				continue;
			}
			if(-1 == ptrace(PTRACE_DETACH, pid, 0, 0)){
				printf("Process %d can *not* detach, errno is %d.\n",
						pid, errno);
				continue;
			}
			has_attached = 0;
			__pid = 0;
			printf("Resume pid: %d success.\n", pid);
		}

		if(0 == strcmp(input, "stack")) {
			if(0 == has_attached){
				if(-1 == ptrace(PTRACE_ATTACH,pid,0,0)){
					printf("Process %d can not attach ,errno is %d\n",pid,errno);
					continue;
				}
				waitpid(pid, &status, WUNTRACED);

				if (WIFEXITED(status)) {
					printf("exited, status=%d\n", WEXITSTATUS(status));
				} else if (WIFSIGNALED(status)) {
					printf("killed by signal %d\n", WTERMSIG(status));
				} else if (WIFSTOPPED(status)) {
					printf("stopped by signal %d\n", WSTOPSIG(status));
				} else if (WIFCONTINUED(status)) {
					printf("continued\n");
				}
				show_user_stack(pid);
				if(-1 == ptrace(PTRACE_DETACH,pid,0,0)){
					printf("Process %d detached failed.\n",pid);
				}
			}else {
				show_user_stack(pid);
			}
			continue;
		}

		if(0 == strcmp(input, "quit") || 'q' == input[0]) {
			if(0 != has_attached
				&& -1 == ptrace(PTRACE_DETACH, pid, 0, 0)){
				printf("process %d detached failed, errno is %d.\n",
					pid, errno);
			}
			__pid = 0;
			printf("quit success %d.\n", pid);
			break;
		}
	}

	return 0;
}

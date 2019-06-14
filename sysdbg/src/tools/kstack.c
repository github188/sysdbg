#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <sys/ioctl.h>

#include "../kernel/debugmisc.h"
#include "common.h"
#include "kstack.h"


/*
 * 说明：显示线程内核调用栈
 */
static int show_kernel_stack(int pid)
{
	kernelstack_t ks = { pid };
	int fd;
	int ret = 0;

	if(-1 == (fd = open(DEBUGMISC_FILENAME, O_RDWR))){
		printf("%s\n", OPEN_DEBUG_MISC_FAILED);
		return -1;
	}
	if(0 != ioctl(fd, DEBUG_KERNEL_BACKTRACE, &ks)){
		ret = -2;
	}
	close(fd);

	return ret;
}

int kstack_main(int argc, char *argv[])
{
	static struct option long_options[] = {
		{"pid",		required_argument,	0, 'p'},		/* 线程id */
		{0,		0,			0,  0 }
	};
	int param_error = 0;		/* 解析过程中参数是否错误 */
	int char_option;		/* 解析的名称缩写 */
	int check_pid = 0;
	int pid = 0;

	opterr = 0;			/* 屏蔽getopt 的错误输出 */
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
						printf("Hint: you input an invalid pid.\n");
						param_error = 1;
					}
				}
				break;
			case '?':
				param_error = 1;
				break;
			default:
				param_error = 1;
				break;
		}
	}

	if (0 != argc - optind || 'p' != check_pid || param_error) {
		print_usage(USAGE_KSTACK);
		return -1;
	}

	if(THREAD_NOEXIST == get_thread_attr(pid)){
		printf("process %d is not a valid process\n", pid);
		return -1;
	}

	show_kernel_stack(pid);
	return 0;
}

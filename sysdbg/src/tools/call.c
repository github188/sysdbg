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
#include "call.h"
#include "debugthread.h"
#include "elfparser.h"


/*
 * 说明：执行内核函数
 */
static int exec_kernel_function(const struct kernelcall *pkc)
{
	int fd;
	int ret = 0;

	if(-1 == (fd = open(DEBUGMISC_FILENAME, O_RDWR))){
		printf("%s\n", OPEN_DEBUG_MISC_FAILED);
		return -1;
	}
	if(0 != ioctl(fd, DEBUG_KERNEL_CALL, pkc))
		ret = -2;
	close(fd);

	return ret;
}


int call_main(int argc, char *argv[])
{
	static struct option long_options[] = {
		{"pid",         required_argument,      0, 'p'},        /* 线程id */
		{"name",        required_argument,      0, 'n'},        /* 函数符号名 */
		{"addr",        required_argument,      0, 'a'},        /* 函数地址 */
		{0,             0,                      0,  0 } 
	};      
	int param_error = 0;            /* 解析过程中参数是否错误 */
	int char_option;                /* 解析的名称缩写 */
	int check_pid = 0;              /* 检查pid 和 type参数 */
	int check_addr = 0;             /* 检查addr 和 size参数，或file 和name 参数 */
	kernelcall_t kc;
	int size;

	char symbol_name[32] = "";
	char * filename = NULL;
	int pid = -1;
	unsigned long addr = 0;
	int param_count = 0;
	int param1 = 0, param2 = 0;

	opterr = 0;                     /* 屏蔽getopt 的错误输出 */
	while(1){
		char_option = getopt_long(argc, argv, "p:n:a:", long_options, NULL);
		if (char_option == -1)
			break;  

		switch(char_option){
			case 'p':
				pid = atoi(optarg);
				check_pid += char_option;
				{
					char buf[8] = "";
					sprintf(buf, "%d", pid);
					if(strcmp(buf, optarg)){
						printf("Hint: you input an invalid pid.\n");
						param_error = 1;
					}
				}
				break;  
			case 'a':
				addr = (unsigned long)strtoul(optarg, NULL, 16);
				check_addr += char_option;
				break;  
			case 'n':
				strcpy(symbol_name, optarg);
				check_addr += char_option;
				break;
			case '?':
				param_error = 1;
				break;
			default:
				param_error = 1;
				break;
		}
	}

	param_count = argc - optind;
	switch(argc - optind){
		case 0:
			break;
		case 1:
			param1 = (char)strtoul(argv[optind++], NULL, 10);
			break;
		case 2:
			param1 = (char)strtoul(argv[optind++], NULL, 10);
			param2 = (char)strtoul(argv[optind++], NULL, 10);
			break;
		default:
			param_error = 1;
	}

	/* 判断参数格式合法性 */
	if (optind < argc || 1 == param_error || !(('a' == check_addr) || ('n' == check_addr))) {
		print_usage(USAGE_CALL);
		return -1;
	}

	kc.paramcount = param_count;
	kc.param1 = param1;
	kc.param2 = param2;

	/* 解析函数地址 */
	if('p' == check_pid){
		/* 解析用户线程函数 */
		if(1 == pid){
			printf("you can not debug process 1\n");
			return -1;
		}
		
		if(THREAD_USER != get_thread_attr(pid)){
			printf("%d is not a valid user thread\n", pid);
			return -1;
		}

		if('n' == check_addr){
			if(0 == check_symbol_in_elf(pid)){
				
				filename = get_filename_from_pid(pid);

				if(NULL == filename)
					return -2;

				if(0 != get_addr_from_elf(filename, symbol_name, "FUNC", &addr, &size)){
					printf("can not find symbol %s int process %d\n", symbol_name, pid);
					free(filename);
					return -1;
				}
				free(filename);				
			}else{
				char *env = getenv(USER_SYMBOL);
				if(NULL == env || 0 != access(env, R_OK)){
					printf("the process %d have no symbol, and can not get from env\n", pid);
					return -1;
				}else{
					/* 转换符号名称为地址, 从符号文件 */
					if(0 == get_address_from_symbolfile(env, symbol_name, "FUNC",
								&addr, &size)){
					}else{
						printf("cant not find symbol %s in file %s\n",
								symbol_name, env);
						return -1;
					}
				}
			}
		}
	}else{
		/* 解析内核函数 */
		if('n' == check_addr){
			char *env = getenv(KERNEL_SYMBOL);
			if(NULL == env || 0 != access(env, R_OK)){
				printf("you must give the kernel symbol path in env\n");
				return -1;
			}else{
				/* 转换符号名称为地址, 从符号文件 */
				if(0 == get_address_from_symbolfile(env, symbol_name, "FUNC",
							&addr, &size)){
				}else{
					printf("can not find symbol %s in file %s\n",
							symbol_name, env);
					return -1;
				}
			}
		}
	}

	kc.addr = addr;		/* 函数地址 */

	if('p' == check_pid){
		sysdbg_sendmsg(pid, &kc);
	}else{
		exec_kernel_function(&kc);
	}
	return 0;
}

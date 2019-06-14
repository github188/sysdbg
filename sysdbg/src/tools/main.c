#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <signal.h>

#include "ps.h"
#include "common.h"
#include "data.h"
#include "stack.h"
#include "kstack.h"
#include "bind.h"
#include "call.h"

#include "unwind.h"

typedef struct sysdbg_usr_cmd{
	char *cmd_name;
	int (*cmd_func)(int argc, char *argv[]);
}sysdbg_usr_cmd_t;

static sysdbg_usr_cmd_t user_cmd[] = {
	{"ps", ps_main},			/* 查看线程信息 */
	{"bind", bind_main},			/* 查看线程信息 */
	{"mm", datamm_main},		/* 修改进程/内核数据 */
	{"md", datamd_main},		/* 查看进程/内核数据 */
	{"call", call_main}, 		/* 调用进程或内核函数 */
	{"stack", stack_main}, 		/* 查看用户线程的用户态调用栈 */
	{"kstack", kstack_main},		/* 查看用户线程或内核线程的内核调用栈 */
    {0}
};

int main(int argc, char **argv)
{
	sysdbg_usr_cmd_t *node = user_cmd;
	
	const char * cmd_name = argv[0];
	const char * func_name = NULL;

	cmd_name = get_cmdname(cmd_name);

	/* If we were called as "sysdbg <function> arg1 arg2 ..." */
	if(argc >= 2){
		func_name = argv[1];	
	}

	while(node->cmd_name){
		if(0 == strcmp(cmd_name, node->cmd_name)){
			return (node->cmd_func)(argc,argv);
		}else if(argc >= 2 && 
				NULL != func_name && 
				0 == strcmp(func_name, node->cmd_name)) {
			argv++;
			argc--;
			return (node->cmd_func)(argc,argv);			
		}
		node++;
	}
	
	print_usage(USAGE_SYSDBG);
    
	return 0;
}

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
	{"ps", ps_main},			/* �鿴�߳���Ϣ */
	{"bind", bind_main},			/* �鿴�߳���Ϣ */
	{"mm", datamm_main},		/* �޸Ľ���/�ں����� */
	{"md", datamd_main},		/* �鿴����/�ں����� */
	{"call", call_main}, 		/* ���ý��̻��ں˺��� */
	{"stack", stack_main}, 		/* �鿴�û��̵߳��û�̬����ջ */
	{"kstack", kstack_main},		/* �鿴�û��̻߳��ں��̵߳��ں˵���ջ */
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

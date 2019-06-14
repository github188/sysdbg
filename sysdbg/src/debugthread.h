#ifndef __SYSDBG__DEBUGTHREAD_H__
#define __SYSDBG__DEBUGTHREAD_H__
#include "../kernel/debugmisc.h"

/*
 * 说明：发送消息（调试命令中使用）
 */
int sysdbg_sendmsg(int pid, const kernelcall_t *pkc);

/*
 * 说明：删除消息队列（只在用户程序中安装）
 */
int sysdbg_delmsg();

#endif


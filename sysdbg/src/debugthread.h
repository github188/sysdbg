#ifndef __SYSDBG__DEBUGTHREAD_H__
#define __SYSDBG__DEBUGTHREAD_H__
#include "../kernel/debugmisc.h"

/*
 * ˵����������Ϣ������������ʹ�ã�
 */
int sysdbg_sendmsg(int pid, const kernelcall_t *pkc);

/*
 * ˵����ɾ����Ϣ���У�ֻ���û������а�װ��
 */
int sysdbg_delmsg();

#endif


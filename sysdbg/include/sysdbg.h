#ifndef __SYSDBG_H__
#define __SYSDBG_H__
#include <signal.h>

#define BACKTRACE_SIZE      50         /*max size of backtrace*/

#ifdef __cplusplus
extern "C"{
#endif

#define NF_NO_DEBUGTHREAD		0x1000		/*don't need the debugthread*/

/* �ú��Ѿ�����(20151010)
* ����ʹ��backtrace/unwind stack���ַ�ʽ������ջ
*/
#define NF_USE_BACKTRACE		0X2000		/*we can use backtrace since glibc2.1*/

/* **********************˵��*******************
 *����:
 * 	symbol_file:�Ƿ����ļ������Ǻ��ԣ�����NULL���ɣ�
 *	crushdump_file:�ǳ����쳣������ļ���ΪNULL �����������̨
 *	dumpfile_size:���ɵ�log�ļ���С���ޣ���������պ���д��
 *			Ĭ��1M����λ:KB
 *			����<0��ʾʹ��Ĭ��ֵ
 *	flags: �������ֵ�������ϻ�0
 *		NF_NO_DEBUGTHREAD �����������̣߳���ʹ��call����ʱ��ָ����ѡ�� 
 *	signum:�ź�id
 *	signals: �Զ�����Ҫ���ٵ��źż���
 *	size: signalsָ����źŵĸ���
 *
 *
 *ʾ��:
 *	init_sysdbg(NULL, NULL,0);
 *	 __init_sysdbg(NULL, NULL,0, 0);
 *	 __init_sysdbg(NULL, NULL,2048,NF_NO_DEBUGTHREAD);
 *	 __init_sysdbg(NULL, "/usr/cursh.out", 0,NF_NO_DEBUGTHREAD);
 *	 __init_sysdbg2(SIGPIPE,  "/bin/ebt.sym", "/usr/cursh.out",0, 0);
 *
 *����:
 * gcc main.c -funwind-tables -rdynamic -lsysdbg
 */

/*****************20140507�ӿ��޸�˵��****************
*1. ���Ҫ����log �ļ���С����ʹ���½ӿ�__init_sysdbg*()
*2. ʹ�þɽӿ�init_sysdbg*()�ĳ�����Ҫ����log ��С��
*    �����û�������SYSDBG_LOG_LIMIT, ��λKB.
*    ��:SYSDBG_LOG_LIMIT=50 ��ʾ����log�ļ���СΪ50KB.
*3. ����ӿںͻ��������ж�ָ�����Ի�������Ϊ׼.
*/

extern int __init_sysdbg(const char *symbol_file, 
		const char *crushdump_file,
		int dumpfile_size,
		int flags);

#define init_sysdbg(symbol_file, crushdump_file, flags) \
	__init_sysdbg(symbol_file, crushdump_file, 0, flags);

extern int __init_sysdbg2(int signum, 
		const char *symbol_file, 
		const char *crushdump_file,
		int dumpfile_size,
		int flags);

#define init_sysdbg2(signum, symbol_file, crushdump_file, flags) \
	__init_sysdbg2(signum, symbol_file, crushdump_file, 0, flags);

extern int __init_sysdbg3(int *signals, 
		int size, 
		const char *symbol_file, 
		const char *crushdump_file, 
		int dumpfile_size,
		int flags);

#define init_sysdbg3(signals, size, symbol_file, crushdump_file, flags) \
	__init_sysdbg3(signals, size, symbol_file, crushdump_file, 0, flags);


char *sysdbg_version();
#define SYSDBG__VERSION	sysdbg_version()

#ifdef __cplusplus
}
#endif

#endif


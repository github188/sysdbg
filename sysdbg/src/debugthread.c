#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/msg.h>
#include <sys/ipc.h>
#include <fcntl.h>
#include <pthread.h>
#include <errno.h>
#include "debugthread.h"
#include "common.h"

#ifndef getpgid
#define getpgid(pid)    __getpgid(pid)
#endif

#define SYS_MSG_PERM		(S_IRUSR | S_IWUSR)
#define MSG_KEY_FILE		"/proc/%d/stat"
typedef struct msgtype{
	long		mtype;
	kernelcall_t	kc;
}msgtype_t;

static void *__debug_thread(void *argv);
static int __thread_call = 0;		/* ͬһ�߳�����ֻ�����ʼ��һ�� */
static pthread_mutex_t __thread_call_mt = PTHREAD_MUTEX_INITIALIZER;

int init_debugthread()
{
	int pgid;
	char msg_keyfile[32] = "";
	key_t key;
	ptr_t msgid;
	pthread_t pid;
	pthread_attr_t attr;

	pthread_mutex_lock(&__thread_call_mt);
	if(0 == __thread_call){
		sysdbg_delmsg();
	}else{
		pthread_mutex_unlock(&__thread_call_mt);
		return -4;
	}

	pgid = getpgid(0);
	sprintf(msg_keyfile, MSG_KEY_FILE, pgid);
	if(-1 == (key = ftok(msg_keyfile, 'a'))){
		pthread_mutex_unlock(&__thread_call_mt);
		return -1;
	}

	errno = 0;
	if(-1 == (msgid = msgget(key, SYS_MSG_PERM | IPC_CREAT | IPC_EXCL)) || errno){
		pthread_mutex_unlock(&__thread_call_mt);
		return -2;		/* debug thread already run in the thread group */
	}

	/* ִ�е����߳� */
	if(0 != pthread_attr_init(&attr)){
		pthread_mutex_unlock(&__thread_call_mt);
		return -3;
	}

	if(0 != pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED)) {
		pthread_attr_destroy(&attr);
		pthread_mutex_unlock(&__thread_call_mt);
		return -3;
	}

	if(0 != pthread_create(&pid, &attr, __debug_thread, (void *)msgid)) {
		pthread_attr_destroy(&attr);
		pthread_mutex_unlock(&__thread_call_mt);
		return -3;
	}

	__thread_call++;
	pthread_attr_destroy(&attr);
	pthread_mutex_unlock(&__thread_call_mt);
	return 0;
}

/*
 * ˵���������߳�������
 */
static void *__debug_thread(void *argv)
{
	ptr_t msgid;
	msgtype_t mt;

	msgid = (ptr_t)argv;

	while(1){
		/* ���յ���ģ������ */
		memset(&mt, 0x00, sizeof(msgtype_t));
		if(-1 == msgrcv(msgid, &mt, sizeof(msgtype_t), (long)1, 0))
			printf("in debug thread loop,msgrcv is -1\n");

		if(0x00 != mt.kc.addr){
			/* ִ�к��� */
			/*
			dprintf("func addr 0x%08x, paramcount: %d, 0x%x, 0x%x\n", mt.kc.addr,
					mt.kc.paramcount, mt.kc.param1, mt.kc.param2);
			continue;
			*/

			printf("\nrun function start======>\n");
			switch(mt.kc.paramcount){
				case 0:
					((func_param0)mt.kc.addr)();
					break;
				case 1:
					((func_param1)mt.kc.addr)(mt.kc.param1);
					break;
				case 2:
					((func_param2)mt.kc.addr)(mt.kc.param1, mt.kc.param2);
					break;
				default:
					break;
			}
			printf("run function end======<\n");
		}
	}

	return NULL;
}

/*
 * ˵����������Ϣ
 */
int sysdbg_sendmsg(int pid, const kernelcall_t *pkc)
{
	int pgid;
	char msg_keyfile[32];
	key_t key;
	int msgid;
	msgtype_t mt;

	pgid = getpgid(pid);
	sprintf(msg_keyfile, MSG_KEY_FILE, pgid);
	if(-1 == (key = ftok(msg_keyfile, 'a')))
		return -1;

	if(-1 == (msgid = msgget(key, SYS_MSG_PERM)))
		return -2;		/* debug thread already run in the thread group */

	mt.mtype = 1;
	mt.kc = *pkc;
	if(-1 == msgsnd(msgid, &mt, sizeof(msgtype_t), IPC_NOWAIT))
		return -3;
	else
		printf("Send message success , addr is : %p\n", (void *)mt.kc.addr);

	return 0;
}

/*
 * ˵����ɾ����Ϣ����
 */
int sysdbg_delmsg()
{
	int pgid;
	char msg_keyfile[32];
	key_t key;
	int msgid;

	pgid = getpgid(0);
	sprintf(msg_keyfile, MSG_KEY_FILE, pgid);
	if(-1 == (key = ftok(msg_keyfile, 'a')))
		return -1;

	if(-1 == (msgid = msgget(key, SYS_MSG_PERM)))
		return -2;		/* debug thread already run in the thread group */

	/* delete the msg queue */
	if(-1 == msgctl(msgid, IPC_RMID, NULL))
		return -3;

	return 0;
}



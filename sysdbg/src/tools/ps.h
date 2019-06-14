#ifndef __SYSDBG_PROCPS_H__
#define __SYSDBG_PROCPS_H__
/*
 * auth: wangyuantao@kedacom.com
 * date: Sun Oct  8 09:33:21 CST 2006
 */
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <dirent.h>
#include <stdint.h>
#include "common.h"
#include "proc.h"

/* ������Ϣ�����ݽṹ */
typedef struct procinfo{
	int pid;			/* �߳�id */
	char command[MAX_PATH];		/* �������� */
	char filepath[MAX_PATH];	/* �ļ�·�� */
	char comm[COMM_LEN];		/* �߳������ɸ��ģ� */
	char threadattr[32];		/* �߳����ԣ�user, kernel�� */
	char state[4];	
	unsigned long flags;         /*The kernel flag of the process*/
	unsigned long  rss;			/* text + data + stack space,we round it to kbytes */
	int vmstk;				/* ջ�Ĵ�С: ��λkb �ֽ� */
	unsigned long policy;		/* 0:normal 1:fifo 2:RR*/
	long nice;			/* nice ֵ�뾲̬���ȼ���� */
	long priority; 		/* ��̬���ȼ� */
	unsigned long bp;
	unsigned long top;		/* ��ջ�� */
	unsigned long bottom;		/* ��ջ��(�ߵ�ַ) */
}procinfo_t;

/* flag bits for procps_scan(xx, flags) calls */
enum {
	PSSCAN_DEFAULT		= 0,
	PSSCAN_SHOWLIBS		= 1 << 0,
	PSSCAN_HASPID		= 1 << 1,
	PSSCAN_THREAD		= 1 << 2
};

extern int ps_main(int argc, char *argv[]);

#endif



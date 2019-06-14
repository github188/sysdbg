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

/* 进程信息的数据结构 */
typedef struct procinfo{
	int pid;			/* 线程id */
	char command[MAX_PATH];		/* 命令行名 */
	char filepath[MAX_PATH];	/* 文件路径 */
	char comm[COMM_LEN];		/* 线程名（可更改） */
	char threadattr[32];		/* 线程属性（user, kernel） */
	char state[4];	
	unsigned long flags;         /*The kernel flag of the process*/
	unsigned long  rss;			/* text + data + stack space,we round it to kbytes */
	int vmstk;				/* 栈的大小: 单位kb 字节 */
	unsigned long policy;		/* 0:normal 1:fifo 2:RR*/
	long nice;			/* nice 值与静态优先级相关 */
	long priority; 		/* 动态优先级 */
	unsigned long bp;
	unsigned long top;		/* 堆栈顶 */
	unsigned long bottom;		/* 堆栈底(高地址) */
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



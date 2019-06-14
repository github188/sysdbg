#ifndef __SYSDBG_KERNEL_H__
#define __SYSDBG_KERNEL_H__
/*
 * auth: wangyuantao@kedacom.com
 * date: Wed Oct 11 10:36:21 CST 2006
 */

//#define DEBUGMISC_MINOR			199	/* for sysdbg */

#define DEBUGMISC_FILENAME "/dev/debugmisc"	/* �豸�ļ��� */
#define OPEN_DEBUG_MISC_FAILED "kernel debug module not load?"

#define KERNEL_DATA_MODE_INVALID	0
#define KERNEL_DATA_MODE_READ		1	/* ��ȡ���� */
#define KERNEL_DATA_MODE_WRITE		2	/* д������ */

#define KERNEL_DATA_ATTR_INVALID	0
#define KERNEL_DATA_ATTR_PHYS		1	/* �����ַ */
#define KERNEL_DATA_ATTR_VIRT		2	/* �����ַ */
#define KERNEL_DATA_ATTR_REG		3	/* �Ĵ�����ַ */

#define DEBUG_IOC_MAGIC 'x'
#define DEBUG_KERNEL_RWDATA 		_IOWR(DEBUG_IOC_MAGIC,  1,struct kerneldata)
#define DEBUG_KERNEL_DATA_TYPE 	_IOWR(DEBUG_IOC_MAGIC, 2,struct kerneldatatype)
#define DEBUG_KERNEL_CALL			_IOW(DEBUG_IOC_MAGIC, 3,struct kernelcall)
#define DEBUG_KERNEL_BACKTRACE 	_IOW(DEBUG_IOC_MAGIC, 4,struct kernelstack)

typedef void (*func_param0)(void);
typedef void (*func_param1)(int t1);
typedef void (*func_param2)(int t1, int t2);

/* ��Ҫ�����ں˺���ʱ�����ݸ��ں˵����ݽṹ */
typedef struct kernelcall{
	unsigned long addr;				/* ������ַ */
	int paramcount;				/* ���������������������ε� */
	int param1;				/* ����1 */
	int param2;				/* ����2 */
}kernelcall_t;

/*��Ҫ��ȡ�޸��ں�����ʱ�����ݸ��ں˵����ݽṹ */
typedef struct kerneldata{
	int mode;				/* ��ȡ���ݻ��� �޸����� */
	int attribute;				/* ��ַ���� */
	unsigned long addr;				/* �ں�������ʼ��ַ */
	int len;				/* ���ݳ��� */
	char *buf;				/* ���ݻ����� */
}kerneldata_t;

/* ��ӡ�̵߳��ں˵���ջ */
typedef struct kernelstack{
	int pid;				/* �߳�id */
}kernelstack_t;

/* ȡ�õ�ַ���� */
typedef struct kerneldatatype{
	unsigned long addr;				/* �ں˵�ַ */
	int type;				/* ���صĵ�ַ���� */
	unsigned long virt_addr;				/* ���ص������ַ�������ַ */
	unsigned long phy_addr;
}kerneldatatype_t;

#endif


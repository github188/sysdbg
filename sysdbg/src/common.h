#ifndef __SYSDBG_COMMON_H__
#define __SYSDBG_COMMON_H__

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <unistd.h>
#include <sys/syscall.h>
#include <stdint.h>
#include <time.h>

#define BUFFER_SIZE     1024
#define FUNCNAME_SIZE   64
#define MAX_PATH        256     /* max len of file pathname */
#define LOGFILE_SIZE    512    /* the log file limited (KB) */
#define COMM_LEN        16      /* max len of thread name */

#define THREAD_USER	1			/*user thread*/
#define THREAD_KERNEL	2			/*kernel thread*/
#define THREAD_NOEXIST	3			/*thread no exist */

#define min(x,y) ((x) < (y) ? (x) : (y))

#if __WORDSIZE == 64
#define PTR_LONG 16	/*the length of a point */
#else
#define PTR_LONG 8
#endif

typedef uintptr_t   ptr_t;

#ifndef gettid
#define gettid() syscall(__NR_gettid)
#endif

#define READ_MEM_SIZE		256			/* 默认读取进程或内核内存大小 */
#define KERNEL_SYMBOL		"KERNEL_SYMBOL"		/* 环境变量名 */
#define USER_SYMBOL         "USER_SYMBOL"
#define SYSDBG_LOG_LIMIT	"SYSDBG_LOG_LIMIT"   /*log文件最大值*/

extern int check_is_hex_number(const char *hex_num);

extern char*  xmalloc_readlink(const char *path);


/*
 * 读取整个文件内容
 */
int read2buf(const char *filename, void *buf, int buf_size);
ssize_t safe_getline(int fd, char *lineptr, size_t size);

extern int get_thread_attr(int pid);
extern char * get_filename_from_pid(int pid);

extern char *skip_fields(char *str, int count);
extern long fast_strtol_10(char **endptr);
extern unsigned long fast_strtoul_10(char **endptr);

extern unsigned int pages_to_kb(void);
extern const char* get_cmdname(const char *name);

extern char*  safe_strncpy(char *dst, const char *src, size_t size);

/*
 * 打印usage:
 */
#define USAGE_SYSDBG                 0
#define USAGE_PS				   1
#define USAGE_MD		   2
#define USAGE_CALL			   3
#define USAGE_STACK			   4
#define USAGE_KSTACK		   5
#define USAGE_BIND			   6
void print_usage(int cmd);
#endif


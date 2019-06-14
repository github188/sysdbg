#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdarg.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <errno.h>
#include "../include/sysdbg.h"
#include "common.h"
#include "version.h"

#define STR(x)	#x
#define XSTR(x)	STR(x)

#ifdef SYSDBG__VERSION
#undef SYSDBG__VERSION
#endif

#define SYSDBG__VERSION    \
	XSTR(MOD_MAIN_VERSION)"." \
	XSTR(MOD_MAJOR_VERSION)"." \
	XSTR(MOD_MINOR_VERSION)"."XSTR(MODULE_SUBVERSION)

char __sysdbg_version[] = SYSDBG__VERSION;
char *sysdbg_version()
{
	return __sysdbg_version;
}

int check_is_hex_number(const char *hex_num)
{
	int i, len;
	char *p = (char*)hex_num;

	len = strlen(hex_num) - 1;	/* strip the '\n' char */
	if((0 == memcmp(hex_num, "0x", 2))
			|| (0 == memcmp(hex_num, "0X", 2))){
		len -= 2;
		p += 2;
	}
	for(i = 0; i < len; i++, p++){
		if(((*p >= '0') && (*p <= '9')) || ((*p >= 'a') && (*p <= 'f')) || ((*p >= 'A') && (*p <= 'F'))){
		}else{
			return -1;
		}
	}

	return 0;
}

/*This function returns a malloced char* that you will have to free yourself.*/
char*  xmalloc_readlink(const char *path)
{
	enum { GROWBY = 80 }; /* how large we will grow strings by */

	char *buf = NULL, *bufold;
	int bufsize = 0, readsize = 0;

	do {
		bufsize += GROWBY;
		bufold = buf;
		buf = realloc(buf, bufsize);
		if (NULL == buf) {
			if (NULL != bufold)
				free(bufold);
			return NULL;
		}
		readsize = readlink(path, buf, bufsize);
		if (readsize == -1) {
			free(buf);
			return NULL;
		}
	} while (bufsize < readsize + 1);

	buf[readsize] = '\0';

	return buf;
}


/*
 * 读取整个文件内容
 */
int read2buf(const char *filename, void *buf, int buf_size)
{
	int fd;
	int size;

	if(NULL == filename || 0 != access(filename, R_OK))
		return -1;

	fd = open(filename, O_RDONLY);
	if (fd < 0)
		return -1;

	size = read(fd, buf, buf_size);
	close(fd);
	if(size < 0)
		return -1;

	((char*)buf)[size > 0 ? size :0] = '\0';

	return size;
}

unsigned long fast_strtoul_10(char **endptr)
{
	unsigned char c;
	char *str = *endptr;
	unsigned long n = *str - '0';

	/* Need to stop on both ' ' and '\n' */
	while ((c = *++str) > ' ')
		n = n*10 + (c - '0');

	*endptr = str + 1; /* We skip trailing space! */
	return n;
}

long fast_strtol_10(char **endptr)
{
	if (**endptr != '-')
		return fast_strtoul_10(endptr);

	(*endptr)++;
	return - (long)fast_strtoul_10(endptr);
}

/*count: the number of space char to skip*/
char *skip_fields(char *str, int count)
{
	do {
		while (*str++ != ' ')
			continue;
		/* we found a space char, str points after it */
	} while (--count);
	return str;
}

unsigned int pages_to_kb(void)
{
	unsigned n = getpagesize();
	unsigned char shift_pages_to_kb = 0;
	unsigned char shift_pages_to_bytes = 0;
	while (1) {
		n >>= 1;
		if (!n) break;
		shift_pages_to_bytes++;
	}
	shift_pages_to_kb = shift_pages_to_bytes - 10;
	return shift_pages_to_kb;
}

/*find the pid is a user thread or a kernel thread*/
int get_thread_attr(int pid)
{
	char filename[sizeof("/proc/%d/stat") + sizeof(int) * 3];
	char buf[BUFFER_SIZE];
	unsigned long rss = 0;		/*kernel thread is 0, otherwise is not 0*/

	sprintf(filename, "/proc/%d/stat", pid);

	if(-1 == read2buf(filename, buf, BUFFER_SIZE))
		return THREAD_NOEXIST;

	char *cp = (char *)buf;

	cp = skip_fields(cp,23);
	rss = fast_strtoul_10(&cp);

	if(0 == rss)
		return THREAD_KERNEL;
	else
		return THREAD_USER;
}


/* read the exe filename of the pid */
char * get_filename_from_pid(int pid)
{
	char pidname[sizeof("/proc/%d/exe") + sizeof(int) * 3];
	char * filename = NULL;
	char * p = NULL;

	sprintf(pidname, "/proc/%d/exe", pid);

	filename = xmalloc_readlink(pidname);

	if(NULL == filename)
		return NULL;                      /*read link error*/

	p = strstr(filename, "(deleted)");
	if(NULL != p){
		free(filename);
		return NULL;             /*file has been deleted*/
	}

	return filename;
}

const char* get_cmdname(const char *name)
{
	const char *cp = strrchr(name, '/');
	if (cp)
		return cp + 1;
	return name;
}

char*  safe_strncpy(char *dst, const char *src, size_t size)
{
	if (!size)
		return dst;
	dst[--size] = '\0';
	return strncpy(dst, src, size);
}

ssize_t safe_getline(int fd, char *lineptr, size_t size)
{
	ssize_t result = 0;
	size_t cur_len = 0;

	if (lineptr == NULL || fd < 0 || size <= 0) {
		errno = EINVAL;
		return -1;
	}

	for(;;) {
		char i;
		if (read(fd, &i, 1) != 1) {
			result = -1;
			break;
		}
		if (i == EOF) {
			result = -1;
			break;
		}
		lineptr[cur_len] = i;
		cur_len++;
		if (i == '\n' || cur_len == size)
			break;
	}
	lineptr[cur_len] = '\0';
	result = cur_len ? cur_len : result;

	return result;
}

void print_usage(int cmd)
{
	printf("Usage: ");

	switch(cmd){
	case USAGE_SYSDBG:
		printf("sysdbg v1.0 (%s-%s) multi-call binary\n", __DATE__, __TIME__);
		printf(" sysdbg is a debug tool for x86/ppc/arm.\n" \
				"sysdbg [function] [arguments]...\n" \
				"   or:     [function] [arguments]...\n" \
				" \n" \
				"Currently defined functions:\n" \
				" ps, bind, md, mm,\n" \
				" call, stack, kstack\n" \
				"\n");
		break;
	case USAGE_PS:
		printf("ps [ --pid N ] [ --verbose ] [--thread]\n");
		printf("-p / --pid   pid\n");
		printf("-v / --verbose show maps of the thread\n");
		printf("-h / --thread  show threads on\n");
		break;
	case USAGE_MD:
		printf("{ mm | md } [ --pid N ]" \
				" { --name symbol_name | --addr address } \n");
		break;
	case USAGE_CALL:
		printf("call [ -p pid ] [ --name function ] [ param1 prarm2 ]\n");
		break;
	case USAGE_STACK:
		printf("stack [ -p pid ] \n");
		break;
	case USAGE_KSTACK:
		printf("kstack [ -p pid ]\n");
		break;
	case USAGE_BIND:
		printf("bind [ -p pid ]\n");
		break;

	default:
		printf("undefined command\n");
		break;
	}
}

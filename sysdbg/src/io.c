/*
 * print functions
 *
 * History:
 *   2015/09/18 - [liuqinglin <liuqinglin@kedacom.com>] Create
 *
 */
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "common.h"
#include "io.h"

extern char __crushdump_file[2][128];

int log_file_limit = LOGFILE_SIZE;

/*check the size of the log file and open it.*/
static int open_logfile()
{
	int flags = O_CREAT |O_RDWR;
	int log_limit = -1;
	int fd = -1, fd0 = -1, fd1 = -1;
	char buf[BUFFER_SIZE+1] = "";

	char *env = getenv(SYSDBG_LOG_LIMIT);

	if (NULL != env)
		log_limit = atoi(env);

	if (log_limit > 0)
		log_file_limit = (unsigned int)log_limit;

	if (0x00 != __crushdump_file[0][0]) {
		struct stat st;

		if (stat(__crushdump_file[0] ,&st) == 0 && st.st_size >= log_file_limit * 1024) {
			/* move all data from log.0 to log.1 */
			fd0 = open(__crushdump_file[0], O_RDONLY, 0666);
			fd1 = open(__crushdump_file[1], O_CREAT | O_RDWR | O_TRUNC, 0666);
			while (BUFFER_SIZE == read(fd0, buf, BUFFER_SIZE))
				write(fd1, buf, strlen(buf));

			close(fd0);
			close(fd1);

			flags |= O_TRUNC;
		} else {
			flags |= O_APPEND;
		}

		fd = open(__crushdump_file[0], flags, 0666);
	}

	if (fd < 0)
		fd = 1;

	return fd;
}

static void close_logfile(int fd)
{
	if (fd > 2)
		close(fd);

	return;
}

/* if you want to print to a file , fd must has been opened by open_logfile().
 * if fd = 1, just print to stdout
 */
void u_printf(const char * fmt,...)
{
	int fd = -1;
	char buf[BUFFER_SIZE] = "";
	va_list args;
	va_start (args, fmt);
	memset(buf, 0x00, sizeof(buf));
	vsprintf(buf, fmt, args);
	va_end (args);

	fd = open_logfile();
	write(fd, buf, strlen(buf));
	close_logfile(fd);
	return ;
}

struct tzfile_hdr_t {
	char type[20];        /* Type "TZif", "TZif2" or "TZif3" as of 2013 */
	int32_t ttisgmtcnt;   /* coded number of trans. time flags */
	int32_t ttisstdcnt;   /* coded number of trans. time flags */
	int32_t leapcnt;      /* coded number of leap seconds */
	int32_t timecnt;      /* coded number of transition times */
	int32_t typecnt;      /* coded number of local time types */
	int32_t charcnt;      /* coded number of abbr. chars */
};

static int32_t read_int32(char *p) {
	int32_t v = *(unsigned char *)p++;
	v = (v << 8) | *(unsigned char *)p++;
	v = (v << 8) | *(unsigned char *)p++;
	v = (v << 8) | *(unsigned char *)p++;
	return v;
}

static size_t get_off(const char *file_name) {
	int fd = -1;
	char hdr[44];
	char buf[6]; /* multiple of 4, 6 and 8 */
	size_t len;
	size_t offset = 0;

	fd = open(file_name, O_RDONLY);
	if (fd < 0)
		return 0;

	if (read(fd, hdr, sizeof(hdr)) != sizeof(hdr))
		goto fail;

	size_t nttisstd = read_int32(hdr + 24);
	size_t nttime = read_int32(hdr + 32);

	if (lseek(fd, nttime * 4 + nttime + (nttisstd - 1) * 6, SEEK_CUR) < 0)
		goto fail;

	len = 6;
	if (read(fd, buf, len) != len)
		goto fail;

	offset = read_int32(buf);

	close(fd);
	return offset;
fail:
	close(fd);
	return 0;
}
static char *sys_get_localtime(time_t second, char *fmt_time)
{
	time_t sec_time, temp;
	int month_day[12] = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};

	int year = 1970, month, day, hour, min, sec;
	month = day = hour = min = sec = 0;

	if(fmt_time == NULL)
		return NULL;

	sec_time = second + get_off("/etc/localtime");

	for(;;) {
		temp = sec_time;
		if((year % 4 == 0 && year % 100 != 0) || (year % 400 == 0))
			sec_time -= 31622400;
		else
			sec_time -= 31536000;
		if (sec_time < 0) {
			sec_time = temp;
			break;
		}
		year++;
	}

	if((year % 4 == 0 && year % 100 != 0) || (year % 400 == 0))
		month_day[1] = 29;

	for(;;) {
		temp = sec_time;
		sec_time = sec_time - month_day[month] * 86400;
		if(sec_time < 0) {
			sec_time = temp;
			break;
		}
		month++;
	}

	month += 1; /* Start from 1 */
	day = sec_time / 86400 + 1; /* Start from 1 */
	hour = (sec_time % 86400) / 3600;
	min = (sec_time % 3600) / 60;
	sec = sec_time % 60;

	sprintf(fmt_time, "%04d-%02d-%02d %02d:%02d:%02d",
	year, month, day, hour, min, sec);

	return fmt_time;
}

void u_printf_time()
{
	struct timespec real_time = {0, 0};
	char fmt_time[64] = {0};

	clock_gettime(CLOCK_REALTIME, &real_time);
	if (sys_get_localtime(real_time.tv_sec, fmt_time))
		u_printf("%s\n", fmt_time);
	else
		u_printf("%lu secs from 1970-01-01\n", real_time.tv_sec);

	return ;
}

#ifdef DEBUG
void dbg(const char * fmt, ...)
{
	char buf[BUFFER_SIZE] = "";

	va_list args;
	va_start(args, fmt);
	memset(buf, 0, sizeof(buf));
	vsprintf(buf, fmt, args);
	va_end (args);

	write(1, buf, strlen(buf));
	return ;
}
#else
void dbg(const char *fmt, ...) {}
#endif

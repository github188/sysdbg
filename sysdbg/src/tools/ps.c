#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <getopt.h>
#include <sys/prctl.h>
#include <errno.h>
#include <sys/time.h>

#include "ps.h"

#include "proc.h"
#include "io.h"

/*get the size of the stack of a thread*/
static int get_vmstk_from_pid(int pid)
{
	char filename[FUNCNAME_SIZE] = "";
	int stksize = -1;		/* 栈大小 */

	FILE *fp;			/* for read file */
	char *line = NULL;
	size_t len = 0;

	sprintf(filename, "/proc/%d/task/%d/status", pid,pid);
	if(0 != access(filename, R_OK))
		return -1;

	if(NULL != (fp = fopen(filename, "r"))){
		while (-1 != getline(&line, &len, fp)) {
			if(NULL != strstr(line, "VmStk")){
				sscanf(line, "VmStk: %d kB", &stksize);
				break;
			}
		}

		fclose(fp);
		if(line)
			free(line);
	}

	return stksize;
}

static char *policy_to_string(unsigned long policy)
{
	char *schedpolicy = (char *)malloc(sizeof(char) * 8);
	if (NULL == schedpolicy)
		return NULL;

	switch(policy){
	case 0:
		strcpy(schedpolicy, "NORMAL");
		break;
	case 1:
		strcpy(schedpolicy, "FIFO");
		break;
	case 2:
		strcpy(schedpolicy, "RR");
		break;
	default:
		break;
	}
	return schedpolicy;
}

static void print_proc_info(const procinfo_t *pproc, int flags)
{
	char *schedpolicy = policy_to_string(pproc->policy);//change policy to string

	if (flags & PSSCAN_SHOWLIBS) {
		u_printf("pid: %d\n" \
				"command: %s\n" \
				"filepath: %s\n" \
				"comm: %s\n" \
				"threadattr: %s\n" \
				"status: %c\n" \
				"rss: %ld kB\n" \
				"stack size: %d kB\n" \
				"scheduling policy: %s\n" \
				"priority: %ld\n" \
				"nice: %ld\n",
				pproc->pid,
				pproc->command,
				pproc->filepath,
				pproc->comm,
				pproc->threadattr,
				pproc->state[0],
				pproc->rss,
				pproc->vmstk,
				schedpolicy,
				pproc->priority,
				pproc->nice);
	}else{

		u_printf("%-6d", pproc->pid);
		u_printf("%-16s", pproc->comm);
		u_printf("%-8s", pproc->threadattr);
		u_printf("   %c   ", pproc->state[0]);

		u_printf("%-11ld", pproc->rss);
		u_printf("%-9s", schedpolicy);
		u_printf("%4ld ", pproc->priority);
		u_printf("%4ld ", pproc->nice);
		u_printf("%s", pproc->command);

		u_printf("\n");
	}

	if(NULL != schedpolicy)
		free(schedpolicy);
}

/*flags: 0 not read maps; 1 read maps*/
static int read_proc_info(int pid, procinfo_t *pproc)
{
	char filename[FUNCNAME_SIZE];
	char buf[BUFFER_SIZE];		/* 文件内存读到这里 */
	int  buf_size;

	unsigned int shift_pages_to_kb = 0;

	memset(pproc, 0x00, sizeof(procinfo_t));
	pproc->pid = pid;

	sprintf(filename, "/proc/%d/cmdline", pid);
	if(-1 == read2buf(filename, pproc->command, MAX_PATH))
		return -1;

	sprintf(filename, "/proc/%d/exe", pid);
	if(0 == access(filename, R_OK) && -1 != (buf_size = readlink(filename, buf, BUFFER_SIZE)))
		strncpy(pproc->filepath, buf, buf_size);

	sprintf(filename, "/proc/%d/task/%d/stat", pid,pid);


	if (-1 == read2buf(filename, buf, BUFFER_SIZE))
		return -1;

	char *cp, *comm1;
	cp = strrchr(buf, ')'); /* split into "pid (cmd" and "<rest>" */

	if (NULL == cp)
		return -1;

	cp[0] = '\0';
	comm1 = strchr(buf, '(');
	if (NULL == comm1)
		return -1;
	safe_strncpy(pproc->comm, comm1 + 1, sizeof(pproc->comm));/*2: thread name*/

	pproc->state[0] = cp[2]; /*3:state*/

	cp = skip_fields(cp,16);/*18:priority*/
	pproc->priority = fast_strtol_10(&cp);
	pproc->nice = fast_strtol_10(&cp);

	cp = skip_fields(cp,4);
	shift_pages_to_kb = pages_to_kb();
	pproc->rss = fast_strtoul_10(&cp)<<shift_pages_to_kb;/*24:rss*/

	if(0 == pproc->rss){
		pproc->flags = THREAD_KERNEL;
		strcpy(pproc->threadattr, "kernel");
	}else {
		pproc->flags = THREAD_USER;
		strcpy(pproc->threadattr, "user");
	}

	cp = skip_fields(cp,3);
	pproc->bp = fast_strtoul_10(&cp);/*28:startstack. this is not correct for thread*/

	cp = skip_fields(cp,12);
	pproc->policy = fast_strtoul_10(&cp);/*41:policy*/

	pproc->vmstk = get_vmstk_from_pid(pid);

    return 0;
}

static int dump_maps_tools(pid_t pid)
{
    int fd = -1;
    char buf[BUFFER_SIZE] = {0};
    char filename[sizeof("/proc/%d/task/%d/maps") + sizeof(int)*3*2];

    sprintf(filename, "/proc/%d/task/%d/maps", pid, pid);

    fd = open(filename, O_RDONLY);
    if (fd < 0)
        return -1;

    u_printf("\n--------Process [%d] Maps-------\n", pid);

    while (read(fd, buf, BUFFER_SIZE-1) > 0) {
        u_printf("%s", buf);
        memset(buf, 0, BUFFER_SIZE);
    }

    close(fd);

    return 0;
}

/* scan all thread */
static void proc_scan(int pid, unsigned flags)
{
	DIR *dir = NULL, *task_dir = NULL;
	struct dirent *entry;
	char *name;
	procinfo_t pi;
	char filename[sizeof("/proc/%u/task/%u/cmdline") + sizeof(int)*3 * 2];

	if(flags & PSSCAN_HASPID){/*with -p ,we switch to /proc/pid/task directly.*/
		sprintf(filename,"/proc/%u/task/",pid);
	}else {
		strcpy(filename, "/proc");
	}

	if (NULL == (dir = opendir(filename))) {
		u_printf("Error: can not open %s.\n", filename);
		return;
	}

	if (!(flags & PSSCAN_SHOWLIBS))
		u_printf("(Status: S=sleeping R=running, W=waiting)\n" \
				"pid   comm            attr   status rss(kB)    schedule  prio nice command\n" \
				"-----------------------------------------------------------------\n");

	for (;;){

		if(flags & PSSCAN_THREAD){
			if(task_dir){
				entry = readdir(task_dir);
				if(entry)
					goto got_entry;
				closedir(task_dir);
				task_dir = NULL;
			}
		}
		if (NULL == (entry = readdir(dir))){
			closedir(dir);
			dir = NULL;
			break;
		}

got_entry:
		name = entry->d_name;
		if (!(*name >= '0' && *name <= '9'))
			continue;

        if (flags & PSSCAN_HASPID) {/*without -h ,we only show the one thread.*/
            if(!(flags & PSSCAN_THREAD) && (atoi(name) != pid))
			    continue;
		}

        if ((flags & PSSCAN_THREAD) &&
            !task_dir &&
            !(flags & PSSCAN_HASPID)) {/*with -p, we have already switched to the /proc/pid/task before*/
			/* We found another /proc/PID. Do not use it,
			 * there will be /proc/PID/task/PID (same PID!),
			 * so just go ahead and dive into /proc/PID/task. */
			sprintf(filename, "/proc/%d/task", atoi(name));
			/* Note: if opendir fails, we just go to next /proc/XXX */
			task_dir = opendir(filename);
			continue;
		}

		if(0 == read_proc_info(atoi(name), &pi))
			print_proc_info(&pi, flags);

        /* The thread should not be a kernel thread */
        if ((flags & PSSCAN_SHOWLIBS) &&
                ~(pi.flags & THREAD_KERNEL)) {
            if (dump_maps_tools(pi.pid) < 0) {
                u_printf("Error: can not read maps.\n"  \
                        "--------------------------------------\n");
            }
        }
	}

    if (dir)
	    closedir(dir);
}

int ps_main(int argc, char *argv[])
{
	static struct option long_options[] = {
		{"pid",		required_argument,	0,	'p'},
		{"verbose",	0,					0, 	'v'},
		{"thread",	0,					0,	'h'}, /* show threads on */
		{0,		0,			0,  0 }
	};

	int param_error = 0;		/* 解析过程中参数是否错误 */
	int char_option;		/* 解析的名称缩写 */
	int pid = 0;			/* 参数：进程号 */
	unsigned scan_mask = PSSCAN_DEFAULT;

	opterr = 0;			/* 屏蔽getopt 的错误输出 */
	while(1){
		char_option = getopt_long(argc, argv, "p:vh", long_options, NULL);
		if (char_option == -1)
			break;

		switch(char_option){
			case 'p':
				pid = atoi(optarg);
				{
					char buf[8] = "";
					sprintf(buf, "%d", pid);
					if(strcmp(buf, optarg) || pid < 0){
						u_printf("Error: you input an invalid pid.\n");
						param_error = 1;
					}else {
						scan_mask |= PSSCAN_HASPID;
					}
				}
				break;
			case 'v':
				scan_mask |= PSSCAN_SHOWLIBS;
				break;
			case 'h':
				scan_mask |= PSSCAN_THREAD;
				break;
			case '?':
				u_printf("Error:option %c requires an argument\n",optopt);
				param_error = 1;
				break;
			default:
				param_error = 1;
				break;
		}
	}

	if(optind < argc)
		param_error = 1;

	if(1 == param_error){
		print_usage(USAGE_PS);
		return -1;
	}

	proc_scan(pid, scan_mask);

	return 0;
}


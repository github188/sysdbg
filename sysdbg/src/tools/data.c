#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/ptrace.h>
#include <fcntl.h>
#include <getopt.h>
#include <signal.h>
#include "../kernel/debugmisc.h"
#include "data.h"
#include "common.h"
#include "elfparser.h"
#include "ps.h"
#include "stack.h"

static unsigned long request_addr = 0;	/*the address wanted to modify/show */
static int request_size = 0;		/*the size of memory wanted to modify/show */
static int request_pid = -1;

static int kat = KERNEL_DATA_ATTR_INVALID;			/* 内核地址属性 */

static int __pid = 0;;
static void __sig_int(int sig)
{
	if(0 != __pid){
		ptrace(PTRACE_DETACH, __pid, 0, 0);
		ptrace(PTRACE_CONT, __pid, 0, 0);
	}

	exit(-1);
}

/*
 * 说明：读写内核数据
 */
static int rw_kernel_data(struct kerneldata *pkd)
{
	int fd;
	int ret = 0;

	if(-1 == (fd = open(DEBUGMISC_FILENAME, O_RDWR))){
		printf("%s\n", OPEN_DEBUG_MISC_FAILED);
		return -1;
	}
	if(0 != ioctl(fd, DEBUG_KERNEL_RWDATA, pkd))
		ret = -2;
	close(fd);

	return ret;
}

/*
 * 说明：获取内核地址属性，物理地址还是虚拟地址
 */
static int check_kernel_addr(int addr, int *virt_addr, int *phy_addr)
{
	int fd;
	kerneldatatype_t kdt;

	kdt.addr = addr;
	if(-1 == (fd = open(DEBUGMISC_FILENAME, O_RDWR))){
		printf("%s\n", OPEN_DEBUG_MISC_FAILED);
		return -1;
	}
	if(0 != ioctl(fd, DEBUG_KERNEL_DATA_TYPE, &kdt))
		printf("read data type error\n");
	close(fd);

	if(NULL != virt_addr)
		*virt_addr = kdt.virt_addr;

	if(NULL != phy_addr)
		*phy_addr = kdt.phy_addr;

	return kdt.type;
}

static void show_data(int size, int addr, char *data)
{
	int i;

	/* patch for big/small endian */
	/*if(0 == addr_not_symbol){
		printf("addr: 0x%08x, value: 0x%08x\n", addr, (int)*(int*)data);
		return;
	}
      */
      
	for(i = 0;  i < size; i++){
		if( i % 16 == 0 && 0 != i)
			printf("\n");

		if(i % 16 == 0)
			printf("0x%08x: ", addr + i);

		printf("%02x ", (unsigned char)data[i]);
	}
	printf("\n");

}

static void get_process_data(int pid, int addr, int size)
{
	/* ptrace读取进程一个字长的数据，这里封装成读写任意字节数的函数 */
	int count;
	int i;
	char *data = NULL;

	if(size < 1)
		return;

	count = size / 4 + ((size % 4)? 1: 0);
	if(NULL == (data = (char*)malloc(count * 4)))
		return;
	memset(data, 0x00, count * 4);

	errno = 0;
	if(-1 == ptrace(PTRACE_ATTACH, pid, 0, 0) || errno){
		printf("process %d can *not* attach, errno is %d\n", pid, errno);
		if(data){
			free(data);
		}
		return;
	}
	waitpid(pid, NULL, WUNTRACED);

	/*
	dprintf("pid is %d, addr is 0x%08x, size is %d, count is %d\n", pid, addr, size, count);
	*/
	for(i = 0; i < count; i++){
		*(int *)(data + 4 * i) = ptrace(PTRACE_PEEKDATA, pid, addr + i * 4, 0);
		//ptrace(PTRACE_PEEKDATA, pid, addr, 0);
		if(0 != errno)
			break;
	}

	if(0 == errno){
		show_data(count * 4, addr, data);
	}else if(i > 0 && i -1 >0){
		printf("Notes: we can only read %d bytes: \n", (i -1)* 4);
		show_data((i-1) * 4, addr, data);
	}else {
		printf("fetal error: get data error\n");
	}
	
	ptrace(PTRACE_DETACH, pid, 0, 0);
	ptrace(PTRACE_CONT, pid, 0, 0);
	if(data)
		free(data);
}

static void write_process_data(int pid, ptr_t addr, int size)
{
	char input[32] = "";
	long value = 0;
    char *fgets_ret __attribute__((unused));

	signal(SIGINT, __sig_int);
	__pid = pid;
	if(-1 == ptrace(PTRACE_ATTACH, pid, 0, 0) || errno){
		printf("process %d can *not* attach, errno is %d\n", pid, errno);
		return;
	}
	waitpid(pid, NULL, WUNTRACED);

	do{
		errno = 0;
		value = ptrace(PTRACE_PEEKDATA, pid, (void *)addr, 0);
		if(0 != errno){
			printf("fetal error: get data error. address may out of range.\n");
			break;
		}

re_input:
		memset(input, 0x00, sizeof(input));
		printf("addr: %p, value: 0x%lx: ", (void *)addr, value);
		fgets_ret = fgets(input, 32, stdin);
		input[31] = 0x00;
		if(0x00 == input[0] || '\n' == input[0])
			continue;
		if('q' == input[0] || 'Q' == input[0])
			break;

		if(0 != check_is_hex_number(input)){
			printf("(invalid hex numeric, please re-input!)\n");
			goto re_input;
		}
		value = strtoul(input, NULL, 16);

		ptrace(PTRACE_POKEDATA, pid, (void *)addr, value);
		if(0 != errno){
			printf("fetal error: write data error\n");
			break;
		}
	}while(NULL != (void *)(addr += sizeof(void *)));

	ptrace(PTRACE_DETACH, pid, 0, 0);
	ptrace(PTRACE_CONT, __pid, 0, 0);
}

void read_kernel_data(int addr_type, int addr, int size)
{
	/* 查看内核空间数据 */
	kerneldata_t kd;
	int count;

	kd.mode = KERNEL_DATA_MODE_READ;
	kd.attribute = addr_type;
	kd.addr = addr;
	kd.len = size;

	count = kd.len / 4 + ((kd.len % 4)? 1: 0);
	if(NULL == (kd.buf = (char*)malloc(count * 4)))
		return;
	memset(kd.buf, 0x00, count * 4);

	if(0 == rw_kernel_data(&kd)){
		show_data(count * 4, addr, kd.buf);
	}

	if(kd.buf)
		free(kd.buf);
}

void write_kernel_data(int addr_type, unsigned long addr, int size)
{
	char input[32];
	kerneldata_t kd;
	int value;
    char *fgets_ret __attribute__((unused));

	do{
		kd.mode = KERNEL_DATA_MODE_READ;
		kd.attribute = addr_type;
		kd.addr = addr;
		kd.len = 4;
		kd.buf = (char*)&value;

		if(0 != rw_kernel_data(&kd))
			break;

re_input:
		memset(input, 0x00, sizeof(input));
		printf("addr: %p, value: 0x%08x: ", (void *)addr, value);
		fgets_ret = fgets(input, 32, stdin);
		input[31] = 0x00;

		if(0x00 == input[0] || '\n' == input[0])
			continue;

		if('q' == input[0] || 'Q' == input[0])
			break;

		if(0 != check_is_hex_number(input)){
			printf("(invalid hex numeric, please re-input!)\n");
			goto re_input;
		}
		value = strtoul(input, NULL, 16);

		kd.mode = KERNEL_DATA_MODE_WRITE;
		if(0 != rw_kernel_data(&kd))
			break;

	}while(NULL != (void *)(addr += 4));
}


static int check_parameter(int argc, char *argv[])
{
	static struct option long_options[] = {
		{"pid",	required_argument,	0, 'p'},	/* 线程id */
		{"name",	required_argument,	0, 'n'},	/* 变量符号名 */
		{"addr",	required_argument,	0, 'a'},	/* 变量地址 */
		{0,		0,			0,  0 }
	};
	int param_error = 0;		/* 解析过程中参数是否错误 */
	int char_option;		/* 解析的名称缩写 */
	int check_pid = 0;		/* 检查pid 和 type参数 */
	int check_addr = 0;		/* 检查addr 和 size参数，或file 和name 参数 */

	char symbol_name[32] = "";
	char * filename = NULL;

	opterr = 0;			/* 屏蔽getopt 的错误输出 */
	while(1){
		char_option = getopt_long(argc, argv, "p:n:a:", long_options, NULL);
		if (char_option == -1)
			break;

		switch(char_option){
			case 'p':
				request_pid = atoi(optarg);
				check_pid += char_option;
				{
					char buf[8] = "";
					sprintf(buf, "%d", request_pid);
					if(strcmp(buf, optarg)){
						printf("Hint: you input an invalid pid.\n");
						param_error = 1;
					}
				}
				break;
			case 'a':
				request_addr = (unsigned long)strtoul(optarg, NULL, 16);
				check_addr += char_option;
				break;
			case 'n':
				strcpy(symbol_name, optarg);
				check_addr += char_option;
				break;
			case '?':
				param_error = 1;
				break;
			default:
				param_error = 1;
				break;
		}
	}

	/* 判断参数格式合法性 */
	if(optind < argc || 1 == param_error || !(('a' == check_addr) || ('n' == check_addr))) {
		print_usage(USAGE_MD);
		return -1;
	}

	/* 如果指定线程，必须存在该线程 */
	if('p' == check_pid){
		/* 不能调试id 为1 的线程 */
		if(1 == request_pid){
			printf("you can not debug process 1\n");
			return -1;
		}
		if(THREAD_USER != get_thread_attr(request_pid)){
			printf("%d is not a valid user thread\n", request_pid);
			return -2;
		}

		if('n' == check_addr){
			if(0 == check_symbol_in_elf(request_pid)){
				filename = get_filename_from_pid(request_pid);

				if(NULL == filename){
					return -3;
				}else if(0 == get_addr_from_elf(filename, symbol_name, "OBJECT", &request_addr, &request_size)){
					//addr_not_symbol = 0;
					free(filename);
				}else{
					printf("can not find symbol %s in process %d\n", symbol_name, request_pid);
					free(filename);
					return -5;
				}
			}else{
				char *env = getenv(USER_SYMBOL);
				if(NULL == env || 0 != access(env, R_OK)){
					printf("the process %d have no symbol, and can not get from env\n", request_pid);
					return -3;
				}else{
					/* 转换符号名称为地址, 从符号文件 */
					if(0 == get_address_from_symbolfile(env, symbol_name, "OBJECT", &request_addr, &request_size)) {
						//addr_not_symbol = 0;
					}else{
						printf("cant not find symbol %s in file %s\n", 
								symbol_name, env);
						return -4;
					}
				}
			}
		}else{
			request_size = READ_MEM_SIZE;
		}
	}else{
		if('n' == check_addr){
			char *env = getenv(KERNEL_SYMBOL);
			if(NULL == env || 0 != access(env, R_OK)){
				printf("you must give the kernel symbol path in env\n");
				return -6;
			}else{
				/* 转换符号名称为地址, 从符号文件 */
				if(0 == get_address_from_symbolfile(env, symbol_name, "OBJECT", 
							&request_addr, &request_size)){
					//addr_not_symbol = 0;
				}else{
					printf("cant not find symbol %s in file %s\n", 
							symbol_name, env);
					return -7;
				}
			}
			kat = KERNEL_DATA_ATTR_VIRT;
		}else{
			/* 判断地址是物理， 虚拟地址， 还是寄存器地址 */
			int virt_addr, phy_addr;
			int ret = check_kernel_addr(request_addr, &virt_addr, &phy_addr);

			if(KERNEL_DATA_ATTR_VIRT == ret 
					|| KERNEL_DATA_ATTR_PHYS == ret 
					|| KERNEL_DATA_ATTR_REG == ret){
				ret = check_kernel_addr((int)((unsigned int)request_addr + (unsigned int)READ_MEM_SIZE),
							NULL, NULL);

				if(KERNEL_DATA_ATTR_VIRT == ret){
					kat = KERNEL_DATA_ATTR_VIRT;
					printf("address is virtual address, physical addr: 0x%08x\n", phy_addr);
				}else if(KERNEL_DATA_ATTR_PHYS == ret){
					kat = KERNEL_DATA_ATTR_PHYS;
					printf("address is physical address, virtual addr: 0x%08x\n", virt_addr);
				}else if(KERNEL_DATA_ATTR_REG == ret){
					kat = KERNEL_DATA_ATTR_REG;
					printf("address is register io address\n");
				}else{
					printf("address is out of range, only show 4 byte.\n");
					request_size = 4;
				}
				request_size = READ_MEM_SIZE;	/* 查看内存的大小 */
			}else{
				return -9;
			}
		}
	}
	return 0;
}


int datamm_main(int argc, char *argv[])
{
	if(0 != check_parameter(argc, argv) || request_size < 1)
		return -1;

	printf("size of addr maybe: %d\n", request_size);

	if(request_pid > 1){
		/* 修改用户空间数据 */
		write_process_data(request_pid, (unsigned long)request_addr, request_size);
	}else{
		/* 修改内核空间数据 */
		write_kernel_data(kat, request_addr, request_size);
	}

	return 0;
}

int datamd_main(int argc, char *argv[])
{
	if(0 != check_parameter(argc, argv) || request_size < 1)
		return -1;

	printf("size of addr maybe: %d\n", request_size);
	
	if(request_pid > 1){
		/* 查看用户空间数据 */
		get_process_data(request_pid, request_addr, request_size);
	}else{
		read_kernel_data(kat, request_addr, request_size);
	}

	return 0;
}


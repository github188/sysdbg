/*
 * auth: wangyuantao@kedacom.com
 * date: Wed Oct 11 10:36:40 CST 2006
 */

#include <linux/module.h>
#include <linux/sched.h>
#include <linux/types.h>	/* u8, u16, u32 ... */
#include <linux/errno.h>
#include <linux/miscdevice.h>
#include <linux/ioport.h>
#include <linux/fcntl.h>
#include <linux/init.h>
#include <linux/rtc.h>
#include <linux/bcd.h>
#include <linux/fs.h>		/* struct file_operations, register_chrdev(), ... */
#include <linux/proc_fs.h>
#include <linux/spinlock.h>
#include <linux/timex.h>
#include <linux/kernel.h>	/* printk() is here */
#include <asm/pgtable.h>
#include <asm/bitops.h>
#include <asm/uaccess.h>	/* copy_to_user(), copy_from_user */
#include <asm/page.h>
#include <asm/io.h>
#include <linux/dma-mapping.h>
#include <linux/delay.h>
#include <linux/slab.h>
#include <linux/version.h>
#include <linux/kallsyms.h>
#include "debugmisc.h"
#include "io_range.h"

#undef DEBUG
#define DEBUG

#ifdef DEBUG
#define dprintk(fmt, args...) printk(fmt, ##args)
#else
#define dprintk(fmt, args...)
#endif

typedef void (* show_stack_func )(struct task_struct *tsk, unsigned long *sp);

/*different kernel version has different callback function*/
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,35)
static int debugmisc_ioctl(struct inode *inode, struct file *file, unsigned int cmd, unsigned long arg);
#else
static long debugmisc_ioctl(struct file *file, unsigned int cmd, unsigned long arg);
#endif

/* 文件操作 */
static struct file_operations debugmisc_fops = {
	.owner		=	THIS_MODULE,
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,35)
	.ioctl		=	debugmisc_ioctl,	/* 主要实现这个函数 */
#else
	.unlocked_ioctl = debugmisc_ioctl,
#endif
};

/* 注册到misc设备链表的数据结构 */
static struct miscdevice debugmisc_dev = {
	.minor		=	MISC_DYNAMIC_MINOR,
	.name		=	"debugmisc",
	.fops		=	&debugmisc_fops,
};

static int __init debugmisc_init_module(void)
{
	int err = -EIO;

	err = misc_register(&debugmisc_dev);
	if (err){
		misc_deregister(&debugmisc_dev);
		printk("misc_register debugmisc failed, %s %s.\n", __DATE__, __TIME__);
	}

	printk("misc_register debugmisc success, %s %s.\n", __DATE__, __TIME__);
	return err;
}

static void __exit debugmisc_exit_module(void)
{
	misc_deregister(&debugmisc_dev);
	printk("misc_deregister debugmisc success, %s %s.\n", __DATE__, __TIME__);
}

module_init(debugmisc_init_module);
module_exit(debugmisc_exit_module);
MODULE_AUTHOR("wangyuantao");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("debug misc(read/write kernel data/text, kernel stack backtrace of thread)");

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,35)
static int debugmisc_ioctl(struct inode *inode, struct file *file, unsigned int cmd, unsigned long arg)
#else
static long debugmisc_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
#endif
{
	kernelcall_t		kc;			/* 调用内核函数的结构 */
	kerneldata_t		kd;			/* 读写内核数据的结构 */
	kernelstack_t		ks;			/* 查看线程内核栈 */
	kerneldatatype_t	kdt;			/* 获取地址属性 */
	char 			*p = NULL;		/* 指向用户传递的数据 */

	
	switch(cmd){
		case DEBUG_KERNEL_RWDATA:
			if(!copy_from_user((void*)&kd, (kerneldata_t *)arg, sizeof(kerneldata_t))
					&& NULL != (p = kmalloc(kd.len, GFP_KERNEL))
					&& !copy_from_user((void*)p, (const void*)kd.buf, kd.len)){

				if (NULL == p)
					break;

				if(KERNEL_DATA_ATTR_REG == kd.attribute){
					void __iomem *virt_ioaddr = NULL;
					int i;

					if(NULL != (virt_ioaddr = ioremap(kd.addr, kd.len))){
						for(i = 0; i < kd.len / 4; i++){
							/* 寄存器 */
							if(KERNEL_DATA_MODE_READ == kd.mode){
								*((int*)(p) + i) = ioread32(virt_ioaddr + i * 4);
							}else{
								iowrite32(*((int*)(p) + i), virt_ioaddr + i * 4);
							}
						}
						iounmap(virt_ioaddr);
					}

				}else if(KERNEL_DATA_ATTR_PHYS == kd.attribute){
					/* 物理地址（先转换成虚拟地址） */
					unsigned long virt_addr = (unsigned long)__va(kd.addr);

					if(KERNEL_DATA_MODE_READ == kd.mode){
						memcpy((void*)p, (const void*)virt_addr, kd.len);
					}else{
						memcpy((void*)virt_addr, (const void*)kd.buf, kd.len);
					}
				}else{
					unsigned long virt_addr = (unsigned long)kd.addr;

					/* 虚拟地址 */
					if(KERNEL_DATA_MODE_READ == kd.mode){
						memcpy((void*)p, (const void*)kd.addr, kd.len);
					}else{
						memcpy((void*)virt_addr, (const void*)kd.buf, kd.len);
					}
				}

				if(KERNEL_DATA_MODE_READ == kd.mode){
					/* 读取数据（拷贝到用户空间） */
					if(0 != copy_to_user((void*)kd.buf, (const void*)p, kd.len))
						dprintk("copy to user error\n");
				}
			}

			if(NULL != p){
				kfree(p);
				p = NULL;
			}

			break;

		case DEBUG_KERNEL_CALL:
			if(0 == copy_from_user((void*)&kc, (const void*)arg, sizeof(kernelcall_t))){
				switch(kc.paramcount){
					case 0:
						((func_param0)kc.addr)();
						break;
					case 1:
						((func_param1)kc.addr)(kc.param1);
						break;
					case 2:
						((func_param2)kc.addr)(kc.param1, kc.param2);
						break;
				}
			}
			break;

		case DEBUG_KERNEL_BACKTRACE:
			if(0 == copy_from_user((void*)&ks, (const void*)arg, sizeof(kernelstack_t))){
				struct task_struct *__task;
				
				rcu_read_lock();

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24)
				__task = find_task_by_pid(ks.pid);
#elif LINUX_VERSION_CODE < KERNEL_VERSION(2,6,31)
				__task = find_task_by_vpid(ks.pid);
#else
				__task = pid_task(find_vpid(ks.pid), PIDTYPE_PID);
#endif
				rcu_read_unlock();                           
			
				if(NULL == __task){
					panic("get_task couldn't find a task\n");
				}else{
					unsigned long show_stack_addr = kallsyms_lookup_name("show_stack");
					if(0  != show_stack_addr){
						printk(KERN_ALERT"begin dump_stack=========>\n");
						((show_stack_func)show_stack_addr)(__task, NULL);
						printk(KERN_ALERT"end dump_stack<==========\n");
					}else {
						panic(KERN_ALERT"can not find the kernel function: show_stack.\n");
					}
					
				}     
			}
			break;

		case DEBUG_KERNEL_DATA_TYPE:
			if(0 == copy_from_user((void*)&kdt, (const void*)arg, sizeof(kerneldatatype_t))){
				unsigned long addr = (unsigned long)kdt.addr;

				if(virt_addr_valid(addr)){
					kdt.type = KERNEL_DATA_ATTR_VIRT;
					kdt.phy_addr = __pa(addr);

				}else if(pfn_valid(addr >> PAGE_SHIFT)){
					kdt.type = KERNEL_DATA_ATTR_PHYS;
					kdt.virt_addr = __va(addr);

				}else{
					if(IO_SPACE_START <= addr && IO_SPACE_END > addr)
						kdt.type = KERNEL_DATA_ATTR_REG;
					else
						kdt.type = KERNEL_DATA_ATTR_INVALID;
				}

				if(0 != copy_to_user((void*)arg, (const void*)&kdt, sizeof(kerneldatatype_t)))
					dprintk("copy to user error\n");

			}

			break;
		default:
			break;
	}

	return 0;
}




#ifndef __SYSDBG_ELFPASER_H__
#define __SYSDBG_ELFPASER_H__
/*
 * auth: wangyuantao@kedacom.com
 * date: Fri Oct 13 11:43:32 CST 2006
 */
#include <stdint.h>
#include <elf.h>

#if __WORDSIZE == 64
#define ELF_Internal_Ehdr	Elf64_Ehdr
#define ELF_Internal_Shdr	Elf64_Shdr
#define ELF_Internal_Sym	Elf64_Sym
#define ELF_Internal_Word	Elf64_Word
#define ELF_Internal_ST_TYPE	ELF64_ST_TYPE
#else
#define ELF_Internal_Ehdr	Elf32_Ehdr
#define ELF_Internal_Shdr	Elf32_Shdr
#define ELF_Internal_Sym	Elf32_Sym
#define ELF_Internal_Word	Elf32_Word
#define ELF_Internal_ST_TYPE	ELF32_ST_TYPE
#endif

extern int check_symbol_in_elf(int pid);

/*using a symbol to find its address*/
extern int get_addr_from_elf(const char *filename, const char *symbol_name,
				const char *attr, unsigned long *addr, int *size);
extern int get_address_from_symbolfile(const char *symbol_file, const char *symbol_name, 
		const char *attribute, unsigned long *addr, int *size);


/*using a address to find function name*/
extern int get_symbol_from_symbolfile(const char *symbol_file, unsigned long addr, char *symbol_name);
extern int get_symbol_from_elf(const char *filename, unsigned long addr, char * symbol_name);
#endif


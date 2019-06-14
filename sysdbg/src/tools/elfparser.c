/*
 * auth: wangyuantao@kedacom.com
 * date: Fri Oct 13 18:05:36 CST 2006
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "elfparser.h"
#include "common.h"

static int elf_read(const char *filename, int offset, int size, void *buf)
{
	FILE *fp;

	if(NULL == buf)
		return -1;
	if(NULL == filename || 0 != access(filename, R_OK))
		return -1;
	if(NULL == (fp = fopen(filename, "r")))
		return -1;

	fseek(fp, offset, SEEK_SET);
	size = fread(buf, 1, size, fp);
	fclose(fp);

	return size;
}

/*read elf header from a file*/
static ELF_Internal_Ehdr * read_elf_header(const char *filename)
{
	ELF_Internal_Ehdr * elf_header = (ELF_Internal_Ehdr *)malloc(sizeof(ELF_Internal_Ehdr));
	
	if(sizeof(ELF_Internal_Ehdr) != elf_read(filename, 0, sizeof(ELF_Internal_Ehdr), elf_header)){
		if(NULL != elf_header)
			free(elf_header);
		elf_header = NULL;
	}

	return elf_header;
}

/*read section header from a file
  *the function return a pointer of the section header
  *pcount save the number of section entries
  **/
static ELF_Internal_Shdr * read_section_header(const char * filename, int *pcount)
{
	ELF_Internal_Shdr * section_header = NULL;
	int section_header_size = 0;
	
	ELF_Internal_Ehdr * elf_header = read_elf_header(filename);

	*pcount = -1;

	if(NULL != elf_header){
		*pcount = elf_header->e_shnum;
		section_header_size = elf_header->e_shentsize * (*pcount);
		section_header = (ELF_Internal_Shdr*)malloc(section_header_size);

		if(section_header_size != elf_read(filename, elf_header->e_shoff, section_header_size, section_header)){
			if(NULL != section_header)
				free(section_header);
			section_header = NULL;
			*pcount = -1;
		}

		free(elf_header);
	}

	return section_header;
}

/*read symbol table  from a file
 * the function  return a pointer of the symbol table
 * psym_entries save the number of symbol entries
 * sh_link save the index of string table*/
static ELF_Internal_Sym * read_symbol_table(const char *filename,
				int * psym_entries, ELF_Internal_Word * sh_link)
{
	ELF_Internal_Shdr * section_header = NULL;
	ELF_Internal_Shdr * pshdr_sym = NULL;			/* symbol table position in section header */
	ELF_Internal_Sym * psymbol_table = NULL;

	int section_count;						/*section header entries*/
	int symbol_size;						
	int i;

	*psym_entries = -1;
	*sh_link = 0;
	
	section_header = read_section_header(filename, &section_count);
	
	if(NULL == section_header){
		return NULL;
	}

	pshdr_sym = section_header;
	
	for(i = 0; i < section_count; i++, pshdr_sym++){
		if(SHT_SYMTAB == pshdr_sym->sh_type){
			psymbol_table = (ELF_Internal_Sym *)malloc(pshdr_sym->sh_size);
			symbol_size = elf_read(filename, pshdr_sym->sh_offset,
										pshdr_sym->sh_size, psymbol_table);
			if(symbol_size != pshdr_sym->sh_size){
				if(NULL != psymbol_table)
					free(psymbol_table);
				psymbol_table = NULL;
			}else {
				*psym_entries = symbol_size /sizeof(ELF_Internal_Sym);
				*sh_link = pshdr_sym->sh_link;
			}
			break;
		}
	}

	if(NULL != section_header)
		free(section_header);

	return psymbol_table;
}

/*using the index in section header to read string table
 *sh_index:the index of the string table
 */
static void * read_string_table(const char *filename, ELF_Internal_Word sh_index)
{
	ELF_Internal_Shdr * section_header = NULL;
	ELF_Internal_Shdr * pshdr_string = NULL;		/*string table index in section header*/
	
	void * pstring_table = NULL;

	
	int section_count;						/*section header entries*/
	int string_size;
	
	section_header = read_section_header(filename, &section_count);
	if(NULL == section_header)
		return NULL;

	pshdr_string = section_header + sh_index;

	pstring_table = (void *)malloc(pshdr_string->sh_size);

	string_size = elf_read(filename,pshdr_string->sh_offset,
							pshdr_string->sh_size, pstring_table);
	
	if(NULL != section_header)
		free(section_header);

	/*read string table error*/
	if(string_size != pshdr_string->sh_size && NULL != pstring_table) {
			free(pstring_table);
			pstring_table = NULL;
	}

	return pstring_table;
}


/*find symbols in the elf file.
 *return: 0 has symbols; !0 don't have symbols
 */
int check_symbol_in_elf(int pid)
{
	char *filename = NULL;
	ELF_Internal_Sym * psymbol_table = NULL;
	ELF_Internal_Word sh_link_index;
	int symbol_count;

	int ret = -1;
	
	filename = get_filename_from_pid(pid);
	
	if(NULL == filename)
		return ret;

	psymbol_table = read_symbol_table(filename, &symbol_count, &sh_link_index);

	if(NULL != psymbol_table){
		ret = 0;
		free(psymbol_table);
	}
	
	if(NULL != filename)
		free(filename);
      
	return ret;
}


/*using a symbol to find its address in the symbol file*/
int get_address_from_symbolfile(const char *symbol_file, const char *symbol_name, 
		const char *attribute, unsigned long *addr, int *size)
{
	FILE *fp;			/* for read file */
	char *line = NULL;
	size_t len = 0;

	char buf[8][64] = {""};		/* for parse */
	int ret_value = -1;
	int find_symbol = 0;    /*flag of symbol section*/

	if(!(0 == strcmp("FUNC", attribute) || 
		0 == strcmp("OBJECT", attribute))|| 
		NULL == symbol_file || 
		NULL == symbol_name || 
		NULL == addr || 
		NULL == size)
		return -2;

	if(NULL == symbol_file || 0 != access(symbol_file, R_OK))
		return -3;

	if(NULL != (fp = fopen(symbol_file, "r"))){
		while(-1 != getline(&line, &len, fp)) {
			if(NULL != strstr(line,"Symbol table \'.symtab\'"))
                			find_symbol = 1;

			/*we find symbol section */
			if(1 == find_symbol  && 
				NULL != strstr(line, attribute) && 
				NULL != strstr(line, symbol_name)){
				sscanf(line, "%s %s %s %s %s %s %s %s", 
					buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7]);

				if(NULL != strstr(buf[6],"UND")) /*this is a symbol in .so file,we skip it*/
					continue;
				
				if(0 == strcmp(symbol_name, buf[7])) {
					*addr = (unsigned int)strtoul(buf[1], NULL, 16);
					*size = atoi(buf[2]);
					ret_value = 0;
					break;
				}
			}
		}

		fclose(fp);
		if(line)
			free(line);
	}

	return ret_value;
}

/*using a symbol to find its address in elf format file
 *attr: FUNC or OBJECT to identify the symbol attribute
 *addr:save the address
 *size: save the memory size of the symbol 
 */
int get_addr_from_elf(const char *filename, const char *symbol_name,
	const char *attr, unsigned long *addr, int *size)
{
	ELF_Internal_Sym * psymbol_table = NULL;
	ELF_Internal_Sym * psym_cur = NULL;
	char * pstring_table = NULL;
	ELF_Internal_Word sh_link;

	int symbol_count;
	int j;

	int ret = -1;
	
	if(!(0 == strcmp("FUNC", attr)|| 0 == strcmp("OBJECT", attr))
			|| NULL == filename
			|| NULL == symbol_name
			|| NULL == addr
			|| NULL == size)
		return ret;

	psymbol_table = read_symbol_table(filename, &symbol_count, &sh_link);
	if(NULL == psymbol_table)
		return ret;

	pstring_table = read_string_table(filename, sh_link);
	if(NULL == pstring_table){
		if(NULL != psymbol_table)
			free(psymbol_table);
		return ret;
	}

	psym_cur = psymbol_table;
	for(j = 0; j < symbol_count; j++,psym_cur++){
		/*skip the entries which don't have name or is not a func*/
		if(0 == psym_cur->st_shndx)
			continue;
		
		if(!psym_cur->st_value)
			continue;

		if(!(0 == strcmp("FUNC",attr) && STT_FUNC == ELF_Internal_ST_TYPE(psym_cur->st_info))
			&& !(0 == strcmp("OBJECT",attr) && STT_OBJECT == ELF_Internal_ST_TYPE(psym_cur->st_info)))
			continue;

		/*we find the right address */
		if(0 == strcmp(symbol_name, pstring_table + psym_cur->st_name)){
			*addr = psym_cur->st_value;
			*size = psym_cur->st_size;
			ret = 0;
			break;
		}				
	}

	if(NULL != pstring_table)
		free(pstring_table);
	if(NULL != psymbol_table)
		free(psymbol_table);

	return ret;
	
}

/*using a address to find a function name in the symbol file*/
int get_symbol_from_symbolfile(const char *symbol_file, unsigned long addr, char *symbol_name)
{
	FILE *fp;			/* for read file */
	char *line = NULL;
	size_t len = 0;

	char buf[8][64] = {""};		/* for parse */
	unsigned long func_start;
	unsigned long func_size;
	int ret_value = -1;
    	int find_symbol = 0;    /*flag of symbol section*/

	if(NULL == symbol_file || 0 != access(symbol_file, R_OK))
		return -1;

	if(NULL != (fp = fopen(symbol_file, "r"))) {
		while (-1 != getline(&line, &len, fp)) {
			if(NULL != strstr(line,"Symbol table \'.symtab\'"))
                			find_symbol = 1; /*we find symbol section */
			if(1 == find_symbol && 
				NULL != strstr(line, "FUNC") && \
				NULL != strstr(line, "DEFAULT")){
					sscanf(line, "%s %s %s %s %s %s %s %s", 
						buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7]);

				if(NULL != strstr(buf[6],"UND")) /*this is a symbol in .so file,we skip it*/
					continue;
				
				func_start = (unsigned int)strtoul(buf[1], NULL, 16);
				func_size = (unsigned int)strtoul(buf[2], NULL, 10);

				if(addr >= func_start && addr < func_start + func_size && func_size > 0){
					strcpy(symbol_name, buf[7]);
					ret_value = 0;
					break;
				}
			}
		}

		fclose(fp);
		if(line)
			free(line);
	}

	return ret_value;
}

/*using a address to find the function name in elf format file*/
int get_symbol_from_elf(const char *filename, unsigned long addr, char * symbol_name)
{
	ELF_Internal_Sym * psymbol_table = NULL;
	ELF_Internal_Sym * psym_cur = NULL;
	char * pstring_table = NULL;
	ELF_Internal_Word sh_link;

	int symbol_count;
	int j;

	int ret = -1;

	psymbol_table = read_symbol_table(filename, &symbol_count, &sh_link);
	if(NULL == psymbol_table)
		return ret;

	pstring_table = read_string_table(filename, sh_link);
	if(NULL == pstring_table){
		if(NULL != psymbol_table)
			free(psymbol_table);
		return ret;
	}

	psym_cur = psymbol_table;
	for(j = 0; j < symbol_count; j++,psym_cur++){
		/*skip the entries which don't have name or is not a func*/
		if(0 == psym_cur->st_shndx || STT_FUNC != ELF_Internal_ST_TYPE(psym_cur->st_info))
			continue;
		if(!psym_cur->st_value)
			continue;
		/*we find the right function name*/
		if(addr >= psym_cur->st_value 
				&& addr < psym_cur->st_value + psym_cur->st_size){
			safe_strncpy(symbol_name, pstring_table + psym_cur->st_name, FUNCNAME_SIZE);
			ret = 0;
			break;
		}		
	}

	if(NULL != pstring_table)
		free(pstring_table);
	if(NULL != psymbol_table)
		free(psymbol_table);

	return ret;
}



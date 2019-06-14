/*
 * This code is derived from libunwind-1.1 by 
 * liuqinglin <liuqinglin@kedacom.com>
 *
 *
 * History:
 *   2015/09/18 - [liuqinglin] Create
 *
 */
/* libunwind - a platform-independent unwind library
   Copyright (C) 2003-2005 Hewlett-Packard Co
   Copyright (C) 2007 David Mosberger-Tang
	Contributed by David Mosberger-Tang <dmosberger@gmail.com>

This file is part of libunwind.

Permission is hereby granted, free of charge, to any person obtaining
a copy of this software and associated documentation files (the
"Software"), to deal in the Software without restriction, including
without limitation the rights to use, copy, modify, merge, publish,
distribute, sublicense, and/or sell copies of the Software, and to
permit persons to whom the Software is furnished to do so, subject to
the following conditions:

The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.  */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>

#include "elfxx.h"
#include "io.h"
#include "proc.h"
#include "arch_dep.h"

static inline int valid_object(struct elf_image *ei)
{
    if (ei->size <= EI_VERSION)
        return 0;

    return (memcmp(ei->image, ELFMAG, SELFMAG) == 0 &&
        ((uint8_t *)ei->image)[EI_CLASS] == ELF_CLASS &&
        ((uint8_t *)ei->image)[EI_VERSION] != EV_NONE &&
        ((uint8_t *)ei->image)[EI_VERSION] <= EV_CURRENT);
}

/* get_load_offset - get offset of the base virtual address 
*           relatived to given in elf file.
*
* @ei: point to the start address mapped the elf file
* @map_base: the start address of the elf file mapped in
*           virtual address space when excuted
* @file_offset: the offset from the beginning of the file 
*           at which the first byte of the segment resides
*
*
* Return offset of the base virtual address relatived to which
* given in elf file
*
*/
static Elf_W(Addr) get_load_offset(struct elf_image *ei,
            unsigned long map_base,
            unsigned long file_offset)
{
    Elf_W(Addr) offset = 0;
    Elf_W(Ehdr) *ehdr;
    Elf_W(Phdr) *phdr;
    int i;

    ehdr = ei->image;
    phdr = (Elf_W(Phdr) *)((char *) ei->image + ehdr->e_phoff);

    for (i = 0; i < ehdr->e_phnum; ++i) {
        if (phdr[i].p_type == PT_LOAD && phdr[i].p_offset == file_offset) {
            offset = map_base - phdr[i].p_vaddr;
            break;
        }
    }
    
    return offset;
}

/*
*
* Return a pointer point to section header table
*
*/
static Elf_W(Shdr) *section_table(struct elf_image *ei)
{
    Elf_W(Ehdr) *ehdr = ei->image;
    Elf_W(Off) soff;

    soff = ehdr->e_shoff;
    if (soff + ehdr->e_shnum * ehdr->e_shentsize > ei->size) {
        dbg("section table outside of image? (%lu > %lu)\n",
         (unsigned long)(soff + ehdr->e_shnum * ehdr->e_shentsize),
         (unsigned long)ei->size);
        return NULL;
    }

    return (Elf_W(Shdr) *)((char *)ei->image + soff);
}

static char* string_table(struct elf_image *ei, int section)
{
    Elf_W (Ehdr) *ehdr = ei->image;
    Elf_W (Off) soff, str_soff;
    Elf_W (Shdr) *str_shdr;

    /* this offset is assumed to be OK */
    soff = ehdr->e_shoff;

    str_soff = soff + (section * ehdr->e_shentsize);
    if (str_soff + ehdr->e_shentsize > ei->size) {
        dbg("string shdr table outside of image? (%lu > %lu)\n",
            (unsigned long)(str_soff + ehdr->e_shentsize),
            (unsigned long)ei->size);
        return NULL;
    }
    
    str_shdr = (Elf_W(Shdr) *)((char *) ei->image + str_soff);

    if (str_shdr->sh_offset + str_shdr->sh_size > ei->size) {
        dbg("string table outside of image? (%lu > %lu)\n",
            (unsigned long) (str_shdr->sh_offset + str_shdr->sh_size),
            (unsigned long) ei->size);
        return NULL;
    }

    dbg("strtab=0x%lx\n", (long) str_shdr->sh_offset);
    return (char *)ei->image + str_shdr->sh_offset;
}


int elf_map_image (struct elf_image *ei, 
            const char *path)
{
    struct stat statbuf;
    int fd;
    
    fd = open (path, O_RDONLY);
    if (fd < 0)
        return -1;

    if (fstat(fd, &statbuf) < 0) {
        close (fd);
        return -1;
    }

    ei->size = statbuf.st_size;
    ei->image = mmap(NULL, ei->size, PROT_READ, MAP_PRIVATE, fd, 0);
    close (fd);
    if (ei->image == MAP_FAILED)
        return -1;

    if (!valid_object(ei)) {
        munmap(ei->image, ei->size);
        return -1;
    }

    return 0;
}

/* lookup_symbol - Find the ELF image that contains
 *          IP and return the function name && offset included 
 *          the IP, if there is one.
 *
 */
int lookup_symbol(struct elf_image *ei,
            unsigned long map_start,
            unsigned long long map_offset,
            unsigned long ip,
            char *func_name,
            unsigned long *func_offset)
{
    Elf_W(Ehdr) *ehdr = ei->image;
    Elf_W(Sym) *sym, *symtab, *symtab_end;
    Elf_W(Shdr) *shdr;
    Elf_W(Addr) val, load_offset;
    size_t syment_size;
    char *strtab;
    int copy_bytes;
    unsigned int i = 0;

    if (!valid_object(ei))
        return -1;

    shdr = section_table(ei);
    if (!shdr)
        return -1;

    load_offset = get_load_offset(ei, map_start, map_offset);

    /* scanning section header table */
    for (i = 0; i < ehdr->e_shnum; ++i) {
        switch (shdr->sh_type) {
        case SHT_SYMTAB:
        case SHT_DYNSYM:
            symtab = (Elf_W(Sym) *)((char *)ei->image + shdr->sh_offset);
            symtab_end = (Elf_W(Sym) *)((char *)symtab + shdr->sh_size);
            syment_size = shdr->sh_entsize;     /* entry size */

            strtab = string_table(ei, shdr->sh_link);
            if (!strtab)
                break;

            dbg("symtab=0x%lx[%d]\n", shdr->sh_offset, shdr->sh_type);

            for (sym = symtab; sym < symtab_end;
                    sym = (Elf_W(Sym) *)((char *)sym + syment_size)) {
                if (ELF_W(ST_TYPE)(sym->st_info) == STT_FUNC &&
                        sym->st_shndx != SHN_UNDEF) {
                    /* val hold the function vaddr */
                    if (arch_get_func_addr(sym->st_value, &val) < 0)
                        continue;
                    if (sym->st_shndx != SHN_ABS)
                        val += load_offset;
                    
                    dbg("0x%016lx info=0x%02x %s\n",
                            (long) val, sym->st_info, strtab + sym->st_name);

                    /* found the symbol */
                    if ((Elf_W(Addr))ip >= (Elf_W(Addr))val && 
                        (Elf_W(Addr))ip < val + sym->st_size) {
                        if (strlen(strtab + sym->st_name) >= FUNCNAME_SIZE - 1)
                            copy_bytes = FUNCNAME_SIZE - 1;
                        else
                            copy_bytes = strlen(strtab + sym->st_name);
                        
                        strncpy(func_name, strtab + sym->st_name, copy_bytes);
                        func_name[copy_bytes] = '\0';
                        *func_offset = ip - val;
                        return 0;
                    }
                }
            }
            break;

        default:
            break;
        }
        shdr = (Elf_W(Shdr) *)(((char *) shdr) + ehdr->e_shentsize);
    }
    return -1;
}

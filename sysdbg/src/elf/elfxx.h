/*
 * This code is derived from libunwind-1.1 by 
 * <liuqinglin@kedacom.com>
 *
 *
 * History:
 *   2015/09/18 - [liuqinglin] Create
 *
 */
/* libunwind - a platform-independent unwind library
   Copyright (C) 2003, 2005 Hewlett-Packard Co
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
#ifndef __SYSDBG_ELFXX_H__
#define __SYSDBG_ELFXX_H__

#include <elf.h>
#include "proc.h"

#if defined __aarch64__ || defined __x86_64__
#ifndef ELF_CLASS
#define ELF_CLASS	ELFCLASS64
#endif
#else
#ifndef ELF_CLASS
#define ELF_CLASS	ELFCLASS32
#endif
#endif

#if ELF_CLASS == ELFCLASS32
# define ELF_W(x)	ELF32_##x
# define Elf_W(x)	Elf32_##x
#else
# define ELF_W(x)	ELF64_##x
# define Elf_W(x)	Elf64_##x
#endif

struct elf_image{
    void *image;		/* pointer to mmap'd image */
    size_t size;		/* (file-) size of the image */
};

int elf_map_image (struct elf_image *ei, 
            const char *path);

int lookup_symbol(struct elf_image *ei,
            unsigned long map_start,
            unsigned long long map_offset,
            unsigned long ip,
            char *func_name,
            unsigned long *func_offset);
#endif

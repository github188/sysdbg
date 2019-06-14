#ifndef __SYSDBG_IO_H__
#define __SYSDBG_IO_H__

#include "common.h"

extern int log_file_limit;

void u_printf(const char * fmt,...);
void u_printf_time();

void dbg(const char * fmt, ...);
#endif

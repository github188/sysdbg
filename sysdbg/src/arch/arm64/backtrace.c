/*
 * This code is derived from glibc-2.22 by
 * liuqinglin <liuqinglin@kedacom.com>
 *
 *
 * History:
 *   2015/09/16 - [liuqinglin] Create
 *
 */
/* Return backtrace of current program state.
   Copyright (C) 2008-2015 Free Software Foundation, Inc.
   This file is part of the GNU C Library.
   Contributed by Kazu Hirata <kazu@codesourcery.com>, 2008.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library.  If not, see
   <http://www.gnu.org/licenses/>.  */
#include <dlfcn.h>
#include <stdlib.h>

#include "unwind_arm.h"

struct trace_arg {
	void **array;
	int cnt, size;
	_Unwind_VRS_Result (*unwind_vrs_get) (_Unwind_Context *,
			_Unwind_VRS_RegClass,
			_uw,
			_Unwind_VRS_DataRepresentation,
			void *);
};

struct trace_context {
	void *handle;
	_Unwind_Reason_Code (*unwind_backtrace) (_Unwind_Trace_Fn, void *);
	_Unwind_VRS_Result (*unwind_vrs_get) (_Unwind_Context *,
			_Unwind_VRS_RegClass,
			_uw,
			_Unwind_VRS_DataRepresentation,
			void *);
};

static void init(struct trace_context *lib_context)
{
	lib_context->handle = dlopen("libgcc_s.so.1", RTLD_LAZY);

	if (lib_context->handle == NULL)
		return;

	lib_context->unwind_backtrace = dlsym(lib_context->handle, "_Unwind_Backtrace");
	lib_context->unwind_vrs_get = dlsym(lib_context->handle, "_Unwind_VRS_Get");
	if (lib_context->unwind_vrs_get == NULL)
		lib_context->unwind_backtrace = NULL;
}

/* This function is identical to "_Unwind_GetGR", except that it uses
   "unwind_vrs_get" instead of "_Unwind_VRS_Get".  */
	static inline _Unwind_Word
unwind_getgr (_Unwind_Context *context, int regno,
		_Unwind_VRS_Result (*unwind_vrs_get) (_Unwind_Context *,
			_Unwind_VRS_RegClass,
			_uw,
			_Unwind_VRS_DataRepresentation,
			void *))
{
	_uw val;
	unwind_vrs_get (context, _UVRSC_CORE, regno, _UVRSD_UINT32, &val);
	return val;
}

/* This macro is identical to the _Unwind_GetIP macro, except that it
   uses "unwind_getgr" instead of "_Unwind_GetGR".  */
# define unwind_getip(context, vrs_get) \
	(unwind_getgr(context, 15, vrs_get) & ~(_Unwind_Word)1)

	static _Unwind_Reason_Code
backtrace_helper (struct _Unwind_Context *ctx, void *a)
{
	struct trace_arg *arg = a;

	/* We are first called with address in the __backtrace function.
	   Skip it.  */
	if (arg->cnt != -1)
		arg->array[arg->cnt] = (void *) unwind_getip (ctx, arg->unwind_vrs_get);
	if (++arg->cnt == arg->size)
		return _URC_END_OF_STACK;
	return _URC_NO_REASON;
}

static void close_handler (struct trace_context *lib_context)
{
	lib_context->unwind_backtrace = NULL;
	lib_context->unwind_vrs_get = NULL;
	if (lib_context->handle != NULL) {
		dlclose(lib_context->handle);
		lib_context->handle = NULL;
	}
}

int internal_backtrace (void **array, int size)
{
	struct trace_context lib_context = {0};
	struct trace_arg arg = {
		.array = array,
		.size = size,
		.cnt = -1
	};

	init(&lib_context);

	if (lib_context.handle == NULL)
		return 0;

	if (lib_context.unwind_backtrace == NULL)
		return 0;

	arg.unwind_vrs_get = lib_context.unwind_vrs_get;

	if (size >= 1)
		lib_context.unwind_backtrace(backtrace_helper, &arg);

	if (arg.cnt > 1 && arg.array[arg.cnt - 1] == NULL)
		--arg.cnt;

	close_handler(&lib_context);

	return arg.cnt != -1 ? arg.cnt : 0;
}

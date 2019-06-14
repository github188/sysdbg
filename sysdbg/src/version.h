/**
 * version.h
 * 
 * Kedacom CBB modules version track.
 * Copyright (C) 2013-2020, Kedacom, Inc.
 *
 * History:
 * 	2014/11/24  ZhangYan  Create
 */

#ifndef INCLUDE_VERSION_H
#define INCLUDE_VERSION_H

#include "auto_modsubver.h"

/* versions */
#define MOD_MAIN_VERSION        1
#define MOD_MAJOR_VERSION       0
#define MOD_MINOR_VERSION       0


/* Module version */
#define MODULE_VERSION	((MOD_MAIN_VERSION << 24) | (MOD_MAJOR_VERSION << 16) \
			| MOD_MINOR_VERSION)

/**
 * Module subversion, should be defined in auto_modsubver.h 
 * if not exist, define it.
 */
#ifndef MODULE_SUBVERSION
#define MODULE_SUBVERSION	0
#endif /* MODULE_SUBVERSION */

#endif /* INCLUDE_VERSION_H */

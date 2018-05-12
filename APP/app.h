/***********************************************************************
 * Copyright (c)  2008 - 2016, Shanghai AisinoChip Co.,Ltd .
 * All rights reserved.
 * Filename    : app.h
 * Description : application example header file
 * Author(s)   : Eric
 * version     : V1.0
 * Modify date : 2016-03-24
 ***********************************************************************/
#ifndef __APP_H__
#define __APP_H__
#include "common.h"

extern UINT32 g_data_buf[];
#define DATABUF             ((UINT8 *)g_data_buf)
#define PRIV_KEY_BIT        32

void init_boot(void);
#endif


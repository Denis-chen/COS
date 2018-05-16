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

#define  PAGE_ADDRESS_MASK   0xFFFFFE00U
#define PRIV_KEY_BIT         32
#define DATA_LEN		     256
typedef struct
{
	UINT8   is_ready;     //数据是否就绪， 用于AP模块读取它来判断SE是否已经处理完成
	UINT8	id;			  //参考命令ID
	UINT16	len;		  //para data len
}message_header;

typedef struct 
{
	message_header	header;	
	char 			para[DATA_LEN];	// pointer to the actual data in the buffer
}message_t;


//命令ID：
typedef enum
{
	AT_M2S_GEN_WALLET = 0,  /*创建钱包*/
	AT_M2S_SET_PWD,			/*用户更改交易密码*/
	AT_M2S_SAVE_MNEMONIC,   /*保存助记词*/
	AT_M2S_RECOVER_WALLET,  /*恢复钱包*/
	AT_M2S_GET_PUBKEY,      /*获取某币种主公钥*/
	AT_M2S_SIGN_TRANX,		/*签名交易*/
	AT_M2S_DEL_WALLET,      /*删除钱包*/
	AT_M2S_END,

	AT_S2M_GEN_WALLET_RSP,
	AT_S2M_SET_PWD_RSP, 
	AT_S2M_SAVE_MNEMONIC_RSP,
	AT_S2M_RECOVER_WALLET_RSP,
	AT_S2M_GET_PUBKEY_RSP,
	AT_S2M_SIGN_TRANX_RSP,
	AT_S2M_DEL_WALLET_RSP,
	AT_MAX,
}AT_CMD_ID;

void init_boot(void);
#endif


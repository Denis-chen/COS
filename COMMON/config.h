/***********************************************************************
 * Copyright (c)  2008 - 2016, Shanghai AisinoChip Co.,Ltd .
 * All rights reserved.
 * Filename    : config.h
 * Description : config header file
 * Author(s)   : Eric  
 * version     : V1.0
 * Modify date : 2016-03-24
 ***********************************************************************/
#ifndef __CONFIG_H__
#define __CONFIG_H__

#define DEBUG    //printf调试接口使能

#define DEBUG_UART    UARTA  //调试打印的端口
 
#ifdef DEBUG
#define printfS     printf
#define printfB8    printf_buff_byte
#define printfB32   printf_buff_word	 
#else
#define	printfS(format, ...)	     ((void)0)
#define	printfB8(buff, byte_len)	 ((void)0)
#define	printfB32(buff, word_len)	 ((void)0)
#endif

/*--------------- 时钟设置 ----------------------- */
#define FCLK 110  //配置core时钟/HCLK ,可配置为：6 12 30 48 50 60 70 80 90 100 110 等 (uint:MHz)
  
/*--------------- uart设置 ----------------------- */
//通信格式采用：8位数据位，1位停止位，无校验位

#define UART_BAUD_RATE	115200
//#define UART_Tx_INT_MODE   // Tx采用中断方式  （程序中Rx始终采用中断方式）
//#define UARTB_USE_CTSMODE    //CTS mode
//#define UARTB_USE_RTSMODE	 //RTS mode

#endif

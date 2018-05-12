/***********************************************************************
 * Copyright (c)  2008 - 2016, Shanghai AisinoChip Co.,Ltd .
 * All rights reserved.
 * Filename    : uart.h
 * Description : uart driver header file
 * Author(s)   : Eric  
 * version     : V1.0
 * Modify date : 2016-03-24
 ***********************************************************************/
#ifndef __UART_H__
#define __UART_H__

#include "common.h"

extern volatile UINT8 tx_flag;
extern volatile UINT8 rx_flag;

extern volatile UINT8 uart_rx_buf[];
extern volatile UINT8 rx_count;

/************************************************************************
 * function   : uart_set_baud_rate
 * Description: uart set baud rate
 * input : 
 *         UINT32 uart_index: Serial port number
 *         UINT32 cpu_mhz: cpu frequency
 *         UINT32 baud_rate: Series rate
 * return: none
 ************************************************************************/
void uart_set_baud_rate(UINT32 uart_index, UINT32 cpu_mhz, UINT32 baud_rate);

/************************************************************************
 * function   : uart_init
 * Description: uart initial for uart_index, cpu_mhz, baud_rate
 * input : 
 *         UINT32 uart_index: Serial port number
 *         UINT32 baud_rate: Series rate
 * return: none
 ************************************************************************/
void uart_init(UINT32 uart_index, UINT32 baud_rate);

/************************************************************************
 * function   : outbyte
 * Description: uart out byte
 * input : 
 *         UINT32 uart_index: Serial port number
 *         char c: out byte
 * return: none
 ************************************************************************/
void outbyte(UINT32 uart_index, char c);

/************************************************************************
 * function   : uart_send_bytes
 * Description: uart send bytes
 * input : 
 *         UINT32 uart_index: Serial port number
 *         UINT8* buff: out buffer
 *         UINT32 length: buffer length
 * return: none
 ************************************************************************/
void uart_send_bytes(UINT32 uart_index, UINT8 *buff, UINT32 length);

#endif



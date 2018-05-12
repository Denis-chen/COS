/***********************************************************************
 * Copyright (c)  2008 - 2016, Shanghai AisinoChip Co.,Ltd .
 * All rights reserved.
 * Filename    : uart.c
 * Description : uart driver source file
 * Author(s)   : Eric  
 * version     : V1.0
 * Modify date : 2016-03-24
 ***********************************************************************/
#include  "uart.h"
#include <stdlib.h>

volatile UINT8 tx_flag = 0;
volatile UINT8 rx_flag = 0;

volatile UINT8 uart_rx_buf[32];
volatile UINT8 rx_count = 0;

void UARTA_IRQHandler(void)
{
	UINT32 temp;
	UINT32 len = 0;
	temp = REG_UART_RIS(UARTA);
	//temp = REG_UART_MIS(UARTA);
	if(temp & 0x10)       // Rx int
	{
		while((REG_UART_FR(UARTA) & 0x10) != 0x10)  //read the DR ential Rx fifo  empty
		{
			uart_rx_buf[rx_count] = REG_UART_DR(UARTA);
			if(rx_count == 1){
				len = uart_rx_buf[0]*10 + uart_rx_buf[1];
			}
			if(rx_count == len){
				rx_flag = 1;
			}
			rx_count++;
		}
	}
	else if(temp & 0x20)  // Tx int
	{
		if((REG_UART_FR(UARTA) & 0x80) == 0x80)  //Tx fifo empty
		{
			tx_flag = 1;
		}
	}
	else
	{
		REG_UART_ICR(UARTA) = 0xfff; //clear int
	}
}

void UARTB_IRQHandler(void)
{
	UINT32 temp;

	temp = REG_UART_RIS(UARTB);

	if(temp & 0x10)       // Rx int
	{
		while((REG_UART_FR(UARTB) & 0x10) != 0x10)  //read the DR ential Rx fifo  empty
		{
			uart_rx_buf[rx_count] = REG_UART_DR(UARTB);
			rx_count++;
			rx_flag = 1;
		}
	}
	else if(temp & 0x20)  // Tx int
	{
		if((REG_UART_FR(UARTB) & 0x80) == 0x80)  //Tx fifo empty
		{
			tx_flag = 1;
		}
	}
	else
	{
		REG_UART_ICR(UARTB) = 0xfff; //clear int
	}
}

/************************************************************************
 * function   : uart_set_baud_rate
 * Description: uart set baud rate
 * input : 
 *         UINT32 uart_index: Serial port number
 *         UINT32 cpu_mhz: cpu frequency
 *         UINT32 baud_rate: Series rate
 * return: none
 ************************************************************************/
void uart_set_baud_rate(UINT32 uart_index, UINT32 clk_hz, UINT32 baud_rate)
{
	UINT32 temp, divider, remainder, fraction;

	temp = 16 * baud_rate;
	divider = clk_hz / temp;
	remainder =	clk_hz % temp;
	temp = 1 + (128 * remainder) / temp;
	fraction = temp / 2;

	REG_UART_IBRD(uart_index) = divider + (fraction >> 6);
	REG_UART_FBRD(uart_index) = fraction & 0x3f;
}
/************************************************************************
 * function   : uart_init
 * Description: uart initial for uart_index, cpu_mhz, baud_rate
 * input : 
 *         UINT32 uart_index: Serial port number
 *         UINT32 baud_rate: Series rate
 * return: none
 ************************************************************************/
void uart_init(UINT32 uart_index, UINT32 baud_rate)
{
	UINT32 uart_clk_hz;

	if(uart_index == UARTA)
	{
#ifdef LOW_POWER
		enable_module(BIT_UARTA); //enable UARTA
#endif
		uart_clk_hz = PClock;
		REG_SCU_MUXCTRLA = ((REG_SCU_MUXCTRLA & (~(0x0f << 0)))) | (0x05 << 0); //复用成UARTA
		NVIC_ClearPendingIRQ(UARTA_IRQn);
		NVIC_EnableIRQ(UARTA_IRQn);
	}
	else
	{
#ifdef LOW_POWER
		enable_module(BIT_UARTB); //enable UARTB
#endif
		uart_clk_hz = SRCClock / (((REG_SCU_CLKDIV >> 24) & 0x0f) + 1); //默认为5分频
		REG_SCU_MUXCTRLC = ((REG_SCU_MUXCTRLC & (~(0x0f << 18)))) | (0x05 << 18); //复用成UARTB

#ifdef UARTB_USE_RTSMODE
		REG_SCU_MUXCTRLC = ((REG_SCU_MUXCTRLC & (~(0x03 << 24)))) | (0x01 << 24);
		REG_UART_CR(UARTB) |= (1 << 14);
#endif
#ifdef UARTB_USE_CTSMODE
		REG_SCU_MUXCTRLC = ((REG_SCU_MUXCTRLC & (~(0x03 << 22)))) | (0x01 << 22);
		REG_UART_CR(UARTB) |= (1 << 15);
#endif
		NVIC_ClearPendingIRQ(UARTB_IRQn);
		NVIC_EnableIRQ(UARTB_IRQn);
	}

	tx_flag = 0;
	rx_flag = 0;

	REG_UART_CR(uart_index) &= ~0x01;            //disable uart
	uart_set_baud_rate(uart_index, uart_clk_hz, baud_rate);

	REG_UART_LCRH(uart_index) =	0x60; //8位数据位?1位停止位?无校验位?关闭FIFO功能
	REG_UART_CR(uart_index) = 0x0301; //enable uart

#ifdef UART_Tx_INT_MODE
	REG_UART_IMSC(uart_index) = 0x030;  //enable Rx/Tx_INT,disable else int
#else
	REG_UART_IMSC(uart_index) = 0x010;  //enable Rx_INT,disable Tx_INT and else int
#endif

	REG_UART_ICR(uart_index) = 0xfff; //clear int

	printfS("ACH512 run at %d Hz\r\n", SystemCoreClock);
	printfS("SRCClock= %d Hz, PClock= %d Hz\n", SRCClock, PClock);
	
}

/************************************************************************
 * function   : outbyte
 * Description: uart out byte
 * input : 
 *         UINT32 uart_index: Serial port number
 *         char c: out byte
 * return: none
 ************************************************************************/
void outbyte(UINT32 uart_index, char c)
{
	REG_UART_DR(uart_index) = c;

#ifdef UART_Tx_INT_MODE
	while(!tx_flag);
	tx_flag = 0;
#else
	while(REG_UART_FR(uart_index) & 0x08);  //wait for idle
#endif
}
/************************************************************************
 * function   : uart_send_bytes
 * Description: uart send bytes
 * input : 
 *         UINT32 uart_index: Serial port number
 *         UINT8* buff: out buffer
 *         UINT32 length: buffer length
 * return: none
 ************************************************************************/
void uart_send_bytes(UINT32 uart_index, UINT8 *buff, UINT32 length)
{
	UINT32 i;

	for(i = 0; i < length; i++)
	{
		outbyte(uart_index, *buff++);
	}
}

struct __FILE  //please select UART NO( UARTA or UARTB)
{
	int handle;
	/* Add whatever you need here */
};
//FILE __stdout;
//FILE __stdin;

//该函数指向UARTA
int fputc(int ch, FILE *f)
{
	/* Place your implementation of fputc here */
	/* e.g. write a character to the USART */

	outbyte(DEBUG_UART, ch); //debug uart: UARTA or UARTB
	return ch;
}


/***********************************************************************
 * Copyright (c)  2008 - 2016, Shanghai AisinoChip Co.,Ltd .
 * All rights reserved.
 * Filename    : main.c
 * Description : main source file
 * Author(s)   : Eric
 * version     : V1.0
 * Modify date : 2016-03-24
 ***********************************************************************/
#include  "common.h"
#include  "app.h"

/***********************************************************************
 * main������
 * ������� ����
 * ����ֵ   ����
 * �������� ����������ں���������ģ���ʼ���Լ�����ģ���֧�Ӻ�������ѯ
 ***********************************************************************/
int main(void)
{	
	SystemInit();
	uart_init(DEBUG_UART, UART_BAUD_RATE);

	init_boot();

	while(1);		
}


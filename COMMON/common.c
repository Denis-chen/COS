/***********************************************************************
 * Copyright (c)  2008 - 2016, Shanghai AisinoChip Co.,Ltd .
 * All rights reserved.
 * Filename    : common.c
 * Description : conmmon source file
 * Author(s)   : Eric  
 * version     : V1.0
 * Modify date : 2016-03-24
 ***********************************************************************/
#include  "common.h"

#ifdef DEBUG
/************************************************************************
 * function   : printf_buff_byte
 * Description: printf data block by byte
 * input :
 *         UINT8* buff: buff
 *         UINT32 length: byte length
 * return: none
 ************************************************************************/
void printf_buff_byte(UINT8* buff, UINT32 length)
{
	UINT32 i;

	for(i=0;i<length;i++)
	{
		printf("%.2x ",buff[i]);	
	}
	printf("\n");
}

/************************************************************************
 * function   : printf_buff_word
 * Description: printf data block by word
 * input :
 *         UINT8* buff: buff
 *         UINT32 length: word length
 * return: none
 ************************************************************************/
void printf_buff_word(UINT32* buff, UINT32 length)
{
	UINT32 i;

	for(i=0;i<length;i++)
	{
		printf("%.8x ",buff[i]);	
	}
	printf("\n");
}
#endif

void delay(UINT32 count)
{
    while(count--);
}

//一个字内大小端转换
void reverse_DWORD(UINT32 *var)
{
    UINT8 *P = (UINT8 *)var;
    UINT8 tmp;

    tmp = P[0];
    P[0] = P[3];
    P[3] = tmp;
    tmp = P[1];
    P[1] = P[2];
    P[2] = tmp;
}

//整批数据前后大小端转换
void reverse_memory(UINT8 *buff, UINT32 length)
{
    UINT8 temp;
    UINT8 *buff_start = buff;
    UINT8 *buff_end = buff + length - 1;

    while(buff_end > buff_start)
    {
        temp = *buff_start;
        *buff_start++ = *buff_end;
        *buff_end-- = temp;
    }
}


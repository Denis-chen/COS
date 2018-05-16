/***********************************************************************
 * Copyright (c)  2008 - 2016, Shanghai AisinoChip Co.,Ltd .
 * All rights reserved.
 * Filename    : eflash.c
 * Description : eflash driver source file
 * Author(s)   : Eric  
 * version     : V1.0
 * Modify date : 2016-03-24
 ***********************************************************************/
#include  "eflash.h"

#ifndef ROM_DRIVER_FLASH
/************************************************************************
 * function   : eflash_write_word
 * Description: eflash write word
 * input : 
 *         UINT32 addr: address
 *         UINT32 value: value
 * return: 0--success   1--fail
 ************************************************************************/
UINT8 eflash_write_word(UINT32 addr, UINT32 value)
{

    UINT8 vf;
    REG_EFC_CTRL |= EFC_WRITE_MODE;
#ifdef EFLASH_VERIFY_EN
    REG_EFC_CTRL |= EFC_PROGRAM_VRI_EN;
#endif
    REG_EFC_SEC = 0x55AAAA55;
    *((volatile UINT32 *)(addr)) = value;
    while(!(REG_EFC_STATUS & 0x01));
    REG_EFC_CTRL &= ~EFC_WRITE_MODE;
    vf = 0;

#ifdef EFLASH_VERIFY_EN	
	while(!(REG_EFC_INTSTATUS & (0x01 << 4)));
	REG_EFC_INTSTATUS = (0x01 << 4);
    if(REG_EFC_INTSTATUS & (0x01 << 6)) //vf error
    {
        REG_EFC_INTSTATUS = (0x01 << 6);
        vf = 1;
    }
	REG_EFC_CTRL &= ~EFC_PROGRAM_VRI_EN;
#endif

    return vf;
}

/************************************************************************
 * function   : eflash_erase_page
 * Description: eflash erase page
 * input : 
 *         UINT32 page_addr: page address
 * return: 0--success   1--fail
 ************************************************************************/
UINT8 eflash_erase_page(UINT32 page_addr)
{
    UINT8 vf;

    REG_EFC_CTRL |= EFC_PAGE_ERASE_MODE;
    REG_EFC_SEC = 0x55AAAA55;
    *((volatile UINT32 *)(page_addr)) = 0;
    while(!(REG_EFC_STATUS & 0x01));
    REG_EFC_CTRL &= ~EFC_PAGE_ERASE_MODE;
    vf = 0;

#ifdef EFLASH_VERIFY_EN
    REG_EFC_ADCT = (page_addr) >> 2;
    REG_EFC_CTRL |= EFC_ERASE_VRI_EN;
    while(!(REG_EFC_INTSTATUS & (0x01 << 4)));
	REG_EFC_INTSTATUS = (0x01 << 4);
    if(REG_EFC_INTSTATUS & (0x01 << 3)) //vf error
    {
        REG_EFC_INTSTATUS = (0x01 << 3);
        vf = 1;
    }
#endif

    return vf;
}
#endif


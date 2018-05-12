/***********************************************************************
 * Copyright (c)  2008 - 2016, Shanghai AisinoChip Co.,Ltd .
 * All rights reserved.
 * Filename    : system_ach512.h
 * Description : system config header file (for example: clock config.....)
 * Author(s)   : Eric
 * version     : V1.0
 * Modify date : 2016-03-24
 ***********************************************************************/
#ifndef __SYSTEM_ACH512_H__
#define __SYSTEM_ACH512_H__

#include  "common.h"

#ifdef __cplusplus
extern "C" {
#endif

//#define LOW_POWER
//#undef  LOW_POWER

//#define BIT_RSV           (1<<0)
#define BIT_HRNGS       (1<<0)  //for CTRLB
#define BIT_CACHE       (1<<1)
#define BIT_DES         (1<<2)
#define BIT_DMAC        (1<<3)
#define BIT_EFC         (1<<4)
#define BIT_HRNG        (1<<5)
#define BIT_MIM         (1<<6)
#define BIT_NFM         (1<<7)
//#define BIT_ROM         (1<<8)
#define BIT_PKI         (1<<8)  //for CTRLB
#define BIT_SDIO        (1<<9)
#define BIT_SM1         (1<<10)
#define BIT_HASH        (1<<11)
#define BIT_SM4         (1<<12)
#define BIT_SPIA        (1<<13)
#define BIT_SPIB        (1<<14)
//#define BIT_SRAM          (1<<15)
#define BIT_UARTB       (1<<15) //for CTRLB
#define BIT_SSF33       (1<<16)
#define BIT_UAC         (1<<17)
#define BIT_USB         (1<<18)
#define BIT_EMW         (1<<19)
//#define BIT_RSV           (1<<20)
#define BIT_CRC16       (1<<20) //for CTRLB
//#define BIT_RSV           (1<<21)
#define BIT_AES         (1<<21) //for CTRLB
#define BIT_GPIO        (1<<22)
//#define BIT_RSV           (1<<23)
#define BIT_7816MS      (1<<24)
//#define BIT_RSV           (1<<25)
#define BIT_SENSOR      (1<<26)
#define BIT_TIMER       (1<<27)
#define BIT_UARTA       (1<<28)
//#define BIT_RSV           (1<<29)
#define BIT_WDT         (1<<30)
#define BIT_I2C         (1UL<<31)

#define CLK_DIV_CORE    (0<<0)      //不分频
#define CLK_DIV_PCLK    (1<<4)      //2分频
#define CLK_DIV_PKI     (0<<8)      //不分频
#define CLK_DIV_SDIO    (3<<12)     //4分频
#define CLK_DIV_SPIB    (2<<20)     //3分频
#define CLK_DIV_UARTB   (4<<24)     //5分频
//#define CLK_DIV_HRNGS     (47<<13)    //HRNGS = 1Mhz (48M下)

#define CLK_SRC_RC48M   0x00000000   //clk src from RC48M
#define CLK_SRC_XTAL    0x40000000   //clk src from XC12M
#define CLK_SRC_RC32K   0x40001100   //clk src from RC32K
#define CLK_SRC_PLL     0x40000100  //clk src from PLL
#define CLK_SRC_USBPHY  0x40000900  //clk src from USBPHY

#define PLL_CFG(m,n,o)      (((o)<<18)|((n)<<14)|(m) )
#define PLL_DLY             (0x30<<23) //PLL等待约1ms
#define PLL_UPDATE_EN       (1<<22)

extern uint32_t SystemCoreClock;     //core时钟/HCLK , (uint:Hz)
extern uint32_t SRCClock;            //源时钟,clk_src, (uint:Hz)
extern uint32_t PClock;              //APB时钟/PCLK  , (uint:Hz)

/************************************************************************
 * function   : enable_module
 * Description: digital module enable
 * input :
           UINT32 value: enable module bits
 * return: none
 ************************************************************************/
void enable_module(UINT32 value);

/************************************************************************
 * function   : disable_module
 * Description: digital module disable
 * input :
           UINT32 value: enable module bits
 * return: none
 ************************************************************************/
void disable_module(UINT32 value);

/************************************************************************
 * function   : SystemInit
 * Description: SystemInit
 * input : none
 * return: none
 ************************************************************************/
void SystemInit(void);

/************************************************************************
 * function   : clock_init
 * Description: clock init, initil several clock variables
 * input :
           uint32_t system_clk_mhz: expected system core clock
 * return: none
 ************************************************************************/
void clock_init(uint32_t system_clk_mhz);

void SystemCoreClockUpdate (void);


#ifdef __cplusplus
}
#endif

#endif

/***********************************************************************
 * Copyright (c)  2008 - 2016, Shanghai AisinoChip Co.,Ltd .
 * All rights reserved.
 * Filename    : system_ach512.c
 * Description : system config source file (for example: clock config.....)
 * Author(s)   : Eric
 * version     : V1.0
 * Modify date : 2016-03-24
 ***********************************************************************/
#include  "system_ach512.h"

uint32_t SystemCoreClock = 0; //core时钟/HCLK , (uint:Hz)
uint32_t SRCClock = 0;        //源时钟,clk_src, (uint:Hz)
uint32_t PClock = 0;          //APB时钟/PCLK  , (uint:Hz)


/************************************************************************
 * function   : enable_module
 * Description: digital module enable
 * input :
           UINT32 value: enable module bits
 * return: none
 ************************************************************************/
void enable_module(UINT32 value)
{
    UINT32 mask = BIT_AES | BIT_CRC16 | BIT_UARTB | BIT_PKI | BIT_HRNGS;

    if(value & BIT_AES)     REG_SCU_CTRLB &= ~(1UL << 31);
    if(value & BIT_CRC16)   REG_SCU_CTRLB &= ~(1 << 29);
    if(value & BIT_UARTB)   REG_SCU_CTRLB &= ~(1 << 6);
    if(value & BIT_PKI)     REG_SCU_CTRLB &= ~(1 << 5);
    if(value & BIT_HRNGS)   REG_SCU_CTRLB &= ~(1 << 2);
    if(value & BIT_SPIB)    REG_SCU_CTRLB &= ~(1 << 4);
    if(value & BIT_SDIO)    REG_SCU_CTRLB &= ~(3 << 0);

    REG_SCU_CTRLA &= (~value) | mask;
}

/************************************************************************
 * function   : disable_module
 * Description: digital module disable
 * input :
           UINT32 value: enable module bits
 * return: none
 ************************************************************************/
void disable_module(UINT32 value)
{
    UINT32 mask = BIT_AES | BIT_CRC16 | BIT_UARTB | BIT_PKI | BIT_HRNGS;

    if(value & BIT_AES)     REG_SCU_CTRLB |= (1UL << 31);
    if(value & BIT_CRC16)   REG_SCU_CTRLB |= (1 << 29);
    if(value & BIT_UARTB)   REG_SCU_CTRLB |= (1 << 6);
    if(value & BIT_PKI)     REG_SCU_CTRLB |= (1 << 5);
    if(value & BIT_HRNGS)   REG_SCU_CTRLB |= (1 << 2);
    if(value & BIT_SPIB)    REG_SCU_CTRLB |= (1 << 4);
    if(value & BIT_SDIO)    REG_SCU_CTRLB |= (3 << 0);

    REG_SCU_CTRLA |= value & (~mask);
}

/************************************************************************
 * function   : clock_init_XOSC
 * Description: cclock_init_XOSC, initil several clock variables
 * input :
           uint32_t system_clk_mhz: expected system core clock
 * return: none
 ************************************************************************/
void clock_init_XOSC(uint32_t system_clk_mhz)
{
    uint8_t  pll_m = 0, pll_n = 0, pll_od = 0;
    uint8_t  wait_value = 0;
    uint32_t div, efmz;

    if(system_clk_mhz <= 12)
    {
        if(12 % system_clk_mhz)
        {
            return;
        }
        REG_SCU_CTRLB = (REG_SCU_CTRLB & ~0x40001900) | CLK_SRC_XTAL; //时钟源选择12M
        div = 12 / system_clk_mhz;
        REG_SCU_CLKDIV = ((div - 1) << 0) | CLK_DIV_PCLK | CLK_DIV_PKI | CLK_DIV_SDIO | CLK_DIV_SPIB | CLK_DIV_UARTB;
    }
    else
    {
        switch(system_clk_mhz)
        {
            case 30: pll_m = 40; pll_n = 2; pll_od = 3; break;
            case 48: pll_m = 64; pll_n = 2; pll_od = 3; break;
            case 50: pll_m = 50; pll_n = 3; pll_od = 2; break;
            case 60: pll_m = 60; pll_n = 3; pll_od = 2; break;
            case 70: pll_m = 70; pll_n = 3; pll_od = 2; break;
            case 80: pll_m = 80; pll_n = 3; pll_od = 2; break;
            case 90: pll_m = 90; pll_n = 3; pll_od = 2; break;
            case 100: pll_m = 50; pll_n = 3; pll_od = 1; break;
            case 110: pll_m = 55; pll_n = 3; pll_od = 1; break;
            case 120: pll_m = 60; pll_n = 3; pll_od = 1; break;
            default: return;
        }

        REG_EFC_CTRL = (REG_EFC_CTRL & ~(0x1f << 8)) | (0x08 << 8);    //配置初始EFC RD wait
        REG_SCU_CTRLB = (REG_SCU_CTRLB & ~0x40001900) | CLK_SRC_RC48M; //RCC48

        REG_SCU_PLLCSR = PLL_CFG(pll_m, pll_n, pll_od) | PLL_DLY;
        REG_SCU_PLLCSR &= ~(1UL << 31); //PLL时钟源选择片外12M
        REG_SCU_PLLCSR |= PLL_UPDATE_EN;
        while(!(REG_SCU_PLLCSR & (1 << 30)));      //wait PLL stabled
        REG_SCU_CLKDIV = (0 << 0) | CLK_DIV_PCLK | CLK_DIV_PKI | CLK_DIV_SDIO  | CLK_DIV_SPIB | CLK_DIV_UARTB;
        REG_SCU_CTRLB = (REG_SCU_CTRLB & ~0x40001900) | CLK_SRC_PLL; //PLL
    }

    //REG_SCU_CTRLB = (REG_SCU_CTRLB & (~(0xffff << 13))) | CLK_DIV_HRNGS;
    REG_SCU_CTRLB = (REG_SCU_CTRLB & (~(0xffff << 13))) | ((system_clk_mhz-1) << 13);

    SystemCoreClock = system_clk_mhz * 1000000;
    div = (REG_SCU_CLKDIV & 0x0f) + 1;
    SRCClock = SystemCoreClock * div;
    div = ((REG_SCU_CLKDIV >> 4) & 0x0f) + 1;
    PClock = SystemCoreClock / div;

    //set EFC RD_WAIT (至少52ns)
    efmz = SystemCoreClock / 1000000;
    wait_value = (52 * efmz) / 1000;
    REG_EFC_CTRL = (REG_EFC_CTRL & (~(0x1f << 8))) | (wait_value << 8);
}

/************************************************************************
 * function   : clock_init_ROSC
 * Description: clock_init_ROSC, initil several clock variables
 * input :
           uint32_t system_clk_mhz: expected system core clock
 * return: none
 ************************************************************************/
void clock_init_ROSC(uint32_t system_clk_mhz)
{
    uint8_t  pll_m = 0, pll_n = 0, pll_od = 0;
    uint8_t  wait_value = 0;
    uint32_t div, clk_hz, efmz;

    if(system_clk_mhz <= 12)
    {
        if(12 % system_clk_mhz)
        {
            return;
        }
        REG_SCU_CTRLB = (REG_SCU_CTRLB & ~0x40001900) | CLK_SRC_RC48M; //RC48
        div = 48 / system_clk_mhz;
        REG_SCU_CLKDIV = ((div - 1) << 0) | CLK_DIV_PCLK | CLK_DIV_PKI | CLK_DIV_SDIO | CLK_DIV_SPIB | CLK_DIV_UARTB;
    }
    else
    {
        switch(system_clk_mhz)
        {
            case 30: pll_m = 40; pll_n = 2; pll_od = 3; break;
            case 48: pll_m = 64; pll_n = 2; pll_od = 3; break;
            case 50: pll_m = 50; pll_n = 3; pll_od = 2; break;
            case 60: pll_m = 60; pll_n = 3; pll_od = 2; break;
            case 70: pll_m = 70; pll_n = 3; pll_od = 2; break;
            case 80: pll_m = 80; pll_n = 3; pll_od = 2; break;
            case 90: pll_m = 90; pll_n = 3; pll_od = 2; break;
            case 100: pll_m = 50; pll_n = 3; pll_od = 1; break;
            case 110: pll_m = 55; pll_n = 3; pll_od = 1; break;
            case 120: pll_m = 60; pll_n = 3; pll_od = 1; break;
            default: return;
        }

        REG_EFC_CTRL = (REG_EFC_CTRL & ~(0x1f << 8)) | (0x08 << 8);    //配置初始EFC RD wait
        REG_SCU_CTRLB = (REG_SCU_CTRLB & ~0x40001900) | CLK_SRC_RC48M; //RC48

        REG_SCU_PLLCSR = PLL_CFG(pll_m, pll_n, pll_od) | PLL_DLY;
        REG_SCU_PLLCSR |= 1UL << 31; //PLL时钟源选择RC48M的4分频
        REG_SCU_PLLCSR |= PLL_UPDATE_EN;
        while(!(REG_SCU_PLLCSR & (1 << 30))); //wait PLL stabled
        REG_SCU_CLKDIV = (0 << 0) | CLK_DIV_PCLK | CLK_DIV_PKI | CLK_DIV_SDIO  | CLK_DIV_SPIB | CLK_DIV_UARTB;
        REG_SCU_CTRLB = (REG_SCU_CTRLB & ~0x40001900) | CLK_SRC_PLL; //PLL

    }

   //REG_SCU_CTRLB = (REG_SCU_CTRLB & (~(0xffff << 13))) | CLK_DIV_HRNGS;
    REG_SCU_CTRLB = (REG_SCU_CTRLB & (~(0xffff << 13))) | ((system_clk_mhz-1) << 13);

    clk_hz = (*(volatile UINT32 *)(0x0008022C));//实测值/16000
    if((clk_hz < (49000000 / 16000)) && (clk_hz > (44000000 / 16000)))
    { //RC48M实测值有效
      //clk_hz = (clk_hz * 16000 * system_clk_mhz)/48
        clk_hz = (clk_hz * 1000 * system_clk_mhz) / 3; //为了防止数据溢出
    }
    else
    {
        clk_hz = system_clk_mhz * 1000000;
    }

    SystemCoreClock = clk_hz;
    div = (REG_SCU_CLKDIV & 0x0f) + 1;
    SRCClock = SystemCoreClock * div;
    div = ((REG_SCU_CLKDIV >> 4) & 0x0f) + 1;
    PClock = SystemCoreClock / div;

    //set EFC RD_WAIT (至少52ns)
    efmz = SystemCoreClock / 1000000;
    wait_value = (52 * efmz) / 1000;
    REG_EFC_CTRL = (REG_EFC_CTRL & (~(0x1f << 8))) | (wait_value << 8);
}



/************************************************************************
 * function   : clock_init
 * Description: clock init, initil several clock variables
 * input :
           uint32_t system_clk_mhz: expected system core clock
 * return: none
 ************************************************************************/
void clock_init(uint32_t system_clk_mhz)
{

    clock_init_XOSC(system_clk_mhz); //PLL使用片外时钟12M

    //clock_init_ROSC(system_clk_mhz); //PLL使用片内时钟RC48/4
}
void cache_on(void)
{

#ifdef LOW_POWER
    enable_module(BIT_CACHE); //enable CACHE
#endif
    REG_CACHE_CR  = (1 << 0) | (1 << 1); // Enable cache、clear buff
}

void cache_off(void)
{
    REG_CACHE_CR  = 0;
#ifdef LOW_POWER
    disable_module(BIT_CACHE); //disable CACHE
#endif
}

/************************************************************************
 * function   : SystemInit
 * Description: SystemInit
 * input : none
 * return: none
 ************************************************************************/
void SystemInit(void)
{
    REG_SCU_RESETCTRLA = 0x6C966274; //reset all modules(except：SENSOR/SRAM/ROM/EFC)
    REG_SCU_RESETCTRLB |= 0x01;
    delay(10);
    REG_SCU_RESETCTRLA = 0x00;
    REG_SCU_RESETCTRLB &= ~0x01;

#ifdef LOW_POWER
    REG_SCU_CTRLA = ~0x04000110; //disable all modules(except：SENSOR/ROM/EFC)
    REG_SCU_CTRLB |= 0xa0000077;
//  disable_module(BIT_SDIO | BIT_MIM);//example：disable SDIO/MIM
#else
    enable_module(0xffffffff); //enable all modules
#endif
    clock_init(FCLK);
    cache_on();
}

void SystemCoreClockUpdate(void)
{
    //SystemCoreClock=FCLK;
}



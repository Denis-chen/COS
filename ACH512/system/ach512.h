/***********************************************************************
 * Copyright (c)  2008 - 2016, Shanghai AisinoChip Co.,Ltd .
 * All rights reserved.
 * Filename    : ach512.h
 * Description : chip header file (registers and interrupt source)
 * Author(s)   : Eric
 * version     : V1.0
 * Modify date : 2016-03-24
 ***********************************************************************/

#ifndef __ACH512_H__
#define __ACH512_H__

#ifdef __cplusplus
extern "C"
{
#endif

/* -------------------------  Interrupt Number Definition  ------------------------ */

typedef enum IRQn
{
/* -------------------  Cortex-M3 Processor Exceptions Numbers  ------------------- */
    NonMaskableInt_IRQn           = -14,      /*  2 Non Maskable Interrupt */
    HardFault_IRQn                = -13,      /*  3 HardFault Interrupt */
    MemoryManagement_IRQn         = -12,      /*  4 Memory Management Interrupt */
    BusFault_IRQn                 = -11,      /*  5 Bus Fault Interrupt */
    UsageFault_IRQn               = -10,      /*  6 Usage Fault Interrupt */
    SVCall_IRQn                   =  -5,      /* 11 SV Call Interrupt */
    DebugMonitor_IRQn             =  -4,      /* 12 Debug Monitor Interrupt */
    PendSV_IRQn                   =  -2,      /* 14 Pend SV Interrupt */
    SysTick_IRQn                  =  -1,      /* 15 System Tick Interrupt */

/* ----------------------  ARMCM3 Specific Interrupt Numbers  --------------------- */
    WDT_IRQn   	        		   = 0,        // 0:  WDT_IRQHandler
    TIMER_IRQn                     = 1,        // 1:  TIMER_IRQHandler
    UARTA_IRQn                     = 3,        // 3:  UARTA_IRQHandler
    SPIA_IRQn                      = 4,        // 4:  SPIA_IRQHandler
    SPIB_IRQn                      = 5,        // 5:  SPIB_IRQHandler
    GPIOA_IRQn                     = 6,        // 6:  GPIOA_IRQHandler
    USB_IRQn                       = 7,        // 7:  USB_IRQHandler
    SM1_IRQn                       = 9,        // 9:  SM1_IRQHandler
    DES_IRQn                       = 10,       // 10: DES_IRQHandler
    ECC_IRQn                       = 11,       // 11: ECC_IRQHandler
    EFC_IRQn                       = 12,       // 12: EFC_IRQHandler
    I2C_IRQn                       = 14,       // 14: I2C_IRQHandler
    MS7816RST_IRQn                 = 15,       // 15: MS7816RST_IRQn
    SM4_IRQn                       = 16,       // 16: SM4_IRQHandler
    GPIOB_IRQn                     = 17,       // 17: GPIOB_IRQHandler
    DMA_IRQn                       = 18,       // 18: DMA_IRQHandler
    CCPWM_IRQn                     = 19,       // 19: CCPWM_IRQHandler
    SDIO_IRQn                      = 20,       // 20: SDIO_IRQHandler
    UARTB_IRQn                     = 21,       // 21: UARTB_IRQHandler
    BCH_IRQn                       = 22,       // 22: BCH_IRQHandler
    NFM_IRQn                       = 23,       // 23: NFM_IRQHandler
    EMW_IRQHandle                  = 24,       // 24: EMW_IRQHandle
    SENSOR_IRQn                    = 26,       // 26: SENSOR_IRQHandler
    MS7816_IRQn                    = 27,       // 27: MS7816_IRQHandler
    WAKEUP_IRQn                    = 31,         // 31: WAKEUP_IRQHandler

} IRQn_Type;


/* ================================================================================ */
/* ================      Processor and Core Peripheral Section     ================ */
/* ================================================================================ */

/* -------  Start of section using anonymous unions and disabling warnings  ------- */
#if   defined (__CC_ARM)
#pragma push
#pragma anon_unions
#elif defined (__ICCARM__)
#pragma language=extended
#elif defined(__ARMCC_VERSION) && (__ARMCC_VERSION >= 6010050)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wc11-extensions"
#pragma clang diagnostic ignored "-Wreserved-id-macro"
#elif defined (__GNUC__)
/* anonymous unions are enabled by default */
#elif defined (__TMS470__)
/* anonymous unions are enabled by default */
#elif defined (__TASKING__)
#pragma warning 586
#elif defined (__CSMC__)
/* anonymous unions are enabled by default */
#else
#warning Not supported compiler type
#endif

/* --------  Configuration of the Cortex-M3 Processor and Core Peripherals  ------- */
#define __CM3_REV                 0x0201U   /* Core revision r2p1 */
#define __MPU_PRESENT             1         /* MPU present */
#define __VTOR_PRESENT            1         /* VTOR present or not */
#define __NVIC_PRIO_BITS          3         /* Number of Bits used for Priority Levels */
#define __Vendor_SysTickConfig    0         /* Set to 1 if different SysTick Config is used */

#include "core_cm3.h"                       /* Processor and core peripherals */
#include "system_ach512.h"                  /* System Header */

/* ================================================================================ */
/* ================       Device Specific Peripheral Section       ================ */
/* ================================================================================ */

/* --------  End of section using anonymous unions and disabling warnings  -------- */
#if   defined (__CC_ARM)
#pragma pop
#elif defined (__ICCARM__)
/* leave anonymous unions enabled */
#elif (__ARMCC_VERSION >= 6010050)
#pragma clang diagnostic pop
#elif defined (__GNUC__)
/* anonymous unions are enabled by default */
#elif defined (__TMS470__)
/* anonymous unions are enabled by default */
#elif defined (__TASKING__)
#pragma warning restore
#elif defined (__CSMC__)
/* anonymous unions are enabled by default */
#else
#warning Not supported compiler type
#endif

#define ROM_BASE_ADDR                    0x12000000

///*----------------------EFC------------------------*/
#define EFLASH_BASE_ADDR                 0x00000000  //rom mode
#define EFC_REG_BASE_ADDR				 EFLASH_BASE_ADDR+0x00100000

#define REG_EFC_CTRL    	             (*(volatile uint32_t  *)(EFC_REG_BASE_ADDR + 0x00))
#define REG_EFC_SEC    		             (*(volatile uint32_t  *)(EFC_REG_BASE_ADDR + 0x04))
#define REG_EFC_ADCT    	             (*(volatile uint32_t  *)(EFC_REG_BASE_ADDR + 0x08))
#define REG_EFC_ERTO   		             (*(volatile uint32_t  *)(EFC_REG_BASE_ADDR + 0x0C))
#define REG_EFC_WRTO    	             (*(volatile uint32_t  *)(EFC_REG_BASE_ADDR + 0x10))
#define REG_EFC_STATUS    	             (*(volatile uint32_t  *)(EFC_REG_BASE_ADDR + 0x14))
#define REG_EFC_INTSTATUS                (*(volatile uint32_t  *)(EFC_REG_BASE_ADDR + 0x18))
#define REG_EFC_INEN    	             (*(volatile uint32_t  *)(EFC_REG_BASE_ADDR + 0x1c))


///*----------------------DMA------------------------*/
#define DMACH0                           0
#define DMACH1                           1
#define DMACH2                           2
#define DMACH3                           3
#define DMA_BASE_ADDR                    0x40000000
#define REG_DMAC_IntStatus               (*(volatile uint32_t *)(DMA_BASE_ADDR + 0x00))
#define REG_DMAC_IntTCStatus             (*(volatile uint32_t *)(DMA_BASE_ADDR + 0x04))
#define REG_DMAC_IntTCClr                (*(volatile uint32_t *)(DMA_BASE_ADDR + 0x08))
#define REG_DMAC_IntErrStatus            (*(volatile uint32_t *)(DMA_BASE_ADDR + 0x0C))
#define REG_DMAC_IntErrClr               (*(volatile uint32_t *)(DMA_BASE_ADDR + 0x10))
#define REG_DMAC_RawIntTCStatus          (*(volatile uint32_t *)(DMA_BASE_ADDR + 0x14))
#define REG_DMAC_RawIntErrStatus         (*(volatile uint32_t *)(DMA_BASE_ADDR + 0x18))
#define REG_DMAC_EnChnStatus             (*(volatile uint32_t *)(DMA_BASE_ADDR + 0x1C))
#define REG_DMAC_Config                  (*(volatile uint32_t *)(DMA_BASE_ADDR + 0x30))
#define REG_DMAC_Sync                    (*(volatile uint32_t *)(DMA_BASE_ADDR + 0x34))

#define REG_DMAC_ChSrcAddr(x)            (*(volatile uint32_t *)(DMA_BASE_ADDR + 0x100 + 0x20 * (x)))
#define REG_DMAC_ChDestAddr(x)           (*(volatile uint32_t *)(DMA_BASE_ADDR + 0x104 + 0x20 * (x)))
#define REG_DMAC_ChLinkList(x)           (*(volatile uint32_t *)(DMA_BASE_ADDR + 0x108 + 0x20 * (x)))
#define REG_DMAC_ChCtrl(x)               (*(volatile uint32_t *)(DMA_BASE_ADDR + 0x10C + 0x20 * (x)))
#define REG_DMAC_ChConfig(x)             (*(volatile uint32_t *)(DMA_BASE_ADDR + 0x110 + 0x20 * (x)))

///*----------------------CRC16------------------------*/
#define CRC16_BASE_ADDR                  0x40013000
#define REG_CRC16_DATA                   (*(volatile uint32_t *)(CRC16_BASE_ADDR + 0x00))
#define REG_CRC16_INIT                   (*(volatile uint32_t *)(CRC16_BASE_ADDR + 0x04))
#define REG_CRC16_CTRL                   (*(volatile uint32_t *)(CRC16_BASE_ADDR + 0x08))


///*----------------------USB------------------------*/
#define USB_BASE_ADDR                    0x40030000
#define REG_USBC_FADDRR 			     (*(volatile uint8_t  *)(USB_BASE_ADDR + 0))
#define REG_USBC_UCSR                    (*(volatile uint8_t  *)(USB_BASE_ADDR + 1))
#define REG_USBC_IntrTx		             (*(volatile uint16_t *)(USB_BASE_ADDR + 2))
#define REG_USBC_IntrRx				     (*(volatile uint16_t *)(USB_BASE_ADDR + 4))
#define REG_USBC_INTRTXE	             (*(volatile uint16_t *)(USB_BASE_ADDR + 6))
#define REG_USBC_INTRRXE			     (*(volatile uint16_t *)(USB_BASE_ADDR + 8))
#define REG_USBC_IntrUSB			     (*(volatile uint8_t  *)(USB_BASE_ADDR + 0x0A))
#define REG_USBC_IntrUSBE			     (*(volatile uint8_t  *)(USB_BASE_ADDR + 0x0B))
#define	REG_USBC_FNUMR				     (*(volatile uint16_t *)(USB_BASE_ADDR + 0x0C))
#define	REG_USBC_Eindex				     (*(volatile uint8_t  *)(USB_BASE_ADDR + 0x0E))
#define	REG_USBC_Testmode			     (*(volatile uint8_t  *)(USB_BASE_ADDR + 0x0F))
#define REG_USBC_TXPSZR				     (*(volatile uint16_t *)(USB_BASE_ADDR + 0x10))
#define REG_USBC_E0CSR				     (*(volatile uint8_t  *)(USB_BASE_ADDR + 0x12))
#define REG_USBC_TxCSR				     (*(volatile uint16_t *)(USB_BASE_ADDR + 0x12))
#define REG_USBC_RXPSZR				     (*(volatile uint16_t *)(USB_BASE_ADDR + 0x14))
#define REG_USBC_RxCSR				     (*(volatile uint16_t *)(USB_BASE_ADDR + 0x16))
#define REG_USBC_E0COUNTR			     (*(volatile uint8_t  *)(USB_BASE_ADDR + 0x18))
#define REG_USBC_RXCOUNT			     (*(volatile uint16_t *)(USB_BASE_ADDR + 0x18))
#define REG_USBC_TxFIFO_SIZE		     (*(volatile uint8_t  *)(USB_BASE_ADDR + 0x1A))
#define REG_USBC_RxFIFO_SIZE		     (*(volatile uint8_t  *)(USB_BASE_ADDR + 0x1B))
#define REG_USBC_TxFIFO_ADD			     (*(volatile uint16_t *)(USB_BASE_ADDR + 0x1C))
#define REG_USBC_RxFIFO_ADD			     (*(volatile uint16_t *)(USB_BASE_ADDR + 0x1E))
#define REG_USBC_FIFO_ENTRY(index)       (*(volatile uint8_t  *)(USB_BASE_ADDR + 0x20 + (index) * 4))
#define REG_USBC_TX_PTR				     (*(volatile uint16_t *)(USB_BASE_ADDR + 0x40))

///*------------------------NFM-----------------------*/
//NFM  register
#define NFM_BASE_ADDR                    0x40040000
#define REG_NFM_CTRL 		             (*(volatile uint32_t *)(NFM_BASE_ADDR))
#define REG_NFM_WST 		             (*(volatile uint32_t *)(NFM_BASE_ADDR + 0x04))
#define REG_NFM_STATUS 		             (*(volatile uint32_t *)(NFM_BASE_ADDR + 0x08))
//BCH register
#define REG_BCH_CONFIG  	             (*(volatile uint32_t *)(NFM_BASE_ADDR + 0x10))
#define REG_BCH_CTRL  		             (*(volatile uint32_t *)(NFM_BASE_ADDR + 0x14))
#define REG_BCH_STATUS 		             (*(volatile uint32_t *)(NFM_BASE_ADDR + 0x18))
#define REG_BCH_CODE8     	             (*(volatile uint8_t  *)(NFM_BASE_ADDR + 0x1C))
#define REG_BCH_CODE16     	             (*(volatile uint16_t *)(NFM_BASE_ADDR + 0x1C))
#define REG_BCH_CODE32     	             (*(volatile uint32_t *)(NFM_BASE_ADDR + 0x1C))
#define REG_BCH_ERRADR  	             (*(volatile uint32_t *)(NFM_BASE_ADDR + 0x20))
#define REG_BCH_ERRVEC  	             (*(volatile uint32_t *)(NFM_BASE_ADDR + 0x24))
#define REG_BCH_BASEADDR  	             (*(volatile uint32_t *)(NFM_BASE_ADDR + 0x28))
#define REG_BCH_CODEPTR 	             (*(volatile uint32_t *)(NFM_BASE_ADDR + 0x2C))
#define REG_BCH_ERRADDRPTR               (*(volatile uint32_t *)(NFM_BASE_ADDR + 0x30))
#define REG_BCH_ERRVECTPTR               (*(volatile uint32_t *)(NFM_BASE_ADDR + 0x34))
#define REG_BCH_PAGENUM 	             (*(volatile uint32_t *)(NFM_BASE_ADDR + 0x38))
#define REG_BCH_ADDRLATCH 	             (*(volatile uint32_t *)(NFM_BASE_ADDR + 0x3C))
//Nand Flash Channel
#define REG_NFM_CMD_CH                 	 (*(volatile uint32_t *)(NFM_BASE_ADDR + 0x40))
#define REG_NFM_ADDR_CH               	 (*(volatile uint32_t *)(NFM_BASE_ADDR + 0x44))
#define REG_NFM_ECC_CH8                  (*(volatile uint8_t  *)(NFM_BASE_ADDR + 0x48))
#define REG_NFM_ECC_CH16                 (*(volatile uint16_t *)(NFM_BASE_ADDR + 0x48))
#define REG_NFM_ECC_CH32               	 (*(volatile uint32_t *)(NFM_BASE_ADDR + 0x48))
#define REG_NFM_NECC_CH8                 (*(volatile uint8_t  *)(NFM_BASE_ADDR + 0x4C))
#define REG_NFM_NECC_CH16                (*(volatile uint16_t  *)(NFM_BASE_ADDR + 0x4C))
#define REG_NFM_NECC_CH32                (*(volatile uint32_t  *)(NFM_BASE_ADDR + 0x4C))

///*----------------------SDIO------------------------*/
#define SDIO_BASE_ADDR	                 0x40050000
#define REG_SDIO_CTRL   	             (*(volatile uint32_t *)(SDIO_BASE_ADDR + 0x00))
#define REG_SDIO_POWEN   	             (*(volatile uint32_t *)(SDIO_BASE_ADDR + 0x04))
#define REG_SDIO_CLK_DIV                 (*(volatile uint32_t *)(SDIO_BASE_ADDR + 0x08))
#define REG_SDIO_CLK_SRC                 (*(volatile uint32_t *)(SDIO_BASE_ADDR + 0x0C))
#define REG_SDIO_CLK_EN   	             (*(volatile uint32_t *)(SDIO_BASE_ADDR + 0x10))
#define REG_SDIO_TIMEOUT                 (*(volatile uint32_t *)(SDIO_BASE_ADDR + 0x14))
#define REG_SDIO_WIDTH  	             (*(volatile uint32_t *)(SDIO_BASE_ADDR + 0x18))
#define REG_SDIO_BLK_SIZE	             (*(volatile uint32_t *)(SDIO_BASE_ADDR + 0x1C))
#define REG_SDIO_BYTE_CNT                (*(volatile uint32_t *)(SDIO_BASE_ADDR + 0x20))
#define REG_SDIO_INT_MASK                (*(volatile uint32_t *)(SDIO_BASE_ADDR + 0x24))
#define REG_SDIO_CMD_ARG                 (*(volatile uint32_t *)(SDIO_BASE_ADDR + 0x28))
#define REG_SDIO_CMD	   	             (*(volatile uint32_t *)(SDIO_BASE_ADDR + 0x2C))
#define REG_SDIO_RESP0	   	             (*(volatile uint32_t *)(SDIO_BASE_ADDR + 0x30))
#define REG_SDIO_RESP1   	             (*(volatile uint32_t *)(SDIO_BASE_ADDR + 0x34))
#define REG_SDIO_RESP2	   	             (*(volatile uint32_t *)(SDIO_BASE_ADDR + 0x38))
#define REG_SDIO_RESP3	   	             (*(volatile uint32_t *)(SDIO_BASE_ADDR + 0x3C))
#define REG_SDIO_MINTSTS                 (*(volatile uint32_t *)(SDIO_BASE_ADDR + 0x40))
#define REG_SDIO_RINTSTS                 (*(volatile uint32_t *)(SDIO_BASE_ADDR + 0x44))
#define REG_SDIO_STATUS   	             (*(volatile uint32_t *)(SDIO_BASE_ADDR + 0x48))
#define REG_SDIO_FIFOTH   	             (*(volatile uint32_t *)(SDIO_BASE_ADDR + 0x4C))
#define REG_SDIO_CARD_DETECT             (*(volatile uint32_t *)(SDIO_BASE_ADDR + 0x50))
#define REG_SDIO_WRTPRT                  (*(volatile uint32_t *)(SDIO_BASE_ADDR + 0x54))
#define REG_SDIO_TCBCNT                  (*(volatile uint32_t *)(SDIO_BASE_ADDR + 0x5C))
#define REG_SDIO_TBBCNT                  (*(volatile uint32_t *)(SDIO_BASE_ADDR + 0x60))
#define REG_SDIO_DEBOUNCE                (*(volatile uint32_t *)(SDIO_BASE_ADDR + 0x64))
#define REG_SDIO_DATA 		             (*(volatile uint32_t *)(SDIO_BASE_ADDR + 0x100))

///*----------------------SPI------------------------*/
#define SPIA                             0
#define SPIB                             1
#define SPI_BASE_ADDR(x)                 (0x40060000 + 0x10000 * (x))
#define REG_SPI_TX_DAT(x)                (*(volatile uint8_t  *)(SPI_BASE_ADDR(x)+0x00))
#define REG_SPI_RX_DAT(x)                (*(volatile uint8_t  *)(SPI_BASE_ADDR(x)+0x00))
#define REG_SPI_BAUD(x)                  (*(volatile uint32_t *)(SPI_BASE_ADDR(x)+0x04))
#define REG_SPI_CTL(x)                   (*(volatile uint32_t *)(SPI_BASE_ADDR(x)+0x08))
#define REG_SPI_TX_CTL(x)                (*(volatile uint32_t *)(SPI_BASE_ADDR(x)+0x0c))
#define REG_SPI_RX_CTL(x)                (*(volatile uint32_t *)(SPI_BASE_ADDR(x)+0x10))
#define REG_SPI_IE(x)                    (*(volatile uint32_t *)(SPI_BASE_ADDR(x)+0x14))
#define REG_SPI_STATUS(x)                (*(volatile uint32_t *)(SPI_BASE_ADDR(x)+0x18))
#define REG_SPI_TX_DLY(x)                (*(volatile uint32_t *)(SPI_BASE_ADDR(x)+0x1c))
#define REG_SPI_BATCH(x)                 (*(volatile uint32_t *)(SPI_BASE_ADDR(x)+0x20))
#define REG_SPI_CS(x)                    (*(volatile uint32_t *)(SPI_BASE_ADDR(x)+0x24))
#define REG_SPI_OUT_EN(x)                (*(volatile uint32_t *)(SPI_BASE_ADDR(x)+0x28))
#define REG_SPI_MEM_ACC(x)               (*(volatile uint32_t *)(SPI_BASE_ADDR(x)+0x2c))
#define REG_SPI_CMD(x)                   (*(volatile uint32_t *)(SPI_BASE_ADDR(x)+0x30))
#define REG_SPI_PARA(x)                  (*(volatile uint32_t *)(SPI_BASE_ADDR(x)+0x34))
#define REG_SPI_BOUND(x)                 (*(volatile uint32_t *)(SPI_BASE_ADDR(x)+0x38))

#define SPIA_MEM_ADDR                    0x63000000

///*----------------------CACHE------------------------*/
#define CACHE_BASE_ADDR                  0x40080000
#define CACHE_MEM_BASE_ADDR  	         0x4008F000
#define REG_CACHE_CR                     (*(volatile uint32_t *)(CACHE_BASE_ADDR + 0xD000))


///*----------------------UART------------------------*/
#define UARTA		                     0
#define UARTB		                     1
#define UART_BASE_ADDR(x)	             (0x48010000 + (x) * 0xc0000)
#define REG_UART_DR(x)   	             (*(volatile uint32_t *)(UART_BASE_ADDR(x) + 0x00))
#define REG_UART_RSR(x)  	             (*(volatile uint32_t *)(UART_BASE_ADDR(x) + 0x04))
#define REG_UART_FR(x)   	             (*(volatile uint32_t *)(UART_BASE_ADDR(x) + 0x18))
#define REG_UART_IBRD(x) 	             (*(volatile uint32_t *)(UART_BASE_ADDR(x) + 0x24))
#define REG_UART_FBRD(x) 	             (*(volatile uint32_t *)(UART_BASE_ADDR(x) + 0x28))
#define REG_UART_LCRH(x) 	             (*(volatile uint32_t *)(UART_BASE_ADDR(x) + 0x2C))
#define REG_UART_CR(x)   	             (*(volatile uint32_t *)(UART_BASE_ADDR(x) + 0x30))
#define REG_UART_IFLS(x) 	             (*(volatile uint32_t *)(UART_BASE_ADDR(x) + 0x34))
#define REG_UART_IMSC(x) 	             (*(volatile uint32_t *)(UART_BASE_ADDR(x) + 0x38))
#define REG_UART_RIS(x)  	             (*(volatile uint32_t *)(UART_BASE_ADDR(x) + 0x3C))
#define REG_UART_MIS(x)  	             (*(volatile uint32_t *)(UART_BASE_ADDR(x) + 0x40))
#define REG_UART_ICR(x)  	             (*(volatile uint32_t *)(UART_BASE_ADDR(x) + 0x44))

///*----------------------TIMER------------------------*/
#define TIMER0		                      0
#define TIMER1		                      1
#define TIMER2		                      2
#define TIMER3		                      3
#define TIMER_BASE_ADDR		              0x48030000
#define REG_TIMER_ARR(x)                 (*(volatile UINT32 *)(TIMER_BASE_ADDR + 0x14 * (x)))
#define REG_TIMER_CNT(x)                 (*(volatile UINT32 *)(TIMER_BASE_ADDR + 0x14 * (x) + 4))
#define REG_TIMER_CR(x)                  (*(volatile UINT32 *)(TIMER_BASE_ADDR + 0x14 * (x) + 8))
#define REG_TIMER_IF(x)                  (*(volatile UINT32 *)(TIMER_BASE_ADDR + 0x14 * (x) + 12))
#define REG_TIMER_CIF(x)                 (*(volatile UINT32 *)(TIMER_BASE_ADDR + 0x14 * (x) + 16))
#define REG_TIMER_PSC                    (*(volatile UINT32 *)(TIMER_BASE_ADDR + 0x50))
#define REG_TIMER_ICMODE                 (*(volatile UINT32 *)(TIMER_BASE_ADDR + 0x54))
#define REG_TIMER_CCR                    (*(volatile UINT32 *)(TIMER_BASE_ADDR + 0x58))
#define REG_TIMER_CCIF                   (*(volatile UINT32 *)(TIMER_BASE_ADDR + 0x5C))
#define REG_TIMER_C0_CR                  (*(volatile UINT32 *)(TIMER_BASE_ADDR + 0x60))
#define REG_TIMER_C2_CR                  (*(volatile UINT32 *)(TIMER_BASE_ADDR + 0x64))	
#define REG_TIMER_PCR                    (*(volatile UINT32 *)(TIMER_BASE_ADDR + 0x68))
#define REG_TIMER_CPIF                   (*(volatile UINT32 *)(TIMER_BASE_ADDR + 0x6C))
#define REG_TIMER_CX_PR(x)               (*(volatile UINT32 *)(TIMER_BASE_ADDR + 0x70 + 4 * (x)))

///*---------------------WDT------------------------*/
#define WDT_BASE_ADDR                    0x48040000
#define REG_WDT_LOAD                     (*(volatile uint32_t *)(WDT_BASE_ADDR + 0x0))
#define REG_WDT_CNT                      (*(volatile uint32_t *)(WDT_BASE_ADDR + 0x04))
#define REG_WDT_CTRL                     (*(volatile uint32_t *)(WDT_BASE_ADDR + 0x08))
#define REG_WDT_FEED                     (*(volatile uint32_t *)(WDT_BASE_ADDR + 0x0C))
#define REG_WDT_INT_CLR_TIME             (*(volatile uint32_t *)(WDT_BASE_ADDR + 0x10))
#define REG_WDT_RIS                      (*(volatile uint32_t *)(WDT_BASE_ADDR + 0x14))


///*----------------------SCU------------------------*/
#define SCU_BASE_ADDR	                 0x48060000
#define REG_SCU_CTRLA                    (*(volatile uint32_t *)(SCU_BASE_ADDR + 0x00))
#define REG_SCU_CTRLB					 (*(volatile uint32_t *)(SCU_BASE_ADDR + 0x04))
#define REG_SCU_CLKDIV		             (*(volatile uint32_t *)(SCU_BASE_ADDR + 0x08))
#define REG_SCU_PLLCSR                   (*(volatile uint32_t *)(SCU_BASE_ADDR + 0x0C))
#define REG_SCU_RESETCTRLA		   		 (*(volatile uint32_t *)(SCU_BASE_ADDR + 0x10))
#define REG_SCU_RESETCTRLB   			 (*(volatile uint32_t *)(SCU_BASE_ADDR + 0x14))
#define REG_SCU_ANALOGCSR   			 (*(volatile uint32_t *)(SCU_BASE_ADDR + 0x18))
#define REG_SCU_BUZZERCTRL               (*(volatile uint32_t *)(SCU_BASE_ADDR + 0x1C))
#define REG_SCU_SYSREMAPCTRL             (*(volatile uint32_t *)(SCU_BASE_ADDR + 0x20))
#define REG_SCU_WAKEUPCTRL               (*(volatile uint32_t *)(SCU_BASE_ADDR + 0x24))
#define REG_SCU_MUXCTRL(x)				 (*(volatile uint32_t *)(SCU_BASE_ADDR + 0x2C + ((x) << 2)))
#define REG_SCU_MUXCTRLA             	 (*(volatile uint32_t *)(SCU_BASE_ADDR + 0x2C))
#define REG_SCU_MUXCTRLB             	 (*(volatile uint32_t *)(SCU_BASE_ADDR + 0x30))
#define REG_SCU_MUXCTRLC             	 (*(volatile uint32_t *)(SCU_BASE_ADDR + 0x34))
#define REG_SCU_MUXCTRLD             	 (*(volatile uint32_t *)(SCU_BASE_ADDR + 0x38))
#define REG_SCU_PUCRA               	 (*(volatile uint32_t *)(SCU_BASE_ADDR + 0x40))
#define REG_SCU_PUCRB               	 (*(volatile uint32_t *)(SCU_BASE_ADDR + 0x44))
#define REG_SCU_SENSORRSTCTRL            (*(volatile uint32_t *)(SCU_BASE_ADDR + 0x48))
#define REG_SCU_SCICTRL                  (*(volatile uint32_t *)(SCU_BASE_ADDR + 0x54))
#define REG_SCU_USBPHYCSR	             (*(volatile uint32_t *)(SCU_BASE_ADDR + 0x58))
#define REG_SCU_SENSORRSTSTATUS          (*(volatile uint32_t *)(SCU_BASE_ADDR + 0x5C))
#define REG_SCU_ANACR                    (*(volatile uint32_t *)(SCU_BASE_ADDR + 0x60))

///*----------------------IIC------------------------*/
#define I2C_BASE_ADDR                    0x48070000
#define REG_I2C_CSR                      (*(volatile uint32_t *)(I2C_BASE_ADDR + 0x00))
#define REG_I2C_SLAVE_ADDR               (*(volatile uint32_t *)(I2C_BASE_ADDR + 0x04))
#define REG_I2C_CLK_DIV                  (*(volatile uint32_t *)(I2C_BASE_ADDR + 0x08))
#define REG_I2C_FIFO_CTRL                (*(volatile uint32_t *)(I2C_BASE_ADDR + 0x0c))
#define REG_I2C_INT_STAT                 (*(volatile uint32_t *)(I2C_BASE_ADDR + 0xffe0))
#define REG_I2C_INT_STAT_RAW             (*(volatile uint32_t *)(I2C_BASE_ADDR + 0xffe4))
#define REG_I2C_INT_EN                   (*(volatile uint32_t *)(I2C_BASE_ADDR + 0xffe8))
#define REG_I2C_INT_SET                  (*(volatile uint32_t *)(I2C_BASE_ADDR + 0xffec))
#define REG_I2C_INT_CLR                  (*(volatile uint32_t *)(I2C_BASE_ADDR + 0xfff0))
#define REG_I2C_FIFO                     (*(volatile uint8_t  *)(I2C_BASE_ADDR + 0x100))

///*----------------------7816MS------------------------*/
#define ISO7816MS_BASE_ADDR              0x48080000
#define REG_7816_ISR   	                 (*(volatile uint32_t *)(ISO7816MS_BASE_ADDR + 0x00))
#define REG_7816_IER   	                 (*(volatile uint32_t *)(ISO7816MS_BASE_ADDR + 0x04))
#define REG_7816_CTRL  	                 (*(volatile uint32_t *)(ISO7816MS_BASE_ADDR + 0x08))
#define REG_7816_MCTRL                   (*(volatile uint32_t *)(ISO7816MS_BASE_ADDR + 0x0c))
#define REG_7816_DR    	                 (*(volatile uint32_t *)(ISO7816MS_BASE_ADDR + 0x10))
#define REG_7816_RSTT  	                 (*(volatile uint32_t *)(ISO7816MS_BASE_ADDR + 0x14))
#define REG_7816_BPR   	                 (*(volatile uint32_t *)(ISO7816MS_BASE_ADDR + 0x18))
#define REG_7816_ETU   	                 (*(volatile uint32_t *)(ISO7816MS_BASE_ADDR + 0x1c))
#define REG_7816_EDC   	                 (*(volatile uint32_t *)(ISO7816MS_BASE_ADDR + 0x20))
#define REG_7816_CCKCNT                  (*(volatile uint32_t *)(ISO7816MS_BASE_ADDR + 0x24))


///*-----------------------Sensor----------------------*/
#define SENSOR_BASE_ADDR                 0x48090000
#define REG_SENSOR_SECR1                 (*(volatile UINT32 *)(SENSOR_BASE_ADDR + 0x00))
#define REG_SENSOR_SECR2                 (*(volatile UINT32 *)(SENSOR_BASE_ADDR + 0x04))
#define REG_SENSOR_EFDTH                 (*(volatile UINT32 *)(SENSOR_BASE_ADDR + 0x08))
//#define REG_SENSOR_IFDTH                 (*(volatile UINT32 *)(SENSOR_BASE_ADDR + 0x0C))
#define REG_SENSOR_SEINTEN               (*(volatile UINT32 *)(SENSOR_BASE_ADDR + 0x10))
#define REG_SENSOR_SESR                  (*(volatile UINT32 *)(SENSOR_BASE_ADDR + 0x14))
#define REG_SENSOR_FDCNTR                (*(volatile UINT32 *)(SENSOR_BASE_ADDR + 0x18))


///*----------------------GPIO------------------------*/
#define GPIOA                            0
#define GPIOB                            1
#define GPIO_BASE_ADDR(x)                (0x480a0000 + 0x10000 * (x))
#define REG_GPIO_DIR(x)                  (*(volatile uint32_t *)(GPIO_BASE_ADDR(x) + 0x00))
#define REG_GPIO_SET(x)                  (*(volatile uint32_t *)(GPIO_BASE_ADDR(x) + 0x08))
#define REG_GPIO_CLR(x)                  (*(volatile uint32_t *)(GPIO_BASE_ADDR(x) + 0x0C))
#define REG_GPIO_ODATA(x)                (*(volatile uint32_t *)(GPIO_BASE_ADDR(x) + 0x10))
#define REG_GPIO_IDATA(x)                (*(volatile uint32_t *)(GPIO_BASE_ADDR(x) + 0x14))
#define REG_GPIO_IEN(x)	                 (*(volatile uint32_t *)(GPIO_BASE_ADDR(x) + 0x18))
#define REG_GPIO_IS(x)                   (*(volatile uint32_t *)(GPIO_BASE_ADDR(x) + 0x1c))
#define REG_GPIO_IBE(x)                  (*(volatile uint32_t *)(GPIO_BASE_ADDR(x) + 0x20))
#define REG_GPIO_IEV(x)                  (*(volatile uint32_t *)(GPIO_BASE_ADDR(x) + 0x24))
#define REG_GPIO_IC(x)                   (*(volatile uint32_t *)(GPIO_BASE_ADDR(x) + 0x28))
#define REG_GPIO_RIS(x)                  (*(volatile uint32_t *)(GPIO_BASE_ADDR(x) + 0x2c))
#define REG_GPIO_MIS(x)                  (*(volatile uint32_t *)(GPIO_BASE_ADDR(x) + 0x30))


///*----------------------MIM------------------------*/
#define MIM_BASE_ADDR                    0x62000000
#define REG_MIM_CSCR0	                 (*(volatile uint32_t *)(MIM_BASE_ADDR + 0x00))
#define REG_MIM_CSCR1	                 (*(volatile uint32_t *)(MIM_BASE_ADDR + 0x04))
#define REG_MIM_CSCR2	                 (*(volatile uint32_t *)(MIM_BASE_ADDR + 0x08))
#define REG_MIM_CSCR3	                 (*(volatile uint32_t *)(MIM_BASE_ADDR + 0x0C))
#define REG_MIM_TFTS	                 (*(volatile uint32_t *)(MIM_BASE_ADDR + 0x10))
#define REG_MIM_CMD		                 (*(volatile uint32_t *)(MIM_BASE_ADDR + 0x14))
#define REG_MIM_DATA	                 (*(volatile uint32_t *)(MIM_BASE_ADDR + 0x18))
#define REG_MIM_SEG0	                 (*(volatile uint32_t *)(MIM_BASE_ADDR + 0x1c))
#define REG_MIM_SEG1	                 (*(volatile uint32_t *)(MIM_BASE_ADDR + 0x20))
#define REG_MIM_SEG2	                 (*(volatile uint32_t *)(MIM_BASE_ADDR + 0x24))
#define REG_MIM_SEG3	                 (*(volatile uint32_t *)(MIM_BASE_ADDR + 0x28))

#define EMEM0                            0
#define EMEM1                            1
#define EMEM2                            2
#define EMEM3                            3
#define MIM_MEM_ADDR(x)                  (0x60000000 + 0x7ffffff * (x))

#ifdef __cplusplus
}
#endif

#endif  /* ARMCM3_H */


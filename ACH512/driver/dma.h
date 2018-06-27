/***********************************************************************
 * Copyright (c)  2008 - 2016, Shanghai AisinoChip Co.,Ltd .
 * All rights reserved.
 * Filename    : dma.h
 * Description : dma driver header file
 * Author(s)   : Eric
 * version     : V1.0
 * Modify date : 2016-03-24
 ***********************************************************************/
#ifndef __DMA_H__
#define __DMA_H__

#include  "common.h"

//#define DMA_INT
#define DMA_NUMBER               4

/*----------------------DMA BIT------------------------*/
#define TRICOUNT                (1<<31)
#define DEST_INC                (1<<27)
#define SRC_INC		    		(1<<26)
#define WIDTH_8BIT      		0
#define WIDTH_16BIT   			1
#define WIDTH_32BIT      		2
#define DEST_WIDTH(x)  			(x<<21)
#define SRC_WIDTH(x)     		(x<<18)
#define BURST_1                 0x00
#define BURST_4                 0x01
#define BURST_8                 0x02
#define BURST_16			    0x03
#define BURST_32			    0x04
#define BURST_64			    0x05
#define BURST_128			    0x06
#define BURST_256			    0x07
#define DEST_BURST_SIZE(x)      (x<<15)
#define SRC_BURST_SIZE(x)       (x<<12)

#define DMACC_ITC               (1<<15)
#define MEM_TO_MEM			    0
#define MEM_TO_PER    			1
#define PER_TO_MEM   			2
#define PER_TO_PER   			3
#define TRANS_TYPE(x)           (x<<11)
#define REQ_ADC_FROHALF         0
#define REQ_ADC_BEHALF          1
#define REQ_SDIO_WRITE          2
#define REQ_SDIO_READ           3
#define REQ_SPIA_TX             4
#define REQ_SPIA_RX             5
#define REQ_SPIB_TX             6
#define REQ_SPIB_RX             7
#define DEST_PREIPH(x)          (x<<6)
#define SRC_PREIPH(x)           (x<<1)
#define START_DMA               (1<<0)


extern volatile UINT8 flag_dma_end_int[DMA_NUMBER];
extern volatile UINT8 flag_dma_err_int[DMA_NUMBER];

/************************************************************************
 * function   : dma_init
 * Description: dma initial
 * input : none
 * return: none
 ************************************************************************/
void dma_init(void);

/************************************************************************
 * function   : dma_transfer
 * Description: dma transfer data
 * input :
 *         UINT8 channel_index: DMA channel index , 0/1/2/3
 *         UINT32 dest_addr: destination address
 *         UINT32 src_addr: source address
 *  	   UINT32 length: data length, unit is byte
 * return: none
 ************************************************************************/
void dma_transfer(UINT8 channel_index, UINT32 dest_addr, UINT32 src_addr, UINT32 length);


#endif

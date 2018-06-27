/***********************************************************************
 * Copyright (c)  2008 - 2016, Shanghai AisinoChip Co.,Ltd .
 * All rights reserved.
 * Filename    : dma.c
 * Description : dma driver source file
 * Author(s)   : Eric
 * version     : V1.0
 * Modify date : 2016-03-24
 ***********************************************************************/
#include  "dma.h"

volatile UINT8 flag_dma_end_int[DMA_NUMBER] = { 0 };
volatile UINT8 flag_dma_err_int[DMA_NUMBER] = { 0 };

void DMA_IRQHandler(void)
{
	UINT8 i;
	for(i = 0; i < DMA_NUMBER; i++)
	{
		if(REG_DMAC_IntStatus & (0x01 << i))  //channel
		{
			if(REG_DMAC_IntTCStatus & (0x01 << i))
			{
				REG_DMAC_IntTCClr |= 0x01 << i;
				flag_dma_end_int[i] = 1;
			}
			if(REG_DMAC_IntErrStatus & (0x01 << i))
			{
				REG_DMAC_IntErrClr |= 0x01 << i;
				flag_dma_err_int[i] = 1;
			}
		}
	}
}

/************************************************************************
 * function   : dma_init
 * Description: dma initial
 * input : none
 * return: none
 ************************************************************************/
void dma_init(void)
{

#ifdef LOW_POWER
    enable_module(BIT_DMAC); //enable DMA
#endif
    //ÖÐ¶ÏÅäÖÃ
	NVIC_ClearPendingIRQ(DMA_IRQn);
	NVIC_EnableIRQ(DMA_IRQn);

	REG_DMAC_Config = 0x01; //enable DMAC
	REG_DMAC_Sync = 0x01;          //enable synchronize request

}
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
void dma_transfer(UINT8 channel_index, UINT32 dest_addr, UINT32 src_addr, UINT32 length)
{
	REG_DMAC_ChDestAddr(channel_index) = dest_addr;
	REG_DMAC_ChSrcAddr(channel_index) = src_addr;
	REG_DMAC_ChCtrl(channel_index) = 0x80000000 | DEST_INC | SRC_INC |
			DEST_WIDTH(WIDTH_32BIT) | SRC_WIDTH(WIDTH_32BIT) | DEST_BURST_SIZE(BURST_8) | SRC_BURST_SIZE(BURST_8) | (length >> WIDTH_32BIT);
#ifdef DMA_INT
	REG_DMAC_ChConfig(channel_index) =  DMACC_ITC | TRANS_TYPE(MEM_TO_MEM) | START_DMA;
	while(!(flag_dma_end_int[channel_index]));
	flag_dma_end_int[channel_index] = 0;
#else
	REG_DMAC_ChConfig(channel_index) =   TRANS_TYPE(MEM_TO_MEM) | START_DMA;
	while(!(REG_DMAC_RawIntTCStatus & (0x01 << channel_index)));
	REG_DMAC_IntTCClr = 0x01;
#endif
}

/***********************************************************************
 * Copyright (c)  2008 - 2016, Shanghai AisinoChip Co.,Ltd .
 * All rights reserved.
 * Filename    : spi.c
 * Description : spi driver source file
 * Author(s)   : Eric
 * version     : V1.0
 * Modify date : 2016-03-24
 ***********************************************************************/
#include "spi.h"
#include "dma.h"

volatile UINT8 flag_spia_batchdone_int;
volatile UINT8 flag_spib_batchdone_int;

void SPIA_IRQHandler(void)
{
    if(REG_SPI_STATUS(SPIA) & 0x02) //check batch_done flag
    {
        flag_spia_batchdone_int = 1;
        REG_SPI_STATUS(SPIA) |= 0x02; //clear batch_done flag
    }
}

void SPIB_IRQHandler(void)
{
    if(REG_SPI_STATUS(SPIB) & 0x02) //check batch_done flag
    {
        flag_spib_batchdone_int = 1;
        REG_SPI_STATUS(SPIB) |= 0x02; //clear batch_done flag
    }
}

/************************************************************************
 * function   : spi_init
 * Description: spi initial
 * input :
 *         UINT8 spi_index: select spi number     SPIA,SPIB
 *         UINT8 work_mode: select spi work mode  0,1,2,3
 * return: none
 ************************************************************************/
void spi_init(UINT8 spi_index, UINT8 work_mode)
{
    if(spi_index == SPIA)
    {
        NVIC_ClearPendingIRQ(SPIA_IRQn);
        NVIC_EnableIRQ(SPIA_IRQn);
        REG_SCU_MUXCTRLA = (REG_SCU_MUXCTRLA & ~(0xfff << 4)) | (0x555 << 4); //复用为SPIA
    }
    else
    {
        NVIC_ClearPendingIRQ(SPIB_IRQn);
        NVIC_EnableIRQ(SPIB_IRQn);
        REG_SCU_MUXCTRLA = (REG_SCU_MUXCTRLA & ~(0x0fUL << 28)) | (0x05 << 28);
        REG_SCU_MUXCTRLB = (REG_SCU_MUXCTRLB & ~(0xff << 0)) | (0x55 << 0); //复用为SPIB   		      
    }

    REG_SPI_CTL(spi_index) = work_mode << 2;

#ifdef SPI_MASTER
    REG_SPI_BAUD(spi_index) = ((3 << 8) | 6); 

    REG_SPI_OUT_EN(spi_index) = 0x01; //默认单线模式
    REG_SPI_CTL(spi_index) |= 0x01; //设置主机模式
#else
    REG_SPI_OUT_EN(spi_index) = 0x02; //默认单线模式
    REG_SPI_CTL(spi_index) &= ~0x01; //设置从机模式
#endif
}

void chip_disable(UINT8 spi_index)
{
    REG_SPI_CS(spi_index) = 0;
}
void chip_enable(UINT8 spi_index)
{
    REG_SPI_CS(spi_index) = 1;
}

/************************************************************************
 * function   : spi_rx_bytes
 * Description: spi receive data by general mode
 * input :
 *         UINT8 spi_index: select spi number    SPIA,SPIB
 *         UINT8* rx_data: pointer to receive data buffer
 *         UINT32 len: length of bytes to receive
 * return: none
 ************************************************************************/
void spi_rx_bytes(UINT8 spi_index, UINT8 *rx_data, UINT32 len)
{
    UINT32 i;
    len &= 0x3ff;

    REG_SPI_STATUS(spi_index) |= 0x01 << 1; //clear batch_done flag
    REG_SPI_BATCH(spi_index) = len;

    REG_SPI_RX_CTL(spi_index) |= 0x01; //rx work is enable

#ifdef SPI_MASTER
    REG_SPI_CS(spi_index) = 1;
#endif

    for(i = 0; i < len; i++)
    {
        while(REG_SPI_STATUS(spi_index) & 0x10); //wait rx fifo not empty:RX_FIFO_EMPTY
        *rx_data = (UINT8)REG_SPI_RX_DAT(spi_index);
        rx_data++;
    }

    while(!(REG_SPI_STATUS(spi_index) & 0x02)); //batch done
    REG_SPI_STATUS(spi_index) |= 0x02;

    REG_SPI_RX_CTL(spi_index) &= ~0x01; //close rx work
}
/************************************************************************
 * function   : spi_tx_bytes
 * Description: spi send data by general mode
 * input :
 *         UINT8 spi_index: spi number    SPIA,SPIB
 *         UINT8* tx_data: pointer to send data buffer
 *         UINT32 len: length of bytes to send
 * return: none
 ************************************************************************/
void spi_tx_bytes(UINT8 spi_index, UINT8 *tx_data, UINT32 len)
{
    UINT32 i;

    len &= 0x3ff;

    REG_SPI_STATUS(spi_index) |= 0x02; //clear batch_done flag
    REG_SPI_BATCH(spi_index) = len;

    REG_SPI_TX_CTL(spi_index) |= 0x01; //tx work is enable
#ifdef SPI_MASTER
    REG_SPI_CS(spi_index) = 1;
#endif

    for(i = 0; i < len; i++)
    {
        while(REG_SPI_STATUS(spi_index) & 0x08); //wait tx fifo not full:TX_FIFO_FULL
        REG_SPI_TX_DAT(spi_index) = *tx_data;
        tx_data++;
    }

    while(!(REG_SPI_STATUS(spi_index) & 0x02)); //Batch_DONE
    REG_SPI_STATUS(spi_index) |= 0x02;

    REG_SPI_TX_CTL(spi_index) &= ~0x01; //close tx work
}

/************************************************************************
 * function   : spi_txrx_bytes
 * Description: spi send data by general mode
 * input :
 *         UINT8 spi_index: spi number    SPIA,SPIB
 *         UINT8* tx_data: pointer to send data buffer
 *         UINT8* rx_data: pointer to receive data buffer
 *         UINT32 len: length of bytes
 * return: none
 ************************************************************************/
void spi_txrx_bytes(UINT8 spi_index, UINT8 *tx_data, UINT8 *rx_data, UINT32 len)
{
    UINT32 i = 0;

    REG_SPI_STATUS(spi_index) |= 0x02; //Batch_DONE
    REG_SPI_BATCH(spi_index) = len;

    REG_SPI_TX_CTL(spi_index) |= 0x01; //tx work is enable
    REG_SPI_RX_CTL(spi_index) |= 0x01; //rx work is enable

#ifdef SPI_MASTER
    REG_SPI_CS(spi_index) = 1;
#endif

    while(!(REG_SPI_STATUS(spi_index) & 0x02)) //Batch_DONE
    {
        if(i < len)
        {
            if(!(REG_SPI_STATUS(spi_index) & 0x08)) //wait tx fifo not full:TX_FIFO_FULL
            {
                REG_SPI_TX_DAT(spi_index) = *tx_data;
                tx_data++;
                i++;
            }
        }

        if(!(REG_SPI_STATUS(spi_index) & 0x10)) //wait rx fifo not empty:RX_FIFO_EMPTY
        {
            *rx_data = (UINT8)REG_SPI_RX_DAT(spi_index);
            rx_data++;

        }
    }

    while(!(REG_SPI_STATUS(spi_index) & 0x10)) //wait rx fifo not empty:RX_FIFO_EMPTY
    {
        *rx_data = (UINT8)REG_SPI_RX_DAT(spi_index);
        rx_data++;
    }

    REG_SPI_STATUS(spi_index) |= 0x02;

    REG_SPI_TX_CTL(spi_index) &= ~0x01;
    REG_SPI_RX_CTL(spi_index) &= ~0x01;

}
/************************************************************************
 * function   : spi_tx_bytes
 * Description: spi send data by dma mode
 * input : 
 *         UINT8 spi_index: spi number    SPIA,SPIB
 *         UINT8* tx_data: pointer to send data buffer
 *         UINT32 len: length of bytes to send
 * return: none
 ************************************************************************/
void spi_tx_bytes_dma(UINT8 spi_index, UINT8 *tx_data, UINT32 len)
{
    len &= 0x1ff;

//SPI config
    REG_SPI_STATUS(spi_index) |= 0x02; //clear batch_done flag
    REG_SPI_BATCH(spi_index) = len;
    REG_SPI_TX_CTL(spi_index) |= 8 << 4 | 1 << 3; //tx_dma_level =8 ,enable dma_req
    REG_SPI_TX_CTL(spi_index) |= 0x01; //tx work is enable
//DMA config
    REG_DMAC_Config = 0x01; //enable DMA
    REG_DMAC_Sync = 0x01;          //enable synchronize request

    REG_DMAC_ChSrcAddr(DMACH0) =  (UINT32)tx_data;
    REG_DMAC_ChDestAddr(DMACH0) = SPI_BASE_ADDR(spi_index);
    REG_DMAC_ChCtrl(DMACH0) = 0x80000000 |  SRC_INC |
            DEST_WIDTH(WIDTH_8BIT) | SRC_WIDTH(WIDTH_8BIT) | DEST_BURST_SIZE(BURST_8) | SRC_BURST_SIZE(BURST_8) | (len >> WIDTH_8BIT);
    if (spi_index == SPIA)
    {
        REG_DMAC_ChConfig(DMACH0) =   TRANS_TYPE(MEM_TO_PER) | DEST_PREIPH(REQ_SPIA_TX) | START_DMA;
    }
    else
    {
        REG_DMAC_ChConfig(DMACH0) =   TRANS_TYPE(MEM_TO_PER) | DEST_PREIPH(REQ_SPIB_TX) | START_DMA;
    }
#ifdef SPI_MASTER
    chip_enable(spi_index);
#endif
    while (!(REG_SPI_STATUS(spi_index) & 0x02)); //check spi_batch done
    REG_SPI_STATUS(spi_index) |= 0x02;

    while (!(REG_DMAC_RawIntTCStatus & (0x01 << DMACH0))); //check dma done
    REG_DMAC_IntTCClr |= 0x01 << DMACH0;

    REG_SPI_TX_CTL(spi_index) &= ~0x01; //close tx work
    REG_DMAC_ChConfig(DMACH0) &= ~START_DMA; //close dma
}
/************************************************************************
 * function   : spi_rx_bytes
 * Description: spi receive data by dma mode
 * input : 
 *         UINT8 spi_index: select spi number    SPIA,SPIB
 *         UINT8* rx_data: pointer to receive data buffer
 *         UINT32 len: length of bytes to receive
 * return: none
 ************************************************************************/
void spi_rx_bytes_dma(UINT8 spi_index, UINT8 *rx_data, UINT32 len)
{
    len &= 0x1ff;

//SPI config
    REG_SPI_STATUS(spi_index) |= 0x02; //clear batch_done flag
    REG_SPI_BATCH(spi_index) = len;

    REG_SPI_RX_CTL(spi_index) |= 1 << 4 | 1 << 3; //rx_dma_level =1 ,enable dma_req
    REG_SPI_RX_CTL(spi_index) |= 0x01; //rx work is enable

//DMA config
    REG_DMAC_Config = 0x01; //enable DMA
    REG_DMAC_Sync = 0x01;          //enable synchronize request

    REG_DMAC_ChSrcAddr(DMACH1) =  SPI_BASE_ADDR(spi_index);
    REG_DMAC_ChDestAddr(DMACH1) = (UINT32)rx_data;
    REG_DMAC_ChCtrl(DMACH1) = 0x80000000 | DEST_INC |
            DEST_WIDTH(WIDTH_8BIT) | SRC_WIDTH(WIDTH_8BIT) | DEST_BURST_SIZE(BURST_1) | SRC_BURST_SIZE(BURST_1) | (len >> WIDTH_8BIT);
    if (spi_index == SPIA)
    {
        REG_DMAC_ChConfig(DMACH1) =   TRANS_TYPE(PER_TO_MEM) | SRC_PREIPH(REQ_SPIA_RX) | START_DMA;
    }
    else
    {
        REG_DMAC_ChConfig(DMACH1) =   TRANS_TYPE(MEM_TO_PER) | SRC_PREIPH(REQ_SPIB_RX) | START_DMA;
    }
#ifdef SPI_MASTER
    chip_enable(spi_index);
#endif
    while (!(REG_SPI_STATUS(spi_index) & 0x02)); //check spi_batch done
    REG_SPI_STATUS(spi_index) |= 0x02;

    while (!(REG_DMAC_RawIntTCStatus & (0x01 << DMACH1))); //check dma done
    REG_DMAC_IntTCClr |= 0x01 << DMACH1;

    REG_SPI_RX_CTL(spi_index) &= ~0x01; //close rx work
    REG_DMAC_ChConfig(DMACH1) &= ~START_DMA; //close dma
}

#ifndef _HRNG_H__
#define _HRNG_H__

#include "common.h"


/*********************************************************************************
* Function Name  : hrng_initial
* Description    : config hrng module
* Input          : - ctrl   : input ctrl reg data;
				 : - cmpres : input cmpres reg data;
* Output         : None
* Return         : None
*********************************************************************************/
void hrng_initial(void);
/*********************************************************************************
* Function Name  : hrng_source_disable
* Description    : disable hrng source 
* Input          : - ctrl   : input ctrl reg data;
				 : - cmpres : input cmpres reg data;
* Output         : None
* Return         : None
*********************************************************************************/
void hrng_source_disable(void);
/*********************************************************************************
* Function Name  : get_hrng8
* Description    : get 8bit random number
* Input          : None
* Output         : None
* Return         : 8 bit random number
*********************************************************************************/
UINT8 get_hrng8(void);

/*********************************************************************************
* Function Name  : get_hrng32
* Description    : get 32bit random number
* Input          : None
* Output         : None
* Return         : 32 bit random number
*********************************************************************************/
UINT32 get_hrng32(void);

/*********************************************************************************
* Function Name  : get_hrng
* Description    : get random number
* Input          : byte_len :  the byte length of random number
* Output         : *hdata   :  the start address of random number the size must be 16bytes
* Return         : 0: hrng data is ok; 1: hrng data is bad
*********************************************************************************/
UINT8 get_hrng(UINT8 *hdata, UINT32 byte_len);

#endif




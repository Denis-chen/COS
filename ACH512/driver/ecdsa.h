/***********************************************************************
 * Copyright (c)  2008 - 2016, Shanghai AisinoChip Co.,Ltd .
 * All rights reserved.
 * Filename    : ecdsa.h
 * Description : esdsa header file
 * Author(s)   : Eric  
 * version     : V1.0
 * Modify date : 2016-03-24
 ***********************************************************************/
#include "ecc.h"
#include "rsa_keygen.h"

#ifndef _ECDSA_H
#define _ECDSA_H

//Signature and Verification
/******************************************************************************
* Function Name  : ECDSA_keypair
* Description    : generate ECC private and public key
	               Step 1. Generate PrivateKey - k
	               Step 2. Caculate PublicKey  - kG
Note: the length of PrivateKey , PublicKeyX , PrivateKeyY should be no less than CurveLength
* Input          : - *p_ecc_para        : the struct of ecc curve parameter point

* Output         : - PrivateKey[]       : used to store the generated private key
				         : - PublicKeyX[]       : used to store the x coordination of generated public key
				         : - PublicKeyY[]       : used to store the y coordination of generated public key
* Return         : 0:success; 1:fail
******************************************************************************/
UINT8 ECDSA_keypair(ECC_G_STR *p_ecc_para,UINT32 PrivateKey[],UINT32 PublicKeyX[],UINT32 PublicKeyY[]);

/******************************************************************************
* Function Name  : ECDSA_sign
* Description    : generate the ECC signature
	               hashdata is hash value of given message
	               Step 1. Generate random k (k<P)
	               Step 2. Signature0 = kG.x mod P
	               Step 3. Signature1 = k^-1 * (hashdata + PrivateKey * Signature0) mod P
Note: the length of input and output parameters should be no less than CurveLength
* Input          : - *p_ecc_para        : the struct of ecc curve parameter point
				 : - *p_math_str        : the struct of global variable of math.c
				 : - *hashdata          : start address of hashdata
				 : - *PrivateKey        : start address of PrivateKey

* Output         : - *Signature0        : start address of signature r
				 : - *Signature1        : store address of signature s
* Return         : 0:successful 1:failure
******************************************************************************/
UINT8 ECDSA_sign(ECC_G_STR *p_ecc_para,MATH_G_STR *p_math_str,UINT32 *hashdata,UINT32 *PrivateKey,UINT32 *Signature0,UINT32 *Signature1);

/******************************************************************************
* Function Name  : ECDSA_verify
* Description    : verify the ECC signature
	               hashdata is hash value of message to be verified
			   	   Step 1. Check signature's range
			       Step 2. u1 = Signature1^-1 * hashdata mod P
			       Step 3. u2 = Signature1^-1 * Signature0 mod P
			       Step 4. P1 = u1*G, P2 = u2 * (PublicKeyX,PublicKeyY)
			       Step 5. P = P1 + P2 , if P is infinite point , return 0
			       Step 6. if P.x mod P = Signature0 ,return 1
Note: the length of input and output parameters should be no less than CurveLength
* Input          : - *p_ecc_para        : the struct of ecc curve parameter point
				 : - *p_math_str        : the struct of global variable of math.c
				 : - *hashdata          : start address of hashdata
				 : - *PublicKeyX        : start address of PublicKeyX
				 : - *PublicKeyY        : start address of PublicKeyY
				 : - *Signature0        : start address of signature r
				 : - *Signature1        : store address of signature s

* Output         : NONE
* Return         : 0:successful 1:failure
******************************************************************************/
int ECDSA_verify(ECC_G_STR *p_ecc_para,MATH_G_STR *p_math_str,UINT32 *hashdata,UINT32 *PublicKeyX,UINT32 *PublicKeyY,UINT32 *Signature0,UINT32 *Signature1);

UINT32 CalLength_B(UINT32 *B,UINT32 curve_len );
void Updatek(ECC_G_STR *p_ecc_para,UINT32 *k);


#endif

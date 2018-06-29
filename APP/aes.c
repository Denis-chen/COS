#include "aes.h"
#include "sha2.h"

UINT32 aes_ecb_crypt(UINT8 *password, UINT8 *data, UINT32 mne_len, UINT8 *result){
	UINT32 ret;
	UINT32 mode;
	UINT32 blk_len;
	__align(4) UINT8 iv_ecb[32];
	if(mne_len%16 != 0){
		blk_len = mne_len/16+1;
	}else{
		blk_len = mne_len/16;
	}
	mode = AES_SECURITY_MODE;
	aes_set_key((UINT32 *)password, AES_KEY_256, AES_SWAP_ENABLE);
	ret = aes_crypt((UINT32 *)data, (UINT32 *)result, blk_len, AES_ENCRYPTION, AES_ECB_MODE, (UINT32 *)iv_ecb, mode);
	return ret;
}

UINT32 aes_ecb_uncrypt(UINT8 *password, UINT8 *data, UINT32 mne_len, UINT8 *result){
	UINT32 ret;
	UINT32 mode;
	UINT32 blk_len;
	__align(4) UINT8 iv_ecb[32];
	if(mne_len%16 != 0){
		blk_len = mne_len/16+1;
	}else{
		blk_len = mne_len/16;
	}
	mode = AES_SECURITY_MODE;
	aes_set_key((UINT32 *)password, AES_KEY_256, AES_SWAP_ENABLE);
	ret = aes_crypt((UINT32 *)data, (UINT32 *)result, blk_len, AES_DECRYPTION, AES_ECB_MODE, (UINT32 *)iv_ecb, mode);
	return ret;
}
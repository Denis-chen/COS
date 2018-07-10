/***********************************************************************
 * Copyright (c)  2008 - 2016, Shanghai AisinoChip Co.,Ltd .
 * All rights reserved.
 * Filename    : app.c
 * Description : app source file
 * Author(s)   : Eric  
 * version     : V1.0
 * Modify date : 2016-03-24
 ***********************************************************************/
#include "common.h"
#include "app.h"
#include "hrng.h"
#include "uart.h"
#include "hmac_sha2.h"
#include "wally_bip32.h"
#include "wally_bip39.h"
#include "wally_crypto.h"
#include "hex.h"
#include <string.h>
#include "internal.h"
#include "eflash.h"
#include "spi.h"
#include "basic-config.h"
#include "ed25519.h"

extern volatile UINT8 rx_flag;
extern volatile UINT8 uart_rx_buf[32];
UINT8 spi_ready = 0;
UINT8 spi_data_buf[BUFF_LEN];
message_t rx_message;
message_t tx_message;
char *MNEMONIC = "amazing crew job journey drop country subject melody false layer output elite task wrap dish elite example mixed group body aerobic since custom cash";
void wallet_response(UINT8 cmd, UINT8 *data, UINT16 len, UINT8 resp);
UINT8 spi_read(void);
UINT8 spi_write(message_t message);

int endian_input(char *data, int index, UINT16 input){
	#ifdef BIG_ENDIAN
    data[index] = input & 0x00ff;
    data[index+1] = (input & 0xff00) >> 8;
	#else
    data[index] = input & 0xff00;
    data[index+1] = input & 0x00ff;
	#endif
    return 2;
}

int endian_output(char *data, int index, UINT16 *output){
	#ifdef BIG_ENDIAN
	*output = data[index] | data[index+1] << 8;
	#else
    *output = (data[index] << 8 ) | data[index+1];
	#endif
    return 2;
}

void wallet_entropy(){
	UINT32 i;
	UINT8 entropy[PRIV_KEY_BIT] = {0};
	hrng_initial();
	if(get_hrng(entropy, PRIV_KEY_BIT))
	{
		printfS("random number is error\r\n");
		return;
	}
	print_hexstr_key("entropy", entropy, PRIV_KEY_BIT);
	wallet_response(AT_S2M_GEN_WALLET_RSP, entropy, PRIV_KEY_BIT, RSP_OK);
}

static void eflash_write_page(UINT32 *buf, UINT32 pageAddr)
{
    UINT32 len = PAGE_SIZE >> 2;
    UINT32 loop;

    for(loop = 0; loop < len; loop++)
    {
        eflash_write_word(pageAddr + (loop << 2), buf[loop]);
    }
}

void AC_MemoryWrite(UINT8 *inData, UINT32 inLen, UINT32 dstAddr)
{
    UINT32 pageBuffer[PAGE_SIZE >> 2];
    UINT32 pageBaseAddr, nextPageBaseAddr;
    UINT32 tmpLen;

    pageBaseAddr = dstAddr & PAGE_ADDRESS_MASK;
    nextPageBaseAddr = pageBaseAddr + PAGE_SIZE;

    if(inLen > nextPageBaseAddr - dstAddr) //跨页
        tmpLen = nextPageBaseAddr - dstAddr;
    else
        tmpLen = inLen;

    memcpy((UINT8 *)pageBuffer, (UINT8 *)pageBaseAddr, PAGE_SIZE >> 2);
    eflash_erase_page(pageBaseAddr);
    memcpy((UINT8 *)pageBuffer + (dstAddr - pageBaseAddr), inData, tmpLen);
    eflash_write_page(pageBuffer, pageBaseAddr);

    if(tmpLen != inLen)
    {
        memcpy((UINT8 *)pageBuffer, (UINT8 *)nextPageBaseAddr, PAGE_SIZE >> 2);
        eflash_erase_page(nextPageBaseAddr);
        memcpy((UINT8 *)pageBuffer, inData + tmpLen, inLen - tmpLen);
        eflash_write_page(pageBuffer, nextPageBaseAddr);
    }
}


void get_mnemonic(UINT32 base_addr, UINT8 *value, UINT32 *data_len){
	UINT32 i, len, addr;
	addr = base_addr,
	len = eflash_read_word(addr);
	printf("get_mnemonic len = %d\r\n", len);
	*data_len = len;
	addr = addr + 4 + SHA256_DIGEST_SIZE;
	for(i = 0; i < len; i++){
		*value = eflash_read_byte(addr+i);
		value++;
	}
}

void get_pass_pharase(UINT32 base_addr, UINT8 *value){
	UINT32 i, addr;
	addr = base_addr,

	addr = addr + 4;
	for(i = 0; i < SHA256_DIGEST_SIZE; i++){
		*value = eflash_read_byte(addr+i);
		value++;
	}
}

int check_pass_pharase(char *pass_pharase, UINT8 *value){
	int ret, i;
	UINT8 digest[SHA256_DIGEST_SIZE];
	sha256(pass_pharase, strlen(pass_pharase), digest);
	get_pass_pharase(EFlashMainBaseAddr, value);
	for(i = 0; i < SHA256_DIGEST_SIZE; i++){
		if(digest[i] != *(value+i)){
			return WALLY_ERROR;
		}
	}
	return WALLY_OK;
}

void store_mnemonic(char *pass_pharase, UINT8 *mnemonic, UINT32 len){
	UINT32 i, addr, data_len;
	char *data;
	UINT8 digest[SHA256_DIGEST_SIZE];
	addr = EFlashMainBaseAddr;
	data_len = len + (16 - len % 16);
	data = wally_malloc(data_len);
	printf("store_mnemonic len = %d, pass_pharase = %s\r\n", len, pass_pharase);
	eflash_erase_page(addr);
	eflash_write_word(addr, data_len);
	addr = addr+4;
	sha256(pass_pharase, strlen(pass_pharase), digest);
	print_hexstr_key("store_mnemonic-digest", digest, sizeof(digest));
	for(i = 0; i < SHA256_DIGEST_SIZE; i++){
		AC_MemoryWrite(digest + i, 1, addr+i);
	}
	aes_ecb_crypt(digest, mnemonic, data_len, data);
	addr = addr+SHA256_DIGEST_SIZE;
	for(i = 0; i < data_len; i++){
		AC_MemoryWrite(data + i, 1, addr+i);
	}
	wally_clear(data, data_len);
	wally_free(data);
	printf("store_mnemonic ok!!!\r\n");
}

void wallet_password(char *pass_pharase, UINT8 state){
	int ret;
	UINT32 data_len;
	UINT8 digest[SHA256_DIGEST_SIZE];
	UINT8 crypt_data[DATA_LEN] = {0};
	UINT8 mnemonic[DATA_LEN] = {0};
	printf("pass_pharase = %s, state = %x\r\n", pass_pharase, state);
	if(state == RSP_CHECK_PD){
		ret = check_pass_pharase(pass_pharase, digest);
		if(ret == WALLY_OK){
			printf("check_pass_pharase ok\r\n");
			get_mnemonic(EFlashMainBaseAddr, crypt_data, &data_len);
			ret = aes_ecb_uncrypt(digest, crypt_data, data_len, mnemonic);
			printf("wallet_password mnemonic = %s, data_len = %d\r\n", mnemonic, data_len);
			wallet_response(AT_S2M_SET_PWD_RSP, NULL, 0, RSP_OK);
		}else{
			printf("check_pass_pharase fail\r\n");
			wallet_response(AT_S2M_SET_PWD_RSP, NULL, 0, RSP_ERROR_PD);
		}
	}else if(state == RSP_NEW_PD){
		store_mnemonic(pass_pharase, mnemonic, strlen((char *)mnemonic));
		wallet_response(AT_S2M_SET_PWD_RSP, NULL, 0, RSP_OK);
	}
}

void wallet_recover(char *pass_pharase, UINT8 *mnemonic, UINT32 len){
	store_mnemonic(pass_pharase, mnemonic, len);
	wallet_response(AT_S2M_RECOVER_WALLET_RSP, NULL, 0, RSP_OK);
}

void wallet_save(char *pass_pharase, UINT8 *mnemonic, UINT32 len){
	store_mnemonic(pass_pharase, mnemonic, len);
	wallet_response(AT_S2M_SAVE_MNEMONIC_RSP, NULL, 0, RSP_OK);
}

void wallet_delete(char *pass_pharase){
	UINT32 i, len, addr;
	addr = EFlashMainBaseAddr,
	len = eflash_read_word(addr);
	eflash_erase_page(addr);
	printf("delete_wallet len = %d\r\n", len);
	addr = addr+4;
	for(i = 0; i < len; i=i+4){
		eflash_erase_page(addr+i);	
	}
	wallet_response(AT_S2M_DEL_WALLET_RSP, NULL, 0, RSP_OK);
}

int get_mnemonic_number(char *pass_pharase, UINT32 base_addr, UINT8 *value, UINT16 number){
	int ret;
	char *ptr;
	UINT32 data_len;
	UINT16 index = 0;
	UINT8 mnemonic[DATA_LEN] = {0};
	UINT8 data[DATA_LEN] = {0};
	UINT8 digest[SHA256_DIGEST_SIZE];
	ret = check_pass_pharase(pass_pharase, digest);
	if(ret != WALLY_OK){
		return ret;
	}
	get_mnemonic(EFlashMainBaseAddr, data, &data_len);
	printf("get_mnemonic_number data_len = %d\r\n", data_len);
	ret = aes_ecb_uncrypt(digest, data, data_len, mnemonic);
	if(ret == 0){
		return WALLY_ERROR;
	}
	ptr = strtok(mnemonic, " ");
	do{
		index++;
		strcat(value, ptr);
		if(index != number){
			strcat(value, " ");
		}
		ptr = strtok(NULL, " ");
	}while (ptr != NULL && index < number);
	return WALLY_OK;
}

void child_path_split(char *in, uint32_t *out, size_t *outlen){
	char *ptr;
	char str[10] = {0};
	size_t len = 0;
	ptr = strtok(in, "/");
	while (ptr != NULL) {  
		ptr = strtok(NULL, "/");
		if(ptr != NULL){
			memset(str, 0, sizeof(str));
			if(strstr(ptr, "'")){
				strncpy(str, ptr, strlen(ptr) - 1);
				out[len] = (uint32_t)(BIP32_INITIAL_HARDENED_CHILD|atoi(str));
				printf("out[%d] = %x\r\n", len, out[len]);
			}else{
				strncpy(str, ptr, strlen(ptr));
				out[len] = (uint32_t)(atoi(str));
				printf("out[%d] = %x\r\n", len, out[len]);
			}
			len++;
		}
	}
	*outlen = len;
}

int derived(char *pass_pharase, char *key_path, UINT16 path_len, 
			UINT16 mne_number, UINT8 *serial, UINT16 serial_len, 
			struct ext_key *key_out){
	size_t seed_len;
	int ret;
	int i = 0;
	struct ext_key hdkey;
	uint32_t child_path[8] = {0};
	size_t child_path_len = 0;
	BYTE bSeed[BIP39_SEED_LEN_512] = {0};
	UINT8 mnemonic[DATA_LEN] = {0};
	printf("derived start !!!\r\n");
	ret = get_mnemonic_number(pass_pharase, EFlashMainBaseAddr, mnemonic, mne_number);
	if(ret != WALLY_OK){
		printf("pass_pharase error!!\r\n");
		return ret;
	}
	printf("mnemonic = %s, mne_number = %d\r\n", mnemonic, mne_number);
	bip39_mnemonic_to_seed(mnemonic, NULL, bSeed, sizeof(bSeed), &seed_len);
	print_hexstr_key("seed", bSeed, sizeof(bSeed));
	printf("key_path = %s\r\n", key_path);
	//wally_hex_to_bytes(SEED, bSeed, sizeof(bSeed), &seed_len);
	child_path_split(key_path, child_path, &child_path_len);
	ret = bip32_key_from_seed(bSeed, seed_len, BIP32_VER_MAIN_PRIVATE, BIP32_FLAG_KEY_PRIVATE, &hdkey);
	printf("bip32_key_from_seed -- ret = %d\r\n", ret);
	if(ret == WALLY_OK){
		//debug log
		#if USE_DEBUG
			printf("================================master=====================================\r\n");
			print_hexstr_key("prvkey", hdkey.priv_key, sizeof(hdkey.priv_key));
			print_hexstr_key("pubkey", hdkey.pub_key, sizeof(hdkey.pub_key));
			print_hexstr_key("chcode", hdkey.chain_code, sizeof(hdkey.chain_code));
			print_hexstr_key("has160", hdkey.hash160, sizeof(hdkey.hash160));
			printf("================================serialize=====================================\r\n");
			bip32_key_serialize(&hdkey, BIP32_FLAG_KEY_PRIVATE, serial, serial_len);
			print_hexstr_key("prvkey", serial, serial_len);
			bip32_key_serialize(&hdkey, BIP32_FLAG_KEY_PUBLIC, serial, serial_len);
			print_hexstr_key("pubkey", serial, serial_len);
		#endif
		if(child_path_len != 0){
			ret = bip32_key_from_parent_path(&hdkey, child_path, child_path_len, BIP32_FLAG_KEY_PRIVATE, key_out);
			printf("bip32_key_from_parent_path -- ret = %d\r\n", ret);
			if(ret == WALLY_OK){
				//debug log
				#if USE_DEBUG
					printf("================================child======================================\r\n");
					print_hexstr_key("prvkey", key_out->priv_key, sizeof(key_out->priv_key));
					print_hexstr_key("pubkey", key_out->pub_key, sizeof(key_out->priv_key));
					print_hexstr_key("chcode", key_out->chain_code, sizeof(key_out->priv_key));
					print_hexstr_key("has160", key_out->hash160, sizeof(key_out->priv_key));
					printf("================================serialize=====================================\r\n");
					bip32_key_serialize(key_out, BIP32_FLAG_KEY_PRIVATE, serial, serial_len);
					print_hexstr_key("prvkey", serial, serial_len);
				#endif
				bip32_key_serialize(key_out, BIP32_FLAG_KEY_PUBLIC, serial, serial_len);
				print_hexstr_key("pubkey", serial, serial_len);
			}
		}
	}
	return ret;
}
/**
*	签名交易
*	输出参数顺序
*	1,UINT16 pubkey_len
*	2,UINT16 signhash_len
*	3,char* pubkey
*	4,char* signhash
*/
int wallet_sign(char *pass_pharase, char *key_path, UINT16 path_len, 
				unsigned char *message, UINT16 len, 
				UINT16 mne_number){
	int ret; 
	int i = 0;
	UINT8 serial[BIP32_SERIALIZED_LEN] = {0};
	UINT8 sign_out[EC_SIGNATURE_LEN] = {0};
	UINT8 buff[NUM_LEN*2 + BIP32_SERIALIZED_LEN + EC_SIGNATURE_LEN] = {0};
	struct ext_key key_out;
	ret = derived(pass_pharase, key_path, path_len, mne_number, serial, BIP32_SERIALIZED_LEN, &key_out);
	if(ret == WALLY_OK){
		printf("keysign start !!!\r\n");
		ret = wally_ec_sig_from_bytes(key_out.priv_key+1, sizeof(key_out.priv_key)-1, message, len, EC_FLAG_ECDSA, sign_out, sizeof(sign_out));
		printf("keysign ret = %d\r\n", ret);
		if(ret == WALLY_OK){
			//debug log
			printf("================================keysign=====================================\r\n");
			print_hexstr_key("message", message, len);
			print_hexstr_key("signed", sign_out, sizeof(sign_out));
			i += endian_input(buff, i, BIP32_SERIALIZED_LEN);
			i += endian_input(buff, i, EC_SIGNATURE_LEN);
			
			memcpy(buff+i, serial, BIP32_SERIALIZED_LEN);
			memcpy(buff+i+BIP32_SERIALIZED_LEN, sign_out, EC_SIGNATURE_LEN);
			wallet_response(AT_S2M_SIGN_TRANX_RSP, buff, sizeof(buff), RSP_OK);
		}else{
			wallet_response(AT_S2M_SIGN_TRANX_RSP, NULL, 0, RSP_ERROR_SIGN);
		}
	}else {
		wallet_response(AT_S2M_SIGN_TRANX_RSP, NULL, 0, RSP_ERROR_PD);
	}
	return ret;
}

int wallet_verify(char *pass_pharase, char *key_path, UINT16 path_len, 
				unsigned char *message, UINT16 len, 
				UINT16 mne_number){
	int ret; 
	UINT8 serial[BIP32_SERIALIZED_LEN] = {0};
	UINT8 sign_out[EC_SIGNATURE_LEN] = {0};
	struct ext_key key_out;
	ret = derived(pass_pharase, key_path, path_len, mne_number, serial, BIP32_SERIALIZED_LEN, &key_out);
	if(ret == WALLY_OK){
		printf("keysign start !!!\r\n");
		ret = wally_ec_sig_from_bytes(key_out.priv_key+1, sizeof(key_out.priv_key)-1, message, len, EC_FLAG_ECDSA, sign_out, sizeof(sign_out));
		if(ret == WALLY_OK){
			//debug log
			printf("================================keysign=====================================\r\n");
			print_hexstr_key("message", message, len);
			print_hexstr_key("signed", sign_out, sizeof(sign_out));
			printf("================================keyverify===================================\r\n");
			ret = wally_ec_sig_verify(key_out.pub_key, sizeof(key_out.pub_key), message, len, EC_FLAG_ECDSA, sign_out, sizeof(sign_out));
			if(ret == WALLY_OK){
				printf("key verify ok!!!\r\n");
			}else{
				printf("key verify fail!!!\r\n");
			}
		}
	}
	return ret;
}
/**
*	获取某币种主公钥
*	输出参数顺序
*	1,UINT16 pubkey_len
*	2,char* pubkey
*/
void wallet_pubkey(char *pass_pharase, char *key_path, UINT16 path_len, UINT16 mne_number){
	int ret;
	int i = 0;
	struct ext_key key_out;
	UINT8 serial[BIP32_SERIALIZED_LEN] = {0};
	UINT8 buff[NUM_LEN + BIP32_SERIALIZED_LEN] = {0};
	ret = derived(pass_pharase, key_path, path_len, mne_number, serial, BIP32_SERIALIZED_LEN, &key_out);
	if(ret == WALLY_OK){
		i += endian_input(buff, i, BIP32_SERIALIZED_LEN);
		memcpy(buff+i, serial, BIP32_SERIALIZED_LEN);
		wallet_response(AT_S2M_GET_PUBKEY_RSP, buff, sizeof(buff), RSP_OK);
	}else{
		wallet_response(AT_S2M_GET_PUBKEY_RSP, NULL, 0, RSP_ERROR_PD);
	}
}

void boot_start(){
	return_to_boot();
	wallet_response(AT_M2S_RETURN_BOOT_RSP, NULL, 0, RSP_OK);
}

void wallet_response(UINT8 cmd, UINT8 *data, UINT16 len, UINT8 resp){
	memset(&tx_message, 0, sizeof(message_t));
	switch(cmd){
		case AT_S2M_GEN_WALLET_RSP:
			tx_message.header.id = cmd;
			tx_message.header.is_ready = IS_READY;
			tx_message.header.len = len;
			tx_message.response.state = resp;
			memcpy(tx_message.para, data, len);
			break;
		case AT_S2M_SET_PWD_RSP:
			tx_message.header.id = cmd;
			tx_message.header.is_ready = IS_READY;
			tx_message.header.len = len;
			tx_message.response.state = resp;
			break;
		case AT_S2M_SAVE_MNEMONIC_RSP:
			tx_message.header.id = cmd;
			tx_message.header.is_ready = IS_READY;
			tx_message.header.len = len;
			tx_message.response.state = resp;
			break;
		case AT_S2M_RECOVER_WALLET_RSP:
			tx_message.header.id = cmd;
			tx_message.header.is_ready = IS_READY;
			tx_message.header.len = len;
			tx_message.response.state = resp;
			break;
		case AT_S2M_GET_PUBKEY_RSP:
			tx_message.header.id = cmd;
			tx_message.header.is_ready = IS_READY;
			tx_message.header.len = len;
			tx_message.response.state = resp;
			memcpy(tx_message.para, data, len);
			break;
		case AT_S2M_SIGN_TRANX_RSP:
			tx_message.header.id = cmd;
			tx_message.header.is_ready = IS_READY;
			tx_message.header.len = len;
			tx_message.response.state = resp;
			memcpy(tx_message.para, data, len);
			break;
		case AT_S2M_DEL_WALLET_RSP:
			tx_message.header.id = cmd;
			tx_message.header.is_ready = IS_READY;
			tx_message.header.len = len;
			tx_message.response.state = resp;
			break;
		case AT_M2S_RETURN_BOOT_RSP:
			tx_message.header.id = cmd;
			tx_message.header.is_ready = IS_READY;
			tx_message.header.len = len;
			tx_message.response.state = resp;
			break;
		default:
			tx_message.header.id = AT_MAX;
			tx_message.header.is_ready = IS_BUSY;
			tx_message.header.len = 0;
			tx_message.response.state = RSP_UNKNOWN;
			break;
	}
}
void wallet_interface(message_t message){

	UINT8 cmd, i, state;
	UINT16 password_len, mne_number, mne_len, deriveAlgoId, signAlgoId, path_len, transhash_len;
	char pass_pharase[PRIV_KEY_BIT] = {0};
	char mnemonic[DATA_LEN] = {0};
	char derive_path[DATA_LEN] = {0};
	char transhash[DATA_LEN] = {0};
	unsigned char *hash;
	size_t hash_len;
	cmd = message.header.id;
	switch(cmd){
		/*创建钱包*/
		case AT_M2S_GEN_WALLET:
			wallet_entropy();
			break;
		/**
		*	用户更改交易密码
		* 输入参数
		*	1,UINT16 password_len
		*	2,char* pass_pharase
		*/
		case AT_M2S_SET_PWD:
			i = 0;
			i += endian_output(message.para, i, &password_len);
			state = message.para[i];
			memcpy(pass_pharase,  message.para, password_len);
			pass_pharase[password_len] = '\0';
			printf("pass_pharase = %s\r\n", pass_pharase);
			wallet_password(pass_pharase, state);
			break;
		/**
		* 保存助记词
		*	参数顺序
		*	1,UINT16 number
		*	2,UINT16 password_len
		*	3,UINT16 mne_len
		*	4,char* passphrase
		*	5,char* mnemonic
		*/
		case AT_M2S_SAVE_MNEMONIC:
			i = 0;
			i += endian_output(message.para, i, &mne_number);
			i += endian_output(message.para, i, &password_len);
			i += endian_output(message.para, i, &mne_len);
			
			memcpy(pass_pharase,  message.para+i, password_len);
			pass_pharase[password_len] = '\0';
			printf("pass_pharase = %s\r\n", pass_pharase);
			memcpy(mnemonic, message.para+i+password_len, mne_len);
			mnemonic[mne_len] = '\0';
			printf("mnemonic = %s\r\n", mnemonic);
			wallet_save(pass_pharase, (UINT8 *)mnemonic, mne_len);
			break;
		/**
		* 恢复钱包
		*	参数顺序
		*	1,UINT16 mne_number
		*	2,UINT16 password_len
		*	3,UINT16 mne_len
		*	4,char* passphrase
		*	5,char* mnemonic
		*/
		case AT_M2S_RECOVER_WALLET:
			i = 0;
			i += endian_output(message.para, i, &mne_number);
			i += endian_output(message.para, i, &password_len);
			i += endian_output(message.para, i, &mne_len);
			
			memcpy(pass_pharase,  message.para+i, password_len);
			pass_pharase[password_len] = '\0';
			printf("pass_pharase = %s\r\n", pass_pharase);
			memcpy(mnemonic, message.para+i+password_len, mne_len);
			mnemonic[mne_len] = '\0';
			printf("mnemonic = %s\r\n", mnemonic);
			wallet_recover(pass_pharase, (UINT8 *)mnemonic, mne_len);
			break;
		/**
		* 获取某币种主公钥
		*	输入参数顺序
		*	1,UINT16 mne_number
		*	2,UINT16 password_len
		*	3,UINT16 deriveAlgoId
		*	4,UINT16 signAlgoId
		*	5,UINT16 path_len
		*	6,char* passphrase
		*	7,char* derive_path
		*	输出参数顺序
		*	1,UINT16 pubkey_len
		*	2,char* pubkey
		*/
		case AT_M2S_GET_PUBKEY:
			i = 0;
			i += endian_output(message.para, i, &mne_number);
			i += endian_output(message.para, i, &password_len);
			i += endian_output(message.para, i, &deriveAlgoId);
			i += endian_output(message.para, i, &signAlgoId);
			i += endian_output(message.para, i, &path_len);

			memcpy(pass_pharase,  message.para+i, password_len);
			pass_pharase[password_len] = '\0';
			printf("pass_pharase = %s\r\n", pass_pharase);
			memcpy(derive_path,  message.para+i+password_len, path_len);
			derive_path[path_len] = '\0';
			printf("derive_path = %s\r\n", derive_path);
			wallet_pubkey(pass_pharase, derive_path, path_len, mne_number);
			break;
		/**
		* 签名交易
		*	输入参数顺序
		*	1,UINT16 mne_number
		*	2,UINT16 password_len
		*	3,UINT16 deriveAlgoId
		*	4,UINT16 signAlgoId
		*	5,UINT16 path_len
		*	6,UINT16 transhash_len
		*	7,char* passphrase
		*	8,char* derive_path
		*	9,char* transhash
		*	输出参数顺序
		*	1,UINT16 pubkey_len
		*	2,UINT16 signhash_len
		*	3,char* pubkey
		*	4,char* signhash
		*/
		case AT_M2S_SIGN_TRANX:
			i = 0;
			i += endian_output(message.para, i, &mne_number);
			i += endian_output(message.para, i, &password_len);
			i += endian_output(message.para, i, &deriveAlgoId);
			i += endian_output(message.para, i, &signAlgoId);
			i += endian_output(message.para, i, &path_len);
			i += endian_output(message.para, i, &transhash_len);
			
			memcpy(pass_pharase,  message.para+i, password_len);
			pass_pharase[password_len] = '\0';
			printf("pass_pharase = %s\r\n", pass_pharase);
			memcpy(derive_path,  message.para+i+password_len, path_len);
			derive_path[path_len] = '\0';
			printf("derive_path = %s\r\n", derive_path);
			memcpy(transhash,  message.para+i+password_len+path_len, transhash_len);
			transhash[transhash_len] = '\0';
			printf("transhash = %s, transhash_len = &d\r\n", transhash, transhash_len);
			hash = wally_malloc(transhash_len);
			wally_hex_to_bytes(transhash, hash, transhash_len, &hash_len);
			printf("hash_len = &d\r\n", hash_len);
			wallet_sign(pass_pharase, derive_path, path_len, hash, hash_len, mne_number);
			wally_clear(hash, transhash_len);
			wally_free(hash);
			break;
		/**
		*	删除钱包
		*	输入参数
		*	1,UINT16 password_len
		*	2,char* pass_pharase
		*/
		case AT_M2S_DEL_WALLET:
			i = 0;
			i += endian_output(message.para, i, &password_len);
		
			memcpy(pass_pharase,  message.para, password_len);
			pass_pharase[password_len] = '\0';
			printf("pass_pharase = %s\r\n", pass_pharase);
			wallet_delete(pass_pharase);
			break;
	   /**
	   * 返回boot启动
	   */
	   case AT_M2S_RETURN_BOOT:
	   		boot_start();
	   		break;
	}
}

UINT8 spi_response(UINT8 response){
	UINT8 ret = 0;
	UINT8 ready[HEADER_LEN] = {0};
	switch(response){
		case IS_READY:
			ready[0] = IS_READY;
			printf("spi_response IS_READY\r\n");
			spi_tx_bytes_dma(SPIA, ready, HEADER_LEN);
			break;
		case IS_BUSY:
			ready[0] = IS_BUSY;
			printf("spi_response IS_BUSY\r\n");
			spi_tx_bytes_dma(SPIA, ready, HEADER_LEN);
			break;
		case IS_READ:
			printf("spi_response IS_READ\r\n");
			spi_write(tx_message);
			break;
		default:
			printf("spi_response default\r\n");
			break;
	}
	ret = 1;
	return ret;
}

UINT8 spi_read(void){
	UINT8 ret = 0;
	memset(spi_data_buf, 0, BUFF_LEN);
	memset(&rx_message, 0, sizeof(rx_message));
	spi_rx_bytes_dma(SPIA, spi_data_buf, BUFF_LEN);
	print_hexstr_key("spi_read", spi_data_buf, HEADER_LEN+1);
	memcpy(&rx_message, spi_data_buf+1, HEADER_LEN);
	printf("spi_read - message.header.is_ready = %x\r\n", rx_message.header.is_ready);
	switch(rx_message.header.is_ready){
		case IS_READY:
			printf("spi_read - message.header.id = %x\r\n", rx_message.header.id);
			printf("spi_read - message.header.len = %d\r\n", rx_message.header.len);
			memcpy(rx_message.para, spi_data_buf+HEADER_LEN+1, rx_message.header.len);
			spi_response(IS_READY);
			printf("spi_read return is ready\r\n");
			wallet_interface(rx_message);
			spi_ready = IS_READY;
			break;
		case IS_READ:
			spi_response(IS_READ);
			spi_ready = IS_READ;
			break;
		default:
			spi_response(IS_BUSY);
			break;
	}
	return ret;
}

UINT8 spi_write(message_t message){
	UINT8 ret = 0;
	UINT8 i = 0;
	UINT16 len = message.header.len + HEADER_LEN + 1;
	memset(spi_data_buf, 0, BUFF_LEN);
	memcpy(spi_data_buf, &message, len);
	//endian_input(spi_data_buf, PARA_LEN_START, message.header.len);
	print_hexstr_key("spi_write", spi_data_buf,  len);
	spi_tx_bytes_dma(SPIA, spi_data_buf, BUFF_LEN);
	return ret;
}

//uart test code
void init_boot(void){
	UINT8 ret = 0;
	unsigned char message[EC_MESSAGE_HASH_LEN];
	#ifndef USE_BORAD
	printf("spi init\r\n");
	spi_init(SPIA, WORK_MODE_0);
	printf("dma init\r\n");
	dma_init();
	#endif
	printf("boot done\r\n");
	while(1){
		#ifdef USE_BORAD
		//uart
		if(rx_flag == 1){
			printfS("rx_flag = %d, uart_rx_buf = %s\r\n", rx_flag, uart_rx_buf);
			if(strstr((char *)(uart_rx_buf), "entropy")){
				wallet_entropy();
			}else if(strstr((char *)(uart_rx_buf), "check_pd")){
				wallet_password("12345678", RSP_CHECK_PD);
			}else if(strstr((char *)(uart_rx_buf), "new_pd")){
				wallet_password("87654321", RSP_NEW_PD);
			}else if(strstr((char *)(uart_rx_buf), "store")){
				wallet_save("12345678", (UINT8 *)MNEMONIC, strlen(MNEMONIC));
			}else if(strstr((char *)(uart_rx_buf), "derived")){
				wallet_pubkey("12345678", "m/44'/0'/0'/0", strlen("m/44'/0'/0'/0"), 24);
			}else if(strstr((char *)(uart_rx_buf), "keysign")){
				sha256("1234567890", strlen("1234567890"), message);
				wallet_sign("12345678", "m/44'/0'/0'/0", strlen("m/44'/0'/0'/0"), message, sizeof(message), 24);
			}else if(strstr((char *)(uart_rx_buf), "keyverify")){
				sha256("1234567890", strlen("1234567890"), message);
				wallet_verify("12345678", "m/44'/0'/0'/0", strlen("m/44'/0'/0'/0"), message, sizeof(message), 24);
			}else if(strstr((char *)(uart_rx_buf), "bootloader")){
				printf("return_to_boot !!!\r\n");
				return_to_boot();
			}
			rx_flag = 0;
			rx_count = 0;
			memset((char*)uart_rx_buf, 0, sizeof(uart_rx_buf));
		}
		#else
		//spi
		printf("REG_SPI_CS(SPIA) = %d\r\n", REG_SPI_CS(SPIA));
		ret = spi_read();
		printf("spi spi_read ok ret=%d\r\n", ret);
		#endif
	}
}


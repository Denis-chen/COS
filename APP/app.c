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
#include "sha256.h"
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

extern volatile UINT8 rx_flag;
extern volatile UINT8 uart_rx_buf[32];
UINT8 spi_data_buf[BUFF_LEN];
char *MNEMONIC = "amazing crew job journey drop country subject melody false layer output elite task wrap dish elite example mixed group body aerobic since custom cash";
void wallet_response(UINT8 cmd, UINT8 *data, UINT16 len);
UINT8 spi_write(message_t message);

void wallet_entropy(){
	UINT32 i;
	UINT8 entropy[DATA_LEN] = {0};
	hrng_initial();
	if(get_hrng(entropy, PRIV_KEY_BIT))
	{
		printfS("random number is error\r\n");
		return;
	}
	print_hexstr_key("entropy", entropy, PRIV_KEY_BIT);
	wallet_response(AT_S2M_GEN_WALLET_RSP, entropy, PRIV_KEY_BIT);
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

    if(inLen > nextPageBaseAddr - dstAddr) //??
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


void get_mnemonic(UINT32 base_addr, UINT8 *value){
	UINT32 i, len, addr;
	addr = base_addr,
	len = eflash_read_word(addr);
	printf("get_mnemonic len = %d\r\n", len);
	addr = addr+4;
	for(i = 0; i < len; i++){
		*value = eflash_read_byte(addr+i);
		value++;
	}
}

void store_mnemonic(char *pass_pharase, UINT8 *mnemonic, UINT32 len){
	UINT32 i, addr;
	addr = EFlashMainBaseAddr,
	printf("store_mnemonic len = %d\r\n", len);
	eflash_erase_page(addr);
	eflash_write_word(addr, len);
	addr = addr+4;
	for(i = 0; i < len; i++){
		AC_MemoryWrite(mnemonic+i, 1, addr+i);
	}
	printf("store_mnemonic ok!!!\r\n");
}

void wallet_password(char *pass_pharase){
	UINT8 mnemonic[DATA_LEN] = {0};
	get_mnemonic(EFlashMainBaseAddr, mnemonic);
	store_mnemonic(pass_pharase, mnemonic, DATA_LEN);
	wallet_response(AT_S2M_SET_PWD_RSP, mnemonic, 0);
}

void wallet_recover(char *pass_pharase, UINT8 *mnemonic, UINT32 len){
	store_mnemonic(pass_pharase, mnemonic, len);
	wallet_response(AT_S2M_RECOVER_WALLET_RSP, mnemonic, 0);
}

void wallet_save(char *pass_pharase, UINT8 *mnemonic, UINT32 len){
	store_mnemonic(pass_pharase, mnemonic, len);
	wallet_response(AT_S2M_SAVE_MNEMONIC_RSP, mnemonic, 0);
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
	wallet_response(AT_S2M_DEL_WALLET_RSP, NULL, 0);
}

void get_mnemonic_number(UINT32 base_addr, UINT8 *value, UINT16 number){
	char *ptr;
	UINT16 index = 0;
	UINT8 mnemonic[DATA_LEN] = {0};
	get_mnemonic(EFlashMainBaseAddr, mnemonic);
	
	ptr = strtok(mnemonic, " ");
	do{
		index++;
		strcat(value, ptr);
		if(index != number){
			strcat(value, " ");
		}
		ptr = strtok(NULL, " ");
	}while (ptr != NULL && index < number);
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
			strncpy(str, ptr, strlen(ptr)-1);
			if(strstr(ptr, "'")){
				out[len] = BIP32_INITIAL_HARDENED_CHILD|atoi(str);
			}else{
				out[len] = atoi(str);
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
	struct ext_key hdkey;
	uint32_t child_path[8] = {0};
	size_t child_path_len = 0;
	BYTE bSeed[BIP39_SEED_LEN_512] = {0};
	UINT8 mnemonic[DATA_LEN] = {0};
	printf("derived start !!!\r\n");
	get_mnemonic_number(EFlashMainBaseAddr, mnemonic, mne_number);
	printf("mnemonic = %s\r\n", mnemonic);
	bip39_mnemonic_to_seed(mnemonic, NULL, bSeed, sizeof(bSeed), &seed_len);
	print_hexstr_key("seed", bSeed, sizeof(bSeed));
	printf("key_path = %s\r\n", key_path);
	//wally_hex_to_bytes(SEED, bSeed, sizeof(bSeed), &seed_len);
	child_path_split(key_path, child_path, &child_path_len);
	ret = bip32_key_from_seed(bSeed, seed_len, BIP32_VER_MAIN_PRIVATE, BIP32_FLAG_KEY_PRIVATE, &hdkey);
	printf("bip32_key_from_seed -- ret = %d\r\n", ret);
	if(ret == WALLY_OK){
		//debug log
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
		if(child_path_len != 0){
			ret = bip32_key_from_parent_path(&hdkey, child_path, child_path_len, BIP32_FLAG_KEY_PRIVATE, key_out);
			printf("bip32_key_from_parent_path -- ret = %d\r\n", ret);
			if(ret == WALLY_OK){
				//debug log
				printf("================================child======================================\r\n");
				print_hexstr_key("prvkey", key_out->priv_key, sizeof(key_out->priv_key));
				print_hexstr_key("pubkey", key_out->pub_key, sizeof(key_out->priv_key));
				print_hexstr_key("chcode", key_out->chain_code, sizeof(key_out->priv_key));
				print_hexstr_key("has160", key_out->hash160, sizeof(key_out->priv_key));
				printf("================================serialize=====================================\r\n");
				bip32_key_serialize(key_out, BIP32_FLAG_KEY_PRIVATE, serial, serial_len);
				print_hexstr_key("prvkey", serial, serial_len);
				bip32_key_serialize(key_out, BIP32_FLAG_KEY_PUBLIC, serial, serial_len);
				print_hexstr_key("pubkey", serial, serial_len);
			}
		}
	}
	return ret;
}

int wallet_sign(char *pass_pharase, char *key_path, UINT16 path_len, 
				unsigned char *message, UINT16 len, 
				UINT16 mne_number){
	int ret; 
	UINT8 serial[BIP32_SERIALIZED_LEN] = {0};
	UINT8 sign_out[EC_SIGNATURE_LEN] = {0};
	UINT8 number[NUM_LEN] = {0};
	UINT8 buff[NUM_LEN*2 + BIP32_SERIALIZED_LEN + EC_SIGNATURE_LEN] = {0};
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
			sprintf(number, "%d", EC_PUBLIC_KEY_LEN);
			strncpy(buff, number, sizeof(number));
			memset(number, 0, sizeof(number));
			sprintf(number, "%d", EC_SIGNATURE_LEN);
			strncat(buff, number, sizeof(number));
			strncat(buff, serial, BIP32_SERIALIZED_LEN);
			strncat(buff, sign_out, EC_SIGNATURE_LEN);
			wallet_response(AT_S2M_SIGN_TRANX_RSP, buff, sizeof(buff));
		}
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

void wallet_pubkey(char *pass_pharase, char *key_path, UINT16 path_len, UINT16 mne_number){
	int ret;
	struct ext_key key_out;
	UINT8 serial[BIP32_SERIALIZED_LEN] = {0};
	UINT8 number[NUM_LEN] = {0};
	UINT8 buff[NUM_LEN + BIP32_SERIALIZED_LEN] = {0};
	ret = derived(pass_pharase, key_path, path_len, mne_number, serial, BIP32_SERIALIZED_LEN, &key_out);
	if(ret == WALLY_OK){
		sprintf(number, "%d", EC_PUBLIC_KEY_LEN);
		strncpy(buff, number, sizeof(number));
		strncat(buff, serial, BIP32_SERIALIZED_LEN);
		wallet_response(AT_S2M_GET_PUBKEY_RSP, buff, sizeof(buff));
	}
}
void wallet_response(UINT8 cmd, UINT8 *data, UINT16 len){
	UINT8 result = 1;
	message_t message;
	switch(cmd){
		case AT_S2M_GEN_WALLET_RSP:
			message.header.id = cmd;
			message.header.is_ready = 0x55;
			message.header.len = len;
			strncpy(message.para, data, len);
			result = 0;
			break;
		case AT_S2M_SET_PWD_RSP:
			message.header.id = cmd;
			message.header.is_ready = 0x55;
			message.header.len = 0;
			result = 0;
			break;
		case AT_S2M_SAVE_MNEMONIC_RSP:
			message.header.id = cmd;
			message.header.is_ready = 0x55;
			message.header.len = 0;
			result = 0;
			break;
		case AT_S2M_RECOVER_WALLET_RSP:
			message.header.id = cmd;
			message.header.is_ready = 0x55;
			message.header.len = 0;
			result = 0;
			break;
		case AT_S2M_GET_PUBKEY_RSP:
			message.header.id = cmd;
			message.header.is_ready = 0x55;
			message.header.len = len;
			result = 0;
			strncpy(message.para, data, len);
			break;
		case AT_S2M_SIGN_TRANX_RSP:
			message.header.id = cmd;
			message.header.is_ready = 0x55;
			message.header.len = len;
			result = 0;
			strncpy(message.para, data, len);
			break;
		case AT_S2M_DEL_WALLET_RSP:
			message.header.id = cmd;
			message.header.is_ready = 0x55;
			message.header.len = 0;
			result = 0;
			break;
		default:
			message.header.id = AT_MAX;
			message.header.is_ready = 0x77;
			message.header.len = 0;
			result = 0;
			break;
	}
	spi_write(message);
}
void wallet_interface(message_t message){
	UINT8 cmd, i;
	UINT16 mne_number, mne_len, deriveAlgoId, signAlgoId, derive_path_len, trans_hash_len;
	char pass_pharase[8] = {0};
	char tmpData[NUM_LEN] = {0};
	char mnemonic[DATA_LEN] = {0};
	char derive_path[DATA_LEN] = {0};
	char tans_hash[DATA_LEN] = {0};
	cmd = message.header.id;
	switch(cmd){
		/*????*/
		case AT_M2S_GEN_WALLET:
			wallet_entropy();
			break;
		/*????????*/
		case AT_M2S_SET_PWD:
			strncpy(pass_pharase,  message.para, sizeof(pass_pharase));
			wallet_password(pass_pharase);
			break;
		/*?????*/
		case AT_M2S_SAVE_MNEMONIC:
			strncpy(pass_pharase,  message.para, sizeof(pass_pharase));
			memset(tmpData, 0, sizeof(tmpData));
			strncpy(tmpData, message.para+sizeof(pass_pharase), NUM_LEN);
			mne_number = atoi(tmpData);
			memset(tmpData, 0, sizeof(tmpData));
			strncpy(tmpData, message.para+sizeof(pass_pharase)+NUM_LEN, NUM_LEN);
			mne_len = atoi(tmpData);
			strncpy(mnemonic, message.para+sizeof(pass_pharase)+NUM_LEN*2, mne_len);
			wallet_save(pass_pharase, (UINT8 *)mnemonic, mne_len);
			break;
		/*????*/
		case AT_M2S_RECOVER_WALLET:
			i = 0;
			strncpy(pass_pharase,  message.para, sizeof(pass_pharase));
			memset(tmpData, 0, sizeof(tmpData));
			strncpy(tmpData, message.para+sizeof(pass_pharase), NUM_LEN);
			mne_number = atoi(tmpData);
			memset(tmpData, 0, sizeof(tmpData));
			strncpy(tmpData, message.para+sizeof(pass_pharase)+NUM_LEN*i, NUM_LEN);
			i++;
			mne_len = atoi(tmpData);
			strncpy(mnemonic, message.para+sizeof(pass_pharase)+NUM_LEN*i, mne_len);
			wallet_recover(pass_pharase, (UINT8 *)mnemonic, mne_len);
			break;
		/*????????*/
		case AT_M2S_GET_PUBKEY:
			i = 0;
			strncpy(pass_pharase,  message.para, sizeof(pass_pharase));
			memset(tmpData, 0, sizeof(tmpData));
			strncpy(tmpData, message.para+sizeof(pass_pharase), NUM_LEN);
			mne_number = atoi(tmpData);
			i++;
			memset(tmpData, 0, sizeof(tmpData));
			strncpy(tmpData, message.para+sizeof(pass_pharase), NUM_LEN);
			deriveAlgoId = atoi(tmpData);
			memset(tmpData, 0, sizeof(tmpData));
			strncpy(tmpData, message.para+sizeof(pass_pharase)+NUM_LEN*i, NUM_LEN);
			signAlgoId = atoi(tmpData);
			memset(tmpData, 0, sizeof(tmpData));
			i++;
			strncpy(tmpData, message.para+sizeof(pass_pharase)+NUM_LEN*i, NUM_LEN);
			derive_path_len = atoi(tmpData);
			i++;
			strncpy(derive_path, message.para+sizeof(pass_pharase)+NUM_LEN*i, derive_path_len);
			wallet_pubkey(pass_pharase, derive_path, derive_path_len, mne_number);
			break;
		/*????*/
		case AT_M2S_SIGN_TRANX:
			i = 0;
			strncpy(pass_pharase,  message.para, sizeof(pass_pharase));
			memset(tmpData, 0, sizeof(tmpData));
			strncpy(tmpData, message.para+sizeof(pass_pharase), NUM_LEN);
			mne_number = atoi(tmpData);
			i++;
			memset(tmpData, 0, sizeof(tmpData));
			strncpy(tmpData, message.para+sizeof(pass_pharase), NUM_LEN);
			deriveAlgoId = atoi(tmpData);
			memset(tmpData, 0, sizeof(tmpData));
			strncpy(tmpData, message.para+sizeof(pass_pharase)+NUM_LEN*i, NUM_LEN);
			signAlgoId = atoi(tmpData);
			i++;
			memset(tmpData, 0, sizeof(tmpData));
			strncpy(tmpData, message.para+sizeof(pass_pharase)+NUM_LEN*i, NUM_LEN);
			trans_hash_len = atoi(tmpData);
			i++;
			memset(tmpData, 0, sizeof(tmpData));
			strncpy(tmpData, message.para+sizeof(pass_pharase)+NUM_LEN*i, NUM_LEN);
			derive_path_len = atoi(tmpData);
			i++;
			strncpy(tans_hash, message.para+sizeof(pass_pharase)+NUM_LEN*i, trans_hash_len);
			i++;
			strncpy(derive_path, message.para+sizeof(pass_pharase)+NUM_LEN*i, derive_path_len);
			wallet_sign(pass_pharase, derive_path, derive_path_len, tans_hash, trans_hash_len, mne_number);
			break;
		case AT_M2S_DEL_WALLET:
			strncpy(pass_pharase,  message.para, sizeof(pass_pharase));
			wallet_delete(pass_pharase);
			break;
	}
}

UINT8 spi_read(){
	UINT8 ret = 0;
	message_t message;
	memset(spi_data_buf, 0, BUFF_LEN);
	REG_SPI_CTL(SPIA) = 0 << 5 | 0 << 4 | 0 << 2 | 0 << 0;
	REG_SPI_OUT_EN(SPIA) = 0x00;
	spi_rx_bytes(SPIA, spi_data_buf, BUFF_LEN);
	memcpy(&message, spi_data_buf, sizeof(message));
	if(message.header.is_ready != 0){
		printf("spi_read - spi_data_buf = %s\r\n", spi_data_buf);
		printf("spi_read - message.header.is_ready = %x\r\n", message.header.is_ready);
	}
	if(message.header.is_ready == 0x55){
		wallet_interface(message);
		ret = 1;
	}
	return ret;
}

UINT8 spi_write(message_t message){
	UINT8 ret = 0;
	memset(spi_data_buf, 0, BUFF_LEN);
	REG_SPI_CTL(SPIA) = 0 << 5 | 0 << 4 | 0 << 2 | 0 << 0;
	REG_SPI_OUT_EN(SPIA) = 0x02;
	printf("spi_write - message.header.is_ready = %x\r\n", message.header.is_ready);
	memcpy(spi_data_buf, &message, sizeof(message));
	spi_tx_bytes(SPIA, spi_data_buf, BUFF_LEN);
	return ret;
}

//uart test code
void init_boot(void){
	unsigned char message[EC_MESSAGE_HASH_LEN];
	printf("spi init\r\n");
	spi_init(SPIA, WORK_MODE_0);
	REG_SPI_TX_CTL(SPIA) = (REG_SPI_TX_CTL(SPIA) & ~0xff00) | 0x55 << 8;
	printf("boot done\r\n");
	while(1){
		//uart
		if(rx_flag == 1){
			printfS("rx_flag = %d, uart_rx_buf = %s\r\n", rx_flag, uart_rx_buf);
			if(strstr((char *)(uart_rx_buf), "entropy")){
				wallet_entropy();
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
		}else {
			//spi
			spi_read();
			delay(200);
		}
	}
}


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

UINT32 g_data_buf[256];
extern volatile UINT8 rx_flag;
extern volatile UINT8 uart_rx_buf[32];
char *MNEMONIC = "amazing crew job journey drop country subject melody false layer output elite task wrap dish elite example mixed group body aerobic since custom cash";
struct ext_key key_out;
unsigned char sign_out[EC_SIGNATURE_LEN] = {0};
void hrng_entropy(){
	UINT32 i;
	hrng_initial();
	if(get_hrng(DATABUF, PRIV_KEY_BIT))
	{
		printfS("random number is error\r\n");
		return;
	}
	printfS("---------hrng_entropy : ");
	for(i = 0; i < PRIV_KEY_BIT; i++){
		printfS("%02x", DATABUF[i]);
	}
	printfS("\r\n");
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
			if(strstr(ptr, "H")){
				out[len] = BIP32_INITIAL_HARDENED_CHILD|atoi(str);
			}else{
				out[len] = atoi(str);
			}
			len++;
		}
	}
	*outlen = len;
}

void derived(char *key_path){
	size_t seed_len;
	int ret;
	struct ext_key hdkey;
	uint32_t child_path[8] = {0};
	size_t child_path_len = 0;
	BYTE bSeed[BIP39_SEED_LEN_512] = {0};
	BYTE serial[BIP32_SERIALIZED_LEN] = {0};
	printf("derived start !!!\r\n");
	bip39_mnemonic_to_seed(MNEMONIC, NULL, bSeed, sizeof(bSeed), &seed_len);
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
		bip32_key_serialize(&hdkey, BIP32_FLAG_KEY_PRIVATE, serial, sizeof(serial));
		print_hexstr_key("prvkey", serial, sizeof(serial));
		bip32_key_serialize(&hdkey, BIP32_FLAG_KEY_PUBLIC, serial, sizeof(serial));
		print_hexstr_key("pubkey", serial, sizeof(serial));
		if(child_path_len != 0){
			ret = bip32_key_from_parent_path(&hdkey, child_path, child_path_len, BIP32_FLAG_KEY_PRIVATE, &key_out);
			printf("bip32_key_from_parent_path -- ret = %d\r\n", ret);
			if(ret == WALLY_OK){
				//debug log
				printf("================================child======================================\r\n");
				print_hexstr_key("prvkey", key_out.priv_key, sizeof(key_out.priv_key));
				print_hexstr_key("pubkey", key_out.pub_key, sizeof(key_out.priv_key));
				print_hexstr_key("chcode", key_out.chain_code, sizeof(key_out.priv_key));
				print_hexstr_key("has160", key_out.hash160, sizeof(key_out.priv_key));
				printf("================================serialize=====================================\r\n");
				bip32_key_serialize(&key_out, BIP32_FLAG_KEY_PRIVATE, serial, sizeof(serial));
				print_hexstr_key("prvkey", serial, sizeof(serial));
				bip32_key_serialize(&key_out, BIP32_FLAG_KEY_PUBLIC, serial, sizeof(serial));
				print_hexstr_key("pubkey", serial, sizeof(serial));
			}
		}
	}
}

void keysign(unsigned char *message, size_t len){
	int ret = 0;
	printf("keysign start !!!\r\n");
	wally_ec_sig_from_bytes(key_out.priv_key+1, sizeof(key_out.priv_key)-1, message, len, EC_FLAG_ECDSA, sign_out, sizeof(sign_out));
	//debug log
	printf("================================keysign=====================================\r\n");
	print_hexstr_key("message", message, len);
	print_hexstr_key("signed", sign_out, sizeof(sign_out));
}

int keyverify(unsigned char *pub_key, size_t pub_key_len, 
				unsigned char *bytes, size_t bytes_len, 
				unsigned char *sig, size_t sig_len){
	int ret;
	ret = wally_ec_sig_verify(pub_key, pub_key_len, bytes, bytes_len, EC_FLAG_ECDSA, sig, sig_len);
	if(ret == WALLY_OK){
		printf("key verify ok!!!\r\n");
	}else{
		printf("key verify fail!!!\r\n");
	}
	return ret;
}
void init_boot(void){
	unsigned char message[EC_MESSAGE_HASH_LEN];
	while(1){
		if(rx_flag == 1){
			printfS("rx_flag = %d, uart_rx_buf = %s\r\n", rx_flag, uart_rx_buf);
			if(strstr((char *)(uart_rx_buf), "entropy")){
				hrng_entropy();
			}else if(strstr((char *)(uart_rx_buf), "derived")){
				derived("m/44H/0H/0H/0");
			}else if(strstr((char *)(uart_rx_buf), "keysign")){
				derived("m/44H/0H/0H/0");
				sha256("1234567890", strlen("1234567890"), message);
				keysign(message, sizeof(message));
			}else if(strstr((char *)(uart_rx_buf), "keyverify")){
				sha256("1234567890", strlen("1234567890"), message);
				keyverify(key_out.pub_key, sizeof(key_out.pub_key), message, sizeof(message), sign_out, sizeof(sign_out));
			}
			rx_flag = 0;
			rx_count = 0;
			memset((char*)uart_rx_buf, 0, sizeof(uart_rx_buf));
		}
	}
}


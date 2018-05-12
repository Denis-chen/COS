#ifndef LIBWALLY_CORE_BIP39_H
#define LIBWALLY_CORE_BIP39_H

#include "wally_core.h"

#ifdef __cplusplus
extern "C" {
#endif

struct words;

/** Valid entropy lengths */
#define BIP39_ENTROPY_LEN_128 16
#define BIP39_ENTROPY_LEN_160 20
#define BIP39_ENTROPY_LEN_192 24
#define BIP39_ENTROPY_LEN_224 28
#define BIP39_ENTROPY_LEN_256 32
#define BIP39_ENTROPY_LEN_288 36
#define BIP39_ENTROPY_LEN_320 40

/** The required size of the output buffer for `bip39_mnemonic_to_seed` */
#define BIP39_SEED_LEN_512 64

/** The number of words in a BIP39 compliant wordlist */
#define BIP39_WORDLIST_LEN 2048

WALLY_CORE_API int bip39_mnemonic_to_seed(
    const char *mnemonic,
    const char *password,
    unsigned char *bytes_out,
    size_t len,
    size_t *written);

#ifdef __cplusplus
}
#endif

#endif /* LIBWALLY_CORE_BIP39_H */

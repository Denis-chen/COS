#include "internal.h"
#include "hmac.h"
#include <stdbool.h>
#include "sha2.h"
#include "hmac_sha2.h"

void hmac_sha256_impl(struct sha256 *sha,
                      const unsigned char *key, size_t key_len,
                      const unsigned char *msg, size_t msg_len)
{
	hmac_sha256(key, key_len, (unsigned char *)msg,
					msg_len, sha->u.u8, SHA256_DIGEST_SIZE);
}


void hmac_sha512_impl(struct sha512 *sha,
                      const unsigned char *key, size_t key_len,
                      const unsigned char *msg, size_t msg_len)
{
	hmac_sha512(key, key_len, (unsigned char *)msg,
					msg_len, sha->u.u8, SHA512_DIGEST_SIZE);
}


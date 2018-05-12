/*
 * fast-pbkdf2 - Optimal PBKDF2-HMAC calculation
 * Written in 2015 by Joseph Birr-Pixton <jpixton@gmail.com>
 *
 * To the extent possible under law, the author(s) have dedicated all
 * copyright and related and neighboring rights to this software to the
 * public domain worldwide. This software is distributed without any
 * warranty.
 *
 * You should have received a copy of the CC0 Public Domain Dedication
 * along with this software. If not, see
 * <http://creativecommons.org/publicdomain/zero/1.0/>.
 */

#include "pbkdf2.h"

#include <string.h>
#if defined(__GNUC__)
#include "endian.h"
#endif
#include "secp256k1.h"
#include "sha2.h"
#include "hmac_sha2.h"
/* --- MSVC doesn't support C99 --- */
#ifdef _MSC_VER
#define restrict
#define _Pragma __pragma
#endif

/* --- Common useful things --- */
#define MIN(a, b) ((a) > (b)) ? (b) : (a)

static SECP256K1_INLINE void write32_be(uint32_t n, uint8_t out[4])
{
#if defined(__GNUC__) && __GNUC__ >= 4 && __BYTE_ORDER == __LITTLE_ENDIAN
  *(uint32_t *)(out) = __builtin_bswap32(n);
#else
  out[0] = (n >> 24) & 0xff;
  out[1] = (n >> 16) & 0xff;
  out[2] = (n >> 8) & 0xff;
  out[3] = n & 0xff;
#endif
}

static SECP256K1_INLINE void write64_be(uint64_t n, uint8_t out[8])
{
#if defined(__GNUC__) &&  __GNUC__ >= 4 && __BYTE_ORDER == __LITTLE_ENDIAN
  *(uint64_t *)(out) = __builtin_bswap64(n);
#else
  write32_be((n >> 32) & 0xffffffff, out);
  write32_be(n & 0xffffffff, out + 4);
#endif
}

/* --- Optional OpenMP parallelisation of consecutive blocks --- */
#ifdef WITH_OPENMP
# define OPENMP_PARALLEL_FOR _Pragma("omp parallel for")
#else
# define OPENMP_PARALLEL_FOR
#endif
typedef struct {															
  sha256_ctx inner;																
  sha256_ctx outer;																
} HMAC_CTX_SHA256;	 

typedef struct {															
  sha512_ctx inner;																
  sha512_ctx outer;																
} HMAC_CTX_SHA512;	 

/* Prepare block (of blocksz bytes) to contain md padding denoting a msg-size
 * message (in bytes).  block has a prefix of used bytes.
 *
 * Message length is expressed in 32 bits (so suitable for sha1, sha256, sha512). */
static SECP256K1_INLINE void md_pad(uint8_t *block, size_t blocksz, size_t used, size_t msg)
{
  memset(block + used, 0, blocksz - used - 4);
  block[used] = 0x80;
  block += blocksz - 4;
  write32_be((uint32_t) (msg * 8), block);
}

int pbkdf2_sha256(const uint8_t *key, uint32_t keylen, const uint8_t *salt, uint32_t saltlen,
	uint32_t rounds, uint8_t *dk, uint32_t dklen)
{
	uint8_t *T = dk;
	uint32_t i, j, k;
	uint8_t U[SHA256_DIGEST_SIZE];
	uint8_t count[4];
	uint32_t hlen = SHA256_DIGEST_SIZE;
	uint32_t len = hlen;
	uint32_t l = dklen / hlen + ((dklen % hlen) ? 1 : 0);
	uint32_t r = dklen - (l - 1) * hlen;
	int ret = 0;
	hmac_sha256_ctx hmac;
	hmac_sha256_init(&hmac, key, keylen);
	for (i = 1; i <= l; i++)
	{
		if (i == l)
		{
			len = r;
		}
		count[0] = (i >> 24) & 0xFF;
		count[1] = (i >> 16) & 0xFF;
		count[2] = (i >>  8) & 0xFF;
		count[3] = (i) & 0xFF;
		hmac_sha256_init(&hmac, key, keylen);
		hmac_sha256_update(&hmac, salt, saltlen);
		hmac_sha256_update(&hmac, count, 4);
		hmac_sha256_final(&hmac, U, SHA256_DIGEST_SIZE);
		memcpy(T, U, len);
		for (j = 1; j < rounds; j++)
		{
			hmac_sha256_init(&hmac, key, keylen);
			hmac_sha256_update(&hmac, U, hlen);
			hmac_sha256_final(&hmac, U, SHA256_DIGEST_SIZE);
			for (k = 0; k < len; k++)
			{
				T[k] ^= U[k];
			}
		}
		T += len;
	}
	return ret;
}



int pbkdf2_hmac_sha256(const uint8_t *pw, size_t npw,
                            const uint8_t *salt, size_t nsalt,
                            uint32_t iterations,
                            uint8_t *out, size_t nout)
{
	return pbkdf2_sha256(pw, npw, salt, nsalt, iterations, out, nout);
}
					 
 int pbkdf2_sha512(const uint8_t *key, uint32_t keylen, const uint8_t *salt, uint32_t saltlen,
	 uint32_t rounds, uint8_t *dk, uint32_t dklen)
 {
	 uint8_t *T = dk;
	 uint32_t i, j, k;
	 uint8_t U[SHA512_DIGEST_SIZE];
	 uint8_t count[4];
	 uint32_t hlen = SHA512_DIGEST_SIZE;
	 uint32_t len = hlen;
	 uint32_t l = dklen / hlen + ((dklen % hlen) ? 1 : 0);
	 uint32_t r = dklen - (l - 1) * hlen;
	 int ret = 0;
	 hmac_sha512_ctx hmac;
	 hmac_sha512_init(&hmac, key, keylen);
	 for (i = 1; i <= l; i++)
	 {
		 if (i == l)
		 {
			 len = r;
		 }
		 count[0] = (i >> 24) & 0xFF;
		 count[1] = (i >> 16) & 0xFF;
		 count[2] = (i >>  8) & 0xFF;
		 count[3] = (i) & 0xFF;
		 hmac_sha512_init(&hmac, key, keylen);
		 hmac_sha512_update(&hmac, salt, saltlen);
		 hmac_sha512_update(&hmac, count, 4);
		 hmac_sha512_final(&hmac, U, SHA512_DIGEST_SIZE);
		 memcpy(T, U, len);
		 for (j = 1; j < rounds; j++)
		 {
		 	 hmac_sha512_init(&hmac, key, keylen);
			 hmac_sha512_update(&hmac, U, hlen);
			 hmac_sha512_final(&hmac, U, SHA512_DIGEST_SIZE);
			 for (k = 0; k < len; k++)
			 {
				 T[k] ^= U[k];
			 }
		 }
		 T += len;
	 }
	 return ret;
 }

int pbkdf2_hmac_sha512(const uint8_t *pw, size_t npw,
							const uint8_t *salt, size_t nsalt,
							uint32_t iterations,
							uint8_t *out, size_t nout)
{
	return pbkdf2_sha512(pw, npw, salt, nsalt, iterations, out, nout);
}




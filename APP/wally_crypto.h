#ifndef LIBWALLY_CORE_CRYPTO_H
#define LIBWALLY_CORE_CRYPTO_H

#include "wally_core.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Output length for `wally_sha256` */
#define SHA256_LEN 32

/** Output length for `wally_sha512` */
#define SHA512_LEN 64

/**
 * SHA-256(m)
 *
 * :param bytes: The message to hash
 * :param bytes_len: The length of ``bytes`` in bytes.
 * :param bytes_out: Destination for the resulting hash.
 * :param len: The length of ``bytes_out`` in bytes. Must be ``SHA256_LEN``.
 */
WALLY_CORE_API int wally_sha256(
    const unsigned char *bytes,
    size_t bytes_len,
    unsigned char *bytes_out,
    size_t len);

/**
 * SHA-256(SHA-256(m)) (double SHA-256)
 *
 * :param bytes: The message to hash
 * :param bytes_len: The length of ``bytes`` in bytes.
 * :param bytes_out: Destination for the resulting hash.
 * :param len: The length of ``bytes_out`` in bytes. Must be ``SHA256_LEN``.
 */
WALLY_CORE_API int wally_sha256d(
    const unsigned char *bytes,
    size_t bytes_len,
    unsigned char *bytes_out,
    size_t len);

/**
 * SHA-512(m)
 *
 * :param bytes: The message to hash
 * :param bytes_len: The length of ``bytes`` in bytes.
 * :param bytes_out: Destination for the resulting hash.
 * :param len: The length of ``bytes_out`` in bytes. Must be ``SHA512_LEN``.
 */
WALLY_CORE_API int wally_sha512(
    const unsigned char *bytes,
    size_t bytes_len,
    unsigned char *bytes_out,
    size_t len);

/** Output length for `wally_hash160` */
#define HASH160_LEN 20

/**
 * RIPEMD-160(SHA-256(m))
 *
 * :param bytes: The message to hash
 * :param bytes_len: The length of ``bytes`` in bytes.
 * :param bytes_out: Destination for the resulting hash.
 * :param len: The length of ``bytes_out`` in bytes. Must be ``HASH160_LEN``.
 */
WALLY_CORE_API int wally_hash160(
    const unsigned char *bytes,
    size_t bytes_len,
    unsigned char *bytes_out,
    size_t len);

/** The length of a private key used for EC signing */
#define EC_PRIVATE_KEY_LEN 32
/** The length of a public key used for EC signing */
#define EC_PUBLIC_KEY_LEN 33
/** The length of an uncompressed public key */
#define EC_PUBLIC_KEY_UNCOMPRESSED_LEN 65
/** The length of a message hash to EC sign */
#define EC_MESSAGE_HASH_LEN 32
/** The length of a compact signature produced by EC signing */
#define EC_SIGNATURE_LEN 64
/** The maximum encoded length of a DER encoded signature */
#define EC_SIGNATURE_DER_MAX_LEN 72

/** Indicates that a signature using ECDSA/secp256k1 is required */
#define EC_FLAG_ECDSA 0x1
/** Indicates that a signature using EC-Schnorr-SHA256 is required */
#define EC_FLAG_SCHNORR 0x2


/**
 * Sign a message hash with a private key, producing a compact signature.
 *
 * :param priv_key: The private key to sign with.
 * :param priv_key_len: The length of ``priv_key`` in bytes. Must be ``EC_PRIVATE_KEY_LEN``.
 * :param bytes: The message hash to sign.
 * :param bytes_len: The length of ``bytes`` in bytes. Must be ``EC_MESSAGE_HASH_LEN``.
 * :param flags: EC_FLAG_ flag values indicating desired behaviour.
 * :param bytes_out: Destination for the resulting compact signature.
 * :param len: The length of ``bytes_out`` in bytes. Must be ``EC_SIGNATURE_LEN``.
 */
WALLY_CORE_API int wally_ec_sig_from_bytes(
    const unsigned char *priv_key,
    size_t priv_key_len,
    const unsigned char *bytes,
    size_t bytes_len,
    uint32_t flags,
    unsigned char *bytes_out,
    size_t len);

/**
 * Verify a signed message hash.
 *
 * :param pub_key: The public key to verify with.
 * :param pub_key_len: The length of ``pub_key`` in bytes. Must be ``EC_PUBLIC_KEY_LEN``.
 * :param bytes: The message hash to verify.
 * :param bytes_len: The length of ``bytes`` in bytes. Must be ``EC_MESSAGE_HASH_LEN``.
 * :param flags: EC_FLAG_ flag values indicating desired behaviour.
 * :param sig: The compact signature of the message in ``bytes``.
 * :param sig_len: The length of ``sig`` in bytes. Must be ``EC_SIGNATURE_LEN``.
 */
WALLY_CORE_API int wally_ec_sig_verify(
    const unsigned char *pub_key,
    size_t pub_key_len,
    const unsigned char *bytes,
    size_t bytes_len,
    uint32_t flags,
    const unsigned char *sig,
    size_t sig_len);

#ifdef __cplusplus
}
#endif

#endif /* LIBWALLY_CORE_CRYPTO_H */

#include "internal.h"
#include "wally_crypto.h"
#include <stdbool.h>
#include "rsa_keygen.h"
#include "secp256k1.h"

#define EC_FLAGS_TYPES (EC_FLAG_ECDSA | EC_FLAG_SCHNORR)
#define EC_FLAGS_ALL (EC_FLAG_ECDSA | EC_FLAG_SCHNORR)

#define MSG_ALL_FLAGS (BITCOIN_MESSAGE_FLAG_HASH)

static const char MSG_PREFIX[] = "\x18" "Bitcoin Signed Message:\n";

static bool is_valid_ec_type(uint32_t flags)
{
    return ((flags & EC_FLAGS_TYPES) == EC_FLAG_ECDSA) ||
           ((flags & EC_FLAGS_TYPES) == EC_FLAG_SCHNORR);
}

int wally_ec_public_key_from_private_key(const unsigned char *priv_key, size_t priv_key_len,
                                         unsigned char *bytes_out, size_t len)
{
	size_t len_in_out = EC_PUBLIC_KEY_LEN;
	bool ok;
	secp256k1_pubkey pub;
	ok = priv_key && priv_key_len == EC_PRIVATE_KEY_LEN &&
		bytes_out && len == EC_PUBLIC_KEY_LEN &&
		pubkey_create(&pub, priv_key) &&
		pubkey_serialize(bytes_out, &len_in_out, &pub, PUBKEY_COMPRESSED) && 
		len_in_out == EC_PUBLIC_KEY_LEN;
	if (!ok && bytes_out)
		wally_clear(bytes_out, len);
	return ok ? WALLY_OK : WALLY_EINVAL;
}

int wally_ec_sig_from_bytes(const unsigned char *priv_key, size_t priv_key_len,
                            const unsigned char *bytes, size_t bytes_len,
                            uint32_t flags,
                            unsigned char *bytes_out, size_t len)
{
    if (!priv_key || priv_key_len != EC_PRIVATE_KEY_LEN ||
        !bytes || bytes_len != EC_MESSAGE_HASH_LEN ||
        !is_valid_ec_type(flags) || flags & ~EC_FLAGS_ALL ||
        !bytes_out || len != EC_SIGNATURE_LEN)
        return WALLY_EINVAL;

    if (flags & EC_FLAG_SCHNORR) {
        return WALLY_EINVAL;
    } else {
        secp256k1_ecdsa_signature sig_secp;

        if (!secp256k1_ecdsa_sign(&sig_secp, bytes, priv_key)) {
            wally_clear(&sig_secp, sizeof(sig_secp));
            return WALLY_EINVAL; /* invalid priv_key */
        }

        /* Note this function is documented as never failing */
        secp256k1_ecdsa_signature_serialize_compact(bytes_out, &sig_secp);
        wally_clear(&sig_secp, sizeof(sig_secp));
    }
    return WALLY_OK;
}

int wally_ec_sig_verify(const unsigned char *pub_key, size_t pub_key_len,
                        const unsigned char *bytes, size_t bytes_len,
                        uint32_t flags,
                        const unsigned char *sig, size_t sig_len)
{
	secp256k1_pubkey pub;
	secp256k1_ecdsa_signature sig_secp;
	bool ok;

	if (!pub_key || pub_key_len != EC_PUBLIC_KEY_LEN ||
		!bytes || bytes_len != EC_MESSAGE_HASH_LEN ||
		!is_valid_ec_type(flags) || flags & ~EC_FLAGS_ALL ||
		!sig || sig_len != EC_SIGNATURE_LEN)
	return WALLY_EINVAL;

	ok = pubkey_parse(&pub, pub_key, pub_key_len);

	if (flags & EC_FLAG_SCHNORR)
		ok = false;
	else
		ok = ok && secp256k1_ecdsa_verify(sig, bytes, &pub) == 0;

	wally_clear_2(&pub, sizeof(pub), &sig_secp, sizeof(sig_secp));
	return ok ? WALLY_OK : WALLY_EINVAL;
}

static SECP256K1_INLINE size_t varint_len(size_t bytes_len) {
    return bytes_len < 0xfd ? 1u : 3u;
}

int wally_format_bitcoin_message(const unsigned char *bytes, size_t bytes_len,
                                 uint32_t flags,
                                 unsigned char *bytes_out, size_t len,
                                 size_t *written)
{
    unsigned char buf[256], *msg_buf = bytes_out, *out;
    const bool do_hash = (flags & BITCOIN_MESSAGE_FLAG_HASH);
    size_t msg_len;

    if (written)
        *written = 0;

    if (!bytes || !bytes_len || bytes_len > BITCOIN_MESSAGE_MAX_LEN ||
        (flags & ~MSG_ALL_FLAGS) || !bytes_out || !written)
        return WALLY_EINVAL;

    msg_len = sizeof(MSG_PREFIX) - 1 + varint_len(bytes_len) + bytes_len;
    *written = do_hash ? SHA256_LEN : msg_len;

    if (len < *written)
        return WALLY_OK; /* Not enough output space, return required size */

    if (do_hash) {
        /* Ensure we have a suitable temporary buffer to serialise into */
        msg_buf = buf;
        if (msg_len > sizeof(buf)) {
            msg_buf = wally_malloc(msg_len);
            if (!msg_buf) {
                *written = 0;
                return WALLY_ENOMEM;
            }
        }
    }

    /* Serialise the message */
    out = msg_buf;
    memcpy(out, MSG_PREFIX, sizeof(MSG_PREFIX) - 1);
    out += sizeof(MSG_PREFIX) - 1;
    if (bytes_len < 0xfd)
        *out++ = bytes_len;
    else {
        *out++ = 0xfd;
        *out++ = bytes_len & 0xff;
        *out++ = bytes_len >> 8;
    }
    memcpy(out, bytes, bytes_len);

    if (do_hash) {
        wally_sha256d(msg_buf, msg_len, bytes_out, SHA256_LEN);
        wally_clear(msg_buf, msg_len);
        if (msg_buf != buf)
            wally_free(msg_buf);
    }
    return WALLY_OK;
}

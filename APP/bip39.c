#include "internal.h"
#include "hmac.h"
#include "wally_bip39.h"
#include "wally_crypto.h"


int  bip39_mnemonic_to_seed(const char *mnemonic, const char *password,
                            unsigned char *bytes_out, size_t len,
                            size_t *written)
{
	const size_t bip9_cost = 2048u;
	const char *prefix = "mnemonic";
	const size_t prefix_len = strlen(prefix);
	const size_t password_len = password ? strlen(password) : 0;
	const size_t salt_len = prefix_len + password_len;
	unsigned char *salt;
	int ret;

	if (written)
	    *written = 0;

	if (!mnemonic || !bytes_out || len != BIP39_SEED_LEN_512)
	    return WALLY_EINVAL;

	salt = wally_malloc(salt_len);
	if (!salt)
	    return WALLY_ENOMEM;

	memcpy(salt, prefix, prefix_len);
	if (password_len)
	    memcpy(salt + prefix_len, password, password_len);
	
	ret = pbkdf2_hmac_sha512((unsigned char *)mnemonic, strlen(mnemonic),
	                               salt, salt_len,
	                               bip9_cost, bytes_out, len);
	if (!ret && written)
	    *written = BIP39_SEED_LEN_512; /* Succeeded */

	wally_clear(salt, salt_len);
	wally_free(salt);

	return ret;
}

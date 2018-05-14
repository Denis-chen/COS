#include "internal.h"
#include "hex.h"

bool char_to_hex(unsigned char *val, char c)
{
	if (c >= '0' && c <= '9') {
		*val = c - '0';
		return true;
	}
	if (c >= 'a' && c <= 'f') {
		*val = c - 'a' + 10;
		return true;
	}
	if (c >= 'A' && c <= 'F') {
		*val = c - 'A' + 10;
		return true;
	}
	return false;
}

bool hex_decode(const char *str, size_t slen, void *buf, size_t bufsize)
{
	unsigned char v1, v2;
	unsigned char *p = buf;

	while (slen > 1) {
		if (!char_to_hex(&v1, str[0]) || !char_to_hex(&v2, str[1]))
			return false;
		if (!bufsize)
			return false;
		*(p++) = (v1 << 4) | v2;
		str += 2;
		slen -= 2;
		bufsize--;
	}
	return slen == 0 && bufsize == 0;
}

static char hexchar(unsigned int val)
{
	if (val < 10)
		return '0' + val;
	if (val < 16)
		return 'a' + val - 10;
	abort();
}

bool hex_encode(const void *buf, size_t bufsize, char *dest, size_t destsize)
{
	size_t i;

	if (destsize < hex_str_size(bufsize))
		return false;

	for (i = 0; i < bufsize; i++) {
		unsigned int c = ((const unsigned char *)buf)[i];
		*(dest++) = hexchar(c >> 4);
		*(dest++) = hexchar(c & 0xF);
	}
	*dest = '\0';

	return true;
}

int wally_hex_from_bytes(const unsigned char *bytes, size_t bytes_len,
                         char **output)
{
    if (output)
        *output = NULL;

    if (!bytes || !output)
        return WALLY_EINVAL;

    *output = wally_malloc(hex_str_size(bytes_len));
    if (!*output)
        return WALLY_ENOMEM;

    /* Note we ignore the return value as this call cannot fail */
    hex_encode(bytes, bytes_len, *output, hex_str_size(bytes_len));
    return WALLY_OK;
}

int wally_hex_to_bytes(const char *hex,
                       unsigned char *bytes_out, size_t len, size_t *written)
{
    size_t bytes_len = hex ? strlen(hex) : 0;

    if (written)
        *written = 0;

    if (!hex || !bytes_out || !len || bytes_len & 0x1)
        return WALLY_EINVAL;

    if (len < bytes_len / 2) {
        if (written)
            *written = bytes_len / 2;
        return WALLY_OK; /* Not enough room in bytes_out, or empty string */
    }

    len = bytes_len / 2; /* hex_decode expects exact length */
    if (!hex_decode(hex, bytes_len, bytes_out, len))
        return WALLY_EINVAL;

    if (written)
        *written = len;

    return WALLY_OK;
}

void print_hexstr_key(char *tag, const unsigned char *in, uint16_t len){
   char *out;
   wally_hex_from_bytes(in, len, &out);
   printf("%s : %s\r\n", tag, out);
   wally_clear(out, len);
   wally_free(out);
}


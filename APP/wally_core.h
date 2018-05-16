#ifndef WALLY_CORE_H
#define WALLY_CORE_H

#include <stdlib.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef WALLY_CORE_API
# if defined(_WIN32)
#  ifdef WALLY_CORE_BUILD
#   define WALLY_CORE_API __declspec(dllexport)
#  else
#   define WALLY_CORE_API
#  endif
# elif defined(__GNUC__) && defined(WALLY_CORE_BUILD)
#  define WALLY_CORE_API __attribute__ ((visibility ("default")))
# else
#  define WALLY_CORE_API
# endif
#endif

/** Return codes */
#define WALLY_OK      0 /** Success */
#define WALLY_ERROR  -1 /** General error */
#define WALLY_EINVAL -2 /** Invalid argument */
#define WALLY_ENOMEM -3 /** malloc() failed */

/**
 * Initialize wally.
 *
 * As wally is not currently threadsafe, this function should be called once
 * before threads are created by the application.
 *
 * :param flags: Flags controlling what to initialize. Currently must be zero.
 */
WALLY_CORE_API int wally_init(uint32_t flags);

/**
 * Free any internally allocated memory.
 *
 * :param flags: Flags controlling what to clean up. Currently must be zero.
 */
WALLY_CORE_API int wally_cleanup(uint32_t flags);

/**
 * Securely wipe memory.
 *
 * :param bytes: Memory to wipe
 * :param bytes_len: Size of ``bytes`` in bytes.
 */
WALLY_CORE_API int wally_bzero(
    void *bytes,
    size_t bytes_len);

/**
 * Securely wipe and then free a string allocated by the library.
 *
 * :param str: String to free (must be NUL terminated UTF-8).
 */
WALLY_CORE_API int wally_free_string(
    char *str);


/**
 * Convert bytes to a (lower-case) hexadecimal string.
 *
 * :param bytes: Bytes to convert.
 * :param bytes_len: Size of ``bytes`` in bytes.
 * :param output: Destination for the resulting hexadecimal string.
 *|    The string returned should be freed using `wally_free_string`.
 */
WALLY_CORE_API int wally_hex_from_bytes(
    const unsigned char *bytes,
    size_t bytes_len,
    char **output);

/**
 * Convert a hexadecimal string to bytes.
 *
 * :param hex: String to convert.
 * :param bytes_out: Where to store the resulting bytes.
 * :param len: The length of ``bytes_out`` in bytes.
 * :param written: Destination for the number of bytes written to ``bytes_out``.
 */
WALLY_CORE_API int wally_hex_to_bytes(
    const char *hex,
    unsigned char *bytes_out,
    size_t len,
    size_t *written);

WALLY_CORE_API void print_hexstr_key(
	char *tag, 
	const unsigned char *in, 
	uint16_t len);

#ifndef SWIG
/** The type of an overridable function to allocate memory */
typedef void *(*wally_malloc_t)(
    size_t size);

/** The type of an overridable function to free memory */
typedef void (*wally_free_t)(
    void *ptr);

/** The type of an overridable function to clear memory */
typedef void (*wally_bzero_t)(
    void *ptr, size_t len);

/** The type of an overridable function to generate an EC nonce */
typedef int (*wally_ec_nonce_t)(
    unsigned char *nonce32,
    const unsigned char *msg32,
    const unsigned char *key32,
    const unsigned char *algo16,
    void *data,
    unsigned int attempt
    );

/** Structure holding function pointers for overridable wally operations */
struct wally_operations {
    wally_malloc_t malloc_fn;
    wally_free_t free_fn;
    wally_bzero_t bzero_fn;
    wally_ec_nonce_t ec_nonce_fn;
};

/**
 * Fetch the current overridable operations used by wally.
 *
 * :param output: Destination for the overridable operations.
 */
WALLY_CORE_API int wally_get_operations(
    struct wally_operations *output);

/**
 * Set the current overridable operations used by wally.
 *
 * :param ops: The overridable operations to set.
 */
WALLY_CORE_API int wally_set_operations(
    const struct wally_operations *ops);

#endif /* SWIG */

#ifdef __cplusplus
}
#endif

#endif /* WALLY_CORE_H */

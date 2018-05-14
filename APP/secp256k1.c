/**********************************************************************
 * Copyright (c) 2013-2015 Pieter Wuille                              *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#include "secp256k1.h"

#include "util.h"
#include "field_impl.h"
#include "scalar_impl.h"
#include "group_impl.h"
#include "wally_crypto.h"
#include "ecdsa.h"
#include "ecc.h"
#include "ecc_byte.h"
#include "eckey_impl.h"

static int secp256k1_pubkey_load(secp256k1_ge* ge, const secp256k1_pubkey* pubkey) {
    if (sizeof(secp256k1_ge_storage) == 64) {
        /* When the secp256k1_ge_storage type is exactly 64 byte, use its
         * representation inside secp256k1_pubkey, as conversion is very fast.
         * Note that secp256k1_pubkey_save must use the same representation. */
        secp256k1_ge_storage s;
        memcpy(&s, &pubkey->data[0], 64);
        secp256k1_ge_from_storage(ge, &s);
    } else {
        /* Otherwise, fall back to 32-byte big endian for X and Y. */
        secp256k1_fe x, y;
        secp256k1_fe_set_b32(&x, pubkey->data);
        secp256k1_fe_set_b32(&y, pubkey->data + 32);
        secp256k1_ge_set_xy(ge, &x, &y);
    }
    return 1;
}

static void secp256k1_pubkey_save(secp256k1_pubkey* pubkey, secp256k1_ge* ge) {
    if (sizeof(secp256k1_ge_storage) == 64) {
        secp256k1_ge_storage s;
        secp256k1_ge_to_storage(&s, ge);
        memcpy(&pubkey->data[0], &s, 64);
    } else {
        secp256k1_fe_get_b32(pubkey->data, &ge->x);
        secp256k1_fe_get_b32(pubkey->data + 32, &ge->y);
    }
}

int secp256k1_ec_pubkey_parse(secp256k1_pubkey* pubkey, const unsigned char *input, size_t inputlen) {
    secp256k1_ge Q;

    memset(pubkey, 0, sizeof(*pubkey));
    if (!secp256k1_eckey_pubkey_parse(&Q, input, inputlen)) {
        return 0;
    }
    secp256k1_pubkey_save(pubkey, &Q);
    secp256k1_ge_clear(&Q);
    return 1;
}

int secp256k1_ec_pubkey_serialize(unsigned char *output, size_t *outputlen, const secp256k1_pubkey* pubkey, unsigned int flags) {
    secp256k1_ge Q;
    size_t len;
    int ret = 0;

    len = *outputlen;
    *outputlen = 0;
    memset(output, 0, len);
    if (secp256k1_pubkey_load(&Q, pubkey)) {
        ret = secp256k1_eckey_pubkey_serialize(&Q, output, &len, flags & SECP256K1_FLAGS_BIT_COMPRESSION);
        if (ret) {
            *outputlen = len;
        }
    }
    return ret;
}

static void secp256k1_ecdsa_signature_load(secp256k1_scalar* r, secp256k1_scalar* s, const secp256k1_ecdsa_signature* sig) {
    if (sizeof(secp256k1_scalar) == 32) {
        /* When the secp256k1_scalar type is exactly 32 byte, use its
         * representation inside secp256k1_ecdsa_signature, as conversion is very fast.
         * Note that secp256k1_ecdsa_signature_save must use the same representation. */
        memcpy(r, &sig->data[0], 32);
        memcpy(s, &sig->data[32], 32);
    } else {
        secp256k1_scalar_set_b32(r, &sig->data[0], NULL);
        secp256k1_scalar_set_b32(s, &sig->data[32], NULL);
    }
}

static void secp256k1_ecdsa_signature_save(secp256k1_ecdsa_signature* sig, const secp256k1_scalar* r, const secp256k1_scalar* s) {
    if (sizeof(secp256k1_scalar) == 32) {
        memcpy(&sig->data[0], r, 32);
        memcpy(&sig->data[32], s, 32);
    } else {
        secp256k1_scalar_get_b32(&sig->data[0], r);
        secp256k1_scalar_get_b32(&sig->data[32], s);
    }
}

int secp256k1_ecdsa_signature_parse_compact(secp256k1_ecdsa_signature* sig, const unsigned char *input64) {
    secp256k1_scalar r, s;
    int ret = 1;
    int overflow = 0;

    secp256k1_scalar_set_b32(&r, &input64[0], &overflow);
    ret &= !overflow;
    secp256k1_scalar_set_b32(&s, &input64[32], &overflow);
    ret &= !overflow;
    if (ret) {
        secp256k1_ecdsa_signature_save(sig, &r, &s);
    } else {
        memset(sig, 0, sizeof(*sig));
    }
    return ret;
}


int secp256k1_ecdsa_signature_serialize_compact(unsigned char *output64, const secp256k1_ecdsa_signature* sig) {
    secp256k1_scalar r, s;

    secp256k1_ecdsa_signature_load(&r, &s, sig);
    secp256k1_scalar_get_b32(&output64[0], &r);
    secp256k1_scalar_get_b32(&output64[32], &s);
    return 1;
}

static int secp256k1_fe_get(secp256k1_pubkey *tKey, const secp256k1_pubkey *pubkey){
	secp256k1_ge Q;
	secp256k1_fe x, y;
	secp256k1_fe_set_b32(&x, pubkey->data);
	secp256k1_fe_set_b32(&y, pubkey->data + 32);
	secp256k1_ge_set_xy(&Q, &x, &y);

	secp256k1_pubkey_save(tKey, &Q);
}

int secp256k1_ecdsa_verify(const unsigned char *sig, const unsigned char *msg32, const secp256k1_pubkey *pubkey) {
	int ret = 1;
	int overflow = 0;
	secp256k1_pubkey tKey;
	ECC_G_STR ecc_glb_str;
	MATH_G_STR math_glb_str;
	UINT32 Signr[CurveLength];
	UINT32 Signs[CurveLength];
	UINT32 QxKey[CurveLength];
	UINT32 QyKey[CurveLength];
	UINT32 digest[CurveLength];

	scalar_set_b32(digest, msg32);
	scalar_set_b32(Signr, sig);
	scalar_set_b32(Signs, sig+32);
	secp256k1_fe_get(&tKey, pubkey);
	print_hexstr_key("pubkey64", tKey.data, sizeof(tKey.data));
	print_hexstr_key("signdata", sig, 64);
	scalar_set_b32(QxKey, tKey.data);
	scalar_set_b32(QyKey, tKey.data+32);
	ECC_para_initial((ECC_G_STR *)(&ecc_glb_str), CurveLength, (UINT32 *)P_Array, (UINT32 *)a_Array, (UINT32 *)b_Array, (UINT32 *)N_Array, (UINT32 *)BaseX_Array, (UINT32 *)BaseY_Array);
	ret = ECDSA_verify((ECC_G_STR *)(&ecc_glb_str), (MATH_G_STR *)(&math_glb_str), digest, QxKey, QyKey, Signr, Signs);
	return ret;
}


int secp256k1_ecdsa_sign(secp256k1_ecdsa_signature *signature, const unsigned char *msg32, const unsigned char *seckey) {
	int ret = 0;
	int overflow = 0;
	secp256k1_scalar r, s;
	ECC_G_STR ecc_glb_str;
	MATH_G_STR math_glb_str;
	unsigned char cSignr[CurveLength*4];
	unsigned char cSigns[CurveLength*4];
	UINT32 Signr[CurveLength];
	UINT32 Signs[CurveLength];
	UINT32 digest[CurveLength];
	UINT32 dkey[CurveLength];

	memset(Signr, 0, sizeof(Signr));
	memset(Signs, 0, sizeof(Signs));
	scalar_set_b32(dkey, seckey);
	scalar_set_b32(digest, msg32);
	ECC_para_initial((ECC_G_STR *)(&ecc_glb_str), CurveLength, (UINT32 *)P_Array, (UINT32 *)a_Array, (UINT32 *)b_Array, (UINT32 *)N_Array, (UINT32 *)BaseX_Array, (UINT32 *)BaseY_Array);
	ret = ECDSA_sign((ECC_G_STR *)(&ecc_glb_str), (MATH_G_STR *)(&math_glb_str), digest, dkey, Signr, Signs);
	if (!ret) {
		scalar_get_b32(cSignr, Signr);
		scalar_get_b32(cSigns, Signs);
		secp256k1_scalar_set_b32(&r, cSignr, &overflow);
		secp256k1_scalar_set_b32(&s, cSigns, &overflow);
		secp256k1_ecdsa_signature_save(signature, &r, &s);
		secp256k1_scalar_clear(&r);
		secp256k1_scalar_clear(&s);
	} else {
		memset(signature, 0, sizeof(*signature));
	}
	return !ret;
}


int secp256k1_ec_pubkey_create(secp256k1_pubkey *pubkey, const unsigned char *seckey) {
	int ret = 0;
	ECC_G_STR ecc_glb_str;
	MATH_G_STR math_glb_str;
	UINT32 qxKey[CurveLength];
	UINT32 qyKey[CurveLength];
	UINT32 key[CurveLength];
	scalar_set_b32(key, seckey);
	enable_module(BIT_PKI|BIT_UAC);
	ECC_para_initial((ECC_G_STR *)(&ecc_glb_str), CurveLength, (UINT32 *)P_Array, (UINT32 *)a_Array, (UINT32 *)b_Array, (UINT32 *)N_Array, (UINT32 *)BaseX_Array, (UINT32 *)BaseY_Array);
	ret = ECC_PM((ECC_G_STR *)(&ecc_glb_str), key, (UINT32 *)BaseX_Array, (UINT32 *)BaseY_Array, qxKey, qyKey);
	memset(pubkey, 0, sizeof(*pubkey));
	memcpy(pubkey->data, qxKey, EC_PRIVATE_KEY_LEN);
	memcpy(pubkey->data+EC_PRIVATE_KEY_LEN, qyKey, EC_PRIVATE_KEY_LEN);
	return ret == 0 ? 1 : 0;
}

int secp256k1_ec_privkey_tweak_add(unsigned char *seckey, const unsigned char *tweak) {
	UINT8 out_len = 0;
	UINT32 term[CurveLength];
	UINT32 sec[CurveLength];
	UINT32 out[CurveLength];

	scalar_set_b32(term, tweak);
	scalar_set_b32(sec, seckey);
	ECC_mod_add_sub(sec, CurveLength, term, CurveLength, (UINT32*)N_Array, CurveLength, out, &out_len, 0x02);
	memset(seckey, 0, 32);
	scalar_get_b32(seckey, out);
	return 1;
}

int secp256k1_ec_pubkey_tweak_add(secp256k1_pubkey *pubkey, const unsigned char *tweak) {
	UINT8 out_len = 0;
	UINT32 pubkeyt[CurveLength];
	UINT32 tweakt[CurveLength];
	UINT32 out[CurveLength];
	unsigned char tmpKey[CurveLength];

	scalar_set_b32(pubkeyt, pubkey->data);
	scalar_set_b32(tweakt, tweak);
	ECC_mod_add_sub(pubkeyt, CurveLength, tweakt, CurveLength, (UINT32*)N_Array, CurveLength, out, &out_len, 0x02);
	scalar_get_b32(tmpKey, out);
	memcpy(pubkey->data, tmpKey, sizeof(pubkey));
	return 1;
}


#ifndef ECC_BYTE
#define ECC_BYTE
#include "types.h"
#include "basic-config.h"

#ifdef _ECC_256
const UINT32 CurveLength = 8;
const UINT32 P_Array[8] = { 0xFFFFFC2F, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF };
const UINT32 a_Array[8] = { 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000 };
const UINT32 b_Array[8] = { 0x00000007, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000 };
const UINT32 N_Array[8] = { 0xD0364141, 0xBFD25E8C, 0xAF48A03B, 0xBAAEDCE6, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF };
const UINT32 BaseX_Array[8] = { 0x16F81798, 0x59F2815B, 0x2DCE28D9, 0x029BFCDB, 0xCE870B07, 0x55A06295, 0xF9DCBBAC, 0x79BE667E };
const UINT32 BaseY_Array[8] = { 0xFB10D4B8, 0x9C47D08F, 0xA6855419, 0xFD17B448, 0x0E1108A8, 0x5DA4FBFC, 0x26A3C465, 0x483ADA77 };

#endif

void scalar_set_b32(UINT32 *r, const unsigned char *b32) {
    r[0] = (uint32_t)b32[31] | (uint32_t)b32[30] << 8 | (uint32_t)b32[29] << 16 | (uint32_t)b32[28] << 24;
    r[1] = (uint32_t)b32[27] | (uint32_t)b32[26] << 8 | (uint32_t)b32[25] << 16 | (uint32_t)b32[24] << 24;
    r[2] = (uint32_t)b32[23] | (uint32_t)b32[22] << 8 | (uint32_t)b32[21] << 16 | (uint32_t)b32[20] << 24;
    r[3] = (uint32_t)b32[19] | (uint32_t)b32[18] << 8 | (uint32_t)b32[17] << 16 | (uint32_t)b32[16] << 24;
    r[4] = (uint32_t)b32[15] | (uint32_t)b32[14] << 8 | (uint32_t)b32[13] << 16 | (uint32_t)b32[12] << 24;
    r[5] = (uint32_t)b32[11] | (uint32_t)b32[10] << 8 | (uint32_t)b32[9] << 16 | (uint32_t)b32[8] << 24;
    r[6] = (uint32_t)b32[7] | (uint32_t)b32[6] << 8 | (uint32_t)b32[5] << 16 | (uint32_t)b32[4] << 24;
    r[7] = (uint32_t)b32[3] | (uint32_t)b32[2] << 8 | (uint32_t)b32[1] << 16 | (uint32_t)b32[0] << 24;
}

void scalar_get_b32(unsigned char *bin, const UINT32* a) {
    bin[0] = a[7] >> 24; bin[1] = a[7] >> 16; bin[2] = a[7] >> 8; bin[3] = a[7];
    bin[4] = a[6] >> 24; bin[5] = a[6] >> 16; bin[6] = a[6] >> 8; bin[7] = a[6];
    bin[8] = a[5] >> 24; bin[9] = a[5] >> 16; bin[10] = a[5] >> 8; bin[11] = a[5];
    bin[12] = a[4] >> 24; bin[13] = a[4] >> 16; bin[14] = a[4] >> 8; bin[15] = a[4];
    bin[16] = a[3] >> 24; bin[17] = a[3] >> 16; bin[18] = a[3] >> 8; bin[19] = a[3];
    bin[20] = a[2] >> 24; bin[21] = a[2] >> 16; bin[22] = a[2] >> 8; bin[23] = a[2];
    bin[24] = a[1] >> 24; bin[25] = a[1] >> 16; bin[26] = a[1] >> 8; bin[27] = a[1];
    bin[28] = a[0] >> 24; bin[29] = a[0] >> 16; bin[30] = a[0] >> 8; bin[31] = a[0];
}
#endif

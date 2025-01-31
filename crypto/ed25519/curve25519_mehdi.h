/* The MIT License (MIT)
 * 
 * Copyright (c) 2015 mehdi sotoodeh
 * 
 * Permission is hereby granted, free of charge, to any person obtaining 
 * a copy of this software and associated documentation files (the 
 * "Software"), to deal in the Software without restriction, including 
 * without limitation the rights to use, copy, modify, merge, publish, 
 * distribute, sublicense, and/or sell copies of the Software, and to 
 * permit persons to whom the Software is furnished to do so, subject to 
 * the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included 
 * in all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS 
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF 
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. 
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY 
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, 
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE 
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include "BaseTypes.h"

#define U_WORD          U64
#define S_WORD          S64
#define WORDSIZE_64
#define W64(lo,hi)      ((U64)hi<<32)+lo

#define K_BYTES         32
#define K_WORDS         (K_BYTES/sizeof(U_WORD))

#define W256(x0,x1,x2,x3,x4,x5,x6,x7) {W64(x0,x1),W64(x2,x3),W64(x4,x5),W64(x6,x7)}

/* Affine coordinates */
typedef struct {
    U_WORD x[K_WORDS];
    U_WORD y[K_WORDS];
} Affine_POINT;

/* Projective coordinates */
typedef struct {
    U_WORD x[K_WORDS];  /* x/z */
    U_WORD y[K_WORDS];  /* y/z */
    U_WORD z[K_WORDS];
    U_WORD t[K_WORDS];  /* xy/z */
} Ext_POINT;

/* pre-computed, extended point */
typedef struct
{
    U_WORD YpX[K_WORDS];        /* Y+X */
    U_WORD YmX[K_WORDS];        /* Y-X */
    U_WORD T2d[K_WORDS];        /* 2d*T */
    U_WORD Z2[K_WORDS];         /* 2*Z */
} PE_POINT;

/* pre-computed, Affine point */
typedef struct
{
    U_WORD YpX[K_WORDS];        /* Y+X */
    U_WORD YmX[K_WORDS];        /* Y-X */
    U_WORD T2d[K_WORDS];        /* 2d*T */
} PA_POINT;

typedef struct {
    U_WORD bl[K_WORDS];
    U_WORD zr[K_WORDS];
    PE_POINT BP;
} EDP_BLINDING_CTX;

extern const U8 ecp_BasePoint[K_BYTES];

const U_WORD _w_P[K_WORDS] = 
    W256(0xFFFFFFED,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0x7FFFFFFF);

/* Maximum number of prime p that fits into 256-bits */
const U_WORD _w_maxP[K_WORDS] = /* 2*P < 2**256 */
    W256(0xFFFFFFDA,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF);

const U_WORD _w_di[K_WORDS] = /* 1/d */
    W256(0xCDC9F843,0x25E0F276,0x4279542E,0x0B5DD698,0xCDB9CF66,0x2B162114,0x14D5CE43,0x40907ED2);

/* Return point Q = k*P */
void ecp_PointMultiply(U8 *Q, IN const U8 *P, IN const U8 *K, IN int len);

/* -- utils ----------------------------------------------------------------- */

/* Convert little-endian byte array to little-endian word array */
U_WORD* ecp_BytesToWords(OUT U_WORD *Y, IN const U8 *X);
/* Convert little-endian word array to little-endian byte array */
U8* ecp_EncodeInt(OUT U8 *Y, IN const U_WORD *X, IN U8 parity);
U8 ecp_DecodeInt(OUT U_WORD *Y, IN const U8 *X);

/* -- base point order ------------------------------------------------------ */

/* Z = (X*Y)/R mod BPO */
void eco_MontMul(OUT U_WORD *Z, IN const U_WORD *X, IN const U_WORD *Y);
/* Return Y = X*R mod BPO */
void eco_ToMont(OUT U_WORD *Y, IN const U_WORD *X);
/* Return Y = X/R mod BPO */
void eco_FromMont(OUT U_WORD *Y, IN const U_WORD *X);
/* Calculate Y = X**E mod BPO */
void eco_ExpModBPO(OUT U_WORD *Y, IN const U_WORD *X, IN const U8 *E, IN int bytes);
/* Calculate Y = 1/X mod BPO */
void eco_InvModBPO(OUT U_WORD *Y, IN const U_WORD *X);
/* Return Y = D mod BPO where D is 512-bit big-endian byte array (i.e SHA512 digest) */
void eco_DigestToWords( OUT U_WORD *Y, IN const U8 *D);
/* Z = X + Y mod BPO */
void eco_AddReduce(OUT U_WORD *Z, IN const U_WORD *X, IN const U_WORD *Y);
/* X mod BPO */
void eco_Mod(U_WORD *X);

#define ed25519_PackPoint(buff, Y, parity) ecp_EncodeInt(buff, Y, (U8)(parity & 1))

/* -- big-number ------------------------------------------------------------ */
U_WORD ecp_Add(U_WORD* Z, const U_WORD* X, const U_WORD* Y);
S_WORD ecp_Sub(U_WORD* Z, const U_WORD* X, const U_WORD* Y);
void ecp_SetValue(U_WORD* X, U_WORD value);
void ecp_Copy(U_WORD* Y, const U_WORD* X);
void ecp_AddReduce(U_WORD* Z, const U_WORD* X, const U_WORD* Y);
void ecp_SubReduce(U_WORD* Z, const U_WORD* X, const U_WORD* Y);
void ecp_MulReduce(U_WORD* Z, const U_WORD* X, const U_WORD* Y);
void ecp_SqrReduce(U_WORD* Y, const U_WORD* X);
void ecp_ModExp2523(U_WORD *Y, const U_WORD *X);
void ecp_Inverse(U_WORD *out, const U_WORD *z);
void ecp_MulMod(U_WORD* Z, const U_WORD* X, const U_WORD* Y);
void ecp_Mul(U_WORD* Z, const U_WORD* X, const U_WORD* Y);
void ecp_Mod(U_WORD* X);
int ecp_CmpNE(const U_WORD* X, const U_WORD* Y);
int ecp_CmpLT(const U_WORD* X, const U_WORD* Y);
/* Calculate: Y = [b:X] mod BPO */
void eco_ReduceHiWord(U_WORD* Y, U_WORD b, const U_WORD* X);

/* -- ed25519 --------------------------------------------------------------- */
void ed25519_CalculateX(OUT U_WORD *X, IN const U_WORD *Y, U_WORD parity);
void edp_AddAffinePoint(Ext_POINT *p, const PA_POINT *q);
void edp_AddBasePoint(Ext_POINT *p);
void edp_AddPoint(Ext_POINT *r, const Ext_POINT *p, const PE_POINT *q);
void edp_DoublePoint(Ext_POINT *p);
void edp_ExtPoint2PE(PE_POINT *r, const Ext_POINT *p);
void ecp_4Folds(U8* Y, const U_WORD* X);
void ecp_8Folds(U8* Y, const U_WORD* X);

#ifdef __cplusplus
}
#endif
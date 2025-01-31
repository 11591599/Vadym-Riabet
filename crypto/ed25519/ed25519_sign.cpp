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

#include "curve25519_mehdi.h"

/*
 * Arithmetic on twisted Edwards curve y^2 - x^2 = 1 + dx^2y^2
 * with d = -(121665/121666) mod p
 *      d = 0x52036CEE2B6FFE738CC740797779E89800700A4D4141D8AB75EB4DCA135978A3
 *      p = 2**255 - 19
 *      p = 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFED
 * Base point: y=4/5 mod p
 *      x = 0x216936D3CD6E53FEC0A4E231FDD6DC5C692CC7609525A7B2C9562D608F25D51A
 *      y = 0x6666666666666666666666666666666666666666666666666666666666666658
 * Base point order:
 *      l = 2**252 + 27742317777372353535851937790883648493
 *      l = 0x1000000000000000000000000000000014DEF9DEA2F79CD65812631A5CF5D3ED
 */

const U_WORD _w_2d[K_WORDS] = /* 2*d */
    W256(0x26B2F159,0xEBD69B94,0x8283B156,0x00E0149A,0xEEF3D130,0x198E80F2,0x56DFFCE7,0x2406D9DC);

/*
    Assumptions: pre-computed q, q->Z=1
    Cost: 7M + 7add
    Return: P = P + Q
*/
void edp_AddAffinePoint(Ext_POINT *p, const PA_POINT *q) {
    U_WORD a[K_WORDS], b[K_WORDS], c[K_WORDS], d[K_WORDS], e[K_WORDS];
    ecp_SubReduce(a, p->y, p->x);           /* A = (Y1-X1)*(Y2-X2) */
    ecp_MulReduce(a, a, q->YmX);
    ecp_AddReduce(b, p->y, p->x);           /* B = (Y1+X1)*(Y2+X2) */
    ecp_MulReduce(b, b, q->YpX);
    ecp_MulReduce(c, p->t, q->T2d);         /* C = T1*2d*T2 */
    ecp_AddReduce(d, p->z, p->z);           /* D = Z1*2*Z2 (Z2=1)*/
    ecp_SubReduce(e, b, a);                 /* E = B-A */
    ecp_AddReduce(b, b, a);                 /* H = B+A */
    ecp_SubReduce(a, d, c);                 /* F = D-C */
    ecp_AddReduce(d, d, c);                 /* G = D+C */

    ecp_MulReduce(p->x, e, a);              /* E*F */
    ecp_MulReduce(p->y, b, d);              /* H*G */
    ecp_MulReduce(p->t, e, b);              /* E*H */
    ecp_MulReduce(p->z, d, a);              /* G*F */
}

/*
    Reference: http://eprint.iacr.org/2008/522
    Cost: 4M + 4S + 7add
    Return: P = 2*P
*/
void edp_DoublePoint(Ext_POINT *p) {
    U_WORD a[K_WORDS], b[K_WORDS], c[K_WORDS], d[K_WORDS], e[K_WORDS];

    ecp_SqrReduce(a, p->x);         /* A = X1^2 */
    ecp_SqrReduce(b, p->y);         /* B = Y1^2 */
    ecp_SqrReduce(c, p->z);         /* C = 2*Z1^2 */
    ecp_AddReduce(c, c, c);
    ecp_SubReduce(d, _w_maxP, a);   /* D = -A */

    ecp_SubReduce(a, d, b);         /* H = D-B */
    ecp_AddReduce(d, d, b);         /* G = D+B */
    ecp_SubReduce(b, d, c);         /* F = G-C */
    ecp_AddReduce(e, p->x, p->y);   /* E = (X1+Y1)^2-A-B = (X1+Y1)^2+H */
    ecp_SqrReduce(e, e);
    ecp_AddReduce(e, e, a);

    ecp_MulReduce(p->x, e, b);      /* E*F */
    ecp_MulReduce(p->y, a, d);      /* H*G */
    ecp_MulReduce(p->z, d, b);      /* G*F */
    ecp_MulReduce(p->t, e, a);      /* E*H */
}

void edp_ExtPoint2PE(PE_POINT *r, const Ext_POINT *p)
{
    ecp_AddReduce(r->YpX, p->y, p->x);
    ecp_SubReduce(r->YmX, p->y, p->x);
    ecp_MulReduce(r->T2d, p->t, _w_2d);
    ecp_AddReduce(r->Z2, p->z, p->z);
}
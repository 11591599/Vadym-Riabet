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

.include "crypto/ed25519/defines.inc"

# _______________________________________________________________________
#
#   Calculate: Y = [b:X] mod BPO
#   void eco_ReduceHiWord(U64* Y, U64 b, const U64* X)
#
#   Return Y = X + b*R mod BPO, where R = 2^256 mod BPO
#   Since -R is 129-bits, we can save some multiplication by
#   calculating: Y = X - b*(-R) mod BPO
#   -R mod BPO = { 0x812631A5CF5D3ED0,0x4DEF9DEA2F79CD65,1,0 }#
# _______________________________________________________________________
    PUBPROC eco_ReduceHiWord

    PushB
    SaveArg1

.equ  Y,  ARG1M
.equ  b,  ARG2
.equ  X,  ARG3

    mov     b,B2
    LOADA   X

    MULSET  B1,B0,$0x812631A5CF5D3ED0,B2
    MULT    $0x4DEF9DEA2F79CD65,B2
    xor     B3,B3
    add     ACL,B1
    adc     ACH,B2
    adc     B3,B3

    SUBA    B3,B2,B1,B0

    # Add BPO if there is a carry
    sbb     ACL,ACL

    # B = BPO & carry
    mov     $0x5812631A5CF5D3ED,B0
    mov     $0x14DEF9DEA2F79CD6,B1
    xor     B2,B2
    mov     $0x1000000000000000,B3

    and     ACL,B0
    and     ACL,B1
    and     ACL,B3
    ADDA    B3,B2,B1,B0

    STOREA  Y

    RestoreArg1
    PopB
    ret
  
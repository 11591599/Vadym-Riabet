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

#include <stdint.h>

typedef unsigned char       U8;
typedef signed   char       S8;

typedef uint16_t            U16;
typedef int16_t             S16;
typedef uint32_t            U32;
typedef int32_t             S32;
typedef uint64_t            U64;
typedef int64_t             S64;

union M16 {
    U16 u16;
    S16 s16;
    U8 bytes[2];
    struct { U8 b0, b1; } u8;
    struct { U8 b0; S8 b1; } s8;
};

union M32 {
    U32 u32;
    S32 s32;
    U8 bytes[4];
    struct { U16 w0, w1; } u16;
    struct { U16 w0; S16 w1; } s16;
    struct { U8 b0, b1, b2, b3; } u8;
    struct { M16 lo, hi; } m16;
};

union M64 {
    U64 u64;
    S64 s64;
    U8 bytes[8];
    struct { U32 lo, hi; } u32;
    struct { U32 lo; S32 hi; } s32;
    struct { U16 w0, w1, w2, w3; } u16;
    struct { U8 b0, b1, b2, b3, b4, b5, b6, b7; } u8;
    struct { M32 lo, hi; } m32;
};

#define IN
#define OUT
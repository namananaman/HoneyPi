/* crypto/sha/sha.h */
/* Copyright (C) 1995-1998 Eric Young (eay@cryptsoft.com)
 * All rights reserved.
 *
 * This package is an SSL implementation written
 * by Eric Young (eay@cryptsoft.com).
 * The implementation was written so as to conform with Netscapes SSL.
 * 
 * This library is free for commercial and non-commercial use as long as
 * the following conditions are aheared to.  The following conditions
 * apply to all code found in this distribution, be it the RC4, RSA,
 * lhash, DES, etc., code; not just the SSL code.  The SSL documentation
 * included with this distribution is covered by the same copyright terms
 * except that the holder is Tim Hudson (tjh@cryptsoft.com).
 * 
 * Copyright remains Eric Young's, and as such any Copyright notices in
 * the code are not to be removed.
 * If this package is used in a product, Eric Young should be given attribution
 * as the author of the parts of the library used.
 * This can be in the form of a textual message at program startup or
 * in documentation (online or textual) provided with the package.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    "This product includes cryptographic software written by
 *     Eric Young (eay@cryptsoft.com)"
 *    The word 'cryptographic' can be left out if the rouines from the library
 *    being used are not cryptographic related :-).
 * 4. If you include any Windows specific code (or a derivative thereof) from 
 *    the apps directory (application code) you must include an acknowledgement:
 *    "This product includes software written by Tim Hudson (tjh@cryptsoft.com)"
 * 
 * THIS SOFTWARE IS PROVIDED BY ERIC YOUNG ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 * 
 * The licence and distribution terms for any publically available version or
 * derivative of this code cannot be changed.  i.e. this code cannot simply be
 * copied and put under another distribution licence
 * [including the GNU Public Licence.]
 */

#ifndef HEADER_SHA_H
#define HEADER_SHA_H


#ifdef  __cplusplus
extern "C" {
#endif

/*
 * !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
 * ! SHA_LONG has to be at least 32 bits wide. If it's wider, then !
 * ! SHA_LONG_LOG2 has to be defined along.                        !
 * !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
 */

#if defined(OPENSSL_SYS_WIN16) || defined(__LP32__)
#define SHA_LONG unsigned long
#elif defined(OPENSSL_SYS_CRAY) || defined(__ILP64__)
#define SHA_LONG unsigned long
#define SHA_LONG_LOG2 3
#else
#define SHA_LONG unsigned int
#endif

#define SHA_LBLOCK  16
#define SHA_CBLOCK  (SHA_LBLOCK*4)  /* SHA treats input data as a
           * contiguous array of 32 bit
           * wide big-endian values. */
#define SHA_LAST_BLOCK  (SHA_CBLOCK-8)
#define SHA_DIGEST_LENGTH 20

typedef struct SHAstate_st
  {
  SHA_LONG h0,h1,h2,h3,h4;
  SHA_LONG Nl,Nh;
  SHA_LONG data[SHA_LBLOCK];
  unsigned int num;
  } SHA_CTX;

#ifndef OPENSSL_NO_SHA0
#ifdef OPENSSL_FIPS
int private_SHA_Init(SHA_CTX *c);
#endif
int SHA_Init(SHA_CTX *c);
int SHA_Update(SHA_CTX *c, const void *data, size_t len);
int SHA_Final(unsigned char *md, SHA_CTX *c);
unsigned char *SHA(const unsigned char *d, size_t n, unsigned char *md);
void SHA_Transform(SHA_CTX *c, const unsigned char *data);
#endif
#ifndef OPENSSL_NO_SHA1
int SHA1_Init(SHA_CTX *c);
int SHA1_Update(SHA_CTX *c, const void *data, size_t len);
int SHA1_Final(unsigned char *md, SHA_CTX *c);
unsigned char *SHA1(const unsigned char *d, size_t n, unsigned char *md);
void SHA1_Transform(SHA_CTX *c, const unsigned char *data);
#endif

#define SHA256_CBLOCK (SHA_LBLOCK*4)  /* SHA-256 treats input data as a
           * contiguous array of 32 bit
           * wide big-endian values. */
#define SHA224_DIGEST_LENGTH  28
#define SHA256_DIGEST_LENGTH  32

typedef struct SHA256state_st
  {
  SHA_LONG h[8];
  SHA_LONG Nl,Nh;
  SHA_LONG data[SHA_LBLOCK];
  unsigned int num,md_len;
  } SHA256_CTX;

#ifndef OPENSSL_NO_SHA256
int SHA224_Init(SHA256_CTX *c);
int SHA224_Update(SHA256_CTX *c, const void *data, size_t len);
int SHA224_Final(unsigned char *md, SHA256_CTX *c);
unsigned char *SHA224(const unsigned char *d, size_t n,unsigned char *md);
int SHA256_Init(SHA256_CTX *c);
int SHA256_Update(SHA256_CTX *c, const void *data, size_t len);
int SHA256_Final(unsigned char *md, SHA256_CTX *c);
unsigned char *SHA256(const unsigned char *d, size_t n,unsigned char *md);
void SHA256_Transform(SHA256_CTX *c, const unsigned char *data);
#endif

#define SHA384_DIGEST_LENGTH  48
#define SHA512_DIGEST_LENGTH  64

#ifndef OPENSSL_NO_SHA512
/*
 * Unlike 32-bit digest algorithms, SHA-512 *relies* on SHA_LONG64
 * being exactly 64-bit wide. See Implementation Notes in sha512.c
 * for further details.
 */
#define SHA512_CBLOCK (SHA_LBLOCK*8)  /* SHA-512 treats input data as a
           * contiguous array of 64 bit
           * wide big-endian values. */
#if (defined(_WIN32) || defined(_WIN64)) && !defined(__MINGW32__)
#define SHA_LONG64 unsigned __int64
#define U64(C)     C##UI64
#elif defined(__arch64__)
#define SHA_LONG64 unsigned long
#define U64(C)     C##UL
#else
#define SHA_LONG64 unsigned long long
#define U64(C)     C##ULL
#endif

typedef struct SHA512state_st
  {
  SHA_LONG64 h[8];
  SHA_LONG64 Nl,Nh;
  union {
    SHA_LONG64  d[SHA_LBLOCK];
    unsigned char p[SHA512_CBLOCK];
  } u;
  unsigned int num,md_len;
  } SHA512_CTX;
#endif

#ifndef OPENSSL_NO_SHA512
int SHA384_Init(SHA512_CTX *c);
int SHA384_Update(SHA512_CTX *c, const void *data, size_t len);
int SHA384_Final(unsigned char *md, SHA512_CTX *c);
unsigned char *SHA384(const unsigned char *d, size_t n,unsigned char *md);
int SHA512_Init(SHA512_CTX *c);
int SHA512_Update(SHA512_CTX *c, const void *data, size_t len);
int SHA512_Final(unsigned char *md, SHA512_CTX *c);
unsigned char *SHA512(const unsigned char *d, size_t n,unsigned char *md);
void SHA512_Transform(SHA512_CTX *c, const unsigned char *data);
#endif

#ifdef  __cplusplus
}
#endif

#endif

/* crypto/sha/sha256.c */
/* ====================================================================
 * Copyright (c) 2004 The OpenSSL Project.  All rights reserved
 * according to the OpenSSL license [found in ../../LICENSE].
 * ====================================================================
 */




#include <sys/types.h>
#include <string.h>

int SHA224_Init (SHA256_CTX *c)
  {
#ifdef OPENSSL_FIPS
  FIPS_selftest_check();
#endif
  c->h[0]=0xc1059ed8UL; c->h[1]=0x367cd507UL;
  c->h[2]=0x3070dd17UL; c->h[3]=0xf70e5939UL;
  c->h[4]=0xffc00b31UL; c->h[5]=0x68581511UL;
  c->h[6]=0x64f98fa7UL; c->h[7]=0xbefa4fa4UL;
  c->Nl=0;  c->Nh=0;
  c->num=0; c->md_len=SHA224_DIGEST_LENGTH;
  return 1;
  }

int SHA256_Init (SHA256_CTX *c)
  {
#ifdef OPENSSL_FIPS
  FIPS_selftest_check();
#endif
  c->h[0]=0x6a09e667UL; c->h[1]=0xbb67ae85UL;
  c->h[2]=0x3c6ef372UL; c->h[3]=0xa54ff53aUL;
  c->h[4]=0x510e527fUL; c->h[5]=0x9b05688cUL;
  c->h[6]=0x1f83d9abUL; c->h[7]=0x5be0cd19UL;
  c->Nl=0;  c->Nh=0;
  c->num=0; c->md_len=SHA256_DIGEST_LENGTH;
  return 1;
  }

unsigned char *SHA224(const unsigned char *d, size_t n, unsigned char *md)
  {
  SHA256_CTX c;
  static unsigned char m[SHA224_DIGEST_LENGTH];

  if (md == NULL) md=m;
  SHA224_Init(&c);
  SHA256_Update(&c,d,n);
  SHA256_Final(md,&c);
  //OPENSSL_cleanse(&c,sizeof(c));
  return(md);
  }

unsigned char *SHA256(const unsigned char *d, size_t n, unsigned char *md)
  {
  SHA256_CTX c;
  static unsigned char m[SHA256_DIGEST_LENGTH];

  if (md == NULL) md=m;
  SHA256_Init(&c);
  SHA256_Update(&c,d,n);
  SHA256_Final(md,&c);
  //OPENSSL_cleanse(&c,sizeof(c));
  return(md);
  }

int SHA224_Update(SHA256_CTX *c, const void *data, size_t len)
{   return SHA256_Update (c,data,len);   }
int SHA224_Final (unsigned char *md, SHA256_CTX *c)
{   return SHA256_Final (md,c);   }

#define DATA_ORDER_IS_BIG_ENDIAN

#define HASH_LONG   SHA_LONG
#define HASH_CTX    SHA256_CTX
#define HASH_CBLOCK   SHA_CBLOCK
/*
 * Note that FIPS180-2 discusses "Truncation of the Hash Function Output."
 * default: case below covers for it. It's not clear however if it's
 * permitted to truncate to amount of bytes not divisible by 4. I bet not,
 * but if it is, then default: case shall be extended. For reference.
 * Idea behind separate cases for pre-defined lenghts is to let the
 * compiler decide if it's appropriate to unroll small loops.
 */
#define HASH_MAKE_STRING(c,s) do {  \
  unsigned long ll;   \
  unsigned int  xn;   \
  switch ((c)->md_len)    \
  {   case SHA224_DIGEST_LENGTH:  \
    for (xn=0;xn<SHA224_DIGEST_LENGTH/4;xn++) \
    {   ll=(c)->h[xn]; HOST_l2c(ll,(s));   }  \
    break;      \
      case SHA256_DIGEST_LENGTH:  \
    for (xn=0;xn<SHA256_DIGEST_LENGTH/4;xn++) \
    {   ll=(c)->h[xn]; HOST_l2c(ll,(s));   }  \
    break;      \
      default:      \
    if ((c)->md_len > SHA256_DIGEST_LENGTH) \
        return 0;       \
    for (xn=0;xn<(c)->md_len/4;xn++)    \
    {   ll=(c)->h[xn]; HOST_l2c(ll,(s));   }  \
    break;      \
  }       \
  } while (0)

#define HASH_UPDATE   SHA256_Update
#define HASH_TRANSFORM    SHA256_Transform
#define HASH_FINAL    SHA256_Final
#define HASH_BLOCK_DATA_ORDER sha256_block_data_order
#ifndef SHA256_ASM
static
#endif
void sha256_block_data_order (SHA256_CTX *ctx, const void *in, size_t num);


#include "md32_common.h"

#ifndef SHA256_ASM
static const SHA_LONG K256[64] = {
  0x428a2f98UL,0x71374491UL,0xb5c0fbcfUL,0xe9b5dba5UL,
  0x3956c25bUL,0x59f111f1UL,0x923f82a4UL,0xab1c5ed5UL,
  0xd807aa98UL,0x12835b01UL,0x243185beUL,0x550c7dc3UL,
  0x72be5d74UL,0x80deb1feUL,0x9bdc06a7UL,0xc19bf174UL,
  0xe49b69c1UL,0xefbe4786UL,0x0fc19dc6UL,0x240ca1ccUL,
  0x2de92c6fUL,0x4a7484aaUL,0x5cb0a9dcUL,0x76f988daUL,
  0x983e5152UL,0xa831c66dUL,0xb00327c8UL,0xbf597fc7UL,
  0xc6e00bf3UL,0xd5a79147UL,0x06ca6351UL,0x14292967UL,
  0x27b70a85UL,0x2e1b2138UL,0x4d2c6dfcUL,0x53380d13UL,
  0x650a7354UL,0x766a0abbUL,0x81c2c92eUL,0x92722c85UL,
  0xa2bfe8a1UL,0xa81a664bUL,0xc24b8b70UL,0xc76c51a3UL,
  0xd192e819UL,0xd6990624UL,0xf40e3585UL,0x106aa070UL,
  0x19a4c116UL,0x1e376c08UL,0x2748774cUL,0x34b0bcb5UL,
  0x391c0cb3UL,0x4ed8aa4aUL,0x5b9cca4fUL,0x682e6ff3UL,
  0x748f82eeUL,0x78a5636fUL,0x84c87814UL,0x8cc70208UL,
  0x90befffaUL,0xa4506cebUL,0xbef9a3f7UL,0xc67178f2UL };

/*
 * FIPS specification refers to right rotations, while our ROTATE macro
 * is left one. This is why you might notice that rotation coefficients
 * differ from those observed in FIPS document by 32-N...
 */
#define Sigma0(x) (ROTATE((x),30) ^ ROTATE((x),19) ^ ROTATE((x),10))
#define Sigma1(x) (ROTATE((x),26) ^ ROTATE((x),21) ^ ROTATE((x),7))
#define sigma0(x) (ROTATE((x),25) ^ ROTATE((x),14) ^ ((x)>>3))
#define sigma1(x) (ROTATE((x),15) ^ ROTATE((x),13) ^ ((x)>>10))

#define Ch(x,y,z) (((x) & (y)) ^ ((~(x)) & (z)))
#define Maj(x,y,z)  (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))

#ifdef OPENSSL_SMALL_FOOTPRINT

static void sha256_block_data_order (SHA256_CTX *ctx, const void *in, size_t num)
  {
  unsigned MD32_REG_T a,b,c,d,e,f,g,h,s0,s1,T1,T2;
  SHA_LONG  X[16],l;
  int i;
  const unsigned char *data=in;

      while (num--) {

  a = ctx->h[0];  b = ctx->h[1];  c = ctx->h[2];  d = ctx->h[3];
  e = ctx->h[4];  f = ctx->h[5];  g = ctx->h[6];  h = ctx->h[7];

  for (i=0;i<16;i++)
    {
    HOST_c2l(data,l); T1 = X[i] = l;
    T1 += h + Sigma1(e) + Ch(e,f,g) + K256[i];
    T2 = Sigma0(a) + Maj(a,b,c);
    h = g;  g = f;  f = e;  e = d + T1;
    d = c;  c = b;  b = a;  a = T1 + T2;
    }

  for (;i<64;i++)
    {
    s0 = X[(i+1)&0x0f]; s0 = sigma0(s0);
    s1 = X[(i+14)&0x0f];  s1 = sigma1(s1);

    T1 = X[i&0xf] += s0 + s1 + X[(i+9)&0xf];
    T1 += h + Sigma1(e) + Ch(e,f,g) + K256[i];
    T2 = Sigma0(a) + Maj(a,b,c);
    h = g;  g = f;  f = e;  e = d + T1;
    d = c;  c = b;  b = a;  a = T1 + T2;
    }

  ctx->h[0] += a; ctx->h[1] += b; ctx->h[2] += c; ctx->h[3] += d;
  ctx->h[4] += e; ctx->h[5] += f; ctx->h[6] += g; ctx->h[7] += h;

      }
}

#else

#define ROUND_00_15(i,a,b,c,d,e,f,g,h)    do {  \
  T1 += h + Sigma1(e) + Ch(e,f,g) + K256[i];  \
  h = Sigma0(a) + Maj(a,b,c);     \
  d += T1;  h += T1;    } while (0)

#define ROUND_16_63(i,a,b,c,d,e,f,g,h,X)  do {  \
  s0 = X[(i+1)&0x0f]; s0 = sigma0(s0);  \
  s1 = X[(i+14)&0x0f];  s1 = sigma1(s1);  \
  T1 = X[(i)&0x0f] += s0 + s1 + X[(i+9)&0x0f];  \
  ROUND_00_15(i,a,b,c,d,e,f,g,h);   } while (0)

static void sha256_block_data_order (SHA256_CTX *ctx, const void *in, size_t num)
  {
  unsigned MD32_REG_T a,b,c,d,e,f,g,h,s0,s1,T1;
  SHA_LONG  X[16];
  int i;
  const unsigned char *data=in;
  const union { long one; char little; } is_endian = {1};

      while (num--) {

  a = ctx->h[0];  b = ctx->h[1];  c = ctx->h[2];  d = ctx->h[3];
  e = ctx->h[4];  f = ctx->h[5];  g = ctx->h[6];  h = ctx->h[7];

  if (!is_endian.little && sizeof(SHA_LONG)==4 && ((size_t)in%4)==0)
    {
    const SHA_LONG *W=(const SHA_LONG *)data;

    T1 = X[0] = W[0]; ROUND_00_15(0,a,b,c,d,e,f,g,h);
    T1 = X[1] = W[1]; ROUND_00_15(1,h,a,b,c,d,e,f,g);
    T1 = X[2] = W[2]; ROUND_00_15(2,g,h,a,b,c,d,e,f);
    T1 = X[3] = W[3]; ROUND_00_15(3,f,g,h,a,b,c,d,e);
    T1 = X[4] = W[4]; ROUND_00_15(4,e,f,g,h,a,b,c,d);
    T1 = X[5] = W[5]; ROUND_00_15(5,d,e,f,g,h,a,b,c);
    T1 = X[6] = W[6]; ROUND_00_15(6,c,d,e,f,g,h,a,b);
    T1 = X[7] = W[7]; ROUND_00_15(7,b,c,d,e,f,g,h,a);
    T1 = X[8] = W[8]; ROUND_00_15(8,a,b,c,d,e,f,g,h);
    T1 = X[9] = W[9]; ROUND_00_15(9,h,a,b,c,d,e,f,g);
    T1 = X[10] = W[10]; ROUND_00_15(10,g,h,a,b,c,d,e,f);
    T1 = X[11] = W[11]; ROUND_00_15(11,f,g,h,a,b,c,d,e);
    T1 = X[12] = W[12]; ROUND_00_15(12,e,f,g,h,a,b,c,d);
    T1 = X[13] = W[13]; ROUND_00_15(13,d,e,f,g,h,a,b,c);
    T1 = X[14] = W[14]; ROUND_00_15(14,c,d,e,f,g,h,a,b);
    T1 = X[15] = W[15]; ROUND_00_15(15,b,c,d,e,f,g,h,a);

    data += SHA256_CBLOCK;
    }
  else
    {
    SHA_LONG l;

    HOST_c2l(data,l); T1 = X[0] = l;  ROUND_00_15(0,a,b,c,d,e,f,g,h);
    HOST_c2l(data,l); T1 = X[1] = l;  ROUND_00_15(1,h,a,b,c,d,e,f,g);
    HOST_c2l(data,l); T1 = X[2] = l;  ROUND_00_15(2,g,h,a,b,c,d,e,f);
    HOST_c2l(data,l); T1 = X[3] = l;  ROUND_00_15(3,f,g,h,a,b,c,d,e);
    HOST_c2l(data,l); T1 = X[4] = l;  ROUND_00_15(4,e,f,g,h,a,b,c,d);
    HOST_c2l(data,l); T1 = X[5] = l;  ROUND_00_15(5,d,e,f,g,h,a,b,c);
    HOST_c2l(data,l); T1 = X[6] = l;  ROUND_00_15(6,c,d,e,f,g,h,a,b);
    HOST_c2l(data,l); T1 = X[7] = l;  ROUND_00_15(7,b,c,d,e,f,g,h,a);
    HOST_c2l(data,l); T1 = X[8] = l;  ROUND_00_15(8,a,b,c,d,e,f,g,h);
    HOST_c2l(data,l); T1 = X[9] = l;  ROUND_00_15(9,h,a,b,c,d,e,f,g);
    HOST_c2l(data,l); T1 = X[10] = l; ROUND_00_15(10,g,h,a,b,c,d,e,f);
    HOST_c2l(data,l); T1 = X[11] = l; ROUND_00_15(11,f,g,h,a,b,c,d,e);
    HOST_c2l(data,l); T1 = X[12] = l; ROUND_00_15(12,e,f,g,h,a,b,c,d);
    HOST_c2l(data,l); T1 = X[13] = l; ROUND_00_15(13,d,e,f,g,h,a,b,c);
    HOST_c2l(data,l); T1 = X[14] = l; ROUND_00_15(14,c,d,e,f,g,h,a,b);
    HOST_c2l(data,l); T1 = X[15] = l; ROUND_00_15(15,b,c,d,e,f,g,h,a);
    }

  for (i=16;i<64;i+=8)
    {
    ROUND_16_63(i+0,a,b,c,d,e,f,g,h,X);
    ROUND_16_63(i+1,h,a,b,c,d,e,f,g,X);
    ROUND_16_63(i+2,g,h,a,b,c,d,e,f,X);
    ROUND_16_63(i+3,f,g,h,a,b,c,d,e,X);
    ROUND_16_63(i+4,e,f,g,h,a,b,c,d,X);
    ROUND_16_63(i+5,d,e,f,g,h,a,b,c,X);
    ROUND_16_63(i+6,c,d,e,f,g,h,a,b,X);
    ROUND_16_63(i+7,b,c,d,e,f,g,h,a,X);
    }

  ctx->h[0] += a; ctx->h[1] += b; ctx->h[2] += c; ctx->h[3] += d;
  ctx->h[4] += e; ctx->h[5] += f; ctx->h[6] += g; ctx->h[7] += h;

      }
  }

#endif
#endif /* SHA256_ASM */

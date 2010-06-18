/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2003, 2004, 2005, 2006, 2009 Christian Grothoff (and other contributing authors)

     GNUnet is free software; you can redistribute it and/or modify
     it under the terms of the GNU General Public License as published
     by the Free Software Foundation; either version 2, or (at your
     option) any later version.

     GNUnet is distributed in the hope that it will be useful, but
     WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
     General Public License for more details.

     You should have received a copy of the GNU General Public License
     along with GNUnet; see the file COPYING.  If not, write to the
     Free Software Foundation, Inc., 59 Temple Place - Suite 330,
     Boston, MA 02111-1307, USA.

     SHA-512 code by Jean-Luc Cooke <jlcooke@certainkey.com>

     Copyright (c) Jean-Luc Cooke <jlcooke@certainkey.com>
     Copyright (c) Andrew McDonald <andrew@mcdonald.org.uk>
     Copyright (c) 2003 Kyle McMartin <kyle@debian.org>
*/

/**
 * @file util/crypto_hash.c
 * @brief SHA-512 GNUNET_CRYPTO_hash related functions
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_common.h"
#include "gnunet_crypto_lib.h"
#include "gnunet_disk_lib.h"

#define SHA512_DIGEST_SIZE 64
#define SHA512_HMAC_BLOCK_SIZE 128

struct sha512_ctx
{
  unsigned long long state[8];
  unsigned int count[4];
  unsigned char buf[128];
};

static unsigned long long
Ch (unsigned long long x, unsigned long long y, unsigned long long z)
{
  return z ^ (x & (y ^ z));
}

static unsigned long long
Maj (unsigned long long x, unsigned long long y, unsigned long long z)
{
  return (x & y) | (z & (x | y));
}

static unsigned long long
RORu64 (unsigned long long x, unsigned long long y)
{
  return (x >> y) | (x << (64 - y));
}

#define e0(x)       (RORu64(x,28) ^ RORu64(x,34) ^ RORu64(x,39))
#define e1(x)       (RORu64(x,14) ^ RORu64(x,18) ^ RORu64(x,41))
#define s0(x)       (RORu64(x, 1) ^ RORu64(x, 8) ^ (x >> 7))
#define s1(x)       (RORu64(x,19) ^ RORu64(x,61) ^ (x >> 6))

/* H* initial state for SHA-512 */
#define H0         0x6a09e667f3bcc908ULL
#define H1         0xbb67ae8584caa73bULL
#define H2         0x3c6ef372fe94f82bULL
#define H3         0xa54ff53a5f1d36f1ULL
#define H4         0x510e527fade682d1ULL
#define H5         0x9b05688c2b3e6c1fULL
#define H6         0x1f83d9abfb41bd6bULL
#define H7         0x5be0cd19137e2179ULL

/* H'* initial state for SHA-384 */
#define HP0 0xcbbb9d5dc1059ed8ULL
#define HP1 0x629a292a367cd507ULL
#define HP2 0x9159015a3070dd17ULL
#define HP3 0x152fecd8f70e5939ULL
#define HP4 0x67332667ffc00b31ULL
#define HP5 0x8eb44a8768581511ULL
#define HP6 0xdb0c2e0d64f98fa7ULL
#define HP7 0x47b5481dbefa4fa4ULL

#define LOAD_OP(t1, I, W, input) \
  t1  = input[(8*I)  ] & 0xff;\
  t1 <<= 8;\
  t1 |= input[(8*I)+1] & 0xff;\
  t1 <<= 8;\
  t1 |= input[(8*I)+2] & 0xff;\
  t1 <<= 8;\
  t1 |= input[(8*I)+3] & 0xff;\
  t1 <<= 8;\
  t1 |= input[(8*I)+4] & 0xff;\
  t1 <<= 8;\
  t1 |= input[(8*I)+5] & 0xff;\
  t1 <<= 8;\
  t1 |= input[(8*I)+6] & 0xff;\
  t1 <<= 8;\
  t1 |= input[(8*I)+7] & 0xff;\
  W[I] = t1;


#define BLEND_OP(I, W) \
  W[I] = s1(W[I-2]) + W[I-7] + s0(W[I-15]) + W[I-16];

static void
sha512_transform (unsigned long long *state, const unsigned char *input)
{
  static const unsigned long long sha512_K[80] = {
    0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL,
    0xe9b5dba58189dbbcULL, 0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL,
    0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL, 0xd807aa98a3030242ULL,
    0x12835b0145706fbeULL, 0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
    0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL,
    0xc19bf174cf692694ULL, 0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL,
    0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL, 0x2de92c6f592b0275ULL,
    0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
    0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL, 0xb00327c898fb213fULL,
    0xbf597fc7beef0ee4ULL, 0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL,
    0x06ca6351e003826fULL, 0x142929670a0e6e70ULL, 0x27b70a8546d22ffcULL,
    0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
    0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL,
    0x92722c851482353bULL, 0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL,
    0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL, 0xd192e819d6ef5218ULL,
    0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
    0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL, 0x2748774cdf8eeb99ULL,
    0x34b0bcb5e19b48a8ULL, 0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL,
    0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL, 0x748f82ee5defb2fcULL,
    0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
    0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL,
    0xc67178f2e372532bULL, 0xca273eceea26619cULL, 0xd186b8c721c0c207ULL,
    0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL, 0x06f067aa72176fbaULL,
    0x0a637dc5a2c898a6ULL, 0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
    0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL,
    0x431d67c49c100d4cULL, 0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL,
    0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL,
  };
  
  unsigned long long a, b, c, d, e, f, g, h, t1, t2;
  unsigned long long W[80];
  unsigned long long t0;
  int i;

  /* load the input */
  for (i = 0; i < 16; i++)
    {
      LOAD_OP (t0, i, W, input);
    }

  for (i = 16; i < 80; i++)
    {
      BLEND_OP (i, W);
    }

  /* load the state into our registers */
  a = state[0];
  b = state[1];
  c = state[2];
  d = state[3];
  e = state[4];
  f = state[5];
  g = state[6];
  h = state[7];

  /* now iterate */
  for (i = 0; i < 80; i += 8)
    {
      t1 = h + e1 (e) + Ch (e, f, g) + sha512_K[i] + W[i];
      t2 = e0 (a) + Maj (a, b, c);
      d += t1;
      h = t1 + t2;
      t1 = g + e1 (d) + Ch (d, e, f) + sha512_K[i + 1] + W[i + 1];
      t2 = e0 (h) + Maj (h, a, b);
      c += t1;
      g = t1 + t2;
      t1 = f + e1 (c) + Ch (c, d, e) + sha512_K[i + 2] + W[i + 2];
      t2 = e0 (g) + Maj (g, h, a);
      b += t1;
      f = t1 + t2;
      t1 = e + e1 (b) + Ch (b, c, d) + sha512_K[i + 3] + W[i + 3];
      t2 = e0 (f) + Maj (f, g, h);
      a += t1;
      e = t1 + t2;
      t1 = d + e1 (a) + Ch (a, b, c) + sha512_K[i + 4] + W[i + 4];
      t2 = e0 (e) + Maj (e, f, g);
      h += t1;
      d = t1 + t2;
      t1 = c + e1 (h) + Ch (h, a, b) + sha512_K[i + 5] + W[i + 5];
      t2 = e0 (d) + Maj (d, e, f);
      g += t1;
      c = t1 + t2;
      t1 = b + e1 (g) + Ch (g, h, a) + sha512_K[i + 6] + W[i + 6];
      t2 = e0 (c) + Maj (c, d, e);
      f += t1;
      b = t1 + t2;
      t1 = a + e1 (f) + Ch (f, g, h) + sha512_K[i + 7] + W[i + 7];
      t2 = e0 (b) + Maj (b, c, d);
      e += t1;
      a = t1 + t2;
    }

  state[0] += a;
  state[1] += b;
  state[2] += c;
  state[3] += d;
  state[4] += e;
  state[5] += f;
  state[6] += g;
  state[7] += h;
}

static void
sha512_init (struct sha512_ctx *sctx)
{
  sctx->state[0] = H0;
  sctx->state[1] = H1;
  sctx->state[2] = H2;
  sctx->state[3] = H3;
  sctx->state[4] = H4;
  sctx->state[5] = H5;
  sctx->state[6] = H6;
  sctx->state[7] = H7;
  sctx->count[0] = sctx->count[1] = sctx->count[2] = sctx->count[3] = 0;
  memset (sctx->buf, 0, sizeof (sctx->buf));
}

static void
sha512_update (struct sha512_ctx *sctx,
               const unsigned char *data, unsigned int len)
{
  unsigned int i, index, part_len;

  /* Compute number of bytes mod 128 */
  index = (unsigned int) ((sctx->count[0] >> 3) & 0x7F);

  /* Update number of bits */
  if ((sctx->count[0] += (len << 3)) < (len << 3))
    {
      if ((sctx->count[1] += 1) < 1)
        if ((sctx->count[2] += 1) < 1)
          sctx->count[3]++;
      sctx->count[1] += (len >> 29);
    }

  part_len = 128 - index;

  /* Transform as many times as possible. */
  if (len >= part_len)
    {
      memcpy (&sctx->buf[index], data, part_len);
      sha512_transform (sctx->state, sctx->buf);

      for (i = part_len; i + 127 < len; i += 128)
        sha512_transform (sctx->state, &data[i]);

      index = 0;
    }
  else
    {
      i = 0;
    }

  /* Buffer remaining input */
  memcpy (&sctx->buf[index], &data[i], len - i);
}

static void
sha512_final (struct sha512_ctx *sctx, unsigned char *hash)
{
  static unsigned char padding[128] = { 0x80, };

  unsigned int t;
  unsigned char bits[128];
  unsigned int index;
  unsigned int pad_len;
  unsigned long long t2;
  int i, j;

  /* Save number of bits */
  t = sctx->count[0];
  bits[15] = t;
  t >>= 8;
  bits[14] = t;
  t >>= 8;
  bits[13] = t;
  t >>= 8;
  bits[12] = t;
  t = sctx->count[1];
  bits[11] = t;
  t >>= 8;
  bits[10] = t;
  t >>= 8;
  bits[9] = t;
  t >>= 8;
  bits[8] = t;
  t = sctx->count[2];
  bits[7] = t;
  t >>= 8;
  bits[6] = t;
  t >>= 8;
  bits[5] = t;
  t >>= 8;
  bits[4] = t;
  t = sctx->count[3];
  bits[3] = t;
  t >>= 8;
  bits[2] = t;
  t >>= 8;
  bits[1] = t;
  t >>= 8;
  bits[0] = t;

  /* Pad out to 112 mod 128. */
  index = (sctx->count[0] >> 3) & 0x7f;
  pad_len = (index < 112) ? (112 - index) : ((128 + 112) - index);
  sha512_update (sctx, padding, pad_len);

  /* Append length (before padding) */
  sha512_update (sctx, bits, 16);

  /* Store state in digest */
  for (i = j = 0; i < 8; i++, j += 8)
    {
      t2 = sctx->state[i];
      hash[j + 7] = (char) t2 & 0xff;
      t2 >>= 8;
      hash[j + 6] = (char) t2 & 0xff;
      t2 >>= 8;
      hash[j + 5] = (char) t2 & 0xff;
      t2 >>= 8;
      hash[j + 4] = (char) t2 & 0xff;
      t2 >>= 8;
      hash[j + 3] = (char) t2 & 0xff;
      t2 >>= 8;
      hash[j + 2] = (char) t2 & 0xff;
      t2 >>= 8;
      hash[j + 1] = (char) t2 & 0xff;
      t2 >>= 8;
      hash[j] = (char) t2 & 0xff;
    }

  /* Zeroize sensitive information. */
  memset (sctx, 0, sizeof (struct sha512_ctx));
}


/**
 * Hash block of given size.
 *
 * @param block the data to GNUNET_CRYPTO_hash, length is given as a second argument
 * @param size the length of the data to GNUNET_CRYPTO_hash
 * @param ret pointer to where to write the hashcode
 */
void
GNUNET_CRYPTO_hash (const void *block, size_t size, GNUNET_HashCode * ret)
{
  struct sha512_ctx ctx;

  sha512_init (&ctx);
  sha512_update (&ctx, block, size);
  sha512_final (&ctx, (unsigned char *) ret);
}


/**
 * Context used when hashing a file.
 */
struct GNUNET_CRYPTO_FileHashContext
{

  /**
   * Function to call upon completion.
   */
  GNUNET_CRYPTO_HashCompletedCallback callback;

  /**
   * Closure for callback.
   */
  void *callback_cls;

  /**
   * IO buffer.
   */
  unsigned char *buffer;

  /**
   * Name of the file we are hashing.
   */
  char *filename;

  /**
   * File descriptor.
   */
  struct GNUNET_DISK_FileHandle *fh;

  /**
   * Our scheduler.
   */
  struct GNUNET_SCHEDULER_Handle *sched;

  /**
   * Cummulated hash.
   */
  struct sha512_ctx hctx;

  /**
   * Size of the file.
   */
  uint64_t fsize;

  /**
   * Current offset.
   */
  uint64_t offset;

  /**
   * Current task for hashing.
   */
  GNUNET_SCHEDULER_TaskIdentifier task;

  /**
   * Blocksize.
   */
  size_t bsize;

};


/**
 * Report result of hash computation to callback
 * and free associated resources.
 */
static void
file_hash_finish (struct GNUNET_CRYPTO_FileHashContext *fhc, 
		  const GNUNET_HashCode * res)
{
  fhc->callback (fhc->callback_cls, res);
  GNUNET_free (fhc->filename);
  if (!GNUNET_DISK_handle_invalid (fhc->fh))
    GNUNET_break (GNUNET_OK == GNUNET_DISK_file_close (fhc->fh));
  GNUNET_free (fhc);            /* also frees fhc->buffer */
}


/**
 * File hashing task.
 *
 * @param cls closure
 * @param tc context
 */
static void
file_hash_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_CRYPTO_FileHashContext *fhc = cls;
  GNUNET_HashCode res;
  size_t delta;

  fhc->task = GNUNET_SCHEDULER_NO_TASK;
  GNUNET_assert (fhc->offset < fhc->fsize);
  delta = fhc->bsize;
  if (fhc->fsize - fhc->offset < delta)
    delta = fhc->fsize - fhc->offset;
  if (delta != GNUNET_DISK_file_read (fhc->fh, fhc->buffer, delta))
    {
      GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_WARNING,
                                "read", fhc->filename);
      file_hash_finish (fhc, NULL);
      return;
    }
  sha512_update (&fhc->hctx, fhc->buffer, delta);
  fhc->offset += delta;
  if (fhc->offset == fhc->fsize)
    {
      sha512_final (&fhc->hctx, (unsigned char *) &res);
      file_hash_finish (fhc, &res);
      return;
    }
  fhc->task 
    = GNUNET_SCHEDULER_add_after (tc->sched,
				  GNUNET_SCHEDULER_NO_TASK, 
				  &file_hash_task, fhc);
}


/**
 * Compute the hash of an entire file.
 *
 * @param sched scheduler to use
 * @param priority scheduling priority to use
 * @param filename name of file to hash
 * @param blocksize number of bytes to process in one task
 * @param callback function to call upon completion
 * @param callback_cls closure for callback
 * @return NULL on (immediate) errror
 */
struct GNUNET_CRYPTO_FileHashContext *
GNUNET_CRYPTO_hash_file (struct GNUNET_SCHEDULER_Handle *sched,
                         enum GNUNET_SCHEDULER_Priority priority,
                         const char *filename,
                         size_t blocksize,
                         GNUNET_CRYPTO_HashCompletedCallback callback,
                         void *callback_cls)
{
  struct GNUNET_CRYPTO_FileHashContext *fhc;

  GNUNET_assert (blocksize > 0);
  fhc = GNUNET_malloc (sizeof (struct GNUNET_CRYPTO_FileHashContext) + blocksize);
  fhc->callback = callback;
  fhc->callback_cls = callback_cls;
  fhc->sched = sched;
  fhc->buffer = (unsigned char *) &fhc[1];
  fhc->filename = GNUNET_strdup (filename);
  fhc->fh = NULL;
  sha512_init (&fhc->hctx);
  fhc->bsize = blocksize;
  if (GNUNET_OK != GNUNET_DISK_file_size (filename, &fhc->fsize, GNUNET_NO))
    {
      GNUNET_free (fhc->filename);
      GNUNET_free (fhc);
      return NULL;
    }
  fhc->fh = GNUNET_DISK_file_open (filename,
                                   GNUNET_DISK_OPEN_READ,
                                   GNUNET_DISK_PERM_NONE);
  if (!fhc->fh)
    {
      GNUNET_free (fhc->filename);
      GNUNET_free (fhc);
      return NULL;
    }
  fhc->task 
    = GNUNET_SCHEDULER_add_with_priority (sched, priority, 
					  &file_hash_task, fhc);
  return fhc;
}


/**
 * Cancel a file hashing operation.
 *
 * @param fhc operation to cancel (callback must not yet have been invoked)
 */
void
GNUNET_CRYPTO_hash_file_cancel (struct GNUNET_CRYPTO_FileHashContext *fhc)
{
  GNUNET_SCHEDULER_cancel (fhc->sched,
			   fhc->task);
  GNUNET_free (fhc->filename);
  GNUNET_break (GNUNET_OK == GNUNET_DISK_file_close (fhc->fh));
  GNUNET_free (fhc);
}



/* ***************** binary-ASCII encoding *************** */

static unsigned int
getValue__ (unsigned char a)
{
  if ((a >= '0') && (a <= '9'))
    return a - '0';
  if ((a >= 'A') && (a <= 'V'))
    return (a - 'A' + 10);
  return -1;
}

/**
 * Convert GNUNET_CRYPTO_hash to ASCII encoding.  The ASCII encoding is rather
 * GNUnet specific.  It was chosen such that it only uses characters
 * in [0-9A-V], can be produced without complex arithmetics and uses a
 * small number of characters.  The GNUnet encoding uses 102
 * characters plus a null terminator.
 *
 * @param block the hash code
 * @param result where to store the encoding (struct GNUNET_CRYPTO_HashAsciiEncoded can be
 *  safely cast to char*, a '\\0' termination is set).
 */
void
GNUNET_CRYPTO_hash_to_enc (const GNUNET_HashCode * block,
                           struct GNUNET_CRYPTO_HashAsciiEncoded *result)
{
  /**
   * 32 characters for encoding (GNUNET_CRYPTO_hash => 32 characters)
   */
  static char *encTable__ = "0123456789ABCDEFGHIJKLMNOPQRSTUV";
  unsigned int wpos;
  unsigned int rpos;
  unsigned int bits;
  unsigned int vbit;

  GNUNET_assert (block != NULL);
  GNUNET_assert (result != NULL);
  vbit = 0;
  wpos = 0;
  rpos = 0;
  bits = 0;
  while ((rpos < sizeof (GNUNET_HashCode)) || (vbit > 0))
    {
      if ((rpos < sizeof (GNUNET_HashCode)) && (vbit < 5))
        {
          bits = (bits << 8) | ((unsigned char *) block)[rpos++];       /* eat 8 more bits */
          vbit += 8;
        }
      if (vbit < 5)
        {
          bits <<= (5 - vbit);  /* zero-padding */
          GNUNET_assert (vbit == 2);    /* padding by 3: 512+3 mod 5 == 0 */
          vbit = 5;
        }
      GNUNET_assert (wpos <
                     sizeof (struct GNUNET_CRYPTO_HashAsciiEncoded) - 1);
      result->encoding[wpos++] = encTable__[(bits >> (vbit - 5)) & 31];
      vbit -= 5;
    }
  GNUNET_assert (wpos == sizeof (struct GNUNET_CRYPTO_HashAsciiEncoded) - 1);
  GNUNET_assert (vbit == 0);
  result->encoding[wpos] = '\0';
}

/**
 * Convert ASCII encoding back to GNUNET_CRYPTO_hash
 *
 * @param enc the encoding
 * @param result where to store the GNUNET_CRYPTO_hash code
 * @return GNUNET_OK on success, GNUNET_SYSERR if result has the wrong encoding
 */
int
GNUNET_CRYPTO_hash_from_string (const char *enc, GNUNET_HashCode * result)
{
  unsigned int rpos;
  unsigned int wpos;
  unsigned int bits;
  unsigned int vbit;

  if (strlen (enc) != sizeof (struct GNUNET_CRYPTO_HashAsciiEncoded) - 1)
    return GNUNET_SYSERR;

  vbit = 2;                     /* padding! */
  wpos = sizeof (GNUNET_HashCode);
  rpos = sizeof (struct GNUNET_CRYPTO_HashAsciiEncoded) - 1;
  bits = getValue__ (enc[--rpos]) >> 3;
  while (wpos > 0)
    {
      GNUNET_assert (rpos > 0);
      bits = (getValue__ (enc[--rpos]) << vbit) | bits;
      vbit += 5;
      if (vbit >= 8)
        {
          ((unsigned char *) result)[--wpos] = (unsigned char) bits;
          bits >>= 8;
          vbit -= 8;
        }
    }
  GNUNET_assert (rpos == 0);
  GNUNET_assert (vbit == 0);
  return GNUNET_OK;
}

/**
 * Compute the distance between 2 hashcodes.  The computation must be
 * fast, not involve bits[0] or bits[4] (they're used elsewhere), and be
 * somewhat consistent. And of course, the result should be a positive
 * number.
 *
 * @returns a positive number which is a measure for
 *  hashcode proximity.
 */
unsigned int
GNUNET_CRYPTO_hash_distance_u32 (const GNUNET_HashCode * a,
                                 const GNUNET_HashCode * b)
{
  unsigned int x1 = (a->bits[1] - b->bits[1]) >> 16;
  unsigned int x2 = (b->bits[1] - a->bits[1]) >> 16;
  return (x1 * x2);
}

void
GNUNET_CRYPTO_hash_create_random (enum GNUNET_CRYPTO_Quality mode,
                                  GNUNET_HashCode * result)
{
  int i;
  for (i = (sizeof (GNUNET_HashCode) / sizeof (uint32_t)) - 1; i >= 0; i--)
    result->bits[i] = GNUNET_CRYPTO_random_u32 (mode, UINT32_MAX);
}

void
GNUNET_CRYPTO_hash_difference (const GNUNET_HashCode * a,
                               const GNUNET_HashCode * b,
                               GNUNET_HashCode * result)
{
  int i;
  for (i = (sizeof (GNUNET_HashCode) / sizeof (unsigned int)) - 1; i >= 0;
       i--)
    result->bits[i] = b->bits[i] - a->bits[i];
}

void
GNUNET_CRYPTO_hash_sum (const GNUNET_HashCode * a,
                        const GNUNET_HashCode * delta,
                        GNUNET_HashCode * result)
{
  int i;
  for (i = (sizeof (GNUNET_HashCode) / sizeof (unsigned int)) - 1; i >= 0;
       i--)
    result->bits[i] = delta->bits[i] + a->bits[i];
}

void
GNUNET_CRYPTO_hash_xor (const GNUNET_HashCode * a,
                        const GNUNET_HashCode * b, GNUNET_HashCode * result)
{
  int i;
  for (i = (sizeof (GNUNET_HashCode) / sizeof (unsigned int)) - 1; i >= 0;
       i--)
    result->bits[i] = a->bits[i] ^ b->bits[i];
}

/**
 * Convert a hashcode into a key.
 */
void
GNUNET_CRYPTO_hash_to_aes_key (const GNUNET_HashCode * hc,
                               struct GNUNET_CRYPTO_AesSessionKey *skey,
                               struct GNUNET_CRYPTO_AesInitializationVector
                               *iv)
{
  GNUNET_assert (sizeof (GNUNET_HashCode) >=
                 GNUNET_CRYPTO_AES_KEY_LENGTH +
                 sizeof (struct GNUNET_CRYPTO_AesInitializationVector));
  memcpy (skey, hc, GNUNET_CRYPTO_AES_KEY_LENGTH);
  skey->crc32 =
    htonl (GNUNET_CRYPTO_crc32_n (skey, GNUNET_CRYPTO_AES_KEY_LENGTH));
  memcpy (iv, &((char *) hc)[GNUNET_CRYPTO_AES_KEY_LENGTH],
          sizeof (struct GNUNET_CRYPTO_AesInitializationVector));
}

/**
 * Obtain a bit from a hashcode.
 * @param code the GNUNET_CRYPTO_hash to index bit-wise
 * @param bit index into the hashcode, [0...511]
 * @return Bit \a bit from hashcode \a code, -1 for invalid index
 */
int
GNUNET_CRYPTO_hash_get_bit (const GNUNET_HashCode * code, unsigned int bit)
{
  GNUNET_assert (bit < 8 * sizeof (GNUNET_HashCode));
  return (((unsigned char *) code)[bit >> 3] & (1 << (bit & 7))) > 0;
}

/**
 * Compare function for HashCodes, producing a total ordering
 * of all hashcodes.
 * @return 1 if h1 > h2, -1 if h1 < h2 and 0 if h1 == h2.
 */
int
GNUNET_CRYPTO_hash_cmp (const GNUNET_HashCode * h1,
                        const GNUNET_HashCode * h2)
{
  unsigned int *i1;
  unsigned int *i2;
  int i;

  i1 = (unsigned int *) h1;
  i2 = (unsigned int *) h2;
  for (i = (sizeof (GNUNET_HashCode) / sizeof (unsigned int)) - 1; i >= 0;
       i--)
    {
      if (i1[i] > i2[i])
        return 1;
      if (i1[i] < i2[i])
        return -1;
    }
  return 0;
}

/**
 * Find out which of the two GNUNET_CRYPTO_hash codes is closer to target
 * in the XOR metric (Kademlia).
 * @return -1 if h1 is closer, 1 if h2 is closer and 0 if h1==h2.
 */
int
GNUNET_CRYPTO_hash_xorcmp (const GNUNET_HashCode * h1,
                           const GNUNET_HashCode * h2,
                           const GNUNET_HashCode * target)
{
  int i;
  unsigned int d1;
  unsigned int d2;

  for (i = sizeof (GNUNET_HashCode) / sizeof (unsigned int) - 1; i >= 0; i--)
    {
      d1 = ((unsigned int *) h1)[i] ^ ((unsigned int *) target)[i];
      d2 = ((unsigned int *) h2)[i] ^ ((unsigned int *) target)[i];
      if (d1 > d2)
        return 1;
      else if (d1 < d2)
        return -1;
    }
  return 0;
}


/**
 * Calculate HMAC of a message (RFC 2104)
 *
 * @param key secret key
 * @param plaintext input plaintext
 * @param plaintext_len length of plaintext
 * @param hmac where to store the hmac
 */
void 
GNUNET_CRYPTO_hmac (const struct GNUNET_CRYPTO_AesSessionKey *key,
		    const void *plaintext,
		    size_t plaintext_len,
		    GNUNET_HashCode *hmac)
{
  GNUNET_HashCode kh;
  GNUNET_HashCode ipad;
  GNUNET_HashCode opad;
  GNUNET_HashCode him;
  struct sha512_ctx sctx;

  memset (&kh, 0, sizeof (kh));
  GNUNET_assert (sizeof (GNUNET_HashCode) > sizeof (struct GNUNET_CRYPTO_AesSessionKey));
  memcpy (&kh, key, sizeof (struct GNUNET_CRYPTO_AesSessionKey));				
  memset (&ipad, 0x5c, sizeof (ipad));
  memset (&opad, 0x36, sizeof (opad));
  GNUNET_CRYPTO_hash_xor (&ipad, &kh, &ipad);
  GNUNET_CRYPTO_hash_xor (&opad, &kh, &opad);
  sha512_init (&sctx);
  sha512_update (&sctx, (const unsigned char*) &ipad, sizeof (ipad));
  sha512_update (&sctx, plaintext, plaintext_len);
  sha512_final (&sctx, (unsigned char*) &him);
  sha512_init (&sctx);
  sha512_update (&sctx, (const unsigned char*) &opad, sizeof (opad));
  sha512_update (&sctx, (const unsigned char*) &him, sizeof (him));
  sha512_final (&sctx, (unsigned char*) hmac);
}


/* end of crypto_hash.c */

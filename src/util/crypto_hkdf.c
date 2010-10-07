/*
    Copyright (c) 2010 Nils Durner

    Permission is hereby granted, free of charge, to any person obtaining a copy
    of this software and associated documentation files (the "Software"), to deal
    in the Software without restriction, including without limitation the rights
    to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
    copies of the Software, and to permit persons to whom the Software is
    furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in
    all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
    THE SOFTWARE.
*/

/**
 * @file src/util/crypto_hkdf.c
 * @brief Hash-based KDF as defined in RFC 5869
 * @see http://www.rfc-editor.org/rfc/rfc5869.txt
 * @author Nils Durner
 */

#include <gcrypt.h>

#include "platform.h"
#include "gnunet_crypto_lib.h"

#define DEBUG_HKDF GNUNET_NO

/**
 * @brief Compute the HMAC
 * @param mac gcrypt MAC handle
 * @param key HMAC key
 * @param key_len length of key
 * @param buf message to be processed
 * @param buf_len length of buf
 * @return HMAC, freed by caller via gcry_md_close/_reset
 */
static void *
doHMAC (gcry_md_hd_t mac, 
	const void *key, size_t key_len,
	const void *buf, size_t buf_len)
{
  gcry_md_setkey (mac, key, key_len);
  gcry_md_write (mac, buf, buf_len);

  return (void *) gcry_md_read (mac, 0);
}

/**
 * @brief Generate pseudo-random key
 * @param mac gcrypt HMAC handle
 * @param xts salt
 * @param xts_len length of the salt
 * @param skm source key material
 * @param skm_len length of skm
 * @param prk result buffer (allocated by caller; at least gcry_md_dlen() bytes)
 * @return GNUNET_YES on success
 */
static int
getPRK (gcry_md_hd_t mac, 
	const void *xts, unsigned long long xts_len, /* FIXME: size_t? */
	const void *skm, unsigned long long skm_len, 
	void *prk)
{
  void *ret;

  ret = doHMAC (mac, xts, xts_len, skm, skm_len);
  if (ret == NULL)
    return GNUNET_SYSERR;
  memcpy (prk, ret, gcry_md_get_algo_dlen (gcry_md_get_algo (mac)));

  return GNUNET_YES;
}


#if DEBUG_HKDF
static void 
dump(const char *src, 
     const void *p, 
     unsigned int l)
{
  unsigned int i;

  printf("\n%s: ", src);
  for (i = 0; i < l; i++)
    {
      printf("%2x", (int) ((const unsigned char *) p)[i]);
    }
  printf("\n");
}
#endif


/**
 * @brief Derive key
 * @param result buffer for the derived key, allocated by caller
 * @param out_len desired length of the derived key
 * @param xtr_algo hash algorithm for the extraction phase, GCRY_MD_...
 * @param prf_algo hash algorithm for the expansion phase, GCRY_MD_...
 * @param xts salt
 * @param xts_len length of xts
 * @param skm source key material
 * @param skm_len length of skm
 * @param argp va_list of void * & size_t pairs for context chunks
 * @return GNUNET_YES on success
 */
int
GNUNET_CRYPTO_hkdf_v (void *result, unsigned long long out_len,
		      int xtr_algo, int prf_algo, 
		      const void *xts, size_t xts_len,
		      const void *skm, size_t skm_len,
		      va_list argp)
{
  void *prk, *hc, *plain;
  unsigned long long plain_len;
  unsigned long i, t, d;
  unsigned int k, xtr_len;
  int ret;
  gcry_md_hd_t xtr, prf;
  size_t ctx_len;
  va_list args;

  prk = plain = NULL;
  xtr_len = gcry_md_get_algo_dlen (xtr_algo);
  k = gcry_md_get_algo_dlen (prf_algo);
  gcry_md_open(&xtr, xtr_algo, GCRY_MD_FLAG_HMAC);
  gcry_md_open(&prf, prf_algo, GCRY_MD_FLAG_HMAC);

  if (out_len > (2 ^ 32 * k) || !xtr_algo || !prf_algo)
    return GNUNET_SYSERR;

  va_copy (args, argp);
  for (ctx_len = 0; va_arg (args, void *);)
    ctx_len += va_arg (args, size_t);
  va_end(args);

  prk = GNUNET_malloc (xtr_len);

  memset (result, 0, out_len);
  gcry_md_reset (xtr);
  if (getPRK (xtr, xts, xts_len, skm, skm_len, prk)
      != GNUNET_YES)
    goto hkdf_error;
#if DEBUG_HKDF
  dump("PRK", prk, xtr_len);
#endif

  t = out_len / k;
  d = out_len % k;

  /* K(1) */
  plain_len = k + ctx_len + 1;
  plain = GNUNET_malloc (plain_len);
  if (t > 0)
    {
      void *ctx, *dst;

      dst = plain;
      va_copy (args, argp);
      while ((ctx = va_arg (args, void *)))
        {
          size_t len;

          len = va_arg (args, size_t);
          memcpy (dst, ctx, len);
          dst += len;
        }
      va_end (args);

      memset (dst, 1, 1);
      gcry_md_reset (prf);
#if DEBUG_HKDF
      dump("K(1)", plain, plain_len);
#endif
      hc = doHMAC (prf, prk, xtr_len, plain, ctx_len + 1);
      if (hc == NULL)
        goto hkdf_error;
      memcpy (result, hc, k);
      result += k;
    }

  if (t > 1 || d > 0)
    {
      void *ctx, *dst;

      dst = plain + k;
      va_copy (args, argp);
      while ((ctx = va_arg (args, void *)))
        {
          size_t len;

          len = va_arg (args, size_t);
          memcpy (dst, ctx, len);
          dst += len;
        }
      va_end (args);
    }

  /* K(i+1) */
  for (i = 1; i < t; i++)
    {
      memcpy (plain, result - k, k);
      memset (plain + k + ctx_len, i + 1, 1);
      gcry_md_reset (prf);
#if DEBUG_HKDF
      dump("K(i+1)", plain, plain_len);
#endif
      hc = doHMAC (prf, prk, xtr_len, plain, plain_len);
      if (hc == NULL)
        goto hkdf_error;
      memcpy (result, hc, k);
      result += k;
    }

  /* K(t):d */
  if (d > 0)
    {
      if (t > 0)
        memcpy (plain, result - k, k);
      memset (plain + k + ctx_len, i + 1, 1);
      gcry_md_reset (prf);
#if DEBUG_HKDF
      dump("K(t):d", plain, plain_len);
#endif
      hc = doHMAC (prf, prk, xtr_len, plain, plain_len);
      if (hc == NULL)
        goto hkdf_error;
      memcpy (result, hc, d);
    }
#if DEBUG_HKDF
  dump("result", result - k, out_len);
#endif

  ret = GNUNET_YES;
  goto hkdf_ok;

hkdf_error:
  ret = GNUNET_SYSERR;
hkdf_ok:
  GNUNET_free (prk);
  GNUNET_free_non_null (plain);
  gcry_md_close (prf);
  gcry_md_close (xtr);

  return ret;
}


/**
 * @brief Derive key
 * @param result buffer for the derived key, allocated by caller
 * @param out_len desired length of the derived key
 * @param xtr_algo hash algorithm for the extraction phase, GCRY_MD_...
 * @param prf_algo hash algorithm for the expansion phase, GCRY_MD_...
 * @param xts salt
 * @param xts_len length of xts
 * @param skm source key material
 * @param skm_len length of skm
 * @param ctx context info
 * @param ctx_len length of ctx
 * @return GNUNET_YES on success
 */
int
GNUNET_CRYPTO_hkdf (void *result, unsigned long long out_len,
		    int xtr_algo, int prf_algo, 
		    const void *xts, size_t xts_len,
		    const void *skm, size_t skm_len, 
		    ...)
{
  va_list argp;
  int ret;

  va_start(argp, skm_len);
  ret = GNUNET_CRYPTO_hkdf_v (result, out_len, xtr_algo, prf_algo, xts,
      xts_len, skm, skm_len, argp);
  va_end(argp);

  return ret;
}

/* end of crypto_hkdf.c */

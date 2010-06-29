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
 * @brief Hash-based KDF as defined in draft-krawczyk-hkdf-01
 * @see http://tools.ietf.org/html/draft-krawczyk-hkdf-01
 * @author Nils Durner
 */

#include "platform.h"
#include "gnunet_crypto_lib.h"

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
doHMAC (gcry_md_hd_t mac, const void *key, const size_t key_len,
    const void *buf, const size_t buf_len)
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
getPRK (gcry_md_hd_t mac, const void *xts, const unsigned long long xts_len,
    const void *skm, const unsigned long long skm_len, void *prk)
{
  void *ret;

  ret = doHMAC (mac, xts, xts_len, skm, skm_len);
  if (ret == NULL)
    return GNUNET_SYSERR;
  memcpy (prk, ret, gcry_md_get_algo_dlen (gcry_md_get_algo (mac)));

  return GNUNET_YES;
}

static void dump(void *p, unsigned int l)
{
  unsigned int i;

  printf("\n");
  for (i = 0; i < l; i++)
    {
      printf("%2x", ((char *) p)[i]);
    }
  printf("\n");
}

/**
 * @brief Derive key
 * @param xtr_algo hash algorithm for the extraction phase, GCRY_MD_...
 * @param prf_algo hash algorithm for the expansion phase, GCRY_MD_...
 * @param xts salt
 * @param xts_len length of xts
 * @param skm source key material
 * @param skm_len length of skm
 * @param ctx context info
 * @param ctx_len length of ctx
 * @param out_len desired length of the derived key
 * @param result buffer for the derived key, allocated by caller
 * @return GNUNET_YES on success
 */
int
GNUNET_CRYPTO_hkdf (int xtr_algo, int prf_algo, const void *xts,
    const size_t xts_len, const void *skm, const size_t skm_len,
    const void *ctx, const size_t ctx_len, const unsigned long long out_len,
    void *result)
{
  void *prk, *hc, *plain;
  unsigned long long plain_len;
  unsigned long i, t, d;
  unsigned int k, xtr_len;
  int ret;
  gcry_md_hd_t xtr, prf;

  prk = plain = NULL;
  xtr_len = gcry_md_get_algo_dlen (xtr_algo);
  k = gcry_md_get_algo_dlen (prf_algo);
  gcry_md_open(&xtr, xtr_algo, GCRY_MD_FLAG_HMAC);
  gcry_md_open(&prf, prf_algo, GCRY_MD_FLAG_HMAC);

  if (out_len > (2 ^ 32 * k) || !xtr_algo || !prf_algo)
    return GNUNET_SYSERR;

  prk = GNUNET_malloc (xtr_len);

  memset (result, 0, out_len);
  gcry_md_reset (xtr);
  if (getPRK (xtr, xts, xts_len, skm, skm_len, prk)
      != GNUNET_YES)
    goto hkdf_error;
dump(prk, xtr_len);

  /* K(1) */
  plain_len = k + ctx_len + 4;
  plain = GNUNET_malloc (plain_len);
  memset (plain, 0, k);
  memcpy (plain + k, ctx, ctx_len);
  t = out_len / k;
  if (t > 0)
    {
      memset (plain + k + ctx_len, 0, 4);
      gcry_md_reset (prf);
      hc = doHMAC (prf, prk, k, plain, plain_len);
      if (hc == NULL)
        goto hkdf_error;
      memcpy (result, hc, k);
      result += k;
    }

  /* K(i+1) */
  for (i = 1; i < t; i++)
    {
      memcpy (plain, result - k, k);
      memcpy (plain + k + ctx_len, &i, 4);
      gcry_md_reset (prf);
      hc = doHMAC (prf, prk, k, plain, plain_len);
      if (hc == NULL)
        goto hkdf_error;
      memcpy (result, hc, k);
      result += k;
    }

  /* K(t):d */
  d = out_len % k;
  if (d > 0)
    {
      if (t > 0)
        memcpy (plain, result - k, k);
      memcpy (plain + k + ctx_len, &i, 4);
      gcry_md_reset (prf);
      hc = doHMAC (prf, prk, k, plain, plain_len);
      if (hc == NULL)
        goto hkdf_error;
      memcpy (result, hc, d);
    }

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


/* end of crypto_hkdf.c */

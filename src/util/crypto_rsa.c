/*
   This file is part of GNUnet
   Copyright (C) 2014,2016,2019 GNUnet e.V.

   GNUnet is free software: you can redistribute it and/or modify it
   under the terms of the GNU Affero General Public License as published
   by the Free Software Foundation, either version 3 of the License,
   or (at your option) any later version.

   GNUnet is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Affero General Public License for more details.

   You should have received a copy of the GNU Affero General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.

     SPDX-License-Identifier: AGPL3.0-or-later
 */

/**
 * @file util/crypto_rsa.c
 * @brief Chaum-style Blind signatures based on RSA
 * @author Sree Harsha Totakura <sreeharsha@totakura.in>
 * @author Christian Grothoff
 * @author Jeffrey Burdges <burdges@gnunet.org>
 */
#include "platform.h"
#include <gcrypt.h>
#include "gnunet_crypto_lib.h"
#include "benchmark.h"

#define LOG(kind, ...) GNUNET_log_from (kind, "util-crypto-rsa", __VA_ARGS__)


/**
 * The private information of an RSA key pair.
 */
struct GNUNET_CRYPTO_RsaPrivateKey
{
  /**
   * Libgcrypt S-expression for the RSA private key.
   */
  gcry_sexp_t sexp;
};


/**
 * The public information of an RSA key pair.
 */
struct GNUNET_CRYPTO_RsaPublicKey
{
  /**
   * Libgcrypt S-expression for the RSA public key.
   */
  gcry_sexp_t sexp;
};


/**
 * @brief an RSA signature
 */
struct GNUNET_CRYPTO_RsaSignature
{
  /**
   * Libgcrypt S-expression for the RSA signature.
   */
  gcry_sexp_t sexp;
};


/**
 * @brief RSA blinding key
 */
struct RsaBlindingKey
{
  /**
   * Random value used for blinding.
   */
  gcry_mpi_t r;
};


/**
 * Extract values from an S-expression.
 *
 * @param array where to store the result(s)
 * @param sexp S-expression to parse
 * @param topname top-level name in the S-expression that is of interest
 * @param elems names of the elements to extract
 * @return 0 on success
 */
static int
key_from_sexp (gcry_mpi_t *array,
               gcry_sexp_t sexp,
               const char *topname,
               const char *elems)
{
  gcry_sexp_t list;
  gcry_sexp_t l2;
  const char *s;
  unsigned int idx;

  if (! (list = gcry_sexp_find_token (sexp, topname, 0)))
    return 1;
  l2 = gcry_sexp_cadr (list);
  gcry_sexp_release (list);
  list = l2;
  if (! list)
    return 2;
  idx = 0;
  for (s = elems; *s; s++, idx++)
  {
    if (! (l2 = gcry_sexp_find_token (list, s, 1)))
    {
      for (unsigned int i = 0; i < idx; i++)
      {
        gcry_free (array[i]);
        array[i] = NULL;
      }
      gcry_sexp_release (list);
      return 3;                 /* required parameter not found */
    }
    array[idx] = gcry_sexp_nth_mpi (l2, 1, GCRYMPI_FMT_USG);
    gcry_sexp_release (l2);
    if (! array[idx])
    {
      for (unsigned int i = 0; i < idx; i++)
      {
        gcry_free (array[i]);
        array[i] = NULL;
      }
      gcry_sexp_release (list);
      return 4;                 /* required parameter is invalid */
    }
  }
  gcry_sexp_release (list);
  return 0;
}


/**
 * Create a new private key. Caller must free return value.
 *
 * @param len length of the key in bits (i.e. 2048)
 * @return fresh private key
 */
struct GNUNET_CRYPTO_RsaPrivateKey *
GNUNET_CRYPTO_rsa_private_key_create (unsigned int len)
{
  struct GNUNET_CRYPTO_RsaPrivateKey *ret;
  gcry_sexp_t s_key;
  gcry_sexp_t s_keyparam;

  BENCHMARK_START (rsa_private_key_create);

  GNUNET_assert (0 ==
                 gcry_sexp_build (&s_keyparam,
                                  NULL,
                                  "(genkey(rsa(nbits %d)))",
                                  len));
  GNUNET_assert (0 ==
                 gcry_pk_genkey (&s_key,
                                 s_keyparam));
  gcry_sexp_release (s_keyparam);
#if EXTRA_CHECKS
  GNUNET_assert (0 ==
                 gcry_pk_testkey (s_key));
#endif
  ret = GNUNET_new (struct GNUNET_CRYPTO_RsaPrivateKey);
  ret->sexp = s_key;
  BENCHMARK_END (rsa_private_key_create);
  return ret;
}


/**
 * Free memory occupied by the private key.
 *
 * @param key pointer to the memory to free
 */
void
GNUNET_CRYPTO_rsa_private_key_free (struct GNUNET_CRYPTO_RsaPrivateKey *key)
{
  gcry_sexp_release (key->sexp);
  GNUNET_free (key);
}


/**
 * Encode the private key in a format suitable for
 * storing it into a file.
 *
 * @param key the private key
 * @param[out] buffer set to a buffer with the encoded key
 * @return size of memory allocated in @a buffer
 */
size_t
GNUNET_CRYPTO_rsa_private_key_encode (const struct
                                      GNUNET_CRYPTO_RsaPrivateKey *key,
                                      void **buffer)
{
  size_t n;
  char *b;

  n = gcry_sexp_sprint (key->sexp,
                        GCRYSEXP_FMT_DEFAULT,
                        NULL,
                        0);
  b = GNUNET_malloc (n);
  GNUNET_assert ((n - 1) ==      /* since the last byte is \0 */
                 gcry_sexp_sprint (key->sexp,
                                   GCRYSEXP_FMT_DEFAULT,
                                   b,
                                   n));
  *buffer = b;
  return n;
}


/**
 * Decode the private key from the data-format back
 * to the "normal", internal format.
 *
 * @param buf the buffer where the private key data is stored
 * @param buf_size the size of the data in @a buf
 * @return NULL on error
 */
struct GNUNET_CRYPTO_RsaPrivateKey *
GNUNET_CRYPTO_rsa_private_key_decode (const void *buf,
                                      size_t buf_size)
{
  struct GNUNET_CRYPTO_RsaPrivateKey *key;

  key = GNUNET_new (struct GNUNET_CRYPTO_RsaPrivateKey);
  if (0 !=
      gcry_sexp_new (&key->sexp,
                     buf,
                     buf_size,
                     0))
  {
    LOG (GNUNET_ERROR_TYPE_WARNING,
         "Decoded private key is not valid\n");
    GNUNET_free (key);
    return NULL;
  }
  if (0 != gcry_pk_testkey (key->sexp))
  {
    LOG (GNUNET_ERROR_TYPE_WARNING,
         "Decoded private key is not valid\n");
    GNUNET_CRYPTO_rsa_private_key_free (key);
    return NULL;
  }
  return key;
}


/**
 * Extract the public key of the given private key.
 *
 * @param priv the private key
 * @retur NULL on error, otherwise the public key
 */
struct GNUNET_CRYPTO_RsaPublicKey *
GNUNET_CRYPTO_rsa_private_key_get_public (const struct
                                          GNUNET_CRYPTO_RsaPrivateKey *priv)
{
  struct GNUNET_CRYPTO_RsaPublicKey *pub;
  gcry_mpi_t ne[2];
  int rc;
  gcry_sexp_t result;

  BENCHMARK_START (rsa_private_key_get_public);

  rc = key_from_sexp (ne, priv->sexp, "public-key", "ne");
  if (0 != rc)
    rc = key_from_sexp (ne, priv->sexp, "private-key", "ne");
  if (0 != rc)
    rc = key_from_sexp (ne, priv->sexp, "rsa", "ne");
  if (0 != rc)
  {
    GNUNET_break_op (0);
    return NULL;
  }
  rc = gcry_sexp_build (&result,
                        NULL,
                        "(public-key(rsa(n %m)(e %m)))",
                        ne[0],
                        ne[1]);
  gcry_mpi_release (ne[0]);
  gcry_mpi_release (ne[1]);
  pub = GNUNET_new (struct GNUNET_CRYPTO_RsaPublicKey);
  pub->sexp = result;
  BENCHMARK_END (rsa_private_key_get_public);
  return pub;
}


/**
 * Free memory occupied by the public key.
 *
 * @param key pointer to the memory to free
 */
void
GNUNET_CRYPTO_rsa_public_key_free (struct GNUNET_CRYPTO_RsaPublicKey *key)
{
  gcry_sexp_release (key->sexp);
  GNUNET_free (key);
}


GNUNET_NETWORK_STRUCT_BEGIN

/**
 * Format of the header of a serialized RSA public key.
 */
struct GNUNET_CRYPTO_RsaPublicKeyHeaderP
{
  /**
   * length of modulus 'n' in bytes, in NBO
   */
  uint16_t modulus_length GNUNET_PACKED;

  /**
   * length of exponent in bytes, in NBO
   */
  uint16_t public_exponent_length GNUNET_PACKED;

  /* followed by variable-size modulus and
     public exponent follows as big-endian encoded
     integers */
};

GNUNET_NETWORK_STRUCT_END


/**
 * Encode the public key in a format suitable for
 * storing it into a file.
 *
 * @param key the private key
 * @param[out] buffer set to a buffer with the encoded key
 * @return size of memory allocated in @a buffer
 */
size_t
GNUNET_CRYPTO_rsa_public_key_encode (
  const struct GNUNET_CRYPTO_RsaPublicKey *key,
  void **buffer)
{
  gcry_mpi_t ne[2];
  size_t n_size;
  size_t e_size;
  size_t rsize;
  size_t buf_size;
  char *buf;
  struct GNUNET_CRYPTO_RsaPublicKeyHeaderP hdr;
  int ret;

  ret = key_from_sexp (ne, key->sexp, "public-key", "ne");
  if (0 != ret)
    ret = key_from_sexp (ne, key->sexp, "rsa", "ne");
  if (0 != ret)
  {
    GNUNET_break (0);
    *buffer = NULL;
    return 0;
  }
  gcry_mpi_print (GCRYMPI_FMT_USG,
                  NULL,
                  0,
                  &n_size,
                  ne[0]);
  gcry_mpi_print (GCRYMPI_FMT_USG,
                  NULL,
                  0,
                  &e_size,
                  ne[1]);
  if ( (e_size > UINT16_MAX) ||
       (n_size > UINT16_MAX) )
  {
    GNUNET_break (0);
    *buffer = NULL;
    gcry_mpi_release (ne[0]);
    gcry_mpi_release (ne[1]);
    return 0;
  }
  buf_size = n_size + e_size + sizeof (hdr);
  buf = GNUNET_malloc (buf_size);
  hdr.modulus_length = htons ((uint16_t) n_size);
  hdr.public_exponent_length = htons ((uint16_t) e_size);
  memcpy (buf, &hdr, sizeof (hdr));
  GNUNET_assert (0 ==
                 gcry_mpi_print (GCRYMPI_FMT_USG,
                                 (unsigned char *) &buf[sizeof (hdr)],
                                 n_size,
                                 &rsize,
                                 ne[0]));

  GNUNET_assert (0 ==
                 gcry_mpi_print (GCRYMPI_FMT_USG,
                                 (unsigned char *) &buf[sizeof (hdr) + n_size],
                                 e_size,
                                 &rsize,
                                 ne[1]));
  *buffer = buf;
  gcry_mpi_release (ne[0]);
  gcry_mpi_release (ne[1]);
  return buf_size;
}


/**
 * Compute hash over the public key.
 *
 * @param key public key to hash
 * @param hc where to store the hash code
 */
void
GNUNET_CRYPTO_rsa_public_key_hash (const struct GNUNET_CRYPTO_RsaPublicKey *key,
                                   struct GNUNET_HashCode *hc)
{
  void *buf;
  size_t buf_size;

  buf_size = GNUNET_CRYPTO_rsa_public_key_encode (key,
                                                  &buf);
  GNUNET_CRYPTO_hash (buf,
                      buf_size,
                      hc);
  GNUNET_free (buf);
}


/**
 * Decode the public key from the data-format back
 * to the "normal", internal format.
 *
 * @param buf the buffer where the public key data is stored
 * @param len the length of the data in @a buf
 * @return NULL on error
 */
struct GNUNET_CRYPTO_RsaPublicKey *
GNUNET_CRYPTO_rsa_public_key_decode (const char *buf,
                                     size_t len)
{
  struct GNUNET_CRYPTO_RsaPublicKey *key;
  struct GNUNET_CRYPTO_RsaPublicKeyHeaderP hdr;
  size_t e_size;
  size_t n_size;
  gcry_mpi_t n;
  gcry_mpi_t e;
  gcry_sexp_t data;

  if (len < sizeof (hdr))
  {
    GNUNET_break_op (0);
    return NULL;
  }
  memcpy (&hdr, buf, sizeof (hdr));
  n_size = ntohs (hdr.modulus_length);
  e_size = ntohs (hdr.public_exponent_length);
  if (len != sizeof (hdr) + e_size + n_size)
  {
    GNUNET_break_op (0);
    return NULL;
  }
  if (0 !=
      gcry_mpi_scan (&n,
                     GCRYMPI_FMT_USG,
                     &buf[sizeof (hdr)],
                     n_size,
                     NULL))
  {
    GNUNET_break_op (0);
    return NULL;
  }
  if (0 !=
      gcry_mpi_scan (&e,
                     GCRYMPI_FMT_USG,
                     &buf[sizeof (hdr) + n_size],
                     e_size,
                     NULL))
  {
    GNUNET_break_op (0);
    gcry_mpi_release (n);
    return NULL;
  }

  if (0 !=
      gcry_sexp_build (&data,
                       NULL,
                       "(public-key(rsa(n %m)(e %m)))",
                       n,
                       e))
  {
    GNUNET_break (0);
    gcry_mpi_release (n);
    gcry_mpi_release (e);
    return NULL;
  }
  gcry_mpi_release (n);
  gcry_mpi_release (e);
  key = GNUNET_new (struct GNUNET_CRYPTO_RsaPublicKey);
  key->sexp = data;
  return key;
}


/**
 * Test for malicious RSA key.
 *
 * Assuming n is an RSA modulous and r is generated using a call to
 * GNUNET_CRYPTO_kdf_mod_mpi, if gcd(r,n) != 1 then n must be a
 * malicious RSA key designed to deanomize the user.
 *
 * @param r KDF result
 * @param n RSA modulus
 * @return True if gcd(r,n) = 1, False means RSA key is malicious
 */
static int
rsa_gcd_validate (gcry_mpi_t r, gcry_mpi_t n)
{
  gcry_mpi_t g;
  int t;

  g = gcry_mpi_new (0);
  t = gcry_mpi_gcd (g, r, n);
  gcry_mpi_release (g);
  return t;
}


/**
 * Create a blinding key
 *
 * @param len length of the key in bits (i.e. 2048)
 * @param bks pre-secret to use to derive the blinding key
 * @return the newly created blinding key, NULL if RSA key is malicious
 */
static struct RsaBlindingKey *
rsa_blinding_key_derive (const struct GNUNET_CRYPTO_RsaPublicKey *pkey,
                         const struct GNUNET_CRYPTO_RsaBlindingKeySecret *bks)
{
  char *xts = "Blinding KDF extrator HMAC key";  /* Trusts bks' randomness more */
  struct RsaBlindingKey *blind;
  gcry_mpi_t n;

  blind = GNUNET_new (struct RsaBlindingKey);
  GNUNET_assert (NULL != blind);

  /* Extract the composite n from the RSA public key */
  GNUNET_assert (0 == key_from_sexp (&n, pkey->sexp, "rsa", "n"));
  /* Assert that it at least looks like an RSA key */
  GNUNET_assert (0 == gcry_mpi_get_flag (n, GCRYMPI_FLAG_OPAQUE));

  GNUNET_CRYPTO_kdf_mod_mpi (&blind->r,
                             n,
                             xts, strlen (xts),
                             bks, sizeof(*bks),
                             "Blinding KDF");
  if (0 == rsa_gcd_validate (blind->r, n))
  {
    GNUNET_free (blind);
    blind = NULL;
  }

  gcry_mpi_release (n);
  return blind;
}


/*
   We originally added GNUNET_CRYPTO_kdf_mod_mpi for the benifit of the
   previous routine.

   There was previously a call to GNUNET_CRYPTO_kdf in
   bkey = rsa_blinding_key_derive (len, bks);
   that gives exactly len bits where
   len = GNUNET_CRYPTO_rsa_public_key_len (pkey);

   Now r = 2^(len-1)/pkey.n is the probability that a set high bit being
   okay, meaning bkey < pkey.n.  It follows that (1-r)/2 of the time bkey >
   pkey.n making the effective bkey be
   bkey mod pkey.n = bkey - pkey.n
   so the effective bkey has its high bit set with probability r/2.

   We expect r to be close to 1/2 if the exchange is honest, but the
   exchange can choose r otherwise.

   In blind signing, the exchange sees
   B = bkey * S mod pkey.n
   On deposit, the exchange sees S so they can compute bkey' = B/S mod
   pkey.n for all B they recorded to see if bkey' has it's high bit set.
   Also, note the exchange can compute 1/S efficiently since they know the
   factors of pkey.n.

   I suppose that happens with probability r/(1+r) if its the wrong B, not
   completely sure.  If otoh we've the right B, then we've the probability
   r/2 of a set high bit in the effective bkey.

   Interestingly, r^2-r has a maximum at the default r=1/2 anyways, giving
   the wrong and right probabilities 1/3 and 1/4, respectively.

   I feared this gives the exchange a meaningful fraction of a bit of
   information per coin involved in the transaction.  It sounds damaging if
   numerous coins were involved.  And it could run across transactions in
   some scenarios.

   We fixed this by using a more uniform deterministic pseudo-random number
   generator for blinding factors.  I do not believe this to be a problem
   for the rsa_full_domain_hash routine, but better safe than sorry.
 */


/**
 * Compare the values of two signatures.
 *
 * @param s1 one signature
 * @param s2 the other signature
 * @return 0 if the two are equal
 */
int
GNUNET_CRYPTO_rsa_signature_cmp (const struct GNUNET_CRYPTO_RsaSignature *s1,
                                 const struct GNUNET_CRYPTO_RsaSignature *s2)
{
  void *b1;
  void *b2;
  size_t z1;
  size_t z2;
  int ret;

  z1 = GNUNET_CRYPTO_rsa_signature_encode (s1,
                                           &b1);
  z2 = GNUNET_CRYPTO_rsa_signature_encode (s2,
                                           &b2);
  if (z1 != z2)
    ret = 1;
  else
    ret = memcmp (b1,
                  b2,
                  z1);
  GNUNET_free (b1);
  GNUNET_free (b2);
  return ret;
}


/**
 * Compare the values of two public keys.
 *
 * @param p1 one public key
 * @param p2 the other public key
 * @return 0 if the two are equal
 */
int
GNUNET_CRYPTO_rsa_public_key_cmp (const struct GNUNET_CRYPTO_RsaPublicKey *p1,
                                  const struct GNUNET_CRYPTO_RsaPublicKey *p2)
{
  void *b1;
  void *b2;
  size_t z1;
  size_t z2;
  int ret;

  z1 = GNUNET_CRYPTO_rsa_public_key_encode (p1,
                                            &b1);
  z2 = GNUNET_CRYPTO_rsa_public_key_encode (p2,
                                            &b2);
  if (z1 != z2)
    ret = 1;
  else
    ret = memcmp (b1,
                  b2,
                  z1);
  GNUNET_free (b1);
  GNUNET_free (b2);
  return ret;
}


/**
 * Compare the values of two private keys.
 *
 * @param p1 one private key
 * @param p2 the other private key
 * @return 0 if the two are equal
 */
int
GNUNET_CRYPTO_rsa_private_key_cmp (const struct GNUNET_CRYPTO_RsaPrivateKey *p1,
                                   const struct GNUNET_CRYPTO_RsaPrivateKey *p2)
{
  void *b1;
  void *b2;
  size_t z1;
  size_t z2;
  int ret;

  z1 = GNUNET_CRYPTO_rsa_private_key_encode (p1,
                                             &b1);
  z2 = GNUNET_CRYPTO_rsa_private_key_encode (p2,
                                             &b2);
  if (z1 != z2)
    ret = 1;
  else
    ret = memcmp (b1,
                  b2,
                  z1);
  GNUNET_free (b1);
  GNUNET_free (b2);
  return ret;
}


/**
 * Obtain the length of the RSA key in bits.
 *
 * @param key the public key to introspect
 * @return length of the key in bits
 */
unsigned int
GNUNET_CRYPTO_rsa_public_key_len (const struct GNUNET_CRYPTO_RsaPublicKey *key)
{
  gcry_mpi_t n;
  unsigned int rval;

  if (0 != key_from_sexp (&n, key->sexp, "rsa", "n"))
  {   /* Not an RSA public key */
    GNUNET_break (0);
    return 0;
  }
  rval = gcry_mpi_get_nbits (n);
  gcry_mpi_release (n);
  return rval;
}


/**
 * Destroy a blinding key
 *
 * @param bkey the blinding key to destroy
 */
static void
rsa_blinding_key_free (struct RsaBlindingKey *bkey)
{
  gcry_mpi_release (bkey->r);
  GNUNET_free (bkey);
}


/**
 * Print an MPI to a newly created buffer
 *
 * @param v MPI to print.
 * @param[out] newly allocated buffer containing the result
 * @return number of bytes stored in @a buffer
 */
static size_t
numeric_mpi_alloc_n_print (gcry_mpi_t v,
                           char **buffer)
{
  size_t n;
  char *b;
  size_t rsize;

  gcry_mpi_print (GCRYMPI_FMT_USG,
                  NULL,
                  0,
                  &n,
                  v);
  b = GNUNET_malloc (n);
  GNUNET_assert (0 ==
                 gcry_mpi_print (GCRYMPI_FMT_USG,
                                 (unsigned char *) b,
                                 n,
                                 &rsize,
                                 v));
  *buffer = b;
  return n;
}


/**
 * Computes a full domain hash seeded by the given public key.
 * This gives a measure of provable security to the Taler exchange
 * against one-more forgery attacks.  See:
 *   https://eprint.iacr.org/2001/002.pdf
 *   http://www.di.ens.fr/~pointche/Documents/Papers/2001_fcA.pdf
 *
 * @param hash initial hash of the message to sign
 * @param pkey the public key of the signer
 * @param rsize If not NULL, the number of bytes actually stored in buffer
 * @return MPI value set to the FDH, NULL if RSA key is malicious
 */
static gcry_mpi_t
rsa_full_domain_hash (const struct GNUNET_CRYPTO_RsaPublicKey *pkey,
                      const struct GNUNET_HashCode *hash)
{
  gcry_mpi_t r, n;
  void *xts;
  size_t xts_len;
  int ok;

  /* Extract the composite n from the RSA public key */
  GNUNET_assert (0 == key_from_sexp (&n, pkey->sexp, "rsa", "n"));
  /* Assert that it at least looks like an RSA key */
  GNUNET_assert (0 == gcry_mpi_get_flag (n, GCRYMPI_FLAG_OPAQUE));

  /* We key with the public denomination key as a homage to RSA-PSS by  *
  * Mihir Bellare and Phillip Rogaway.  Doing this lowers the degree   *
  * of the hypothetical polyomial-time attack on RSA-KTI created by a  *
  * polynomial-time one-more forgary attack.  Yey seeding!             */
  xts_len = GNUNET_CRYPTO_rsa_public_key_encode (pkey, &xts);

  GNUNET_CRYPTO_kdf_mod_mpi (&r,
                             n,
                             xts, xts_len,
                             hash, sizeof(*hash),
                             "RSA-FDA FTpsW!");
  GNUNET_free (xts);

  ok = rsa_gcd_validate (r, n);
  gcry_mpi_release (n);
  if (ok)
    return r;
  gcry_mpi_release (r);
  return NULL;
}


/**
 * Blinds the given message with the given blinding key
 *
 * @param hash hash of the message to sign
 * @param bkey the blinding key
 * @param pkey the public key of the signer
 * @param[out] buf set to a buffer with the blinded message to be signed
 * @param[out] buf_size number of bytes stored in @a buf
 * @return #GNUNET_YES if successful, #GNUNET_NO if RSA key is malicious
 */
int
GNUNET_CRYPTO_rsa_blind (const struct GNUNET_HashCode *hash,
                         const struct GNUNET_CRYPTO_RsaBlindingKeySecret *bks,
                         struct GNUNET_CRYPTO_RsaPublicKey *pkey,
                         void **buf,
                         size_t *buf_size)
{
  struct RsaBlindingKey *bkey;
  gcry_mpi_t data;
  gcry_mpi_t ne[2];
  gcry_mpi_t r_e;
  gcry_mpi_t data_r_e;
  int ret;

  BENCHMARK_START (rsa_blind);

  GNUNET_assert (buf != NULL);
  GNUNET_assert (buf_size != NULL);
  ret = key_from_sexp (ne, pkey->sexp, "public-key", "ne");
  if (0 != ret)
    ret = key_from_sexp (ne, pkey->sexp, "rsa", "ne");
  if (0 != ret)
  {
    GNUNET_break (0);
    *buf = NULL;
    *buf_size = 0;
    return 0;
  }

  data = rsa_full_domain_hash (pkey, hash);
  if (NULL == data)
    goto rsa_gcd_validate_failure;

  bkey = rsa_blinding_key_derive (pkey, bks);
  if (NULL == bkey)
  {
    gcry_mpi_release (data);
    goto rsa_gcd_validate_failure;
  }

  r_e = gcry_mpi_new (0);
  gcry_mpi_powm (r_e,
                 bkey->r,
                 ne[1],
                 ne[0]);
  data_r_e = gcry_mpi_new (0);
  gcry_mpi_mulm (data_r_e,
                 data,
                 r_e,
                 ne[0]);
  gcry_mpi_release (data);
  gcry_mpi_release (ne[0]);
  gcry_mpi_release (ne[1]);
  gcry_mpi_release (r_e);
  rsa_blinding_key_free (bkey);

  *buf_size = numeric_mpi_alloc_n_print (data_r_e,
                                         (char **) buf);
  gcry_mpi_release (data_r_e);

  BENCHMARK_END (rsa_blind);

  return GNUNET_YES;

rsa_gcd_validate_failure:
  /* We know the RSA key is malicious here, so warn the wallet. */
  /* GNUNET_break_op (0); */
  gcry_mpi_release (ne[0]);
  gcry_mpi_release (ne[1]);
  *buf = NULL;
  *buf_size = 0;
  return GNUNET_NO;
}


/**
 * Convert an MPI to an S-expression suitable for signature operations.
 *
 * @param value pointer to the data to convert
 * @return converted s-expression
 */
static gcry_sexp_t
mpi_to_sexp (gcry_mpi_t value)
{
  gcry_sexp_t data = NULL;

  GNUNET_assert (0 ==
                 gcry_sexp_build (&data,
                                  NULL,
                                  "(data (flags raw) (value %M))",
                                  value));
  return data;
}


/**
 * Sign the given MPI.
 *
 * @param key private key to use for the signing
 * @param value the MPI to sign
 * @return NULL on error, signature on success
 */
static struct GNUNET_CRYPTO_RsaSignature *
rsa_sign_mpi (const struct GNUNET_CRYPTO_RsaPrivateKey *key,
              gcry_mpi_t value)
{
  struct GNUNET_CRYPTO_RsaSignature *sig;
  gcry_sexp_t data;
  gcry_sexp_t result;
  int rc;

  data = mpi_to_sexp (value);

  if (0 !=
      (rc = gcry_pk_sign (&result,
                          data,
                          key->sexp)))
  {
    LOG (GNUNET_ERROR_TYPE_WARNING,
         _ ("RSA signing failed at %s:%d: %s\n"),
         __FILE__,
         __LINE__,
         gcry_strerror (rc));
    GNUNET_break (0);
    return NULL;
  }

  /* Lenstra protection was first added to libgcrypt 1.6.4
   * with commit c17f84bd02d7ee93845e92e20f6ddba814961588.
   */
#if GCRYPT_VERSION_NUMBER < 0x010604
  /* verify signature (guards against Lenstra's attack with fault injection...) */
  struct GNUNET_CRYPTO_RsaPublicKey *public_key =
    GNUNET_CRYPTO_rsa_private_key_get_public (key);
  if (0 !=
      gcry_pk_verify (result,
                      data,
                      public_key->sexp))
  {
    GNUNET_break (0);
    GNUNET_CRYPTO_rsa_public_key_free (public_key);
    gcry_sexp_release (data);
    gcry_sexp_release (result);
    return NULL;
  }
  GNUNET_CRYPTO_rsa_public_key_free (public_key);
#endif

  /* return signature */
  gcry_sexp_release (data);
  sig = GNUNET_new (struct GNUNET_CRYPTO_RsaSignature);
  sig->sexp = result;
  return sig;
}


/**
 * Sign a blinded value, which must be a full domain hash of a message.
 *
 * @param key private key to use for the signing
 * @param msg the message to sign
 * @param msg_len number of bytes in @a msg to sign
 * @return NULL on error, signature on success
 */
struct GNUNET_CRYPTO_RsaSignature *
GNUNET_CRYPTO_rsa_sign_blinded (const struct GNUNET_CRYPTO_RsaPrivateKey *key,
                                const void *msg,
                                size_t msg_len)
{
  gcry_mpi_t v = NULL;
  struct GNUNET_CRYPTO_RsaSignature *sig;

  BENCHMARK_START (rsa_sign_blinded);

  GNUNET_assert (0 ==
                 gcry_mpi_scan (&v,
                                GCRYMPI_FMT_USG,
                                msg,
                                msg_len,
                                NULL));

  sig = rsa_sign_mpi (key, v);
  gcry_mpi_release (v);
  BENCHMARK_END (rsa_sign_blinded);
  return sig;
}


/**
 * Create and sign a full domain hash of a message.
 *
 * @param key private key to use for the signing
 * @param hash the hash of the message to sign
 * @return NULL on error, including a malicious RSA key, signature on success
 */
struct GNUNET_CRYPTO_RsaSignature *
GNUNET_CRYPTO_rsa_sign_fdh (const struct GNUNET_CRYPTO_RsaPrivateKey *key,
                            const struct GNUNET_HashCode *hash)
{
  struct GNUNET_CRYPTO_RsaPublicKey *pkey;
  gcry_mpi_t v = NULL;
  struct GNUNET_CRYPTO_RsaSignature *sig;

  pkey = GNUNET_CRYPTO_rsa_private_key_get_public (key);
  v = rsa_full_domain_hash (pkey, hash);
  GNUNET_CRYPTO_rsa_public_key_free (pkey);
  if (NULL == v)   /* rsa_gcd_validate failed meaning */
    return NULL;   /* our *own* RSA key is malicious. */

  sig = rsa_sign_mpi (key, v);
  gcry_mpi_release (v);
  return sig;
}


/**
 * Free memory occupied by signature.
 *
 * @param sig memory to freee
 */
void
GNUNET_CRYPTO_rsa_signature_free (struct GNUNET_CRYPTO_RsaSignature *sig)
{
  gcry_sexp_release (sig->sexp);
  GNUNET_free (sig);
}


/**
 * Encode the given signature in a format suitable for storing it into a file.
 *
 * @param sig the signature
 * @param[out] buffer set to a buffer with the encoded key
 * @return size of memory allocated in @a buffer
 */
size_t
GNUNET_CRYPTO_rsa_signature_encode (
  const struct GNUNET_CRYPTO_RsaSignature *sig,
  void **buffer)
{
  gcry_mpi_t s;
  size_t buf_size;
  size_t rsize;
  unsigned char *buf;
  int ret;

  ret = key_from_sexp (&s,
                       sig->sexp,
                       "sig-val",
                       "s");
  if (0 != ret)
    ret = key_from_sexp (&s,
                         sig->sexp,
                         "rsa",
                         "s");
  GNUNET_assert (0 == ret);
  gcry_mpi_print (GCRYMPI_FMT_USG,
                  NULL,
                  0,
                  &buf_size,
                  s);
  buf = GNUNET_malloc (buf_size);
  GNUNET_assert (0 ==
                 gcry_mpi_print (GCRYMPI_FMT_USG,
                                 buf,
                                 buf_size,
                                 &rsize,
                                 s));
  GNUNET_assert (rsize == buf_size);
  *buffer = (void *) buf;
  gcry_mpi_release (s);
  return buf_size;
}


/**
 * Decode the signature from the data-format back to the "normal", internal
 * format.
 *
 * @param buf the buffer where the public key data is stored
 * @param buf_size the size of the data in @a buf
 * @return NULL on error
 */
struct GNUNET_CRYPTO_RsaSignature *
GNUNET_CRYPTO_rsa_signature_decode (const void *buf,
                                    size_t buf_size)
{
  struct GNUNET_CRYPTO_RsaSignature *sig;
  gcry_mpi_t s;
  gcry_sexp_t data;

  if (0 !=
      gcry_mpi_scan (&s,
                     GCRYMPI_FMT_USG,
                     buf,
                     buf_size,
                     NULL))
  {
    GNUNET_break_op (0);
    return NULL;
  }

  if (0 !=
      gcry_sexp_build (&data,
                       NULL,
                       "(sig-val(rsa(s %M)))",
                       s))
  {
    GNUNET_break (0);
    gcry_mpi_release (s);
    return NULL;
  }
  gcry_mpi_release (s);
  sig = GNUNET_new (struct GNUNET_CRYPTO_RsaSignature);
  sig->sexp = data;
  return sig;
}


/**
 * Duplicate the given public key
 *
 * @param key the public key to duplicate
 * @return the duplicate key; NULL upon error
 */
struct GNUNET_CRYPTO_RsaPublicKey *
GNUNET_CRYPTO_rsa_public_key_dup (const struct GNUNET_CRYPTO_RsaPublicKey *key)
{
  struct GNUNET_CRYPTO_RsaPublicKey *dup;
  gcry_sexp_t dup_sexp;
  size_t erroff;

  /* check if we really are exporting a public key */
  dup_sexp = gcry_sexp_find_token (key->sexp, "public-key", 0);
  GNUNET_assert (NULL != dup_sexp);
  gcry_sexp_release (dup_sexp);
  /* copy the sexp */
  GNUNET_assert (0 == gcry_sexp_build (&dup_sexp, &erroff, "%S", key->sexp));
  dup = GNUNET_new (struct GNUNET_CRYPTO_RsaPublicKey);
  dup->sexp = dup_sexp;
  return dup;
}


/**
 * Unblind a blind-signed signature.  The signature should have been generated
 * with #GNUNET_CRYPTO_rsa_sign() using a hash that was blinded with
 * #GNUNET_CRYPTO_rsa_blind().
 *
 * @param sig the signature made on the blinded signature purpose
 * @param bks the blinding key secret used to blind the signature purpose
 * @param pkey the public key of the signer
 * @return unblinded signature on success, NULL if RSA key is bad or malicious.
 */
struct GNUNET_CRYPTO_RsaSignature *
GNUNET_CRYPTO_rsa_unblind (const struct GNUNET_CRYPTO_RsaSignature *sig,
                           const struct GNUNET_CRYPTO_RsaBlindingKeySecret *bks,
                           struct GNUNET_CRYPTO_RsaPublicKey *pkey)
{
  struct RsaBlindingKey *bkey;
  gcry_mpi_t n;
  gcry_mpi_t s;
  gcry_mpi_t r_inv;
  gcry_mpi_t ubsig;
  int ret;
  struct GNUNET_CRYPTO_RsaSignature *sret;

  BENCHMARK_START (rsa_unblind);

  ret = key_from_sexp (&n, pkey->sexp, "public-key", "n");
  if (0 != ret)
    ret = key_from_sexp (&n, pkey->sexp, "rsa", "n");
  if (0 != ret)
  {
    GNUNET_break_op (0);
    return NULL;
  }
  ret = key_from_sexp (&s, sig->sexp, "sig-val", "s");
  if (0 != ret)
    ret = key_from_sexp (&s, sig->sexp, "rsa", "s");
  if (0 != ret)
  {
    gcry_mpi_release (n);
    GNUNET_break_op (0);
    return NULL;
  }

  bkey = rsa_blinding_key_derive (pkey, bks);
  if (NULL == bkey)
  {
    /* RSA key is malicious since rsa_gcd_validate failed here.
     * It should have failed during GNUNET_CRYPTO_rsa_blind too though,
     * so the exchange is being malicious in an unfamilair way, maybe
     * just trying to crash us.  */
    GNUNET_break_op (0);
    gcry_mpi_release (n);
    gcry_mpi_release (s);
    return NULL;
  }

  r_inv = gcry_mpi_new (0);
  if (1 !=
      gcry_mpi_invm (r_inv,
                     bkey->r,
                     n))
  {
    /* We cannot find r mod n, so gcd(r,n) != 1, which should get *
    * caught above, but we handle it the same here.              */
    GNUNET_break_op (0);
    gcry_mpi_release (r_inv);
    rsa_blinding_key_free (bkey);
    gcry_mpi_release (n);
    gcry_mpi_release (s);
    return NULL;
  }

  ubsig = gcry_mpi_new (0);
  gcry_mpi_mulm (ubsig, s, r_inv, n);
  gcry_mpi_release (n);
  gcry_mpi_release (r_inv);
  gcry_mpi_release (s);
  rsa_blinding_key_free (bkey);

  sret = GNUNET_new (struct GNUNET_CRYPTO_RsaSignature);
  GNUNET_assert (0 ==
                 gcry_sexp_build (&sret->sexp,
                                  NULL,
                                  "(sig-val (rsa (s %M)))",
                                  ubsig));
  gcry_mpi_release (ubsig);
  BENCHMARK_END (rsa_unblind);
  return sret;
}


/**
 * Verify whether the given hash corresponds to the given signature and
 * the signature is valid with respect to the given public key.
 *
 * @param hash hash of the message to verify to match the @a sig
 * @param sig signature that is being validated
 * @param pkey public key of the signer
 * @returns #GNUNET_YES if ok, #GNUNET_NO if RSA key is malicious, #GNUNET_SYSERR if signature is invalid
 */
int
GNUNET_CRYPTO_rsa_verify (const struct GNUNET_HashCode *hash,
                          const struct GNUNET_CRYPTO_RsaSignature *sig,
                          const struct GNUNET_CRYPTO_RsaPublicKey *pkey)
{
  gcry_sexp_t data;
  gcry_mpi_t r;
  int rc;

  BENCHMARK_START (rsa_verify);

  r = rsa_full_domain_hash (pkey, hash);
  if (NULL == r)
  {
    GNUNET_break_op (0);
    /* RSA key is malicious since rsa_gcd_validate failed here.
     * It should have failed during GNUNET_CRYPTO_rsa_blind too though,
     * so the exchange is being malicious in an unfamilair way, maybe
     * just trying to crash us.  Arguably, we've only an internal error
     * though because we should've detected this in our previous call
     * to GNUNET_CRYPTO_rsa_unblind. */return GNUNET_NO;
  }

  data = mpi_to_sexp (r);
  gcry_mpi_release (r);

  rc = gcry_pk_verify (sig->sexp,
                       data,
                       pkey->sexp);
  gcry_sexp_release (data);
  if (0 != rc)
  {
    LOG (GNUNET_ERROR_TYPE_WARNING,
         _ ("RSA signature verification failed at %s:%d: %s\n"),
         __FILE__,
         __LINE__,
         gcry_strerror (rc));
    return GNUNET_SYSERR;
    BENCHMARK_END (rsa_verify);
  }
  BENCHMARK_END (rsa_verify);
  return GNUNET_OK;
}


/**
 * Duplicate the given private key
 *
 * @param key the private key to duplicate
 * @return the duplicate key; NULL upon error
 */
struct GNUNET_CRYPTO_RsaPrivateKey *
GNUNET_CRYPTO_rsa_private_key_dup (const struct
                                   GNUNET_CRYPTO_RsaPrivateKey *key)
{
  struct GNUNET_CRYPTO_RsaPrivateKey *dup;
  gcry_sexp_t dup_sexp;
  size_t erroff;

  /* check if we really are exporting a private key */
  dup_sexp = gcry_sexp_find_token (key->sexp, "private-key", 0);
  GNUNET_assert (NULL != dup_sexp);
  gcry_sexp_release (dup_sexp);
  /* copy the sexp */
  GNUNET_assert (0 == gcry_sexp_build (&dup_sexp, &erroff, "%S", key->sexp));
  dup = GNUNET_new (struct GNUNET_CRYPTO_RsaPrivateKey);
  dup->sexp = dup_sexp;
  return dup;
}


/**
 * Duplicate the given private key
 *
 * @param key the private key to duplicate
 * @return the duplicate key; NULL upon error
 */
struct GNUNET_CRYPTO_RsaSignature *
GNUNET_CRYPTO_rsa_signature_dup (const struct GNUNET_CRYPTO_RsaSignature *sig)
{
  struct GNUNET_CRYPTO_RsaSignature *dup;
  gcry_sexp_t dup_sexp;
  size_t erroff;
  gcry_mpi_t s;
  int ret;

  /* verify that this is an RSA signature */
  ret = key_from_sexp (&s, sig->sexp, "sig-val", "s");
  if (0 != ret)
    ret = key_from_sexp (&s, sig->sexp, "rsa", "s");
  GNUNET_assert (0 == ret);
  gcry_mpi_release (s);
  /* copy the sexp */
  GNUNET_assert (0 == gcry_sexp_build (&dup_sexp, &erroff, "%S", sig->sexp));
  dup = GNUNET_new (struct GNUNET_CRYPTO_RsaSignature);
  dup->sexp = dup_sexp;
  return dup;
}


/* end of util/rsa.c */

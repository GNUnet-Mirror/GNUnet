/*
     This file is part of GNUnet.
     Copyright (C) 2012, 2013, 2015 Christian Grothoff (and other contributing authors)

     GNUnet is free software; you can redistribute it and/or modify
     it under the terms of the GNU General Public License as published
     by the Free Software Foundation; either version 3, or (at your
     option) any later version.

     GNUnet is distributed in the hope that it will be useful, but
     WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
     General Public License for more details.

     You should have received a copy of the GNU General Public License
     along with GNUnet; see the file COPYING.  If not, write to the
     Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
     Boston, MA 02110-1301, USA.
*/

/**
 * @file util/crypto_ecc.c
 * @brief public key cryptography (ECC) with libgcrypt
 * @author Christian Grothoff
 */
#include "platform.h"
#include <gcrypt.h>
#include "gnunet_crypto_lib.h"
#include "gnunet_strings_lib.h"

#define EXTRA_CHECKS 0

/**
 * Name of the curve we are using.  Note that we have hard-coded
 * structs that use 256 bits, so using a bigger curve will require
 * changes that break stuff badly.  The name of the curve given here
 * must be agreed by all peers and be supported by libgcrypt.
 */
#define CURVE "Ed25519"

#define LOG(kind,...) GNUNET_log_from (kind, "util", __VA_ARGS__)

#define LOG_STRERROR(kind,syscall) GNUNET_log_from_strerror (kind, "util", syscall)

#define LOG_STRERROR_FILE(kind,syscall,filename) GNUNET_log_from_strerror_file (kind, "util", syscall, filename)

/**
 * Log an error message at log-level 'level' that indicates
 * a failure of the command 'cmd' with the message given
 * by gcry_strerror(rc).
 */
#define LOG_GCRY(level, cmd, rc) do { LOG(level, _("`%s' failed at %s:%d with error: %s\n"), cmd, __FILE__, __LINE__, gcry_strerror(rc)); } while(0)


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
key_from_sexp (gcry_mpi_t * array,
               gcry_sexp_t sexp,
               const char *topname,
               const char *elems)
{
  gcry_sexp_t list;
  gcry_sexp_t l2;
  const char *s;
  unsigned int i;
  unsigned int idx;

  list = gcry_sexp_find_token (sexp, topname, 0);
  if (! list)
    return 1;
  l2 = gcry_sexp_cadr (list);
  gcry_sexp_release (list);
  list = l2;
  if (! list)
    return 2;

  idx = 0;
  for (s = elems; *s; s++, idx++)
  {
    l2 = gcry_sexp_find_token (list, s, 1);
    if (! l2)
    {
      for (i = 0; i < idx; i++)
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
      for (i = 0; i < idx; i++)
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
 * Convert the given private key from the network format to the
 * S-expression that can be used by libgcrypt.
 *
 * @param priv private key to decode
 * @return NULL on error
 */
static gcry_sexp_t
decode_private_ecdsa_key (const struct GNUNET_CRYPTO_EcdsaPrivateKey *priv)
{
  gcry_sexp_t result;
  int rc;

  rc = gcry_sexp_build (&result, NULL,
			"(private-key(ecc(curve \"" CURVE "\")"
                        "(d %b)))",
			(int) sizeof (priv->d), priv->d);
  if (0 != rc)
  {
    LOG_GCRY (GNUNET_ERROR_TYPE_ERROR, "gcry_sexp_build", rc);
    GNUNET_assert (0);
  }
#if EXTRA_CHECKS
  if (0 != (rc = gcry_pk_testkey (result)))
  {
    LOG_GCRY (GNUNET_ERROR_TYPE_ERROR, "gcry_pk_testkey", rc);
    GNUNET_assert (0);
  }
#endif
  return result;
}


/**
 * Convert the given private key from the network format to the
 * S-expression that can be used by libgcrypt.
 *
 * @param priv private key to decode
 * @return NULL on error
 */
static gcry_sexp_t
decode_private_eddsa_key (const struct GNUNET_CRYPTO_EddsaPrivateKey *priv)
{
  gcry_sexp_t result;
  int rc;

  rc = gcry_sexp_build (&result, NULL,
			"(private-key(ecc(curve \"" CURVE "\")"
                        "(flags eddsa)(d %b)))",
			(int)sizeof (priv->d), priv->d);
  if (0 != rc)
  {
    LOG_GCRY (GNUNET_ERROR_TYPE_ERROR, "gcry_sexp_build", rc);
    GNUNET_assert (0);
  }
#if EXTRA_CHECKS
  if (0 != (rc = gcry_pk_testkey (result)))
  {
    LOG_GCRY (GNUNET_ERROR_TYPE_ERROR, "gcry_pk_testkey", rc);
    GNUNET_assert (0);
  }
#endif
  return result;
}


/**
 * Convert the given private key from the network format to the
 * S-expression that can be used by libgcrypt.
 *
 * @param priv private key to decode
 * @return NULL on error
 */
static gcry_sexp_t
decode_private_ecdhe_key (const struct GNUNET_CRYPTO_EcdhePrivateKey *priv)
{
  gcry_sexp_t result;
  int rc;

  rc = gcry_sexp_build (&result, NULL,
			"(private-key(ecc(curve \"" CURVE "\")"
                        "(d %b)))",
			(int)sizeof (priv->d), priv->d);
  if (0 != rc)
  {
    LOG_GCRY (GNUNET_ERROR_TYPE_ERROR, "gcry_sexp_build", rc);
    GNUNET_assert (0);
  }
#if EXTRA_CHECKS
  if (0 != (rc = gcry_pk_testkey (result)))
  {
    LOG_GCRY (GNUNET_ERROR_TYPE_ERROR, "gcry_pk_testkey", rc);
    GNUNET_assert (0);
  }
#endif
  return result;
}


/**
 * Extract the public key for the given private key.
 *
 * @param priv the private key
 * @param pub where to write the public key
 */
void
GNUNET_CRYPTO_ecdsa_key_get_public (const struct GNUNET_CRYPTO_EcdsaPrivateKey *priv,
                                    struct GNUNET_CRYPTO_EcdsaPublicKey *pub)
{
  gcry_sexp_t sexp;
  gcry_ctx_t ctx;
  gcry_mpi_t q;

  sexp = decode_private_ecdsa_key (priv);
  GNUNET_assert (NULL != sexp);
  GNUNET_assert (0 == gcry_mpi_ec_new (&ctx, sexp, NULL));
  gcry_sexp_release (sexp);
  q = gcry_mpi_ec_get_mpi ("q@eddsa", ctx, 0);
  GNUNET_assert (NULL != q);
  GNUNET_CRYPTO_mpi_print_unsigned (pub->q_y, sizeof (pub->q_y), q);
  gcry_mpi_release (q);
  gcry_ctx_release (ctx);
}


/**
 * Extract the public key for the given private key.
 *
 * @param priv the private key
 * @param pub where to write the public key
 */
void
GNUNET_CRYPTO_eddsa_key_get_public (const struct GNUNET_CRYPTO_EddsaPrivateKey *priv,
                                    struct GNUNET_CRYPTO_EddsaPublicKey *pub)
{
  gcry_sexp_t sexp;
  gcry_ctx_t ctx;
  gcry_mpi_t q;

  sexp = decode_private_eddsa_key (priv);
  GNUNET_assert (NULL != sexp);
  GNUNET_assert (0 == gcry_mpi_ec_new (&ctx, sexp, NULL));
  gcry_sexp_release (sexp);
  q = gcry_mpi_ec_get_mpi ("q@eddsa", ctx, 0);
  GNUNET_assert (q);
  GNUNET_CRYPTO_mpi_print_unsigned (pub->q_y, sizeof (pub->q_y), q);
  gcry_mpi_release (q);
  gcry_ctx_release (ctx);
}


/**
 * Extract the public key for the given private key.
 *
 * @param priv the private key
 * @param pub where to write the public key
 */
void
GNUNET_CRYPTO_ecdhe_key_get_public (const struct GNUNET_CRYPTO_EcdhePrivateKey *priv,
                                    struct GNUNET_CRYPTO_EcdhePublicKey *pub)
{
  gcry_sexp_t sexp;
  gcry_ctx_t ctx;
  gcry_mpi_t q;

  sexp = decode_private_ecdhe_key (priv);
  GNUNET_assert (NULL != sexp);
  GNUNET_assert (0 == gcry_mpi_ec_new (&ctx, sexp, NULL));
  gcry_sexp_release (sexp);
  q = gcry_mpi_ec_get_mpi ("q@eddsa", ctx, 0);
  GNUNET_assert (q);
  GNUNET_CRYPTO_mpi_print_unsigned (pub->q_y, sizeof (pub->q_y), q);
  gcry_mpi_release (q);
  gcry_ctx_release (ctx);
}


/**
 * Convert a public key to a string.
 *
 * @param pub key to convert
 * @return string representing @a pub
 */
char *
GNUNET_CRYPTO_ecdsa_public_key_to_string (const struct GNUNET_CRYPTO_EcdsaPublicKey *pub)
{
  char *pubkeybuf;
  size_t keylen = (sizeof (struct GNUNET_CRYPTO_EcdsaPublicKey)) * 8;
  char *end;

  if (keylen % 5 > 0)
    keylen += 5 - keylen % 5;
  keylen /= 5;
  pubkeybuf = GNUNET_malloc (keylen + 1);
  end = GNUNET_STRINGS_data_to_string ((unsigned char *) pub,
				       sizeof (struct GNUNET_CRYPTO_EcdsaPublicKey),
				       pubkeybuf,
				       keylen);
  if (NULL == end)
  {
    GNUNET_free (pubkeybuf);
    return NULL;
  }
  *end = '\0';
  return pubkeybuf;
}


/**
 * Convert a public key to a string.
 *
 * @param pub key to convert
 * @return string representing @a pub
 */
char *
GNUNET_CRYPTO_eddsa_public_key_to_string (const struct GNUNET_CRYPTO_EddsaPublicKey *pub)
{
  char *pubkeybuf;
  size_t keylen = (sizeof (struct GNUNET_CRYPTO_EddsaPublicKey)) * 8;
  char *end;

  if (keylen % 5 > 0)
    keylen += 5 - keylen % 5;
  keylen /= 5;
  pubkeybuf = GNUNET_malloc (keylen + 1);
  end = GNUNET_STRINGS_data_to_string ((unsigned char *) pub,
				       sizeof (struct GNUNET_CRYPTO_EddsaPublicKey),
				       pubkeybuf,
				       keylen);
  if (NULL == end)
  {
    GNUNET_free (pubkeybuf);
    return NULL;
  }
  *end = '\0';
  return pubkeybuf;
}


/**
 * Convert a string representing a public key to a public key.
 *
 * @param enc encoded public key
 * @param enclen number of bytes in @a enc (without 0-terminator)
 * @param pub where to store the public key
 * @return #GNUNET_OK on success
 */
int
GNUNET_CRYPTO_ecdsa_public_key_from_string (const char *enc,
                                            size_t enclen,
                                            struct GNUNET_CRYPTO_EcdsaPublicKey *pub)
{
  size_t keylen = (sizeof (struct GNUNET_CRYPTO_EcdsaPublicKey)) * 8;

  if (keylen % 5 > 0)
    keylen += 5 - keylen % 5;
  keylen /= 5;
  if (enclen != keylen)
    return GNUNET_SYSERR;

  if (GNUNET_OK != GNUNET_STRINGS_string_to_data (enc, enclen,
						  pub,
						  sizeof (struct GNUNET_CRYPTO_EcdsaPublicKey)))
    return GNUNET_SYSERR;
  return GNUNET_OK;
}


/**
 * Convert a string representing a public key to a public key.
 *
 * @param enc encoded public key
 * @param enclen number of bytes in @a enc (without 0-terminator)
 * @param pub where to store the public key
 * @return #GNUNET_OK on success
 */
int
GNUNET_CRYPTO_eddsa_public_key_from_string (const char *enc,
                                            size_t enclen,
                                            struct GNUNET_CRYPTO_EddsaPublicKey *pub)
{
  size_t keylen = (sizeof (struct GNUNET_CRYPTO_EddsaPublicKey)) * 8;

  if (keylen % 5 > 0)
    keylen += 5 - keylen % 5;
  keylen /= 5;
  if (enclen != keylen)
    return GNUNET_SYSERR;

  if (GNUNET_OK != GNUNET_STRINGS_string_to_data (enc, enclen,
						  pub,
						  sizeof (struct GNUNET_CRYPTO_EddsaPublicKey)))
    return GNUNET_SYSERR;
  return GNUNET_OK;
}


/**
 * Convert a string representing a private key to a private key.
 *
 * @param enc encoded public key
 * @param enclen number of bytes in @a enc (without 0-terminator)
 * @param priv where to store the private key
 * @return #GNUNET_OK on success
 */
int
GNUNET_CRYPTO_eddsa_private_key_from_string (const char *enc,
                                             size_t enclen,
                                             struct GNUNET_CRYPTO_EddsaPrivateKey *pub)
{
  size_t keylen = (sizeof (struct GNUNET_CRYPTO_EddsaPrivateKey)) * 8;

  if (keylen % 5 > 0)
    keylen += 5 - keylen % 5;
  keylen /= 5;
  if (enclen != keylen)
    return GNUNET_SYSERR;

  if (GNUNET_OK != GNUNET_STRINGS_string_to_data (enc, enclen,
						  pub,
						  sizeof (struct GNUNET_CRYPTO_EddsaPrivateKey)))
    return GNUNET_SYSERR;
  return GNUNET_OK;
}


/**
 * @ingroup crypto
 * Clear memory that was used to store a private key.
 *
 * @param pk location of the key
 */
void
GNUNET_CRYPTO_ecdhe_key_clear (struct GNUNET_CRYPTO_EcdhePrivateKey *pk)
{
  memset (pk, 0, sizeof (struct GNUNET_CRYPTO_EcdhePrivateKey));
}


/**
 * @ingroup crypto
 * Clear memory that was used to store a private key.
 *
 * @param pk location of the key
 */
void
GNUNET_CRYPTO_ecdsa_key_clear (struct GNUNET_CRYPTO_EcdsaPrivateKey *pk)
{
  memset (pk, 0, sizeof (struct GNUNET_CRYPTO_EcdsaPrivateKey));
}


/**
 * @ingroup crypto
 * Clear memory that was used to store a private key.
 *
 * @param pk location of the key
 */
void
GNUNET_CRYPTO_eddsa_key_clear (struct GNUNET_CRYPTO_EddsaPrivateKey *pk)
{
  memset (pk, 0, sizeof (struct GNUNET_CRYPTO_EddsaPrivateKey));
}


/**
 * Create a new private key. Caller must free return value.
 *
 * @return fresh private key
 */
struct GNUNET_CRYPTO_EcdhePrivateKey *
GNUNET_CRYPTO_ecdhe_key_create ()
{
  struct GNUNET_CRYPTO_EcdhePrivateKey *priv;
  gcry_sexp_t priv_sexp;
  gcry_sexp_t s_keyparam;
  gcry_mpi_t d;
  int rc;

  /* NOTE: For libgcrypt >= 1.7, we do not need the 'eddsa' flag here,
     but should also be harmless. For libgcrypt < 1.7, using 'eddsa'
     disables an expensive key testing routine. We do not want to run
     the expensive check for ECDHE, as we generate TONS of keys to
     use for a very short time. */
  if (0 != (rc = gcry_sexp_build (&s_keyparam, NULL,
                                  "(genkey(ecc(curve \"" CURVE "\")"
                                  "(flags eddsa no-keytest)))")))
  {
    LOG_GCRY (GNUNET_ERROR_TYPE_ERROR, "gcry_sexp_build", rc);
    return NULL;
  }
  if (0 != (rc = gcry_pk_genkey (&priv_sexp, s_keyparam)))
  {
    LOG_GCRY (GNUNET_ERROR_TYPE_ERROR, "gcry_pk_genkey", rc);
    gcry_sexp_release (s_keyparam);
    return NULL;
  }
  gcry_sexp_release (s_keyparam);
#if EXTRA_CHECKS
  if (0 != (rc = gcry_pk_testkey (priv_sexp)))
  {
    LOG_GCRY (GNUNET_ERROR_TYPE_ERROR, "gcry_pk_testkey", rc);
    gcry_sexp_release (priv_sexp);
    return NULL;
  }
#endif
  if (0 != (rc = key_from_sexp (&d, priv_sexp, "private-key", "d")))
  {
    LOG_GCRY (GNUNET_ERROR_TYPE_ERROR, "key_from_sexp", rc);
    gcry_sexp_release (priv_sexp);
    return NULL;
  }
  gcry_sexp_release (priv_sexp);
  priv = GNUNET_new (struct GNUNET_CRYPTO_EcdhePrivateKey);
  GNUNET_CRYPTO_mpi_print_unsigned (priv->d, sizeof (priv->d), d);
  gcry_mpi_release (d);
  return priv;
}


/**
 * Create a new private key. Caller must free return value.
 *
 * @return fresh private key
 */
struct GNUNET_CRYPTO_EcdsaPrivateKey *
GNUNET_CRYPTO_ecdsa_key_create ()
{
  struct GNUNET_CRYPTO_EcdsaPrivateKey *priv;
  gcry_sexp_t priv_sexp;
  gcry_sexp_t s_keyparam;
  gcry_mpi_t d;
  int rc;

  if (0 != (rc = gcry_sexp_build (&s_keyparam, NULL,
                                  "(genkey(ecc(curve \"" CURVE "\")"
                                  "(flags)))")))
  {
    LOG_GCRY (GNUNET_ERROR_TYPE_ERROR, "gcry_sexp_build", rc);
    return NULL;
  }
  if (0 != (rc = gcry_pk_genkey (&priv_sexp, s_keyparam)))
  {
    LOG_GCRY (GNUNET_ERROR_TYPE_ERROR, "gcry_pk_genkey", rc);
    gcry_sexp_release (s_keyparam);
    return NULL;
  }
  gcry_sexp_release (s_keyparam);
#if EXTRA_CHECKS
  if (0 != (rc = gcry_pk_testkey (priv_sexp)))
  {
    LOG_GCRY (GNUNET_ERROR_TYPE_ERROR, "gcry_pk_testkey", rc);
    gcry_sexp_release (priv_sexp);
    return NULL;
  }
#endif
  if (0 != (rc = key_from_sexp (&d, priv_sexp, "private-key", "d")))
  {
    LOG_GCRY (GNUNET_ERROR_TYPE_ERROR, "key_from_sexp", rc);
    gcry_sexp_release (priv_sexp);
    return NULL;
  }
  gcry_sexp_release (priv_sexp);
  priv = GNUNET_new (struct GNUNET_CRYPTO_EcdsaPrivateKey);
  GNUNET_CRYPTO_mpi_print_unsigned (priv->d, sizeof (priv->d), d);
  gcry_mpi_release (d);
  return priv;
}

/**
 * Create a new private key. Caller must free return value.
 *
 * @return fresh private key
 */
struct GNUNET_CRYPTO_EddsaPrivateKey *
GNUNET_CRYPTO_eddsa_key_create ()
{
  struct GNUNET_CRYPTO_EddsaPrivateKey *priv;
  gcry_sexp_t priv_sexp;
  gcry_sexp_t s_keyparam;
  gcry_mpi_t d;
  int rc;

  if (0 != (rc = gcry_sexp_build (&s_keyparam, NULL,
                                  "(genkey(ecc(curve \"" CURVE "\")"
                                  "(flags eddsa)))")))
  {
    LOG_GCRY (GNUNET_ERROR_TYPE_ERROR, "gcry_sexp_build", rc);
    return NULL;
  }
  if (0 != (rc = gcry_pk_genkey (&priv_sexp, s_keyparam)))
  {
    LOG_GCRY (GNUNET_ERROR_TYPE_ERROR, "gcry_pk_genkey", rc);
    gcry_sexp_release (s_keyparam);
    return NULL;
  }
  gcry_sexp_release (s_keyparam);
#if EXTRA_CHECKS
  if (0 != (rc = gcry_pk_testkey (priv_sexp)))
  {
    LOG_GCRY (GNUNET_ERROR_TYPE_ERROR, "gcry_pk_testkey", rc);
    gcry_sexp_release (priv_sexp);
    return NULL;
  }
#endif
  if (0 != (rc = key_from_sexp (&d, priv_sexp, "private-key", "d")))
  {
    LOG_GCRY (GNUNET_ERROR_TYPE_ERROR, "key_from_sexp", rc);
    gcry_sexp_release (priv_sexp);
    return NULL;
  }
  gcry_sexp_release (priv_sexp);
  priv = GNUNET_new (struct GNUNET_CRYPTO_EddsaPrivateKey);
  GNUNET_CRYPTO_mpi_print_unsigned (priv->d, sizeof (priv->d), d);
  gcry_mpi_release (d);
  return priv;
}


/**
 * Get the shared private key we use for anonymous users.
 *
 * @return "anonymous" private key
 */
const struct GNUNET_CRYPTO_EcdsaPrivateKey *
GNUNET_CRYPTO_ecdsa_key_get_anonymous ()
{
  /**
   * 'anonymous' pseudonym (global static, d=1, public key = G
   * (generator).
   */
  static struct GNUNET_CRYPTO_EcdsaPrivateKey anonymous;
  static int once;

  if (once)
    return &anonymous;
  GNUNET_CRYPTO_mpi_print_unsigned (anonymous.d,
	     sizeof (anonymous.d),
	     GCRYMPI_CONST_ONE);
  once = 1;
  return &anonymous;
}


/**
 * Compare two Peer Identities.
 *
 * @param first first peer identity
 * @param second second peer identity
 * @return bigger than 0 if first > second,
 *         0 if they are the same
 *         smaller than 0 if second > first
 */
int
GNUNET_CRYPTO_cmp_peer_identity (const struct GNUNET_PeerIdentity *first,
                                 const struct GNUNET_PeerIdentity *second)
{
  return memcmp (first, second, sizeof (struct GNUNET_PeerIdentity));
}


/**
 * Convert the data specified in the given purpose argument to an
 * S-expression suitable for signature operations.
 *
 * @param purpose data to convert
 * @return converted s-expression
 */
static gcry_sexp_t
data_to_eddsa_value (const struct GNUNET_CRYPTO_EccSignaturePurpose *purpose)
{
  struct GNUNET_HashCode hc;
  gcry_sexp_t data;
  int rc;

  GNUNET_CRYPTO_hash (purpose, ntohl (purpose->size), &hc);
  if (0 != (rc = gcry_sexp_build (&data, NULL,
				  "(data(flags eddsa)(hash-algo %s)(value %b))",
				  "sha512",
				  (int)sizeof (hc), &hc)))
  {
    LOG_GCRY (GNUNET_ERROR_TYPE_ERROR, "gcry_sexp_build", rc);
    return NULL;
  }
  return data;
}


/**
 * Convert the data specified in the given purpose argument to an
 * S-expression suitable for signature operations.
 *
 * @param purpose data to convert
 * @return converted s-expression
 */
static gcry_sexp_t
data_to_ecdsa_value (const struct GNUNET_CRYPTO_EccSignaturePurpose *purpose)
{
  struct GNUNET_HashCode hc;
  gcry_sexp_t data;
  int rc;

  GNUNET_CRYPTO_hash (purpose, ntohl (purpose->size), &hc);
  if (0 != (rc = gcry_sexp_build (&data, NULL,
				  "(data(flags rfc6979)(hash %s %b))",
				  "sha512",
				  (int)sizeof (hc), &hc)))
  {
    LOG_GCRY (GNUNET_ERROR_TYPE_ERROR, "gcry_sexp_build", rc);
    return NULL;
  }
  return data;
}


/**
 * Sign a given block.
 *
 * @param priv private key to use for the signing
 * @param purpose what to sign (size, purpose)
 * @param sig where to write the signature
 * @return #GNUNET_SYSERR on error, #GNUNET_OK on success
 */
int
GNUNET_CRYPTO_ecdsa_sign (const struct GNUNET_CRYPTO_EcdsaPrivateKey *priv,
                          const struct GNUNET_CRYPTO_EccSignaturePurpose *purpose,
                          struct GNUNET_CRYPTO_EcdsaSignature *sig)
{
  gcry_sexp_t priv_sexp;
  gcry_sexp_t sig_sexp;
  gcry_sexp_t data;
  int rc;
  gcry_mpi_t rs[2];

  priv_sexp = decode_private_ecdsa_key (priv);
  data = data_to_ecdsa_value (purpose);
  if (0 != (rc = gcry_pk_sign (&sig_sexp, data, priv_sexp)))
  {
    LOG (GNUNET_ERROR_TYPE_WARNING,
         _("ECC signing failed at %s:%d: %s\n"), __FILE__,
         __LINE__, gcry_strerror (rc));
    gcry_sexp_release (data);
    gcry_sexp_release (priv_sexp);
    return GNUNET_SYSERR;
  }
  gcry_sexp_release (priv_sexp);
  gcry_sexp_release (data);

  /* extract 'r' and 's' values from sexpression 'sig_sexp' and store in
     'signature' */
  if (0 != (rc = key_from_sexp (rs, sig_sexp, "sig-val", "rs")))
  {
    GNUNET_break (0);
    gcry_sexp_release (sig_sexp);
    return GNUNET_SYSERR;
  }
  gcry_sexp_release (sig_sexp);
  GNUNET_CRYPTO_mpi_print_unsigned (sig->r, sizeof (sig->r), rs[0]);
  GNUNET_CRYPTO_mpi_print_unsigned (sig->s, sizeof (sig->s), rs[1]);
  gcry_mpi_release (rs[0]);
  gcry_mpi_release (rs[1]);
  return GNUNET_OK;
}


/**
 * Sign a given block.
 *
 * @param priv private key to use for the signing
 * @param purpose what to sign (size, purpose)
 * @param sig where to write the signature
 * @return #GNUNET_SYSERR on error, #GNUNET_OK on success
 */
int
GNUNET_CRYPTO_eddsa_sign (const struct GNUNET_CRYPTO_EddsaPrivateKey *priv,
                          const struct GNUNET_CRYPTO_EccSignaturePurpose *purpose,
                          struct GNUNET_CRYPTO_EddsaSignature *sig)
{
  gcry_sexp_t priv_sexp;
  gcry_sexp_t sig_sexp;
  gcry_sexp_t data;
  int rc;
  gcry_mpi_t rs[2];

  priv_sexp = decode_private_eddsa_key (priv);
  data = data_to_eddsa_value (purpose);
  if (0 != (rc = gcry_pk_sign (&sig_sexp, data, priv_sexp)))
  {
    LOG (GNUNET_ERROR_TYPE_WARNING,
         _("EdDSA signing failed at %s:%d: %s\n"), __FILE__,
         __LINE__, gcry_strerror (rc));
    gcry_sexp_release (data);
    gcry_sexp_release (priv_sexp);
    return GNUNET_SYSERR;
  }
  gcry_sexp_release (priv_sexp);
  gcry_sexp_release (data);

  /* extract 'r' and 's' values from sexpression 'sig_sexp' and store in
     'signature' */
  if (0 != (rc = key_from_sexp (rs, sig_sexp, "sig-val", "rs")))
  {
    GNUNET_break (0);
    gcry_sexp_release (sig_sexp);
    return GNUNET_SYSERR;
  }
  gcry_sexp_release (sig_sexp);
  GNUNET_CRYPTO_mpi_print_unsigned (sig->r, sizeof (sig->r), rs[0]);
  GNUNET_CRYPTO_mpi_print_unsigned (sig->s, sizeof (sig->s), rs[1]);
  gcry_mpi_release (rs[0]);
  gcry_mpi_release (rs[1]);
  return GNUNET_OK;
}


/**
 * Verify signature.
 *
 * @param purpose what is the purpose that the signature should have?
 * @param validate block to validate (size, purpose, data)
 * @param sig signature that is being validated
 * @param pub public key of the signer
 * @returns #GNUNET_OK if ok, #GNUNET_SYSERR if invalid
 */
int
GNUNET_CRYPTO_ecdsa_verify (uint32_t purpose,
                            const struct GNUNET_CRYPTO_EccSignaturePurpose *validate,
                            const struct GNUNET_CRYPTO_EcdsaSignature *sig,
                            const struct GNUNET_CRYPTO_EcdsaPublicKey *pub)
{
  gcry_sexp_t data;
  gcry_sexp_t sig_sexpr;
  gcry_sexp_t pub_sexpr;
  int rc;

  if (purpose != ntohl (validate->purpose))
    return GNUNET_SYSERR;       /* purpose mismatch */

  /* build s-expression for signature */
  if (0 != (rc = gcry_sexp_build (&sig_sexpr, NULL,
				  "(sig-val(ecdsa(r %b)(s %b)))",
                                  (int) sizeof (sig->r), sig->r,
                                  (int) sizeof (sig->s), sig->s)))
  {
    LOG_GCRY (GNUNET_ERROR_TYPE_ERROR, "gcry_sexp_build", rc);
    return GNUNET_SYSERR;
  }
  data = data_to_ecdsa_value (validate);
  if (0 != (rc = gcry_sexp_build (&pub_sexpr, NULL,
                                  "(public-key(ecc(curve " CURVE ")(q %b)))",
                                  (int) sizeof (pub->q_y), pub->q_y)))
  {
    gcry_sexp_release (data);
    gcry_sexp_release (sig_sexpr);
    return GNUNET_SYSERR;
  }
  rc = gcry_pk_verify (sig_sexpr, data, pub_sexpr);
  gcry_sexp_release (pub_sexpr);
  gcry_sexp_release (data);
  gcry_sexp_release (sig_sexpr);
  if (0 != rc)
  {
    LOG (GNUNET_ERROR_TYPE_INFO,
         _("ECDSA signature verification failed at %s:%d: %s\n"), __FILE__,
         __LINE__, gcry_strerror (rc));
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}



/**
 * Verify signature.
 *
 * @param purpose what is the purpose that the signature should have?
 * @param validate block to validate (size, purpose, data)
 * @param sig signature that is being validated
 * @param pub public key of the signer
 * @returns #GNUNET_OK if ok, #GNUNET_SYSERR if invalid
 */
int
GNUNET_CRYPTO_eddsa_verify (uint32_t purpose,
                            const struct GNUNET_CRYPTO_EccSignaturePurpose *validate,
                            const struct GNUNET_CRYPTO_EddsaSignature *sig,
                            const struct GNUNET_CRYPTO_EddsaPublicKey *pub)
{
  gcry_sexp_t data;
  gcry_sexp_t sig_sexpr;
  gcry_sexp_t pub_sexpr;
  int rc;

  if (purpose != ntohl (validate->purpose))
    return GNUNET_SYSERR;       /* purpose mismatch */

  /* build s-expression for signature */
  if (0 != (rc = gcry_sexp_build (&sig_sexpr, NULL,
				  "(sig-val(eddsa(r %b)(s %b)))",
                                  (int)sizeof (sig->r), sig->r,
                                  (int)sizeof (sig->s), sig->s)))
  {
    LOG_GCRY (GNUNET_ERROR_TYPE_ERROR, "gcry_sexp_build", rc);
    return GNUNET_SYSERR;
  }
  data = data_to_eddsa_value (validate);
  if (0 != (rc = gcry_sexp_build (&pub_sexpr, NULL,
                                  "(public-key(ecc(curve " CURVE ")(flags eddsa)(q %b)))",
                                  (int)sizeof (pub->q_y), pub->q_y)))
  {
    gcry_sexp_release (data);
    gcry_sexp_release (sig_sexpr);
    return GNUNET_SYSERR;
  }
  rc = gcry_pk_verify (sig_sexpr, data, pub_sexpr);
  gcry_sexp_release (pub_sexpr);
  gcry_sexp_release (data);
  gcry_sexp_release (sig_sexpr);
  if (0 != rc)
  {
    LOG (GNUNET_ERROR_TYPE_INFO,
         _("EdDSA signature verification failed at %s:%d: %s\n"), __FILE__,
         __LINE__, gcry_strerror (rc));
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * Derive key material from a public and a private ECDHE key.
 *
 * @param priv private key to use for the ECDH (x)
 * @param pub public key to use for the ECDH (yG)
 * @param key_material where to write the key material (xyG)
 * @return #GNUNET_SYSERR on error, #GNUNET_OK on success
 */
int
GNUNET_CRYPTO_ecc_ecdh (const struct GNUNET_CRYPTO_EcdhePrivateKey *priv,
                        const struct GNUNET_CRYPTO_EcdhePublicKey *pub,
                        struct GNUNET_HashCode *key_material)
{
  gcry_mpi_point_t result;
  gcry_mpi_point_t q;
  gcry_mpi_t d;
  gcry_ctx_t ctx;
  gcry_sexp_t pub_sexpr;
  gcry_mpi_t result_x;
  unsigned char xbuf[256 / 8];
  size_t rsize;

  /* first, extract the q = dP value from the public key */
  if (0 != gcry_sexp_build (&pub_sexpr, NULL,
                            "(public-key(ecc(curve " CURVE ")(q %b)))",
                            (int)sizeof (pub->q_y), pub->q_y))
    return GNUNET_SYSERR;
  GNUNET_assert (0 == gcry_mpi_ec_new (&ctx, pub_sexpr, NULL));
  gcry_sexp_release (pub_sexpr);
  q = gcry_mpi_ec_get_point ("q", ctx, 0);

  /* second, extract the d value from our private key */
  GNUNET_CRYPTO_mpi_scan_unsigned (&d, priv->d, sizeof (priv->d));

  /* then call the 'multiply' function, to compute the product */
  result = gcry_mpi_point_new (0);
  gcry_mpi_ec_mul (result, d, q, ctx);
  gcry_mpi_point_release (q);
  gcry_mpi_release (d);

  /* finally, convert point to string for hashing */
  result_x = gcry_mpi_new (256);
  if (gcry_mpi_ec_get_affine (result_x, NULL, result, ctx))
  {
    LOG_GCRY (GNUNET_ERROR_TYPE_ERROR, "get_affine failed", 0);
    gcry_mpi_point_release (result);
    gcry_ctx_release (ctx);
    return GNUNET_SYSERR;
  }
  gcry_mpi_point_release (result);
  gcry_ctx_release (ctx);

  rsize = sizeof (xbuf);
  GNUNET_assert (! gcry_mpi_get_flag (result_x, GCRYMPI_FLAG_OPAQUE));
  /* result_x can be negative here, so we do not use 'GNUNET_CRYPTO_mpi_print_unsigned'
     as that does not include the sign bit; x should be a 255-bit
     value, so with the sign it should fit snugly into the 256-bit
     xbuf */
  GNUNET_assert (0 ==
                 gcry_mpi_print (GCRYMPI_FMT_STD, xbuf, rsize, &rsize,
                                 result_x));
  GNUNET_CRYPTO_hash (xbuf,
                      rsize,
                      key_material);
  gcry_mpi_release (result_x);
  return GNUNET_OK;
}


/**
 * Derive the 'h' value for key derivation, where
 * 'h = H(l,P)'.
 *
 * @param pub public key for deriviation
 * @param label label for deriviation
 * @param context additional context to use for HKDF of 'h';
 *        typically the name of the subsystem/application
 * @return h value
 */
static gcry_mpi_t
derive_h (const struct GNUNET_CRYPTO_EcdsaPublicKey *pub,
	  const char *label,
	  const char *context)
{
  gcry_mpi_t h;
  struct GNUNET_HashCode hc;

  GNUNET_CRYPTO_kdf (&hc, sizeof (hc),
		     "key-derivation", strlen ("key-derivation"),
		     pub, sizeof (*pub),
		     label, strlen (label),
		     context, strlen (context),
		     NULL, 0);
  GNUNET_CRYPTO_mpi_scan_unsigned (&h,
				   (unsigned char *) &hc,
				   sizeof (hc));
  return h;
}


/**
 * Derive a private key from a given private key and a label.
 * Essentially calculates a private key 'd = H(l,P) * x mod n'
 * where n is the size of the ECC group and P is the public
 * key associated with the private key 'd'.
 *
 * @param priv original private key
 * @param label label to use for key deriviation
 * @param context additional context to use for HKDF of 'h';
 *        typically the name of the subsystem/application
 * @return derived private key
 */
struct GNUNET_CRYPTO_EcdsaPrivateKey *
GNUNET_CRYPTO_ecdsa_private_key_derive (const struct GNUNET_CRYPTO_EcdsaPrivateKey *priv,
                                        const char *label,
                                        const char *context)
{
  struct GNUNET_CRYPTO_EcdsaPublicKey pub;
  struct GNUNET_CRYPTO_EcdsaPrivateKey *ret;
  gcry_mpi_t h;
  gcry_mpi_t x;
  gcry_mpi_t d;
  gcry_mpi_t n;
  gcry_ctx_t ctx;

  GNUNET_assert (0 == gcry_mpi_ec_new (&ctx, NULL, CURVE));

  n = gcry_mpi_ec_get_mpi ("n", ctx, 1);
  GNUNET_CRYPTO_ecdsa_key_get_public (priv, &pub);

  h = derive_h (&pub, label, context);
  GNUNET_CRYPTO_mpi_scan_unsigned (&x,
				   priv->d,
				   sizeof (priv->d));
  d = gcry_mpi_new (256);
  gcry_mpi_mulm (d, h, x, n);
  gcry_mpi_release (h);
  gcry_mpi_release (x);
  gcry_mpi_release (n);
  gcry_ctx_release (ctx);
  ret = GNUNET_new (struct GNUNET_CRYPTO_EcdsaPrivateKey);
  GNUNET_CRYPTO_mpi_print_unsigned (ret->d, sizeof (ret->d), d);
  gcry_mpi_release (d);
  return ret;
}


/**
 * Derive a public key from a given public key and a label.
 * Essentially calculates a public key 'V = H(l,P) * P'.
 *
 * @param pub original public key
 * @param label label to use for key derivation
 * @param context additional context to use for HKDF of 'h';
 *        typically the name of the subsystem/application
 * @param result where to write the derived public key
 */
void
GNUNET_CRYPTO_ecdsa_public_key_derive (const struct GNUNET_CRYPTO_EcdsaPublicKey *pub,
                                       const char *label,
                                       const char *context,
                                       struct GNUNET_CRYPTO_EcdsaPublicKey *result)
{
  gcry_ctx_t ctx;
  gcry_mpi_t q_y;
  gcry_mpi_t h;
  gcry_mpi_t n;
  gcry_mpi_t h_mod_n;
  gcry_mpi_point_t q;
  gcry_mpi_point_t v;

  GNUNET_assert (0 == gcry_mpi_ec_new (&ctx, NULL, CURVE));

  /* obtain point 'q' from original public key.  The provided 'q' is
     compressed thus we first store it in the context and then get it
     back as a (decompresssed) point.  */
  q_y = gcry_mpi_set_opaque_copy (NULL, pub->q_y, 8*sizeof (pub->q_y));
  GNUNET_assert (NULL != q_y);
  GNUNET_assert (0 == gcry_mpi_ec_set_mpi ("q", q_y, ctx));
  gcry_mpi_release (q_y);
  q = gcry_mpi_ec_get_point ("q", ctx, 0);
  GNUNET_assert (q);

  /* calculate h_mod_n = h % n */
  h = derive_h (pub, label, context);
  n = gcry_mpi_ec_get_mpi ("n", ctx, 1);
  h_mod_n = gcry_mpi_new (256);
  gcry_mpi_mod (h_mod_n, h, n);
  /* calculate v = h_mod_n * q */
  v = gcry_mpi_point_new (0);
  gcry_mpi_ec_mul (v, h_mod_n, q, ctx);
  gcry_mpi_release (h_mod_n);
  gcry_mpi_release (h);
  gcry_mpi_release (n);
  gcry_mpi_point_release (q);

  /* convert point 'v' to public key that we return */
  GNUNET_assert (0 == gcry_mpi_ec_set_point ("q", v, ctx));
  gcry_mpi_point_release (v);
  q_y = gcry_mpi_ec_get_mpi ("q@eddsa", ctx, 0);
  GNUNET_assert (q_y);
  GNUNET_CRYPTO_mpi_print_unsigned (result->q_y,
                                    sizeof (result->q_y),
                                    q_y);
  gcry_mpi_release (q_y);
  gcry_ctx_release (ctx);
}


/**
 * Reverse the sequence of the bytes in @a buffer
 *
 * @param[in|out] buffer buffer to invert
 * @param length number of bytes in @a buffer
 */
static void
reverse_buffer (unsigned char *buffer,
		size_t length)
{
  unsigned char tmp;
  size_t i;

  for (i=0; i < length/2; i++)
  {
    tmp = buffer[i];
    buffer[i] = buffer[length-1-i];
    buffer[length-1-i] = tmp;
  }
}


/**
 * Convert the secret @a d of an EdDSA key to the
 * value that is actually used in the EdDSA computation.
 *
 * @param d secret input
 * @return value used for the calculation in EdDSA
 */
static gcry_mpi_t
eddsa_d_to_a (gcry_mpi_t d)
{
  unsigned char rawmpi[32]; /* 256-bit value */
  size_t rawmpilen;
  unsigned char digest[64]; /* 512-bit hash value */
  gcry_buffer_t hvec[2];
  int b;
  gcry_mpi_t a;

  b = 256 / 8; /* number of bytes in `d` */

  /* Note that we clear DIGEST so we can use it as input to left pad
     the key with zeroes for hashing.  */
  memset (hvec, 0, sizeof hvec);
  rawmpilen = sizeof (rawmpi);
  GNUNET_assert (0 ==
                 gcry_mpi_print (GCRYMPI_FMT_USG,
				 rawmpi, rawmpilen, &rawmpilen,
                                 d));
  hvec[0].data = digest;
  hvec[0].off = 0;
  hvec[0].len = b > rawmpilen? b - rawmpilen : 0;
  hvec[1].data = rawmpi;
  hvec[1].off = 0;
  hvec[1].len = rawmpilen;
  GNUNET_assert (0 ==
		 gcry_md_hash_buffers (GCRY_MD_SHA512,
				       0 /* flags */,
				       digest,
				       hvec, 2));
  /* Compute the A value.  */
  reverse_buffer (digest, 32);  /* Only the first half of the hash.  */
  digest[0]   = (digest[0] & 0x7f) | 0x40;
  digest[31] &= 0xf8;

  GNUNET_CRYPTO_mpi_scan_unsigned (&a,
				   digest,
				   32);
  return a;
}


/**
 * @ingroup crypto
 * Derive key material from a ECDH public key and a private EdDSA key.
 * Dual to #GNUNET_CRRYPTO_ecdh_eddsa.
 *
 * @param priv private key from EdDSA to use for the ECDH (x)
 * @param pub public key to use for the ECDH (yG)
 * @param key_material where to write the key material H(h(x)yG)
 * @return #GNUNET_SYSERR on error, #GNUNET_OK on success
 */
int
GNUNET_CRYPTO_eddsa_ecdh (const struct GNUNET_CRYPTO_EddsaPrivateKey *priv,
                          const struct GNUNET_CRYPTO_EcdhePublicKey *pub,
                          struct GNUNET_HashCode *key_material)
{
  gcry_mpi_point_t result;
  gcry_mpi_point_t q;
  gcry_mpi_t d;
  gcry_mpi_t a;
  gcry_ctx_t ctx;
  gcry_sexp_t pub_sexpr;
  gcry_mpi_t result_x;
  unsigned char xbuf[256 / 8];
  size_t rsize;

  /* first, extract the q = dP value from the public key */
  if (0 != gcry_sexp_build (&pub_sexpr, NULL,
                            "(public-key(ecc(curve " CURVE ")(q %b)))",
                            (int)sizeof (pub->q_y), pub->q_y))
    return GNUNET_SYSERR;
  GNUNET_assert (0 == gcry_mpi_ec_new (&ctx, pub_sexpr, NULL));
  gcry_sexp_release (pub_sexpr);
  q = gcry_mpi_ec_get_point ("q", ctx, 0);

  /* second, extract the d value from our private key */
  GNUNET_CRYPTO_mpi_scan_unsigned (&d, priv->d, sizeof (priv->d));

  /* NOW, because this is EdDSA, HASH 'd' first! */
  a = eddsa_d_to_a (d);
  gcry_mpi_release (d);

  /* then call the 'multiply' function, to compute the product */
  result = gcry_mpi_point_new (0);
  gcry_mpi_ec_mul (result, a, q, ctx);
  gcry_mpi_point_release (q);
  gcry_mpi_release (a);

  /* finally, convert point to string for hashing */
  result_x = gcry_mpi_new (256);
  if (gcry_mpi_ec_get_affine (result_x, NULL, result, ctx))
  {
    LOG_GCRY (GNUNET_ERROR_TYPE_ERROR, "get_affine failed", 0);
    gcry_mpi_point_release (result);
    gcry_ctx_release (ctx);
    return GNUNET_SYSERR;
  }
  gcry_mpi_point_release (result);
  gcry_ctx_release (ctx);

  rsize = sizeof (xbuf);
  GNUNET_assert (! gcry_mpi_get_flag (result_x, GCRYMPI_FLAG_OPAQUE));
  /* result_x can be negative here, so we do not use 'GNUNET_CRYPTO_mpi_print_unsigned'
     as that does not include the sign bit; x should be a 255-bit
     value, so with the sign it should fit snugly into the 256-bit
     xbuf */
  GNUNET_assert (0 ==
                 gcry_mpi_print (GCRYMPI_FMT_STD, xbuf, rsize, &rsize,
                                 result_x));
  GNUNET_CRYPTO_hash (xbuf,
                      rsize,
                      key_material);
  gcry_mpi_release (result_x);
  return GNUNET_OK;
}


/**
 * @ingroup crypto
 * Derive key material from a EdDSA public key and a private ECDH key.
 * Dual to #GNUNET_CRRYPTO_eddsa_ecdh.
 *
 * @param priv private key to use for the ECDH (y)
 * @param pub public key from EdDSA to use for the ECDH (X=h(x)G)
 * @param key_material where to write the key material H(yX)=H(h(x)yG)
 * @return #GNUNET_SYSERR on error, #GNUNET_OK on success
 */
int
GNUNET_CRYPTO_ecdh_eddsa (const struct GNUNET_CRYPTO_EcdhePrivateKey *priv,
                          const struct GNUNET_CRYPTO_EddsaPublicKey *pub,
                          struct GNUNET_HashCode *key_material)
{
  gcry_mpi_point_t result;
  gcry_mpi_point_t q;
  gcry_mpi_t d;
  gcry_ctx_t ctx;
  gcry_sexp_t pub_sexpr;
  gcry_mpi_t result_x;
  unsigned char xbuf[256 / 8];
  size_t rsize;

  /* first, extract the q = dP value from the public key */
  if (0 != gcry_sexp_build (&pub_sexpr, NULL,
                            "(public-key(ecc(curve " CURVE ")(q %b)))",
                            (int)sizeof (pub->q_y), pub->q_y))
    return GNUNET_SYSERR;
  GNUNET_assert (0 == gcry_mpi_ec_new (&ctx, pub_sexpr, NULL));
  gcry_sexp_release (pub_sexpr);
  q = gcry_mpi_ec_get_point ("q", ctx, 0);

  /* second, extract the d value from our private key */
  GNUNET_CRYPTO_mpi_scan_unsigned (&d, priv->d, sizeof (priv->d));

  /* then call the 'multiply' function, to compute the product */
  result = gcry_mpi_point_new (0);
  gcry_mpi_ec_mul (result, d, q, ctx);
  gcry_mpi_point_release (q);
  gcry_mpi_release (d);

  /* finally, convert point to string for hashing */
  result_x = gcry_mpi_new (256);
  if (gcry_mpi_ec_get_affine (result_x, NULL, result, ctx))
  {
    LOG_GCRY (GNUNET_ERROR_TYPE_ERROR, "get_affine failed", 0);
    gcry_mpi_point_release (result);
    gcry_ctx_release (ctx);
    return GNUNET_SYSERR;
  }
  gcry_mpi_point_release (result);
  gcry_ctx_release (ctx);

  rsize = sizeof (xbuf);
  GNUNET_assert (! gcry_mpi_get_flag (result_x, GCRYMPI_FLAG_OPAQUE));
  /* result_x can be negative here, so we do not use 'GNUNET_CRYPTO_mpi_print_unsigned'
     as that does not include the sign bit; x should be a 255-bit
     value, so with the sign it should fit snugly into the 256-bit
     xbuf */
  GNUNET_assert (0 ==
                 gcry_mpi_print (GCRYMPI_FMT_STD, xbuf, rsize, &rsize,
                                 result_x));
  GNUNET_CRYPTO_hash (xbuf,
                      rsize,
                      key_material);
  gcry_mpi_release (result_x);
  return GNUNET_OK;
}



/* end of crypto_ecc.c */

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
*/

/**
 * @file util/crypto_rsa.c
 * @brief public key cryptography (RSA) with libgcrypt
 * @author Christian Grothoff
 *
 * Note that the code locks often needlessly on the gcrypt-locking api.
 * One would think that simple MPI operations should not require locking
 * (since only global operations on the random pool must be locked,
 * strictly speaking).  But libgcrypt does sometimes require locking in
 * unexpected places, so the safe solution is to always lock even if it
 * is not required.  The performance impact is minimal anyway.
 */

#include "platform.h"
#include <gcrypt.h>
#include "gnunet_common.h"
#include "gnunet_util_lib.h"

#define LOG(kind,...) GNUNET_log_from (kind, "util", __VA_ARGS__)

#define LOG_STRERROR(kind,syscall) GNUNET_log_from_strerror (kind, "util", syscall)

#define LOG_STRERROR_FILE(kind,syscall,filename) GNUNET_log_from_strerror_file (kind, "util", syscall, filename)


/**
 * The private information of an RSA key pair.
 * NOTE: this must match the definition in crypto_ksk.c and gnunet-rsa.c!
 */
struct GNUNET_CRYPTO_RsaPrivateKey
{
  gcry_sexp_t sexp;
};


#define HOSTKEY_LEN 2048

#define EXTRA_CHECKS ALLOW_EXTRA_CHECKS


/**
 * Log an error message at log-level 'level' that indicates
 * a failure of the command 'cmd' with the message given
 * by gcry_strerror(rc).
 */
#define LOG_GCRY(level, cmd, rc) do { LOG(level, _("`%s' failed at %s:%d with error: %s\n"), cmd, __FILE__, __LINE__, gcry_strerror(rc)); } while(0);

/**
 * If target != size, move target bytes to the
 * end of the size-sized buffer and zero out the
 * first target-size bytes.
 */
static void
adjust (unsigned char *buf, size_t size, size_t target)
{
  if (size < target)
  {
    memmove (&buf[target - size], buf, size);
    memset (buf, 0, target - size);
  }
}


/**
 * Free memory occupied by hostkey
 * @param hostkey pointer to the memory to free
 */
void
GNUNET_CRYPTO_rsa_key_free (struct GNUNET_CRYPTO_RsaPrivateKey *hostkey)
{
  gcry_sexp_release (hostkey->sexp);
  GNUNET_free (hostkey);
}


/**
 * FIXME: document!
 */
static int
key_from_sexp (gcry_mpi_t * array, gcry_sexp_t sexp, const char *topname,
               const char *elems)
{
  gcry_sexp_t list, l2;
  const char *s;
  int i, idx;

  list = gcry_sexp_find_token (sexp, topname, 0);
  if (!list)
  {
    return 1;
  }
  l2 = gcry_sexp_cadr (list);
  gcry_sexp_release (list);
  list = l2;
  if (!list)
  {
    return 2;
  }

  idx = 0;
  for (s = elems; *s; s++, idx++)
  {
    l2 = gcry_sexp_find_token (list, s, 1);
    if (!l2)
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
    if (!array[idx])
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
 * Extract the public key of the host.
 * @param priv the private key
 * @param pub where to write the public key
 */
void
GNUNET_CRYPTO_rsa_key_get_public (const struct GNUNET_CRYPTO_RsaPrivateKey
                                  *priv,
                                  struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded
                                  *pub)
{
  gcry_mpi_t skey[2];
  size_t size;
  int rc;

  rc = key_from_sexp (skey, priv->sexp, "public-key", "ne");
  if (rc)
    rc = key_from_sexp (skey, priv->sexp, "private-key", "ne");
  if (rc)
    rc = key_from_sexp (skey, priv->sexp, "rsa", "ne");
  GNUNET_assert (0 == rc);
  pub->len =
      htons (sizeof (struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded) -
             sizeof (pub->padding));
  pub->sizen = htons (GNUNET_CRYPTO_RSA_DATA_ENCODING_LENGTH);
  pub->padding = 0;
  size = GNUNET_CRYPTO_RSA_DATA_ENCODING_LENGTH;
  GNUNET_assert (0 ==
                 gcry_mpi_print (GCRYMPI_FMT_USG, &pub->key[0], size, &size,
                                 skey[0]));
  adjust (&pub->key[0], size, GNUNET_CRYPTO_RSA_DATA_ENCODING_LENGTH);
  size = GNUNET_CRYPTO_RSA_KEY_LENGTH - GNUNET_CRYPTO_RSA_DATA_ENCODING_LENGTH;
  GNUNET_assert (0 ==
                 gcry_mpi_print (GCRYMPI_FMT_USG,
                                 &pub->key
                                 [GNUNET_CRYPTO_RSA_DATA_ENCODING_LENGTH], size,
                                 &size, skey[1]));
  adjust (&pub->key[GNUNET_CRYPTO_RSA_DATA_ENCODING_LENGTH], size,
          GNUNET_CRYPTO_RSA_KEY_LENGTH -
          GNUNET_CRYPTO_RSA_DATA_ENCODING_LENGTH);
  gcry_mpi_release (skey[0]);
  gcry_mpi_release (skey[1]);
}


/**
 * Convert a public key to a string.
 *
 * @param pub key to convert
 * @return string representing  'pub'
 */
char *
GNUNET_CRYPTO_rsa_public_key_to_string (struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded *pub)
{
  char *pubkeybuf;
  size_t keylen = (sizeof (struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded)) * 8;
  char *end;

  if (keylen % 5 > 0)
    keylen += 5 - keylen % 5;
  keylen /= 5;
  pubkeybuf = GNUNET_malloc (keylen + 1);
  end = GNUNET_STRINGS_data_to_string ((unsigned char *) pub, 
				       sizeof (struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded), 
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
 * @param enclen number of bytes in enc (without 0-terminator)
 * @param pub where to store the public key
 * @return GNUNET_OK on success
 */
int
GNUNET_CRYPTO_rsa_public_key_from_string (const char *enc, 
					  size_t enclen,
					  struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded *pub)
{
  size_t keylen = (sizeof (struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded)) * 8;

  if (keylen % 5 > 0)
    keylen += 5 - keylen % 5;
  keylen /= 5;
  if (enclen != keylen)
    return GNUNET_SYSERR;

  if (GNUNET_OK != GNUNET_STRINGS_string_to_data (enc, enclen,
						 (unsigned char*) pub,
						 sizeof (struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded)))
    return GNUNET_SYSERR;
  if ( (ntohs (pub->len) != sizeof (struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded)) ||
       (ntohs (pub->padding) != 0) ||
       (ntohs (pub->sizen) != GNUNET_CRYPTO_RSA_DATA_ENCODING_LENGTH) )
    return GNUNET_SYSERR;
  return GNUNET_OK;
}


/**
 * Internal: publicKey => RSA-Key.
 *
 * Note that the return type is not actually a private
 * key but rather an sexpression for the public key!
 */
static struct GNUNET_CRYPTO_RsaPrivateKey *
public2PrivateKey (const struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded
                   *publicKey)
{
  struct GNUNET_CRYPTO_RsaPrivateKey *ret;
  gcry_sexp_t result;
  gcry_mpi_t n;
  gcry_mpi_t e;
  size_t size;
  size_t erroff;
  int rc;

  if ((ntohs (publicKey->sizen) != GNUNET_CRYPTO_RSA_DATA_ENCODING_LENGTH) ||
      (ntohs (publicKey->len) !=
       sizeof (struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded) -
       sizeof (publicKey->padding)))
  {
    GNUNET_break (0);
    return NULL;
  }
  size = GNUNET_CRYPTO_RSA_DATA_ENCODING_LENGTH;
  rc = gcry_mpi_scan (&n, GCRYMPI_FMT_USG, &publicKey->key[0], size, &size);
  if (rc)
  {
    LOG_GCRY (GNUNET_ERROR_TYPE_ERROR, "gcry_mpi_scan", rc);
    return NULL;
  }
  size = GNUNET_CRYPTO_RSA_KEY_LENGTH - GNUNET_CRYPTO_RSA_DATA_ENCODING_LENGTH;
  rc = gcry_mpi_scan (&e, GCRYMPI_FMT_USG,
                      &publicKey->key[GNUNET_CRYPTO_RSA_DATA_ENCODING_LENGTH],
                      size, &size);
  if (rc)
  {
    LOG_GCRY (GNUNET_ERROR_TYPE_ERROR, "gcry_mpi_scan", rc);
    gcry_mpi_release (n);
    return NULL;
  }
  rc = gcry_sexp_build (&result, &erroff, "(public-key(rsa(n %m)(e %m)))", n,
                        e);
  gcry_mpi_release (n);
  gcry_mpi_release (e);
  if (rc)
  {
    LOG_GCRY (GNUNET_ERROR_TYPE_ERROR, "gcry_sexp_build", rc);  /* erroff gives more info */
    return NULL;
  }
  ret = GNUNET_malloc (sizeof (struct GNUNET_CRYPTO_RsaPrivateKey));
  ret->sexp = result;
  return ret;
}


/**
 * Encode the private key in a format suitable for
 * storing it into a file.
 * @returns encoding of the private key.
 *    The first 4 bytes give the size of the array, as usual.
 */
struct GNUNET_CRYPTO_RsaPrivateKeyBinaryEncoded *
GNUNET_CRYPTO_rsa_encode_key (const struct GNUNET_CRYPTO_RsaPrivateKey *hostkey)
{
  struct GNUNET_CRYPTO_RsaPrivateKeyBinaryEncoded *retval;
  gcry_mpi_t pkv[6];
  void *pbu[6];
  size_t sizes[6];
  int rc;
  int i;
  int size;

#if EXTRA_CHECKS
  if (gcry_pk_testkey (hostkey->sexp))
  {
    GNUNET_break (0);
    return NULL;
  }
#endif

  memset (pkv, 0, sizeof (gcry_mpi_t) * 6);
  rc = key_from_sexp (pkv, hostkey->sexp, "private-key", "nedpqu");
  if (rc)
    rc = key_from_sexp (pkv, hostkey->sexp, "rsa", "nedpqu");
  if (rc)
    rc = key_from_sexp (pkv, hostkey->sexp, "private-key", "nedpq");
  if (rc)
    rc = key_from_sexp (pkv, hostkey->sexp, "rsa", "nedpq");
  if (rc)
    rc = key_from_sexp (pkv, hostkey->sexp, "private-key", "ned");
  if (rc)
    rc = key_from_sexp (pkv, hostkey->sexp, "rsa", "ned");
  GNUNET_assert (0 == rc);
  size = sizeof (struct GNUNET_CRYPTO_RsaPrivateKeyBinaryEncoded);
  for (i = 0; i < 6; i++)
  {
    if (pkv[i] != NULL)
    {
      GNUNET_assert (0 ==
                     gcry_mpi_aprint (GCRYMPI_FMT_USG,
                                      (unsigned char **) &pbu[i], &sizes[i],
                                      pkv[i]));
      size += sizes[i];
    }
    else
    {
      pbu[i] = NULL;
      sizes[i] = 0;
    }
  }
  GNUNET_assert (size < 65536);
  retval = GNUNET_malloc (size);
  retval->len = htons (size);
  i = 0;
  retval->sizen = htons (sizes[0]);
  memcpy (&((char *) (&retval[1]))[i], pbu[0], sizes[0]);
  i += sizes[0];
  retval->sizee = htons (sizes[1]);
  memcpy (&((char *) (&retval[1]))[i], pbu[1], sizes[1]);
  i += sizes[1];
  retval->sized = htons (sizes[2]);
  memcpy (&((char *) (&retval[1]))[i], pbu[2], sizes[2]);
  i += sizes[2];
  /* swap p and q! */
  retval->sizep = htons (sizes[4]);
  memcpy (&((char *) (&retval[1]))[i], pbu[4], sizes[4]);
  i += sizes[4];
  retval->sizeq = htons (sizes[3]);
  memcpy (&((char *) (&retval[1]))[i], pbu[3], sizes[3]);
  i += sizes[3];
  retval->sizedmp1 = htons (0);
  retval->sizedmq1 = htons (0);
  memcpy (&((char *) (&retval[1]))[i], pbu[5], sizes[5]);
  for (i = 0; i < 6; i++)
  {
    if (pkv[i] != NULL)
      gcry_mpi_release (pkv[i]);
    if (pbu[i] != NULL)
      free (pbu[i]);
  }
  return retval;
}


/**
 * Decode the private key from the file-format back
 * to the "normal", internal format.
 *
 * @param buf the buffer where the private key data is stored
 * @param len the length of the data in 'buffer'
 */
struct GNUNET_CRYPTO_RsaPrivateKey *
GNUNET_CRYPTO_rsa_decode_key (const char *buf, uint16_t len)
{
  struct GNUNET_CRYPTO_RsaPrivateKey *ret;
  const struct GNUNET_CRYPTO_RsaPrivateKeyBinaryEncoded *encoding =
      (const struct GNUNET_CRYPTO_RsaPrivateKeyBinaryEncoded *) buf;
  gcry_sexp_t res;
  gcry_mpi_t n, e, d, p, q, u;
  int rc;
  size_t size;
  int pos;
  uint16_t enc_len;

  enc_len = ntohs (encoding->len);
  if (len != enc_len)
    return NULL;

  pos = 0;
  size = ntohs (encoding->sizen);
  rc = gcry_mpi_scan (&n, GCRYMPI_FMT_USG,
                      &((const unsigned char *) (&encoding[1]))[pos], size,
                      &size);
  pos += ntohs (encoding->sizen);
  if (rc)
  {
    LOG_GCRY (GNUNET_ERROR_TYPE_ERROR, "gcry_mpi_scan", rc);
    return NULL;
  }
  size = ntohs (encoding->sizee);
  rc = gcry_mpi_scan (&e, GCRYMPI_FMT_USG,
                      &((const unsigned char *) (&encoding[1]))[pos], size,
                      &size);
  pos += ntohs (encoding->sizee);
  if (rc)
  {
    LOG_GCRY (GNUNET_ERROR_TYPE_ERROR, "gcry_mpi_scan", rc);
    gcry_mpi_release (n);
    return NULL;
  }
  size = ntohs (encoding->sized);
  rc = gcry_mpi_scan (&d, GCRYMPI_FMT_USG,
                      &((const unsigned char *) (&encoding[1]))[pos], size,
                      &size);
  pos += ntohs (encoding->sized);
  if (rc)
  {
    LOG_GCRY (GNUNET_ERROR_TYPE_ERROR, "gcry_mpi_scan", rc);
    gcry_mpi_release (n);
    gcry_mpi_release (e);
    return NULL;
  }
  /* swap p and q! */
  size = ntohs (encoding->sizep);
  if (size > 0)
  {
    rc = gcry_mpi_scan (&q, GCRYMPI_FMT_USG,
                        &((const unsigned char *) (&encoding[1]))[pos], size,
                        &size);
    pos += ntohs (encoding->sizep);
    if (rc)
    {
      LOG_GCRY (GNUNET_ERROR_TYPE_ERROR, "gcry_mpi_scan", rc);
      gcry_mpi_release (n);
      gcry_mpi_release (e);
      gcry_mpi_release (d);
      return NULL;
    }
  }
  else
    q = NULL;
  size = ntohs (encoding->sizeq);
  if (size > 0)
  {
    rc = gcry_mpi_scan (&p, GCRYMPI_FMT_USG,
                        &((const unsigned char *) (&encoding[1]))[pos], size,
                        &size);
    pos += ntohs (encoding->sizeq);
    if (rc)
    {
      LOG_GCRY (GNUNET_ERROR_TYPE_ERROR, "gcry_mpi_scan", rc);
      gcry_mpi_release (n);
      gcry_mpi_release (e);
      gcry_mpi_release (d);
      if (q != NULL)
        gcry_mpi_release (q);
      return NULL;
    }
  }
  else
    p = NULL;
  pos += ntohs (encoding->sizedmp1);
  pos += ntohs (encoding->sizedmq1);
  size =
      ntohs (encoding->len) - sizeof (struct GNUNET_CRYPTO_RsaPrivateKeyBinaryEncoded) - pos;
  if (size > 0)
  {
    rc = gcry_mpi_scan (&u, GCRYMPI_FMT_USG,
                        &((const unsigned char *) (&encoding[1]))[pos], size,
                        &size);
    if (rc)
    {
      LOG_GCRY (GNUNET_ERROR_TYPE_ERROR, "gcry_mpi_scan", rc);
      gcry_mpi_release (n);
      gcry_mpi_release (e);
      gcry_mpi_release (d);
      if (p != NULL)
        gcry_mpi_release (p);
      if (q != NULL)
        gcry_mpi_release (q);
      return NULL;
    }
  }
  else
    u = NULL;

  if ((p != NULL) && (q != NULL) && (u != NULL))
  {
    rc = gcry_sexp_build (&res, &size,  /* erroff */
                          "(private-key(rsa(n %m)(e %m)(d %m)(p %m)(q %m)(u %m)))",
                          n, e, d, p, q, u);
  }
  else
  {
    if ((p != NULL) && (q != NULL))
    {
      rc = gcry_sexp_build (&res, &size,        /* erroff */
                            "(private-key(rsa(n %m)(e %m)(d %m)(p %m)(q %m)))",
                            n, e, d, p, q);
    }
    else
    {
      rc = gcry_sexp_build (&res, &size,        /* erroff */
                            "(private-key(rsa(n %m)(e %m)(d %m)))", n, e, d);
    }
  }
  gcry_mpi_release (n);
  gcry_mpi_release (e);
  gcry_mpi_release (d);
  if (p != NULL)
    gcry_mpi_release (p);
  if (q != NULL)
    gcry_mpi_release (q);
  if (u != NULL)
    gcry_mpi_release (u);

  if (rc)
    LOG_GCRY (GNUNET_ERROR_TYPE_ERROR, "gcry_sexp_build", rc);
#if EXTRA_CHECKS
  if (gcry_pk_testkey (res))
  {
    LOG_GCRY (GNUNET_ERROR_TYPE_ERROR, "gcry_pk_testkey", rc);
    return NULL;
  }
#endif
  ret = GNUNET_malloc (sizeof (struct GNUNET_CRYPTO_RsaPrivateKey));
  ret->sexp = res;
  return ret;
}


/**
 * Create a new private key. Caller must free return value.
 *
 * @return fresh private key
 */
static struct GNUNET_CRYPTO_RsaPrivateKey *
rsa_key_create ()
{
  struct GNUNET_CRYPTO_RsaPrivateKey *ret;
  gcry_sexp_t s_key;
  gcry_sexp_t s_keyparam;

  GNUNET_assert (0 ==
                 gcry_sexp_build (&s_keyparam, NULL,
                                  "(genkey(rsa(nbits %d)(rsa-use-e 3:257)))",
                                  HOSTKEY_LEN));
  GNUNET_assert (0 == gcry_pk_genkey (&s_key, s_keyparam));
  gcry_sexp_release (s_keyparam);
#if EXTRA_CHECKS
  GNUNET_assert (0 == gcry_pk_testkey (s_key));
#endif
  ret = GNUNET_malloc (sizeof (struct GNUNET_CRYPTO_RsaPrivateKey));
  ret->sexp = s_key;
  return ret;
}


/**
 * Try to read the private key from the given file.
 *
 * @param filename file to read the key from
 * @return NULL on error
 */
static struct GNUNET_CRYPTO_RsaPrivateKey *
try_read_key (const char *filename)
{
  struct GNUNET_CRYPTO_RsaPrivateKey *ret;
  struct GNUNET_CRYPTO_RsaPrivateKeyBinaryEncoded *enc;
  struct GNUNET_DISK_FileHandle *fd;
  OFF_T fs;
  uint16_t len;

  if (GNUNET_YES != GNUNET_DISK_file_test (filename))
    return NULL;

  /* hostkey file exists already, read it! */
  if (NULL == (fd = GNUNET_DISK_file_open (filename, GNUNET_DISK_OPEN_READ,
					   GNUNET_DISK_PERM_NONE)))
  {
    LOG_STRERROR_FILE (GNUNET_ERROR_TYPE_ERROR, "open", filename);
    return NULL;
  }
  if (GNUNET_OK != (GNUNET_DISK_file_handle_size (fd, &fs)))
  {
    LOG_STRERROR_FILE (GNUNET_ERROR_TYPE_ERROR, "stat", filename);
    (void) GNUNET_DISK_file_close (fd);
    return NULL;
  }
  if (fs > UINT16_MAX)
  {
    LOG (GNUNET_ERROR_TYPE_ERROR,
         _("File `%s' does not contain a valid private key.  Deleting it.\n"),
         filename);
    GNUNET_break (GNUNET_OK == GNUNET_DISK_file_close (fd));
    if (0 != UNLINK (filename))    
      LOG_STRERROR_FILE (GNUNET_ERROR_TYPE_WARNING, "unlink", filename);
    return NULL;
  }

  enc = GNUNET_malloc (fs);
  GNUNET_break (fs == GNUNET_DISK_file_read (fd, enc, fs));
  len = ntohs (enc->len);
  ret = NULL;
  if ((len != fs) ||
      (NULL == (ret = GNUNET_CRYPTO_rsa_decode_key ((char *) enc, len))))
  {
    LOG (GNUNET_ERROR_TYPE_ERROR,
         _("File `%s' does not contain a valid private key.  Deleting it.\n"),
         filename);
    GNUNET_break (GNUNET_OK == GNUNET_DISK_file_close (fd));
    if (0 != UNLINK (filename))    
      LOG_STRERROR_FILE (GNUNET_ERROR_TYPE_WARNING, "unlink", filename);
    GNUNET_free (enc);
    return NULL;
  }
  GNUNET_free (enc);

  GNUNET_break (GNUNET_OK == GNUNET_DISK_file_close (fd));
  return ret;  
}


/**
 * Create a new private key by reading it from a file.  If the
 * files does not exist, create a new key and write it to the
 * file.  Caller must free return value.  Note that this function
 * can not guarantee that another process might not be trying
 * the same operation on the same file at the same time.
 * If the contents of the file
 * are invalid the old file is deleted and a fresh key is
 * created.
 *
 * @return new private key, NULL on error (for example,
 *   permission denied)
 */
struct GNUNET_CRYPTO_RsaPrivateKey *
GNUNET_CRYPTO_rsa_key_create_from_file (const char *filename)
{
  struct GNUNET_CRYPTO_RsaPrivateKey *ret;
  struct GNUNET_CRYPTO_RsaPrivateKeyBinaryEncoded *enc;
  uint16_t len;
  struct GNUNET_DISK_FileHandle *fd;
  unsigned int cnt;
  int ec;
  uint64_t fs;
  struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded pub;
  struct GNUNET_PeerIdentity pid;

  if (GNUNET_SYSERR == GNUNET_DISK_directory_create_for_file (filename))
    return NULL;
  while (GNUNET_YES != GNUNET_DISK_file_test (filename))
  {
    fd = GNUNET_DISK_file_open (filename,
                                GNUNET_DISK_OPEN_WRITE | GNUNET_DISK_OPEN_CREATE
                                | GNUNET_DISK_OPEN_FAILIFEXISTS,
                                GNUNET_DISK_PERM_USER_READ |
                                GNUNET_DISK_PERM_USER_WRITE);
    if (NULL == fd)
    {
      if (errno == EEXIST)
      {
        if (GNUNET_YES != GNUNET_DISK_file_test (filename))
        {
          /* must exist but not be accessible, fail for good! */
          if (0 != ACCESS (filename, R_OK))
            LOG_STRERROR_FILE (GNUNET_ERROR_TYPE_ERROR, "access", filename);
          else
            GNUNET_break (0);   /* what is going on!? */
          return NULL;
        }
        continue;
      }
      LOG_STRERROR_FILE (GNUNET_ERROR_TYPE_ERROR, "open", filename);
      return NULL;
    }
    cnt = 0;

    while (GNUNET_YES !=
           GNUNET_DISK_file_lock (fd, 0,
                                  sizeof (struct GNUNET_CRYPTO_RsaPrivateKeyBinaryEncoded),
                                  GNUNET_YES))
    {
      sleep (1);
      if (0 == ++cnt % 10)
      {
        ec = errno;
        LOG (GNUNET_ERROR_TYPE_ERROR,
             _("Could not acquire lock on file `%s': %s...\n"), filename,
             STRERROR (ec));
      }
    }
    LOG (GNUNET_ERROR_TYPE_INFO,
         _("Creating a new private key.  This may take a while.\n"));
    ret = rsa_key_create ();
    GNUNET_assert (ret != NULL);
    enc = GNUNET_CRYPTO_rsa_encode_key (ret);
    GNUNET_assert (enc != NULL);
    GNUNET_assert (ntohs (enc->len) ==
                   GNUNET_DISK_file_write (fd, enc, ntohs (enc->len)));
    GNUNET_free (enc);

    GNUNET_DISK_file_sync (fd);
    if (GNUNET_YES !=
        GNUNET_DISK_file_unlock (fd, 0,
                                 sizeof (struct GNUNET_CRYPTO_RsaPrivateKeyBinaryEncoded)))
      LOG_STRERROR_FILE (GNUNET_ERROR_TYPE_WARNING, "fcntl", filename);
    GNUNET_assert (GNUNET_YES == GNUNET_DISK_file_close (fd));
    GNUNET_CRYPTO_rsa_key_get_public (ret, &pub);
    GNUNET_CRYPTO_hash (&pub, sizeof (pub), &pid.hashPubKey);
    LOG (GNUNET_ERROR_TYPE_INFO,
         _("I am host `%s'.  Stored new private key in `%s'.\n"),
         GNUNET_i2s (&pid), filename);
    return ret;
  }
  /* hostkey file exists already, read it! */
  fd = GNUNET_DISK_file_open (filename, GNUNET_DISK_OPEN_READ,
                              GNUNET_DISK_PERM_NONE);
  if (NULL == fd)
  {
    LOG_STRERROR_FILE (GNUNET_ERROR_TYPE_ERROR, "open", filename);
    return NULL;
  }
  cnt = 0;
  while (1)
  {
    if (GNUNET_YES !=
        GNUNET_DISK_file_lock (fd, 0,
                               sizeof (struct GNUNET_CRYPTO_RsaPrivateKeyBinaryEncoded),
                               GNUNET_NO))
    {
      if (0 == ++cnt % 60)
      {
        ec = errno;
        LOG (GNUNET_ERROR_TYPE_ERROR,
             _("Could not acquire lock on file `%s': %s...\n"), filename,
             STRERROR (ec));
        LOG (GNUNET_ERROR_TYPE_ERROR,
             _
             ("This may be ok if someone is currently generating a hostkey.\n"));
      }
      sleep (1);
      continue;
    }
    if (GNUNET_YES != GNUNET_DISK_file_test (filename))
    {
      /* eh, what!? File we opened is now gone!? */
      LOG_STRERROR_FILE (GNUNET_ERROR_TYPE_WARNING, "stat", filename);
      if (GNUNET_YES !=
          GNUNET_DISK_file_unlock (fd, 0,
                                   sizeof (struct GNUNET_CRYPTO_RsaPrivateKeyBinaryEncoded)))
        LOG_STRERROR_FILE (GNUNET_ERROR_TYPE_WARNING, "fcntl", filename);
      GNUNET_assert (GNUNET_OK == GNUNET_DISK_file_close (fd));

      return NULL;
    }
    if (GNUNET_OK != GNUNET_DISK_file_size (filename, &fs, GNUNET_YES, GNUNET_YES))
      fs = 0;
    if (fs < sizeof (struct GNUNET_CRYPTO_RsaPrivateKeyBinaryEncoded))
    {
      /* maybe we got the read lock before the hostkey generating
       * process had a chance to get the write lock; give it up! */
      if (GNUNET_YES !=
          GNUNET_DISK_file_unlock (fd, 0,
                                   sizeof (struct GNUNET_CRYPTO_RsaPrivateKeyBinaryEncoded)))
        LOG_STRERROR_FILE (GNUNET_ERROR_TYPE_WARNING, "fcntl", filename);
      if (0 == ++cnt % 10)
      {
        LOG (GNUNET_ERROR_TYPE_ERROR,
             _
             ("When trying to read hostkey file `%s' I found %u bytes but I need at least %u.\n"),
             filename, (unsigned int) fs,
             (unsigned int) sizeof (struct GNUNET_CRYPTO_RsaPrivateKeyBinaryEncoded));
        LOG (GNUNET_ERROR_TYPE_ERROR,
             _
             ("This may be ok if someone is currently generating a hostkey.\n"));
      }
      sleep (2);                /* wait a bit longer! */
      continue;
    }
    break;
  }
  enc = GNUNET_malloc (fs);
  GNUNET_assert (fs == GNUNET_DISK_file_read (fd, enc, fs));
  len = ntohs (enc->len);
  ret = NULL;
  if ((len != fs) ||
      (NULL == (ret = GNUNET_CRYPTO_rsa_decode_key ((char *) enc, len))))
  {
    LOG (GNUNET_ERROR_TYPE_ERROR,
         _("File `%s' does not contain a valid private key.  Deleting it.\n"),
         filename);
    if (0 != UNLINK (filename))
    {
      LOG_STRERROR_FILE (GNUNET_ERROR_TYPE_WARNING, "unlink", filename);
    }
  }
  GNUNET_free (enc);
  if (GNUNET_YES !=
      GNUNET_DISK_file_unlock (fd, 0,
                               sizeof (struct GNUNET_CRYPTO_RsaPrivateKeyBinaryEncoded)))
    LOG_STRERROR_FILE (GNUNET_ERROR_TYPE_WARNING, "fcntl", filename);
  GNUNET_assert (GNUNET_YES == GNUNET_DISK_file_close (fd));
  if (ret != NULL)
  {
    GNUNET_CRYPTO_rsa_key_get_public (ret, &pub);
    GNUNET_CRYPTO_hash (&pub, sizeof (pub), &pid.hashPubKey);
    LOG (GNUNET_ERROR_TYPE_INFO,
         _("I am host `%s'.  Read private key from `%s'.\n"), GNUNET_i2s (&pid),
         filename);
  }
  return ret;
}


/**
 * Handle to cancel private key generation and state for the
 * key generation operation.
 */
struct GNUNET_CRYPTO_RsaKeyGenerationContext
{
  
  /**
   * Continuation to call upon completion.
   */
  GNUNET_CRYPTO_RsaKeyCallback cont;

  /**
   * Closure for 'cont'.
   */
  void *cont_cls;

  /**
   * Name of the file.
   */
  char *filename;

  /**
   * Handle to the helper process which does the key generation.
   */ 
  struct GNUNET_OS_Process *gnunet_rsa;
  
  /**
   * Handle to 'stdout' of gnunet-rsa.  We 'read' on stdout to detect
   * process termination (instead of messing with SIGCHLD).
   */
  struct GNUNET_DISK_PipeHandle *gnunet_rsa_out;

  /**
   * Location where we store the private key if it already existed.
   * (if this is used, 'filename', 'gnunet_rsa' and 'gnunet_rsa_out' will
   * not be used).
   */
  struct GNUNET_CRYPTO_RsaPrivateKey *pk;
  
  /**
   * Task reading from 'gnunet_rsa_out' to wait for process termination.
   */
  GNUNET_SCHEDULER_TaskIdentifier read_task;
  
};


/**
 * Task called upon shutdown or process termination of 'gnunet-rsa' during
 * RSA key generation.  Check where we are and perform the appropriate
 * action.
 *
 * @param cls the 'struct GNUNET_CRYPTO_RsaKeyGenerationContext'
 * @param tc scheduler context
 */
static void
check_key_generation_completion (void *cls,
				 const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_CRYPTO_RsaKeyGenerationContext *gc = cls;
  enum GNUNET_OS_ProcessStatusType type;
  unsigned long code;
  struct GNUNET_CRYPTO_RsaPrivateKey *pk;

  gc->read_task = GNUNET_SCHEDULER_NO_TASK;
  if (0 != (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN))
  {
    gc->cont (gc->cont_cls, NULL, _("interrupted by shutdown"));
    GNUNET_CRYPTO_rsa_key_create_stop (gc);
    return;
  }
  if (GNUNET_OK != 
      GNUNET_OS_process_status (gc->gnunet_rsa,
				&type, &code))
  {
    GNUNET_break (0);
    gc->cont (gc->cont_cls, NULL, _("internal error"));
    GNUNET_CRYPTO_rsa_key_create_stop (gc);
    return;
  }
  GNUNET_OS_process_destroy (gc->gnunet_rsa);
  gc->gnunet_rsa = NULL;
  if ( (GNUNET_OS_PROCESS_EXITED != type) ||
       (0 != code) )
  {
    gc->cont (gc->cont_cls, NULL, _("gnunet-rsa failed"));
    GNUNET_CRYPTO_rsa_key_create_stop (gc);
    return;
  }
  if (NULL == (pk = try_read_key (gc->filename)))
  {
    GNUNET_break (0);
    gc->cont (gc->cont_cls, NULL, _("gnunet-rsa failed"));
    GNUNET_CRYPTO_rsa_key_create_stop (gc);
    return;
  }
  gc->cont (gc->cont_cls, pk, NULL);
  GNUNET_free (gc->filename);
  GNUNET_free (gc);
}


/**
 * Return the private RSA key which already existed on disk
 * (asynchronously) to the caller.
 *
 * @param cls the 'struct GNUNET_CRYPTO_RsaKeyGenerationContext'
 * @param tc scheduler context (unused)
 */
static void
async_return_key (void *cls,
		  const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_CRYPTO_RsaKeyGenerationContext *gc = cls;

  gc->cont (gc->cont_cls,
	    gc->pk,
	    NULL);
  GNUNET_free (gc);
}


/**
 * Create a new private key by reading it from a file.  If the files
 * does not exist, create a new key and write it to the file.  If the
 * contents of the file are invalid the old file is deleted and a
 * fresh key is created.
 *
 * @param filename name of file to use for storage
 * @param cont function to call when done (or on errors)
 * @param cont_cls closure for 'cont'
 * @return handle to abort operation, NULL on fatal errors (cont will not be called if NULL is returned)
 */
struct GNUNET_CRYPTO_RsaKeyGenerationContext *
GNUNET_CRYPTO_rsa_key_create_start (const char *filename,
				    GNUNET_CRYPTO_RsaKeyCallback cont,
				    void *cont_cls)
{
  struct GNUNET_CRYPTO_RsaKeyGenerationContext *gc;
  struct GNUNET_CRYPTO_RsaPrivateKey *pk;

  if (NULL != (pk = try_read_key (filename)))
  {
    /* quick happy ending: key already exists! */
    gc = GNUNET_malloc (sizeof (struct GNUNET_CRYPTO_RsaKeyGenerationContext));
    gc->pk = pk;
    gc->cont = cont;
    gc->cont_cls = cont_cls;
    gc->read_task = GNUNET_SCHEDULER_add_now (&async_return_key,
					      gc);
    return gc;
  }
  gc = GNUNET_malloc (sizeof (struct GNUNET_CRYPTO_RsaKeyGenerationContext));
  gc->filename = GNUNET_strdup (filename);
  gc->cont = cont;
  gc->cont_cls = cont_cls;
  gc->gnunet_rsa_out = GNUNET_DISK_pipe (GNUNET_NO,
					 GNUNET_NO,
					 GNUNET_NO,
					 GNUNET_YES);
  if (NULL == gc->gnunet_rsa_out)
  {
    GNUNET_log_strerror (GNUNET_ERROR_TYPE_WARNING, "pipe");
    GNUNET_free (gc->filename);
    GNUNET_free (gc);
    return NULL;
  }
  gc->gnunet_rsa = GNUNET_OS_start_process (GNUNET_YES,
					    GNUNET_OS_INHERIT_STD_ERR,
					    NULL, 
					    gc->gnunet_rsa_out,
					    "gnunet-rsa",
					    "gnunet-rsa",
					    gc->filename,
					    NULL);
  if (NULL == gc->gnunet_rsa)
  {
    GNUNET_log_strerror (GNUNET_ERROR_TYPE_WARNING, "fork");
    GNUNET_DISK_pipe_close (gc->gnunet_rsa_out);
    GNUNET_free (gc->filename);
    GNUNET_free (gc);
    return NULL;
  }
  GNUNET_assert (GNUNET_OK ==
		 GNUNET_DISK_pipe_close_end (gc->gnunet_rsa_out,
					     GNUNET_DISK_PIPE_END_WRITE));
  gc->read_task = GNUNET_SCHEDULER_add_read_file (GNUNET_TIME_UNIT_FOREVER_REL,
						  GNUNET_DISK_pipe_handle (gc->gnunet_rsa_out,
									   GNUNET_DISK_PIPE_END_READ),
						  &check_key_generation_completion,
						  gc);
  return gc;
}


/**
 * Abort RSA key generation.
 *
 * @param gc key generation context to abort
 */
void
GNUNET_CRYPTO_rsa_key_create_stop (struct GNUNET_CRYPTO_RsaKeyGenerationContext *gc)
{
  GNUNET_SCHEDULER_cancel (gc->read_task);
  if (NULL != gc->gnunet_rsa)
  {
    (void) GNUNET_OS_process_kill (gc->gnunet_rsa, SIGKILL);
    GNUNET_break (GNUNET_OK ==
		  GNUNET_OS_process_wait (gc->gnunet_rsa));
    GNUNET_OS_process_destroy (gc->gnunet_rsa);
  }
  if (NULL != gc->filename)
  {
    if (0 != UNLINK (gc->filename))
      GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_WARNING, "unlink", gc->filename);
    GNUNET_free (gc->filename);
  }
  if (NULL != gc->pk)
    GNUNET_CRYPTO_rsa_key_free (gc->pk);
  GNUNET_free (gc);
}


/**
 * Setup a hostkey file for a peer given the name of the
 * configuration file (!).  This function is used so that
 * at a later point code can be certain that reading a
 * hostkey is fast (for example in time-dependent testcases).
 *
 * @param cfg_name name of the configuration file to use
 */
void
GNUNET_CRYPTO_setup_hostkey (const char *cfg_name)
{
  struct GNUNET_CONFIGURATION_Handle *cfg;
  struct GNUNET_CRYPTO_RsaPrivateKey *pk;
  char *fn;

  cfg = GNUNET_CONFIGURATION_create ();
  (void) GNUNET_CONFIGURATION_load (cfg, cfg_name);
  if (GNUNET_OK == 
      GNUNET_CONFIGURATION_get_value_filename (cfg, "GNUNETD", "HOSTKEY", &fn))
  {
    pk = GNUNET_CRYPTO_rsa_key_create_from_file (fn);
    if (NULL != pk)
      GNUNET_CRYPTO_rsa_key_free (pk);
    GNUNET_free (fn);
  }
  GNUNET_CONFIGURATION_destroy (cfg);
}


/**
 * Encrypt a block with the public key of another host that uses the
 * same cipher.
 *
 * @param block the block to encrypt
 * @param size the size of block
 * @param publicKey the encoded public key used to encrypt
 * @param target where to store the encrypted block
 * @returns GNUNET_SYSERR on error, GNUNET_OK if ok
 */
int
GNUNET_CRYPTO_rsa_encrypt (const void *block, size_t size,
                           const struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded
                           *publicKey,
                           struct GNUNET_CRYPTO_RsaEncryptedData *target)
{
  gcry_sexp_t result;
  gcry_sexp_t data;
  struct GNUNET_CRYPTO_RsaPrivateKey *pubkey;
  gcry_mpi_t val;
  gcry_mpi_t rval;
  size_t isize;
  size_t erroff;

  GNUNET_assert (size <= sizeof (struct GNUNET_HashCode));
  pubkey = public2PrivateKey (publicKey);
  if (pubkey == NULL)
    return GNUNET_SYSERR;
  isize = size;
  GNUNET_assert (0 ==
                 gcry_mpi_scan (&val, GCRYMPI_FMT_USG, block, isize, &isize));
  GNUNET_assert (0 ==
                 gcry_sexp_build (&data, &erroff,
                                  "(data (flags pkcs1)(value %m))", val));
  gcry_mpi_release (val);
  GNUNET_assert (0 == gcry_pk_encrypt (&result, data, pubkey->sexp));
  gcry_sexp_release (data);
  GNUNET_CRYPTO_rsa_key_free (pubkey);

  GNUNET_assert (0 == key_from_sexp (&rval, result, "rsa", "a"));
  gcry_sexp_release (result);
  isize = sizeof (struct GNUNET_CRYPTO_RsaEncryptedData);
  GNUNET_assert (0 ==
                 gcry_mpi_print (GCRYMPI_FMT_USG, (unsigned char *) target,
                                 isize, &isize, rval));
  gcry_mpi_release (rval);
  adjust (&target->encoding[0], isize,
          sizeof (struct GNUNET_CRYPTO_RsaEncryptedData));
  return GNUNET_OK;
}


/**
 * Decrypt a given block with the hostkey.
 *
 * @param key the key with which to decrypt this block
 * @param block the data to decrypt, encoded as returned by encrypt
 * @param result pointer to a location where the result can be stored
 * @param max the maximum number of bits to store for the result, if
 *        the decrypted block is bigger, an error is returned
 * @return the size of the decrypted block, -1 on error
 */
ssize_t
GNUNET_CRYPTO_rsa_decrypt (const struct GNUNET_CRYPTO_RsaPrivateKey * key,
                           const struct GNUNET_CRYPTO_RsaEncryptedData * block,
                           void *result, size_t max)
{
  gcry_sexp_t resultsexp;
  gcry_sexp_t data;
  size_t erroff;
  size_t size;
  gcry_mpi_t val;
  unsigned char *endp;
  unsigned char *tmp;

#if EXTRA_CHECKS
  GNUNET_assert (0 == gcry_pk_testkey (key->sexp));
#endif
  size = sizeof (struct GNUNET_CRYPTO_RsaEncryptedData);
  GNUNET_assert (0 ==
                 gcry_mpi_scan (&val, GCRYMPI_FMT_USG, &block->encoding[0],
                                size, &size));
  GNUNET_assert (0 ==
                 gcry_sexp_build (&data, &erroff, "(enc-val(flags)(rsa(a %m)))",
                                  val));
  gcry_mpi_release (val);
  GNUNET_assert (0 == gcry_pk_decrypt (&resultsexp, data, key->sexp));
  gcry_sexp_release (data);
  /* resultsexp has format "(value %m)" */
  GNUNET_assert (NULL !=
                 (val = gcry_sexp_nth_mpi (resultsexp, 1, GCRYMPI_FMT_USG)));
  gcry_sexp_release (resultsexp);
  tmp = GNUNET_malloc (max + HOSTKEY_LEN / 8);
  size = max + HOSTKEY_LEN / 8;
  GNUNET_assert (0 == gcry_mpi_print (GCRYMPI_FMT_USG, tmp, size, &size, val));
  gcry_mpi_release (val);
  endp = tmp;
  endp += (size - max);
  size = max;
  memcpy (result, endp, size);
  GNUNET_free (tmp);
  return size;
}


/**
 * Sign a given block.
 *
 * @param key private key to use for the signing
 * @param purpose what to sign (size, purpose)
 * @param sig where to write the signature
 * @return GNUNET_SYSERR on error, GNUNET_OK on success
 */
int
GNUNET_CRYPTO_rsa_sign (const struct GNUNET_CRYPTO_RsaPrivateKey *key,
                        const struct GNUNET_CRYPTO_RsaSignaturePurpose *purpose,
                        struct GNUNET_CRYPTO_RsaSignature *sig)
{
  gcry_sexp_t result;
  gcry_sexp_t data;
  size_t ssize;
  gcry_mpi_t rval;
  struct GNUNET_HashCode hc;
  char *buff;
  int bufSize;

  GNUNET_CRYPTO_hash (purpose, ntohl (purpose->size), &hc);
#define FORMATSTRING "(4:data(5:flags5:pkcs1)(4:hash6:sha51264:0123456789012345678901234567890123456789012345678901234567890123))"
  bufSize = strlen (FORMATSTRING) + 1;
  buff = GNUNET_malloc (bufSize);
  memcpy (buff, FORMATSTRING, bufSize);
  memcpy (&buff
          [bufSize -
           strlen
           ("0123456789012345678901234567890123456789012345678901234567890123))")
           - 1], &hc, sizeof (struct GNUNET_HashCode));
  GNUNET_assert (0 == gcry_sexp_new (&data, buff, bufSize, 0));
  GNUNET_free (buff);
  GNUNET_assert (0 == gcry_pk_sign (&result, data, key->sexp));
  gcry_sexp_release (data);
  GNUNET_assert (0 == key_from_sexp (&rval, result, "rsa", "s"));
  gcry_sexp_release (result);
  ssize = sizeof (struct GNUNET_CRYPTO_RsaSignature);
  GNUNET_assert (0 ==
                 gcry_mpi_print (GCRYMPI_FMT_USG, (unsigned char *) sig, ssize,
                                 &ssize, rval));
  gcry_mpi_release (rval);
  adjust (sig->sig, ssize, sizeof (struct GNUNET_CRYPTO_RsaSignature));
  return GNUNET_OK;
}


/**
 * Verify signature.
 *
 * @param purpose what is the purpose that the signature should have?
 * @param validate block to validate (size, purpose, data)
 * @param sig signature that is being validated
 * @param publicKey public key of the signer
 * @returns GNUNET_OK if ok, GNUNET_SYSERR if invalid
 */
int
GNUNET_CRYPTO_rsa_verify (uint32_t purpose,
                          const struct GNUNET_CRYPTO_RsaSignaturePurpose
                          *validate,
                          const struct GNUNET_CRYPTO_RsaSignature *sig,
                          const struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded
                          *publicKey)
{
  gcry_sexp_t data;
  gcry_sexp_t sigdata;
  size_t size;
  gcry_mpi_t val;
  struct GNUNET_CRYPTO_RsaPrivateKey *hostkey;
  struct GNUNET_HashCode hc;
  char *buff;
  int bufSize;
  size_t erroff;
  int rc;

  if (purpose != ntohl (validate->purpose))
    return GNUNET_SYSERR;       /* purpose mismatch */
  GNUNET_CRYPTO_hash (validate, ntohl (validate->size), &hc);
  size = sizeof (struct GNUNET_CRYPTO_RsaSignature);
  GNUNET_assert (0 ==
                 gcry_mpi_scan (&val, GCRYMPI_FMT_USG,
                                (const unsigned char *) sig, size, &size));
  GNUNET_assert (0 ==
                 gcry_sexp_build (&sigdata, &erroff, "(sig-val(rsa(s %m)))",
                                  val));
  gcry_mpi_release (val);
  bufSize = strlen (FORMATSTRING) + 1;
  buff = GNUNET_malloc (bufSize);
  memcpy (buff, FORMATSTRING, bufSize);
  memcpy (&buff
          [strlen (FORMATSTRING) -
           strlen
           ("0123456789012345678901234567890123456789012345678901234567890123))")],
          &hc, sizeof (struct GNUNET_HashCode));
  GNUNET_assert (0 == gcry_sexp_new (&data, buff, bufSize, 0));
  GNUNET_free (buff);
  hostkey = public2PrivateKey (publicKey);
  if (hostkey == NULL)
  {
    gcry_sexp_release (data);
    gcry_sexp_release (sigdata);
    return GNUNET_SYSERR;
  }
  rc = gcry_pk_verify (sigdata, data, hostkey->sexp);
  GNUNET_CRYPTO_rsa_key_free (hostkey);
  gcry_sexp_release (data);
  gcry_sexp_release (sigdata);
  if (rc)
  {
    LOG (GNUNET_ERROR_TYPE_WARNING,
         _("RSA signature verification failed at %s:%d: %s\n"), __FILE__,
         __LINE__, gcry_strerror (rc));
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/* end of crypto_rsa.c */

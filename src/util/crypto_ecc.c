/*
     This file is part of GNUnet.
     (C) 2012, 2013 Christian Grothoff (and other contributing authors)

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
 * @file util/crypto_ecc.c
 * @brief public key cryptography (ECC) with libgcrypt
 * @author Christian Grothoff
 */
#include "platform.h"
#include <gcrypt.h>
#include "gnunet_common.h"
#include "gnunet_util_lib.h"

#define EXTRA_CHECKS ALLOW_EXTRA_CHECKS 

#define CURVE "NIST P-256"

#define LOG(kind,...) GNUNET_log_from (kind, "util", __VA_ARGS__)

#define LOG_STRERROR(kind,syscall) GNUNET_log_from_strerror (kind, "util", syscall)

#define LOG_STRERROR_FILE(kind,syscall,filename) GNUNET_log_from_strerror_file (kind, "util", syscall, filename)

/**
 * Log an error message at log-level 'level' that indicates
 * a failure of the command 'cmd' with the message given
 * by gcry_strerror(rc).
 */
#define LOG_GCRY(level, cmd, rc) do { LOG(level, _("`%s' failed at %s:%d with error: %s\n"), cmd, __FILE__, __LINE__, gcry_strerror(rc)); } while(0);


/**
 * The private information of an ECC private key.
 */
struct GNUNET_CRYPTO_EccPrivateKey
{
  
  /**
   * Libgcrypt S-expression for the ECC key.
   */
  gcry_sexp_t sexp;
};


/**
 * Free memory occupied by ECC key
 *
 * @param privatekey pointer to the memory to free
 */
void
GNUNET_CRYPTO_ecc_key_free (struct GNUNET_CRYPTO_EccPrivateKey *privatekey)
{
  gcry_sexp_release (privatekey->sexp);
  GNUNET_free (privatekey);
}


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
key_from_sexp (gcry_mpi_t * array, gcry_sexp_t sexp, const char *topname,
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
 * Extract the public key for the given private key.
 *
 * @param priv the private key
 * @param pub where to write the public key
 */
void
GNUNET_CRYPTO_ecc_key_get_public (const struct GNUNET_CRYPTO_EccPrivateKey *priv,
                                  struct GNUNET_CRYPTO_EccPublicKeyBinaryEncoded *pub)
{
  gcry_mpi_t skey;
  size_t size;
  int rc;

  memset (pub, 0, sizeof (struct GNUNET_CRYPTO_EccPublicKeyBinaryEncoded));
  rc = key_from_sexp (&skey, priv->sexp, "public-key", "q");
  if (rc)
    rc = key_from_sexp (&skey, priv->sexp, "private-key", "q");
  if (rc)
    rc = key_from_sexp (&skey, priv->sexp, "ecc", "q");
  GNUNET_assert (0 == rc);
  pub->size = htons (sizeof (struct GNUNET_CRYPTO_EccPublicKeyBinaryEncoded));
  size = GNUNET_CRYPTO_ECC_MAX_PUBLIC_KEY_LENGTH;
  GNUNET_assert (0 ==
                 gcry_mpi_print (GCRYMPI_FMT_USG, pub->key, size, &size,
                                 skey));
  pub->len = htons (size);
  gcry_mpi_release (skey);
}


/**
 * Convert a public key to a string.
 *
 * @param pub key to convert
 * @return string representing  'pub'
 */
char *
GNUNET_CRYPTO_ecc_public_key_to_string (const struct GNUNET_CRYPTO_EccPublicKeyBinaryEncoded *pub)
{
  char *pubkeybuf;
  size_t keylen = (sizeof (struct GNUNET_CRYPTO_EccPublicKeyBinaryEncoded)) * 8;
  char *end;

  if (keylen % 5 > 0)
    keylen += 5 - keylen % 5;
  keylen /= 5;
  pubkeybuf = GNUNET_malloc (keylen + 1);
  end = GNUNET_STRINGS_data_to_string ((unsigned char *) pub, 
				       sizeof (struct GNUNET_CRYPTO_EccPublicKeyBinaryEncoded), 
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
GNUNET_CRYPTO_ecc_public_key_from_string (const char *enc, 
					  size_t enclen,
					  struct GNUNET_CRYPTO_EccPublicKeyBinaryEncoded *pub)
{
  size_t keylen = (sizeof (struct GNUNET_CRYPTO_EccPublicKeyBinaryEncoded)) * 8;

  if (keylen % 5 > 0)
    keylen += 5 - keylen % 5;
  keylen /= 5;
  if (enclen != keylen)
    return GNUNET_SYSERR;

  if (GNUNET_OK != GNUNET_STRINGS_string_to_data (enc, enclen,
						  pub,
						  sizeof (struct GNUNET_CRYPTO_EccPublicKeyBinaryEncoded)))
    return GNUNET_SYSERR;
  if ( (ntohs (pub->size) != sizeof (struct GNUNET_CRYPTO_EccPublicKeyBinaryEncoded)) ||
       (ntohs (pub->len) > GNUNET_CRYPTO_ECC_SIGNATURE_DATA_ENCODING_LENGTH) )
    return GNUNET_SYSERR;
  return GNUNET_OK;
}


/**
 * Convert the given public key from the network format to the
 * S-expression that can be used by libgcrypt.
 *
 * @param publicKey public key to decode
 * @return NULL on error
 */
static gcry_sexp_t
decode_public_key (const struct GNUNET_CRYPTO_EccPublicKeyBinaryEncoded *publicKey)
{
  gcry_sexp_t result;
  gcry_mpi_t q;
  size_t size;
  size_t erroff;
  int rc;

  if (ntohs (publicKey->len) > GNUNET_CRYPTO_ECC_SIGNATURE_DATA_ENCODING_LENGTH) 
  {
    GNUNET_break (0);
    return NULL;
  }
  size = ntohs (publicKey->len);
  if (0 != (rc = gcry_mpi_scan (&q, GCRYMPI_FMT_USG, publicKey->key, size, &size)))
  {
    LOG_GCRY (GNUNET_ERROR_TYPE_ERROR, "gcry_mpi_scan", rc);
    return NULL;
  }

  rc = gcry_sexp_build (&result, &erroff, 
			"(public-key(ecdsa(curve \"" CURVE "\")(q %m)))",
			q);
  gcry_mpi_release (q);
  if (0 != rc)
  {
    LOG_GCRY (GNUNET_ERROR_TYPE_ERROR, "gcry_sexp_build", rc);  /* erroff gives more info */
    return NULL;
  }
#if EXTRA_CHECKS
  if (0 != (rc = gcry_pk_testkey (result)))
  {
    LOG_GCRY (GNUNET_ERROR_TYPE_ERROR, "gcry_pk_testkey", rc);
    gcry_sexp_release (result);
    return NULL;
  }
#endif
  return result;
}


/**
 * Encode the private key in a format suitable for
 * storing it into a file.
 *
 * @param key key to encode
 * @return encoding of the private key.
 *    The first 4 bytes give the size of the array, as usual.
 */
struct GNUNET_CRYPTO_EccPrivateKeyBinaryEncoded *
GNUNET_CRYPTO_ecc_encode_key (const struct GNUNET_CRYPTO_EccPrivateKey *key)
{
  struct GNUNET_CRYPTO_EccPrivateKeyBinaryEncoded *retval;
  char buf[65536];
  uint16_t be;
  size_t size;

#if EXTRA_CHECKS
  if (0 != gcry_pk_testkey (key->sexp))
  {
    GNUNET_break (0);
    return NULL;
  }
#endif
  size = gcry_sexp_sprint (key->sexp, 
			   GCRYSEXP_FMT_DEFAULT,
			   &buf[2], sizeof (buf) - sizeof (uint16_t));
  if (0 == size)
  {
    GNUNET_break (0);
    return NULL;
  }
  GNUNET_assert (size < 65536 - sizeof (uint16_t));
  be = htons ((uint16_t) size + (sizeof (be)));
  memcpy (buf, &be, sizeof (be));
  size += sizeof (be);
  retval = GNUNET_malloc (size);
  memcpy (retval, buf, size);
  return retval;
}


/**
 * Decode the private key from the file-format back
 * to the "normal", internal format.
 *
 * @param buf the buffer where the private key data is stored
 * @param len the length of the data in 'buffer'
 * @param validate GNUNET_YES to validate that the key is well-formed,
 *                 GNUNET_NO if the key comes from a totally trusted source 
 *                 and validation is considered too expensive
 * @return NULL on error
 */
struct GNUNET_CRYPTO_EccPrivateKey *
GNUNET_CRYPTO_ecc_decode_key (const char *buf, 
			      size_t len,
			      int validate)
{
  struct GNUNET_CRYPTO_EccPrivateKey *ret;
  uint16_t be;
  gcry_sexp_t sexp;
  int rc;
  size_t erroff;

  if (len < sizeof (uint16_t)) 
    return NULL;
  memcpy (&be, buf, sizeof (be));
  if (len < ntohs (be))
    return NULL;
  len = ntohs (be);
  if (0 != (rc = gcry_sexp_sscan (&sexp,
				  &erroff,
				  &buf[2],
				  len - sizeof (uint16_t))))
  {
    LOG_GCRY (GNUNET_ERROR_TYPE_ERROR, "gcry_sexp_scan", rc);
    return NULL;
  }  
  if ( (GNUNET_YES == validate) &&
       (0 != (rc = gcry_pk_testkey (sexp))) )
  {
    LOG_GCRY (GNUNET_ERROR_TYPE_ERROR, "gcry_pk_testkey", rc);
    return NULL;
  }
  ret = GNUNET_malloc (sizeof (struct GNUNET_CRYPTO_EccPrivateKey));
  ret->sexp = sexp;
  return ret;
}


/**
 * Create a new private key. Caller must free return value.
 *
 * @return fresh private key
 */
struct GNUNET_CRYPTO_EccPrivateKey *
GNUNET_CRYPTO_ecc_key_create ()
{
  struct GNUNET_CRYPTO_EccPrivateKey *ret;
  gcry_sexp_t s_key;
  gcry_sexp_t s_keyparam;
  int rc;

  if (0 != (rc = gcry_sexp_build (&s_keyparam, NULL,
                                  "(genkey(ecdsa(curve \"" CURVE "\")))")))
  {
    LOG_GCRY (GNUNET_ERROR_TYPE_ERROR, "gcry_sexp_build", rc);
    return NULL;
  }
  if (0 != (rc = gcry_pk_genkey (&s_key, s_keyparam)))
  {
    LOG_GCRY (GNUNET_ERROR_TYPE_ERROR, "gcry_pk_genkey", rc);
    gcry_sexp_release (s_keyparam);
    return NULL;
  }
  gcry_sexp_release (s_keyparam);
#if EXTRA_CHECKS
  if (0 != (rc = gcry_pk_testkey (s_key)))
  {
    LOG_GCRY (GNUNET_ERROR_TYPE_ERROR, "gcry_pk_testkey", rc);
    gcry_sexp_release (s_key);
    return NULL;
  }
#endif
  ret = GNUNET_malloc (sizeof (struct GNUNET_CRYPTO_EccPrivateKey));
  ret->sexp = s_key;
  return ret;
}


/**
 * Wait for a short time (we're trying to lock a file or want
 * to give another process a shot at finishing a disk write, etc.).
 * Sleeps for 100ms (as that should be long enough for virtually all
 * modern systems to context switch and allow another process to do
 * some 'real' work).
 */
static void
short_wait ()
{
  struct GNUNET_TIME_Relative timeout;

  timeout = GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MILLISECONDS, 100);
  (void) GNUNET_NETWORK_socket_select (NULL, NULL, NULL, timeout);
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
struct GNUNET_CRYPTO_EccPrivateKey *
GNUNET_CRYPTO_ecc_key_create_from_file (const char *filename)
{
  struct GNUNET_CRYPTO_EccPrivateKey *ret;
  struct GNUNET_CRYPTO_EccPrivateKeyBinaryEncoded *enc;
  uint16_t len;
  struct GNUNET_DISK_FileHandle *fd;
  unsigned int cnt;
  int ec;
  uint64_t fs;
  struct GNUNET_CRYPTO_EccPublicKeyBinaryEncoded pub;
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
                                  sizeof (struct GNUNET_CRYPTO_EccPrivateKeyBinaryEncoded),
                                  GNUNET_YES))
    {
      short_wait ();
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
    ret = GNUNET_CRYPTO_ecc_key_create ();
    GNUNET_assert (ret != NULL);
    enc = GNUNET_CRYPTO_ecc_encode_key (ret);
    GNUNET_assert (enc != NULL);
    GNUNET_assert (ntohs (enc->size) ==
                   GNUNET_DISK_file_write (fd, enc, ntohs (enc->size)));
    GNUNET_free (enc);

    GNUNET_DISK_file_sync (fd);
    if (GNUNET_YES !=
        GNUNET_DISK_file_unlock (fd, 0,
                                 sizeof (struct GNUNET_CRYPTO_EccPrivateKeyBinaryEncoded)))
      LOG_STRERROR_FILE (GNUNET_ERROR_TYPE_WARNING, "fcntl", filename);
    GNUNET_assert (GNUNET_YES == GNUNET_DISK_file_close (fd));
    GNUNET_CRYPTO_ecc_key_get_public (ret, &pub);
    GNUNET_CRYPTO_hash (&pub, sizeof (pub), &pid.hashPubKey);
    return ret;
  }
  /* key file exists already, read it! */
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
                               sizeof (struct GNUNET_CRYPTO_EccPrivateKeyBinaryEncoded),
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
             ("This may be ok if someone is currently generating a private key.\n"));
      }
      short_wait ();
      continue;
    }
    if (GNUNET_YES != GNUNET_DISK_file_test (filename))
    {
      /* eh, what!? File we opened is now gone!? */
      LOG_STRERROR_FILE (GNUNET_ERROR_TYPE_WARNING, "stat", filename);
      if (GNUNET_YES !=
          GNUNET_DISK_file_unlock (fd, 0,
                                   sizeof (struct GNUNET_CRYPTO_EccPrivateKeyBinaryEncoded)))
        LOG_STRERROR_FILE (GNUNET_ERROR_TYPE_WARNING, "fcntl", filename);
      GNUNET_assert (GNUNET_OK == GNUNET_DISK_file_close (fd));

      return NULL;
    }
    if (GNUNET_OK != GNUNET_DISK_file_size (filename, &fs, GNUNET_YES, GNUNET_YES))
      fs = 0;
    if (fs < sizeof (struct GNUNET_CRYPTO_EccPrivateKeyBinaryEncoded))
    {
      /* maybe we got the read lock before the key generating
       * process had a chance to get the write lock; give it up! */
      if (GNUNET_YES !=
          GNUNET_DISK_file_unlock (fd, 0,
                                   sizeof (struct GNUNET_CRYPTO_EccPrivateKeyBinaryEncoded)))
        LOG_STRERROR_FILE (GNUNET_ERROR_TYPE_WARNING, "fcntl", filename);
      if (0 == ++cnt % 10)
      {
        LOG (GNUNET_ERROR_TYPE_ERROR,
             _
             ("When trying to read key file `%s' I found %u bytes but I need at least %u.\n"),
             filename, (unsigned int) fs,
             (unsigned int) sizeof (struct GNUNET_CRYPTO_EccPrivateKeyBinaryEncoded));
        LOG (GNUNET_ERROR_TYPE_ERROR,
             _
             ("This may be ok if someone is currently generating a key.\n"));
      }
      short_wait ();                /* wait a bit longer! */
      continue;
    }
    break;
  }
  enc = GNUNET_malloc (fs);
  GNUNET_assert (fs == GNUNET_DISK_file_read (fd, enc, fs));
  len = ntohs (enc->size);
  ret = NULL;
  if ((len > fs) ||
      (NULL == (ret = GNUNET_CRYPTO_ecc_decode_key ((char *) enc, len, GNUNET_YES))))
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
                               sizeof (struct GNUNET_CRYPTO_EccPrivateKeyBinaryEncoded)))
    LOG_STRERROR_FILE (GNUNET_ERROR_TYPE_WARNING, "fcntl", filename);
  GNUNET_assert (GNUNET_YES == GNUNET_DISK_file_close (fd));
  if (ret != NULL)
  {
    GNUNET_CRYPTO_ecc_key_get_public (ret, &pub);
    GNUNET_CRYPTO_hash (&pub, sizeof (pub), &pid.hashPubKey);
  }
  return ret;
}


/**
 * Create a new private key by reading our peer's key from
 * the file specified in the configuration.
 *
 * @return new private key, NULL on error (for example,
 *   permission denied)
 */
struct GNUNET_CRYPTO_EccPrivateKey *
GNUNET_CRYPTO_ecc_key_create_from_configuration (const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  struct GNUNET_CRYPTO_EccPrivateKey *pk;
  char *fn;

  if (GNUNET_OK != 
      GNUNET_CONFIGURATION_get_value_filename (cfg, "PEER", "PRIVATE_KEY", &fn))
    return NULL;
  pk = GNUNET_CRYPTO_ecc_key_create_from_file (fn);
  GNUNET_free (fn);
  return pk;
}


/**
 * Setup a key file for a peer given the name of the
 * configuration file (!).  This function is used so that
 * at a later point code can be certain that reading a
 * key is fast (for example in time-dependent testcases).
 *
 * @param cfg_name name of the configuration file to use
 */
void
GNUNET_CRYPTO_ecc_setup_key (const char *cfg_name)
{
  struct GNUNET_CONFIGURATION_Handle *cfg;
  struct GNUNET_CRYPTO_EccPrivateKey *pk;

  cfg = GNUNET_CONFIGURATION_create ();
  (void) GNUNET_CONFIGURATION_load (cfg, cfg_name);
  pk = GNUNET_CRYPTO_ecc_key_create_from_configuration (cfg);
  if (NULL != pk)
    GNUNET_CRYPTO_ecc_key_free (pk);
  GNUNET_CONFIGURATION_destroy (cfg);
}


/**
 * Retrieve the identity of the host's peer.
 *
 * @param cfg configuration to use
 * @param dst pointer to where to write the peer identity
 * @return GNUNET_OK on success, GNUNET_SYSERR if the identity
 *         could not be retrieved
 */
int
GNUNET_CRYPTO_get_host_identity (const struct GNUNET_CONFIGURATION_Handle *cfg,
                                 struct GNUNET_PeerIdentity *dst)
{
  struct GNUNET_CRYPTO_EccPrivateKey *my_private_key;
  struct GNUNET_CRYPTO_EccPublicKeyBinaryEncoded my_public_key;

  if (NULL == (my_private_key = GNUNET_CRYPTO_ecc_key_create_from_configuration (cfg)))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _("Could not load peer's private key\n"));
    return GNUNET_SYSERR;
  }
  GNUNET_CRYPTO_ecc_key_get_public (my_private_key, &my_public_key);
  GNUNET_CRYPTO_ecc_key_free (my_private_key);
  GNUNET_CRYPTO_hash (&my_public_key, sizeof (my_public_key), &dst->hashPubKey);
  return GNUNET_OK;
}


/**
 * Convert the data specified in the given purpose argument to an
 * S-expression suitable for signature operations.
 *
 * @param purpose data to convert
 * @return converted s-expression
 */
static gcry_sexp_t
data_to_pkcs1 (const struct GNUNET_CRYPTO_EccSignaturePurpose *purpose)
{
  struct GNUNET_CRYPTO_ShortHashCode hc;
  size_t bufSize;
  gcry_sexp_t data;

  GNUNET_CRYPTO_short_hash (purpose, ntohl (purpose->size), &hc);
#define FORMATSTRING "(4:data(5:flags3:raw)(5:value32:01234567890123456789012345678901))"
  bufSize = strlen (FORMATSTRING) + 1;
  {
    char buff[bufSize];

    memcpy (buff, FORMATSTRING, bufSize);
    memcpy (&buff
	    [bufSize -
	     strlen
	     ("01234567890123456789012345678901))")
	     - 1], &hc, sizeof (struct GNUNET_CRYPTO_ShortHashCode));
    GNUNET_assert (0 == gcry_sexp_new (&data, buff, bufSize, 0));
  }
#undef FORMATSTRING
  return data;
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
GNUNET_CRYPTO_ecc_sign (const struct GNUNET_CRYPTO_EccPrivateKey *key,
                        const struct GNUNET_CRYPTO_EccSignaturePurpose *purpose,
                        struct GNUNET_CRYPTO_EccSignature *sig)
{
  gcry_sexp_t result;
  gcry_sexp_t data;
  size_t ssize;
  int rc;

  data = data_to_pkcs1 (purpose);
  if (0 != (rc = gcry_pk_sign (&result, data, key->sexp)))
  {
    LOG (GNUNET_ERROR_TYPE_WARNING,
         _("ECC signing failed at %s:%d: %s\n"), __FILE__,
         __LINE__, gcry_strerror (rc));
    gcry_sexp_release (data);
    return GNUNET_SYSERR;
  }
  gcry_sexp_release (data);
  ssize = gcry_sexp_sprint (result, 
			    GCRYSEXP_FMT_DEFAULT,
			    sig->sexpr,
			    GNUNET_CRYPTO_ECC_SIGNATURE_DATA_ENCODING_LENGTH);
  if (0 == ssize)
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  sig->size = htons ((uint16_t) (ssize + sizeof (uint16_t)));
  /* padd with zeros */
  memset (&sig->sexpr[ssize], 0, GNUNET_CRYPTO_ECC_SIGNATURE_DATA_ENCODING_LENGTH - ssize);
  gcry_sexp_release (result);
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
GNUNET_CRYPTO_ecc_verify (uint32_t purpose,
                          const struct GNUNET_CRYPTO_EccSignaturePurpose
                          *validate,
                          const struct GNUNET_CRYPTO_EccSignature *sig,
                          const struct GNUNET_CRYPTO_EccPublicKeyBinaryEncoded
                          *publicKey)
{
  gcry_sexp_t data;
  gcry_sexp_t sigdata;
  size_t size;
  gcry_sexp_t psexp;
  size_t erroff;
  int rc;

  if (purpose != ntohl (validate->purpose))
    return GNUNET_SYSERR;       /* purpose mismatch */
  size = ntohs (sig->size);
  if ( (size < sizeof (uint16_t)) ||
       (size > GNUNET_CRYPTO_ECC_SIGNATURE_DATA_ENCODING_LENGTH - sizeof (uint16_t)) )
    return GNUNET_SYSERR; /* size out of range */
  data = data_to_pkcs1 (validate);
  GNUNET_assert (0 ==
                 gcry_sexp_sscan (&sigdata, &erroff, 
				  sig->sexpr, size - sizeof (uint16_t)));
  if (! (psexp = decode_public_key (publicKey)))
  {
    gcry_sexp_release (data);
    gcry_sexp_release (sigdata);
    return GNUNET_SYSERR;
  }
  rc = gcry_pk_verify (sigdata, data, psexp);
  gcry_sexp_release (psexp);
  gcry_sexp_release (data);
  gcry_sexp_release (sigdata);
  if (0 != rc)
  {
    LOG (GNUNET_ERROR_TYPE_WARNING,
         _("ECC signature verification failed at %s:%d: %s\n"), __FILE__,
         __LINE__, gcry_strerror (rc));
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * Derive key material from a public and a private ECC key.
 *
 * @param key private key to use for the ECDH (x)
 * @param pub public key to use for the ECDY (yG)
 * @param key_material where to write the key material (xyG)
 * @return GNUNET_SYSERR on error, GNUNET_OK on success
 */
int
GNUNET_CRYPTO_ecc_ecdh (const struct GNUNET_CRYPTO_EccPrivateKey *key,
                        const struct GNUNET_CRYPTO_EccPublicKeyBinaryEncoded *pub,
                        struct GNUNET_HashCode *key_material)
{ 
  size_t slen;
  size_t erroff;
  int rc;
  unsigned char sdata_buf[2048]; /* big enough to print dh-shared-secret as S-expression */
  gcry_mpi_point_t result;
  gcry_mpi_point_t q;
  gcry_mpi_t d;
  gcry_ctx_t ctx;
  gcry_sexp_t psexp;
  gcry_mpi_t result_x;
  gcry_mpi_t result_y;

  /* first, extract the q = dP value from the public key */
  if (! (psexp = decode_public_key (pub)))
    return GNUNET_SYSERR;
  if (0 != (rc = gcry_mpi_ec_new (&ctx, psexp, NULL)))
  {
    LOG_GCRY (GNUNET_ERROR_TYPE_ERROR, "gcry_mpi_ec_new", rc);  /* erroff gives more info */
    return GNUNET_SYSERR;
  }
  gcry_sexp_release (psexp);
  q = gcry_mpi_ec_get_point ("q", ctx, 0);
  gcry_ctx_release (ctx);

  /* second, extract the d value from our private key */
  rc = key_from_sexp (&d, key->sexp, "private-key", "d");
  if (rc)
    rc = key_from_sexp (&d, key->sexp, "ecc", "d");
  if (0 != rc)
  {
    GNUNET_break (0);
    gcry_mpi_point_release (q);
    return GNUNET_SYSERR;
  }

  /* create a new context for definitively the correct curve;
     theoretically the 'public_key' might not use the right curve */
  if (0 != (rc = gcry_mpi_ec_new (&ctx, NULL, "NIST P-256")))
  {
    LOG_GCRY (GNUNET_ERROR_TYPE_ERROR, "gcry_mpi_ec_new", rc);  /* erroff gives more info */
    gcry_mpi_release (d);
    gcry_mpi_point_release (q);
    return GNUNET_SYSERR;
  }

  /* then call the 'multiply' function, to compute the product */
  GNUNET_assert (NULL != ctx);
  result = gcry_mpi_point_new (0);
  gcry_mpi_ec_mul (result, d, q, ctx);
  gcry_mpi_point_release (q);
  gcry_mpi_release (d);

  /* finally, convert point to string for hashing */
  result_x = gcry_mpi_new (256);
  result_y = gcry_mpi_new (256);
  if (gcry_mpi_ec_get_affine (result_x, result_y, result, ctx))
  {
    LOG_GCRY (GNUNET_ERROR_TYPE_ERROR, "get_affine failed", 0);
    gcry_mpi_point_release (result);
    gcry_ctx_release (ctx);
    return GNUNET_SYSERR;
  }
  gcry_mpi_point_release (result);
  gcry_ctx_release (ctx);
  if (0 != (rc = gcry_sexp_build (&psexp, &erroff, 
				  "(dh-shared-secret (x %m)(y %m))",
				  result_x,
				  result_y)))
  {
    LOG_GCRY (GNUNET_ERROR_TYPE_ERROR, "gcry_sexp_build", rc);  /* erroff gives more info */
    gcry_mpi_release (result_x);
    gcry_mpi_release (result_y);
    return GNUNET_SYSERR;
  }
  gcry_mpi_release (result_x);
  gcry_mpi_release (result_y);
  slen = gcry_sexp_sprint (psexp, GCRYSEXP_FMT_DEFAULT, sdata_buf, sizeof (sdata_buf));
  GNUNET_assert (0 != slen);
  gcry_sexp_release (psexp);
  /* finally, get a string of the resulting S-expression and hash it to generate the key material */
  GNUNET_CRYPTO_hash (sdata_buf, slen, key_material);
  return GNUNET_OK;
}


/* end of crypto_ecc.c */

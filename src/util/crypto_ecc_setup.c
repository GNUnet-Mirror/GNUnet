/*
     This file is part of GNUnet.
     Copyright (C) 2012, 2013, 2015, 2020 GNUnet e.V.

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
 * @file util/crypto_ecc_setup.c
 * @brief helper function for easy EdDSA key setup
 * @author Christian Grothoff
 */
#include "platform.h"
#include <gcrypt.h>
#include "gnunet_util_lib.h"

#define LOG(kind, ...) GNUNET_log_from (kind, "util-crypto-ecc", __VA_ARGS__)

#define LOG_STRERROR(kind, syscall) \
  GNUNET_log_from_strerror (kind, "util-crypto-ecc", syscall)

#define LOG_STRERROR_FILE(kind, syscall, filename) \
  GNUNET_log_from_strerror_file (kind, "util-crypto-ecc", syscall, filename)

/**
 * Log an error message at log-level 'level' that indicates
 * a failure of the command 'cmd' with the message given
 * by gcry_strerror(rc).
 */
#define LOG_GCRY(level, cmd, rc)                      \
  do                                                  \
  {                                                   \
    LOG (level,                                       \
         _ ("`%s' failed at %s:%d with error: %s\n"), \
         cmd,                                         \
         __FILE__,                                    \
         __LINE__,                                    \
         gcry_strerror (rc));                         \
  } while (0)


/**
 * Read file to @a buf. Fails if the file does not exist or
 * does not have precisely @a buf_size bytes.
 *
 * @param filename file to read
 * @param[out] buf where to write the file contents
 * @param buf_size number of bytes in @a buf
 * @return #GNUNET_OK on success
 */
static int
read_from_file (const char *filename,
                void *buf,
                size_t buf_size)
{
  int fd;
  struct stat sb;

  fd = open (filename,
             O_RDONLY);
  if (-1 == fd)
  {
    memset (buf,
            0,
            buf_size);
    return GNUNET_SYSERR;
  }
  if (0 != fstat (fd,
                  &sb))
  {
    GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_WARNING,
                              "stat",
                              filename);
    GNUNET_assert (0 == close (fd));
    memset (buf,
            0,
            buf_size);
    return GNUNET_SYSERR;
  }
  if (sb.st_size != buf_size)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "File `%s' has wrong size (%llu), expected %llu bytes\n",
                filename,
                (unsigned long long) sb.st_size,
                (unsigned long long) buf_size);
    GNUNET_assert (0 == close (fd));
    memset (buf,
            0,
            buf_size);
    return GNUNET_SYSERR;
  }
  if (buf_size !=
      read (fd,
            buf,
            buf_size))
  {
    GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_WARNING,
                              "read",
                              filename);
    GNUNET_assert (0 == close (fd));
    memset (buf,
            0,
            buf_size);
    return GNUNET_SYSERR;
  }
  GNUNET_assert (0 == close (fd));
  return GNUNET_OK;
}


/**
 * Write contents of @a buf atomically to @a filename.
 * Fail if @a filename already exists or if not exactly
 * @a buf with @a buf_size bytes could be written to
 * @a filename.
 *
 * @param filename where to write
 * @param buf buffer to write
 * @param buf_size number of bytes in @a buf to write
 * @return #GNUNET_OK on success,
 *         #GNUNET_NO if a file existed under @a filename
 *         #GNUNET_SYSERR on failure
 */
static int
atomic_write_to_file (const char *filename,
                      const void *buf,
                      size_t buf_size)
{
  char *tmpl;
  int fd;

  {
    char *dname;

    dname = GNUNET_strdup (filename);
    GNUNET_asprintf (&tmpl,
                     "%s/XXXXXX",
                     dirname (dname));
    GNUNET_free (dname);
  }
  fd = mkstemp (tmpl);
  if (-1 == fd)
  {
    GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_WARNING,
                              "mkstemp",
                              tmpl);
    GNUNET_free (tmpl);
    return GNUNET_SYSERR;
  }
  if (0 != fchmod (fd,
                   S_IRUSR))
  {
    GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_WARNING,
                              "chmod",
                              tmpl);
    GNUNET_assert (0 == close (fd));
    if (0 != unlink (tmpl))
      GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_ERROR,
                                "unlink",
                                tmpl);
    GNUNET_free (tmpl);
    return GNUNET_SYSERR;
  }
  if (buf_size !=
      write (fd,
             buf,
             buf_size))
  {
    GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_WARNING,
                              "write",
                              tmpl);
    GNUNET_assert (0 == close (fd));
    if (0 != unlink (tmpl))
      GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_ERROR,
                                "unlink",
                                tmpl);
    GNUNET_free (tmpl);
    return GNUNET_SYSERR;
  }
  GNUNET_assert (0 == close (fd));

  if (0 != link (tmpl,
                 filename))
  {
    if (0 != unlink (tmpl))
      GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_ERROR,
                                "unlink",
                                tmpl);
    GNUNET_free (tmpl);
    return GNUNET_NO;
  }
  if (0 != unlink (tmpl))
    GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_ERROR,
                              "unlink",
                              tmpl);
  GNUNET_free (tmpl);
  return GNUNET_OK;
}


/**
 * @ingroup crypto
 * @brief Create a new private key by reading it from a file.
 *
 * If the files does not exist and @a do_create is set, creates a new key and
 * write it to the file.
 *
 * If the contents of the file are invalid, an error is returned.
 *
 * @param filename name of file to use to store the key
 * @param do_create should a file be created?
 * @param[out] pkey set to the private key from @a filename on success
 * @return #GNUNET_OK on success, #GNUNET_NO if @a do_create was set but
 *         we found an existing file, #GNUNET_SYSERR on failure
 */
int
GNUNET_CRYPTO_eddsa_key_from_file (const char *filename,
                                   int do_create,
                                   struct GNUNET_CRYPTO_EddsaPrivateKey *pkey)
{
  int ret;

  if (GNUNET_OK ==
      read_from_file (filename,
                      pkey,
                      sizeof (*pkey)))
  {
    /* file existed, report that we didn't create it... */
    return (do_create) ? GNUNET_NO : GNUNET_OK;
  }
  GNUNET_CRYPTO_eddsa_key_create (pkey);
  ret = atomic_write_to_file (filename,
                              pkey,
                              sizeof (*pkey));
  if ( (GNUNET_OK == ret) ||
       (GNUNET_SYSERR == ret) )
    return ret;
  /* maybe another process succeeded in the meantime, try reading one more time */
  if (GNUNET_OK ==
      read_from_file (filename,
                      pkey,
                      sizeof (*pkey)))
  {
    /* file existed, report that *we* didn't create it... */
    return (do_create) ? GNUNET_NO : GNUNET_OK;
  }
  /* give up */
  return GNUNET_SYSERR;
}


/**
 * @ingroup crypto
 * @brief Create a new private key by reading it from a file.
 *
 * If the files does not exist and @a do_create is set, creates a new key and
 * write it to the file.
 *
 * If the contents of the file are invalid, an error is returned.
 *
 * @param filename name of file to use to store the key
 * @param do_create should a file be created?
 * @param[out] pkey set to the private key from @a filename on success
 * @return #GNUNET_OK on success, #GNUNET_NO if @a do_create was set but
 *         we found an existing file, #GNUNET_SYSERR on failure
 */
int
GNUNET_CRYPTO_ecdsa_key_from_file (const char *filename,
                                   int do_create,
                                   struct GNUNET_CRYPTO_EcdsaPrivateKey *pkey)
{
  if (GNUNET_OK ==
      read_from_file (filename,
                      pkey,
                      sizeof (*pkey)))
  {
    /* file existed, report that we didn't create it... */
    return (do_create) ? GNUNET_NO : GNUNET_OK;
  }
  GNUNET_CRYPTO_ecdsa_key_create (pkey);
  if (GNUNET_OK ==
      atomic_write_to_file (filename,
                            pkey,
                            sizeof (*pkey)))
    return GNUNET_OK;
  /* maybe another process succeeded in the meantime, try reading one more time */
  if (GNUNET_OK ==
      read_from_file (filename,
                      pkey,
                      sizeof (*pkey)))
  {
    /* file existed, report that *we* didn't create it... */
    return (do_create) ? GNUNET_NO : GNUNET_OK;
  }
  /* give up */
  return GNUNET_SYSERR;
}


/**
 * Create a new private key by reading our peer's key from
 * the file specified in the configuration.
 *
 * @param cfg the configuration to use
 * @return new private key, NULL on error (for example,
 *   permission denied)
 */
struct GNUNET_CRYPTO_EddsaPrivateKey *
GNUNET_CRYPTO_eddsa_key_create_from_configuration (
  const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  struct GNUNET_CRYPTO_EddsaPrivateKey *priv;
  char *fn;

  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_filename (cfg,
                                               "PEER",
                                               "PRIVATE_KEY",
                                               &fn))
    return NULL;
  priv = GNUNET_new (struct GNUNET_CRYPTO_EddsaPrivateKey);
  GNUNET_CRYPTO_eddsa_key_from_file (fn,
                                     GNUNET_YES,
                                     priv);
  GNUNET_free (fn);
  return priv;
}


/**
 * Retrieve the identity of the host's peer.
 *
 * @param cfg configuration to use
 * @param dst pointer to where to write the peer identity
 * @return #GNUNET_OK on success, #GNUNET_SYSERR if the identity
 *         could not be retrieved
 */
int
GNUNET_CRYPTO_get_peer_identity (const struct GNUNET_CONFIGURATION_Handle *cfg,
                                 struct GNUNET_PeerIdentity *dst)
{
  struct GNUNET_CRYPTO_EddsaPrivateKey *priv;

  if (NULL == (priv = GNUNET_CRYPTO_eddsa_key_create_from_configuration (cfg)))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _ ("Could not load peer's private key\n"));
    return GNUNET_SYSERR;
  }
  GNUNET_CRYPTO_eddsa_key_get_public (priv,
                                      &dst->public_key);
  GNUNET_free (priv);
  return GNUNET_OK;
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
GNUNET_CRYPTO_eddsa_setup_key (const char *cfg_name)
{
  struct GNUNET_CONFIGURATION_Handle *cfg;
  struct GNUNET_CRYPTO_EddsaPrivateKey *priv;

  cfg = GNUNET_CONFIGURATION_create ();
  (void) GNUNET_CONFIGURATION_load (cfg, cfg_name);
  priv = GNUNET_CRYPTO_eddsa_key_create_from_configuration (cfg);
  if (NULL != priv)
    GNUNET_free (priv);
  GNUNET_CONFIGURATION_destroy (cfg);
}


/* end of crypto_ecc_setup.c */

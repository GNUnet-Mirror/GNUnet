/*
     This file is part of GNUnet.
     (C) 2013 Christian Grothoff

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
     Free Software Foundation, Inc., 59 Temple Place - Suite 330,
     Boston, MA 02111-1307, USA.
*/

/**
 * @file topology/friends.c
 * @brief library to read and write the FRIENDS file
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_friends_lib.h"


/**
 * Parse the FRIENDS file.
 *
 * @param cfg our configuration
 * @param cb function to call on each friend found
 * @param cb_cls closure for @a cb
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on parsing errors
 */
int
GNUNET_FRIENDS_parse (const struct GNUNET_CONFIGURATION_Handle *cfg,
                      GNUNET_FRIENDS_Callback cb,
                      void *cb_cls)
{
  char *fn;
  char *data;
  size_t pos;
  size_t start;
  struct GNUNET_PeerIdentity pid;
  uint64_t fsize;

  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_filename (cfg, "TOPOLOGY", "FRIENDS", &fn))
  {
    GNUNET_log_config_missing (GNUNET_ERROR_TYPE_ERROR,
			       "topology", "FRIENDS");
    return GNUNET_SYSERR;
  }
  if ( (GNUNET_OK != GNUNET_DISK_file_test (fn)) &&
       (GNUNET_OK != GNUNET_DISK_fn_write (fn, NULL, 0,
					   GNUNET_DISK_PERM_USER_READ |
					   GNUNET_DISK_PERM_USER_WRITE)) )
      GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_WARNING, "write", fn);
  if ( (GNUNET_OK !=
        GNUNET_DISK_file_size (fn,
                               &fsize,
                               GNUNET_NO, GNUNET_YES)) ||
       (0 == fsize) )
  {
    GNUNET_free (fn);
    return GNUNET_OK;
  }
  data = GNUNET_malloc_large (fsize);
  if (NULL == data)
  {
    GNUNET_log_strerror (GNUNET_ERROR_TYPE_ERROR, "malloc");
    GNUNET_free (fn);
    return GNUNET_SYSERR;
  }
  if (fsize != GNUNET_DISK_fn_read (fn, data, fsize))
  {
    GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_ERROR, "read", "fn");
    GNUNET_free (fn);
    GNUNET_free (data);
    return GNUNET_SYSERR;
  }
  start = 0;
  pos = 0;
  while (pos < fsize)
  {
    while ((pos < fsize) && isspace ((unsigned char) data[pos]))
      pos++;
    if (GNUNET_OK !=
        GNUNET_CRYPTO_ecc_public_sign_key_from_string (&data[start],
						       pos - start,
						       &pid.public_key))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  _("Syntax error in topology specification at offset %llu, skipping bytes `%.*s'.\n"),
                  (unsigned long long) pos,
		  (int) (pos - start),
		  &data[start]);
      pos++;
      start = pos;
      continue;
    }
    pos++;
    start = pos;
    cb (cb_cls, &pid);
  }
  GNUNET_free (data);
  GNUNET_free (fn);
  return GNUNET_OK;
}


/**
 * Handle for writing a friends file.
 */
struct GNUNET_FRIENDS_Writer
{
};


/**
 * Start writing a fresh FRIENDS file.  Will make a backup of the
 * old one.
 *
 * @param cfg configuration to use.
 * @return NULL on error
 */
struct GNUNET_FRIENDS_Writer *
GNUNET_FRIENDS_write_start (const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  return NULL;
}


/**
 * Finish writing out the friends file.
 *
 * @param w write handle
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on error
 */
int
GNUNET_FRIENDS_write_stop (struct GNUNET_FRIENDS_Writer *w)
{
  return GNUNET_SYSERR;
}


/**
 * Add a friend to the friends file.
 *
 * @param w write handle
 * @param friend friend to add
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on error
 */
int
GNUNET_FRIENDS_write (struct GNUNET_FRIENDS_Writer *w,
                      const struct GNUNET_PeerIdentity *friend)
{
  return GNUNET_SYSERR;
}


/* end of friends.c */

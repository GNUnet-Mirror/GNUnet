/*
     This file is part of GNUnet
     (C) 2012 Christian Grothoff (and other contributing authors)

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
 * @file hello/gnunet-hello.c
 * @brief change HELLO files to never expire
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_hello_lib.h"

#define DEBUG GNUNET_EXTRA_LOGGING

#define VERBOSE GNUNET_NO

/**
 * Closure for 'add_to_buf'.
 */
struct AddContext
{
  /**
   * Where to add.
   */
  char *buf;
  
  /**
   * Maximum number of bytes left
   */
  size_t max;

  /**
   * Number of bytes added so far.
   */
  size_t ret;
};


/**
 * Add the given address with infinit expiration to the buffer.
 *
 * @param cls closure
 * @param address address to add
 * @param expiration old expiration
 * @return GNUNET_OK keep iterating
 */
static int
add_to_buf (void *cls, const struct GNUNET_HELLO_Address *address,
            struct GNUNET_TIME_Absolute expiration)
{
  struct AddContext *ac = cls;
  size_t ret;

  ret = GNUNET_HELLO_add_address (address, 
				  GNUNET_TIME_UNIT_FOREVER_ABS,
				  ac->buf,
				  ac->max);
  ac->buf += ret;
  ac->max -= ret;
  ac->ret += ret;  
  return GNUNET_OK;
}


/**
 * Add addresses from the address list to the HELLO.
 *
 * @param cls the HELLO with the addresses to add
 * @param max maximum space available
 * @param buf where to add the addresses
 * @return number of bytes added, 0 to terminate
 */
static size_t
add_from_hello (void *cls, size_t max, void *buf)
{
  struct GNUNET_HELLO_Message **orig = cls;
  struct AddContext ac;

  if (NULL == *orig)
    return 0; /* already done */
  ac.buf = buf;
  ac.max = max;
  ac.ret = 0;
  GNUNET_assert (NULL ==
		 GNUNET_HELLO_iterate_addresses (*orig, 
						 GNUNET_NO, &add_to_buf,
						 &ac));
  *orig = NULL;
  return ac.ret;
}


int
main (int argc, char *argv[])
{
  struct GNUNET_DISK_FileHandle *fh;
  struct GNUNET_HELLO_Message *orig;
  struct GNUNET_HELLO_Message *result;
  struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded pk;
  uint64_t fsize;

  GNUNET_log_setup ("gnunet-hello", "INFO", NULL);
  if (argc != 2)
  {
    FPRINTF (stderr,
	     "%s",
	     _("Call with name of HELLO file to modify.\n"));
    return 1;
  }
  if (GNUNET_OK != GNUNET_DISK_file_size (argv[1], &fsize, GNUNET_YES, GNUNET_YES))
  {
    FPRINTF (stderr,
	     _("Error accessing file `%s': %s\n"),
	     argv[1],
	     STRERROR (errno));
    return 1;
  }
  if (fsize > 65536)
  {
    FPRINTF (stderr,
	     _("File `%s' is too big to be a HELLO\n"),
	     argv[1]);
    return 1;
  }
  if (fsize < sizeof (struct GNUNET_MessageHeader))
  {
    FPRINTF (stderr,
	     _("File `%s' is too small to be a HELLO\n"),
	     argv[1]);
    return 1;
  }
  fh = GNUNET_DISK_file_open (argv[1], 
			      GNUNET_DISK_OPEN_READ,
			      GNUNET_DISK_PERM_USER_READ);
  if (NULL == fh)
  {
    FPRINTF (stderr,
	     _("Error opening file `%s': %s\n"),
	     argv[1],
	     STRERROR (errno));
    return 1;
  }
  {
    char buf[fsize] GNUNET_ALIGN;
    
    GNUNET_assert (fsize == 
		   GNUNET_DISK_file_read (fh, buf, fsize));
    GNUNET_assert (GNUNET_OK == GNUNET_DISK_file_close (fh));
    orig = (struct GNUNET_HELLO_Message *) buf;
    if ( (fsize != GNUNET_HELLO_size (orig)) ||
	 (GNUNET_OK != GNUNET_HELLO_get_key (orig, &pk)) )
    {
      FPRINTF (stderr,
	       _("Did not find well-formed HELLO in file `%s'\n"),
	       argv[1]);
      return 1;
    }
    result = GNUNET_HELLO_create (&pk, &add_from_hello, &orig);
    GNUNET_assert (NULL != result);
     fh = GNUNET_DISK_file_open (argv[1], 
				 GNUNET_DISK_OPEN_WRITE,
				 GNUNET_DISK_PERM_USER_READ | GNUNET_DISK_PERM_USER_WRITE);
     if (NULL == fh)
     {
       FPRINTF (stderr,
		_("Error opening file `%s': %s\n"),
		argv[1],
		STRERROR (errno));
       GNUNET_free (result);
       return 1;
     }
     fsize = GNUNET_HELLO_size (result);
     if (fsize != GNUNET_DISK_file_write (fh,
					  result,
					  fsize))
     {
       FPRINTF (stderr,
		_("Error writing HELLO to file `%s': %s\n"),
		argv[1],
		STRERROR (errno));
       (void) GNUNET_DISK_file_close (fh);
       return 1;
     }
    GNUNET_assert (GNUNET_OK == GNUNET_DISK_file_close (fh));
  }
  return 0;
}

/* end of gnunet-hello.c */

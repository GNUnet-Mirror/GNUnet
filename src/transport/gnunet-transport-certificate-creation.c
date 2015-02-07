/*
     This file is part of GNUnet.
     Copyright (C) 2011, 2013 Christian Grothoff (and other contributing authors)

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
 * @file transport/gnunet-transport-certificate-creation.c
 * @brief create certificate for HTTPS transport
 * @author LRN
 */
#include "platform.h"
#include "gnunet_util_lib.h"

#ifndef WINDOWS
/**
 * Turn the given file descriptor in to '/dev/null'.
 *
 * @param fd fd to bind to /dev/null
 * @param flags flags to use (O_RDONLY or O_WRONLY)
 */
static void
make_dev_zero (int fd,
	       int flags)
{
  int z;

  GNUNET_assert (0 == close (fd));
  z = open ("/dev/null", flags);
  GNUNET_assert (-1 != z);
  if (z == fd)
    return;
  dup2 (z, fd);
  GNUNET_assert (0 == close (z));
}
#endif


static void
removecerts (const char *file1,
	     const char *file2)
{
  if (GNUNET_YES == GNUNET_DISK_file_test (file1))
  {
    if (0 != CHMOD (file1, S_IWUSR | S_IRUSR))
      GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_WARNING, "chmod", file1);
    if (0 != REMOVE (file1))
      GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_WARNING, "remove", file1);
  }
  if (GNUNET_YES == GNUNET_DISK_file_test (file2))
  {
    if (0 != CHMOD (file2, S_IWUSR | S_IRUSR))
      GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_WARNING, "chmod", file2);
    if (0 != REMOVE (file2))
      GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_WARNING, "remove", file2);
  }
}


int
main (int argc, char **argv)
{
  struct GNUNET_OS_Process *openssl;

  if (3 != argc)
  {
    fprintf (stderr,
	     "Invalid arguments.\n");
    return 1;
  }
  removecerts (argv[1], argv[2]);
  (void) GNUNET_DISK_directory_create_for_file (argv[1]);
  (void) GNUNET_DISK_directory_create_for_file (argv[2]);
  /* eliminate stderr */
#if WINDOWS
  (void) close (2);
#else
  make_dev_zero (2, O_WRONLY);
#endif
  /* Create RSA Private Key */
  /* openssl genrsa -out $1 1024 2> /dev/null */
  openssl =
      GNUNET_OS_start_process (GNUNET_NO, GNUNET_OS_INHERIT_STD_OUT_AND_ERR,
                               NULL, NULL, NULL,
                               "openssl", "openssl", "genrsa",
                               "-out", argv[1], "1024", NULL);
  if (NULL == openssl)
  {
    fprintf (stderr,
	     "Failed to run openssl.  Is openssl installed?\n");
    return 2;
  }
  GNUNET_assert (GNUNET_OK == GNUNET_OS_process_wait (openssl));
  GNUNET_OS_process_destroy (openssl);

  /* Create a self-signed certificate in batch mode using rsa key */
  /* openssl req -batch -days 365 -out $2 -new -x509 -key $1 2> /dev/null */
  openssl =
      GNUNET_OS_start_process (GNUNET_NO, GNUNET_OS_INHERIT_STD_OUT_AND_ERR,
                               NULL, NULL, NULL,
                               "openssl", "openssl", "req",
                               "-batch", "-days", "365", "-out", argv[2],
                               "-new", "-x509", "-key", argv[1], NULL);
  if (NULL == openssl)
  {
    fprintf (stderr,
	     "Failed to create self-signed certificate with openssl.\n");
    return 3;
  }
  GNUNET_assert (GNUNET_OK == GNUNET_OS_process_wait (openssl));
  GNUNET_OS_process_destroy (openssl);
  if (0 != CHMOD (argv[1], S_IRUSR))
    GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_WARNING, "chmod", argv[1]);
  if (0 != CHMOD (argv[2], S_IRUSR))
    GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_WARNING, "chmod", argv[2]);
  return 0;
}

/* end of gnunet-transport-certificate-creation.c */

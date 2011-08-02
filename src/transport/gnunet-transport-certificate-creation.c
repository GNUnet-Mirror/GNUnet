/*
     This file is part of GNUnet.
     (C) 2011 Christian Grothoff (and other contributing authors)

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
 *
 */
#include "platform.h"
#include "gnunet_disk_lib.h"
#include "gnunet_os_lib.h"


static void 
removecerts (const char *file1, 
	     const char *file2)
{
  if (GNUNET_DISK_file_test (file1) == GNUNET_YES)
    {
      CHMOD (file1, 0777);
      REMOVE (file1);
    }
  if (GNUNET_DISK_file_test (file2) == GNUNET_YES)
    {
      CHMOD (file2, 0777);
      REMOVE (file2);
    }
}


int
main (int argc, char **argv)
{
  struct GNUNET_OS_Process *openssl;
  enum GNUNET_OS_ProcessStatusType status_type;
  unsigned long code;

  if (argc != 3)
    return 1;
  close (2); /* no output to stderr */
  removecerts (argv[1], argv[2]);
  /* Create RSA Private Key */
  /* openssl genrsa -out $1 1024 2> /dev/null */
  openssl = GNUNET_OS_start_process (NULL, NULL,
				     "openssl", 
				     "openssl",
				     "genrsa", "-out", argv[1], "1024",
				     NULL);
  if (openssl == NULL)
    return 2;
  if (GNUNET_OS_process_wait (openssl) != GNUNET_OK)
    {
      GNUNET_OS_process_kill (openssl, SIGTERM);
      removecerts (argv[1], argv[2]);
      return 3;
    }
  if (GNUNET_OS_process_status (openssl, &status_type, &code) != GNUNET_OK)
    {
      GNUNET_OS_process_kill (openssl, SIGTERM);
      removecerts (argv[1], argv[2]);
      return 4;
    }
  if (status_type != GNUNET_OS_PROCESS_EXITED || code != 0)
    {
      GNUNET_OS_process_kill (openssl, SIGTERM);
      removecerts (argv[1], argv[2]);
      return 5;
    }
  GNUNET_OS_process_close (openssl);
  
  /* Create a self-signed certificate in batch mode using rsa key*/
  /* openssl req -batch -days 365 -out $2 -new -x509 -key $1 2> /dev/null */
  openssl = GNUNET_OS_start_process (NULL, NULL, 
				     "openssl", 
				     "openssl", 
				     "req", "-batch", "-days", "365", 
				     "-out", argv[2], "-new", "-x509", "-key", argv[1], 
				     NULL);
  if (openssl == NULL)
    return 6;
  if (GNUNET_OS_process_wait (openssl) != GNUNET_OK)
    {
      GNUNET_OS_process_kill (openssl, SIGTERM);
      removecerts (argv[1], argv[2]);
      return 7;
    }
  if (GNUNET_OS_process_status (openssl, &status_type, &code) != GNUNET_OK)
    {
      GNUNET_OS_process_kill (openssl, SIGTERM);
      removecerts (argv[1], argv[2]);
      return 8;
    }
  if (status_type != GNUNET_OS_PROCESS_EXITED || code != 0)
    {
      GNUNET_OS_process_kill (openssl, SIGTERM);
      removecerts (argv[1], argv[2]);
      return 9;
    }
  GNUNET_OS_process_close (openssl);
  CHMOD (argv[1], 0400);
  CHMOD (argv[2], 0400);
  return 0;
}

/* end of gnunet-transport-certificate-creation.c */

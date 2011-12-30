/*
     This file is part of GNUnet
     (C) 2009 Christian Grothoff (and other contributing authors)

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
 * @file fs/test_fs_getopt.c
 * @brief test for fs_getopt.c
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_fs_service.h"

int
main (int argc, char *argv[])
{
  GNUNET_log_setup ("test_fs_directory",
#if VERBOSE
                    "DEBUG",
#else
                    "WARNING",
#endif
                    NULL);
  FPRINTF (stderr, "%s",  "WARNING: testcase not yet written.\n");
  return 0;                     /* testcase passed */
}

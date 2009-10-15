/*
     This file is part of GNUnet.
     (C) 2009 Christian Grothoff (and other contributing authors)

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
 * @file util/test_bio.c
 * @brief testcase for the buffered IO module
 * @author
 */
#include "platform.h"
#include "gnunet_common.h"
#include "gnunet_disk_lib.h"
#include "gnunet_scheduler_lib.h"



int
main (int argc, char *argv[])
{
  unsigned int failureCount = 0;

  GNUNET_log_setup ("test-bio", "WARNING", NULL);
  if (failureCount != 0)
    {
      fprintf (stderr, "\n%u TESTS FAILED!\n", failureCount);
      return -1;
    }
  return 0;
}                               /* end of main */

/*
     This file is part of GNUnet.
     (C) 2009, 2013 Christian Grothoff (and other contributing authors)

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
 * @file dv/test_transport_dv.c
 * @brief base testcase for testing distance vector transport
 */
#include "platform.h"
#include "gnunet_core_service.h"
#include "gnunet_testbed_service.h"

/**
 * Return value from main, set to 0 on success.
 */
static int ok;

static void
test_connection (void *cls,
                 struct GNUNET_TESTBED_RunHandle *h,
		 unsigned int num_peers,
		 struct GNUNET_TESTBED_Peer **peers,
                 unsigned int links_succeeded,
                 unsigned int links_failed)
{
  int c;
  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Links successful %u / %u failed\n", links_succeeded, links_failed);

  if ( (4 != num_peers) || (0 != links_failed) )
  {
    fprintf (stderr, "Testbed failed to connect peers\n");
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  ok = 0;
  if (1)
  {
    GNUNET_SCHEDULER_shutdown ();
  }
  else
    fprintf (stderr, "Test passed, press CTRL-C to shut down\n");
}


int
main (int argc, char *argv[])
{
  ok = 1;
  (void) GNUNET_TESTBED_test_run ("test-transport-dv",
				  "test_transport_dv_data.conf",
				  4,
				  0, NULL, NULL,
				  &test_connection, NULL);
  return ok;
}

/* end of test_transport_dv.c */

/*
     This file is part of GNUnet.
     Copyright (C) 2009, 2013 Christian Grothoff (and other contributing authors)

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
     Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
     Boston, MA 02110-1301, USA.
*/
/**
 * @file dv/test_transport_blacklist.c
 * @brief base testcase for testing blacklist
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
  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Links successful %u / %u failed\n", links_succeeded, links_failed);
  if ( (4 == num_peers) && (0 == links_failed) )
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		"Testbed connect peers despite blacklist!\n");
    ok = 1;
  }
  else
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		"Note that getting a message about a timeout during setup is expected for this test.\n");
  }
  GNUNET_SCHEDULER_shutdown ();
}


int
main (int argc, char *argv[])
{
  (void) GNUNET_TESTBED_test_run ("test-transport-blacklist",
				  "test_transport_blacklist_data.conf",
				  4,
				  0, NULL, NULL,
				  &test_connection, NULL);
  return ok;
}

/* end of test_transport_blacklist.c */

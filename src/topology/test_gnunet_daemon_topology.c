/*
     This file is part of GNUnet.
     Copyright (C) 2009, 2012 Christian Grothoff (and other contributing authors)

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
 * @file topology/test_gnunet_daemon_topology.c
 * @brief testcase for topology maintenance code
 */
#include "platform.h"
#include "gnunet_testbed_service.h"


#define NUM_PEERS 8

/**
 * How long until we give up on connecting the peers?
 */
#define TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 600)


static int ok;

static unsigned int connect_left;


static void
notify_connect_complete (void *cls,
			 struct GNUNET_TESTBED_Operation *op,
			 const char *emsg)
{
  GNUNET_TESTBED_operation_done (op);
  if (NULL != emsg)
  {
    FPRINTF (stderr, "Failed to connect two peers: %s\n", emsg);
    GNUNET_SCHEDULER_shutdown ();
    ok = 1;
    return;
  }
  connect_left--;
  if (0 == connect_left)
  {
    /* FIXME: check that topology adds a few more links
     * in addition to those that were seeded */
    GNUNET_SCHEDULER_shutdown ();
  }
}


static void
do_connect (void *cls,
            struct GNUNET_TESTBED_RunHandle *h,
	    unsigned int num_peers,
	    struct GNUNET_TESTBED_Peer **peers,
            unsigned int links_succeeded,
            unsigned int links_failed)
{
  unsigned int i;

  GNUNET_assert (NUM_PEERS == num_peers);
  for (i=0;i<num_peers-1;i++)
    {
      connect_left++;
      GNUNET_TESTBED_overlay_connect (NULL,
				      &notify_connect_complete, NULL,
				      peers[i], peers[i+1]);
    }
}


int
main (int argc, char *argv[])
{
  (void) GNUNET_TESTBED_test_run ("test-gnunet-daemon-topology",
                                  "test_gnunet_daemon_topology_data.conf",
                                  NUM_PEERS,
                                  0, NULL, NULL,
                                  &do_connect, NULL);
  GNUNET_DISK_directory_remove ("/tmp/test-gnunet-topology");
  return ok;
}

/* end of test_gnunet_daemon_topology.c */

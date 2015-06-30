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

struct GNUNET_TESTBED_Operation *topology_op;

static struct GNUNET_SCHEDULER_Task * shutdown_task;


static void
do_shutdown (void *cls,
             const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  shutdown_task = NULL;
  if (NULL != topology_op)
  {
    GNUNET_TESTBED_operation_done (topology_op);
    topology_op = NULL;
  }
}


static void
topology_completed (void *cls,
                    unsigned int nsuccess,
                    unsigned int nfailures)
{
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "Links successful %u / %u failed\n",
              nsuccess,
              nfailures);
  GNUNET_TESTBED_operation_done (topology_op);
  topology_op = NULL;

  if (nfailures > 0)
  {
    fprintf (stderr,
             "Error: links successful %u but %u failed\n",
             nsuccess,
             nfailures);
    ok = 1;
  }
  else
    ok = 0;

  GNUNET_SCHEDULER_shutdown ();
}


static void
test_connection (void *cls,
                 struct GNUNET_TESTBED_RunHandle *h,
		 unsigned int num_peers,
		 struct GNUNET_TESTBED_Peer **peers,
                 unsigned int links_succeeded,
                 unsigned int links_failed)
{
  shutdown_task = GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_FOREVER_REL,
                                                &do_shutdown, NULL);
  if (4 != num_peers)
  {
    ok = 1;
    fprintf (stderr,
             "Only %u out of 4 peers were started ...\n",
             num_peers);
  }

  if (0 != links_failed)
  {
    /* All peers except DV peers are connected  */
    fprintf (stderr,
             "Testbed failed to connect peers (%u links OK, %u links failed)\n",
             links_succeeded,
             links_failed);

    topology_op = GNUNET_TESTBED_overlay_configure_topology
      (NULL, num_peers, peers, NULL,
       &topology_completed, NULL,
       GNUNET_TESTBED_TOPOLOGY_CLIQUE,
       GNUNET_TESTBED_TOPOLOGY_OPTION_END);
    return;
  }

  ok = 1;
  fprintf (stderr,
           "Testbed connected peers, should not happen...\n");
  GNUNET_SCHEDULER_shutdown ();
}


int
main (int argc, char *argv[])
{
  ok = 1;
  /* Connecting initial topology */
  (void) GNUNET_TESTBED_test_run ("test-transport-dv",
				  "test_transport_dv_data.conf",
				  4,
				  0, NULL, NULL,
				  &test_connection, NULL);
  return ok;
}

/* end of test_transport_dv.c */

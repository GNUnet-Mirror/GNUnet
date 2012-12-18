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
 * @file mesh/test_mesh_2dtorus.c
 *
 * @brief Test for creating a 2dtorus.
 */
#include "platform.h"
#include "mesh_test_lib.h"
#include "gnunet_mesh_service.h"

#define REMOVE_DIR GNUNET_YES

/**
 * How long until we give up on connecting the peers?
 */
#define TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 1500)

/**
 * Time to wait for stuff that should be rather fast
 */
#define SHORT_TIME GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 30)


/**
 * How many events have happened
 */
static int ok;

/**
 * Total number of currently running peers.
 */
static unsigned long long peers_running;

/**
 * Task to time out.
 */
static GNUNET_SCHEDULER_TaskIdentifier timeout_task;


static void
shutdown_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "shutting down test\n");
}


/**
 * test main: start test when all peers are connected
 *
 * @param cls Closure.
 * @param ctx Argument to give to GNUNET_MESH_TEST_cleanup on test end.
 * @param num_peers Number of peers that are running.
 * @param peers Array of peers.
 * @param meshes Handle to each of the MESHs of the peers.
 */
static void
tmain (void *cls,
       struct GNUNET_MESH_TEST_Context *ctx,
       unsigned int num_peers,
       struct GNUNET_TESTBED_Peer **peers,
       struct GNUNET_MESH_Handle **meshes)
{
  if (16 != num_peers)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "running peers mismatch, aborting test!\n");
    ok--;
    GNUNET_MESH_TEST_cleanup (ctx);
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "testbed started successfully with ?? connections\n");
  peers_running = num_peers;
  timeout_task = GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_MINUTES, 
                                               &shutdown_task, ctx);
  ok = GNUNET_OK;
  GNUNET_MESH_TEST_cleanup (ctx);
}


/**
 * Main: start test
 */
int
main (int argc, char *argv[])
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "test: Start\n");
  ok = GNUNET_SYSERR;

  GNUNET_MESH_TEST_run ("test_mesh_2dtorus",
                        "test_mesh_2dtorus.conf",
                        16,
                        &tmain,
                        NULL,
                        NULL,
                        NULL,
                        NULL,
                        NULL
  );

  if (GNUNET_OK != ok)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING, "FAILED!\n");
    return 1;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "success\n");
  return 0;
}

/* end of test_mesh_2dtorus.c */

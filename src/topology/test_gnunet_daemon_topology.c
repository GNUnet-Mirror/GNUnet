/*
     This file is part of GNUnet.
     Copyright (C) 2009, 2012 GNUnet e.V.

     GNUnet is free software: you can redistribute it and/or modify it
     under the terms of the GNU Affero General Public License as published
     by the Free Software Foundation, either version 3 of the License,
     or (at your option) any later version.

     GNUnet is distributed in the hope that it will be useful, but
     WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
     Affero General Public License for more details.

     You should have received a copy of the GNU Affero General Public License
     along with this program.  If not, see <http://www.gnu.org/licenses/>.

     SPDX-License-Identifier: AGPL3.0-or-later
 */
/**
 * @file topology/test_gnunet_daemon_topology.c
 * @brief testcase for topology maintenance code
 * @author Christian Grothoff
 * @author xrs
 */
#include "platform.h"
#include "gnunet_testbed_service.h"
#include "gnunet_statistics_service.h"


#define NUM_PEERS 8

/*
 * The threshold defines the number of connection that are needed
 * for one peer to pass the test. Be aware that setting NUM_PEERS
 * too high can cause bandwidth problems for the testing peers.
 * Normal should be 5KB/s per peer. See gnunet-config -s ats.
 * schanzen 12/2019: This _only_ makes sense if we connect to the
 * actual network as in the test we do not connect to more than 1 peer.
 * => reducing to 1 for now, was NUM_PEERS / 2
 */
#define THRESHOLD 1

/**
 * How long until we give up on connecting the peers?
 */
#define TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 60)

/*
 * Store manual connections.
 */
static unsigned int connect_left;

/*
 * Result of the testcase.
 */
static int result;

/*
 * Peers that reached the threshold of connections.
 */
static int checked_peers;

/*
 * Testbed operations.
 */
struct GNUNET_TESTBED_Operation *op[NUM_PEERS];

/*
 * Timeout for testcase.
 */
static struct GNUNET_SCHEDULER_Task *timeout_tid;

/*
 * Peer context for every testbed peer.
 */
struct peerctx
{
  int index;
  struct GNUNET_STATISTICS_Handle *statistics;
  int connections;
  int reported; /* GNUNET_NO | GNUNET_YES */
};


static void
shutdown_task (void *cls)
{
  unsigned int i;

  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "Shutting down testcase\n");

  for (i = 0; i < NUM_PEERS; i++)
  {
    if (NULL != op[i])
      GNUNET_TESTBED_operation_done (op[i]);
  }

  if (NULL != timeout_tid)
    GNUNET_SCHEDULER_cancel (timeout_tid);
}


static void
timeout_task (void *cls)
{
  timeout_tid = NULL;
  GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
              "Testcase timeout\n");

  result = GNUNET_SYSERR;
  GNUNET_SCHEDULER_shutdown ();
}


/*
 * The function is called every time the topology of connected
 * peers to a peer changes.
 */
int
statistics_iterator (void *cls,
                     const char *subsystem,
                     const char *name,
                     uint64_t value,
                     int is_persistent)
{
  struct peerctx *p_ctx = (struct peerctx*) cls;

  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "Peer %d: %s = %llu\n",
              p_ctx->index,
              name,
              (unsigned long long) value);

  if (p_ctx->connections < value)
    p_ctx->connections = value;

  if ((THRESHOLD <= value) && (GNUNET_NO == p_ctx->reported))
  {
    p_ctx->reported = GNUNET_YES;
    checked_peers++;
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                "Peer %d successfully connected to at least %d peers once.\n",
                p_ctx->index,
                THRESHOLD);

    if (checked_peers == NUM_PEERS)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                  "Test OK: All peers have connected to %d peers once.\n",
                  THRESHOLD);
      result = GNUNET_YES;
      GNUNET_SCHEDULER_shutdown ();
    }
  }

  return GNUNET_YES;
}


static void *
ca_statistics (void *cls,
               const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  return GNUNET_STATISTICS_create ("topology", cfg);
}


void
da_statistics (void *cls,
               void *op_result)
{
  struct peerctx *p_ctx = (struct peerctx *) cls;

  GNUNET_break (GNUNET_OK == GNUNET_STATISTICS_watch_cancel
                  (p_ctx->statistics, "topology", "# peers connected",
                  statistics_iterator, p_ctx));

  GNUNET_STATISTICS_destroy (p_ctx->statistics, GNUNET_NO);
  p_ctx->statistics = NULL;

  GNUNET_free (p_ctx);
}


static void
service_connect_complete (void *cls,
                          struct GNUNET_TESTBED_Operation *op,
                          void *ca_result,
                          const char *emsg)
{
  int ret;
  struct peerctx *p_ctx = (struct peerctx*) cls;

  if (NULL == ca_result)
    GNUNET_SCHEDULER_shutdown ();

  p_ctx->statistics = ca_result;

  ret = GNUNET_STATISTICS_watch (ca_result,
                                 "topology",
                                 "# peers connected",
                                 statistics_iterator,
                                 p_ctx);

  if (GNUNET_NO == ret)
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                "call to GNUNET_STATISTICS_watch() failed\n");
}


static void
notify_connect_complete (void *cls,
                         struct GNUNET_TESTBED_Operation *op,
                         const char *emsg)
{
  GNUNET_TESTBED_operation_done (op);
  if (NULL != emsg)
  {
    fprintf (stderr, "Failed to connect two peers: %s\n", emsg);
    result = GNUNET_SYSERR;
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  connect_left--;
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
  struct peerctx *p_ctx;

  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "Threshold is set to %d.\n",
              THRESHOLD);

  GNUNET_assert (NUM_PEERS == num_peers);

  for (i = 0; i < NUM_PEERS; i++)
  {
    p_ctx = GNUNET_new (struct peerctx);
    p_ctx->index = i;
    p_ctx->connections = 0;
    p_ctx->reported = GNUNET_NO;

    if (i < NUM_PEERS - 1)
    {
      connect_left++;
      GNUNET_TESTBED_overlay_connect (NULL,
                                      &notify_connect_complete, NULL,
                                      peers[i], peers[i + 1]);
    }

    op[i] =
      GNUNET_TESTBED_service_connect (cls,
                                      peers[i],
                                      "statistics",
                                      service_connect_complete,
                                      p_ctx,   /* cls of completion cb */
                                      ca_statistics,   /* connect adapter */
                                      da_statistics,   /* disconnect adapter */
                                      p_ctx);
  }

  GNUNET_SCHEDULER_add_shutdown (&shutdown_task, NULL);
  timeout_tid =
    GNUNET_SCHEDULER_add_delayed (TIMEOUT,
                                  &timeout_task,
                                  NULL);
}


int
main (int argc, char *argv[])
{
  result = GNUNET_SYSERR;
  checked_peers = 0;

  (void) GNUNET_TESTBED_test_run ("test-gnunet-daemon-topology",
                                  "test_gnunet_daemon_topology_data.conf",
                                  NUM_PEERS,
                                  0, NULL, NULL,
                                  &do_connect, NULL);
  GNUNET_DISK_directory_remove ("/tmp/test-gnunet-topology");

  return (GNUNET_OK != result) ? 1 : 0;
}


/* end of test_gnunet_daemon_topology.c */

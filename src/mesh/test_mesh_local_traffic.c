/*
     This file is part of GNUnet.
     (C) 2012 Christian Grothoff (and other contributing authors)

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
 * @file mesh/test_mesh_local_traffic.c
 * @brief test mesh local traffic: test of tunnels with just one peer
 * @author Bartlomiej Polot
 */

#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_mesh_service.h"
#include "gnunet_testing_lib-new.h"
#include <gauger.h>

#define TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 5)

#define TARGET 100


static struct GNUNET_MESH_Handle *mesh_peer_1;

static struct GNUNET_MESH_Handle *mesh_peer_2;

static struct GNUNET_MESH_Tunnel *t;

static unsigned int one = 1;

static unsigned int two = 2;

static int result = GNUNET_SYSERR;

static unsigned int sent = 0;

static unsigned int got = 0;

static GNUNET_SCHEDULER_TaskIdentifier abort_task;

static GNUNET_SCHEDULER_TaskIdentifier shutdown_task;

static struct GNUNET_TIME_Absolute start_time;

static struct GNUNET_TIME_Absolute end_time;

static struct GNUNET_PeerIdentity peer_id;


/**
 * Shutdown nicely
 */
static void
do_shutdown (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "shutdown\n");
  if (0 != abort_task)
  {
    GNUNET_SCHEDULER_cancel (abort_task);
  }
  if (NULL != t)
  {
    GNUNET_MESH_tunnel_destroy(t);
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "D1\n");
  if (NULL != mesh_peer_1)
  {
    GNUNET_MESH_disconnect (mesh_peer_1);
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "D2\n");
  if (NULL != mesh_peer_2)
  {
    GNUNET_MESH_disconnect (mesh_peer_2);
  }
}


/**
 * Something went wrong and timed out. Kill everything and set error flag
 */
static void
do_abort (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  GNUNET_log (GNUNET_ERROR_TYPE_WARNING, "ABORT\n");
  result = GNUNET_SYSERR;
  abort_task = 0;
  if (GNUNET_SCHEDULER_NO_TASK != shutdown_task)
  {
    GNUNET_SCHEDULER_cancel (shutdown_task);
    shutdown_task = GNUNET_SCHEDULER_NO_TASK;
  }
  do_shutdown (cls, tc);
}

static void
finish(void)
{
  if (GNUNET_SCHEDULER_NO_TASK != shutdown_task)
    GNUNET_SCHEDULER_cancel(shutdown_task);
  shutdown_task =  GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_SECONDS,
                                                 &do_shutdown, NULL);
}


/**
 * Function is called whenever a message is received.
 *
 * @param cls closure (set from GNUNET_MESH_connect)
 * @param tunnel connection to the other end
 * @param tunnel_ctx place to store local state associated with the tunnel
 * @param sender who sent the message
 * @param message the actual message
 * @param atsi performance data for the connection
 * @return GNUNET_OK to keep the connection open,
 *         GNUNET_SYSERR to close it (signal serious error)
 */
static int
data_callback (void *cls, struct GNUNET_MESH_Tunnel *tunnel, void **tunnel_ctx,
               const struct GNUNET_PeerIdentity *sender,
               const struct GNUNET_MessageHeader *message,
               const struct GNUNET_ATS_Information *atsi)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Data callback\n");
  got++;
  if (TARGET == got)
  {
    end_time = GNUNET_TIME_absolute_get();
    result = GNUNET_OK;
    finish();
    return GNUNET_OK;
  }
  if (GNUNET_SCHEDULER_NO_TASK != shutdown_task)
    GNUNET_SCHEDULER_cancel (shutdown_task);
  shutdown_task =
    GNUNET_SCHEDULER_add_delayed (TIMEOUT, &do_shutdown,
                                  NULL);
  return GNUNET_OK;
}


/**
 * Method called whenever another peer has added us to a tunnel
 * the other peer initiated.
 *
 * @param cls closure
 * @param tunnel new handle to the tunnel
 * @param initiator peer that started the tunnel
 * @param atsi performance information for the tunnel
 * @return initial tunnel context for the tunnel (can be NULL -- that's not an error)
 */
static void *
inbound_tunnel (void *cls, struct GNUNET_MESH_Tunnel *tunnel,
                const struct GNUNET_PeerIdentity *initiator,
                const struct GNUNET_ATS_Information *atsi)
{
  unsigned int id = *(unsigned int *) cls;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "received incoming tunnel\n");
  if (id != 1)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "received incoming tunnel on peer 2\n");
    result = GNUNET_SYSERR;
  }
  return NULL;
}


/**
 * Function called whenever an inbound tunnel is destroyed.  Should clean up
 * any associated state.
 *
 * @param cls closure (set from GNUNET_MESH_connect)
 * @param tunnel connection to the other end (henceforth invalid)
 * @param tunnel_ctx place where local state associated
 *                   with the tunnel is stored
 */
static void
inbound_end (void *cls, const struct GNUNET_MESH_Tunnel *tunnel,
             void *tunnel_ctx)
{
  unsigned int id = *(unsigned int *) cls;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "incoming tunnel closed\n");
  if (id != 1)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "received closing tunnel on peer 2\n");
    result = GNUNET_SYSERR;
  }
}


/**
 * Transmit ready callback.
 * 
 * @param cls Closure.
 * @param size Buffer size.
 * @param buf Buffer.
 */
static size_t
tmt_rdy (void *cls, size_t size, void *buf)
{
  struct GNUNET_MessageHeader *m = buf;
  size_t msize = sizeof (struct GNUNET_MessageHeader);

  if (0 == size || NULL == buf)
    return 0;
  GNUNET_assert (size >= msize);
  sent++;
  if (TARGET > sent)
    GNUNET_MESH_notify_transmit_ready (t, GNUNET_NO,
                                       GNUNET_TIME_UNIT_FOREVER_REL,
                                       &peer_id, msize, &tmt_rdy, NULL);
  m->size = htons (msize);
  m->type = htons (1);
  return msize;
}


/**
 * Method called whenever a peer has connected to the tunnel.
 *
 * @param cls Closure.
 * @param peer Peer identity of connected peer.
 */
static void
peer_connected (void *cls, const struct GNUNET_PeerIdentity *peer,
               const struct GNUNET_ATS_Information *atsi)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "peer connected\n");
  peer_id = *peer;
  start_time = GNUNET_TIME_absolute_get();
  GNUNET_MESH_notify_transmit_ready (t, GNUNET_NO, GNUNET_TIME_UNIT_FOREVER_REL,
                                     peer, sizeof (struct GNUNET_MessageHeader),
                                     &tmt_rdy, NULL);
}


/**
 * Method called whenever a peer has connected to the tunnel.
 *
 * @param cls closure
 * @param peer peer identity the tunnel was created to, NULL on timeout
 * @param atsi performance data for the connection
 */
static void
peer_disconnected (void *cls, const struct GNUNET_PeerIdentity *peer)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "peer disconnected\n");
}


/**
 * Handler array for traffic received on peer1
 */
static struct GNUNET_MESH_MessageHandler handlers1[] = {
  {&data_callback, 1, 0},
  {NULL, 0, 0}
};


/**
 * Handler array for traffic received on peer2 (none expected)
 */
static struct GNUNET_MESH_MessageHandler handlers2[] = { {NULL, 0, 0} };


/**
 * Initialize framework and start test
 */
static void
run (void *cls, 
     const struct GNUNET_CONFIGURATION_Handle *cfg,
     struct GNUNET_TESTING_Peer *peer)
{
  static const GNUNET_MESH_ApplicationType app1[] = { 1, 0 };
  static const GNUNET_MESH_ApplicationType app2[] = { 0 };

  abort_task =
      GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_relative_multiply
                                    (GNUNET_TIME_UNIT_SECONDS, 20), &do_abort,
                                    NULL);
  mesh_peer_1 = GNUNET_MESH_connect (cfg,       /* configuration */
                                     (void *) &one,     /* cls */
                                     &inbound_tunnel,   /* inbound new hndlr */
                                     &inbound_end,      /* inbound end hndlr */
                                     handlers1, /* traffic handlers */
                                     app1);     /* apps offered */

  mesh_peer_2 = GNUNET_MESH_connect (cfg,       /* configuration */
                                     (void *) &two,     /* cls */
                                     NULL,   /* inbound new hndlr */
                                     NULL,      /* inbound end hndlr */
                                     handlers2, /* traffic handlers */
                                     app2);     /* apps offered */
  if (NULL == mesh_peer_1 || NULL == mesh_peer_2)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Couldn't connect to mesh\n");
    result = GNUNET_SYSERR;
    return;
  }
  else
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Connected to mesh\n");
  }
  t = GNUNET_MESH_tunnel_create (mesh_peer_2, NULL, &peer_connected,
                                 &peer_disconnected, (void *) &two);
  GNUNET_MESH_peer_request_connect_by_type (t, 1);
}


/**
 * Main
 */
int
main (int argc, char *argv[])
{
  if (0 != GNUNET_TESTING_peer_run ("test-mesh-local-traffic",
				    "test_mesh.conf",
				    &run, NULL))
    return 1;
  if (result != GNUNET_OK)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Failed. Sent: %u, Got: %u\n",
                sent, got);
    return 1;
  }
  else
  {
    struct GNUNET_TIME_Relative total_time;

    total_time = GNUNET_TIME_absolute_get_difference(start_time, end_time);
    FPRINTF (stderr, "\nTest time %llu ms\n",
             (unsigned long long) total_time.rel_value);
    FPRINTF (stderr, "Test bandwidth: %f kb/s\n",
             4 * 1000.0 / total_time.rel_value); // 4bytes * ms
    FPRINTF (stderr, "Test throughput: %f packets/s\n\n",
             TARGET * 1000.0 / total_time.rel_value); // 1000 packets * ms
    GAUGER ("MESH", "Local traffic default", TARGET * 1000.0 / total_time.rel_value,
            "packets/s");
  }
  return 0;
}

/* end of test_mesh_local_traffic.c */

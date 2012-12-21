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
 * @file mesh/test_mesh_local_1.c
 * @brief test mesh local: test of tunnels with just one peer
 * @author Bartlomiej Polot
 */

#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_dht_service.h"
#include "gnunet_testing_lib.h"
#include "gnunet_mesh_service.h"


static struct GNUNET_MESH_Handle *mesh_peer_1;

static struct GNUNET_MESH_Handle *mesh_peer_2;

static struct GNUNET_MESH_Tunnel *t;

static unsigned int one = 1;

static unsigned int two = 2;

static int result = GNUNET_OK;

static GNUNET_SCHEDULER_TaskIdentifier abort_task;

static GNUNET_SCHEDULER_TaskIdentifier shutdown_task;


/**
 * Shutdown nicely
 */
static void
do_shutdown (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "test: shutdown\n");
  if (0 != abort_task)
  {
    GNUNET_SCHEDULER_cancel (abort_task);
  }
  if (NULL != t)
  {
    GNUNET_MESH_tunnel_destroy(t);
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "test: D1\n");
  if (NULL != mesh_peer_1)
  {
    GNUNET_MESH_disconnect (mesh_peer_1);
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "test: D2\n");
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
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "test: ABORT\n");
  result = GNUNET_SYSERR;
  abort_task = 0;
  if (GNUNET_SCHEDULER_NO_TASK != shutdown_task)
  {
    GNUNET_SCHEDULER_cancel (shutdown_task);
    shutdown_task = GNUNET_SCHEDULER_NO_TASK;
  }
  do_shutdown (cls, tc);
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
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "test: Data callback\n");
  if (GNUNET_SCHEDULER_NO_TASK != shutdown_task)
    GNUNET_SCHEDULER_cancel (shutdown_task);
  shutdown_task =
    GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_relative_multiply
                                  (GNUNET_TIME_UNIT_SECONDS, 2), &do_shutdown,
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

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "test: received incoming tunnel\n");
  if (id != 1)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "test: received incoming tunnel on peer 2\n");
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

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "test: incoming tunnel closed\n");
  if (id != 1)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "test: received closing tunnel on peer 2\n");
    result = GNUNET_SYSERR;
  }
}


/**
 * Method called whenever a peer has connected to the tunnel.
 *
 * @param cls closure
 * @param peer peer identity the tunnel stopped working with
 */
static void
peer_conected (void *cls, const struct GNUNET_PeerIdentity *peer,
               const struct GNUNET_ATS_Information *atsi)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "test: peer connected\n");
  if (GNUNET_SCHEDULER_NO_TASK != shutdown_task)
    GNUNET_SCHEDULER_cancel(shutdown_task);
  shutdown_task =  GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_SECONDS,
                                                 &do_shutdown, NULL);
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
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "test: peer disconnected\n");
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
 * Start looking for a peer by type
 */
static void
do_find (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "test: CONNECT BY TYPE\n");
  GNUNET_MESH_peer_request_connect_by_type (t, 1);
}


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
                                     &inbound_tunnel,   /* inbound new hndlr */
                                     &inbound_end,      /* inbound end hndlr */
                                     handlers2, /* traffic handlers */
                                     app2);     /* apps offered */
  if (NULL == mesh_peer_1 || NULL == mesh_peer_2)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "test: Couldn't connect to mesh :(\n");
    result = GNUNET_SYSERR;
    return;
  }
  else
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "test: YAY! CONNECTED TO MESH :D\n");
  }
  t = GNUNET_MESH_tunnel_create (mesh_peer_2, NULL, &peer_conected,
                                 &peer_disconnected, (void *) &two);
  GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_SECONDS, &do_find, NULL);
}


/**
 * Main
 */
int
main (int argc, char *argv[])
{
  if (0 != GNUNET_TESTING_peer_run ("test-mesh-local-1",
				    "test_mesh.conf",
				    &run, NULL))
    return 1;
  return (result == GNUNET_OK) ? 0 : 1;
}

/* end of test_mesh_local_1.c */

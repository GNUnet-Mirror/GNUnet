/*
      This file is part of GNUnet
      (C) 2012 Christian Grothoff (and other contributing authors)

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
 * @file consensus/gnunet-service-consensus.c
 * @brief 
 * @author Florian Dold
 */

#include "platform.h"
#include "gnunet_common.h"
#include "gnunet_protocols.h"
#include "gnunet_applications.h"
#include "gnunet_util_lib.h"
#include "gnunet_consensus_service.h"
#include "gnunet_core_service.h"
#include "gnunet_mesh_service.h"
#include "consensus.h"


struct ConsensusSession;

static void
send_next (struct ConsensusSession *session);


/**
 * An element that is waiting to be transmitted to a client.
 */
struct PendingElement
{
  /**
   * Pending elements are kept in a DLL.
   */
  struct PendingElement *next;

  /**
   * Pending elements are kept in a DLL.
   */
  struct PendingElement *prev;

  /**
   * The actual element
   */
  struct GNUNET_CONSENSUS_Element *element;
};


/*
 * A peer that is also in a consensus session.
 * Note that 'this' peer is not in the list.
 */
struct ConsensusPeer
{
  struct GNUNET_PeerIdentity *peer_id;

  /**
   * Incoming tunnel from the peer.
   */
  struct GNUNET_MESH_Tunnel *incoming_tunnel;

  struct InvertibleBloomFilter *last_ibf;

};


/**
 * A consensus session consists of one local client and the remote authorities.
 */
struct ConsensusSession
{
  /**
   * Consensus sessions are kept in a DLL.
   */
  struct ConsensusSession *next;

  /**
   * Consensus sessions are kept in a DLL.
   */
  struct ConsensusSession *prev;

  /**
   * Local consensus identification, chosen by clients.
   */
  struct GNUNET_HashCode *local_id;
 
  /**
  * Global consensus identification, computed
  * from the local id and participating authorities.
  */
  struct GNUNET_HashCode *global_id;

  /**
   * Local client in this consensus session.
   * There is only one client per consensus session.
   */
  struct GNUNET_SERVER_Client *client;

  /**
   * Values in the consensus set of this session,
   * all of them either have been sent by or approved by the client.
   */
  struct GNUNET_CONTAINER_MultiHashMap *values;

  /**
   * Elements that have not been sent to the client yet.
   */
  struct PendingElement *transmit_pending_head;

  /**
   * Elements that have not been sent to the client yet.
   */
  struct PendingElement *transmit_pending_tail;

  /**
   * Elements that have not been approved (or rejected) by the client yet.
   */
  struct PendingElement *approval_pending_head;

  /**
   * Elements that have not been approved (or rejected) by the client yet.
   */
  struct PendingElement *approval_pending_tail;

  /**
   * Currently active transmit handle for sending to the client
   */
  struct GNUNET_SERVER_TransmitHandle *th;

  /**
   * Once conclude_requested is GNUNET_YES, the client may not
   * insert any more values.
   */
  int conclude_requested;

  /**
   * Client has been informed about the conclusion.
   */
  int conclude_sent;

  /**
   * Minimum number of peers to form a consensus group
   */
  int conclude_group_min;

  /**
   * Current round of the conclusion
   */
  int current_round;

  /**
   * Soft deadline for conclude.
   * Speed up the speed of the consensus at the cost of consensus quality, as
   * the time approached or crosses the deadline.
   */
  struct GNUNET_TIME_Absolute conclude_deadline;

  /**
   * Number of other peers in the consensus
   */
  unsigned int num_peers;

  /**
   * Other peers in the consensus, array of ConsensusPeer
   */
  struct ConsensusPeer *peers;

  /**
   * Tunnel for broadcasting to all other authorities
   */
  struct GNUNET_MESH_Tunnel *broadcast_tunnel;

  /**
   * Time limit for one round of pairwise exchange.
   * FIXME: should not actually be a constant
   */
  struct GNUNET_TIME_Relative round_time;

  /**
   * Task identifier for the round timeout task
   */
  GNUNET_SCHEDULER_TaskIdentifier round_timeout_tid;
};


/**
 * Linked list of sesstions this peer participates in.
 */
static struct ConsensusSession *sessions_head;

/**
 * Linked list of sesstions this peer participates in.
 */
static struct ConsensusSession *sessions_tail;

/**
 * Configuration of the consensus service.
 */
static const struct GNUNET_CONFIGURATION_Handle *cfg;

/**
 * Handle to the server for this service.
 */
static struct GNUNET_SERVER_Handle *srv;

/**
 * Peer that runs this service
 */
static struct GNUNET_PeerIdentity *my_peer;

/**
 * Handle to the mesh service.
 */
static struct GNUNET_MESH_Handle *mesh;

/**
 * Handle to the core service. Only used during service startup, will be NULL after that.
 */
static struct GNUNET_CORE_Handle *core;

static void
disconnect_client (struct GNUNET_SERVER_Client *client)
{
  GNUNET_SERVER_client_disconnect (client);
  /* FIXME: free data structures that this client owns */
}

static void
compute_global_id (struct GNUNET_HashCode *dst,
                   const struct GNUNET_HashCode *local_id,
                   const struct GNUNET_PeerIdentity *peers,
                   int num_peers)
{
  int i;
  struct GNUNET_HashCode tmp;

  *dst = *local_id;
  for (i = 0; i < num_peers; ++i)
  {
    GNUNET_CRYPTO_hash_xor (dst, &peers[0].hashPubKey, &tmp);
    *dst = tmp;
    GNUNET_CRYPTO_hash (dst, sizeof (struct GNUNET_PeerIdentity), &tmp);
    *dst = tmp;
  }
}


static size_t
transmit_pending (void *cls, size_t size, void *buf)
{
  struct GNUNET_CONSENSUS_Element *element;
  struct GNUNET_CONSENSUS_ElementMessage *msg;
  struct ConsensusSession *session;

  session = (struct ConsensusSession *) cls;
  msg = (struct GNUNET_CONSENSUS_ElementMessage *) buf;
  element = session->transmit_pending_head->element;

  GNUNET_assert (NULL != element);

  session->th = NULL;

  msg->element_type = element->type;
  msg->header.type = htons (GNUNET_MESSAGE_TYPE_CONSENSUS_CLIENT_RECEIVED_ELEMENT);
  msg->header.size = htons (sizeof (struct GNUNET_CONSENSUS_ElementMessage) + element->size);
  memcpy (&msg[1], element->data, element->size);

  session->transmit_pending_head = session->transmit_pending_head->next;

  send_next (session);

  return sizeof (struct GNUNET_CONSENSUS_ElementMessage) + element->size;
}


static size_t
transmit_conclude_done (void *cls, size_t size, void *buf)
{
  struct GNUNET_CONSENSUS_ConcludeDoneMessage *msg;

  msg = (struct GNUNET_CONSENSUS_ConcludeDoneMessage *) buf;
  msg->header.type = htons (GNUNET_MESSAGE_TYPE_CONSENSUS_CLIENT_CONCLUDE_DONE);
  msg->header.size = htons (sizeof (struct GNUNET_CONSENSUS_ConcludeDoneMessage));
  msg->num_peers = htons (0);

  return sizeof (struct GNUNET_CONSENSUS_ConcludeDoneMessage);
}


/**
 * Schedule sending the next message (if there is any) to a client.
 *
 * @param cli the client to send the next message to
 */
static void
send_next (struct ConsensusSession *session)
{
  int msize;

  GNUNET_assert (NULL != session);

  if (NULL != session->th)
  {
    return;
  }

  if ((session->conclude_requested == GNUNET_YES) && (session->conclude_sent == GNUNET_NO))
  {
    /* FIXME */
    msize = sizeof (struct GNUNET_CONSENSUS_ConcludeMessage);
    session->th =
        GNUNET_SERVER_notify_transmit_ready (session->client, msize,
                                             GNUNET_TIME_UNIT_FOREVER_REL, &transmit_conclude_done, session);
    session->conclude_sent = GNUNET_YES;
  }
  else if (NULL != session->transmit_pending_head)
  {
    msize = session->transmit_pending_head->element->size + sizeof (struct GNUNET_CONSENSUS_ElementMessage);
    session->th =
        GNUNET_SERVER_notify_transmit_ready (session->client, msize,
                                             GNUNET_TIME_UNIT_FOREVER_REL, &transmit_pending, session);
    /* TODO: insert into ack pending */
  }
}


/**
 * Method called whenever a peer has disconnected from the tunnel.
 * Implementations of this callback must NOT call
 * GNUNET_MESH_tunnel_destroy immediately, but instead schedule those
 * to run in some other task later.  However, calling 
 * "GNUNET_MESH_notify_transmit_ready_cancel" is allowed.
 *
 * @param cls closure
 * @param peer peer identity the tunnel stopped working with
 */
static void
disconnect_handler (void *cls, const struct GNUNET_PeerIdentity *peer)
{
  /* FIXME: how do we handle this */
}


/**
 * Method called whenever a peer has connected to the tunnel.
 *
 * @param cls closure
 * @param peer peer identity the tunnel was created to, NULL on timeout
 * @param atsi performance data for the connection
 */
static void
connect_handler (void *cls,
                 const struct GNUNET_PeerIdentity *peer,
                 const struct GNUNET_ATS_Information *atsi)
{
  /* not much we can do here, now we know the other peer has been added to our broadcast tunnel */
}


/**
 * Called when a client wants to join a consensus session.
 *
 * @param cls unused
 * @param client client that sent the message
 * @param m message sent by the client
 */
static void
client_join (void *cls,
             struct GNUNET_SERVER_Client *client,
             const struct GNUNET_MessageHeader *m)
{
  struct GNUNET_HashCode global_id;
  const struct GNUNET_CONSENSUS_JoinMessage *msg;
  struct ConsensusSession *session;
  unsigned int i;

  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "client joining\n");

  msg = (struct GNUNET_CONSENSUS_JoinMessage *) m;

  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "session id is %s\n", GNUNET_h2s (&msg->session_id));

  compute_global_id (&global_id, &msg->session_id, (struct GNUNET_PeerIdentity *) &m[1], msg->num_peers);

  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "computed global id is %s\n", GNUNET_h2s (&global_id));

  session = sessions_head;
  while (NULL != session)
  {
    if (client == session->client)
    {

      GNUNET_log (GNUNET_ERROR_TYPE_WARNING, "client already in session\n");
      disconnect_client (client);
      return;
    }
    if (0 == memcmp (session->global_id, &global_id, sizeof (struct GNUNET_HashCode)))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING, "session already owned by another client\n");
      disconnect_client (client);
      return;
    }
    session = session->next;
  }

  GNUNET_SERVER_client_keep (client);

  /* session does not exist yet, create it */
  session = GNUNET_malloc (sizeof (struct ConsensusSession));
  session->local_id = GNUNET_memdup (&msg->session_id, sizeof (struct GNUNET_HashCode));
  session->global_id = GNUNET_memdup (&global_id, sizeof (struct GNUNET_HashCode));
  session->values = GNUNET_CONTAINER_multihashmap_create (4, GNUNET_NO);
  session->client = client;
  /* FIXME: should not be a constant, but chosen adaptively */
  session->round_time = GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 5);

  session->broadcast_tunnel = GNUNET_MESH_tunnel_create (mesh, session, connect_handler, disconnect_handler, session);

  session->num_peers = 0;

  /* count the peers that are not the local peer */
  for (i = 0; i < msg->num_peers; i++)
  {
    struct GNUNET_PeerIdentity *peers;
    peers = (struct GNUNET_PeerIdentity *) &msg[1];
    if (0 != memcmp (&peers[i], my_peer, sizeof (struct GNUNET_PeerIdentity)))
      session->num_peers++;
  }

  session->peers = GNUNET_malloc (session->num_peers * sizeof (struct ConsensusPeer));

  /* copy the peer identities and add peers to broadcast tunnel */
  for (i = 0; i < msg->num_peers; i++)
  {
    struct GNUNET_PeerIdentity *peers;
    peers = (struct GNUNET_PeerIdentity *) &msg[1];
    if (0 != memcmp (&peers[i], my_peer, sizeof (struct GNUNET_PeerIdentity)))
    {
      *session->peers->peer_id = peers[i];
      GNUNET_MESH_peer_request_connect_add (session->broadcast_tunnel, &peers[i]);
    }
  }

  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "created new session\n");

  GNUNET_CONTAINER_DLL_insert (sessions_head, sessions_tail, session);

  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}


/**
 * Called when a client performs an insert operation.
 */
void
client_insert (void *cls,
             struct GNUNET_SERVER_Client *client,
             const struct GNUNET_MessageHeader *m)
{
  struct ConsensusSession *session;
  struct GNUNET_CONSENSUS_ElementMessage *msg;
  struct GNUNET_CONSENSUS_Element *element;
  struct GNUNET_HashCode key;
  int element_size;

  GNUNET_log(GNUNET_ERROR_TYPE_INFO, "insert\n");

  session = sessions_head;
  while (NULL != session)
  {
    if (session->client == client)
      break;
  }

  if (NULL == session)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING, "client tried to insert, but client is not in any session\n");
    GNUNET_SERVER_client_disconnect (client);
    return;
  }

  msg = (struct GNUNET_CONSENSUS_ElementMessage *) m;
  element_size = msg->header.size - sizeof (struct GNUNET_CONSENSUS_ElementMessage);

  element = GNUNET_malloc (sizeof (struct GNUNET_CONSENSUS_Element) + element_size);

  element->type = msg->element_type;
  element->size = element_size;
  memcpy (&element[1], &msg[1], element_size);
  element->data = &element[1];

  GNUNET_CRYPTO_hash (element, element_size, &key);

  GNUNET_CONTAINER_multihashmap_put (session->values, &key, element,
                                     GNUNET_CONTAINER_MULTIHASHMAPOPTION_REPLACE);

  GNUNET_SERVER_receive_done (client, GNUNET_OK);

  send_next (session);
}


/**
 * Do one round of the conclusion.
 * Start by broadcasting the set difference estimator (IBF strata).
 *
 */
void
conclude_do_round (struct ConsensusSession *session)
{
  /* FIXME */
}


/**
 * Cancel the current round if necessary, decide to run another round or
 * terminate.
 */
void
conclude_round_done (struct ConsensusSession *session)
{
  /* FIXME */
}


/**
 * Called when a client performs the conclude operation.
 */
void
client_conclude (void *cls,
             struct GNUNET_SERVER_Client *client,
             const struct GNUNET_MessageHeader *message)
{
  struct ConsensusSession *session;

  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "conclude requested\n");

  session = sessions_head;
  while ((session != NULL) && (session->client != client))
  {
    session = session->next;
  }
  if (NULL == session)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING, "client not found\n");
    GNUNET_SERVER_client_disconnect (client);
    return;
  }

  if (GNUNET_YES == session->conclude_requested)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING, "client requested conclude twice\n");
    GNUNET_SERVER_client_disconnect (client);
    return;
  }

  session->conclude_requested = GNUNET_YES;

  conclude_do_round (session);

  GNUNET_SERVER_receive_done (client, GNUNET_OK);

  send_next (session);
}


/**
 * Called when a client sends an ack
 */
void
client_ack (void *cls,
             struct GNUNET_SERVER_Client *client,
             const struct GNUNET_MessageHeader *message)
{
  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "client ack received\n");
}

/**
 * Task that disconnects from core.
 *
 * @param cls core handle
 * @param tc context information (why was this task triggered now)
 */
static void
disconnect_core (void *cls,
                 const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  GNUNET_CORE_disconnect (core);
  core = NULL;
  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "disconnected from core\n");
}


static void
core_startup (void *cls,
              struct GNUNET_CORE_Handle *core,
              const struct GNUNET_PeerIdentity *peer)
{
  static const struct GNUNET_SERVER_MessageHandler handlers[] = {
    {&client_join, NULL, GNUNET_MESSAGE_TYPE_CONSENSUS_CLIENT_JOIN, 0},
    {&client_insert, NULL, GNUNET_MESSAGE_TYPE_CONSENSUS_CLIENT_INSERT, 0},
    {&client_conclude, NULL, GNUNET_MESSAGE_TYPE_CONSENSUS_CLIENT_CONCLUDE,
        sizeof (struct GNUNET_CONSENSUS_ConcludeMessage)},
    {&client_ack, NULL, GNUNET_MESSAGE_TYPE_CONSENSUS_CLIENT_ACK,
        sizeof (struct GNUNET_CONSENSUS_AckMessage)},
    {NULL, NULL, 0, 0}
  };

  GNUNET_SERVER_add_handlers (srv, handlers);
  my_peer = GNUNET_memdup(peer, sizeof (struct GNUNET_PeerIdentity));
  /* core can't be disconnected directly in the core startup callback, schedule a task to do it! */
  GNUNET_SCHEDULER_add_now (&disconnect_core, core);
  GNUNET_log(GNUNET_ERROR_TYPE_INFO, "connected to core\n");
}



/**
 * Method called whenever another peer has added us to a tunnel
 * the other peer initiated.
 * Only called (once) upon reception of data with a message type which was
 * subscribed to in GNUNET_MESH_connect. A call to GNUNET_MESH_tunnel_destroy
 * causes te tunnel to be ignored and no further notifications are sent about
 * the same tunnel.
 *
 * @param cls closure
 * @param tunnel new handle to the tunnel
 * @param initiator peer that started the tunnel
 * @param atsi performance information for the tunnel
 * @return initial tunnel context for the tunnel
 *         (can be NULL -- that's not an error)
 */
static void *
new_tunnel (void *cls,
            struct GNUNET_MESH_Tunnel *tunnel,
            const struct GNUNET_PeerIdentity *initiator,
            const struct GNUNET_ATS_Information *atsi)
{
  /* there's nothing we can do here, as we don't have the global consensus id yet */
  return NULL;
}


/**
 * Function called whenever an inbound tunnel is destroyed.  Should clean up
 * any associated state.  This function is NOT called if the client has
 * explicitly asked for the tunnel to be destroyed using
 * GNUNET_MESH_tunnel_destroy. It must NOT call GNUNET_MESH_tunnel_destroy on
 * the tunnel.
 *
 * @param cls closure (set from GNUNET_MESH_connect)
 * @param tunnel connection to the other end (henceforth invalid)
 * @param tunnel_ctx place where local state associated
 *                   with the tunnel is stored
 */
static void
cleaner (void *cls, const struct GNUNET_MESH_Tunnel *tunnel, void *tunnel_ctx)
{
  /* FIXME: what to do here? */
}



/**
 * Called to clean up, after a shutdown has been requested.
 *
 * @param cls closure
 * @param tc context information (why was this task triggered now)
 */
static void
shutdown_task (void *cls,
               const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  /* mesh requires all the tunnels to be destroyed manually */
  while (NULL != sessions_head)
  {
    struct ConsensusSession *session;
    session = sessions_head;
    GNUNET_MESH_tunnel_destroy (sessions_head->broadcast_tunnel);
    sessions_head = sessions_head->next;
    GNUNET_free (session);
  }

  if (NULL != mesh)
  {
    GNUNET_MESH_disconnect (mesh);
    mesh = NULL;
  }
  if (NULL != core)
  {
    GNUNET_CORE_disconnect (core);
    core = NULL;
  }
}



/**
 * Functions with this signature are called whenever a message is
 * received.
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
p2p_delta_estimate (void *cls,
                    struct GNUNET_MESH_Tunnel * tunnel,
                    void **tunnel_ctx,
                    const struct GNUNET_PeerIdentity *sender,
                    const struct GNUNET_MessageHeader *message,
                    const struct GNUNET_ATS_Information *atsi)
{
  /* FIXME */
  return GNUNET_OK;
}


/**
 * Functions with this signature are called whenever a message is
 * received.
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
p2p_difference_digest (void *cls,
                       struct GNUNET_MESH_Tunnel * tunnel,
                       void **tunnel_ctx,
                       const struct GNUNET_PeerIdentity *sender,
                       const struct GNUNET_MessageHeader *message,
                       const struct GNUNET_ATS_Information *atsi)
{
  /* FIXME */
  return GNUNET_OK;
}


/**
 * Functions with this signature are called whenever a message is
 * received.
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
p2p_elements_and_requests (void *cls,
                           struct GNUNET_MESH_Tunnel * tunnel,
                           void **tunnel_ctx,
                           const struct GNUNET_PeerIdentity *sender,
                           const struct GNUNET_MessageHeader *message,
                           const struct GNUNET_ATS_Information *atsi)
{
  /* FIXME */
  return GNUNET_OK;
}


/**
 * Start processing consensus requests.
 *
 * @param cls closure
 * @param server the initialized server
 * @param c configuration to use
 */
static void
run (void *cls, struct GNUNET_SERVER_Handle *server, const struct GNUNET_CONFIGURATION_Handle *c)
{
  static const struct GNUNET_CORE_MessageHandler handlers[] = {
    {NULL, 0, 0}
  };
  static const struct GNUNET_MESH_MessageHandler mesh_handlers[] = {
    {p2p_delta_estimate, GNUNET_MESSAGE_TYPE_CONSENSUS_P2P_DELTA_ESTIMATE, 0},
    {p2p_difference_digest, GNUNET_MESSAGE_TYPE_CONSENSUS_P2P_DIFFERENCE_DIGEST, 0},
    {p2p_elements_and_requests, GNUNET_MESSAGE_TYPE_CONSENSUS_P2P_ELEMENTS_AND_REQUESTS, 0},
    {NULL, 0, 0}
  };
  static const GNUNET_MESH_ApplicationType app_types[] = { 
    GNUNET_APPLICATION_TYPE_CONSENSUS,
    GNUNET_APPLICATION_TYPE_END
  };

  GNUNET_log(GNUNET_ERROR_TYPE_INFO, "consensus running\n");

  cfg = c;
  srv = server;

  GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_FOREVER_REL, &shutdown_task, NULL);

  mesh = GNUNET_MESH_connect (cfg, NULL, new_tunnel, cleaner, mesh_handlers, app_types);
  GNUNET_assert (NULL != mesh);

  /* we have to wait for the core_startup callback before proceeding with the consensus service startup */
  core = GNUNET_CORE_connect (c, NULL, &core_startup, NULL, NULL, NULL, GNUNET_NO, NULL, GNUNET_NO, handlers);
  GNUNET_assert (NULL != core);
}


/**
 * The main function for the consensus service.
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return 0 ok, 1 on error
 */
int
main (int argc, char *const *argv)
{
  int ret;
  ret = GNUNET_SERVICE_run (argc, argv, "consensus", GNUNET_SERVICE_OPTION_NONE, &run, NULL);
  return (GNUNET_OK == ret) ? 0 : 1;
}


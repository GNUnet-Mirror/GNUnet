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


#include "platform.h"
#include "gnunet_common.h"
#include "gnunet_protocols.h"
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
   * Corresponding server handle.
   */
  struct GNUNET_SERVER_Client *client;

  /**
   * Client wants to receive and send updates.
   */
  int begin;

  /**
   * Values in the consensus set of this session,
   * all of them either have been sent or approved by the client.
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
   * Elements that have not been sent to the client yet.
   */
  struct PendingElement *approval_pending_head;

  /**
   * Elements that have not been sent to the client yet.
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
   * Number of other peers in the consensus
   */
  int num_peers;
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

static void
disconnect_client (struct GNUNET_SERVER_Client *client)
{
  /* FIXME */
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
    /* FIXME: maybe hash_xor/hash allow aliased source/target, and we can get by without tmp */
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
    /* just the conclude message with no other authorities in the dummy */
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

  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "client joining\n");

  msg = (struct GNUNET_CONSENSUS_JoinMessage *) m;

  compute_global_id (&global_id, &msg->session_id, (struct GNUNET_PeerIdentity *) &m[1], msg->num_peers);

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
  }

  GNUNET_SERVER_client_keep (client);

  /* session does not exist yet, create it */
  session = GNUNET_malloc (sizeof (struct ConsensusSession));
  session->local_id = GNUNET_memdup (&msg->session_id, sizeof (struct GNUNET_HashCode));
  session->global_id = GNUNET_memdup (&global_id, sizeof (struct GNUNET_HashCode));
  session->values = GNUNET_CONTAINER_multihashmap_create (4, GNUNET_NO);
  session->client = client;

  GNUNET_CONTAINER_DLL_insert (sessions_head, sessions_tail, session);

  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "created new session\n");

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
 * Called when a client wants to begin
 */
void
client_begin (void *cls,
             struct GNUNET_SERVER_Client *client,
             const struct GNUNET_MessageHeader *message)
{
  struct ConsensusSession *session;

  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "client requested begin\n");

  session = sessions_head;
  while (NULL != session)
  {
    if (session->client == client)
      break;
  }

  if (NULL == session)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING, "client tried to 'begin', but client is not in any session\n");
    GNUNET_SERVER_client_disconnect (client);
    return;
  }

  session->begin = GNUNET_YES;

  send_next (session);

  GNUNET_SERVER_receive_done (client, GNUNET_OK);
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

  session = sessions_head;
  while ((session != NULL) && (session->client != client))
  {
    session = session->next;
  }
  if (NULL == session)
  {
    GNUNET_SERVER_client_disconnect (client);
    return;
  }
  session->conclude_requested = GNUNET_YES;
  send_next (session);
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
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
  struct GNUNET_CORE_Handle *core;
  core = (struct GNUNET_CORE_Handle *) cls;
  GNUNET_CORE_disconnect (core);

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
    {&client_begin, NULL, GNUNET_MESSAGE_TYPE_CONSENSUS_CLIENT_BEGIN,
        sizeof (struct GNUNET_MessageHeader)},
    {&client_conclude, NULL, GNUNET_MESSAGE_TYPE_CONSENSUS_CLIENT_CONCLUDE,
        sizeof (struct GNUNET_CONSENSUS_ConcludeMessage)},
    {&client_ack, NULL, GNUNET_MESSAGE_TYPE_CONSENSUS_CLIENT_ACK,
        sizeof (struct GNUNET_CONSENSUS_AckMessage)},
    {NULL, NULL, 0, 0}
  };

  GNUNET_SERVER_add_handlers (srv, handlers);
  my_peer = GNUNET_memdup(peer, sizeof (struct GNUNET_PeerIdentity));
  GNUNET_SCHEDULER_add_now (&disconnect_core, core);
  GNUNET_log(GNUNET_ERROR_TYPE_INFO, "connected to core\n");
}


/**
 * Process consensus requests.
 *
 * @param cls closure
 * @param server the initialized server
 * @param c configuration to use
 */
static void
run (void *cls, struct GNUNET_SERVER_Handle *server, const struct GNUNET_CONFIGURATION_Handle *c)
{
  struct GNUNET_CORE_Handle *my_core;
  static const struct GNUNET_CORE_MessageHandler handlers[] = {
    {NULL, 0, 0}
  };

  GNUNET_log(GNUNET_ERROR_TYPE_INFO, "consensus  running\n");

  cfg = c;
  srv = server;
  my_core = GNUNET_CORE_connect (c, NULL, &core_startup, NULL, NULL, NULL, GNUNET_NO, NULL, GNUNET_NO, handlers);
  GNUNET_assert (NULL != my_core);
}


/**
 * The main function for the statistics service.
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return 0 ok, 1 on error
 */
int
main (int argc, char *const *argv)
{
  return (GNUNET_OK ==
          GNUNET_SERVICE_run (argc, argv, "consensus", GNUNET_SERVICE_OPTION_NONE, &run, NULL)) ? 0 : 1;
}


/*
     This file is part of GNUnet.
     Copyright (C) 

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
 * @file rps/rps_api.c
 * @brief API for rps
 * @author Julius Bünger
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "rps.h"
#include "gnunet_rps_service.h"

#include <inttypes.h>

#define LOG(kind,...) GNUNET_log_from (kind, "rps-api",__VA_ARGS__)

/**
 * Handler to handle requests from a client.
 */
struct GNUNET_RPS_Handle
{
  /**
   * The handle to the client configuration.
   */
  struct GNUNET_CONFIGURATION_Handle *cfg;

  /**
   * The connection to the client.
   */
  struct GNUNET_CLIENT_Connection *conn;

  /**
   * The message queue to the client.
   */
  struct GNUNET_MQ_Handle *mq;
};


/**
 * Handler to single requests from the client.
 */
struct GNUNET_RPS_Request_Handle
{
  /**
   * The client issuing the request.
   */
  struct GNUNET_RPS_Handle *rps_handle;

  /**
   * The id of the request.
   */
  uint32_t id;

  /**
   * The callback to be called when we receive an answer.
   */
  GNUNET_RPS_NotifyReadyCB ready_cb;

  /**
   * The closure for the callback.
   */
  void *ready_cb_cls;
};


/**
 * Array of Request_Handles.
 */
struct GNUNET_RPS_Request_Handle *req_handlers = NULL;

/**
 * Current length of req_handlers.
 */
unsigned int req_handlers_size = 0;


/**
 * Struct used to pack the callback, its closure (provided by the caller)
 * and the connection handler to the service to pass it to a callback function.
 */
struct cb_cls_pack
{
  /**
   * Callback provided by the client
   */
  GNUNET_RPS_NotifyReadyCB cb;

  /**
   * Closure provided by the client
   */
  void *cls;

  /**
   * Handle to the service connection
   */
 struct GNUNET_CLIENT_Connection *service_conn;
};


/**
 * This function is called, when the service replies to our request.
 * It calls the callback the caller gave us with the provided closure
 * and disconnects afterwards.
 *
 * @param cls the closure
 * @param message the message
 */
  static void
handle_reply (void *cls,
              const struct GNUNET_MessageHeader *message)
{
  struct GNUNET_RPS_CS_ReplyMessage *msg;
  struct GNUNET_PeerIdentity *peers;
  struct GNUNET_RPS_Request_Handle *rh;

  /* Give the peers back */
  msg = (struct GNUNET_RPS_CS_ReplyMessage *) message;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Service replied with %" PRIu32 " peers for id %" PRIu32 "\n",
       ntohl (msg->num_peers),
       ntohl (msg->id));

  peers = (struct GNUNET_PeerIdentity *) &msg[1];
  rh = &req_handlers[ntohl (msg->id)];
  rh->ready_cb((rh)->ready_cb_cls, ntohl (msg->num_peers), peers);
}

/**
 * Reconnect to the service
 */
static void
reconnect (struct GNUNET_RPS_Handle *h);


/**
 * Error handler for mq.
 *
 * This function is called whan mq encounters an error.
 * Until now mq doesn't provide useful error messages.
 *
 * @param cls the closure
 * @param error error code without specyfied meaning
 */
  static void
mq_error_handler (void *cls, enum GNUNET_MQ_Error error)
{
  struct GNUNET_RPS_Handle *h = cls;
  //TODO LOG
  LOG (GNUNET_ERROR_TYPE_WARNING, "Some problem with the message queue. error: %i\n\
       1: READ,\n\
       2: WRITE,\n\
       4: TIMEOUT\n",
       error);
  reconnect (h);
}

/**
 * Reconnect to the service
 */
static void
reconnect (struct GNUNET_RPS_Handle *h)
{
  static const struct GNUNET_MQ_MessageHandler mq_handlers[] = {
    {&handle_reply, GNUNET_MESSAGE_TYPE_RPS_CS_REPLY, 0},
    GNUNET_MQ_HANDLERS_END
  };

  if (NULL != h->mq)
    GNUNET_MQ_destroy (h->mq);
  if (NULL != h->conn)
    GNUNET_CLIENT_disconnect (h->conn);
  h->conn = GNUNET_CLIENT_connect ("rps", h->cfg);
  GNUNET_assert (NULL != h->conn);
  h->mq = GNUNET_MQ_queue_for_connection_client(h->conn,
                                                mq_handlers,
                                                mq_error_handler, // TODO implement
                                                h);
}

/**
 * Connect to the rps service
 *
 * @param cfg configuration to use
 * @return a handle to the service
 */
  struct GNUNET_RPS_Handle *
GNUNET_RPS_connect (const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  struct GNUNET_RPS_Handle *h;
  //struct GNUNET_RPS_Request_Handle *rh;

  h = GNUNET_new(struct GNUNET_RPS_Handle);
  h->cfg = GNUNET_CONFIGURATION_dup (cfg);
  reconnect (h);
  return h;
}


/**
 * Request n random peers.
 *
 * @param rps_handle handle to the rps service
 * @param num_req_peers number of peers we want to receive
 * @param ready_cb the callback called when the peers are available
 * @param cls closure given to the callback
 * @return a handle to cancel this request
 */
  struct GNUNET_RPS_Request_Handle *
GNUNET_RPS_request_peers (struct GNUNET_RPS_Handle *rps_handle,
                          uint32_t num_req_peers,
                          GNUNET_RPS_NotifyReadyCB ready_cb,
                          void *cls)
{
  struct GNUNET_RPS_Request_Handle *rh;
  struct GNUNET_MQ_Envelope *ev;
  struct GNUNET_RPS_CS_RequestMessage *msg;

  // assert func != NULL
  rh = GNUNET_new (struct GNUNET_RPS_Request_Handle);
  rh->rps_handle = rps_handle;
  rh->id = req_handlers_size; // TODO ntoh
  rh->ready_cb = ready_cb;
  rh->ready_cb_cls = cls;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Requesting %" PRIu32 " peers with id %" PRIu32 "\n",
       num_req_peers,
       rh->id);

  GNUNET_array_append (req_handlers, req_handlers_size, *rh);
  //memcpy(&req_handlers[req_handlers_size-1], rh, sizeof(struct GNUNET_RPS_Request_Handle));

  ev = GNUNET_MQ_msg (msg, GNUNET_MESSAGE_TYPE_RPS_CS_REQUEST);
  msg->num_peers = htonl (num_req_peers);
  msg->id = htonl (rh->id);
  GNUNET_MQ_send (rps_handle->mq, ev);
  return rh;
}


/**
 * Seed rps service with peerIDs.
 *
 * @param h handle to the rps service
 * @param n number of peers to seed
 * @param ids the ids of the peers seeded
 */
  void
GNUNET_RPS_seed_ids (struct GNUNET_RPS_Handle *h,
                     uint32_t n,
                     const struct GNUNET_PeerIdentity *ids)
{
  size_t size_needed;
  uint32_t num_peers_max;
  const struct GNUNET_PeerIdentity *tmp_peer_pointer;
  struct GNUNET_MQ_Envelope *ev;
  struct GNUNET_RPS_CS_SeedMessage *msg;

  unsigned int i;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Client wants to seed %" PRIu32 " peers:\n",
       n);
  for (i = 0 ; i < n ; i++)
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "%u. peer: %s\n",
         i,
         GNUNET_i2s (&ids[i]));

  /* The actual size the message occupies */
  size_needed = sizeof (struct GNUNET_RPS_CS_SeedMessage) +
    n * sizeof (struct GNUNET_PeerIdentity);
  /* The number of peers that fits in one message together with
   * the respective header */
  num_peers_max = (GNUNET_SERVER_MAX_MESSAGE_SIZE -
      sizeof (struct GNUNET_RPS_CS_SeedMessage)) /
    sizeof (struct GNUNET_PeerIdentity);
  tmp_peer_pointer = ids;

  while (GNUNET_SERVER_MAX_MESSAGE_SIZE < size_needed)
  {
    ev = GNUNET_MQ_msg_extra (msg, num_peers_max * sizeof (struct GNUNET_PeerIdentity),
        GNUNET_MESSAGE_TYPE_RPS_CS_SEED);
    msg->num_peers = htonl (num_peers_max);
    memcpy (&msg[1], tmp_peer_pointer, num_peers_max * sizeof (struct GNUNET_PeerIdentity));
    GNUNET_MQ_send (h->mq, ev);

    n -= num_peers_max;
    size_needed = sizeof (struct GNUNET_RPS_CS_SeedMessage) +
                  n * sizeof (struct GNUNET_PeerIdentity);
    /* Set pointer to beginning of next block of num_peers_max peers */
    tmp_peer_pointer = &ids[num_peers_max];
  }

  ev = GNUNET_MQ_msg_extra (msg, n * sizeof (struct GNUNET_PeerIdentity),
                            GNUNET_MESSAGE_TYPE_RPS_CS_SEED);
  msg->num_peers = htonl (n);
  memcpy (&msg[1], tmp_peer_pointer, n * sizeof (struct GNUNET_PeerIdentity));

  GNUNET_MQ_send (h->mq, ev);
}


#ifdef ENABLE_MALICIOUS
/**
 * Turn RPS service to act malicious.
 *
 * @param h handle to the rps service
 * @param type which type of malicious peer to turn to.
 *             0 Don't act malicious at all
 *             1 Try to maximise representation
 *             2 Try to partition the network
 *               (isolate one peer from the rest)
 * @param n number of @a ids
 * @param ids the ids of the malicious peers
 *            if @type is 2 the last id is the id of the
 *            peer to be isolated from the rest
 */
  void
GNUNET_RPS_act_malicious (struct GNUNET_RPS_Handle *h,
                          uint32_t type,
                          uint32_t num_peers,
                          const struct GNUNET_PeerIdentity *peer_ids,
                          const struct GNUNET_PeerIdentity *target_peer)
{
  size_t size_needed;
  uint32_t num_peers_max;
  const struct GNUNET_PeerIdentity *tmp_peer_pointer;
  struct GNUNET_MQ_Envelope *ev;
  struct GNUNET_RPS_CS_ActMaliciousMessage *msg;

  unsigned int i;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Client turns malicious (type %" PRIu32 ") with %" PRIu32 " other peers:\n",
       type,
       num_peers);
  for (i = 0 ; i < num_peers ; i++)
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "%u. peer: %s\n",
         i,
         GNUNET_i2s (&peer_ids[i]));

  /* The actual size the message would occupy */
  size_needed = sizeof (struct GNUNET_RPS_CS_SeedMessage) +
    num_peers * sizeof (struct GNUNET_PeerIdentity);
  /* The number of peers that fit in one message together with
   * the respective header */
  num_peers_max = (GNUNET_SERVER_MAX_MESSAGE_SIZE -
      sizeof (struct GNUNET_RPS_CS_SeedMessage)) /
    sizeof (struct GNUNET_PeerIdentity);
  tmp_peer_pointer = peer_ids;

  while (GNUNET_SERVER_MAX_MESSAGE_SIZE < size_needed)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Too many peers to send at once, sending %" PRIu32 " (all we can so far)\n",
         num_peers_max);
    ev = GNUNET_MQ_msg_extra (msg,
                              num_peers_max * sizeof (struct GNUNET_PeerIdentity),
                              GNUNET_MESSAGE_TYPE_RPS_ACT_MALICIOUS);
    msg->type = htonl (type);
    msg->num_peers = htonl (num_peers_max);
    if ( (2 == type) ||
         (3 == type) )
      msg->attacked_peer = peer_ids[num_peers];
    memcpy (&msg[1],
            tmp_peer_pointer,
            num_peers_max * sizeof (struct GNUNET_PeerIdentity));

    GNUNET_MQ_send (h->mq, ev);

    num_peers -= num_peers_max;
    size_needed = sizeof (struct GNUNET_RPS_CS_SeedMessage) +
                  num_peers * sizeof (struct GNUNET_PeerIdentity);
    /* Set pointer to beginning of next block of num_peers_max peers */
    tmp_peer_pointer = &peer_ids[num_peers_max];
  }

  ev = GNUNET_MQ_msg_extra (msg,
                            num_peers * sizeof (struct GNUNET_PeerIdentity),
                            GNUNET_MESSAGE_TYPE_RPS_ACT_MALICIOUS);
  msg->type = htonl (type);
  msg->num_peers = htonl (num_peers);
  if ( (2 == type) ||
       (3 == type) )
    msg->attacked_peer = *target_peer;
  memcpy (&msg[1], tmp_peer_pointer, num_peers * sizeof (struct GNUNET_PeerIdentity));

  GNUNET_MQ_send (h->mq, ev);
}
#endif /* ENABLE_MALICIOUS */


/**
 * Cancle an issued request.
 *
 * @param rh request handle of request to cancle
 */
  void
GNUNET_RPS_request_cancel (struct GNUNET_RPS_Request_Handle *rh)
{
  struct GNUNET_MQ_Envelope *ev;
  struct GNUNET_RPS_CS_RequestCancelMessage*msg;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Cancelling request with id %" PRIu32 "\n",
       rh->id);

  GNUNET_array_append (req_handlers, req_handlers_size, *rh);
  ev = GNUNET_MQ_msg (msg, GNUNET_MESSAGE_TYPE_RPS_CS_REQUEST_CANCEL);
  msg->id = htonl (rh->id);
  GNUNET_MQ_send (rh->rps_handle->mq, ev);
}


/**
 * Disconnect from the rps service
 *
 * @param h the handle to the rps service
 */
  void
GNUNET_RPS_disconnect (struct GNUNET_RPS_Handle *h)
{
  if (NULL != h->conn)
    GNUNET_CLIENT_disconnect (h->conn);
  GNUNET_CONFIGURATION_destroy (h->cfg);
  GNUNET_MQ_destroy (h->mq);
  GNUNET_free (h);
}


/* end of rps_api.c */

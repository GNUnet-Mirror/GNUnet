
/*
     This file is part of GNUnet.
     Copyright (C) 2001-2017 GNUnet e.V.

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
 * @file cadet/gnunet-service-cadet-new_connection.c
 * @brief management of CORE-level end-to-end connections; establishes
 *        end-to-end routes and transmits messages along the route
 * @author Bartlomiej Polot
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet-service-cadet-new_channel.h"
#include "gnunet-service-cadet-new_paths.h"
#include "gnunet-service-cadet-new_peer.h"
#include "gnunet-service-cadet-new_connection.h"
#include "gnunet_cadet_service.h"
#include "cadet_protocol.h"


/**
 * All the states a connection can be in.
 */
enum CadetConnectionState
{
  /**
   * Uninitialized status, we have not yet even gotten the message queue.
   */
  CADET_CONNECTION_NEW,

  /**
   * Connection create message in queue, awaiting transmission by CORE.
   */
  CADET_CONNECTION_SENDING_CREATE,

  /**
   * Connection create message sent, waiting for ACK.
   */
  CADET_CONNECTION_SENT,

  /**
   * Connection confirmed, ready to carry traffic.
   */
  CADET_CONNECTION_READY,

  /**
   * Connection to be destroyed, just waiting to empty queues.
   */
  CADET_CONNECTION_DESTROYED,

  /**
   * Connection to be destroyed because of a distant peer, same as DESTROYED.
   */
  CADET_CONNECTION_BROKEN
};


/**
 * Low-level connection to a destination.
 */
struct CadetConnection
{

  /**
   * ID of the connection.
   */
  struct GNUNET_CADET_ConnectionTunnelIdentifier cid;

  /**
   * To which peer does this connection go?
   */
  struct CadetPeer *destination;

  /**
   * Which tunnel is using this connection?
   */
  struct CadetTConnection *ct;

  /**
   * Path we are using to our destination.
   */
  struct CadetPeerPath *path;

  /**
   * Pending message, NULL if we are ready to transmit.
   */
  struct GNUNET_MQ_Envelope *env;

  /**
   * Message queue to the first hop, or NULL if we have no connection yet.
   */
  struct GNUNET_MQ_Handle *mq;

  /**
   * Handle for calling #GCP_request_mq_cancel() once we are finished.
   */
  struct GCP_MessageQueueManager *mq_man;

  /**
   * Task for connection maintenance.
   */
  struct GNUNET_SCHEDULER_Task *task;

  /**
   * Function to call once we are ready to transmit.
   */
  GNUNET_SCHEDULER_TaskCallback ready_cb;

  /**
   * Closure for @e ready_cb.
   */
  void *ready_cb_cls;

  /**
   * How long do we wait before we try again with a CREATE message?
   */
  struct GNUNET_TIME_Relative retry_delay;

  /**
   * State of the connection.
   */
  enum CadetConnectionState state;

  /**
   * Offset of our @e destination in @e path.
   */
  unsigned int off;

};


/**
 * Is the given connection currently ready for transmission?
 *
 * @param cc connection to transmit on
 * @return #GNUNET_YES if we could transmit
 */
int
GCC_is_ready (struct CadetConnection *cc)
{
  return ( (NULL != cc->mq) &&
           (CADET_CONNECTION_READY == cc->state) &&
           (NULL == cc->env) ) ? GNUNET_YES : GNUNET_NO;
}


/**
 * Destroy a connection.
 *
 * @param cc connection to destroy
 */
void
GCC_destroy (struct CadetConnection *cc)
{
  if (NULL != cc->env)
  {
    if (NULL != cc->mq)
      GNUNET_MQ_send_cancel (cc->env);
    else
      GNUNET_MQ_discard (cc->env);
    cc->env = NULL;
  }
  if ( (NULL != cc->mq) &&
       (CADET_CONNECTION_SENDING_CREATE != cc->state) )
  {
    /* Need to notify next hop that we are down. */
    struct GNUNET_MQ_Envelope *env;
    struct GNUNET_CADET_ConnectionDestroy *destroy_msg;

    env = GNUNET_MQ_msg (destroy_msg,
                         GNUNET_MESSAGE_TYPE_CADET_CONNECTION_DESTROY);
    destroy_msg->cid = cc->cid;
    GNUNET_MQ_send (cc->mq,
                    env);
  }
  cc->mq = NULL;
  GCP_request_mq_cancel (cc->mq_man);
  cc->mq_man = NULL;
  GCPP_del_connection (cc->path,
                       cc->off,
                       cc);
  GNUNET_free (cc);
}


/**
 * Expand the shorter CADET hash to a full GNUnet hash.
 *
 * @param id hash to expand
 * @return expanded hash
 * @param deprecated
 */
const struct GNUNET_HashCode *
GCC_h2hc (const struct GNUNET_CADET_Hash *id)
{
  static struct GNUNET_HashCode hc;
  char *ptr = (char *) &hc;

  GNUNET_assert (sizeof (hc) == 2 * sizeof (*id));
  GNUNET_memcpy (ptr,
                 id,
                 sizeof (*id));
  GNUNET_memcpy (&ptr[sizeof (*id)],
                 id,
                 sizeof (*id));
  return &hc;
}


/**
 * Get the connection ID as a full hash.
 *
 * @param cc Connection to get the ID from.
 * @return full hash ID of the connection.
 */
const struct GNUNET_HashCode *
GCC_get_h (const struct CadetConnection *cc)
{
  return GCC_h2hc (&cc->cid.connection_of_tunnel);
}


/**
 * Return the tunnel associated with this connection.
 *
 * @param cc connection to query
 * @return corresponding entry in the tunnel's connection list
 */
struct CadetTConnection *
GCC_get_ct (struct CadetConnection *cc)
{
  return cc->ct;
}


/**
 * A connection ACK was received for this connection, implying
 * that the end-to-end connection is up.  Process it.
 *
 * @param cc the connection that got the ACK.
 */
void
GCC_handle_connection_ack (struct CadetConnection *cc)
{
  GNUNET_SCHEDULER_cancel (cc->task);
#if FIXME
  cc->task = GNUNET_SCHEDULER_add_delayed (cc->keepalive_period,
                                           &send_keepalive,
                                           cc);
#endif
  cc->state = CADET_CONNECTION_READY;
  cc->ready_cb (cc->ready_cb_cls);
}


/**
 * Handle KX message.
 *
 * @param cc connection that received encrypted message
 * @param msg the key exchange message
 */
void
GCC_handle_kx (struct CadetConnection *cc,
               const struct GNUNET_CADET_KX *msg)
{
  GNUNET_assert (0); // FIXME: not implemented
}


/**
 * Handle encrypted message.
 *
 * @param cc connection that received encrypted message
 * @param msg the encrypted message to decrypt
 */
void
GCC_handle_encrypted (struct CadetConnection *cc,
                      const struct GNUNET_CADET_Encrypted *msg)
{
  GNUNET_assert (0); // FIXME: not implemented
}


/**
 * Send a CREATE message to the first hop.
 *
 * @param cls the `struct CadetConnection` to initiate
 */
static void
send_create (void *cls);


/**
 * We finished transmission of the create message, now wait for
 * ACK or retransmit.
 *
 * @param cls the `struct CadetConnection` that sent the create message
 */
static void
transmit_create_done_cb (void *cls)
{
  struct CadetConnection *cc = cls;

  cc->state = CADET_CONNECTION_SENT;
  cc->env = NULL;
  /* FIXME: at some point, we need to reset the delay back to 0! */
  cc->retry_delay = GNUNET_TIME_STD_BACKOFF (cc->retry_delay);
  cc->task = GNUNET_SCHEDULER_add_delayed (cc->retry_delay,
                                           &send_create,
                                           cc);
}


/**
 * Send a CREATE message to the first hop.
 *
 * @param cls the `struct CadetConnection` to initiate
 */
static void
send_create (void *cls)
{
  struct CadetConnection *cc = cls;
  struct GNUNET_CADET_ConnectionCreate *create_msg;
  struct GNUNET_PeerIdentity *pids;
  struct GNUNET_MQ_Envelope *env;
  unsigned int path_length;

  cc->task = NULL;
  GNUNET_assert (NULL != cc->mq);
  path_length = GCPP_get_length (cc->path);
  env = GNUNET_MQ_msg_extra (create_msg,
                             path_length * sizeof (struct GNUNET_PeerIdentity),
                             GNUNET_MESSAGE_TYPE_CADET_CONNECTION_CREATE);
  create_msg->cid = cc->cid;
  pids = (struct GNUNET_PeerIdentity *) &create_msg[1];
  for (unsigned int i=0;i<path_length;i++)
    pids[i] = *GCP_get_id (GCPP_get_peer_at_offset (cc->path,
                                                    i));
  cc->env = env;
  GNUNET_MQ_notify_sent (env,
                         &transmit_create_done_cb,
                         cc);
  GNUNET_MQ_send (cc->mq,
                  env);
}


/**
 * There has been a change in the message queue existence for our
 * peer at the first hop.  Adjust accordingly.
 *
 * @param cls the `struct CadetConnection`
 * @param mq NULL if the CORE connection was lost, non-NULL if
 *           it became available
 */
static void
manage_first_hop_mq (void *cls,
                     struct GNUNET_MQ_Handle *mq)
{
  struct CadetConnection *cc = cls;

  if (NULL == mq)
  {
    /* Connection is down, for now... */
    cc->mq = NULL;
    if (NULL != cc->task)
    {
      GNUNET_SCHEDULER_cancel (cc->task);
      cc->task = NULL;
    }
    return;
  }

  cc->mq = mq;
  cc->state = CADET_CONNECTION_SENDING_CREATE;

  /* Now repeat sending connection creation messages
     down the path, until we get an ACK! */
  cc->task = GNUNET_SCHEDULER_add_now (&send_create,
                                       cc);
}


/**
 * Create a connection to @a destination via @a path and
 * notify @a cb whenever we are ready for more data.
 *
 * @param destination where to go
 * @param path which path to take (may not be the full path)
 * @param ct tunnel that uses the connection
 * @param ready_cb function to call when ready to transmit
 * @param ready_cb_cls closure for @a cb
 * @return handle to the connection
 */
struct CadetConnection *
GCC_create (struct CadetPeer *destination,
            struct CadetPeerPath *path,
            struct CadetTConnection *ct,
            GNUNET_SCHEDULER_TaskCallback ready_cb,
            void *ready_cb_cls)
{
  struct CadetConnection *cc;
  struct CadetPeer *first_hop;
  unsigned int off;

  off = GCPP_find_peer (path,
                        destination);
  GNUNET_assert (UINT_MAX > off);
  cc = GNUNET_new (struct CadetConnection);
  cc->ct = ct;
  GNUNET_CRYPTO_random_block (GNUNET_CRYPTO_QUALITY_NONCE,
                              &cc->cid,
                              sizeof (cc->cid));
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_CONTAINER_multihashmap_put (connections,
                                                    GCC_get_h (cc),
                                                    cc,
                                                    GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY));
  cc->ready_cb = ready_cb;
  cc->ready_cb_cls = ready_cb_cls;
  cc->path = path;
  cc->off = off;
  GCPP_add_connection (path,
                       off,
                       cc);
  for (unsigned int i=0;i<off;i++)
    GCP_add_connection (GCPP_get_peer_at_offset (path,
                                                 off),
                        cc);

  first_hop = GCPP_get_peer_at_offset (path,
                                       0);
  cc->mq_man = GCP_request_mq (first_hop,
                               &manage_first_hop_mq,
                               cc);
  return cc;
}


/**
 * We finished transmission of a message, if we are still ready, tell
 * the tunnel!
 *
 * @param cls our `struct CadetConnection`
 */
static void
transmit_done_cb (void *cls)
{
  struct CadetConnection *cc = cls;

  cc->env = NULL;
  if ( (NULL != cc->mq) &&
       (CADET_CONNECTION_READY == cc->state) )
    cc->ready_cb (cc->ready_cb_cls);
}


/**
 * Transmit message @a msg via connection @a cc.  Must only be called
 * (once) after the connection has signalled that it is ready via the
 * `ready_cb`.  Clients can also use #GCC_is_ready() to check if the
 * connection is right now ready for transmission.
 *
 * @param cc connection identification
 * @param env envelope with message to transmit
 */
void
GCC_transmit (struct CadetConnection *cc,
              struct GNUNET_MQ_Envelope *env)
{
  GNUNET_assert (NULL == cc->env);
  cc->env = env;
  GNUNET_MQ_notify_sent (env,
                         &transmit_done_cb,
                         cc);
  if ( (NULL != cc->mq) &&
       (CADET_CONNECTION_READY == cc->state) )
    GNUNET_MQ_send (cc->mq,
                    env);
}


/**
 * Obtain the path used by this connection.
 *
 * @param cc connection
 * @return path to @a cc
 */
struct CadetPeerPath *
GCC_get_path (struct CadetConnection *cc)
{
  return cc->path;
}


/**
 * Obtain unique ID for the connection.
 *
 * @param cc connection.
 * @return unique number of the connection
 */
const struct GNUNET_CADET_ConnectionTunnelIdentifier *
GCC_get_id (struct CadetConnection *cc)
{
  return &cc->cid;
}


/**
 * Log connection info.
 *
 * @param cc connection
 * @param level Debug level to use.
 */
void
GCC_debug (struct CadetConnection *cc,
           enum GNUNET_ErrorType level)
{
  GNUNET_break (0); // FIXME: implement...
}

/* end of gnunet-service-cadet-new_connection.c */


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
 *
 * TODO:
 * - Optimization: keepalive messages / timeout (timeout to be done @ peer level!)
 * - Optimization: keep performance metrics (?)
 */
#include "platform.h"
#include "gnunet-service-cadet-new_channel.h"
#include "gnunet-service-cadet-new_connection.h"
#include "gnunet-service-cadet-new_paths.h"
#include "gnunet-service-cadet-new_peer.h"
#include "gnunet-service-cadet-new_tunnels.h"
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
   * We are an inbound connection, and received a CREATE. Need to
   * send an CREATE_ACK back.
   */
  CADET_CONNECTION_CREATE_RECEIVED,

  /**
   * Connection confirmed, ready to carry traffic.
   */
  CADET_CONNECTION_READY

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
  GCC_ReadyCallback ready_cb;

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

  /**
   * Are we ready to transmit via @e mq_man right now?
   */
  int mqm_ready;

};


/**
 * Destroy a connection.
 *
 * @param cc connection to destroy
 */
void
GCC_destroy (struct CadetConnection *cc)
{
  struct GNUNET_MQ_Envelope *env = NULL;

  if (CADET_CONNECTION_SENDING_CREATE != cc->state)
  {
    struct GNUNET_CADET_ConnectionDestroyMessage *destroy_msg;

    /* Need to notify next hop that we are down. */
    env = GNUNET_MQ_msg (destroy_msg,
                         GNUNET_MESSAGE_TYPE_CADET_CONNECTION_DESTROY);
    destroy_msg->cid = cc->cid;
  }
  GCP_request_mq_cancel (cc->mq_man,
                         env);
  cc->mq_man = NULL;
  GCPP_del_connection (cc->path,
                       cc->off,
                       cc);
  GNUNET_assert (GNUNET_YES ==
                 GNUNET_CONTAINER_multishortmap_remove (connections,
                                                        &GCC_get_id (cc)->connection_of_tunnel,
                                                        cc));
  GNUNET_free (cc);
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
  if (NULL != cc->task)
  {
    GNUNET_SCHEDULER_cancel (cc->task);
    cc->task = NULL;
  }
#if FIXME_KEEPALIVE
  cc->task = GNUNET_SCHEDULER_add_delayed (cc->keepalive_period,
                                           &send_keepalive,
                                           cc);
#endif
  cc->state = CADET_CONNECTION_READY;
  if (GNUNET_YES == cc->mqm_ready)
    cc->ready_cb (cc->ready_cb_cls,
                  GNUNET_YES);
}


/**
 * Handle KX message.
 *
 * @param cc connection that received encrypted message
 * @param msg the key exchange message
 */
void
GCC_handle_kx (struct CadetConnection *cc,
               const struct GNUNET_CADET_TunnelKeyExchangeMessage *msg)
{
  if (CADET_CONNECTION_SENT == cc->state)
  {
    /* We didn't get the CREATE_ACK, but instead got payload. That's fine,
       clearly something is working, so pretend we got an ACK. */
    GCC_handle_connection_ack (cc);
  }
  GCT_handle_kx (cc->ct,
                 msg);
}


/**
 * Handle encrypted message.
 *
 * @param cc connection that received encrypted message
 * @param msg the encrypted message to decrypt
 */
void
GCC_handle_encrypted (struct CadetConnection *cc,
                      const struct GNUNET_CADET_TunnelEncryptedMessage *msg)
{
  if (CADET_CONNECTION_SENT == cc->state)
  {
    /* We didn't get the CREATE_ACK, but instead got payload. That's fine,
       clearly something is working, so pretend we got an ACK. */
    GCC_handle_connection_ack (cc);
  }
  GCT_handle_encrypted (cc->ct,
                        msg);
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
  struct GNUNET_CADET_ConnectionCreateMessage *create_msg;
  struct GNUNET_PeerIdentity *pids;
  struct GNUNET_MQ_Envelope *env;
  unsigned int path_length;

  cc->task = NULL;
  GNUNET_assert (GNUNET_YES == cc->mqm_ready);
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
  cc->mqm_ready = GNUNET_NO;
  cc->state = CADET_CONNECTION_SENT;
  GCP_send (cc->mq_man,
            env);
}


/**
 * Send a CREATE_ACK message towards the origin.
 *
 * @param cls the `struct CadetConnection` to initiate
 */
static void
send_create_ack (void *cls)
{
  struct CadetConnection *cc = cls;
  struct GNUNET_CADET_ConnectionCreateMessage *create_msg;
  struct GNUNET_PeerIdentity *pids;
  struct GNUNET_MQ_Envelope *env;
  unsigned int path_length;

  cc->task = NULL;
  GNUNET_assert (GNUNET_YES == cc->mqm_ready);
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
  cc->mqm_ready = GNUNET_NO;
  cc->state = CADET_CONNECTION_READY;
  GCP_send (cc->mq_man,
            env);
}


/**
 * We got a #GNUNET_MESSAGE_TYPE_CADET_CONNECTION_CREATE for a
 * connection that we already have.  Either our ACK got lost
 * or something is fishy.  Consider retransmitting the ACK.
 *
 * @param cc connection that got the duplicate CREATE
 */
void
GCC_handle_duplicate_create (struct CadetConnection *cc)
{
  if (GNUNET_YES == cc->mqm_ready)
  {
    /* Tell tunnel that we are not ready for transmission anymore
       (until CREATE_ACK is done) */
    cc->ready_cb (cc->ready_cb_cls,
                  GNUNET_NO);

    /* Revert back to the state of having only received the 'CREATE',
       and immediately proceed to send the CREATE_ACK. */
    cc->state = CADET_CONNECTION_CREATE_RECEIVED;
    cc->task = GNUNET_SCHEDULER_add_now (&send_create_ack,
                                         cc);
  }
  else
  {
    /* We are currently sending something else back, which
       can only be an ACK or payload, either of which would
       do. So actually no need to do anything. */
  }
}


/**
 * There has been a change in the message queue existence for our
 * peer at the first hop.  Adjust accordingly.
 *
 * @param cls the `struct CadetConnection`
 * @param available #GNUNET_YES if sending is now possible,
 *                  #GNUNET_NO if sending is no longer possible
 *                  #GNUNET_SYSERR if sending is no longer possible
 *                                 and the last envelope was discarded
 */
static void
manage_first_hop_mq (void *cls,
                     int available)
{
  struct CadetConnection *cc = cls;

  if (GNUNET_YES != available)
  {
    /* Connection is down, for now... */
    cc->mqm_ready = GNUNET_NO;
    cc->state = CADET_CONNECTION_NEW;
    cc->retry_delay = GNUNET_TIME_UNIT_ZERO;
    if (NULL != cc->task)
    {
      GNUNET_SCHEDULER_cancel (cc->task);
      cc->task = NULL;
    }
    cc->ready_cb (cc->ready_cb_cls,
                  GNUNET_NO);
    return;
  }

  cc->mqm_ready = GNUNET_YES;
  switch (cc->state)
  {
  case CADET_CONNECTION_NEW:
    /* Transmit immediately */
    cc->task = GNUNET_SCHEDULER_add_now (&send_create,
                                         cc);
    break;
  case CADET_CONNECTION_SENDING_CREATE:
    /* Should not be possible to be called in this state. */
    GNUNET_assert (0);
    break;
  case CADET_CONNECTION_SENT:
    /* Retry a bit later... */
    cc->retry_delay = GNUNET_TIME_STD_BACKOFF (cc->retry_delay);
    cc->task = GNUNET_SCHEDULER_add_delayed (cc->retry_delay,
                                             &send_create,
                                             cc);
    break;
  case CADET_CONNECTION_CREATE_RECEIVED:
    /* We got the 'CREATE' (incoming connection), should send the CREATE_ACK */
    cc->task = GNUNET_SCHEDULER_add_now (&send_create_ack,
                                         cc);
    break;
  case CADET_CONNECTION_READY:
    cc->ready_cb (cc->ready_cb_cls,
                  GNUNET_YES);
    break;
  }
}


/**
 * Create a connection to @a destination via @a path and notify @a cb
 * whenever we are ready for more data.  Shared logic independent of
 * who is initiating the connection.
 *
 * @param destination where to go
 * @param path which path to take (may not be the full path)
 * @param ct which tunnel uses this connection
 * @param init_state initial state for the connection
 * @param ready_cb function to call when ready to transmit
 * @param ready_cb_cls closure for @a cb
 * @return handle to the connection
 */
static struct CadetConnection *
connection_create (struct CadetPeer *destination,
                   struct CadetPeerPath *path,
                   struct CadetTConnection *ct,
                   const struct GNUNET_CADET_ConnectionTunnelIdentifier *cid,
                   enum CadetConnectionState init_state,
                   GCC_ReadyCallback ready_cb,
                   void *ready_cb_cls)
{
  struct CadetConnection *cc;
  struct CadetPeer *first_hop;
  unsigned int off;

  off = GCPP_find_peer (path,
                        destination);
  GNUNET_assert (UINT_MAX > off);
  cc = GNUNET_new (struct CadetConnection);
  cc->state = init_state;
  cc->ct = ct;
  cc->cid = *cid;
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_CONTAINER_multishortmap_put (connections,
                                                     &GCC_get_id (cc)->connection_of_tunnel,
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
 * Create a connection to @a destination via @a path and
 * notify @a cb whenever we are ready for more data.  This
 * is an inbound tunnel, so we must use the existing @a cid
 *
 * @param destination where to go
 * @param path which path to take (may not be the full path)
 * @param ct which tunnel uses this connection
 * @param ready_cb function to call when ready to transmit
 * @param ready_cb_cls closure for @a cb
 * @return handle to the connection
 */
struct CadetConnection *
GCC_create_inbound (struct CadetPeer *destination,
                    struct CadetPeerPath *path,
                    struct CadetTConnection *ct,
                    const struct GNUNET_CADET_ConnectionTunnelIdentifier *cid,
                    GCC_ReadyCallback ready_cb,
                    void *ready_cb_cls)
{
  return connection_create (destination,
                            path,
                            ct,
                            cid,
                            CADET_CONNECTION_CREATE_RECEIVED,
                            ready_cb,
                            ready_cb_cls);
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
            GCC_ReadyCallback ready_cb,
            void *ready_cb_cls)
{
  struct GNUNET_CADET_ConnectionTunnelIdentifier cid;

  GNUNET_CRYPTO_random_block (GNUNET_CRYPTO_QUALITY_NONCE,
                              &cid,
                              sizeof (cid));
  return connection_create (destination,
                            path,
                            ct,
                            &cid,
                            CADET_CONNECTION_NEW,
                            ready_cb,
                            ready_cb_cls);
}


/**
 * Transmit message @a msg via connection @a cc.  Must only be called
 * (once) after the connection has signalled that it is ready via the
 * `ready_cb`.  Clients can also use #GCC_is_ready() to check if the
 * connection is right now ready for transmission.
 *
 * @param cc connection identification
 * @param env envelope with message to transmit; must NOT
 *            yet have a #GNUNET_MQ_notify_sent() callback attached to it
 */
void
GCC_transmit (struct CadetConnection *cc,
              struct GNUNET_MQ_Envelope *env)
{
  GNUNET_assert (GNUNET_YES == cc->mqm_ready);
  GNUNET_assert (CADET_CONNECTION_READY == cc->state);
  cc->mqm_ready = GNUNET_NO;
  GCP_send (cc->mq_man,
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
 * Get a (static) string for a connection.
 *
 * @param cc Connection.
 */
const char *
GCC_2s (const struct CadetConnection *cc)
{
  static char buf[128];

  if (NULL == cc)
    return "Connection(NULL)";

  if (NULL != cc->ct)
  {
    GNUNET_snprintf (buf,
                     sizeof (buf),
                     "Connection(%s(Tunnel(%s)))",
                     GNUNET_sh2s (&cc->cid.connection_of_tunnel),
                     GCT_2s (cc->ct->t));
    return buf;
  }
  GNUNET_snprintf (buf,
                   sizeof (buf),
                   "Connection(%s(Tunnel(NULL)))",
                   GNUNET_sh2s (&cc->cid.connection_of_tunnel));
  return buf;
}


#define LOG2(level, ...) GNUNET_log_from_nocheck(level,"cadet-con",__VA_ARGS__)


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
  int do_log;
  char *s;

  do_log = GNUNET_get_log_call_status (level & (~GNUNET_ERROR_TYPE_BULK),
                                       "cadet-con",
                                       __FILE__, __FUNCTION__, __LINE__);
  if (0 == do_log)
    return;
  if (NULL == cc)
  {
    LOG2 (level,
          "Connection (NULL)\n");
    return;
  }
  s = GCPP_2s (cc->path);
  LOG2 (level,
        "Connection %s to %s via path %s in state %d is %s\n",
        GCC_2s (cc),
        GCP_2s (cc->destination),
        s,
        cc->state,
        (GNUNET_YES == cc->mqm_ready) ? "ready" : "busy");
  GNUNET_free (s);
}

/* end of gnunet-service-cadet-new_connection.c */

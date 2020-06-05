/*
     This file is part of GNUnet.
     Copyright (C) 2001-2017 GNUnet e.V.

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
 * @file cadet/gnunet-service-cadet_connection.c
 * @brief management of CORE-level end-to-end connections; establishes
 *        end-to-end routes and transmits messages along the route
 * @author Bartlomiej Polot
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_signatures.h"
#include "gnunet-service-cadet_connection.h"
#include "gnunet-service-cadet_channel.h"
#include "gnunet-service-cadet_paths.h"
#include "gnunet-service-cadet_tunnels.h"
#include "gnunet_cadet_service.h"
#include "gnunet_statistics_service.h"
#include "cadet_protocol.h"


#define LOG(level, ...) GNUNET_log_from (level, "cadet-con", __VA_ARGS__)


/**
 * How long do we wait initially before retransmitting the KX?
 * TODO: replace by 2 RTT if/once we have connection-level RTT data!
 */
#define INITIAL_CONNECTION_CREATE_RETRY_DELAY \
  GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MILLISECONDS, 200)


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
   * Queue entry for keepalive messages.
   */
  struct CadetTunnelQueueEntry *keepalive_qe;

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
   * Earliest time for re-trying CREATE
   */
  struct GNUNET_TIME_Absolute create_at;

  /**
   * Earliest time for re-trying CREATE_ACK
   */
  struct GNUNET_TIME_Absolute create_ack_at;

  /**
   * Performance metrics for this connection.
   */
  struct CadetConnectionMetrics metrics;

  /**
   * State of the connection.
   */
  enum CadetConnectionState state;

  /**
   * How many latency observations did we make for this connection?
   */
  unsigned int latency_datapoints;

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
 * Lookup a connection by its identifier.
 *
 * @param cid identifier to resolve
 * @return NULL if connection was not found
 */
struct CadetConnection *
GCC_lookup (const struct GNUNET_CADET_ConnectionTunnelIdentifier *cid)
{
  return GNUNET_CONTAINER_multishortmap_get (connections,
                                             &cid->connection_of_tunnel);
}


/**
 * Update the connection state. Also triggers the necessary
 * MQM notifications.
 *
 * @param cc connection to update the state for
 * @param new_state new state for @a cc
 * @param new_mqm_ready new `mqm_ready` state for @a cc
 */
static void
update_state (struct CadetConnection *cc,
              enum CadetConnectionState new_state,
              int new_mqm_ready)
{
  int old_ready;
  int new_ready;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Trying to update connection state for %s having old state %d to new %d and mqm_ready old %d to mqm_ready new %d\n",
       GCT_2s (cc->ct->t),
       cc->state,
       new_state,
       cc->mqm_ready,
       new_mqm_ready);

  if ((new_state == cc->state) && (new_mqm_ready == cc->mqm_ready))
    return; /* no change, nothing to do */
  old_ready =
    ((CADET_CONNECTION_READY == cc->state) && (GNUNET_YES == cc->mqm_ready));
  new_ready =
    ((CADET_CONNECTION_READY == new_state) && (GNUNET_YES == new_mqm_ready));
  cc->state = new_state;
  cc->mqm_ready = new_mqm_ready;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Updating connection state for %s having old_ready %d and new_rady %d\n",
       GCT_2s (cc->ct->t),
       old_ready,
       new_ready);

  if (old_ready != new_ready)
    cc->ready_cb (cc->ready_cb_cls, new_ready);
}


/**
 * Destroy a connection, part of the internal implementation.  Called
 * only from #GCC_destroy_from_core() or #GCC_destroy_from_tunnel().
 *
 * @param cc connection to destroy
 */
static void
GCC_destroy (struct CadetConnection *cc)
{
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Destroying %s\n", GCC_2s (cc));
  if (NULL != cc->mq_man)
  {
    GCP_request_mq_cancel (cc->mq_man, NULL);
    cc->mq_man = NULL;
  }
  if (NULL != cc->task)
  {
    GNUNET_SCHEDULER_cancel (cc->task);
    cc->task = NULL;
  }
  if (NULL != cc->keepalive_qe)
  {
    GCT_send_cancel (cc->keepalive_qe);
    cc->keepalive_qe = NULL;
  }
  GCPP_del_connection (cc->path, cc->off, cc);
  for (unsigned int i = 0; i < cc->off; i++)
    GCP_remove_connection (GCPP_get_peer_at_offset (cc->path, i), cc);
  GNUNET_assert (
    GNUNET_YES ==
    GNUNET_CONTAINER_multishortmap_remove (connections,
                                           &GCC_get_id (cc)
                                           ->connection_of_tunnel,
                                           cc));
  GNUNET_free (cc);
}


/**
 * Destroy a connection, called when the CORE layer is already done
 * (i.e. has received a BROKEN message), but if we still have to
 * communicate the destruction of the connection to the tunnel (if one
 * exists).
 *
 * @param cc connection to destroy
 */
void
GCC_destroy_without_core (struct CadetConnection *cc)
{
  if (NULL != cc->ct)
  {
    GCT_connection_lost (cc->ct);
    cc->ct = NULL;
  }
  GCC_destroy (cc);
}


/**
 * Destroy a connection, called if the tunnel association with the
 * connection was already broken, but we still need to notify the CORE
 * layer about the breakage.
 *
 * @param cc connection to destroy
 */
void
GCC_destroy_without_tunnel (struct CadetConnection *cc)
{
  cc->ct = NULL;
  if ((CADET_CONNECTION_SENDING_CREATE != cc->state) && (NULL != cc->mq_man))
  {
    struct GNUNET_MQ_Envelope *env;
    struct GNUNET_CADET_ConnectionDestroyMessage *destroy_msg;

    /* Need to notify next hop that we are down. */
    env =
      GNUNET_MQ_msg (destroy_msg, GNUNET_MESSAGE_TYPE_CADET_CONNECTION_DESTROY);
    destroy_msg->cid = cc->cid;
    GCP_request_mq_cancel (cc->mq_man, env);
    cc->mq_man = NULL;
  }
  GCC_destroy (cc);
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
 * Obtain performance @a metrics from @a cc.
 *
 * @param cc connection to query
 * @return the metrics
 */
const struct CadetConnectionMetrics *
GCC_get_metrics (struct CadetConnection *cc)
{
  return &cc->metrics;
}


/**
 * Send a #GNUNET_MESSAGE_TYPE_CADET_CHANNEL_KEEPALIVE through the
 * tunnel to prevent it from timing out.
 *
 * @param cls the `struct CadetConnection` to keep alive.
 */
static void
send_keepalive (void *cls);


/**
 * Keepalive was transmitted.  Remember this, and possibly
 * schedule the next one.
 *
 * @param cls the `struct CadetConnection` to keep alive.
 * @param cid identifier of the connection within the tunnel, NULL
 *            if transmission failed
 */
static void
keepalive_done (void *cls,
                const struct GNUNET_CADET_ConnectionTunnelIdentifier *cid)
{
  struct CadetConnection *cc = cls;

  cc->keepalive_qe = NULL;
  if ((GNUNET_YES == cc->mqm_ready) && (NULL == cc->task))
    cc->task =
      GNUNET_SCHEDULER_add_delayed (keepalive_period, &send_keepalive, cc);
}


/**
 * Send a #GNUNET_MESSAGE_TYPE_CADET_CHANNEL_KEEPALIVE through the
 * tunnel to prevent it from timing out.
 *
 * @param cls the `struct CadetConnection` to keep alive.
 */
static void
send_keepalive (void *cls)
{
  struct CadetConnection *cc = cls;
  struct GNUNET_MessageHeader msg;

  cc->task = NULL;
  if (CADET_TUNNEL_KEY_OK != GCT_get_estate (cc->ct->t))
  {
    /* Tunnel not yet ready, wait with keepalives... */
    cc->task =
      GNUNET_SCHEDULER_add_delayed (keepalive_period, &send_keepalive, cc);
    return;
  }
  GNUNET_assert (NULL != cc->ct);
  GNUNET_assert (GNUNET_YES == cc->mqm_ready);
  GNUNET_assert (NULL == cc->keepalive_qe);
  LOG (GNUNET_ERROR_TYPE_INFO,
       "Sending KEEPALIVE on behalf of %s via %s\n",
       GCC_2s (cc),
       GCT_2s (cc->ct->t));
  GNUNET_STATISTICS_update (stats, "# keepalives sent", 1, GNUNET_NO);
  msg.size = htons (sizeof(msg));
  msg.type = htons (GNUNET_MESSAGE_TYPE_CADET_CHANNEL_KEEPALIVE);

  cc->keepalive_qe = GCT_send (cc->ct->t, &msg, &keepalive_done, cc, NULL);
}


/**
 * We sent a message for which we expect to receive an ACK via
 * the connection identified by @a cti.
 *
 * @param cid connection identifier where we expect an ACK
 */
void
GCC_ack_expected (const struct GNUNET_CADET_ConnectionTunnelIdentifier *cid)
{
  struct CadetConnection *cc;

  cc = GCC_lookup (cid);
  if (NULL == cc)
    return; /* whopise, connection alredy down? */
  cc->metrics.num_acked_transmissions++;
}


/**
 * We observed an ACK for a message that was originally sent via
 * the connection identified by @a cti.
 *
 * @param cti connection identifier where we got an ACK for a message
 *            that was originally sent via this connection (the ACK
 *            may have gotten back to us via a different connection).
 */
void
GCC_ack_observed (const struct GNUNET_CADET_ConnectionTunnelIdentifier *cid)
{
  struct CadetConnection *cc;

  cc = GCC_lookup (cid);
  if (NULL == cc)
    return; /* whopise, connection alredy down? */
  cc->metrics.num_successes++;
}


/**
 * We observed some the given @a latency on the connection
 * identified by @a cti.  (The same connection was taken
 * in both directions.)
 *
 * @param cid connection identifier where we measured latency
 * @param latency the observed latency
 */
void
GCC_latency_observed (const struct GNUNET_CADET_ConnectionTunnelIdentifier *cid,
                      struct GNUNET_TIME_Relative latency)
{
  struct CadetConnection *cc;
  double weight;
  double result;

  cc = GCC_lookup (cid);
  if (NULL == cc)
    return; /* whopise, connection alredy down? */
  GNUNET_STATISTICS_update (stats, "# latencies observed", 1, GNUNET_NO);
  cc->latency_datapoints++;
  if (cc->latency_datapoints >= 7)
    weight = 7.0;
  else
    weight = cc->latency_datapoints;
  /* Compute weighted average, giving at MOST weight 7 to the
     existing values, or less if that value is based on fewer than 7
     measurements. */
  result = (weight * cc->metrics.aged_latency.rel_value_us)
           + 1.0 * latency.rel_value_us;
  result /= (weight + 1.0);
  cc->metrics.aged_latency.rel_value_us = (uint64_t) result;
}


/**
 * A #GNUNET_MESSAGE_TYPE_CADET_CONNECTION_CREATE_ACK was received for
 * this connection, implying that the end-to-end connection is up.
 * Process it.
 *
 * @param cc the connection that got the ACK.
 */
void
GCC_handle_connection_create_ack (struct CadetConnection *cc)
{
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Received CADET_CONNECTION_CREATE_ACK for %s in state %d (%s)\n",
       GCC_2s (cc),
       cc->state,
       (GNUNET_YES == cc->mqm_ready) ? "MQM ready" : "MQM busy");
  if (CADET_CONNECTION_READY == cc->state)
    return; /* Duplicate ACK, ignore */
  if (NULL != cc->task)
  {
    GNUNET_SCHEDULER_cancel (cc->task);
    cc->task = NULL;
  }
  cc->metrics.age = GNUNET_TIME_absolute_get ();
  update_state (cc, CADET_CONNECTION_READY, cc->mqm_ready);
  if ((NULL == cc->keepalive_qe) && (GNUNET_YES == cc->mqm_ready) &&
      (NULL == cc->task))
    cc->task =
      GNUNET_SCHEDULER_add_delayed (keepalive_period, &send_keepalive, cc);
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
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Received KX message with ephermal %s on CC %s in state %d\n",
       GNUNET_e2s (&msg->ephemeral_key),
       GNUNET_sh2s (&cc->cid.connection_of_tunnel),
       cc->state);
  if (CADET_CONNECTION_SENT == cc->state)
  {
    /* We didn't get the CADET_CONNECTION_CREATE_ACK, but instead got payload. That's fine,
       clearly something is working, so pretend we got an ACK. */
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Faking connection CADET_CONNECTION_CREATE_ACK for %s due to KX\n",
         GCC_2s (cc));
    GCC_handle_connection_create_ack (cc);
  }
  GCT_handle_kx (cc->ct, msg);
}


/**
 * Handle KX_AUTH message.
 *
 * @param cc connection that received encrypted message
 * @param msg the key exchange message
 */
void
GCC_handle_kx_auth (struct CadetConnection *cc,
                    const struct GNUNET_CADET_TunnelKeyExchangeAuthMessage *msg)
{
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Received KX AUTH message with ephermal %s on CC %s in state %d\n",
       GNUNET_e2s (&msg->kx.ephemeral_key),
       GNUNET_sh2s (&cc->cid.connection_of_tunnel),
       cc->state);
  if (CADET_CONNECTION_SENT == cc->state)
  {
    /* We didn't get the CADET_CONNECTION_CREATE_ACK, but instead got payload. That's fine,
       clearly something is working, so pretend we got an ACK. */
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Faking connection CADET_CONNECTION_CREATE_ACK for %s due to KX\n",
         GCC_2s (cc));
    GCC_handle_connection_create_ack (cc);
  }
  GCT_handle_kx_auth (cc->ct, msg);
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
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Faking connection ACK for %s due to ENCRYPTED payload\n",
         GCC_2s (cc));
    GCC_handle_connection_create_ack (cc);
  }
  cc->metrics.last_use = GNUNET_TIME_absolute_get ();
  GCT_handle_encrypted (cc->ct, msg);
}


/**
 * Set the signature for a monotime value on a GNUNET_CADET_ConnectionCreateMessage.
 *
 * @param msg The GNUNET_CADET_ConnectionCreateMessage.
 */
void
set_monotime_sig (struct GNUNET_CADET_ConnectionCreateMessage *msg)
{

  struct CadetConnectionCreatePS cp = { .purpose.purpose = htonl (
                                          GNUNET_SIGNATURE_PURPOSE_CADET_CONNECTION_INITIATOR),
                                        .purpose.size = htonl (sizeof(cp)),
                                        .monotonic_time = msg->monotime};

  GNUNET_CRYPTO_eddsa_sign (my_private_key, &cp,
                            &msg->monotime_sig);

}

/**
 * Send a #GNUNET_MESSAGE_TYPE_CADET_CONNECTION_CREATE message to the
 * first hop.
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
  struct CadetTunnel *t;

  cc->task = NULL;
  GNUNET_assert (GNUNET_YES == cc->mqm_ready);
  env =
    GNUNET_MQ_msg_extra (create_msg,
                         (2 + cc->off) * sizeof(struct GNUNET_PeerIdentity),
                         GNUNET_MESSAGE_TYPE_CADET_CONNECTION_CREATE);
  // TODO This will be removed in a major release, because this will be a protocol breaking change. We set the deprecated 'reliable' bit here that was removed.
  create_msg->options = 2;
  create_msg->cid = cc->cid;

  // check for tunnel state and set signed monotime (xrs,t3ss)
  t = GCP_get_tunnel (cc->destination, GNUNET_YES);
  if ((NULL != t)&& (GCT_get_estate (t) == CADET_TUNNEL_KEY_UNINITIALIZED) &&
      (GCT_alice_or_betty (GCP_get_id (cc->destination)) == GNUNET_NO))
  {
    create_msg->has_monotime = GNUNET_YES;
    create_msg->monotime = GNUNET_TIME_absolute_hton (
      GNUNET_TIME_absolute_get_monotonic (cfg));
    set_monotime_sig (create_msg);
  }

  pids = (struct GNUNET_PeerIdentity *) &create_msg[1];
  pids[0] = my_full_id;
  for (unsigned int i = 0; i <= cc->off; i++)
    pids[i + 1] = *GCP_get_id (GCPP_get_peer_at_offset (cc->path, i));
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Sending CADET_CONNECTION_CREATE message for %s with %u hops\n",
       GCC_2s (cc),
       cc->off + 2);
  cc->env = env;
  cc->retry_delay = GNUNET_TIME_STD_BACKOFF (cc->retry_delay);
  cc->create_at = GNUNET_TIME_relative_to_absolute (cc->retry_delay);
  update_state (cc, CADET_CONNECTION_SENT, GNUNET_NO);
  GCP_send (cc->mq_man, env);
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
  struct GNUNET_CADET_ConnectionCreateAckMessage *ack_msg;
  struct GNUNET_MQ_Envelope *env;

  cc->task = NULL;
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Sending CONNECTION_CREATE_ACK message for %s\n",
       GCC_2s (cc));
  GNUNET_assert (GNUNET_YES == cc->mqm_ready);
  env =
    GNUNET_MQ_msg (ack_msg, GNUNET_MESSAGE_TYPE_CADET_CONNECTION_CREATE_ACK);
  ack_msg->cid = cc->cid;
  cc->env = env;
  cc->retry_delay = GNUNET_TIME_STD_BACKOFF (cc->retry_delay);
  cc->create_ack_at = GNUNET_TIME_relative_to_absolute (cc->retry_delay);
  if (CADET_CONNECTION_CREATE_RECEIVED == cc->state)
    update_state (cc, CADET_CONNECTION_READY, GNUNET_NO);
  if (CADET_CONNECTION_READY == cc->state)
    cc->task =
      GNUNET_SCHEDULER_add_delayed (keepalive_period, &send_keepalive, cc);
  GCP_send (cc->mq_man, env);
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
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Got duplicate CREATE for %s, scheduling another ACK (%s)\n",
         GCC_2s (cc),
         (GNUNET_YES == cc->mqm_ready) ? "MQM ready" : "MQM busy");
    /* Revert back to the state of having only received the 'CREATE',
       and immediately proceed to send the CREATE_ACK. */
    update_state (cc, CADET_CONNECTION_CREATE_RECEIVED, cc->mqm_ready);
    if (NULL != cc->task)
      GNUNET_SCHEDULER_cancel (cc->task);
    cc->task =
      GNUNET_SCHEDULER_add_at (cc->create_ack_at, &send_create_ack, cc);
  }
  else
  {
    /* We are currently sending something else back, which
       can only be an ACK or payload, either of which would
       do. So actually no need to do anything. */
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Got duplicate CREATE for %s. MQ is busy, not queueing another ACK\n",
         GCC_2s (cc));
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
manage_first_hop_mq (void *cls, int available)
{
  struct CadetConnection *cc = cls;

  if (GNUNET_YES != available)
  {
    /* Connection is down, for now... */
    LOG (GNUNET_ERROR_TYPE_DEBUG, "Core MQ for %s went down\n", GCC_2s (cc));
    update_state (cc, CADET_CONNECTION_NEW, GNUNET_NO);
    cc->retry_delay = INITIAL_CONNECTION_CREATE_RETRY_DELAY;
    if (NULL != cc->task)
    {
      GNUNET_SCHEDULER_cancel (cc->task);
      cc->task = NULL;
    }
    return;
  }

  update_state (cc, cc->state, GNUNET_YES);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Core MQ for %s became available in state %d\n",
       GCC_2s (cc),
       cc->state);
  switch (cc->state)
  {
  case CADET_CONNECTION_NEW:
    /* Transmit immediately */
    cc->task = GNUNET_SCHEDULER_add_at (cc->create_at, &send_create, cc);
    break;

  case CADET_CONNECTION_SENDING_CREATE:
    /* Should not be possible to be called in this state. */
    GNUNET_assert (0);
    break;

  case CADET_CONNECTION_SENT:
    /* Retry a bit later... */
    cc->task = GNUNET_SCHEDULER_add_at (cc->create_at, &send_create, cc);
    break;

  case CADET_CONNECTION_CREATE_RECEIVED:
    /* We got the 'CREATE' (incoming connection), should send the CREATE_ACK */
    cc->metrics.age = GNUNET_TIME_absolute_get ();
    cc->task =
      GNUNET_SCHEDULER_add_at (cc->create_ack_at, &send_create_ack, cc);
    break;

  case CADET_CONNECTION_READY:
    if ((NULL == cc->keepalive_qe) && (GNUNET_YES == cc->mqm_ready) &&
        (NULL == cc->task))
    {
      LOG (GNUNET_ERROR_TYPE_DEBUG,
           "Scheduling keepalive for %s in %s\n",
           GCC_2s (cc),
           GNUNET_STRINGS_relative_time_to_string (keepalive_period,
                                                   GNUNET_YES));
      cc->task =
        GNUNET_SCHEDULER_add_delayed (keepalive_period, &send_keepalive, cc);
    }
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
 * @param off offset of @a destination on @a path
 * @param ct which tunnel uses this connection
 * @param init_state initial state for the connection
 * @param ready_cb function to call when ready to transmit
 * @param ready_cb_cls closure for @a cb
 * @return handle to the connection
 */
static struct CadetConnection *
connection_create (struct CadetPeer *destination,
                   struct CadetPeerPath *path,
                   unsigned int off,
                   struct CadetTConnection *ct,
                   const struct GNUNET_CADET_ConnectionTunnelIdentifier *cid,
                   enum CadetConnectionState init_state,
                   GCC_ReadyCallback ready_cb,
                   void *ready_cb_cls)
{
  struct CadetConnection *cc;
  struct CadetPeer *first_hop;

  cc = GNUNET_new (struct CadetConnection);
  cc->state = init_state;
  cc->ct = ct;
  cc->destination = destination; /* xrs,t3ss,lurchi*/
  cc->cid = *cid;
  cc->retry_delay =
    GNUNET_TIME_relative_multiply (INITIAL_CONNECTION_CREATE_RETRY_DELAY, off);
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_CONTAINER_multishortmap_put (
                   connections,
                   &GCC_get_id (cc)->connection_of_tunnel,
                   cc,
                   GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY));
  cc->ready_cb = ready_cb;
  cc->ready_cb_cls = ready_cb_cls;
  cc->path = path;
  cc->off = off;
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Creating %s using path %s (offset: %u)\n",
       GCC_2s (cc),
       GCPP_2s (path),
       off);
  GCPP_add_connection (path, off, cc);
  for (unsigned int i = 0; i < off; i++)
    GCP_add_connection (GCPP_get_peer_at_offset (path, i), cc);
  first_hop = GCPP_get_peer_at_offset (path, 0);
  cc->mq_man = GCP_request_mq (first_hop, &manage_first_hop_mq, cc);
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
 * @return handle to the connection, NULL if we already have
 *         a connection that takes precedence on @a path
 */
struct CadetConnection *
GCC_create_inbound (struct CadetPeer *destination,
                    struct CadetPeerPath *path,
                    struct CadetTConnection *ct,
                    const struct GNUNET_CADET_ConnectionTunnelIdentifier *cid,
                    GCC_ReadyCallback ready_cb,
                    void *ready_cb_cls)
{
  struct CadetConnection *cc;
  unsigned int off;

  off = GCPP_find_peer (path, destination);
  GNUNET_assert (UINT_MAX != off);
  cc = GCPP_get_connection (path, destination, off);
  if (NULL != cc)
  {
    int cmp;

    cmp = GNUNET_memcmp (cid, &cc->cid);
    if (0 == cmp)
    {
      /* Two peers picked the SAME random connection identifier at the
         same time for the same path? Must be malicious.  Drop
         connection (existing and inbound), even if it is the only
         one. */
      GNUNET_break_op (0);
      GCT_connection_lost (cc->ct);
      GCC_destroy_without_tunnel (cc);
      return NULL;
    }
    if (0 < cmp)
    {
      /* drop existing */
      LOG (GNUNET_ERROR_TYPE_DEBUG,
           "Got two connections on %s, dropping my existing %s\n",
           GCPP_2s (path),
           GCC_2s (cc));
      GCT_connection_lost (cc->ct);
      GCC_destroy_without_tunnel (cc);
    }
    else
    {
      /* keep existing */
      LOG (GNUNET_ERROR_TYPE_DEBUG,
           "Got two connections on %s, keeping my existing %s\n",
           GCPP_2s (path),
           GCC_2s (cc));
      return NULL;
    }
  }

  return connection_create (destination,
                            path,
                            off,
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
 * @param off offset of @a destination on @a path
 * @param ct tunnel that uses the connection
 * @param ready_cb function to call when ready to transmit
 * @param ready_cb_cls closure for @a cb
 * @return handle to the connection
 */
struct CadetConnection *
GCC_create (struct CadetPeer *destination,
            struct CadetPeerPath *path,
            unsigned int off,
            struct CadetTConnection *ct,
            GCC_ReadyCallback ready_cb,
            void *ready_cb_cls)
{
  struct GNUNET_CADET_ConnectionTunnelIdentifier cid;

  GNUNET_CRYPTO_random_block (GNUNET_CRYPTO_QUALITY_NONCE, &cid, sizeof(cid));
  return connection_create (destination,
                            path,
                            off,
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
GCC_transmit (struct CadetConnection *cc, struct GNUNET_MQ_Envelope *env)
{
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Scheduling message for transmission on %s\n",
       GCC_2s (cc));
  GNUNET_assert (GNUNET_YES == cc->mqm_ready);
  GNUNET_assert (CADET_CONNECTION_READY == cc->state);
  cc->metrics.last_use = GNUNET_TIME_absolute_get ();
  cc->mqm_ready = GNUNET_NO;
  if (NULL != cc->task)
  {
    GNUNET_SCHEDULER_cancel (cc->task);
    cc->task = NULL;
  }
  GCP_send (cc->mq_man, env);
}


/**
 * Obtain the path used by this connection.
 *
 * @param cc connection
 * @param off[out] set to the length of the path we use
 * @return path to @a cc
 */
struct CadetPeerPath *
GCC_get_path (struct CadetConnection *cc, unsigned int *off)
{
  *off = cc->off;
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
                     sizeof(buf),
                     "Connection %s (%s)",
                     GNUNET_sh2s (&cc->cid.connection_of_tunnel),
                     GCT_2s (cc->ct->t));
    return buf;
  }
  GNUNET_snprintf (buf,
                   sizeof(buf),
                   "Connection %s",
                   GNUNET_sh2s (&cc->cid.connection_of_tunnel));
  return buf;
}


#define LOG2(level, ...) \
  GNUNET_log_from_nocheck (level, "cadet-con", __VA_ARGS__)


/**
 * Log connection info.
 *
 * @param cc connection
 * @param level Debug level to use.
 */
void
GCC_debug (struct CadetConnection *cc, enum GNUNET_ErrorType level)
{
#if ! defined(GNUNET_CULL_LOGGING)
  int do_log;

  do_log = GNUNET_get_log_call_status (level & (~GNUNET_ERROR_TYPE_BULK),
                                       "cadet-con",
                                       __FILE__,
                                       __FUNCTION__,
                                       __LINE__);
  if (0 == do_log)
    return;
  if (NULL == cc)
  {
    LOG2 (level, "Connection (NULL)\n");
    return;
  }
  LOG2 (level,
        "%s to %s via path %s in state %d is %s\n",
        GCC_2s (cc),
        GCP_2s (cc->destination),
        GCPP_2s (cc->path),
        cc->state,
        (GNUNET_YES == cc->mqm_ready) ? "ready" : "busy");
#endif
}


/* end of gnunet-service-cadet_connection.c */

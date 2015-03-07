/*
  This file is part of GNUnet.
  Copyright (C) 2013, 2014 Christian Grothoff (and other contributing authors)

  GNUnet is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public Licerevocation as published
  by the Free Software Foundation; either version 3, or (at your
  option) any later version.

  GNUnet is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  General Public Licerevocation for more details.

  You should have received a copy of the GNU General Public Licerevocation
  along with GNUnet; see the file COPYING.  If not, write to the
  Free Software Foundation, Inc., 59 Temple Place - Suite 330,
  Boston, MA 02111-1307, USA.
 */

/**
 * @file revocation/gnunet-service-revocation.c
 * @brief key revocation service
 * @author Christian Grothoff
 *
 * The purpose of this service is to allow users to permanently revoke
 * (compromised) keys.  This is done by flooding the network with the
 * revocation requests.  To reduce the attack potential offered by such
 * flooding, revocations must include a proof of work.  We use the
 * set service for efficiently computing the union of revocations of
 * peers that connect.
 *
 * TODO:
 * - optimization: avoid sending revocation back to peer that we got it from;
 * - optimization: have randomized delay in sending revocations to other peers
 *                 to make it rare to traverse each link twice (NSE-style)
 */
#include "platform.h"
#include <math.h>
#include "gnunet_util_lib.h"
#include "gnunet_constants.h"
#include "gnunet_protocols.h"
#include "gnunet_signatures.h"
#include "gnunet_statistics_service.h"
#include "gnunet_core_service.h"
#include "gnunet_revocation_service.h"
#include "gnunet_set_service.h"
#include "revocation.h"
#include <gcrypt.h>


/**
 * Per-peer information.
 */
struct PeerEntry
{

  /**
   * Queue for sending messages to this peer.
   */
  struct GNUNET_MQ_Handle *mq;

  /**
   * What is the identity of the peer?
   */
  struct GNUNET_PeerIdentity id;

  /**
   * Tasked used to trigger the set union operation.
   */
  struct GNUNET_SCHEDULER_Task * transmit_task;

  /**
   * Handle to active set union operation (over revocation sets).
   */
  struct GNUNET_SET_OperationHandle *so;

};


/**
 * Set from all revocations known to us.
 */
static struct GNUNET_SET_Handle *revocation_set;

/**
 * Hash map with all revoked keys, maps the hash of the public key
 * to the respective `struct RevokeMessage`.
 */
static struct GNUNET_CONTAINER_MultiHashMap *revocation_map;

/**
 * Handle to our current configuration.
 */
static const struct GNUNET_CONFIGURATION_Handle *cfg;

/**
 * Handle to the statistics service.
 */
static struct GNUNET_STATISTICS_Handle *stats;

/**
 * Handle to the core service (for flooding)
 */
static struct GNUNET_CORE_Handle *core_api;

/**
 * Map of all connected peers.
 */
static struct GNUNET_CONTAINER_MultiPeerMap *peers;

/**
 * The peer identity of this peer.
 */
static struct GNUNET_PeerIdentity my_identity;

/**
 * Handle to this serivce's server.
 */
static struct GNUNET_SERVER_Handle *srv;

/**
 * Notification context for convenient sending of replies to the clients.
 */
static struct GNUNET_SERVER_NotificationContext *nc;

/**
 * File handle for the revocation database.
 */
static struct GNUNET_DISK_FileHandle *revocation_db;

/**
 * Handle for us listening to incoming revocation set union requests.
 */
static struct GNUNET_SET_ListenHandle *revocation_union_listen_handle;

/**
 * Amount of work required (W-bit collisions) for REVOCATION proofs, in collision-bits.
 */
static unsigned long long revocation_work_required;

/**
 * Our application ID for set union operations.  Must be the
 * same for all (compatible) peers.
 */
static struct GNUNET_HashCode revocation_set_union_app_id;



/**
 * An revoke message has been received, check that it is well-formed.
 *
 * @param rm the message to verify
 * @return #GNUNET_YES if the message is verified
 *         #GNUNET_NO if the key/signature don't verify
 */
static int
verify_revoke_message (const struct RevokeMessage *rm)
{
  if (GNUNET_YES !=
      GNUNET_REVOCATION_check_pow (&rm->public_key,
				   rm->proof_of_work,
				   (unsigned int) revocation_work_required))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		"Proof of work invalid!\n");
    GNUNET_break_op (0);
    return GNUNET_NO;
  }
  if (GNUNET_OK !=
      GNUNET_CRYPTO_ecdsa_verify (GNUNET_SIGNATURE_PURPOSE_REVOCATION,
				&rm->purpose,
				&rm->signature,
				&rm->public_key))
  {
    GNUNET_break_op (0);
    return GNUNET_NO;
  }
  return GNUNET_YES;
}


/**
 * Handle QUERY message from client.
 *
 * @param cls unused
 * @param client who sent the message
 * @param message the message received
 */
static void
handle_query_message (void *cls,
		      struct GNUNET_SERVER_Client *client,
                      const struct GNUNET_MessageHeader *message)
{
  const struct QueryMessage *qm = (const struct QueryMessage *) message;
  struct QueryResponseMessage qrm;
  struct GNUNET_HashCode hc;
  int res;

  GNUNET_CRYPTO_hash (&qm->key,
                      sizeof (struct GNUNET_CRYPTO_EcdsaPublicKey),
                      &hc);
  res = GNUNET_CONTAINER_multihashmap_contains (revocation_map,
                                                &hc);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              (GNUNET_NO == res)
	      ? "Received revocation check for valid key `%s' from client\n"
              : "Received revocation check for revoked key `%s' from client\n",
              GNUNET_h2s (&hc));
  qrm.header.size = htons (sizeof (struct QueryResponseMessage));
  qrm.header.type = htons (GNUNET_MESSAGE_TYPE_REVOCATION_QUERY_RESPONSE);
  qrm.is_valid = htonl ((GNUNET_YES == res) ? GNUNET_NO : GNUNET_YES);
  GNUNET_SERVER_notification_context_add (nc,
                                          client);
  GNUNET_SERVER_notification_context_unicast (nc,
                                              client,
                                              &qrm.header,
                                              GNUNET_NO);
  GNUNET_SERVER_receive_done (client,
                              GNUNET_OK);
}


/**
 * Flood the given revocation message to all neighbours.
 *
 * @param cls the `struct RevokeMessage` to flood
 * @param target a neighbour
 * @param value our `struct PeerEntry` for the neighbour
 * @return #GNUNET_OK (continue to iterate)
 */
static int
do_flood (void *cls,
          const struct GNUNET_PeerIdentity *target,
          void *value)
{
  const struct RevokeMessage *rm = cls;
  struct PeerEntry *pe = value;
  struct GNUNET_MQ_Envelope *e;
  struct RevokeMessage *cp;

  e = GNUNET_MQ_msg (cp,
                     GNUNET_MESSAGE_TYPE_REVOCATION_REVOKE);
  *cp = *rm;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Flooding revocation to `%s'\n",
              GNUNET_i2s (target));
  GNUNET_MQ_send (pe->mq,
                  e);
  return GNUNET_OK;
}


/**
 * Publicize revocation message.   Stores the message locally in the
 * database and passes it to all connected neighbours (and adds it to
 * the set for future connections).
 *
 * @param rm message to publicize
 * @return #GNUNET_OK on success, #GNUNET_NO if we encountered an error,
 *         #GNUNET_SYSERR if the message was malformed
 */
static int
publicize_rm (const struct RevokeMessage *rm)
{
  struct RevokeMessage *cp;
  struct GNUNET_HashCode hc;
  struct GNUNET_SET_Element e;

  GNUNET_CRYPTO_hash (&rm->public_key,
                      sizeof (struct GNUNET_CRYPTO_EcdsaPublicKey),
                      &hc);
  if (GNUNET_YES ==
      GNUNET_CONTAINER_multihashmap_contains (revocation_map,
                                              &hc))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Duplicate revocation received from peer. Ignored.\n");
    return GNUNET_OK;
  }
  if (GNUNET_OK !=
      verify_revoke_message (rm))
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  /* write to disk */
  if (sizeof (struct RevokeMessage) !=
      GNUNET_DISK_file_write (revocation_db,
                              rm,
                              sizeof (struct RevokeMessage)))
  {
    GNUNET_log_strerror (GNUNET_ERROR_TYPE_ERROR,
                         "write");
    return GNUNET_NO;
  }
  if (GNUNET_OK !=
      GNUNET_DISK_file_sync (revocation_db))
  {
    GNUNET_log_strerror (GNUNET_ERROR_TYPE_ERROR,
                         "sync");
    return GNUNET_NO;
  }
  /* keep copy in memory */
  cp = (struct RevokeMessage *) GNUNET_copy_message (&rm->header);
  GNUNET_break (GNUNET_OK ==
                GNUNET_CONTAINER_multihashmap_put (revocation_map,
                                                   &hc,
                                                   cp,
                                                   GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY));
  /* add to set for future connections */
  e.size = htons (rm->header.size);
  e.element_type = 0;
  e.data = rm;
  if (GNUNET_OK !=
      GNUNET_SET_add_element (revocation_set,
                              &e,
                              NULL,
                              NULL))
  {
    GNUNET_break (0);
    return GNUNET_OK;
  }
  else
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Added revocation info to SET\n");
  }
  /* flood to neighbours */
  GNUNET_CONTAINER_multipeermap_iterate (peers,
					 &do_flood,
                                         cp);
  return GNUNET_OK;
}


/**
 * Handle REVOKE message from client.
 *
 * @param cls unused
 * @param client who sent the message
 * @param message the message received
 */
static void
handle_revoke_message (void *cls,
                       struct GNUNET_SERVER_Client *client,
                       const struct GNUNET_MessageHeader *message)
{
  const struct RevokeMessage *rm;
  struct RevocationResponseMessage rrm;
  int ret;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Received REVOKE message from client\n");
  rm = (const struct RevokeMessage *) message;
  if (GNUNET_SYSERR == (ret = publicize_rm (rm)))
  {
    GNUNET_break_op (0);
    GNUNET_SERVER_receive_done (client,
                                GNUNET_SYSERR);
    return;
  }
  rrm.header.size = htons (sizeof (struct RevocationResponseMessage));
  rrm.header.type = htons (GNUNET_MESSAGE_TYPE_REVOCATION_REVOKE_RESPONSE);
  rrm.is_valid = htonl ((GNUNET_OK == ret) ? GNUNET_NO : GNUNET_YES);
  GNUNET_SERVER_notification_context_add (nc,
                                          client);
  GNUNET_SERVER_notification_context_unicast (nc,
                                              client,
                                              &rrm.header,
                                              GNUNET_NO);
  GNUNET_SERVER_receive_done (client,
                              GNUNET_OK);
}


/**
 * Core handler for flooded revocation messages.
 *
 * @param cls closure unused
 * @param message message
 * @param peer peer identity this message is from (ignored)
 */
static int
handle_p2p_revoke_message (void *cls,
			   const struct GNUNET_PeerIdentity *peer,
			   const struct GNUNET_MessageHeader *message)
{
  const struct RevokeMessage *rm;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Received REVOKE message from peer\n");
  rm = (const struct RevokeMessage *) message;
  GNUNET_break_op (GNUNET_SYSERR != publicize_rm (rm));
  return GNUNET_OK;
}


/**
 * Callback for set operation results. Called for each element in the
 * result set.  Each element contains a revocation, which we should
 * validate and then add to our revocation list (and set).
 *
 * @param cls closure
 * @param element a result element, only valid if status is #GNUNET_SET_STATUS_OK
 * @param status see `enum GNUNET_SET_Status`
 */
static void
add_revocation (void *cls,
                const struct GNUNET_SET_Element *element,
                enum GNUNET_SET_Status status)
{
  struct PeerEntry *peer_entry = cls;
  const struct RevokeMessage *rm;

  switch (status)
  {
  case GNUNET_SET_STATUS_OK:
    if (element->size != sizeof (struct RevokeMessage))
    {
      GNUNET_break_op (0);
      return;
    }
    if (0 != element->element_type)
    {
      GNUNET_STATISTICS_update (stats,
                                gettext_noop ("# unsupported revocations received via set union"),
                                1, GNUNET_NO);
      return;
    }
    rm = element->data;
    (void) handle_p2p_revoke_message (NULL,
                                      &peer_entry->id,
                                      &rm->header);
    GNUNET_STATISTICS_update (stats,
                              gettext_noop ("# revocation messages received via set union"),
                              1, GNUNET_NO);
    break;
  case GNUNET_SET_STATUS_FAILURE:
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                _("Error computing revocation set union with %s\n"),
                GNUNET_i2s (&peer_entry->id));
    peer_entry->so = NULL;
    GNUNET_STATISTICS_update (stats,
                              gettext_noop ("# revocation set unions failed"),
                              1,
                              GNUNET_NO);
    break;
  case GNUNET_SET_STATUS_HALF_DONE:
    break;
  case GNUNET_SET_STATUS_DONE:
    peer_entry->so = NULL;
    GNUNET_STATISTICS_update (stats,
                              gettext_noop ("# revocation set unions completed"),
                              1,
                              GNUNET_NO);
    break;
  default:
    GNUNET_break (0);
    break;
 }
}


/**
 * The timeout for performing the set union has expired,
 * run the set operation on the revocation certificates.
 *
 * @param cls NULL
 * @param tc scheduler context (unused)
 */
static void
transmit_task_cb (void *cls,
                  const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct PeerEntry *peer_entry = cls;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Starting set exchange with peer `%s'\n",
              GNUNET_i2s (&peer_entry->id));
  peer_entry->transmit_task = NULL;
  peer_entry->so = GNUNET_SET_prepare (&peer_entry->id,
                                       &revocation_set_union_app_id,
                                       NULL,
                                       GNUNET_SET_RESULT_ADDED,
                                       &add_revocation,
                                       peer_entry);
  if (GNUNET_OK !=
      GNUNET_SET_commit (peer_entry->so,
                         revocation_set))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                _("SET service crashed, terminating revocation service\n"));
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
}


/**
 * Method called whenever a peer connects. Sets up the PeerEntry and
 * schedules the initial revocation set exchange with this peer.
 *
 * @param cls closure
 * @param peer peer identity this notification is about
 */
static void
handle_core_connect (void *cls,
		     const struct GNUNET_PeerIdentity *peer)
{
  struct PeerEntry *peer_entry;
  struct GNUNET_HashCode my_hash;
  struct GNUNET_HashCode peer_hash;

  if (0 == memcmp(peer,
                  &my_identity,
                  sizeof (my_identity)))
      return;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Peer `%s' connected to us\n",
              GNUNET_i2s (peer));
  peer_entry = GNUNET_CONTAINER_multipeermap_get (peers,
                                                  peer);
  GNUNET_assert (NULL == peer_entry);
  peer_entry = GNUNET_new (struct PeerEntry);
  peer_entry->id = *peer;
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_CONTAINER_multipeermap_put (peers,
                                                    &peer_entry->id,
                                                    peer_entry,
                                                    GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY));
  peer_entry->mq = GNUNET_CORE_mq_create (core_api, peer);
  GNUNET_CRYPTO_hash (&my_identity,
                      sizeof (my_identity),
                      &my_hash);
  GNUNET_CRYPTO_hash (peer,
                      sizeof (*peer),
                      &peer_hash);
  if (0 < GNUNET_CRYPTO_hash_cmp (&my_hash,
                                  &peer_hash))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Starting SET operation with peer `%s'\n",
                GNUNET_i2s (peer));
    peer_entry->transmit_task =
      GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_SECONDS,
                                    &transmit_task_cb,
                                    peer_entry);
  }
  GNUNET_STATISTICS_update (stats,
                            "# peers connected",
                            1,
                            GNUNET_NO);
}


/**
 * Method called whenever a peer disconnects. Deletes the PeerEntry and cancels
 * any pending transmission requests to that peer.
 *
 * @param cls closure
 * @param peer peer identity this notification is about
 */
static void
handle_core_disconnect (void *cls,
			const struct GNUNET_PeerIdentity *peer)
{
  struct PeerEntry *pos;

  if (0 == memcmp (peer,
                   &my_identity,
                   sizeof (my_identity)))
    return;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Peer `%s' disconnected from us\n",
              GNUNET_i2s (peer));
  pos = GNUNET_CONTAINER_multipeermap_get (peers,
                                           peer);
  GNUNET_assert (NULL != pos);
  GNUNET_assert (GNUNET_YES ==
                 GNUNET_CONTAINER_multipeermap_remove (peers,
                                                       peer,
                                                       pos));
  GNUNET_MQ_destroy (pos->mq);
  if (NULL != pos->transmit_task)
  {
    GNUNET_SCHEDULER_cancel (pos->transmit_task);
    pos->transmit_task = NULL;
  }
  if (NULL != pos->so)
  {
    GNUNET_SET_operation_cancel (pos->so);
    pos->so = NULL;
  }
  GNUNET_free (pos);
  GNUNET_STATISTICS_update (stats,
                            "# peers connected",
                            -1,
                            GNUNET_NO);
}


/**
 * Free all values in a hash map.
 *
 * @param cls NULL
 * @param key the key
 * @param value value to free
 * @return #GNUNET_OK (continue to iterate)
 */
static int
free_entry (void *cls,
            const struct GNUNET_HashCode *key,
            void *value)
{
  GNUNET_free (value);
  return GNUNET_OK;
}


/**
 * Task run during shutdown.
 *
 * @param cls unused
 * @param tc unused
 */
static void
shutdown_task (void *cls,
	       const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  if (NULL != revocation_set)
  {
    GNUNET_SET_destroy (revocation_set);
    revocation_set = NULL;
  }
  if (NULL != revocation_union_listen_handle)
  {
    GNUNET_SET_listen_cancel (revocation_union_listen_handle);
    revocation_union_listen_handle = NULL;
  }
  if (NULL != core_api)
  {
    GNUNET_CORE_disconnect (core_api);
    core_api = NULL;
  }
  if (NULL != stats)
  {
    GNUNET_STATISTICS_destroy (stats, GNUNET_NO);
    stats = NULL;
  }
  if (NULL != peers)
  {
    GNUNET_CONTAINER_multipeermap_destroy (peers);
    peers = NULL;
  }
  if (NULL != nc)
  {
    GNUNET_SERVER_notification_context_destroy (nc);
    nc = NULL;
  }
  if (NULL != revocation_db)
  {
    GNUNET_DISK_file_close (revocation_db);
    revocation_db = NULL;
  }
  GNUNET_CONTAINER_multihashmap_iterate (revocation_map,
                                         &free_entry,
                                         NULL);
  GNUNET_CONTAINER_multihashmap_destroy (revocation_map);
}


/**
 * Called on core init/fail.
 *
 * @param cls service closure
 * @param identity the public identity of this peer
 */
static void
core_init (void *cls,
           const struct GNUNET_PeerIdentity *identity)
{
  if (NULL == identity)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		"Connection to core FAILED!\n");
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  my_identity = *identity;
}


/**
 * Called when another peer wants to do a set operation with the
 * local peer. If a listen error occurs, the 'request' is NULL.
 *
 * @param cls closure
 * @param other_peer the other peer
 * @param context_msg message with application specific information from
 *        the other peer
 * @param request request from the other peer (never NULL), use GNUNET_SET_accept()
 *        to accept it, otherwise the request will be refused
 *        Note that we can't just return value from the listen callback,
 *        as it is also necessary to specify the set we want to do the
 *        operation with, whith sometimes can be derived from the context
 *        message. It's necessary to specify the timeout.
 */
static void
handle_revocation_union_request (void *cls,
                                 const struct GNUNET_PeerIdentity *other_peer,
                                 const struct GNUNET_MessageHeader *context_msg,
                                 struct GNUNET_SET_Request *request)
{
  struct PeerEntry *peer_entry;

  if (NULL == request)
  {
    GNUNET_break (0);
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received set exchange request from peer `%s'\n",
              GNUNET_i2s (other_peer));
  peer_entry = GNUNET_CONTAINER_multipeermap_get (peers,
                                                  other_peer);
  if (NULL == peer_entry)
  {
    peer_entry = GNUNET_new (struct PeerEntry);
    peer_entry->id = *other_peer;
    GNUNET_assert (GNUNET_OK ==
                   GNUNET_CONTAINER_multipeermap_put (peers, other_peer,
                                                      peer_entry,
                                                      GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY));
  }
  peer_entry->so = GNUNET_SET_accept (request,
                                      GNUNET_SET_RESULT_ADDED,
                                      &add_revocation,
                                      peer_entry);
  if (GNUNET_OK !=
      GNUNET_SET_commit (peer_entry->so,
                         revocation_set))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                _("SET service crashed, terminating revocation service\n"));
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
}


/**
 * Handle network size estimate clients.
 *
 * @param cls closure
 * @param server the initialized server
 * @param c configuration to use
 */
static void
run (void *cls,
     struct GNUNET_SERVER_Handle *server,
     const struct GNUNET_CONFIGURATION_Handle *c)
{
  static const struct GNUNET_SERVER_MessageHandler handlers[] = {
    {&handle_query_message, NULL, GNUNET_MESSAGE_TYPE_REVOCATION_QUERY,
     sizeof (struct QueryMessage)},
    {&handle_revoke_message, NULL, GNUNET_MESSAGE_TYPE_REVOCATION_REVOKE,
     sizeof (struct RevokeMessage)},
    {NULL, NULL, 0, 0}
  };
  static const struct GNUNET_CORE_MessageHandler core_handlers[] = {
    {&handle_p2p_revoke_message, GNUNET_MESSAGE_TYPE_REVOCATION_REVOKE,
     sizeof (struct RevokeMessage)},
    {NULL, 0, 0}
  };
  char *fn;
  uint64_t left;
  struct RevokeMessage *rm;
  struct GNUNET_HashCode hc;

  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_filename (c,
                                               "REVOCATION",
                                               "DATABASE",
                                               &fn))
  {
    GNUNET_log_config_missing (GNUNET_ERROR_TYPE_ERROR,
                               "REVOCATION",
                               "DATABASE");
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  cfg = c;
  srv = server;
  revocation_map = GNUNET_CONTAINER_multihashmap_create (16, GNUNET_NO);
  nc = GNUNET_SERVER_notification_context_create (server, 1);
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_number (cfg, "REVOCATION", "WORKBITS",
					     &revocation_work_required))
  {
    GNUNET_log_config_missing (GNUNET_ERROR_TYPE_ERROR,
			       "REVOCATION",
			       "WORKBITS");
    GNUNET_SCHEDULER_shutdown ();
    GNUNET_free (fn);
    return;
  }
  if (revocation_work_required >= sizeof (struct GNUNET_HashCode) * 8)
  {
    GNUNET_log_config_invalid (GNUNET_ERROR_TYPE_ERROR,
			       "REVOCATION",
			       "WORKBITS",
			       _("Value is too large.\n"));
    GNUNET_SCHEDULER_shutdown ();
    GNUNET_free (fn);
    return;
  }
  revocation_set = GNUNET_SET_create (cfg,
				      GNUNET_SET_OPERATION_UNION);
  revocation_union_listen_handle
    = GNUNET_SET_listen (cfg,
                         GNUNET_SET_OPERATION_UNION,
                         &revocation_set_union_app_id,
                         &handle_revocation_union_request,
                         NULL);
  revocation_db = GNUNET_DISK_file_open (fn,
                                         GNUNET_DISK_OPEN_READWRITE |
                                         GNUNET_DISK_OPEN_CREATE,
                                         GNUNET_DISK_PERM_USER_READ | GNUNET_DISK_PERM_USER_WRITE |
                                         GNUNET_DISK_PERM_GROUP_READ |
                                         GNUNET_DISK_PERM_OTHER_READ);
  if (NULL == revocation_db)
  {
    GNUNET_log_config_invalid (GNUNET_ERROR_TYPE_ERROR,
			       "REVOCATION",
			       "DATABASE",
                               _("Could not open revocation database file!"));
    GNUNET_SCHEDULER_shutdown ();
    GNUNET_free (fn);
    return;
  }
  if (GNUNET_OK !=
      GNUNET_DISK_file_size (fn, &left, GNUNET_YES, GNUNET_YES))
    left = 0;
  while (left > sizeof (struct RevokeMessage))
  {
    rm = GNUNET_new (struct RevokeMessage);
    if (sizeof (struct RevokeMessage) !=
        GNUNET_DISK_file_read (revocation_db,
                               rm,
                               sizeof (struct RevokeMessage)))
    {
      GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_ERROR,
                                "read",
                                fn);
      GNUNET_free (rm);
      GNUNET_SCHEDULER_shutdown ();
      GNUNET_free (fn);
      return;
    }
    GNUNET_break (0 == ntohl (rm->reserved));
    GNUNET_CRYPTO_hash (&rm->public_key,
                        sizeof (struct GNUNET_CRYPTO_EcdsaPublicKey),
                        &hc);
    GNUNET_break (GNUNET_OK ==
                  GNUNET_CONTAINER_multihashmap_put (revocation_map,
                                                     &hc,
                                                     rm,
                                                     GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY));
  }
  GNUNET_free (fn);

  GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_FOREVER_REL,
                                &shutdown_task,
                                NULL);
  peers = GNUNET_CONTAINER_multipeermap_create (128,
                                                GNUNET_YES);
  GNUNET_SERVER_add_handlers (srv, handlers);
   /* Connect to core service and register core handlers */
  core_api = GNUNET_CORE_connect (cfg,   /* Main configuration */
                                 NULL,       /* Closure passed to functions */
                                 &core_init,    /* Call core_init once connected */
                                 &handle_core_connect,  /* Handle connects */
                                 &handle_core_disconnect,       /* Handle disconnects */
                                 NULL,  /* Don't want notified about all incoming messages */
                                 GNUNET_NO,     /* For header only inbound notification */
                                 NULL,  /* Don't want notified about all outbound messages */
                                 GNUNET_NO,     /* For header only outbound notification */
                                 core_handlers);        /* Register these handlers */
  if (NULL == core_api)
  {
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  stats = GNUNET_STATISTICS_create ("revocation", cfg);
}


/**
 * The main function for the network size estimation service.
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return 0 ok, 1 on error
 */
int
main (int argc,
      char *const *argv)
{
  GNUNET_CRYPTO_hash ("revocation-set-union-application-id",
                      strlen ("revocation-set-union-application-id"),
                      &revocation_set_union_app_id);
  return (GNUNET_OK ==
          GNUNET_SERVICE_run (argc,
                              argv,
                              "revocation",
                              GNUNET_SERVICE_OPTION_NONE,
                              &run, NULL)) ? 0 : 1;
}


#ifdef LINUX
#include <malloc.h>


/**
 * MINIMIZE heap size (way below 128k) since this process doesn't need much.
 */
void __attribute__ ((constructor))
GNUNET_ARM_memory_init ()
{
  mallopt (M_TRIM_THRESHOLD, 4 * 1024);
  mallopt (M_TOP_PAD, 1 * 1024);
  malloc_trim (0);
}
#endif


/* end of gnunet-service-revocation.c */

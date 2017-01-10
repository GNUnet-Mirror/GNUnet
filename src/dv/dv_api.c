/*
     This file is part of GNUnet.
     Copyright (C) 2009--2013, 2016 GNUnet e.V.

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
 * @file dv/dv_api.c
 * @brief library to access the DV service
 * @author Christian Grothoff
 * @author Nathan Evans
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_dv_service.h"
#include "gnunet_protocols.h"
#include "dv.h"
#include "gnunet_transport_plugin.h"

#define LOG(kind,...) GNUNET_log_from (kind, "dv-api",__VA_ARGS__)


/**
 * Information we track for each peer.
 */
struct ConnectedPeer
{

  /**
   * Identity of the peer.
   */
  struct GNUNET_PeerIdentity pid;

};


/**
 * Handle to the DV service.
 */
struct GNUNET_DV_ServiceHandle
{

  /**
   * Connection to DV service.
   */
  struct GNUNET_MQ_Handle *mq;

  /**
   * Our configuration.
   */
  const struct GNUNET_CONFIGURATION_Handle *cfg;

  /**
   * Closure for the callbacks.
   */
  void *cls;

  /**
   * Function to call on connect events.
   */
  GNUNET_DV_ConnectCallback connect_cb;

  /**
   * Function to call on distance change events.
   */
  GNUNET_DV_DistanceChangedCallback distance_cb;

  /**
   * Function to call on disconnect events.
   */
  GNUNET_DV_DisconnectCallback disconnect_cb;

  /**
   * Function to call on receiving messages events.
   */
  GNUNET_DV_MessageReceivedCallback message_cb;

  /**
   * Information tracked per connected peer.  Maps peer
   * identities to `struct ConnectedPeer` entries.
   */
  struct GNUNET_CONTAINER_MultiPeerMap *peers;

};


/**
 * Disconnect and then reconnect to the DV service.
 *
 * @param sh service handle
 */
static void
reconnect (struct GNUNET_DV_ServiceHandle *sh);


/**
 * We got disconnected from the service and thus all of the
 * connections need to be torn down.
 *
 * @param cls the `struct GNUNET_DV_ServiceHandle`
 * @param key a peer identity
 * @param value a `struct ConnectedPeer` to clean up
 * @return #GNUNET_OK (continue to iterate)
 */
static int
cleanup_send_cb (void *cls,
		 const struct GNUNET_PeerIdentity *key,
		 void *value)
{
  struct GNUNET_DV_ServiceHandle *sh = cls;
  struct ConnectedPeer *peer = value;

  GNUNET_assert (GNUNET_YES ==
		 GNUNET_CONTAINER_multipeermap_remove (sh->peers,
						       key,
						       peer));
  sh->disconnect_cb (sh->cls,
                     key);
  GNUNET_free (peer);
  return GNUNET_OK;
}


/**
 * Handles a message sent from the DV service to us.
 * Parse it out and give it to the plugin.
 *
 * @param cls the handle to the DV API
 * @param cm the message that was received
 */
static void
handle_connect (void *cls,
                const struct GNUNET_DV_ConnectMessage *cm)
{
  struct GNUNET_DV_ServiceHandle *sh = cls;
  struct ConnectedPeer *peer;

  peer = GNUNET_CONTAINER_multipeermap_get (sh->peers,
                                            &cm->peer);
  if (NULL != peer)
  {
    GNUNET_break (0);
    reconnect (sh);
    return;
  }
  peer = GNUNET_new (struct ConnectedPeer);
  peer->pid = cm->peer;
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_CONTAINER_multipeermap_put (sh->peers,
                                                    &peer->pid,
                                                    peer,
                                                    GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY));
  sh->connect_cb (sh->cls,
                  &cm->peer,
                  ntohl (cm->distance),
                  (enum GNUNET_ATS_Network_Type) ntohl (cm->network));
}


/**
 * Handles a message sent from the DV service to us.
 * Parse it out and give it to the plugin.
 *
 * @param cls the handle to the DV API
 * @param dm the message that was received
 */
static void
handle_disconnect (void *cls,
                   const struct GNUNET_DV_DisconnectMessage *dm)
{
  struct GNUNET_DV_ServiceHandle *sh = cls;
  struct ConnectedPeer *peer;

  peer = GNUNET_CONTAINER_multipeermap_get (sh->peers,
                                            &dm->peer);
  if (NULL == peer)
  {
    GNUNET_break (0);
    reconnect (sh);
    return;
  }
  cleanup_send_cb (sh,
                   &dm->peer,
                   peer);
}


/**
 * Handles a message sent from the DV service to us.
 * Parse it out and give it to the plugin.
 *
 * @param cls the handle to the DV API
 * @param msg the message that was received
 */
static void
handle_distance_update (void *cls,
                        const struct GNUNET_DV_DistanceUpdateMessage *dum)
{
  struct GNUNET_DV_ServiceHandle *sh = cls;
  struct ConnectedPeer *peer;

  peer = GNUNET_CONTAINER_multipeermap_get (sh->peers,
                                            &dum->peer);
  if (NULL == peer)
  {
    GNUNET_break (0);
    reconnect (sh);
    return;
  }
  sh->distance_cb (sh->cls,
                   &dum->peer,
                   ntohl (dum->distance),
                   (enum GNUNET_ATS_Network_Type) ntohl (dum->network));
}


/**
 * Handles a message sent from the DV service to us.
 * Parse it out and give it to the plugin.
 *
 * @param cls the handle to the DV API
 * @param rm the message that was received
 */
static int
check_received (void *cls,
                const struct GNUNET_DV_ReceivedMessage *rm)
{
  struct GNUNET_DV_ServiceHandle *sh = cls;
  const struct GNUNET_MessageHeader *payload;

  if (NULL ==
      GNUNET_CONTAINER_multipeermap_get (sh->peers,
                                         &rm->sender))
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  if (ntohs (rm->header.size) - sizeof (struct GNUNET_DV_ReceivedMessage) <
      sizeof (*payload))
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  payload = (const struct GNUNET_MessageHeader *) &rm[1];
  if (ntohs (rm->header.size) !=
      sizeof (struct GNUNET_DV_ReceivedMessage) + ntohs (payload->size))
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * Handles a message sent from the DV service to us.
 * Parse it out and give it to the plugin.
 *
 * @param cls the handle to the DV API
 * @param rm the message that was received
 */
static void
handle_received (void *cls,
                 const struct GNUNET_DV_ReceivedMessage *rm)
{
  struct GNUNET_DV_ServiceHandle *sh = cls;
  const struct GNUNET_MessageHeader *payload;

  payload = (const struct GNUNET_MessageHeader *) &rm[1];
  sh->message_cb (sh->cls,
                  &rm->sender,
                  ntohl (rm->distance),
                  payload);
}


/**
 * Generic error handler, called with the appropriate error code and
 * the same closure specified at the creation of the message queue.
 * Not every message queue implementation supports an error handler.
 *
 * @param cls closure with the `struct GNUNET_DV_ServiceHandle *`
 * @param error error code
 */
static void
mq_error_handler (void *cls,
                  enum GNUNET_MQ_Error error)
{
  struct GNUNET_DV_ServiceHandle *sh = cls;

  reconnect (sh);
}


/**
 * Disconnect and then reconnect to the DV service.
 *
 * @param sh service handle
 */
static void
reconnect (struct GNUNET_DV_ServiceHandle *sh)
{
  struct GNUNET_MQ_MessageHandler handlers[] = {
    GNUNET_MQ_hd_fixed_size (connect,
                             GNUNET_MESSAGE_TYPE_DV_CONNECT,
                             struct GNUNET_DV_ConnectMessage,
                             sh),
    GNUNET_MQ_hd_fixed_size (disconnect,
                             GNUNET_MESSAGE_TYPE_DV_DISCONNECT,
                             struct GNUNET_DV_DisconnectMessage,
                             sh),
    GNUNET_MQ_hd_fixed_size (distance_update,
                             GNUNET_MESSAGE_TYPE_DV_DISTANCE_CHANGED,
                             struct GNUNET_DV_DistanceUpdateMessage,
                             sh),
    GNUNET_MQ_hd_var_size (received,
                           GNUNET_MESSAGE_TYPE_DV_RECV,
                           struct GNUNET_DV_ReceivedMessage,
                           sh),
    GNUNET_MQ_handler_end ()
  };
  struct GNUNET_MessageHeader *sm;
  struct GNUNET_MQ_Envelope *env;

  if (NULL != sh->mq)
  {
    GNUNET_MQ_destroy (sh->mq);
    sh->mq = NULL;
  }
  GNUNET_CONTAINER_multipeermap_iterate (sh->peers,
					 &cleanup_send_cb,
					 sh);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Connecting to DV service\n");
  sh->mq = GNUNET_CLIENT_connect (sh->cfg,
                                  "dv",
                                  handlers,
                                  &mq_error_handler,
                                  sh);
  if (NULL == sh->mq)
  {
    GNUNET_break (0);
    return;
  }
  env = GNUNET_MQ_msg (sm,
                       GNUNET_MESSAGE_TYPE_DV_START);
  GNUNET_MQ_send (sh->mq,
                  env);
}


/**
 * Connect to the DV service.
 *
 * @param cfg configuration
 * @param cls closure for callbacks
 * @param connect_cb function to call on connects
 * @param distance_cb function to call if distances change
 * @param disconnect_cb function to call on disconnects
 * @param message_cb function to call if we receive messages
 * @return handle to access the service
 */
struct GNUNET_DV_ServiceHandle *
GNUNET_DV_service_connect (const struct GNUNET_CONFIGURATION_Handle *cfg,
			   void *cls,
			   GNUNET_DV_ConnectCallback connect_cb,
			   GNUNET_DV_DistanceChangedCallback distance_cb,
			   GNUNET_DV_DisconnectCallback disconnect_cb,
			   GNUNET_DV_MessageReceivedCallback message_cb)
{
  struct GNUNET_DV_ServiceHandle *sh;

  sh = GNUNET_new (struct GNUNET_DV_ServiceHandle);
  sh->cfg = cfg;
  sh->cls = cls;
  sh->connect_cb = connect_cb;
  sh->distance_cb = distance_cb;
  sh->disconnect_cb = disconnect_cb;
  sh->message_cb = message_cb;
  sh->peers = GNUNET_CONTAINER_multipeermap_create (128,
                                                    GNUNET_YES);
  reconnect (sh);
  return sh;
}


/**
 * Disconnect from DV service.
 *
 * @param sh service handle
 */
void
GNUNET_DV_service_disconnect (struct GNUNET_DV_ServiceHandle *sh)
{
  if (NULL == sh)
    return;
  if (NULL != sh->mq)
  {
    GNUNET_MQ_destroy (sh->mq);
    sh->mq = NULL;
  }
  GNUNET_CONTAINER_multipeermap_iterate (sh->peers,
					 &cleanup_send_cb,
					 sh);
  GNUNET_CONTAINER_multipeermap_destroy (sh->peers);
  GNUNET_free (sh);
}


/**
 * Send a message via DV service.
 *
 * @param sh service handle
 * @param target intended recpient
 * @param msg message payload
 */
void
GNUNET_DV_send (struct GNUNET_DV_ServiceHandle *sh,
		const struct GNUNET_PeerIdentity *target,
		const struct GNUNET_MessageHeader *msg)
{
  struct GNUNET_DV_SendMessage *sm;
  struct ConnectedPeer *peer;
  struct GNUNET_MQ_Envelope *env;

  if (ntohs (msg->size) + sizeof (*sm) >= GNUNET_SERVER_MAX_MESSAGE_SIZE)
  {
    GNUNET_break (0);
    return;
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Asked to send %u bytes of type %u to %s\n",
       (unsigned int) ntohs (msg->size),
       (unsigned int) ntohs (msg->type),
       GNUNET_i2s (target));
  peer = GNUNET_CONTAINER_multipeermap_get (sh->peers,
                                            target);
  if (NULL == peer)
  {
    GNUNET_break (0);
    return;
  }
  GNUNET_assert (NULL != sh->mq);
  env = GNUNET_MQ_msg_nested_mh (sm,
                                 GNUNET_MESSAGE_TYPE_DV_SEND,
                                 msg);
  sm->target = *target;
  GNUNET_MQ_send (sh->mq,
                  env);
}


/* end of dv_api.c */

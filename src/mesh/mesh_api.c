/*
     This file is part of GNUnet.
     (C) 2009, 2010 Christian Grothoff (and other contributing authors)

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
 * @file mesh/mesh_api.c
 * @brief mesh service; API for the Mesh. This is used to talk to arbitrary peers
 *        as of 2011-01Jan-06 this is a mockup.
 * @author Philipp Tölke
 */
#include <platform.h>
#include <gnunet_constants.h>
#include <gnunet_mesh_service.h>
#include <gnunet_core_service.h>
#include <gnunet_transport_service.h>
#include <gnunet_container_lib.h>
#include <gnunet_applications.h>

struct tunnel_id
{
  uint32_t id GNUNET_PACKED;
  struct GNUNET_PeerIdentity initiator;
  struct GNUNET_PeerIdentity target;
};

static uint32_t current_id = 0;

struct tunnel_message
{
  struct GNUNET_MessageHeader hdr;
  struct tunnel_id id;
  /* followed by another GNUNET_MessageHeader */
};

struct notify_cls
{
  void *notify_cls;
  GNUNET_CONNECTION_TransmitReadyNotify notify;
  struct GNUNET_MESH_Tunnel *tunnel;
};

struct GNUNET_MESH_Tunnel
{
  /* The other peer this tunnel leads to; just unicast for the moment! */
  struct GNUNET_PeerIdentity peer;

  struct tunnel_id id;

  /* The handlers and cls for outbound tunnels. Are NULL for inbound tunnels. */
  GNUNET_MESH_TunnelDisconnectHandler disconnect_handler;
  GNUNET_MESH_TunnelConnectHandler connect_handler;
  void *handler_cls;

  struct GNUNET_MESH_Handle *handle;

  /* The application-type requested for this tunnel. Is only needed for pending
   * by_tupe-tunnels
   */
  uint16_t application_type;

  struct GNUNET_MESH_TransmitHandle *notify_handle;

  /* The context of the receive-function. */
  void *ctx;

  /* A list, usable by application-code (for queues) */
  void *app_head;
  void *app_tail;

  /* A pointer, usable by application-code */
  void *app_data;
};

struct tunnel_list_element
{
  struct GNUNET_MESH_Tunnel tunnel;
  struct tunnel_list_element *next, *prev;
};

struct tunnel_list
{
  struct tunnel_list_element *head, *tail;
};

struct type_list_element
{
  GNUNET_MESH_ApplicationType type;
  struct type_list_element *next, *prev;
};

struct peer_list_element
{
  struct GNUNET_PeerIdentity peer;

  /* list of application-types */
  struct type_list_element *type_head, *type_tail;

  struct GNUNET_TRANSPORT_ATS_Information atsi;
  struct peer_list_element *next, *prev;

  /* The handle that sends the hellos to this peer */
  struct GNUNET_CORE_TransmitHandle *hello;

  GNUNET_SCHEDULER_TaskIdentifier sched;

  struct GNUNET_MESH_Handle *handle;
};

struct peer_list
{
  struct peer_list_element *head, *tail;
};

struct GNUNET_MESH_Handle
{
  struct GNUNET_CORE_Handle *core;
  struct GNUNET_TRANSPORT_Handle *transport;
  struct GNUNET_MESH_MessageHandler *handlers;
  struct GNUNET_PeerIdentity myself;
  unsigned int connected_to_core;
  struct peer_list connected_peers;
  struct tunnel_list established_tunnels;
  struct tunnel_list pending_tunnels;
  struct tunnel_list pending_by_type_tunnels;
  void *cls;
  GNUNET_MESH_TunnelEndHandler *cleaner;
  size_t hello_message_size;
  uint16_t *hello_message;
};

static void
send_end_connect (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  if ((tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN) != 0)
    return;

  struct GNUNET_MESH_Tunnel *tunnel = cls;

  tunnel->connect_handler (tunnel->handler_cls, NULL, NULL);
}

static void
send_self_connect (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  if ((tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN) != 0)
    return;

  struct GNUNET_MESH_Tunnel *tunnel = cls;

  tunnel->connect_handler (tunnel->handler_cls, &tunnel->handle->myself, NULL);
  GNUNET_SCHEDULER_add_now (send_end_connect, tunnel);
}

static void
call_connect_handler (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  if ((tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN) != 0)
    return;

  struct GNUNET_MESH_Tunnel *tunnel = cls;

  tunnel->connect_handler (tunnel->handler_cls, &tunnel->peer, NULL);
  GNUNET_SCHEDULER_add_now (send_end_connect, tunnel);
}

static void
core_startup (void *cls, struct GNUNET_CORE_Handle *core
              __attribute__ ((unused)),
              const struct GNUNET_PeerIdentity *my_identity)
{
  struct GNUNET_MESH_Handle *handle = cls;

  memcpy (&handle->myself, my_identity, sizeof (struct GNUNET_PeerIdentity));
  handle->connected_to_core = GNUNET_YES;
}

static size_t
send_hello_message (void *cls, size_t size, void *buf)
{
  if (cls == NULL)
    return 0;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Sending hello\n");

  struct peer_list_element *element = cls;
  struct GNUNET_MESH_Handle *handle = element->handle;

  element->hello = NULL;
  struct GNUNET_MessageHeader *hdr = buf;

  size_t sent =
      sizeof (struct GNUNET_MessageHeader) + handle->hello_message_size;

  if (sent > size)
    return 0;

  hdr->type = htons (GNUNET_MESSAGE_TYPE_MESH_HELLO);
  hdr->size = htons (size);

  memcpy (hdr + 1, handle->hello_message, handle->hello_message_size);
  return sent;
}

void
schedule_hello_message (void *cls,
                        const struct GNUNET_SCHEDULER_TaskContext *tctx)
{
  struct peer_list_element *element = cls;

  element->sched = GNUNET_SCHEDULER_NO_TASK;

  if ((tctx->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN) != 0)
    return;

  if (element->hello == NULL)
    element->hello =
        GNUNET_CORE_notify_transmit_ready (element->handle->core, GNUNET_NO, 42,
                                           GNUNET_TIME_UNIT_SECONDS,
                                           &element->peer,
                                           sizeof (struct GNUNET_MessageHeader)
                                           +
                                           element->handle->hello_message_size,
                                           &send_hello_message, element);

  element->sched =
      GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_MINUTES,
                                    schedule_hello_message, cls);
}


/**
 * Core calls this if we are connected to a new peer.
 *
 * The peer is added to the connected_peers-list.
 *
 */
static void
core_connect (void *cls, const struct GNUNET_PeerIdentity *peer,
              const struct GNUNET_TRANSPORT_ATS_Information *atsi)
{
  struct GNUNET_MESH_Handle *handle = cls;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Core tells us we are connected to peer %s\n", GNUNET_i2s (peer));

  /* put the new peer into the list of connected peers */
  struct peer_list_element *element =
      GNUNET_malloc (sizeof (struct peer_list_element));
  memcpy (&element->peer, peer, sizeof (struct GNUNET_PeerIdentity));
  element->handle = handle;

  /* Send a hello to this peer */
  element->sched = GNUNET_SCHEDULER_add_now (schedule_hello_message, element);

  if (NULL != atsi)
    memcpy (&element->atsi, atsi,
            sizeof (struct GNUNET_TRANSPORT_ATS_Information));

  GNUNET_CONTAINER_DLL_insert_after (handle->connected_peers.head,
                                     handle->connected_peers.tail,
                                     handle->connected_peers.tail, element);

  struct tunnel_list_element *tunnel = handle->pending_tunnels.head;

  while (tunnel != NULL)
  {
    if (0 ==
        memcmp (&tunnel->tunnel.peer, peer,
                sizeof (struct GNUNET_PeerIdentity)))
    {
      struct tunnel_list_element *next = tunnel->next;

      GNUNET_CONTAINER_DLL_remove (handle->pending_tunnels.head,
                                   handle->pending_tunnels.tail, tunnel);
      GNUNET_CONTAINER_DLL_insert_after (handle->established_tunnels.head,
                                         handle->established_tunnels.tail,
                                         handle->established_tunnels.tail,
                                         tunnel);
      tunnel->tunnel.connect_handler (tunnel->tunnel.handler_cls, peer, atsi);
      GNUNET_SCHEDULER_add_now (send_end_connect, tunnel);
      tunnel = next;
    }
    else
      tunnel = tunnel->next;
  }
}

/**
 * Core calls this if we disconnect a peer
 *
 * Remove this peer from the list of connected peers
 * Close all tunnels this peer belongs to
 */
static void
core_disconnect (void *cls, const struct GNUNET_PeerIdentity *peer)
{
  struct GNUNET_MESH_Handle *handle = cls;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Core tells us we are no longer connected to peer %s\n",
              GNUNET_i2s (peer));

  struct peer_list_element *element = handle->connected_peers.head;

  while (element != NULL)
  {
    if (0 == memcmp (&element->peer, peer, sizeof (struct GNUNET_PeerIdentity)))
      break;
    element = element->next;
  }
  if (element != NULL)
  {
    GNUNET_CONTAINER_DLL_remove (handle->connected_peers.head,
                                 handle->connected_peers.tail, element);
    while (element->type_head != NULL)
    {
      struct type_list_element *tail = element->type_tail;

      GNUNET_CONTAINER_DLL_remove (element->type_head, element->type_tail,
                                   tail);
      GNUNET_free (tail);
    }
    if (element->hello != NULL)
      GNUNET_CORE_notify_transmit_ready_cancel (element->hello);
    GNUNET_SCHEDULER_cancel (element->sched);
    GNUNET_free (element);
  }

  struct tunnel_list_element *telement = handle->established_tunnels.head;

  while (telement != NULL)
  {
    if (0 ==
        memcmp (&telement->tunnel.peer, peer,
                sizeof (struct GNUNET_PeerIdentity)))
    {
      /* disconnect tunnels */
      /* outbound tunnels */
      if (telement->tunnel.connect_handler != NULL &&
          NULL != telement->tunnel.disconnect_handler)
        telement->tunnel.disconnect_handler (telement->tunnel.handler_cls,
                                             peer);
      /* inbound tunnels */
      else if (NULL != handle->cleaner)
        handle->cleaner (handle->cls, &telement->tunnel, &telement->tunnel.ctx);

      struct tunnel_list_element *next = telement->next;

      GNUNET_CONTAINER_DLL_remove (handle->established_tunnels.head,
                                   handle->established_tunnels.tail, telement);
      GNUNET_free (telement);
      telement = next;
    }
    else
    {
      telement = telement->next;
    }
  }
}

/**
 * Receive a message from core.
 * This is a hello-message, containing the application-types the other peer can receive
 */
static int
receive_hello (void *cls, const struct GNUNET_PeerIdentity *other,
               const struct GNUNET_MessageHeader *message,
               const struct GNUNET_TRANSPORT_ATS_Information *atsi)
{
  struct GNUNET_MESH_Handle *handle = cls;
  uint16_t *num = (uint16_t *) (message + 1);
  GNUNET_MESH_ApplicationType *ports =
      (GNUNET_MESH_ApplicationType *) (num + 1);
  unsigned int i;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "The peer %s tells us he supports %d application-types.\n",
              GNUNET_i2s (other), ntohs (*num));

  struct peer_list_element *element = handle->connected_peers.head;

  while (element != NULL)
  {
    if (0 ==
        memcmp (&element->peer, other, sizeof (struct GNUNET_PeerIdentity)))
      break;
    element = element->next;
  }

  GNUNET_assert (NULL != element);

  for (i = 0; i < ntohs (*num); i++)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "The peer %s newly supports the application-type %d\n",
                GNUNET_i2s (other), ntohs (ports[i]));
    if (GNUNET_APPLICATION_TYPE_END == ntohs (ports[i]))
      continue;
    struct type_list_element *new_type = GNUNET_malloc (sizeof *new_type);

    new_type->type = (GNUNET_MESH_ApplicationType) ntohs (ports[i]);
    GNUNET_CONTAINER_DLL_insert (element->type_head, element->type_tail,
                                 new_type);
  }

  struct type_list_element *type;

  for (type = element->type_head; type != NULL; type = type->next)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "The peer %s supports the application-type %d\n",
                GNUNET_i2s (other), type->type);
  }

  struct tunnel_list_element *tunnel = handle->pending_by_type_tunnels.head;

  while (tunnel != NULL)
  {
    struct tunnel_list_element *next = tunnel->next;

    for (i = 0; i < ntohs (*num); i++)
    {
      if (ntohs (ports[i]) == tunnel->tunnel.application_type)
      {
        GNUNET_CONTAINER_DLL_remove (handle->pending_by_type_tunnels.head,
                                     handle->pending_by_type_tunnels.tail,
                                     tunnel);
        GNUNET_CONTAINER_DLL_insert_after (handle->established_tunnels.head,
                                           handle->established_tunnels.tail,
                                           handle->established_tunnels.tail,
                                           tunnel);
        memcpy (&tunnel->tunnel.peer, other,
                sizeof (struct GNUNET_PeerIdentity));
        tunnel->tunnel.connect_handler (tunnel->tunnel.handler_cls,
                                        &tunnel->tunnel.peer, atsi);
        GNUNET_SCHEDULER_add_now (send_end_connect, tunnel);
        break;
      }
    }
    if (ntohs (ports[i]) == tunnel->tunnel.application_type)
      tunnel = next;
    else
      tunnel = tunnel->next;
  }
  return GNUNET_OK;
}

/**
 * Receive a message from core.
 */
static int
core_receive (void *cls, const struct GNUNET_PeerIdentity *other,
              const struct GNUNET_MessageHeader *message,
              const struct GNUNET_TRANSPORT_ATS_Information *atsi)
{
  struct GNUNET_MESH_Handle *handle = cls;
  struct tunnel_message *tmessage = (struct tunnel_message *) message;
  struct GNUNET_MessageHeader *rmessage =
      (struct GNUNET_MessageHeader *) (tmessage + 1);

  struct GNUNET_MESH_MessageHandler *handler;

  for (handler = handle->handlers; handler->callback != NULL; handler++)
  {
    if ((ntohs (rmessage->type) == handler->type) &&
        ((handler->expected_size == 0) ||
         (handler->expected_size == ntohs (rmessage->size))))
    {
      break;
    }
  }

  /* handler->callback handles this message */

  /* If no handler was found, drop the message but keep the channel open */
  if (handler->callback == NULL)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Received message of type %d from peer %s; dropping it.\n",
                ntohs (rmessage->type), GNUNET_i2s (other));
    return GNUNET_OK;
  }

  struct tunnel_list_element *tunnel = handle->established_tunnels.head;

  while (tunnel != NULL)
  {
    if (tunnel->tunnel.id.id == tmessage->id.id &&
        (0 ==
         memcmp (&tmessage->id.initiator, &tunnel->tunnel.id.initiator,
                 sizeof (struct GNUNET_PeerIdentity))) &&
        (0 ==
         memcmp (&tmessage->id.target, &tunnel->tunnel.id.target,
                 sizeof (struct GNUNET_PeerIdentity))))
      break;
    tunnel = tunnel->next;
  }

  /* if no tunnel was found: create a new inbound tunnel */
  if (tunnel == NULL)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "New inbound tunnel from peer %s; first message has type %d.\n",
                GNUNET_i2s (other), ntohs (rmessage->type));
    tunnel = GNUNET_malloc (sizeof (struct tunnel_list_element));
    tunnel->tunnel.connect_handler = NULL;
    tunnel->tunnel.disconnect_handler = NULL;
    tunnel->tunnel.handler_cls = NULL;
    tunnel->tunnel.ctx = NULL;
    tunnel->tunnel.handle = handle;
    memcpy (&tunnel->tunnel.peer, other, sizeof (struct GNUNET_PeerIdentity));
    memcpy (&tunnel->tunnel.id, &tmessage->id, sizeof (struct tunnel_id));

    GNUNET_CONTAINER_DLL_insert_after (handle->established_tunnels.head,
                                       handle->established_tunnels.tail,
                                       handle->established_tunnels.tail,
                                       tunnel);
  }
  else
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Inbound message from peer %s; type %d.\n", GNUNET_i2s (other),
                ntohs (rmessage->type));

  return handler->callback (handle->cls, &tunnel->tunnel, &tunnel->tunnel.ctx,
                            other, rmessage, atsi);
}

struct GNUNET_MESH_Tunnel *
GNUNET_MESH_peer_request_connect_by_type (struct GNUNET_MESH_Handle *handle,
                                          struct GNUNET_TIME_Relative timeout,
                                          GNUNET_MESH_ApplicationType
                                          application_type,
                                          GNUNET_MESH_TunnelConnectHandler
                                          connect_handler,
                                          GNUNET_MESH_TunnelDisconnectHandler
                                          disconnect_handler, void *handler_cls)
{
  /* Look in the list of connected peers */
  struct peer_list_element *element = handle->connected_peers.head;

  while (element != NULL)
  {
    struct type_list_element *i;

    for (i = element->type_head; i != NULL; i = i->next)
      if (application_type == i->type)
        return GNUNET_MESH_peer_request_connect_all (handle, timeout, 1,
                                                     &element->peer,
                                                     connect_handler,
                                                     disconnect_handler,
                                                     handler_cls);
    element = element->next;
  }

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Trying to connect by tupe %d.\n",
              application_type);

  /* Put into pending list */
  struct tunnel_list_element *tunnel =
      GNUNET_malloc (sizeof (struct tunnel_list_element));

  tunnel->tunnel.connect_handler = connect_handler;
  tunnel->tunnel.disconnect_handler = disconnect_handler;
  tunnel->tunnel.handler_cls = handler_cls;
  tunnel->tunnel.ctx = NULL;
  tunnel->tunnel.handle = handle;
  memcpy (&tunnel->tunnel.id.initiator, &handle->myself,
          sizeof (struct GNUNET_PeerIdentity));
  tunnel->tunnel.id.id = current_id++;
  tunnel->tunnel.application_type = application_type;

  GNUNET_CONTAINER_DLL_insert_after (handle->pending_by_type_tunnels.head,
                                     handle->pending_by_type_tunnels.tail,
                                     handle->pending_by_type_tunnels.tail,
                                     tunnel);
  return &tunnel->tunnel;
}



struct GNUNET_MESH_Tunnel *
GNUNET_MESH_peer_request_connect_all (struct GNUNET_MESH_Handle *handle,
                                      struct GNUNET_TIME_Relative timeout,
                                      unsigned int num_peers,
                                      const struct GNUNET_PeerIdentity *peers,
                                      GNUNET_MESH_TunnelConnectHandler
                                      connect_handler,
                                      GNUNET_MESH_TunnelDisconnectHandler
                                      disconnect_handler, void *handler_cls)
{
  if (num_peers != 1)
    return NULL;

  struct tunnel_list_element *tunnel =
      GNUNET_malloc (sizeof (struct tunnel_list_element));

  tunnel->tunnel.connect_handler = connect_handler;
  tunnel->tunnel.disconnect_handler = disconnect_handler;
  tunnel->tunnel.handler_cls = handler_cls;
  tunnel->tunnel.ctx = NULL;
  tunnel->tunnel.handle = handle;
  memcpy (&tunnel->tunnel.id.initiator, &handle->myself,
          sizeof (struct GNUNET_PeerIdentity));
  memcpy (&tunnel->tunnel.id.target, peers,
          sizeof (struct GNUNET_PeerIdentity));
  tunnel->tunnel.id.id = current_id++;
  memcpy (&tunnel->tunnel.peer, peers, sizeof (struct GNUNET_PeerIdentity));

  struct peer_list_element *element = handle->connected_peers.head;

  while (element != NULL)
  {
    if (0 ==
        memcmp (&element->peer, peers, sizeof (struct GNUNET_PeerIdentity)))
      break;
    element = element->next;
  }

  if (element != NULL)
  {
    /* we are connected to this peer */
    GNUNET_CONTAINER_DLL_insert_after (handle->established_tunnels.head,
                                       handle->established_tunnels.tail,
                                       handle->established_tunnels.tail,
                                       tunnel);
    GNUNET_SCHEDULER_add_now (call_connect_handler, tunnel);
  }
  else if (0 ==
           memcmp (peers, &handle->myself, sizeof (struct GNUNET_PeerIdentity)))
  {
    /* we are the peer */
    GNUNET_CONTAINER_DLL_insert_after (handle->established_tunnels.head,
                                       handle->established_tunnels.tail,
                                       handle->established_tunnels.tail,
                                       tunnel);
    GNUNET_SCHEDULER_add_now (send_self_connect, tunnel);
  }
  else
  {
    /* we are not connected to this peer */
    GNUNET_CONTAINER_DLL_insert_after (handle->pending_tunnels.head,
                                       handle->pending_tunnels.tail,
                                       handle->pending_tunnels.tail, tunnel);
    GNUNET_TRANSPORT_try_connect (handle->transport, peers);
  }

  return &tunnel->tunnel;
}

const struct GNUNET_PeerIdentity *
GNUNET_MESH_get_peer (const struct GNUNET_MESH_Tunnel *tunnel)
{
  return &tunnel->peer;
}

static size_t
core_notify (void *cls, size_t size, void *buf)
{
  struct notify_cls *ncls = cls;
  struct GNUNET_MESH_Tunnel *tunnel = ncls->tunnel;

  if (NULL == buf)
    return ncls->notify (ncls->notify_cls, 0, NULL);

  tunnel->notify_handle = NULL;
  struct tunnel_message *message = buf;
  void *cbuf = (void *) &message[1];

  GNUNET_assert (NULL != ncls->notify);

  size_t sent =
      ncls->notify (ncls->notify_cls, size - sizeof (struct tunnel_message),
                    cbuf);

  GNUNET_free (ncls);

  if (0 == sent)
    return 0;

  sent += sizeof (struct tunnel_message);

  message->hdr.type = htons (GNUNET_MESSAGE_TYPE_MESH);
  message->hdr.size = htons (sent);
  memcpy (&message->id, &tunnel->id, sizeof (struct tunnel_id));
  return sent;
}


/**
 * Ask the mesh to call "notify" once it is ready to transmit the
 * given number of bytes to the specified "target".  If we are not yet
 * connected to the specified peer, a call to this function will cause
 * us to try to establish a connection.
 *
 * @param tunnel tunnel to use for transmission
 * @param cork is corking allowed for this transmission?
 * @param priority how important is the message?
 * @param maxdelay how long can the message wait?
 * @param target destination for the message, NULL for multicast to all tunnel targets
 * @param notify_size how many bytes of buffer space does notify want?
 * @param notify function to call when buffer space is available;
 *        will be called with NULL on timeout or if the overall queue
 *        for this peer is larger than queue_size and this is currently
 *        the message with the lowest priority
 * @param notify_cls closure for notify
 * @return non-NULL if the notify callback was queued,
 *         NULL if we can not even queue the request (insufficient
 *         memory); if NULL is returned, "notify" will NOT be called.
 */
struct GNUNET_MESH_TransmitHandle *
GNUNET_MESH_notify_transmit_ready (struct GNUNET_MESH_Tunnel *tunnel, int cork,
                                   uint32_t priority,
                                   struct GNUNET_TIME_Relative maxdelay,
                                   const struct GNUNET_PeerIdentity *target
                                   __attribute__ ((unused)), size_t notify_size,
                                   GNUNET_CONNECTION_TransmitReadyNotify notify,
                                   void *notify_cls)
{
  if (NULL != tunnel->notify_handle)
  {
    GNUNET_break (0);
    return NULL;
  }

  struct notify_cls *cls = GNUNET_malloc (sizeof (struct notify_cls));

  cls->notify_cls = notify_cls;
  GNUNET_assert (NULL != notify);
  cls->notify = notify;
  cls->tunnel = tunnel;

  tunnel->notify_handle =
      (struct GNUNET_MESH_TransmitHandle *)
      GNUNET_CORE_notify_transmit_ready (tunnel->handle->core, cork, priority,
                                         maxdelay, &tunnel->peer,
                                         notify_size +
                                         sizeof (struct tunnel_message),
                                         &core_notify, (void *) cls);

  return tunnel->notify_handle;
}

void
GNUNET_MESH_notify_transmit_ready_cancel (struct GNUNET_MESH_TransmitHandle *th)
{
  GNUNET_CORE_notify_transmit_ready_cancel ((struct GNUNET_CORE_TransmitHandle
                                             *) th);
}

void
GNUNET_MESH_tunnel_set_head (struct GNUNET_MESH_Tunnel *tunnel, void *head)
{
  tunnel->app_head = head;
}

void
GNUNET_MESH_tunnel_set_tail (struct GNUNET_MESH_Tunnel *tunnel, void *tail)
{
  tunnel->app_tail = tail;
}

void *
GNUNET_MESH_tunnel_get_head (struct GNUNET_MESH_Tunnel *tunnel)
{
  return tunnel->app_head;
}

void *
GNUNET_MESH_tunnel_get_tail (struct GNUNET_MESH_Tunnel *tunnel)
{
  return tunnel->app_head;
}

void
GNUNET_MESH_tunnel_set_data (struct GNUNET_MESH_Tunnel *tunnel, void *data)
{
  tunnel->app_data = data;
}

void *
GNUNET_MESH_tunnel_get_data (struct GNUNET_MESH_Tunnel *tunnel)
{
  return tunnel->app_data;
}


void
build_hello_message (struct GNUNET_MESH_Handle *handle,
                     const GNUNET_MESH_ApplicationType *stypes)
{
  int num = 0;
  const GNUNET_MESH_ApplicationType *t;

  for (t = stypes; *t != GNUNET_APPLICATION_TYPE_END; t++, num++) ;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "I can handle %d app-types.\n", num);

  handle->hello_message_size = sizeof (uint16_t) +      /* For the number of types */
      num * sizeof (GNUNET_MESH_ApplicationType);       /* For the types */

  uint16_t *nums = GNUNET_malloc (handle->hello_message_size);
  GNUNET_MESH_ApplicationType *types =
      (GNUNET_MESH_ApplicationType *) (nums + 1);

  *nums = htons (num);

  int i;

  for (i = 0; i < num; i++)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "I can handle the app-type %d\n",
                stypes[i]);
    types[i] = htons (stypes[i]);
  }

  handle->hello_message = nums;
}


struct GNUNET_MESH_Handle *
GNUNET_MESH_connect (const struct GNUNET_CONFIGURATION_Handle *cfg, void *cls,
                     GNUNET_MESH_TunnelEndHandler cleaner,
                     const struct GNUNET_MESH_MessageHandler *handlers,
                     const GNUNET_MESH_ApplicationType *stypes)
{
  struct GNUNET_MESH_Handle *ret =
      GNUNET_malloc (sizeof (struct GNUNET_MESH_Handle));

  ret->connected_to_core = GNUNET_NO;
  ret->connected_peers.head = NULL;
  ret->connected_peers.tail = NULL;
  ret->cleaner = cleaner;
  ret->cls = cls;

  const struct GNUNET_MESH_MessageHandler *it;
  unsigned int len = 1;

  for (it = handlers; it->callback != NULL; it++)
  {
    len++;
  }

  ret->handlers =
      GNUNET_malloc (len * sizeof (struct GNUNET_MESH_MessageHandler));
  memset (ret->handlers, 0, len * sizeof (struct GNUNET_MESH_MessageHandler));
  memcpy (ret->handlers, handlers,
          len * sizeof (struct GNUNET_MESH_MessageHandler));

  build_hello_message (ret, stypes);

  static const struct GNUNET_CORE_MessageHandler core_handlers[] = {
    {&core_receive, GNUNET_MESSAGE_TYPE_MESH, 0},
    {&receive_hello, GNUNET_MESSAGE_TYPE_MESH_HELLO, 0},
    {NULL, 0, 0}
  };

  ret->core =
      GNUNET_CORE_connect (cfg, 42, ret, &core_startup, &core_connect,
                           &core_disconnect, NULL, GNUNET_NO, NULL,
                           GNUNET_NO, core_handlers);
  ret->transport =
    GNUNET_TRANSPORT_connect (cfg, NULL, NULL, NULL, NULL, NULL);
  return ret;
}

void
GNUNET_MESH_disconnect (struct GNUNET_MESH_Handle *handle)
{
  GNUNET_free (handle->handlers);
  GNUNET_free (handle->hello_message);
  GNUNET_CORE_disconnect (handle->core);
  GNUNET_TRANSPORT_disconnect (handle->transport);

  struct peer_list_element *element = handle->connected_peers.head;

  while (element != NULL)
  {
    struct peer_list_element *next = element->next;

    while (element->type_head != NULL)
    {
      struct type_list_element *tail = element->type_tail;

      GNUNET_CONTAINER_DLL_remove (element->type_head, element->type_tail,
                                   tail);
      GNUNET_free (tail);
    }
    GNUNET_CORE_notify_transmit_ready_cancel (element->hello);
    GNUNET_SCHEDULER_cancel (element->sched);
    GNUNET_free (element);
    element = next;
  }

  struct tunnel_list_element *tunnel = handle->pending_tunnels.head;

  while (tunnel != NULL)
  {
    struct tunnel_list_element *next = tunnel->next;

    GNUNET_free (tunnel);
    tunnel = next;
  }
  tunnel = handle->established_tunnels.head;;
  while (tunnel != NULL)
  {
    struct tunnel_list_element *next = tunnel->next;

    GNUNET_free (tunnel);
    tunnel = next;
  }

  GNUNET_free (handle);
}

/* end of mesh_api.c */

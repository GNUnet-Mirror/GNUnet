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
 * @file mesh/mesh_api.c
 * @brief mesh api: client implementation of mesh service
 * @author Bartlomiej Polot
 *
 * STRUCTURE:
 * - CONSTANTS
 * - DATA STRUCTURES
 * - AUXILIARY FUNCTIONS
 * - RECEIVE HANDLERS
 * - SEND FUNCTIONS
 * - API CALL DEFINITIONS
 */
#ifdef __cplusplus
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif

#include "platform.h"
#include "gnunet_common.h"
#include "gnunet_client_lib.h"
#include "gnunet_util_lib.h"
#include "gnunet_peer_lib.h"
#include "gnunet_mesh_service.h"
#include "mesh.h"
#include "mesh_protocol.h"

#define MESH_API_DEBUG GNUNET_YES

#if MESH_API_DEBUG
#define LOG(kind,...) GNUNET_log_from (kind, "mesh-api",__VA_ARGS__)
#else
#define LOG(kind,...)
#endif

/******************************************************************************/
/************************      DATA STRUCTURES     ****************************/
/******************************************************************************/

/**
 * Transmission queue to the service
 */
struct GNUNET_MESH_TransmitHandle
{

    /**
     * Double Linked list
     */
  struct GNUNET_MESH_TransmitHandle *next;

    /**
     * Double Linked list
     */
  struct GNUNET_MESH_TransmitHandle *prev;

    /**
     * Tunnel this message is sent on / for (may be NULL for control messages).
     */
  struct GNUNET_MESH_Tunnel *tunnel;

    /**
     * Callback to obtain the message to transmit, or NULL if we
     * got the message in 'data'.  Notice that messages built
     * by 'notify' need to be encapsulated with information about
     * the 'target'.
     */
  GNUNET_CONNECTION_TransmitReadyNotify notify;

    /**
     * Closure for 'notify'
     */
  void *notify_cls;

    /**
     * How long is this message valid.  Once the timeout has been
     * reached, the message must no longer be sent.  If this
     * is a message with a 'notify' callback set, the 'notify'
     * function should be called with 'buf' NULL and size 0.
     */
  struct GNUNET_TIME_Absolute timeout;

    /**
     * Task triggering a timeout, can be NO_TASK if the timeout is FOREVER.
     */
  GNUNET_SCHEDULER_TaskIdentifier timeout_task;

    /**
     * Priority of the message.  The queue is sorted by priority,
     * control messages have the maximum priority (UINT32_MAX).
     */
  uint32_t priority;

    /**
     * Target of the message, 0 for multicast.  This field
     * is only valid if 'notify' is non-NULL.
     */
  GNUNET_PEER_Id target;

    /**
     * Size of 'data' -- or the desired size of 'notify' if 'data' is NULL.
     */
  size_t size;
};


/**
 * Opaque handle to the service.
 */
struct GNUNET_MESH_Handle
{

    /**
     * Handle to the server connection, to send messages later
     */
  struct GNUNET_CLIENT_Connection *client;

    /**
     * Set of handlers used for processing incoming messages in the tunnels
     */
  const struct GNUNET_MESH_MessageHandler *message_handlers;

    /**
     * Set of applications that should be claimed to be offered at this node.
     * Note that this is just informative, the appropiate handlers must be
     * registered independently and the mapping is up to the developer of the
     * client application.
     */
  const GNUNET_MESH_ApplicationType *applications;

    /**
     * Double linked list of the tunnels this client is connected to.
     */
  struct GNUNET_MESH_Tunnel *tunnels_head;
  struct GNUNET_MESH_Tunnel *tunnels_tail;

    /**
     * Callback for inbound tunnel creation
     */
  GNUNET_MESH_InboundTunnelNotificationHandler *new_tunnel;

    /**
     * Callback for inbound tunnel disconnection
     */
  GNUNET_MESH_TunnelEndHandler *cleaner;

    /**
     * Handle to cancel pending transmissions in case of disconnection
     */
  struct GNUNET_CLIENT_TransmitHandle *th;

    /**
     * Closure for all the handlers given by the client
     */
  void *cls;

    /**
     * Messages to send to the service
     */
  struct GNUNET_MESH_TransmitHandle *th_head;
  struct GNUNET_MESH_TransmitHandle *th_tail;

    /**
     * tid of the next tunnel to create (to avoid reusing IDs often)
     */
  MESH_TunnelNumber next_tid;
  unsigned int n_handlers;
  unsigned int n_applications;
  unsigned int max_queue_size;

    /**
     * Have we started the task to receive messages from the service
     * yet? We do this after we send the 'MESH_LOCAL_CONNECT' message.
     */
  int in_receive;

    /**
     * Number of packets queued
     */
  unsigned int npackets;

  /**
   * Configuration given by the client, in case of reconnection
   */
  const struct GNUNET_CONFIGURATION_Handle *cfg;

  /**
   * Time to the next reconnect in case one reconnect fails
   */
  struct GNUNET_TIME_Relative reconnect_time;
  
  /**
   * Task for trying to reconnect.
   */
  GNUNET_SCHEDULER_TaskIdentifier reconnect_task;
};


/**
 * Description of a peer
 */
struct GNUNET_MESH_Peer
{
    /**
     * ID of the peer in short form
     */
  GNUNET_PEER_Id id;

  /**
   * Tunnel this peer belongs to
   */
  struct GNUNET_MESH_Tunnel *t;

  /**
   * Flag indicating whether service has informed about its connection
   */
  int connected;

};


/**
 * Opaque handle to a tunnel.
 */
struct GNUNET_MESH_Tunnel
{

    /**
     * DLL
     */
  struct GNUNET_MESH_Tunnel *next;
  struct GNUNET_MESH_Tunnel *prev;

    /**
     * Callback to execute when peers connect to the tunnel
     */
  GNUNET_MESH_PeerConnectHandler connect_handler;

    /**
     * Callback to execute when peers disconnect from the tunnel
     */
  GNUNET_MESH_PeerDisconnectHandler disconnect_handler;

    /**
     * Closure for the connect/disconnect handlers
     */
  void *cls;

    /**
     * Handle to the mesh this tunnel belongs to
     */
  struct GNUNET_MESH_Handle *mesh;

    /**
     * Local ID of the tunnel
     */
  MESH_TunnelNumber tid;

    /**
     * Owner of the tunnel. 0 if the tunnel is the local client.
     */
  GNUNET_PEER_Id owner;

    /**
     * All peers added to the tunnel
     */
  struct GNUNET_MESH_Peer **peers;

  /**
   * List of application types that have been requested for this tunnel
   */
  GNUNET_MESH_ApplicationType *apps;

  /**
   * Any data the caller wants to put in here
   */
  void *ctx;

  /**
     * Number of peers added to the tunnel
     */
  unsigned int npeers;

    /**
     * Number of packets queued in this tunnel
     */
  unsigned int npackets;

    /**
     * Number of applications requested this tunnel
     */
  unsigned int napps;

};


/******************************************************************************/
/***********************     AUXILIARY FUNCTIONS      *************************/
/******************************************************************************/

/**
 * Get the tunnel handler for the tunnel specified by id from the given handle
 * @param h Mesh handle
 * @param tid ID of the wanted tunnel
 * @return handle to the required tunnel or NULL if not found
 */
static struct GNUNET_MESH_Tunnel *
retrieve_tunnel (struct GNUNET_MESH_Handle *h, MESH_TunnelNumber tid)
{
  struct GNUNET_MESH_Tunnel *t;

  t = h->tunnels_head;
  while (t != NULL)
  {
    if (t->tid == tid)
      return t;
    t = t->next;
  }
  return NULL;
}


/**
 * Create a new tunnel and insert it in the tunnel list of the mesh handle
 * @param h Mesh handle
 * @param tid desired tid of the tunnel, 0 to assign one automatically
 * @return handle to the created tunnel
 */
static struct GNUNET_MESH_Tunnel *
create_tunnel (struct GNUNET_MESH_Handle *h, MESH_TunnelNumber tid)
{
  struct GNUNET_MESH_Tunnel *t;

  t = GNUNET_malloc (sizeof (struct GNUNET_MESH_Tunnel));
  GNUNET_CONTAINER_DLL_insert (h->tunnels_head, h->tunnels_tail, t);
  t->mesh = h;
  if (0 == tid)
  {
    t->tid = h->next_tid;
    while (NULL != retrieve_tunnel (h, h->next_tid))
    {
      h->next_tid++;
      h->next_tid &= ~GNUNET_MESH_LOCAL_TUNNEL_ID_SERV;
      h->next_tid |= GNUNET_MESH_LOCAL_TUNNEL_ID_CLI;
    }
  }
  else
  {
    t->tid = tid;
  }
  return t;
}


/**
 * Destroy the specified tunnel.
 * - Destroys all peers, calling the disconnect callback on each if needed
 * - Cancels all outgoing traffic for that tunnel, calling respective notifys
 * - Calls cleaner if tunnel was inbound
 * - Frees all memory used
 *
 * @param t Pointer to the tunnel.
 * @param call_cleaner Whether to call the cleaner handler.
 *
 * @return Handle to the required tunnel or NULL if not found.
 */
static void
destroy_tunnel (struct GNUNET_MESH_Tunnel *t, int call_cleaner)
{
  struct GNUNET_MESH_Handle *h;
  struct GNUNET_PeerIdentity pi;
  struct GNUNET_MESH_TransmitHandle *th;
  struct GNUNET_MESH_TransmitHandle *next;
  unsigned int i;

  if (NULL == t)
  {
    GNUNET_break (0);
    return;
  }
  h = t->mesh;

  /* disconnect all peers */
  GNUNET_CONTAINER_DLL_remove (h->tunnels_head, h->tunnels_tail, t);
  for (i = 0; i < t->npeers; i++)
  {
    if ( (NULL != t->disconnect_handler) && t->peers[i]->connected)
    {
      GNUNET_PEER_resolve (t->peers[i]->id, &pi);
      t->disconnect_handler (t->cls, &pi);
    }
    GNUNET_PEER_change_rc (t->peers[i]->id, -1);
    GNUNET_free (t->peers[i]);
  }

  /* signal tunnel destruction */
  if ( (NULL != h->cleaner) && (0 != t->owner) && (GNUNET_YES == call_cleaner) )
    h->cleaner (h->cls, t, t->ctx);

  /* check that clients did not leave messages behind in the queue */
  for (th = h->th_head; NULL != th; th = next)
  {
    next = th->next;
    if (th->tunnel != t)
      continue;
    /* Clients should have aborted their requests already.
     * Management traffic should be ok, as clients can't cancel that */
    GNUNET_break (NULL == th->notify);
    GNUNET_CONTAINER_DLL_remove (h->th_head, h->th_tail, th);

    /* clean up request */
    if (GNUNET_SCHEDULER_NO_TASK != th->timeout_task)
      GNUNET_SCHEDULER_cancel (th->timeout_task);
    GNUNET_free (th);    
  }

  /* if there are no more pending requests with mesh service, cancel active request */
  /* Note: this should be unnecessary... */
  if ( (NULL == h->th_head) && (NULL != h->th))
  {
    GNUNET_CLIENT_notify_transmit_ready_cancel (h->th);
    h->th = NULL;
  }


  if (t->npeers > 0)
    GNUNET_free (t->peers);
  if (0 != t->owner)
    GNUNET_PEER_change_rc (t->owner, -1);
  if (0 != t->napps && t->apps)
    GNUNET_free (t->apps);
  GNUNET_free (t);
  return;
}


/**
 * Get the peer descriptor for the peer with id from the given tunnel
 * @param t Tunnel handle
 * @param id Short form ID of the wanted peer
 * @return handle to the requested peer or NULL if not found
 */
static struct GNUNET_MESH_Peer *
retrieve_peer (struct GNUNET_MESH_Tunnel *t, GNUNET_PEER_Id id)
{
  unsigned int i;

  for (i = 0; i < t->npeers; i++)
    if (t->peers[i]->id == id)
      return t->peers[i];
  return NULL;
}


/**
 * Add a peer into a tunnel
 * @param t Tunnel handle
 * @param pi Full ID of the new peer
 * @return handle to the newly created peer
 */
static struct GNUNET_MESH_Peer *
add_peer_to_tunnel (struct GNUNET_MESH_Tunnel *t,
                    const struct GNUNET_PeerIdentity *pi)
{
  struct GNUNET_MESH_Peer *p;
  GNUNET_PEER_Id id;

  if (0 != t->owner)
  {
    GNUNET_break (0);
    return NULL;
  }
  id = GNUNET_PEER_intern (pi);

  p = GNUNET_malloc (sizeof (struct GNUNET_MESH_Peer));
  p->id = id;
  p->t = t;
  GNUNET_array_append (t->peers, t->npeers, p);
  return p;
}


/**
 * Remove a peer from a tunnel
 * @param p Peer handle
 */
static void
remove_peer_from_tunnel (struct GNUNET_MESH_Peer *p)
{
  unsigned int i;

  for (i = 0; i < p->t->npeers; i++)
  {
    if (p->t->peers[i] == p)
      break;
  }
  if (i == p->t->npeers)
  {
    GNUNET_break (0);
    return;
  }
  p->t->peers[i] = p->t->peers[p->t->npeers - 1];
  GNUNET_array_grow (p->t->peers, p->t->npeers, p->t->npeers - 1);
}


/**
 * Notify client that the transmission has timed out
 * @param cls closure
 * @param tc task context
 */
static void
timeout_transmission (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_MESH_TransmitHandle *th = cls;
  struct GNUNET_MESH_Handle *mesh;

  mesh = th->tunnel->mesh;
  GNUNET_CONTAINER_DLL_remove (mesh->th_head, mesh->th_tail, th);
  if (th->notify != NULL)
    th->notify (th->notify_cls, 0, NULL);
  GNUNET_free (th);
  if ((NULL == mesh->th_head) && (NULL != mesh->th))
  {
    /* queue empty, no point in asking for transmission */
    GNUNET_CLIENT_notify_transmit_ready_cancel (mesh->th);
    mesh->th = NULL;
  }
}


/**
 * Add a transmit handle to the transmission queue by priority and set the
 * timeout if needed.
 *
 * @param h mesh handle with the queue head and tail
 * @param th handle to the packet to be transmitted
 */
static void
add_to_queue (struct GNUNET_MESH_Handle *h,
              struct GNUNET_MESH_TransmitHandle *th)
{
  struct GNUNET_MESH_TransmitHandle *p;

  p = h->th_head;
  while ((NULL != p) && (th->priority <= p->priority))
    p = p->next;
  if (NULL == p)
    p = h->th_tail;
  else
    p = p->prev;
  GNUNET_CONTAINER_DLL_insert_after (h->th_head, h->th_tail, p, th);
  if (GNUNET_TIME_UNIT_FOREVER_ABS.abs_value == th->timeout.abs_value)
    return;
  th->timeout_task =
      GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_absolute_get_remaining
                                    (th->timeout), &timeout_transmission, th);
}


/**
 * Auxiliary function to send an already constructed packet to the service.
 * Takes care of creating a new queue element, copying the message and
 * calling the tmt_rdy function if necessary.
 *
 * @param h mesh handle
 * @param msg message to transmit
 * @param tunnel tunnel this send is related to (NULL if N/A)
 */
static void
send_packet (struct GNUNET_MESH_Handle *h,
             const struct GNUNET_MessageHeader *msg,
             struct GNUNET_MESH_Tunnel *tunnel);


/**
 * Reconnect callback: tries to reconnect again after a failer previous
 * reconnecttion
 * @param cls closure (mesh handle)
 * @param tc task context
 */
static void
reconnect_cbk (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc);


/**
 * Send a connect packet to the service with the applications and types
 * requested by the user.
 *
 * @param h The mesh handle.
 *
 */
static void
send_connect (struct GNUNET_MESH_Handle *h)
{
  size_t size;

  size = sizeof (struct GNUNET_MESH_ClientConnect);
  size += h->n_applications * sizeof (GNUNET_MESH_ApplicationType);
  size += h->n_handlers * sizeof (uint16_t);
  {
    char buf[size];
    struct GNUNET_MESH_ClientConnect *msg;
    GNUNET_MESH_ApplicationType *apps;
    uint16_t napps;
    uint16_t *types;
    uint16_t ntypes;

    /* build connection packet */
    msg = (struct GNUNET_MESH_ClientConnect *) buf;
    msg->header.type = htons (GNUNET_MESSAGE_TYPE_MESH_LOCAL_CONNECT);
    msg->header.size = htons (size);
    apps = (GNUNET_MESH_ApplicationType *) &msg[1];
    for (napps = 0; napps < h->n_applications; napps++)
    {
      apps[napps] = htonl (h->applications[napps]);
      LOG (GNUNET_ERROR_TYPE_DEBUG, " app %u\n", h->applications[napps]);
    }
    types = (uint16_t *) & apps[napps];
    for (ntypes = 0; ntypes < h->n_handlers; ntypes++)
      types[ntypes] = htons (h->message_handlers[ntypes].type);
    msg->applications = htons (napps);
    msg->types = htons (ntypes);
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Sending %lu bytes long message %d types and %d apps\n",
         ntohs (msg->header.size), ntypes, napps);
    send_packet (h, &msg->header, NULL);
  }
}


/**
 * Reconnect to the service, retransmit all infomation to try to restore the
 * original state.
 *
 * @param h handle to the mesh
 *
 * @return GNUNET_YES in case of sucess, GNUNET_NO otherwise (service down...)
 */
static int
do_reconnect (struct GNUNET_MESH_Handle *h)
{
  struct GNUNET_MESH_Tunnel *t;
  unsigned int i;

  LOG (GNUNET_ERROR_TYPE_DEBUG, "*****************************\n");
  LOG (GNUNET_ERROR_TYPE_DEBUG, "*******   RECONNECT   *******\n");
  LOG (GNUNET_ERROR_TYPE_DEBUG, "*****************************\n");

  h->in_receive = GNUNET_NO;
  /* disconnect */
  if (NULL != h->th)
  {
    GNUNET_CLIENT_notify_transmit_ready_cancel (h->th);
    h->th = NULL;
  }
  if (NULL != h->client)
  {
    GNUNET_CLIENT_disconnect (h->client, GNUNET_NO);
  }

  /* connect again */
  h->client = GNUNET_CLIENT_connect ("mesh", h->cfg);
  if (h->client == NULL)
  {
    h->reconnect_task = GNUNET_SCHEDULER_add_delayed (h->reconnect_time,
                                                      &reconnect_cbk, h);
    h->reconnect_time =
        GNUNET_TIME_relative_min (GNUNET_TIME_UNIT_SECONDS,
                                  GNUNET_TIME_relative_multiply
                                  (h->reconnect_time, 2));
    LOG (GNUNET_ERROR_TYPE_DEBUG, "  Next retry in %sms\n",
         GNUNET_TIME_relative_to_string (h->reconnect_time));
    GNUNET_break (0);
    return GNUNET_NO;
  }
  else
  {
    h->reconnect_time = GNUNET_TIME_UNIT_MILLISECONDS;
  }
  send_connect (h);
  /* Rebuild all tunnels */
  for (t = h->tunnels_head; NULL != t; t = t->next)
  {
    struct GNUNET_MESH_TunnelMessage tmsg;
    struct GNUNET_MESH_PeerControl pmsg;

    if (t->tid >= GNUNET_MESH_LOCAL_TUNNEL_ID_SERV)
    {
      /* Tunnel was created by service (incoming tunnel) */
      /* TODO: Notify service of missing tunnel, to request
       * creator to recreate path (find a path to him via DHT?)
       */
      continue;
    }
    tmsg.header.type = htons (GNUNET_MESSAGE_TYPE_MESH_LOCAL_TUNNEL_CREATE);
    tmsg.header.size = htons (sizeof (struct GNUNET_MESH_TunnelMessage));
    tmsg.tunnel_id = htonl (t->tid);
    send_packet (h, &tmsg.header, t);

    pmsg.header.size = htons (sizeof (struct GNUNET_MESH_PeerControl));
    pmsg.header.type = htons (GNUNET_MESSAGE_TYPE_MESH_LOCAL_PEER_ADD);
    pmsg.tunnel_id = htonl (t->tid);

    /* Reconnect all peers */
    for (i = 0; i < t->npeers; i++)
    {
      GNUNET_PEER_resolve (t->peers[i]->id, &pmsg.peer);
      if (NULL != t->disconnect_handler && t->peers[i]->connected)
        t->disconnect_handler (t->cls, &pmsg.peer);
      /* If the tunnel was "by type", dont connect individual peers */
      if (0 == t->napps)
        send_packet (t->mesh, &pmsg.header, t);
    }
    /* Reconnect all types, if any  */
    for (i = 0; i < t->napps; i++)
    {
      struct GNUNET_MESH_ConnectPeerByType msg;

      msg.header.size = htons (sizeof (struct GNUNET_MESH_ConnectPeerByType));
      msg.header.type = htons (GNUNET_MESSAGE_TYPE_MESH_LOCAL_PEER_ADD_BY_TYPE);
      msg.tunnel_id = htonl (t->tid);
      msg.type = htonl (t->apps[i]);
      send_packet (t->mesh, &msg.header, t);
    }
  }
  return GNUNET_YES;
}

/**
 * Reconnect callback: tries to reconnect again after a failer previous
 * reconnecttion
 * @param cls closure (mesh handle)
 * @param tc task context
 */
static void
reconnect_cbk (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_MESH_Handle *h = cls;

  h->reconnect_task = GNUNET_SCHEDULER_NO_TASK;
  if (0 != (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN))
    return;
  do_reconnect (h);
}


/**
 * Reconnect to the service, retransmit all infomation to try to restore the
 * original state.
 *
 * @param h handle to the mesh
 *
 * @return GNUNET_YES in case of sucess, GNUNET_NO otherwise (service down...)
 */
static void
reconnect (struct GNUNET_MESH_Handle *h)
{
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Requested RECONNECT\n");
  if (GNUNET_SCHEDULER_NO_TASK == h->reconnect_task)
    h->reconnect_task = GNUNET_SCHEDULER_add_delayed (h->reconnect_time,
                                                      &reconnect_cbk, h);
}


/******************************************************************************/
/***********************      RECEIVE HANDLERS     ****************************/
/******************************************************************************/

/**
 * Process the new tunnel notification and add it to the tunnels in the handle
 *
 * @param h     The mesh handle
 * @param msg   A message with the details of the new incoming tunnel
 */
static void
process_tunnel_created (struct GNUNET_MESH_Handle *h,
                        const struct GNUNET_MESH_TunnelNotification *msg)
{
  struct GNUNET_MESH_Tunnel *t;
  MESH_TunnelNumber tid;

  tid = ntohl (msg->tunnel_id);
  if (tid < GNUNET_MESH_LOCAL_TUNNEL_ID_SERV)
  {
    GNUNET_break (0);
    return;
  }
  t = create_tunnel (h, tid);
  t->owner = GNUNET_PEER_intern (&msg->peer);
  t->npeers = 1;
  t->peers = GNUNET_malloc (sizeof (struct GNUNET_MESH_Peer *));
  t->peers[0] = GNUNET_malloc (sizeof (struct GNUNET_MESH_Peer));
  t->peers[0]->t = t;
  t->peers[0]->connected = 1;
  t->peers[0]->id = t->owner;
  GNUNET_PEER_change_rc (t->owner, 1);
  t->mesh = h;
  t->tid = tid;
  if (NULL != h->new_tunnel)
  {
    struct GNUNET_ATS_Information atsi;

    atsi.type = 0;
    atsi.value = 0;
    t->ctx = h->new_tunnel (h->cls, t, &msg->peer, &atsi);
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG, "new incoming tunnel %X\n", t->tid);
  return;
}


/**
 * Process the tunnel destroy notification and free associated resources
 *
 * @param h     The mesh handle
 * @param msg   A message with the details of the tunnel being destroyed
 */
static void
process_tunnel_destroy (struct GNUNET_MESH_Handle *h,
                        const struct GNUNET_MESH_TunnelMessage *msg)
{
  struct GNUNET_MESH_Tunnel *t;
  MESH_TunnelNumber tid;

  tid = ntohl (msg->tunnel_id);
  t = retrieve_tunnel (h, tid);

  if (NULL == t)
  {
    return;
  }
  if (0 == t->owner)
  {
    GNUNET_break (0);
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG, "tunnel %u destroyed\n", t->tid);
  destroy_tunnel (t, GNUNET_YES);
  return;
}


/**
 * Process the new peer event and notify the upper level of it
 *
 * @param h     The mesh handle
 * @param msg   A message with the details of the peer event
 */
static void
process_peer_event (struct GNUNET_MESH_Handle *h,
                    const struct GNUNET_MESH_PeerControl *msg)
{
  struct GNUNET_MESH_Tunnel *t;
  struct GNUNET_MESH_Peer *p;
  struct GNUNET_ATS_Information atsi;
  GNUNET_PEER_Id id;
  uint16_t size;

  LOG (GNUNET_ERROR_TYPE_DEBUG, "processig peer event\n");
  size = ntohs (msg->header.size);
  if (size != sizeof (struct GNUNET_MESH_PeerControl))
  {
    GNUNET_break (0);
    return;
  }
  t = retrieve_tunnel (h, ntohl (msg->tunnel_id));
  if (NULL == t)
  {
    GNUNET_break (0);
    return;
  }
  id = GNUNET_PEER_search (&msg->peer);
  if ((p = retrieve_peer (t, id)) == NULL)
    p = add_peer_to_tunnel (t, &msg->peer);
  if (GNUNET_MESSAGE_TYPE_MESH_LOCAL_PEER_ADD == ntohs (msg->header.type))
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "adding peer\n");
    if (NULL != t->connect_handler)
    {
      atsi.type = 0;
      atsi.value = 0;
      t->connect_handler (t->cls, &msg->peer, &atsi);
    }
    p->connected = 1;
  }
  else
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "removing peer\n");
    if (NULL != t->disconnect_handler && p->connected)
    {
      t->disconnect_handler (t->cls, &msg->peer);
    }
    remove_peer_from_tunnel (p);
    GNUNET_free (p);
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG, "processing peer event END\n");
}


/**
 * Process the incoming data packets
 *
 * @param h         The mesh handle
 * @param message   A message encapsulating the data
 * 
 * @return GNUNET_YES if everything went fine
 *         GNUNET_NO if client closed connection (h no longer valid)
 */
static int
process_incoming_data (struct GNUNET_MESH_Handle *h,
                       const struct GNUNET_MessageHeader *message)
{
  const struct GNUNET_MessageHeader *payload;
  const struct GNUNET_MESH_MessageHandler *handler;
  const struct GNUNET_PeerIdentity *peer;
  struct GNUNET_MESH_Unicast *ucast;
  struct GNUNET_MESH_Multicast *mcast;
  struct GNUNET_MESH_ToOrigin *to_orig;
  struct GNUNET_MESH_Tunnel *t;
  unsigned int i;
  uint16_t type;

  LOG (GNUNET_ERROR_TYPE_DEBUG, "Got a data message!\n");
  type = ntohs (message->type);
  switch (type)
  {
  case GNUNET_MESSAGE_TYPE_MESH_UNICAST:
    ucast = (struct GNUNET_MESH_Unicast *) message;

    t = retrieve_tunnel (h, ntohl (ucast->tid));
    payload = (struct GNUNET_MessageHeader *) &ucast[1];
    peer = &ucast->oid;
    LOG (GNUNET_ERROR_TYPE_DEBUG, "  ucast on tunnel %s [%x]\n",
         GNUNET_i2s (peer), ntohl (ucast->tid));
    break;
  case GNUNET_MESSAGE_TYPE_MESH_MULTICAST:
    mcast = (struct GNUNET_MESH_Multicast *) message;
    t = retrieve_tunnel (h, ntohl (mcast->tid));
    payload = (struct GNUNET_MessageHeader *) &mcast[1];
    peer = &mcast->oid;
    LOG (GNUNET_ERROR_TYPE_DEBUG, "  mcast on tunnel %s [%x]\n",
         GNUNET_i2s (peer), ntohl (mcast->tid));
    break;
  case GNUNET_MESSAGE_TYPE_MESH_TO_ORIGIN:
    to_orig = (struct GNUNET_MESH_ToOrigin *) message;
    t = retrieve_tunnel (h, ntohl (to_orig->tid));
    payload = (struct GNUNET_MessageHeader *) &to_orig[1];
    peer = &to_orig->sender;
    LOG (GNUNET_ERROR_TYPE_DEBUG, "  torig on tunnel %s [%x]\n",
         GNUNET_i2s (peer), ntohl (to_orig->tid));
    break;
  default:
    GNUNET_break (0);
    return GNUNET_YES;
  }
  if (NULL == t)
  {
    GNUNET_break (0);
    return GNUNET_YES;
  }
  type = ntohs (payload->type);
  for (i = 0; i < h->n_handlers; i++)
  {
    handler = &h->message_handlers[i];
    if (handler->type == type)
    {
      struct GNUNET_ATS_Information atsi;

      atsi.type = 0;
      atsi.value = 0;
      if (GNUNET_OK !=
          handler->callback (h->cls, t, &t->ctx, peer, payload, &atsi))
      {
        LOG (GNUNET_ERROR_TYPE_DEBUG, "MESH: callback caused disconnection\n");
        GNUNET_MESH_disconnect (h);
        return GNUNET_NO;
      }
      else
      {
        LOG (GNUNET_ERROR_TYPE_DEBUG,
             "MESH: callback completed successfully\n");

      }
    }
  }
  return GNUNET_YES;
}


/**
 * Function to process all messages received from the service
 *
 * @param cls closure
 * @param msg message received, NULL on timeout or fatal error
 */
static void
msg_received (void *cls, const struct GNUNET_MessageHeader *msg)
{
  struct GNUNET_MESH_Handle *h = cls;

  if (msg == NULL)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "Received NULL msg\n");
    reconnect (h);
    return;
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG, "received a message type %hu from MESH\n",
       ntohs (msg->type));
  switch (ntohs (msg->type))
  {
    /* Notify of a new incoming tunnel */
  case GNUNET_MESSAGE_TYPE_MESH_LOCAL_TUNNEL_CREATE:
    process_tunnel_created (h, (struct GNUNET_MESH_TunnelNotification *) msg);
    break;
    /* Notify of a tunnel disconnection */
  case GNUNET_MESSAGE_TYPE_MESH_LOCAL_TUNNEL_DESTROY:
    process_tunnel_destroy (h, (struct GNUNET_MESH_TunnelMessage *) msg);
    break;
    /* Notify of a new peer or a peer disconnect in the tunnel */
  case GNUNET_MESSAGE_TYPE_MESH_LOCAL_PEER_ADD:
  case GNUNET_MESSAGE_TYPE_MESH_LOCAL_PEER_DEL:
    process_peer_event (h, (struct GNUNET_MESH_PeerControl *) msg);
    break;
    /* Notify of a new data packet in the tunnel */
  case GNUNET_MESSAGE_TYPE_MESH_UNICAST:
  case GNUNET_MESSAGE_TYPE_MESH_MULTICAST:
  case GNUNET_MESSAGE_TYPE_MESH_TO_ORIGIN:
    if (GNUNET_NO == process_incoming_data (h, msg))
      return;
    break;
    /* We shouldn't get any other packages, log and ignore */
  default:
    LOG (GNUNET_ERROR_TYPE_WARNING,
         "MESH: unsolicited message form service (type %d)\n",
         ntohs (msg->type));
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG, "message processed\n");
  GNUNET_CLIENT_receive (h->client, &msg_received, h,
                         GNUNET_TIME_UNIT_FOREVER_REL);
}


/******************************************************************************/
/************************       SEND FUNCTIONS     ****************************/
/******************************************************************************/

/**
 * Function called to send a message to the service.
 * "buf" will be NULL and "size" zero if the socket was closed for writing in
 * the meantime.
 *
 * @param cls closure, the mesh handle
 * @param size number of bytes available in buf
 * @param buf where the callee should write the connect message
 * @return number of bytes written to buf
 */
static size_t
send_callback (void *cls, size_t size, void *buf)
{
  struct GNUNET_MESH_Handle *h = cls;
  struct GNUNET_MESH_TransmitHandle *th;
  char *cbuf = buf;
  size_t tsize;
  size_t psize;

  LOG (GNUNET_ERROR_TYPE_DEBUG, "Send packet() Buffer %u\n", size);
  h->th = NULL;
  if ((0 == size) || (NULL == buf))
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "Received NULL callback\n");
    reconnect (h);
    return 0;
  }
  tsize = 0;
  while ((NULL != (th = h->th_head)) && (size >= th->size))
  {
    if (NULL != th->notify)
    {
      if (th->tunnel->tid >= GNUNET_MESH_LOCAL_TUNNEL_ID_SERV)
      {
        /* traffic to origin */
        struct GNUNET_MESH_ToOrigin to;
        struct GNUNET_MessageHeader *mh;

        GNUNET_assert (size >= th->size);
        mh = (struct GNUNET_MessageHeader *) &cbuf[sizeof (to)];
        psize = th->notify (th->notify_cls, size - sizeof (to), mh);
        LOG (GNUNET_ERROR_TYPE_DEBUG, "  to origin, type %u\n",
             ntohs (mh->type));
        if (psize > 0)
        {
          psize += sizeof (to);
          GNUNET_assert (size >= psize);
          to.header.size = htons (psize);
          to.header.type = htons (GNUNET_MESSAGE_TYPE_MESH_TO_ORIGIN);
          to.tid = htonl (th->tunnel->tid);
          memset (&to.oid, 0, sizeof (struct GNUNET_PeerIdentity));
          memset (&to.sender, 0, sizeof (struct GNUNET_PeerIdentity));
          memcpy (cbuf, &to, sizeof (to));
        }
      }
      else if (th->target == 0)
      {
        /* multicast */
        struct GNUNET_MESH_Multicast mc;
        struct GNUNET_MessageHeader *mh;

        GNUNET_assert (size >= th->size);
        mh = (struct GNUNET_MessageHeader *) &cbuf[sizeof (mc)];
        psize = th->notify (th->notify_cls, size - sizeof (mc), mh);
        LOG (GNUNET_ERROR_TYPE_DEBUG, "  multicast, type %u\n",
             ntohs (mh->type));
        if (psize > 0)
        {
          psize += sizeof (mc);
          GNUNET_assert (size >= psize);
          mc.header.size = htons (psize);
          mc.header.type = htons (GNUNET_MESSAGE_TYPE_MESH_MULTICAST);
          mc.tid = htonl (th->tunnel->tid);
          mc.mid = 0;
          mc.ttl = 0;
          memset (&mc.oid, 0, sizeof (struct GNUNET_PeerIdentity));
          memcpy (cbuf, &mc, sizeof (mc));
        }
      }
      else
      {
        /* unicast */
        struct GNUNET_MESH_Unicast uc;
        struct GNUNET_MessageHeader *mh;

        GNUNET_assert (size >= th->size);
        mh = (struct GNUNET_MessageHeader *) &cbuf[sizeof (uc)];
        psize = th->notify (th->notify_cls, size - sizeof (uc), mh);
        LOG (GNUNET_ERROR_TYPE_DEBUG, "  unicast, type %u\n",
             ntohs (mh->type));
        if (psize > 0)
        {
          psize += sizeof (uc);
          GNUNET_assert (size >= psize);
          uc.header.size = htons (psize);
          uc.header.type = htons (GNUNET_MESSAGE_TYPE_MESH_UNICAST);
          uc.tid = htonl (th->tunnel->tid);
          memset (&uc.oid, 0, sizeof (struct GNUNET_PeerIdentity));
          GNUNET_PEER_resolve (th->target, &uc.destination);
          memcpy (cbuf, &uc, sizeof (uc));
        }
      }
    }
    else
    {
      memcpy (cbuf, &th[1], th->size);
      psize = th->size;
    }
    if (th->timeout_task != GNUNET_SCHEDULER_NO_TASK)
      GNUNET_SCHEDULER_cancel (th->timeout_task);
    if (NULL != th->notify)
    {
      th->tunnel->mesh->npackets--;
      th->tunnel->npackets--;
    }
    GNUNET_CONTAINER_DLL_remove (h->th_head, h->th_tail, th);
    GNUNET_free (th);
    cbuf += psize;
    size -= psize;
    tsize += psize;
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG, "  total size: %u\n", tsize);
  if (NULL != (th = h->th_head))
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "  next size: %u\n", th->size);
    if (NULL == h->th)
      h->th =
          GNUNET_CLIENT_notify_transmit_ready (h->client, th->size,
                                               GNUNET_TIME_UNIT_FOREVER_REL,
                                               GNUNET_YES, &send_callback, h);
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Send packet() END\n");
  if (GNUNET_NO == h->in_receive)
  {
    h->in_receive = GNUNET_YES;
    GNUNET_CLIENT_receive (h->client, &msg_received, h,
                           GNUNET_TIME_UNIT_FOREVER_REL);
  }
  return tsize;
}


/**
 * Auxiliary function to send an already constructed packet to the service.
 * Takes care of creating a new queue element, copying the message and
 * calling the tmt_rdy function if necessary.
 * 
 * @param h mesh handle
 * @param msg message to transmit
 * @param tunnel tunnel this send is related to (NULL if N/A)
 */
static void
send_packet (struct GNUNET_MESH_Handle *h,
             const struct GNUNET_MessageHeader *msg,
             struct GNUNET_MESH_Tunnel *tunnel)
{
  struct GNUNET_MESH_TransmitHandle *th;
  size_t msize;

  msize = ntohs (msg->size);
  th = GNUNET_malloc (sizeof (struct GNUNET_MESH_TransmitHandle) + msize);
  th->priority = UINT32_MAX;
  th->timeout = GNUNET_TIME_UNIT_FOREVER_ABS;
  th->size = msize;
  th->tunnel = tunnel;
  memcpy (&th[1], msg, msize);
  add_to_queue (h, th);
  if (NULL != h->th)
    return;
  h->th =
      GNUNET_CLIENT_notify_transmit_ready (h->client, msize,
                                           GNUNET_TIME_UNIT_FOREVER_REL,
                                           GNUNET_YES, &send_callback, h);
}


/******************************************************************************/
/**********************      API CALL DEFINITIONS     *************************/
/******************************************************************************/

/**
 * Connect to the mesh service.
 *
 * @param cfg configuration to use
 * @param queue_size size of the data message queue, shared among all tunnels
 *                   (each tunnel is guaranteed to accept at least one message,
 *                    no matter what is the status of other tunnels)
 * @param cls closure for the various callbacks that follow
 *            (including handlers in the handlers array)
 * @param new_tunnel function called when an *inbound* tunnel is created
 * @param cleaner function called when an *inbound* tunnel is destroyed by the
 *                remote peer, it is *not* called if GNUNET_MESH_tunnel_destroy
 *                is called on the tunnel
 * @param handlers callbacks for messages we care about, NULL-terminated
 *                note that the mesh is allowed to drop notifications about
 *                inbound messages if the client does not process them fast
 *                enough (for this notification type, a bounded queue is used)
 * @param stypes list of the applications that this client claims to provide
 * @return handle to the mesh service NULL on error
 *         (in this case, init is never called)
 */
struct GNUNET_MESH_Handle *
GNUNET_MESH_connect (const struct GNUNET_CONFIGURATION_Handle *cfg,
                     unsigned int queue_size, void *cls,
                     GNUNET_MESH_InboundTunnelNotificationHandler new_tunnel,
                     GNUNET_MESH_TunnelEndHandler cleaner,
                     const struct GNUNET_MESH_MessageHandler *handlers,
                     const GNUNET_MESH_ApplicationType *stypes)
{
  struct GNUNET_MESH_Handle *h;

  LOG (GNUNET_ERROR_TYPE_DEBUG, "GNUNET_MESH_connect()\n");
  h = GNUNET_malloc (sizeof (struct GNUNET_MESH_Handle));
  h->cfg = cfg;
  h->max_queue_size = queue_size;
  h->new_tunnel = new_tunnel;
  h->cleaner = cleaner;
  h->client = GNUNET_CLIENT_connect ("mesh", cfg);
  if (h->client == NULL)
  {
    GNUNET_break (0);
    GNUNET_free (h);
    return NULL;
  }
  h->cls = cls;
  /* FIXME memdup? */
  h->applications = stypes;
  h->message_handlers = handlers;
  h->next_tid = GNUNET_MESH_LOCAL_TUNNEL_ID_CLI;
  h->reconnect_time = GNUNET_TIME_UNIT_MILLISECONDS;
  h->reconnect_task = GNUNET_SCHEDULER_NO_TASK;

  /* count handlers and apps, calculate size */
  for (h->n_applications = 0; stypes[h->n_applications]; h->n_applications++) ;
  for (h->n_handlers = 0; handlers[h->n_handlers].type; h->n_handlers++) ;
  send_connect (h);
  LOG (GNUNET_ERROR_TYPE_DEBUG, "GNUNET_MESH_connect() END\n");
  return h;
}


/**
 * Disconnect from the mesh service. All tunnels will be destroyed. All tunnel
 * disconnect callbacks will be called on any still connected peers, notifying
 * about their disconnection. The registered inbound tunnel cleaner will be
 * called should any inbound tunnels still exist.
 *
 * @param handle connection to mesh to disconnect
 */
void
GNUNET_MESH_disconnect (struct GNUNET_MESH_Handle *handle)
{
  struct GNUNET_MESH_Tunnel *t;
  struct GNUNET_MESH_Tunnel *aux;
  struct GNUNET_MESH_TransmitHandle *th;

  t = handle->tunnels_head;
  while (NULL != t)
  {
    aux = t->next;
    if (t->tid < GNUNET_MESH_LOCAL_TUNNEL_ID_SERV)
    {
      GNUNET_break (0);
      LOG (GNUNET_ERROR_TYPE_DEBUG, "tunnel %X not destroyed\n", t->tid);
    }
    destroy_tunnel (t, GNUNET_YES);
    t = aux;
  }
  while ( (th = handle->th_head) != NULL)
  {
    struct GNUNET_MessageHeader *msg;

    /* Make sure it is an allowed packet (everything else should have been
     * already canceled).
     */
    GNUNET_break (UINT32_MAX == th->priority);
    GNUNET_break (NULL == th->notify);
    msg = (struct GNUNET_MessageHeader *) &th[1];
    switch (ntohs(msg->type))
    {
      case GNUNET_MESSAGE_TYPE_MESH_LOCAL_CONNECT:
      case GNUNET_MESSAGE_TYPE_MESH_LOCAL_TUNNEL_DESTROY:
        break;
      default:
        GNUNET_break (0);
        LOG (GNUNET_ERROR_TYPE_DEBUG, "unexpected msg %u\n",
             ntohs(msg->type));
    }

    GNUNET_CONTAINER_DLL_remove (handle->th_head, handle->th_tail, th);
    GNUNET_free (th);
  }

  if (NULL != handle->th)
  {
    GNUNET_CLIENT_notify_transmit_ready_cancel (handle->th);
    handle->th = NULL;
  }
  if (NULL != handle->client)
  {
    GNUNET_CLIENT_disconnect (handle->client, GNUNET_NO);
    handle->client = NULL;
  }
  if (GNUNET_SCHEDULER_NO_TASK != handle->reconnect_task)
  {
    GNUNET_SCHEDULER_cancel(handle->reconnect_task);
    handle->reconnect_task = GNUNET_SCHEDULER_NO_TASK;
  }
  GNUNET_free (handle);
}


/**
 * Create a new tunnel (we're initiator and will be allowed to add/remove peers
 * and to broadcast).
 *
 * @param h mesh handle
 * @param tunnel_ctx client's tunnel context to associate with the tunnel
 * @param connect_handler function to call when peers are actually connected
 * @param disconnect_handler function to call when peers are disconnected
 * @param handler_cls closure for connect/disconnect handlers
 */
struct GNUNET_MESH_Tunnel *
GNUNET_MESH_tunnel_create (struct GNUNET_MESH_Handle *h, void *tunnel_ctx,
                           GNUNET_MESH_PeerConnectHandler connect_handler,
                           GNUNET_MESH_PeerDisconnectHandler disconnect_handler,
                           void *handler_cls)
{
  struct GNUNET_MESH_Tunnel *t;
  struct GNUNET_MESH_TunnelMessage msg;

  LOG (GNUNET_ERROR_TYPE_DEBUG, "Creating new tunnel\n");
  t = create_tunnel (h, 0);
  t->connect_handler = connect_handler;
  t->disconnect_handler = disconnect_handler;
  t->cls = handler_cls;
  t->ctx = tunnel_ctx;
  msg.header.type = htons (GNUNET_MESSAGE_TYPE_MESH_LOCAL_TUNNEL_CREATE);
  msg.header.size = htons (sizeof (struct GNUNET_MESH_TunnelMessage));
  msg.tunnel_id = htonl (t->tid);
  send_packet (h, &msg.header, t);
  return t;
}


/**
 * Destroy an existing tunnel. The existing callback for the tunnel will NOT
 * be called.
 *
 * @param tunnel tunnel handle
 */
void
GNUNET_MESH_tunnel_destroy (struct GNUNET_MESH_Tunnel *tunnel)
{
  struct GNUNET_MESH_Handle *h;
  struct GNUNET_MESH_TunnelMessage msg;
  struct GNUNET_MESH_TransmitHandle *th;

  LOG (GNUNET_ERROR_TYPE_DEBUG, "Destroying tunnel\n");
  h = tunnel->mesh;

  msg.header.type = htons (GNUNET_MESSAGE_TYPE_MESH_LOCAL_TUNNEL_DESTROY);
  msg.header.size = htons (sizeof (struct GNUNET_MESH_TunnelMessage));
  msg.tunnel_id = htonl (tunnel->tid);
  th = h->th_head;
  while (th != NULL)
  {
    struct GNUNET_MESH_TransmitHandle *aux;
    if (th->tunnel == tunnel)
    {
      aux = th->next;
      /* FIXME call the handler? */
      if (NULL != th->notify)
        th->notify (th->notify_cls, 0, NULL);
      GNUNET_CONTAINER_DLL_remove (h->th_head, h->th_tail, th);
      GNUNET_free (th);
      th = aux;
    }
    else
      th = th->next;
  }

  destroy_tunnel (tunnel, GNUNET_NO);
  send_packet (h, &msg.header, tunnel);
}


/**
 * Request that a peer should be added to the tunnel.  The existing
 * connect handler will be called ONCE with either success or failure.
 * This function should NOT be called again with the same peer before the
 * connect handler is called.
 *
 * @param tunnel handle to existing tunnel
 * @param peer peer to add
 */
void
GNUNET_MESH_peer_request_connect_add (struct GNUNET_MESH_Tunnel *tunnel,
                                      const struct GNUNET_PeerIdentity *peer)
{
  struct GNUNET_MESH_PeerControl msg;
  GNUNET_PEER_Id peer_id;
  unsigned int i;

  peer_id = GNUNET_PEER_intern (peer);
  for (i = 0; i < tunnel->npeers; i++)
  {
    if (tunnel->peers[i]->id == peer_id)
    {
      /* Peer already exists in tunnel */
      GNUNET_PEER_change_rc (peer_id, -1);
      GNUNET_break (0);
      return;
    }
  }
  if (NULL == add_peer_to_tunnel (tunnel, peer))
    return;

  msg.header.size = htons (sizeof (struct GNUNET_MESH_PeerControl));
  msg.header.type = htons (GNUNET_MESSAGE_TYPE_MESH_LOCAL_PEER_ADD);
  msg.tunnel_id = htonl (tunnel->tid);
  msg.peer = *peer;
  send_packet (tunnel->mesh, &msg.header, tunnel);

  return;
}


/**
 * Request that a peer should be removed from the tunnel.  The existing
 * disconnect handler will be called ONCE if we were connected.
 *
 * @param tunnel handle to existing tunnel
 * @param peer peer to remove
 */
void
GNUNET_MESH_peer_request_connect_del (struct GNUNET_MESH_Tunnel *tunnel,
                                      const struct GNUNET_PeerIdentity *peer)
{
  struct GNUNET_MESH_PeerControl msg;
  GNUNET_PEER_Id peer_id;
  unsigned int i;

  peer_id = GNUNET_PEER_search (peer);
  if (0 == peer_id)
  {
    GNUNET_break (0);
    return;
  }
  for (i = 0; i < tunnel->npeers; i++)
    if (tunnel->peers[i]->id == peer_id)
      break;
  if (i == tunnel->npeers)
  {
    GNUNET_break (0);
    return;
  }
  if (NULL != tunnel->disconnect_handler && tunnel->peers[i]->connected == 1)
    tunnel->disconnect_handler (tunnel->cls, peer);
  GNUNET_PEER_change_rc (peer_id, -1);
  GNUNET_free (tunnel->peers[i]);
  tunnel->peers[i] = tunnel->peers[tunnel->npeers - 1];
  GNUNET_array_grow (tunnel->peers, tunnel->npeers, tunnel->npeers - 1);

  msg.header.size = htons (sizeof (struct GNUNET_MESH_PeerControl));
  msg.header.type = htons (GNUNET_MESSAGE_TYPE_MESH_LOCAL_PEER_DEL);
  msg.tunnel_id = htonl (tunnel->tid);
  memcpy (&msg.peer, peer, sizeof (struct GNUNET_PeerIdentity));
  send_packet (tunnel->mesh, &msg.header, tunnel);
}


/**
 * Request that the mesh should try to connect to a peer supporting the given
 * message type.
 *
 * @param tunnel handle to existing tunnel
 * @param app_type application type that must be supported by the peer (MESH
 *                 should discover peer in proximity handling this type)
 */
void
GNUNET_MESH_peer_request_connect_by_type (struct GNUNET_MESH_Tunnel *tunnel,
                                          GNUNET_MESH_ApplicationType app_type)
{
  struct GNUNET_MESH_ConnectPeerByType msg;

  GNUNET_array_append (tunnel->apps, tunnel->napps, app_type);

  LOG (GNUNET_ERROR_TYPE_DEBUG, "* CONNECT BY TYPE *\n");
  msg.header.size = htons (sizeof (struct GNUNET_MESH_ConnectPeerByType));
  msg.header.type = htons (GNUNET_MESSAGE_TYPE_MESH_LOCAL_PEER_ADD_BY_TYPE);
  msg.tunnel_id = htonl (tunnel->tid);
  msg.type = htonl (app_type);
  send_packet (tunnel->mesh, &msg.header, tunnel);
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
 * @param target destination for the message,
 *               NULL for multicast to all tunnel targets
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
                                   const struct GNUNET_PeerIdentity *target,
                                   size_t notify_size,
                                   GNUNET_CONNECTION_TransmitReadyNotify notify,
                                   void *notify_cls)
{
  struct GNUNET_MESH_TransmitHandle *th;
  struct GNUNET_MESH_TransmitHandle *least_priority_th;
  uint32_t least_priority;
  size_t overhead;

  GNUNET_assert (NULL != tunnel);
  LOG (GNUNET_ERROR_TYPE_DEBUG, "mesh notify transmit ready called\n");
  if (NULL != target)
    LOG (GNUNET_ERROR_TYPE_DEBUG, "    target %s\n", GNUNET_i2s (target));
  else
    LOG (GNUNET_ERROR_TYPE_DEBUG, "    target multicast\n");
  GNUNET_assert (NULL != notify);
  if (tunnel->mesh->npackets >= tunnel->mesh->max_queue_size &&
      tunnel->npackets > 0)
  {
    /* queue full */
    if (0 == priority)
      return NULL;
    th = tunnel->mesh->th_tail;
    least_priority = priority;
    least_priority_th = NULL;
    while (NULL != th)
    {
      if (th->priority < least_priority && th->tunnel->npackets > 1)
      {
        least_priority_th = th;
        least_priority = th->priority;
      }
      th = th->prev;
    }
    if (NULL == least_priority_th)
      return NULL;
    /* Can't be a control message */
    GNUNET_assert (NULL != least_priority_th->notify);
    least_priority_th->notify (notify_cls, 0, NULL);
    least_priority_th->tunnel->npackets--;
    tunnel->mesh->npackets--;
    GNUNET_CONTAINER_DLL_remove (tunnel->mesh->th_head, tunnel->mesh->th_tail,
                                 least_priority_th);
    if (GNUNET_SCHEDULER_NO_TASK != least_priority_th->timeout_task)
      GNUNET_SCHEDULER_cancel (least_priority_th->timeout_task);
    GNUNET_free (least_priority_th);
  }
  tunnel->npackets++;
  tunnel->mesh->npackets++;
  th = GNUNET_malloc (sizeof (struct GNUNET_MESH_TransmitHandle));
  th->tunnel = tunnel;
  th->priority = priority;
  th->timeout = GNUNET_TIME_relative_to_absolute (maxdelay);
  th->target = GNUNET_PEER_intern (target);
  if (tunnel->tid >= GNUNET_MESH_LOCAL_TUNNEL_ID_SERV)
    overhead = sizeof (struct GNUNET_MESH_ToOrigin);
  else if (NULL == target)
    overhead = sizeof (struct GNUNET_MESH_Multicast);
  else
    overhead = sizeof (struct GNUNET_MESH_Unicast);
  th->size = notify_size + overhead;
  th->notify = notify;
  th->notify_cls = notify_cls;
  add_to_queue (tunnel->mesh, th);
  if (NULL != tunnel->mesh->th)
    return th;
  tunnel->mesh->th =
      GNUNET_CLIENT_notify_transmit_ready (tunnel->mesh->client, th->size,
                                           GNUNET_TIME_UNIT_FOREVER_REL,
                                           GNUNET_YES, &send_callback,
                                           tunnel->mesh);
  return th;
}


/**
 * Cancel the specified transmission-ready notification.
 *
 * @param th handle that was returned by "notify_transmit_ready".
 */
void
GNUNET_MESH_notify_transmit_ready_cancel (struct GNUNET_MESH_TransmitHandle *th)
{
  struct GNUNET_MESH_Handle *mesh;

  mesh = th->tunnel->mesh;
  if (th->timeout_task != GNUNET_SCHEDULER_NO_TASK)
    GNUNET_SCHEDULER_cancel (th->timeout_task);
  GNUNET_CONTAINER_DLL_remove (mesh->th_head, mesh->th_tail, th);
  GNUNET_free (th);
  if ((NULL == mesh->th_head) && (NULL != mesh->th))
  {
    /* queue empty, no point in asking for transmission */
    GNUNET_CLIENT_notify_transmit_ready_cancel (mesh->th);
    mesh->th = NULL;
  }
}


/**
 * Transition API for tunnel ctx management
 */
void
GNUNET_MESH_tunnel_set_data (struct GNUNET_MESH_Tunnel *tunnel, void *data)
{
  tunnel->ctx = data;
}

/**
 * Transition API for tunnel ctx management
 */
void *
GNUNET_MESH_tunnel_get_data (struct GNUNET_MESH_Tunnel *tunnel)
{
  return tunnel->ctx;
}


#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

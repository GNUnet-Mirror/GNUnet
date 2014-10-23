/*
     This file is part of GNUnet
     (C) 2002--2014 Christian Grothoff (and other contributing authors)

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
 * @file dv/plugin_transport_dv.c
 * @brief DV transport service, takes incoming DV requests and deals with
 * the DV service
 * @author Nathan Evans
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_protocols.h"
#include "gnunet_statistics_service.h"
#include "gnunet_dv_service.h"
#include "gnunet_transport_service.h"
#include "gnunet_transport_plugin.h"
#include "dv.h"


#define LOG(kind,...) GNUNET_log_from (kind, "transport-dv",__VA_ARGS__)


/**
 * Encapsulation of all of the state of the plugin.
 */
struct Plugin;


/**
 * An active request for transmission via DV.
 */
struct PendingRequest
{

  /**
   * This is a DLL.
   */
  struct PendingRequest *next;

  /**
   * This is a DLL.
   */
  struct PendingRequest *prev;

  /**
   * Continuation function to call once the transmission buffer
   * has again space available.  NULL if there is no
   * continuation to call.
   */
  GNUNET_TRANSPORT_TransmitContinuation transmit_cont;

  /**
   * Closure for @e transmit_cont.
   */
  void *transmit_cont_cls;

  /**
   * Transmission handle from DV client library.
   */
  struct GNUNET_DV_TransmitHandle *th;

  /**
   * Session of this request.
   */
  struct Session *session;

  /**
   * Number of bytes to transmit.
   */
  size_t size;
};


/**
 * Session handle for connections.
 */
struct Session
{
  /**
   * Pointer to the global plugin struct.
   */
  struct Plugin *plugin;

  /**
   * Head of pending requests.
   */
  struct PendingRequest *pr_head;

  /**
   * Tail of pending requests.
   */
  struct PendingRequest *pr_tail;

  /**
   * Address we use for the other peer.
   */
  struct GNUNET_HELLO_Address *address;

  /**
   * To whom are we talking to.
   */
  struct GNUNET_PeerIdentity sender;

  /**
   * Number of bytes waiting for transmission to this peer.
   * FIXME: not set yet.
   */
  unsigned long long bytes_in_queue;

  /**
   * Number of messages waiting for transmission to this peer.
   * FIXME: not set yet.
   */
  unsigned int msgs_in_queue;

  /**
   * Current distance to the given peer.
   */
  uint32_t distance;

  /**
   * Current network the next hop peer is located in
   */
  enum GNUNET_ATS_Network_Type network;

  /**
   * Does the transport service know about this session (and we thus
   * need to call `session_end` when it is released?)
   */
  int active;

};


/**
 * Encapsulation of all of the state of the plugin.
 */
struct Plugin
{
  /**
   * Our environment.
   */
  struct GNUNET_TRANSPORT_PluginEnvironment *env;

  /**
   * Hash map of sessions (active and inactive).
   */
  struct GNUNET_CONTAINER_MultiPeerMap *sessions;

  /**
   * Copy of the handler array where the closures are
   * set to this struct's instance.
   */
  struct GNUNET_SERVER_MessageHandler *handlers;

  /**
   * Handle to the DV service
   */
  struct GNUNET_DV_ServiceHandle *dvh;

  /**
   * Tokenizer for boxed messages.
   */
  struct GNUNET_SERVER_MessageStreamTokenizer *mst;

  /**
   * Function to call about session status changes.
   */
  GNUNET_TRANSPORT_SessionInfoCallback sic;

  /**
   * Closure for @e sic.
   */
  void *sic_cls;
};


/**
 * If a session monitor is attached, notify it about the new
 * session state.
 *
 * @param plugin our plugin
 * @param session session that changed state
 * @param state new state of the session
 */
static void
notify_session_monitor (struct Plugin *plugin,
                        struct Session *session,
                        enum GNUNET_TRANSPORT_SessionState state)
{
  struct GNUNET_TRANSPORT_SessionInfo info;

  if (NULL == plugin->sic)
    return;
  memset (&info, 0, sizeof (info));
  info.state = state;
  info.is_inbound = GNUNET_SYSERR; /* hard to say */
  info.num_msg_pending = session->msgs_in_queue;
  info.num_bytes_pending = session->bytes_in_queue;
  /* info.receive_delay remains zero as this is not supported by DV
     (cannot selectively not receive from 'core') */
  info.session_timeout = GNUNET_TIME_UNIT_FOREVER_ABS;
  info.address = session->address;
  plugin->sic (plugin->sic_cls,
               session,
               &info);
}


/**
 * Notify transport service about the change in distance.
 *
 * @param session session where the distance changed
 */
static void
notify_distance_change (struct Session *session)
{
  struct Plugin *plugin = session->plugin;
  struct GNUNET_ATS_Information ats;

  if (GNUNET_YES != session->active)
    return;
  ats.type = htonl ((uint32_t) GNUNET_ATS_QUALITY_NET_DISTANCE);
  ats.value = htonl (session->distance);
  plugin->env->update_address_metrics (plugin->env->cls,
      session->address, session, &ats, 1);
}


/**
 * Function called by MST on each message from the box.
 *
 * @param cls closure with the `struct Plugin *`
 * @param client identification of the client (with the 'struct Session')
 * @param message the actual message
 * @return #GNUNET_OK on success
 */
static int
unbox_cb (void *cls,
	  void *client,
	  const struct GNUNET_MessageHeader *message)
{
  struct Plugin *plugin = cls;
  struct Session *session = client;
  struct GNUNET_ATS_Information ats;

  ats.type = htonl (GNUNET_ATS_QUALITY_NET_DISTANCE);
  ats.value = htonl (session->distance);
  session->active = GNUNET_YES;
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Delivering message of type %u with %u bytes from peer `%s'\n",
       ntohs (message->type),
       ntohs (message->size),
       GNUNET_i2s (&session->sender));

  plugin->env->receive (plugin->env->cls, session->address, session,
                        message);
  plugin->env->update_address_metrics (plugin->env->cls,
      session->address, session, &ats, 1);
  return GNUNET_OK;
}


/**
 * Handler for messages received from the DV service.
 *
 * @param cls closure with the plugin
 * @param sender sender of the message
 * @param distance how far did the message travel
 * @param msg actual message payload
 */
static void
handle_dv_message_received (void *cls,
			    const struct GNUNET_PeerIdentity *sender,
			    uint32_t distance,
			    const struct GNUNET_MessageHeader *msg)
{
  struct Plugin *plugin = cls;
  struct GNUNET_ATS_Information ats;
  struct Session *session;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Received DV_MESSAGE_RECEIVED message for peer `%s': new distance %u\n",
       GNUNET_i2s (sender), distance);
  session = GNUNET_CONTAINER_multipeermap_get (plugin->sessions,
					       sender);
  if (NULL == session)
  {
    GNUNET_break (0);
    return;
  }
  if (GNUNET_MESSAGE_TYPE_DV_BOX == ntohs (msg->type))
  {
    /* need to unbox using MST */
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Unboxing DV message using MST\n");
    GNUNET_SERVER_mst_receive (plugin->mst,
			       session,
			       (const char *) &msg[1],
			       ntohs (msg->size) - sizeof (struct GNUNET_MessageHeader),
			       GNUNET_YES,
			       GNUNET_NO);
    return;
  }
  ats.type = htonl (GNUNET_ATS_QUALITY_NET_DISTANCE);
  ats.value = htonl (distance);
  session->active = GNUNET_YES;
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Delivering message of type %u with %u bytes from peer `%s'\n",
       ntohs (msg->type),
       ntohs (msg->size),
       GNUNET_i2s (sender));
  plugin->env->receive (plugin->env->cls, session->address, session, msg);
  plugin->env->update_address_metrics (plugin->env->cls,
      session->address, session, &ats, 1);
}


/**
 * Function called if DV starts to be able to talk to a peer.
 *
 * @param cls closure with `struct Plugin *`
 * @param peer newly connected peer
 * @param distance distance to the peer
 * @param network the network the next hop is located in
 */
static void
handle_dv_connect (void *cls,
		   const struct GNUNET_PeerIdentity *peer,
		   uint32_t distance,
                   enum GNUNET_ATS_Network_Type network)
{
  struct Plugin *plugin = cls;
  struct Session *session;
  struct GNUNET_ATS_Information ats[2];

  GNUNET_break (GNUNET_ATS_NET_UNSPECIFIED != network);
  /**
   * This requires transport plugin to be linked to libgnunetats.
   * If you remove it, also remove libgnunetats linkage from Makefile.am
   */
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Received `%s' message for peer `%s' with next hop in network %s\n",
       "DV_CONNECT",
       GNUNET_i2s (peer),
       GNUNET_ATS_print_network_type (network));

  session = GNUNET_CONTAINER_multipeermap_get (plugin->sessions,
					       peer);
  if (NULL != session)
  {
    GNUNET_break (0);
    session->distance = distance;
    notify_distance_change (session);
    return; /* nothing to do */
  }

  session = GNUNET_new (struct Session);
  session->address = GNUNET_HELLO_address_allocate (peer, "dv",
      NULL, 0, GNUNET_HELLO_ADDRESS_INFO_NONE);
  session->sender = *peer;
  session->plugin = plugin;
  session->distance = distance;
  session->network = network;
  GNUNET_assert(GNUNET_YES ==
                GNUNET_CONTAINER_multipeermap_put (plugin->sessions,
                                                   &session->sender, session,
                                                   GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY));

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Creating new DV session %p for peer `%s' at distance %u\n",
       session,
       GNUNET_i2s (peer),
       distance);

  /* Notify transport and ats about new connection */
  ats[0].type = htonl (GNUNET_ATS_QUALITY_NET_DISTANCE);
  ats[0].value = htonl (distance);
  ats[1].type = htonl (GNUNET_ATS_NETWORK_TYPE);
  ats[1].value = htonl ((uint32_t) network);
  session->active = GNUNET_YES;
  plugin->env->session_start (plugin->env->cls, session->address,
                              session, ats, 2);
  notify_session_monitor (session->plugin,
                          session,
                          GNUNET_TRANSPORT_SS_UP);
}


/**
 * Function called if DV distance to a peer is changed.
 *
 * @param cls closure with `struct Plugin *`
 * @param peer connected peer
 * @param distance new distance to the peer
 * @param network network type used for the connection
 */
static void
handle_dv_distance_changed (void *cls,
			    const struct GNUNET_PeerIdentity *peer,
			    uint32_t distance,
                            enum GNUNET_ATS_Network_Type network)
{
  struct Plugin *plugin = cls;
  struct Session *session;

  GNUNET_break (GNUNET_ATS_NET_UNSPECIFIED != network);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Received `%s' message for peer `%s': new distance %u\n",
       "DV_DISTANCE_CHANGED",
       GNUNET_i2s (peer),
       distance);
  session = GNUNET_CONTAINER_multipeermap_get (plugin->sessions,
					       peer);
  if (NULL == session)
  {
    GNUNET_break (0);
    handle_dv_connect (plugin, peer, distance, network);
    return;
  }
  session->distance = distance;
  notify_distance_change (session);
}


/**
 * Release session object and clean up associated resources.
 *
 * @param session session to clean up
 */
static void
free_session (struct Session *session)
{
  struct Plugin *plugin = session->plugin;
  struct PendingRequest *pr;

  GNUNET_assert (GNUNET_YES ==
		 GNUNET_CONTAINER_multipeermap_remove (plugin->sessions,
						       &session->sender,
						       session));

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Freeing session %p for peer `%s'\n",
       session,
       GNUNET_i2s (&session->sender));
  if (GNUNET_YES == session->active)
  {
    notify_session_monitor (session->plugin,
			    session,
			    GNUNET_TRANSPORT_SS_DOWN);
    plugin->env->session_end (plugin->env->cls,
			      session->address,
			      session);
    session->active = GNUNET_NO;
  }
  while (NULL != (pr = session->pr_head))
  {
    GNUNET_CONTAINER_DLL_remove (session->pr_head,
				 session->pr_tail,
				 pr);
    GNUNET_DV_send_cancel (pr->th);
    pr->th = NULL;
    if (NULL != pr->transmit_cont)
      pr->transmit_cont (pr->transmit_cont_cls,
			 &session->sender,
			 GNUNET_SYSERR,
                         pr->size, 0);
    GNUNET_free (pr);
  }
  GNUNET_HELLO_address_free (session->address);
  GNUNET_free (session);
}


/**
 * Function called if DV is no longer able to talk to a peer.
 *
 * @param cls closure with `struct Plugin *`
 * @param peer peer that disconnected
 */
static void
handle_dv_disconnect (void *cls,
                      const struct GNUNET_PeerIdentity *peer)
{
  struct Plugin *plugin = cls;
  struct Session *session;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Received `%s' message for peer `%s'\n",
       "DV_DISCONNECT",
       GNUNET_i2s (peer));
  session = GNUNET_CONTAINER_multipeermap_get (plugin->sessions,
					       peer);
  if (NULL == session)
    return; /* nothing to do */
  free_session (session);
}


/**
 * Function called once the delivery of a message has been successful.
 * Clean up the pending request, and call continuations.
 *
 * @param cls closure
 * @param ok #GNUNET_OK on success, #GNUNET_SYSERR on error
 */
static void
send_finished (void *cls,
	       int ok)
{
  struct PendingRequest *pr = cls;
  struct Session *session = pr->session;

  pr->th = NULL;
  GNUNET_CONTAINER_DLL_remove (session->pr_head,
			       session->pr_tail,
			       pr);
  if (NULL != pr->transmit_cont)
    pr->transmit_cont (pr->transmit_cont_cls,
		       &session->sender,
		       ok,
                       pr->size, 0);
  GNUNET_free (pr);
}


/**
 * Function that can be used by the transport service to transmit
 * a message using the plugin.
 *
 * @param cls closure
 * @param session the session used
 * @param priority how important is the message
 * @param msgbuf the message to transmit
 * @param msgbuf_size number of bytes in 'msgbuf'
 * @param timeout when should we time out
 * @param cont continuation to call once the message has
 *        been transmitted (or if the transport is ready
 *        for the next transmission call; or if the
 *        peer disconnected...)
 * @param cont_cls closure for @a cont
 * @return number of bytes used (on the physical network, with overheads);
 *         -1 on hard errors (i.e. address invalid); 0 is a legal value
 *         and does NOT mean that the message was not transmitted (DV)
 */
static ssize_t
dv_plugin_send (void *cls,
		struct Session *session,
                const char *msgbuf,
                size_t msgbuf_size,
                unsigned int priority,
                struct GNUNET_TIME_Relative timeout,
                GNUNET_TRANSPORT_TransmitContinuation cont, void *cont_cls)
{
  struct Plugin *plugin = cls;
  struct PendingRequest *pr;
  const struct GNUNET_MessageHeader *msg;
  struct GNUNET_MessageHeader *box;

  box = NULL;
  msg = (const struct GNUNET_MessageHeader *) msgbuf;
  if (ntohs (msg->size) != msgbuf_size)
  {
    /* need to box */
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Boxing DV message\n");
    box = GNUNET_malloc (sizeof (struct GNUNET_MessageHeader) + msgbuf_size);
    box->type = htons (GNUNET_MESSAGE_TYPE_DV_BOX);
    box->size = htons (sizeof (struct GNUNET_MessageHeader) + msgbuf_size);
    memcpy (&box[1], msgbuf, msgbuf_size);
    msg = box;
  }
  pr = GNUNET_new (struct PendingRequest);
  pr->transmit_cont = cont;
  pr->transmit_cont_cls = cont_cls;
  pr->session = session;
  pr->size = msgbuf_size;
  GNUNET_CONTAINER_DLL_insert_tail (session->pr_head,
				    session->pr_tail,
				    pr);

  pr->th = GNUNET_DV_send (plugin->dvh,
			   &session->sender,
			   msg,
			   &send_finished,
			   pr);
  GNUNET_free_non_null (box);
  return 0; /* DV */
}


/**
 * Function that can be used to force the plugin to disconnect
 * from the given peer and cancel all previous transmissions
 * (and their continuations).
 *
 * @param cls closure with the `struct Plugin *`
 * @param target peer from which to disconnect
 */
static void
dv_plugin_disconnect_peer (void *cls,
                           const struct GNUNET_PeerIdentity *target)
{
  struct Plugin *plugin = cls;
  struct Session *session;
  struct PendingRequest *pr;

  session = GNUNET_CONTAINER_multipeermap_get (plugin->sessions,
					       target);
  if (NULL == session)
    return; /* nothing to do */
  while (NULL != (pr = session->pr_head))
  {
    GNUNET_CONTAINER_DLL_remove (session->pr_head,
				 session->pr_tail,
				 pr);
    GNUNET_DV_send_cancel (pr->th);
    pr->th = NULL;
    if (NULL != pr->transmit_cont)
      pr->transmit_cont (pr->transmit_cont_cls,
			 &session->sender,
			 GNUNET_SYSERR,
                         pr->size, 0);
    GNUNET_free (pr);
  }
  session->active = GNUNET_NO;
}


/**
 * Function that can be used to force the plugin to disconnect
 * from the given peer and cancel all previous transmissions
 * (and their continuations).
 *
 * @param cls closure with the `struct Plugin *`
 * @param session which session to disconnect
 * @return #GNUNET_OK
 */
static int
dv_plugin_disconnect_session (void *cls,
                              struct Session *session)
{
  struct PendingRequest *pr;

  while (NULL != (pr = session->pr_head))
  {
    GNUNET_CONTAINER_DLL_remove (session->pr_head,
				 session->pr_tail,
				 pr);
    GNUNET_DV_send_cancel (pr->th);
    pr->th = NULL;
    if (NULL != pr->transmit_cont)
      pr->transmit_cont (pr->transmit_cont_cls,
			 &session->sender,
			 GNUNET_SYSERR,
                         pr->size, 0);
    GNUNET_free (pr);
  }
  session->active = GNUNET_NO;
  return GNUNET_OK;
}


/**
 * Convert the transports address to a nice, human-readable
 * format.
 *
 * @param cls closure
 * @param type name of the transport that generated the address
 * @param addr one of the addresses of the host, NULL for the last address
 *        the specific address format depends on the transport
 * @param addrlen length of the address
 * @param numeric should (IP) addresses be displayed in numeric form?
 * @param timeout after how long should we give up?
 * @param asc function to call on each string
 * @param asc_cls closure for @a asc
 */
static void
dv_plugin_address_pretty_printer (void *cls, const char *type,
                                  const void *addr,
                                  size_t addrlen, int numeric,
                                  struct GNUNET_TIME_Relative timeout,
                                  GNUNET_TRANSPORT_AddressStringCallback asc,
                                  void *asc_cls)
{
  if ( (0 == addrlen) &&
       (0 == strcmp (type, "dv")) )
    asc (asc_cls,
         "dv",
         GNUNET_OK);
  else
    asc (asc_cls,
         NULL,
         GNUNET_SYSERR);
  asc (asc_cls,
       NULL,
       GNUNET_OK);
}


/**
 * Convert the DV address to a pretty string.
 *
 * @param cls closure
 * @param addr the (hopefully) DV address
 * @param addrlen the length of the @a addr
 * @return string representing the DV address
 */
static const char *
dv_plugin_address_to_string (void *cls,
                             const void *addr,
                             size_t addrlen)
{
  if (0 != addrlen)
  {
    GNUNET_break (0); /* malformed */
    return NULL;
  }
  return "dv";
}


/**
 * Another peer has suggested an address for this peer and transport
 * plugin.  Check that this could be a valid address.  This function
 * is not expected to 'validate' the address in the sense of trying to
 * connect to it but simply to see if the binary format is technically
 * legal for establishing a connection to this peer (and make sure that
 * the address really corresponds to our network connection/settings
 * and not some potential man-in-the-middle).
 *
 * @param cls closure
 * @param addr pointer to the address
 * @param addrlen length of @a addr
 * @return #GNUNET_OK if this is a plausible address for this peer
 *         and transport, #GNUNET_SYSERR if not
 *
 */
static int
dv_plugin_check_address (void *cls,
                         const void *addr,
                         size_t addrlen)
{
  if (0 != addrlen)
    return GNUNET_SYSERR;
  return GNUNET_OK;
}


/**
 * Create a new session to transmit data to the target
 * This session will used to send data to this peer and the plugin will
 * notify us by calling the env->session_end function
 *
 * @param cls the plugin
 * @param address the address
 * @return the session if the address is valid, NULL otherwise
 */
static struct Session *
dv_get_session (void *cls,
		const struct GNUNET_HELLO_Address *address)
{
  struct Plugin *plugin = cls;
  struct Session *session;

  if (0 != address->address_length)
    return NULL;
  session = GNUNET_CONTAINER_multipeermap_get (plugin->sessions,
					       &address->peer);
  if (NULL == session)
    return NULL; /* not valid right now */
  session->active = GNUNET_YES;
  return session;
}


/**
 * Function called to convert a string address to
 * a binary address.
 *
 * @param cls closure ('struct Plugin*')
 * @param addr string address
 * @param addrlen length of the @a addr including \0 termination
 * @param buf location to store the buffer
 *        If the function returns #GNUNET_SYSERR, its contents are undefined.
 * @param added length of created address
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on failure
 */
static int
dv_plugin_string_to_address (void *cls,
			     const char *addr,
			     uint16_t addrlen,
			     void **buf,
			     size_t *added)
{
  if ( (addrlen == 3) &&
       (0 == strcmp ("dv", addr)) )
  {
    *added = 0;
    return GNUNET_OK;
  }
  return GNUNET_SYSERR;
}


/**
 * Function that will be called whenever the transport service wants to
 * notify the plugin that a session is still active and in use and
 * therefore the session timeout for this session has to be updated
 *
 * @param cls closure (`struct Plugin *`)
 * @param peer which peer was the session for
 * @param session which session is being updated
 */
static void
dv_plugin_update_session_timeout (void *cls,
                                  const struct GNUNET_PeerIdentity *peer,
                                  struct Session *session)
{
  /* DV currently doesn't time out like "normal" plugins,
     so it should be safe to do nothing, right?
     (or should we add an internal timeout?) */
}


/**
 * Function to obtain the network type for a session
 * FIXME: we should probably look at the network type
 * used by the next hop here.  Or find some other way
 * to properly allow ATS-DV resource allocation.
 *
 * @param cls closure (`struct Plugin *`)
 * @param session the session
 * @return the network type
 */
static enum GNUNET_ATS_Network_Type
dv_get_network (void *cls,
		struct Session *session)
{
  GNUNET_assert (NULL != session);
  return session->network;
}


/**
 * Function that is called to get the keepalive factor.
 * #GNUNET_CONSTANTS_IDLE_CONNECTION_TIMEOUT is divided by this number to
 * calculate the interval between keepalive packets.
 *
 * @param cls closure with the `struct Plugin`
 * @return keepalive factor
 */
static unsigned int
dv_plugin_query_keepalive_factor (void *cls)
{
  return 3;
}


/**
 * Return information about the given session to the
 * monitor callback.
 *
 * @param cls the `struct Plugin` with the monitor callback (`sic`)
 * @param peer peer we send information about
 * @param value our `struct Session` to send information about
 * @return #GNUNET_OK (continue to iterate)
 */
static int
send_session_info_iter (void *cls,
                        const struct GNUNET_PeerIdentity *peer,
                        void *value)
{
  struct Plugin *plugin = cls;
  struct Session *session = value;

  if (GNUNET_YES != session->active)
    return GNUNET_OK;
  notify_session_monitor (plugin,
                          session,
                          GNUNET_TRANSPORT_SS_UP);
  return GNUNET_OK;
}


/**
 * Begin monitoring sessions of a plugin.  There can only
 * be one active monitor per plugin (i.e. if there are
 * multiple monitors, the transport service needs to
 * multiplex the generated events over all of them).
 *
 * @param cls closure of the plugin
 * @param sic callback to invoke, NULL to disable monitor;
 *            plugin will being by iterating over all active
 *            sessions immediately and then enter monitor mode
 * @param sic_cls closure for @a sic
 */
static void
dv_plugin_setup_monitor (void *cls,
                          GNUNET_TRANSPORT_SessionInfoCallback sic,
                          void *sic_cls)
{
  struct Plugin *plugin = cls;

  plugin->sic = sic;
  plugin->sic_cls = sic_cls;
  if (NULL != sic)
  {
    GNUNET_CONTAINER_multipeermap_iterate (plugin->sessions,
                                           &send_session_info_iter,
                                           plugin);
    /* signal end of first iteration */
    sic (sic_cls, NULL, NULL);
  }
}


/**
 * Entry point for the plugin.
 *
 * @param cls closure with the plugin environment
 * @return plugin API
 */
void *
libgnunet_plugin_transport_dv_init (void *cls)
{
  struct GNUNET_TRANSPORT_PluginEnvironment *env = cls;
  struct GNUNET_TRANSPORT_PluginFunctions *api;
  struct Plugin *plugin;

  plugin = GNUNET_new (struct Plugin);
  plugin->env = env;
  plugin->sessions = GNUNET_CONTAINER_multipeermap_create (1024 * 8, GNUNET_YES);
  plugin->mst = GNUNET_SERVER_mst_create (&unbox_cb,
					  plugin);
  plugin->dvh = GNUNET_DV_service_connect (env->cfg,
					   plugin,
					   &handle_dv_connect,
					   &handle_dv_distance_changed,
					   &handle_dv_disconnect,
					   &handle_dv_message_received);
  if (NULL == plugin->dvh)
  {
    GNUNET_CONTAINER_multipeermap_destroy (plugin->sessions);
    GNUNET_SERVER_mst_destroy (plugin->mst);
    GNUNET_free (plugin);
    return NULL;
  }
  api = GNUNET_new (struct GNUNET_TRANSPORT_PluginFunctions);
  api->cls = plugin;
  api->send = &dv_plugin_send;
  api->disconnect_peer = &dv_plugin_disconnect_peer;
  api->disconnect_session = &dv_plugin_disconnect_session;
  api->address_pretty_printer = &dv_plugin_address_pretty_printer;
  api->check_address = &dv_plugin_check_address;
  api->address_to_string = &dv_plugin_address_to_string;
  api->string_to_address = &dv_plugin_string_to_address;
  api->query_keepalive_factor = &dv_plugin_query_keepalive_factor;
  api->get_session = &dv_get_session;
  api->get_network = &dv_get_network;
  api->update_session_timeout = &dv_plugin_update_session_timeout;
  api->setup_monitor = &dv_plugin_setup_monitor;
  return api;
}


/**
 * Function called to free a session.
 *
 * @param cls NULL
 * @param key unused
 * @param value session to free
 * @return #GNUNET_OK (continue to iterate)
 */
static int
free_session_iterator (void *cls,
		       const struct GNUNET_PeerIdentity *key,
		       void *value)
{
  struct Session *session = value;

  free_session (session);
  return GNUNET_OK;
}


/**
 * Exit point from the plugin.
 *
 * @param cls plugin API
 * @return NULL
 */
void *
libgnunet_plugin_transport_dv_done (void *cls)
{
  struct GNUNET_TRANSPORT_PluginFunctions *api = cls;
  struct Plugin *plugin = api->cls;

  GNUNET_DV_service_disconnect (plugin->dvh);
  GNUNET_CONTAINER_multipeermap_iterate (plugin->sessions,
					 &free_session_iterator,
					 NULL);
  GNUNET_CONTAINER_multipeermap_destroy (plugin->sessions);
  GNUNET_SERVER_mst_destroy (plugin->mst);
  GNUNET_free (plugin);
  GNUNET_free (api);
  return NULL;
}

/* end of plugin_transport_dv.c */

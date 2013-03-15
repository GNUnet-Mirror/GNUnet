/*
     This file is part of GNUnet
     (C) 2002--2013 Christian Grothoff (and other contributing authors)

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
#include "gnunet_protocols.h"
#include "gnunet_connection_lib.h"
#include "gnunet_server_lib.h"
#include "gnunet_service_lib.h"
#include "gnunet_statistics_service.h"
#include "gnunet_dv_service.h"
#include "gnunet_transport_service.h"
#include "gnunet_transport_plugin.h"
#include "dv.h"

#define DEBUG_TEMPLATE GNUNET_EXTRA_LOGGING

/**
 * Encapsulation of all of the state of the plugin.
 */
struct Plugin;


/**
 * Session handle for connections.
 */
struct Session
{

  /**
   * Stored in a linked list.
   */
  struct Session *next;

  /**
   * Pointer to the global plugin struct.
   */
  struct Plugin *plugin;

  /**
   * The client (used to identify this connection)
   */
  /* void *client; */

  /**
   * Continuation function to call once the transmission buffer
   * has again space available.  NULL if there is no
   * continuation to call.
   */
  GNUNET_TRANSPORT_TransmitContinuation transmit_cont;

  /**
   * Closure for transmit_cont.
   */
  void *transmit_cont_cls;

  /**
   * To whom are we talking to (set to our identity
   * if we are still waiting for the welcome message)
   */
  struct GNUNET_PeerIdentity sender;

  /**
   * At what time did we reset last_received last?
   */
  struct GNUNET_TIME_Absolute last_quota_update;

  /**
   * How many bytes have we received since the "last_quota_update"
   * timestamp?
   */
  uint64_t last_received;

  /**
   * Number of bytes per ms that this peer is allowed
   * to send to us.
   */
  uint32_t quota;

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
   * List of open sessions.  FIXME: use hash map!
   */
  struct Session *sessions;

  /**
   * Copy of the handler array where the closures are
   * set to this struct's instance.
   */
  struct GNUNET_SERVER_MessageHandler *handlers;

  /**
   * Handle to the DV service
   */
  struct GNUNET_DV_ServiceHandle *dvh;

};


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

  ats.type = htonl (GNUNET_ATS_QUALITY_NET_DISTANCE);
  ats.value = htonl (distance);

  plugin->env->receive (plugin->env->cls, sender,
                        msg,
                        &ats, 1,
			NULL, NULL, 0);
}


/* Question: how does the transport service learn of a newly connected (gossipped about)
 * DV peer?  Should the plugin (here) create a HELLO for that peer and send it along,
 * or should the DV service create a HELLO and send it to us via the other part?
 */

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
 * @param cont_cls closure for cont
 * @return number of bytes used (on the physical network, with overheads);
 *         -1 on hard errors (i.e. address invalid); 0 is a legal value
 *         and does NOT mean that the message was not transmitted (DV)
 */
static ssize_t
dv_plugin_send (void *cls, 
		struct Session *session,
                const char *msgbuf, size_t msgbuf_size, unsigned int priority,
                struct GNUNET_TIME_Relative timeout, 
                GNUNET_TRANSPORT_TransmitContinuation cont, void *cont_cls)
{
  int ret = -1;

  return ret;
}



/**
 * Function that can be used to force the plugin to disconnect
 * from the given peer and cancel all previous transmissions
 * (and their continuations).
 *
 * @param cls closure
 * @param target peer from which to disconnect
 */
static void
dv_plugin_disconnect (void *cls, const struct GNUNET_PeerIdentity *target)
{
  // struct Plugin *plugin = cls;
  // TODO: Add message type to send to dv service to "disconnect" a peer
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
 * @param asc_cls closure for asc
 */
static void
dv_plugin_address_pretty_printer (void *cls, const char *type, const void *addr,
                                  size_t addrlen, int numeric,
                                  struct GNUNET_TIME_Relative timeout,
                                  GNUNET_TRANSPORT_AddressStringCallback asc,
                                  void *asc_cls)
{
  asc (asc_cls, NULL);
}


/**
 * Convert the DV address to a pretty string.
 *
 * @param cls closure
 * @param addr the (hopefully) DV address
 * @param addrlen the length of the address
 *
 * @return string representing the DV address
 */
static const char *
address_to_string (void *cls, const void *addr, size_t addrlen)
{
  return "<not implemented>";
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
 * @param addrlen length of addr
 * @return GNUNET_OK if this is a plausible address for this peer
 *         and transport, GNUNET_SYSERR if not
 *
 */
static int
dv_plugin_check_address (void *cls, const void *addr, size_t addrlen)
{
  return GNUNET_SYSERR;
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
  return NULL;
}


/**
 * Entry point for the plugin.
 */
void *
libgnunet_plugin_transport_dv_init (void *cls)
{
  struct GNUNET_TRANSPORT_PluginEnvironment *env = cls;
  struct GNUNET_TRANSPORT_PluginFunctions *api;
  struct Plugin *plugin;

  plugin = GNUNET_malloc (sizeof (struct Plugin));
  plugin->env = env;
  plugin->dvh = GNUNET_DV_service_connect (env->cfg,
					   plugin,
					   NULL, NULL, NULL, /*FIXME! */
					   &handle_dv_message_received);
  api = GNUNET_malloc (sizeof (struct GNUNET_TRANSPORT_PluginFunctions));
  api->cls = plugin;
  api->send = &dv_plugin_send;
  api->disconnect = &dv_plugin_disconnect;
  api->address_pretty_printer = &dv_plugin_address_pretty_printer;
  api->check_address = &dv_plugin_check_address;
  api->address_to_string = &address_to_string;
  api->string_to_address = NULL; /* FIXME */
  api->get_session = dv_get_session;
  return api;
}


/**
 * Exit point from the plugin.
 */
void *
libgnunet_plugin_transport_dv_done (void *cls)
{
  struct GNUNET_TRANSPORT_PluginFunctions *api = cls;
  struct Plugin *plugin = api->cls;

  GNUNET_DV_service_disconnect (plugin->dvh);
  GNUNET_free (plugin);
  GNUNET_free (api);
  return NULL;
}

/* end of plugin_transport_dv.c */

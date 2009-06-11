/*
     This file is part of GNUnet
     (C) 2002, 2003, 2004, 2005, 2006, 2007, 2008, 2009 Christian Grothoff (and other contributing authors)

     GNUnet is free software; you can redistribute it and/or modify
     it under the terms of the GNU General Public License as published
     by the Free Software Foundation; either version 2, or (at your
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
 * @file transport/plugin_transport_template.c
 * @brief template for a new transport service
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_protocols.h"
#include "gnunet_network_lib.h"
#include "gnunet_server_lib.h"
#include "gnunet_service_lib.h"
#include "gnunet_statistics_service.h"
#include "gnunet_transport_service.h"
#include "plugin_transport.h"

#define DEBUG_TEMPLATE GNUNET_NO

/**
 * After how long do we expire an address that we
 * learned from another peer if it is not reconfirmed
 * by anyone?
 */
#define LEARNED_ADDRESS_EXPIRATION GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_HOURS, 6)


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
   * List of open sessions.
   */
  struct Session *sessions;

  /**
   * Handle for the statistics service.
   */
  struct GNUNET_STATISTICS_Handle *statistics;

};



/**
 * Function that can be used by the transport service to transmit
 * a message using the plugin using a fresh connection (even if
 * we already have a connection to this peer, this function is
 * required to establish a new one).
 *
 * @param cls closure
 * @param target who should receive this message
 * @param priority how important is the message
 * @param msg1 first message to transmit
 * @param msg2 second message to transmit (can be NULL)
 * @param timeout how long until we give up?
 * @param addr the address
 * @param addrlen length of the address
 * @return non-null session if the transmission has been scheduled
 *         NULL if the address format is invalid
 */
static void *
template_plugin_send_to (void *cls,
                         const struct GNUNET_PeerIdentity *target,
			 unsigned int priority,
                         const struct GNUNET_MessageHeader *msg1,
                         const struct GNUNET_MessageHeader *msg2,
                         struct GNUNET_TIME_Relative timeout,
                         const void *addr, size_t addrlen)
{
  // FIXME
  return NULL;
}


/**
 * Function that can be used by the transport service to transmit
 * a message using the plugin.
 *
 * @param cls closure
 * @param plugin_context value we were asked to pass to this plugin
 *        to respond to the given peer (use is optional,
 *        but may speed up processing), can be NULL
 * @param service_context value passed to the transport-service
 *        to identify the neighbour
 * @param target who should receive this message
 * @param priority how important is the message
 * @param msg the message to transmit
 * @param cont continuation to call once the message has
 *        been transmitted (or if the transport is ready
 *        for the next transmission call; or if the
 *        peer disconnected...)
 * @param cont_cls closure for cont
 * @return plugin_context that should be used next time for
 *         sending messages to the specified peer
 */
static void *
template_plugin_send (void *cls,
                      void *plugin_context,
                      struct ReadyList *service_context,
                      const struct GNUNET_PeerIdentity *target,
		      unsigned int priority,
                      const struct GNUNET_MessageHeader *msg,
                      struct GNUNET_TIME_Relative timeout,
                      GNUNET_TRANSPORT_TransmitContinuation cont,
                      void *cont_cls)
{
  //  struct Plugin *plugin = cls;
  return NULL;
}



/**
 *
 * @param cls closure
 * @param plugin_context value we were asked to pass to this plugin
 *        to respond to the given peer (use is optional,
 *        but may speed up processing), can be NULL (if
 *        NULL was returned from the transmit function)
 * @param service_context must correspond to the service context
 *        of the corresponding Transmit call; the plugin should
 *        not cancel a send call made with a different service
 *        context pointer!  Never NULL.
 * @param target peer for which the last transmission is
 *        to be cancelled
 */
static void
template_plugin_cancel (void *cls,
                        void *plugin_context,
                        struct ReadyList *service_context,
                        const struct GNUNET_PeerIdentity *target)
{
  // struct Plugin *plugin = cls;
  // FIXME
}


/**
 * Convert the transports address to a nice, human-readable
 * format.
 *
 * @param cls closure
 * @param name name of the transport that generated the address
 * @param addr one of the addresses of the host, NULL for the last address
 *        the specific address format depends on the transport
 * @param addrlen length of the address
 * @param numeric should (IP) addresses be displayed in numeric form?
 * @param timeout after how long should we give up?
 * @param asc function to call on each string
 * @param asc_cls closure for asc
 */
static void
template_plugin_address_pretty_printer (void *cls,
                                        const char *type,
                                        const void *addr,
                                        size_t addrlen,
                                        int numeric,
                                        struct GNUNET_TIME_Relative timeout,
                                        GNUNET_TRANSPORT_AddressStringCallback
                                        asc, void *asc_cls)
{
  asc (asc_cls, NULL);
}

/**
 * Set a quota for receiving data from the given peer; this is a
 * per-transport limit.  The transport should limit its read/select
 * calls to stay below the quota (in terms of incoming data).
 *
 * @param cls closure
 * @param peer the peer for whom the quota is given
 * @param quota_in quota for receiving/sending data in bytes per ms
 */
static void
template_plugin_set_receive_quota (void *cls,
                                   const struct GNUNET_PeerIdentity *target,
                                   uint32_t quota_in)
{
  // struct Plugin *plugin = cls;
  // FIXME!
}


/**
 * Another peer has suggested an address for this
 * peer and transport plugin.  Check that this could be a valid
 * address.  If so, consider adding it to the list
 * of addresses.
 *
 * @param cls closure
 * @param addr pointer to the address
 * @param addrlen length of addr
 * @return GNUNET_OK if this is a plausible address for this peer
 *         and transport
 */
static int
template_plugin_address_suggested (void *cls,
                                   const void *addr, size_t addrlen)
{
  // struct Plugin *plugin = cls;

  /* check if the address is plausible; if so,
     add it to our list! */
  // FIXME!
  return GNUNET_OK;
}


/**
 * Entry point for the plugin.
 */
void *
gnunet_plugin_transport_template_init (void *cls)
{
  struct GNUNET_TRANSPORT_PluginEnvironment *env = cls;
  struct GNUNET_TRANSPORT_PluginFunctions *api;
  struct Plugin *plugin;

  plugin = GNUNET_malloc (sizeof (struct Plugin));
  plugin->env = env;
  plugin->statistics = NULL;
  api = GNUNET_malloc (sizeof (struct GNUNET_TRANSPORT_PluginFunctions));
  api->cls = plugin;
  api->send_to = &template_plugin_send_to;
  api->send = &template_plugin_send;
  api->cancel = &template_plugin_cancel;
  api->address_pretty_printer = &template_plugin_address_pretty_printer;
  api->set_receive_quota = &template_plugin_set_receive_quota;
  api->address_suggested = &template_plugin_address_suggested;
  api->cost_estimate = 42;      // FIXME
  return api;
}


/**
 * Exit point from the plugin.
 */
void *
gnunet_plugin_transport_template_done (void *cls)
{
  struct GNUNET_TRANSPORT_PluginFunctions *api = cls;
  struct Plugin *plugin = api->cls;

  GNUNET_free (plugin);
  GNUNET_free (api);
  return NULL;
}

/* end of plugin_transport_template.c */

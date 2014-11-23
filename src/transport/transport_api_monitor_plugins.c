/*
     This file is part of GNUnet.
     (C) 2014 Christian Grothoff (and other contributing authors)

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
 * @file transport/transport_api_monitor_plugins.c
 * @brief montoring api for transport plugin session status
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_arm_service.h"
#include "gnunet_hello_lib.h"
#include "gnunet_protocols.h"
#include "gnunet_transport_service.h"
#include "transport.h"


/**
 * Handle for a plugin session state monitor.
 */
struct GNUNET_TRANSPORT_PluginMonitor
{

  /**
   * Connection to the service.
   */
  struct GNUNET_CLIENT_Connection *client;

  /**
   * Our configuration.
   */
  const struct GNUNET_CONFIGURATION_Handle *cfg;

  /**
   * Callback to call.
   */
  GNUNET_TRANSPORT_SessionMonitorCallback cb;

  /**
   * Closure for @e cb
   */
  void *cb_cls;

  /**
   * Map of session_ids (reduced to 32-bits) to
   * `struct GNUNET_TRANSPORT_PluginSession` objects.
   */
  struct GNUNET_CONTAINER_MultiHashMap32 *sessions;

  /**
   * Backoff for reconnect.
   */
  struct GNUNET_TIME_Relative backoff;

  /**
   * Task ID for reconnect.
   */
  GNUNET_SCHEDULER_TaskIdentifier reconnect_task;

};


/**
 * Abstract representation of a plugin's session.
 * Corresponds to the `struct Session` within the TRANSPORT service.
 */
struct GNUNET_TRANSPORT_PluginSession
{
  /**
   * Unique session identifier.
   */
  uint64_t session_id;

  /**
   * Location for the client to store "data".
   */
  void *client_ctx;
};


/**
 * Function called with responses from the service.
 *
 * @param cls our `struct GNUNET_TRANSPORT_PluginMonitor *`
 * @param msg NULL on timeout or error, otherwise presumably a
 *        message with the human-readable address
 */
static void
response_processor (void *cls,
                    const struct GNUNET_MessageHeader *msg);


/**
 * Send our subscription request to the service.
 *
 * @param pal_ctx our context
 */
static void
send_plugin_mon_request (struct GNUNET_TRANSPORT_PluginMonitor *pm)
{
  struct GNUNET_MessageHeader msg;

  msg.size = htons (sizeof (struct GNUNET_MessageHeader));
  msg.type = htons (GNUNET_MESSAGE_TYPE_TRANSPORT_MONITOR_PLUGIN_START);
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_CLIENT_transmit_and_get_response (pm->client,
                                                          &msg,
                                                          GNUNET_TIME_UNIT_FOREVER_REL,
                                                          GNUNET_YES,
                                                          &response_processor,
                                                          pm));
}


/**
 * Task run to re-establish the connection.
 *
 * @param cls our `struct GNUNET_TRANSPORT_PluginMonitor *`
 * @param tc scheduler context, unused
 */
static void
do_plugin_connect (void *cls,
                 const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_TRANSPORT_PluginMonitor *pm = cls;

  pm->reconnect_task = GNUNET_SCHEDULER_NO_TASK;
  pm->client = GNUNET_CLIENT_connect ("transport", pm->cfg);
  GNUNET_assert (NULL != pm->client);
  send_plugin_mon_request (pm);
}


/**
 * Free the session entry and notify the callback about its demise.
 *
 * @param cls our `struct GNUNET_TRANSPORT_PluginMonitor`
 * @param key key of the session in the map
 * @param value the session to free
 * @return #GNUNET_OK (continue to iterate)
 */
static int
free_entry (void *cls,
            uint32_t key,
            void *value)
{
  struct GNUNET_TRANSPORT_PluginMonitor *pm = cls;
  struct GNUNET_TRANSPORT_PluginSession *ps = value;

  pm->cb (pm->cb_cls,
          ps,
          &ps->client_ctx,
          NULL);
  GNUNET_break (GNUNET_YES ==
                GNUNET_CONTAINER_multihashmap32_remove (pm->sessions,
                                                        key,
                                                        ps));
  GNUNET_break (NULL == ps->client_ctx);
  GNUNET_free (ps);
  return GNUNET_OK;
}


/**
 * We got disconnected, remove all existing entries from
 * the map and notify client.
 *
 * @param pm montitor that got disconnected
 */
static void
clear_map (struct GNUNET_TRANSPORT_PluginMonitor *pm)
{
  GNUNET_CONTAINER_multihashmap32_iterate (pm->sessions,
                                           &free_entry,
                                           pm);
}


/**
 * Cut the existing connection and reconnect.
 *
 * @param pm our context
 */
static void
reconnect_plugin_ctx (struct GNUNET_TRANSPORT_PluginMonitor *pm)
{
  GNUNET_CLIENT_disconnect (pm->client);
  pm->client = NULL;
  clear_map (pm);
  pm->backoff = GNUNET_TIME_STD_BACKOFF (pm->backoff);
  pm->reconnect_task = GNUNET_SCHEDULER_add_delayed (pm->backoff,
                                                     &do_plugin_connect,
                                                     pm);
}


/**
 * Convert 64-bit session ID to 32-bit index for hash map.
 *
 * @param id 64-bit session ID
 * @return 32-bit hash map index
 */
static uint32_t
wrap_id (uint64_t id)
{
  return ((uint32_t) id) ^ ((uint32_t) (id >> 32));
}


/**
 * Context for #locate_by_id().
 */
struct SearchContext
{

  /**
   * Result.
   */
  struct GNUNET_TRANSPORT_PluginSession *ps;

  /**
   * ID to locate.
   */
  uint64_t session_id;

};


/**
 * Locate a session entry.
 *
 * @param cls our `struct SearchContext`
 * @param key key of the session in the map
 * @param value a session
 * @return #GNUNET_OK (continue to iterate), or #GNUNET_SYSERR (match found)
 */
static int
locate_by_id (void *cls,
              uint32_t key,
              void *value)
{
  struct SearchContext *sc = cls;
  struct GNUNET_TRANSPORT_PluginSession *ps = value;

  if (sc->session_id == ps->session_id)
  {
    sc->ps = ps;
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * Function called with responses from the service.
 *
 * @param cls our `struct GNUNET_TRANSPORT_PluginMonitor *`
 * @param msg NULL on timeout or error, otherwise presumably a
 *        message with the human-readable address
 */
static void
response_processor (void *cls,
                    const struct GNUNET_MessageHeader *msg)
{
  struct GNUNET_TRANSPORT_PluginMonitor *pm = cls;
  const struct TransportPluginMonitorMessage *tpmm;
  struct GNUNET_TRANSPORT_PluginSession *ps;
  const char *pname;
  const void *paddr;
  enum GNUNET_TRANSPORT_SessionState ss;
  size_t pname_len;
  size_t paddr_len;
  struct GNUNET_TRANSPORT_SessionInfo info;
  struct GNUNET_HELLO_Address addr;
  struct SearchContext rv;

  fprintf (stderr, "R\n");
  if (NULL == msg)
  {
    reconnect_plugin_ctx (pm);
    return;
  }
  if ( (GNUNET_MESSAGE_TYPE_TRANSPORT_MONITOR_PLUGIN_SYNC == ntohs (msg->type)) &&
       (sizeof (struct GNUNET_MessageHeader) == ntohs (msg->size)) )
  {
    /* we are in sync */
    pm->cb (pm->cb_cls,
            NULL,
            NULL,
            NULL);
    GNUNET_CLIENT_receive (pm->client,
                           &response_processor,
                           pm,
                           GNUNET_TIME_UNIT_FOREVER_REL);
    return;
  }

  if ( (GNUNET_MESSAGE_TYPE_TRANSPORT_MONITOR_PLUGIN_EVENT != ntohs (msg->type)) ||
       (sizeof (struct TransportPluginMonitorMessage) > ntohs (msg->size)) )
  {
    GNUNET_break (0);
    reconnect_plugin_ctx (pm);
    return;
  }
  tpmm = (const struct TransportPluginMonitorMessage *) msg;
  pname = (const char *) &tpmm[1];
  pname_len = ntohs (tpmm->plugin_name_len);
  paddr_len = ntohs (tpmm->plugin_address_len);
  if ( (pname_len +
        paddr_len +
        sizeof (struct TransportPluginMonitorMessage) != ntohs (msg->size)) ||
       ( (0 != pname_len) &&
         ('\0' != pname[pname_len - 1]) ) )
  {
    GNUNET_break (0);
    reconnect_plugin_ctx (pm);
    return;
  }
  paddr = &pname[pname_len];
  ps = NULL;
  ss = (enum GNUNET_TRANSPORT_SessionState) ntohs (tpmm->session_state);
  if (GNUNET_TRANSPORT_SS_INIT == ss)
  {
    ps = GNUNET_new (struct GNUNET_TRANSPORT_PluginSession);
    ps->session_id = tpmm->session_id;
    (void) GNUNET_CONTAINER_multihashmap32_put (pm->sessions,
                                                wrap_id (tpmm->session_id),
                                                ps,
                                                GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE);

  }
  else
  {
    rv.session_id = tpmm->session_id;
    rv.ps = NULL;
    (void) GNUNET_CONTAINER_multihashmap32_get_multiple (pm->sessions,
                                                         wrap_id (tpmm->session_id),
                                                         &locate_by_id,
                                                         &rv);
    ps = rv.ps;
    if (NULL == ps)
    {
      GNUNET_break (0);
      reconnect_plugin_ctx (pm);
      return;
    }
  }
  info.state = ss;
  info.is_inbound = (int16_t) ntohs (tpmm->is_inbound);
  info.num_msg_pending = ntohl (tpmm->msgs_pending);
  info.num_bytes_pending = ntohl (tpmm->bytes_pending);
  info.receive_delay = GNUNET_TIME_absolute_ntoh (tpmm->delay);
  info.session_timeout = GNUNET_TIME_absolute_ntoh (tpmm->timeout);
  info.address = &addr;
  addr.peer = tpmm->peer;
  addr.address = (0 == paddr_len) ? NULL : paddr;
  addr.address_length = paddr_len;
  addr.transport_name = (0 == pname_len) ? NULL : pname;
  addr.local_info = GNUNET_HELLO_ADDRESS_INFO_NONE;
  pm->cb (pm->cb_cls,
          ps,
          &ps->client_ctx,
          &info);

  if (GNUNET_TRANSPORT_SS_DONE == ss)
  {
    GNUNET_break (NULL == ps->client_ctx);
    GNUNET_assert (GNUNET_YES ==
                   GNUNET_CONTAINER_multihashmap32_remove (pm->sessions,
                                                           wrap_id (tpmm->session_id),
                                                           ps));
    GNUNET_free (ps);
  }
  GNUNET_CLIENT_receive (pm->client,
                         &response_processor,
                         pm,
                         GNUNET_TIME_UNIT_FOREVER_REL);
}


/**
 * Install a plugin session state monitor callback.  The callback
 * will be notified whenever the session changes.
 *
 * @param cfg configuration to use
 * @param cb callback to invoke on events
 * @param cb_cls closure for @a cb
 * @return NULL on error, otherwise handle for cancellation
 */
struct GNUNET_TRANSPORT_PluginMonitor *
GNUNET_TRANSPORT_monitor_plugins (const struct GNUNET_CONFIGURATION_Handle *cfg,
                                  GNUNET_TRANSPORT_SessionMonitorCallback cb,
                                  void *cb_cls)
{
  struct GNUNET_TRANSPORT_PluginMonitor *pm;
  struct GNUNET_CLIENT_Connection *client;

  client = GNUNET_CLIENT_connect ("transport",
                                  cfg);
  if (NULL == client)
    return NULL;
  pm = GNUNET_new (struct GNUNET_TRANSPORT_PluginMonitor);
  pm->cb = cb;
  pm->cb_cls = cb_cls;
  pm->cfg = cfg;
  pm->client = client;
  pm->sessions = GNUNET_CONTAINER_multihashmap32_create (128);
  send_plugin_mon_request (pm);
  return pm;
}


/**
 * Cancel monitoring the plugin session state.  The callback will
 * be called once for each session that is up with the information
 * #GNUNET_TRANSPORT_SS_FINI (even though the session may stay up;
 * this is just to enable client-side cleanup).
 *
 * @param pm handle of the request that is to be cancelled
 */
void
GNUNET_TRANSPORT_monitor_plugins_cancel (struct GNUNET_TRANSPORT_PluginMonitor *pm)
{
  if (NULL != pm->client)
  {
    GNUNET_CLIENT_disconnect (pm->client);
    pm->client = NULL;
  }
  if (GNUNET_SCHEDULER_NO_TASK != pm->reconnect_task)
  {
    GNUNET_SCHEDULER_cancel (pm->reconnect_task);
    pm->reconnect_task = GNUNET_SCHEDULER_NO_TASK;
  }
  clear_map (pm);
  GNUNET_CONTAINER_multihashmap32_destroy (pm->sessions);
  GNUNET_free (pm);
}


/* end of transport_api_monitor_plugins.c */

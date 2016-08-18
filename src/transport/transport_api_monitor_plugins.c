/*
     This file is part of GNUnet.
     Copyright (C) 2014, 2016 GNUnet e.V.

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
  struct GNUNET_MQ_Handle *mq;

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
  struct GNUNET_SCHEDULER_Task *reconnect_task;

};


/**
 * Abstract representation of a plugin's session.
 * Corresponds to the `struct GNUNET_ATS_Session` within the TRANSPORT service.
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
 * Task run to re-establish the connection.
 *
 * @param cls our `struct GNUNET_TRANSPORT_PluginMonitor *`
 */
static void
do_plugin_connect (void *cls);


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
 * Cut the existing connection and reconnect.
 *
 * @param pm our context
 */
static void
reconnect_plugin_ctx (struct GNUNET_TRANSPORT_PluginMonitor *pm)
{
  GNUNET_MQ_destroy (pm->mq);
  pm->mq = NULL;
  GNUNET_CONTAINER_multihashmap32_iterate (pm->sessions,
                                           &free_entry,
                                           pm);
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
 * @paramm tpmm message with event data
 * @return #GNUNET_Ok if message is well-formed
 */
static int
check_event (void *cls,
             const struct TransportPluginMonitorMessage *tpmm)
{
  const char *pname;
  size_t pname_len;
  size_t paddr_len;

  pname = (const char *) &tpmm[1];
  pname_len = ntohs (tpmm->plugin_name_len);
  paddr_len = ntohs (tpmm->plugin_address_len);
  if ( (pname_len +
        paddr_len +
        sizeof (struct TransportPluginMonitorMessage) != ntohs (tpmm->header.size)) ||
       ( (0 != pname_len) &&
         ('\0' != pname[pname_len - 1]) ) )
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * Function called with responses from the service.
 *
 * @param cls our `struct GNUNET_TRANSPORT_PluginMonitor *`
 * @paramm tpmm message with event data
 */
static void
handle_event (void *cls,
              const struct TransportPluginMonitorMessage *tpmm)
{
  struct GNUNET_TRANSPORT_PluginMonitor *pm = cls;
  struct GNUNET_TRANSPORT_PluginSession *ps;
  const char *pname;
  const void *paddr;
  enum GNUNET_TRANSPORT_SessionState ss;
  size_t pname_len;
  size_t paddr_len;
  struct GNUNET_TRANSPORT_SessionInfo info;
  struct GNUNET_HELLO_Address addr;
  struct SearchContext rv;

  pname = (const char *) &tpmm[1];
  pname_len = ntohs (tpmm->plugin_name_len);
  paddr_len = ntohs (tpmm->plugin_address_len);
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
}


/**
 * Function called with sync responses from the service.
 *
 * @param cls our `struct GNUNET_TRANSPORT_PluginMonitor *`
 * @param msg message from the service
 */
static void
handle_sync (void *cls,
             const struct GNUNET_MessageHeader *msg)
{
  struct GNUNET_TRANSPORT_PluginMonitor *pm = cls;

  /* we are in sync, notify callback */
  pm->cb (pm->cb_cls,
          NULL,
          NULL,
          NULL);
}


/**
 * Generic error handler, called with the appropriate
 * error code and the same closure specified at the creation of
 * the message queue.
 * Not every message queue implementation supports an error handler.
 *
 * @param cls closure with the `struct GNUNET_NSE_Handle *`
 * @param error error code
 */
static void
mq_error_handler (void *cls,
                  enum GNUNET_MQ_Error error)
{
  struct GNUNET_TRANSPORT_PluginMonitor *pm = cls;

  reconnect_plugin_ctx (pm);
}


/**
 * Task run to re-establish the connection.
 *
 * @param cls our `struct GNUNET_TRANSPORT_PluginMonitor *`
 */
static void
do_plugin_connect (void *cls)
{
  struct GNUNET_TRANSPORT_PluginMonitor *pm = cls;
  struct GNUNET_MQ_MessageHandler handlers[] = {
    GNUNET_MQ_hd_var_size (event,
                           GNUNET_MESSAGE_TYPE_TRANSPORT_MONITOR_PLUGIN_EVENT,
                           struct TransportPluginMonitorMessage,
                           pm),
    GNUNET_MQ_hd_fixed_size (sync,
                             GNUNET_MESSAGE_TYPE_TRANSPORT_MONITOR_PLUGIN_SYNC,
                             struct GNUNET_MessageHeader,
                             pm),
    GNUNET_MQ_handler_end ()
  };
  struct GNUNET_MessageHeader *msg;
  struct GNUNET_MQ_Envelope *env;

  pm->reconnect_task = NULL;
  pm->mq = GNUNET_CLIENT_connecT (pm->cfg,
                                  "transport",
                                  handlers,
                                  &mq_error_handler,
                                  pm);
  if (NULL == pm->mq)
    return;
  env = GNUNET_MQ_msg (msg,
                       GNUNET_MESSAGE_TYPE_TRANSPORT_MONITOR_PLUGIN_START);
  GNUNET_MQ_send (pm->mq,
                  env);
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

  pm = GNUNET_new (struct GNUNET_TRANSPORT_PluginMonitor);
  pm->cb = cb;
  pm->cb_cls = cb_cls;
  pm->cfg = cfg;
  do_plugin_connect (pm);
  if (NULL == pm->mq)
  {
    GNUNET_free (pm);
    return NULL;
  }
  pm->sessions = GNUNET_CONTAINER_multihashmap32_create (128);
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
  if (NULL != pm->mq)
  {
    GNUNET_MQ_destroy (pm->mq);
    pm->mq = NULL;
  }
  if (NULL != pm->reconnect_task)
  {
    GNUNET_SCHEDULER_cancel (pm->reconnect_task);
    pm->reconnect_task = NULL;
  }
  GNUNET_CONTAINER_multihashmap32_iterate (pm->sessions,
                                           &free_entry,
                                           pm);
  GNUNET_CONTAINER_multihashmap32_destroy (pm->sessions);
  GNUNET_free (pm);
}


/* end of transport_api_monitor_plugins.c */

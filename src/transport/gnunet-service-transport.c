/*
 This file is part of GNUnet.
 (C) 2010,2011 Christian Grothoff (and other contributing authors)

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
 * @file transport/gnunet-service-transport.c
 * @brief
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_hello_lib.h"
#include "gnunet_statistics_service.h"
#include "gnunet_transport_service.h"
#include "gnunet_peerinfo_service.h"
#include "gnunet_ats_service.h"
#include "gnunet-service-transport.h"
#include "gnunet-service-transport_blacklist.h"
#include "gnunet-service-transport_clients.h"
#include "gnunet-service-transport_hello.h"
#include "gnunet-service-transport_neighbours.h"
#include "gnunet-service-transport_plugins.h"
#include "gnunet-service-transport_validation.h"
#include "gnunet-service-transport_manipulation.h"
#include "transport.h"

/**
 * Information we need for an asynchronous session kill.
 */
struct SessionKiller
{
  /**
   * Kept in a DLL.
   */
  struct SessionKiller *next;

  /**
   * Kept in a DLL.
   */
  struct SessionKiller *prev;

  /**
   * Session to kill.
   */
  struct Session *session;

  /**
   * Plugin for the session.
   */
  struct GNUNET_TRANSPORT_PluginFunctions *plugin;

  /**
   * The kill task.
   */
  struct GNUNET_SCHEDULER_Task * task;
};

struct BlacklistCheckContext
{
  struct BlacklistCheckContext *prev;
  struct BlacklistCheckContext *next;


  struct GST_BlacklistCheck *blc;

  struct GNUNET_HELLO_Address *address;
  struct Session *session;
  struct GNUNET_MessageHeader *msg;
  struct GNUNET_ATS_Information *ats;
  uint32_t ats_count;
};

/* globals */

/**
 * Statistics handle.
 */
struct GNUNET_STATISTICS_Handle *GST_stats;

/**
 * Configuration handle.
 */
const struct GNUNET_CONFIGURATION_Handle *GST_cfg;

/**
 * Configuration handle.
 */
struct GNUNET_PeerIdentity GST_my_identity;

/**
 * Handle to peerinfo service.
 */
struct GNUNET_PEERINFO_Handle *GST_peerinfo;

/**
 * Handle to our service's server.
 */
static struct GNUNET_SERVER_Handle *GST_server;

/**
 * Our private key.
 */
struct GNUNET_CRYPTO_EddsaPrivateKey *GST_my_private_key;

/**
 * ATS handle.
 */
struct GNUNET_ATS_SchedulingHandle *GST_ats;

/**
 * Hello address expiration
 */
struct GNUNET_TIME_Relative hello_expiration;

/**
 * DEBUGGING connection counter
 */
static int connections;

/**
 * Head of DLL of asynchronous tasks to kill sessions.
 */
static struct SessionKiller *sk_head;

/**
 * Tail of DLL of asynchronous tasks to kill sessions.
 */
static struct SessionKiller *sk_tail;

struct BlacklistCheckContext *bc_head;
struct BlacklistCheckContext *bc_tail;


/**
 * Transmit our HELLO message to the given (connected) neighbour.
 *
 * @param cls the 'HELLO' message
 * @param target a connected neighbour
 * @param address the address
 * @param state current state this peer is in
 * @param state_timeout timeout for the current state of the peer
 * @param bandwidth_in inbound quota in NBO
 * @param bandwidth_out outbound quota in NBO
 */
static void
transmit_our_hello (void *cls, const struct GNUNET_PeerIdentity *target,
    const struct GNUNET_HELLO_Address *address,
    enum GNUNET_TRANSPORT_PeerState state,
    struct GNUNET_TIME_Absolute state_timeout,
    struct GNUNET_BANDWIDTH_Value32NBO bandwidth_in,
    struct GNUNET_BANDWIDTH_Value32NBO bandwidth_out)
{
  const struct GNUNET_MessageHeader *hello = cls;

  if (GNUNET_NO == GST_neighbours_test_connected (target))
    return;

  GST_neighbours_send (target, hello, ntohs (hello->size), hello_expiration,
      NULL, NULL );
}

/**
 * My HELLO has changed. Tell everyone who should know.
 *
 * @param cls unused
 * @param hello new HELLO
 */
static void
process_hello_update (void *cls, const struct GNUNET_MessageHeader *hello)
{
  GST_clients_broadcast (hello, GNUNET_NO);
  GST_neighbours_iterate (&transmit_our_hello, (void *) hello);
}

/**
 * We received some payload.  Prepare to pass it on to our clients.
 *
 * @param peer (claimed) identity of the other peer
 * @param address the address
 * @param session session used
 * @param message the message to process
 * @return how long the plugin should wait until receiving more data
 */
static struct GNUNET_TIME_Relative
process_payload (const struct GNUNET_PeerIdentity *peer,
    const struct GNUNET_HELLO_Address *address, struct Session *session,
    const struct GNUNET_MessageHeader *message)
{
  struct GNUNET_TIME_Relative ret;
  int do_forward;
  struct InboundMessage *im;
  size_t msg_size = ntohs (message->size);
  size_t size = sizeof(struct InboundMessage) + msg_size;
  char buf[size] GNUNET_ALIGN;

  do_forward = GNUNET_SYSERR;
  ret = GST_neighbours_calculate_receive_delay (peer, msg_size, &do_forward);
  if (!GST_neighbours_test_connected (peer))
  {
    GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
        "Discarded %u bytes type %u payload from peer `%s'\n", msg_size,
        ntohs (message->type), GNUNET_i2s (peer));
    GNUNET_STATISTICS_update (GST_stats, gettext_noop
    ("# bytes payload discarded due to not connected peer"), msg_size,
        GNUNET_NO);
    return ret;
  }

  GST_ats_add_address (address, session, NULL, 0);

  if (GNUNET_YES != do_forward)
    return ret;
  im = (struct InboundMessage *) buf;
  im->header.size = htons (size);
  im->header.type = htons (GNUNET_MESSAGE_TYPE_TRANSPORT_RECV);
  im->peer = *peer;
  memcpy (&im[1], message, ntohs (message->size));
  GST_clients_broadcast (&im->header, GNUNET_YES);
  return ret;
}

/**
 * Task to asynchronously terminate a session.
 *
 * @param cls the `struct SessionKiller` with the information for the kill
 * @param tc scheduler context
 */
static void
kill_session_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct SessionKiller *sk = cls;

  sk->task = NULL;
  GNUNET_CONTAINER_DLL_remove(sk_head, sk_tail, sk);
  sk->plugin->disconnect_session (sk->plugin->cls, sk->session);
  GNUNET_free(sk);
}

static void
cancel_pending_blacklist_checks (const struct GNUNET_HELLO_Address *address, struct Session *session)
{
  struct BlacklistCheckContext *blctx;
  struct BlacklistCheckContext *next;
  next = bc_head;
  for (blctx = next; NULL != blctx; blctx = next)
  {
    next = blctx->next;
    if ((NULL != blctx->address) && (0 == GNUNET_HELLO_address_cmp(blctx->address, address)) && (blctx->session == session))
    {
      GNUNET_CONTAINER_DLL_remove (bc_head, bc_tail, blctx);
      if (NULL != blctx->blc)
      {
        GST_blacklist_test_cancel (blctx->blc);
        blctx->blc = NULL;
      }
      GNUNET_HELLO_address_free (blctx->address);
      GNUNET_free_non_null (blctx->msg);
      GNUNET_free_non_null (blctx->ats);
      GNUNET_free (blctx);
    }
  }
}

/**
 * Force plugin to terminate session due to communication
 * issue.
 *
 * @param plugin_name name of the plugin
 * @param session session to termiante
 */
static void
kill_session (const char *plugin_name, struct Session *session)
{
  struct GNUNET_TRANSPORT_PluginFunctions *plugin;
  struct SessionKiller *sk;

  for (sk = sk_head; NULL != sk; sk = sk->next)
    if (sk->session == session)
      return;
  plugin = GST_plugins_find (plugin_name);
  if (NULL == plugin)
  {
    GNUNET_break(0);
    return;
  }
  /* need to issue disconnect asynchronously */
  sk = GNUNET_new (struct SessionKiller);
  sk->session = session;
  sk->plugin = plugin;
  sk->task = GNUNET_SCHEDULER_add_now (&kill_session_task, sk);
  GNUNET_CONTAINER_DLL_insert(sk_head, sk_tail, sk);
}



/**
 * Black list check result for try_connect call
 * If connection to the peer is allowed request adddress and
 *
 * @param cls blc_ctx bl context
 * @param peer the peer
 * @param result the result
 */
static void
connect_bl_check_cont (void *cls,
    const struct GNUNET_PeerIdentity *peer, int result)
{
  struct BlacklistCheckContext *blctx = cls;

  GNUNET_CONTAINER_DLL_remove (bc_head, bc_tail, blctx);
  blctx->blc = NULL;

  if (GNUNET_OK == result)
  {
    /* Blacklist allows to speak to this peer, forward SYN to neighbours  */
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                "Received SYN message from peer `%s' with `%s' %p\n",
                GNUNET_i2s (peer), GST_plugins_a2s (blctx->address), blctx->session);

    if (GNUNET_OK != GST_neighbours_handle_session_syn (blctx->msg,
        &blctx->address->peer))
    {
      cancel_pending_blacklist_checks (blctx->address, blctx->session);
      kill_session (blctx->address->transport_name, blctx->session);
    }
  }
  else
  {
    /* Blacklist denies to speak to this peer */

    GNUNET_log(GNUNET_ERROR_TYPE_INFO,
        "Discarding SYN message from `%s' due to denied blacklist check\n",
        GNUNET_i2s (peer));
    cancel_pending_blacklist_checks (blctx->address, blctx->session);
    kill_session (blctx->address->transport_name, blctx->session);
  }

  if (NULL != blctx->address)
    GNUNET_HELLO_address_free (blctx->address);
  GNUNET_free (blctx->msg);
  GNUNET_free (blctx);
}

/**
 * Black list check result for try_connect call
 * If connection to the peer is allowed request adddress and
 *
 * @param cls blc_ctx bl context
 * @param peer the peer
 * @param result the result
 */
static void
connect_transport_bl_check_cont (void *cls,
    const struct GNUNET_PeerIdentity *peer, int result)
{
  struct BlacklistCheckContext *blctx = cls;

  GNUNET_CONTAINER_DLL_remove (bc_head, bc_tail, blctx);
  blctx->blc = NULL;

  if (GNUNET_OK == result)
  {
    /* Blacklist allows to speak to this transport */
    GST_ats_add_address(blctx->address, blctx->session, blctx->ats, blctx->ats_count);
  }

  if (NULL != blctx->address)
    GNUNET_HELLO_address_free (blctx->address);
  GNUNET_free (blctx->msg);
  GNUNET_free (blctx);
}


/**
 * Function called by the transport for each received message.
 *
 * @param cls closure, const char* with the name of the plugin we received the message from
 * @param address address and (claimed) identity of the other peer
 * @param message the message, NULL if we only care about
 *                learning about the delay until we should receive again
 * @param session identifier used for this session (NULL for plugins
 *                that do not offer bi-directional communication to the sender
 *                using the same "connection")
 * @return how long the plugin should wait until receiving more data
 *         (plugins that do not support this, can ignore the return value)
 */
struct GNUNET_TIME_Relative
GST_receive_callback (void *cls,
                      const struct GNUNET_HELLO_Address *address,
                      struct Session *session,
                      const struct GNUNET_MessageHeader *message)
{
  const char *plugin_name = cls;
  struct GNUNET_TIME_Relative ret;
  struct BlacklistCheckContext *blctx;
  struct GST_BlacklistCheck *blc;
  uint16_t type;

  ret = GNUNET_TIME_UNIT_ZERO;
  if (NULL == message)
    goto end;
  type = ntohs (message->type);
  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
      "Received Message with type %u from peer `%s'\n", type,
      GNUNET_i2s (&address->peer));

  GNUNET_STATISTICS_update (GST_stats, gettext_noop
  ("# bytes total received"), ntohs (message->size), GNUNET_NO);
  GST_neighbours_notify_data_recv (&address->peer, address, session, message);

  switch (type)
  {
  case GNUNET_MESSAGE_TYPE_HELLO_LEGACY:
    /* Legacy HELLO message, discard  */
    return ret;
  case GNUNET_MESSAGE_TYPE_HELLO:
    if (GNUNET_OK != GST_validation_handle_hello (message))
    {
      GNUNET_break_op(0);
      cancel_pending_blacklist_checks (address, session);
    }
    return ret;
  case GNUNET_MESSAGE_TYPE_TRANSPORT_PING:
    GNUNET_log(GNUNET_ERROR_TYPE_DEBUG | GNUNET_ERROR_TYPE_BULK,
        "Processing `%s' from `%s'\n", "PING", GST_plugins_a2s (address));
    if (GNUNET_OK
        != GST_validation_handle_ping (&address->peer, message, address, session))
    {
      cancel_pending_blacklist_checks (address, session);
      kill_session (plugin_name, session);
    }
    break;
  case GNUNET_MESSAGE_TYPE_TRANSPORT_PONG:
    GNUNET_log(GNUNET_ERROR_TYPE_DEBUG | GNUNET_ERROR_TYPE_BULK,
        "Processing `%s' from `%s'\n", "PONG",
        GST_plugins_a2s (address));
    if (GNUNET_OK != GST_validation_handle_pong (&address->peer, message))
    {
      GNUNET_break_op(0);
      cancel_pending_blacklist_checks (address, session);
      kill_session (plugin_name, session);
    }
    break;
  case GNUNET_MESSAGE_TYPE_TRANSPORT_SESSION_SYN:
    /* Do blacklist check if communication with this peer is allowed */
    blctx = GNUNET_new (struct BlacklistCheckContext);
    blctx->address = GNUNET_HELLO_address_copy (address);
    blctx->session = session;
    blctx->msg = GNUNET_malloc (ntohs(message->size));
    memcpy (blctx->msg, message, ntohs(message->size));
    GNUNET_CONTAINER_DLL_insert (bc_head, bc_tail, blctx);
    if (NULL != (blc = GST_blacklist_test_allowed (&address->peer, NULL,
          &connect_bl_check_cont, blctx)))
    {
      blctx->blc = blc;
    }

    blctx = GNUNET_new (struct BlacklistCheckContext);
    blctx->address = GNUNET_HELLO_address_copy (address);
    blctx->session = session;
    blctx->msg = GNUNET_malloc (ntohs(message->size));
    memcpy (blctx->msg, message, ntohs(message->size));
    GNUNET_CONTAINER_DLL_insert (bc_head, bc_tail, blctx);
    if (NULL != (blc = GST_blacklist_test_allowed (&address->peer,
        address->transport_name, &connect_transport_bl_check_cont, blctx)))
    {
      blctx->blc = blc;
    }
    break;
  case GNUNET_MESSAGE_TYPE_TRANSPORT_SESSION_SYN_ACK:
    if (GNUNET_OK != GST_neighbours_handle_session_syn_ack (message,
        &address->peer, address, session))
    {
      cancel_pending_blacklist_checks (address, session);
      kill_session (plugin_name, session);
    }
    break;
  case GNUNET_MESSAGE_TYPE_TRANSPORT_SESSION_ACK:
    if (GNUNET_OK
        != GST_neighbours_handle_session_ack (message, &address->peer, address, session))
    {
      GNUNET_break_op(0);
      cancel_pending_blacklist_checks (address, session);
      kill_session (plugin_name, session);
    }
    break;
  case GNUNET_MESSAGE_TYPE_TRANSPORT_SESSION_DISCONNECT:
    GST_neighbours_handle_disconnect_message (&address->peer, message);
    break;
  case GNUNET_MESSAGE_TYPE_TRANSPORT_SESSION_KEEPALIVE:
    GST_neighbours_keepalive (&address->peer, message);
    break;
  case GNUNET_MESSAGE_TYPE_TRANSPORT_SESSION_KEEPALIVE_RESPONSE:
    GST_neighbours_keepalive_response (&address->peer, message);
    break;
  default:
    /* should be payload */
    GNUNET_STATISTICS_update (GST_stats, gettext_noop
    ("# bytes payload received"), ntohs (message->size), GNUNET_NO);
    GST_neighbours_notify_payload_recv (&address->peer, address, session, message);
    ret = process_payload (&address->peer, address, session, message);
    break;
  }
  end:
  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
      "Allowing receive from peer %s to continue in %s\n", GNUNET_i2s (&address->peer),
      GNUNET_STRINGS_relative_time_to_string (ret, GNUNET_YES));
  return ret;
}

/**
 * Function that will be called for each address the transport
 * is aware that it might be reachable under.  Update our HELLO.
 *
 * @param cls name of the plugin (const char*)
 * @param add_remove should the address added (YES) or removed (NO) from the
 *                   set of valid addresses?
 * @param address the address to add or remove
 */
static void
plugin_env_address_change_notification (void *cls, int add_remove,
    const struct GNUNET_HELLO_Address *address)
{
  static int addresses = 0;
  struct GNUNET_STATISTICS_Handle *cfg = GST_stats;

  if (GNUNET_YES == add_remove)
  {
    addresses ++;
    GNUNET_STATISTICS_update (cfg, "# transport addresses", 1, GNUNET_NO);
  }
  else if (GNUNET_NO == add_remove)
  {
    if (0 == addresses)
      GNUNET_break (0);
    else
    {
      addresses --;
      GNUNET_STATISTICS_update (cfg, "# transport addresses", -1, GNUNET_NO);
    }
  }

  GNUNET_log(GNUNET_ERROR_TYPE_INFO,
      "Transport now has %u addresses to communicate\n", addresses);

  GST_hello_modify_addresses (add_remove, address);
}

/**
 * Function that will be called whenever the plugin internally
 * cleans up a session pointer and hence the service needs to
 * discard all of those sessions as well.  Plugins that do not
 * use sessions can simply omit calling this function and always
 * use NULL wherever a session pointer is needed.  This function
 * should be called BEFORE a potential "TransmitContinuation"
 * from the "TransmitFunction".
 *
 * @param cls closure
 * @param address which address was the session for
 * @param session which session is being destoyed
 */
static void
plugin_env_session_end (void *cls, const struct GNUNET_HELLO_Address *address,
    struct Session *session)
{
  struct SessionKiller *sk;

  if (NULL == address)
  {
    GNUNET_break (0);
    return;
  }

  if (NULL == session)
  {
    GNUNET_break (0);
    return;
  }

  GNUNET_assert(strlen (address->transport_name) > 0);
  GNUNET_log(GNUNET_ERROR_TYPE_INFO, "Session %p to peer `%s' ended \n",
      session, GNUNET_i2s (&address->peer));

  GNUNET_log(GNUNET_ERROR_TYPE_INFO,
      "Notification from plugin `%s' about terminated %s session %p from peer `%s' address `%s'\n",
      address->transport_name,
      GNUNET_HELLO_address_check_option (address,
          GNUNET_HELLO_ADDRESS_INFO_INBOUND) ? "inbound" : "outbound", session,
      GNUNET_i2s (&address->peer), GST_plugins_a2s (address));

  GST_neighbours_session_terminated (&address->peer, session);

  GNUNET_log_from(GNUNET_ERROR_TYPE_DEBUG | GNUNET_ERROR_TYPE_BULK,
      "transport-ats", "Telling ATS to destroy session %p from peer %s\n",
      session, GNUNET_i2s (&address->peer));

  /* Tell ATS that session has ended */
  GNUNET_ATS_address_destroyed (GST_ats, address, session);

  cancel_pending_blacklist_checks (address, session);

  for (sk = sk_head; NULL != sk; sk = sk->next)
  {
    if (sk->session == session)
    {
      GNUNET_CONTAINER_DLL_remove(sk_head, sk_tail, sk);
      GNUNET_SCHEDULER_cancel (sk->task);
      GNUNET_free(sk);
      break;
    }
  }
}

/**
 * Function that will be called to figure if an address is an loopback,
 * LAN, WAN etc. address
 *
 * @param cls closure
 * @param addr binary address
 * @param addrlen length of the @a addr
 * @return type of the network @a addr belongs to
 */
static enum GNUNET_ATS_Network_Type
plugin_env_address_to_type (void *cls,
                            const struct sockaddr *addr,
                            size_t addrlen)
{
  if (NULL == GST_ats)
  {
    GNUNET_break(0);
    return GNUNET_ATS_NET_UNSPECIFIED;
  }
  if (((addr->sa_family != AF_INET) && (addrlen != sizeof(struct sockaddr_in)))
      && ((addr->sa_family != AF_INET6)
          && (addrlen != sizeof(struct sockaddr_in6)))
      && (addr->sa_family != AF_UNIX))
  {
    GNUNET_break(0);
    return GNUNET_ATS_NET_UNSPECIFIED;
  }
  return GNUNET_ATS_address_get_type (GST_ats,
                                      addr,
                                      addrlen);
}


/**
 * Notify ATS about the new address including the network this address is
 * located in.
 *
 * @param address the address
 * @param session the session
 * @param ats ats information
 * @param ats_count number of @a ats information
 */
void
GST_ats_add_address (const struct GNUNET_HELLO_Address *address,
    struct Session *session, const struct GNUNET_ATS_Information *ats,
    uint32_t ats_count)
{
  struct GNUNET_TRANSPORT_PluginFunctions *papi;
  struct GNUNET_ATS_Information ats2[ats_count + 1];
  uint32_t net;

  /* valid new address, let ATS know! */
  if (NULL == address->transport_name)
  {
    GNUNET_break(0);
    return;
  }
  if (NULL == (papi = GST_plugins_find (address->transport_name)))
  {
    /* we don't have the plugin for this address */
    GNUNET_break(0);
    return;
  }

  if (GNUNET_YES == GNUNET_ATS_session_known (GST_ats, address, session))
  {
    GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
        "ATS already knows the address, not passing it on again\n");
    return;
  }

  net = papi->get_network (papi->cls, session);
  if (GNUNET_ATS_NET_UNSPECIFIED == net)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
        _("Could not obtain a valid network for `%s' %s (%s)\n"),
        GNUNET_i2s (&address->peer), GST_plugins_a2s (address),
        address->transport_name);
    return;
  }
  ats2[0].type = htonl (GNUNET_ATS_NETWORK_TYPE);
  ats2[0].value = htonl (net);
  memcpy (&ats2[1], ats, sizeof(struct GNUNET_ATS_Information) * ats_count);
  GNUNET_log(GNUNET_ERROR_TYPE_INFO,
      "Notifying ATS about peer `%s''s new address `%s' session %p in network %s\n",
      GNUNET_i2s (&address->peer),
      (0 == address->address_length) ? "<inbound>" : GST_plugins_a2s (address),
      session, GNUNET_ATS_print_network_type (net));
  GNUNET_ATS_address_add (GST_ats, address, session, ats2, ats_count + 1);
}

/**
 * Notify ATS about property changes to an address
 *
 * @param peer the peer
 * @param address the address
 * @param session the session
 * @param ats performance information
 * @param ats_count number of elements in @a ats
 */
void
GST_ats_update_metrics (const struct GNUNET_PeerIdentity *peer,
                        const struct GNUNET_HELLO_Address *address,
                        struct Session *session,
                        const struct GNUNET_ATS_Information *ats,
                        uint32_t ats_count)
{
  struct GNUNET_ATS_Information *ats_new;

  if (GNUNET_NO == GNUNET_ATS_session_known (GST_ats, address, session))
    return;

  /* Call to manipulation to manipulate ATS information */
  ats_new = GST_manipulation_manipulate_metrics (peer, address, session, ats,
      ats_count);
  if (NULL == ats_new)
  {
    GNUNET_break(0);
    return;
  }
  if (GNUNET_NO == GNUNET_ATS_address_update (GST_ats, address, session,
        ats_new, ats_count))
  {
    GNUNET_log(GNUNET_ERROR_TYPE_ERROR,
        _("Address or session unknown: failed to update properties for peer `%s' plugin `%s' address `%s' session %p\n"),
        GNUNET_i2s (peer), address->transport_name, GST_plugins_a2s (address),
        session);
  }
  GNUNET_free(ats_new);
}

/**
 * Function that will be called to update metrics for an address
 *
 * @param cls closure
 * @param address address to update metrics for
 * @param session the session
 * @param ats the ats information to update
 * @param ats_count the number of @a ats elements
 */
static void
plugin_env_update_metrics (void *cls,
                           const struct GNUNET_HELLO_Address *address,
                           struct Session *session,
                           const struct GNUNET_ATS_Information *ats,
                           uint32_t ats_count)
{
  if ((NULL == ats) || (0 == ats_count))
    return;
  GNUNET_assert(NULL != GST_ats);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Updating metrics for peer `%s' address %s session %p\n",
              GNUNET_i2s (&address->peer),
              GST_plugins_a2s (address),
              session);
  GST_ats_update_metrics (&address->peer,
                          address,
                          session,
                          ats, ats_count);
}


/**
 * Black list check result for try_connect call
 * If connection to the peer is allowed request adddress and
 *
 * @param cls blc_ctx bl context
 * @param peer the peer
 * @param result the result
 */
static void
plugin_env_session_start_bl_check_cont (void *cls,
    const struct GNUNET_PeerIdentity *peer, int result)
{
  struct BlacklistCheckContext *blctx = cls;

  GNUNET_CONTAINER_DLL_remove (bc_head, bc_tail, blctx);
  blctx->blc = NULL;

  if (GNUNET_OK == result)
  {
    GST_ats_add_address (blctx->address, blctx->session,
        blctx->ats, blctx->ats_count);
  }
  else
  {
    cancel_pending_blacklist_checks (blctx->address, blctx->session);
    kill_session (blctx->address->transport_name, blctx->session);
  }

  GNUNET_HELLO_address_free (blctx->address);
  GNUNET_free_non_null (blctx->ats);
  GNUNET_free (blctx);
}


/**
 * Plugin tells transport service about a new inbound session
 *
 * @param cls unused
 * @param address the address
 * @param session the new session
 * @param ats ats information
 * @param ats_count number of @a ats information
 */
static void
plugin_env_session_start (void *cls,
                          struct GNUNET_HELLO_Address *address,
                          struct Session *session,
                          const struct GNUNET_ATS_Information *ats,
                          uint32_t ats_count)
{
  struct BlacklistCheckContext *blctx;
  struct GST_BlacklistCheck *blc;
  int c;

  if (NULL == address)
  {
    GNUNET_break(0);
    return;
  }
  if (NULL == session)
  {
    GNUNET_break(0);
    return;
  }
  GNUNET_log(GNUNET_ERROR_TYPE_INFO,
      "Notification from plugin `%s' about new %s session %p from peer `%s' address `%s'\n",
      address->transport_name,
      GNUNET_HELLO_address_check_option (address,
          GNUNET_HELLO_ADDRESS_INFO_INBOUND) ? "inbound" : "outbound",
      session, GNUNET_i2s (&address->peer), GST_plugins_a2s (address));

  /* Do blacklist check if communication with this peer is allowed */
  blctx = GNUNET_new (struct BlacklistCheckContext);
  blctx->address = GNUNET_HELLO_address_copy (address);
  blctx->session = session;
  if (ats_count > 0)
  {
    blctx->ats = GNUNET_malloc (ats_count * sizeof (struct GNUNET_ATS_Information));
    for (c = 0; c < ats_count; c++)
    {
      blctx->ats[c].type = ats[c].type;
      blctx->ats[c].value = ats[c].value;
    }
  }

  GNUNET_CONTAINER_DLL_insert (bc_head, bc_tail, blctx);
  if (NULL != (blc = GST_blacklist_test_allowed (&address->peer, address->transport_name,
        &plugin_env_session_start_bl_check_cont, blctx)))
  {
    blctx->blc = blc;
  }
}


/**
 * Function called by ATS to notify the callee that the
 * assigned bandwidth or address for a given peer was changed.  If the
 * callback is called with address/bandwidth assignments of zero, the
 * ATS disconnect function will still be called once the disconnect
 * actually happened.
 *
 * @param cls closure
 * @param peer the peer this address is intended for
 * @param address address to use (for peer given in address)
 * @param session session to use (if available)
 * @param bandwidth_out assigned outbound bandwidth for the connection in NBO,
 * 	0 to disconnect from peer
 * @param bandwidth_in assigned inbound bandwidth for the connection in NBO,
 * 	0 to disconnect from peer
 * @param ats ATS information
 * @param ats_count number of @a ats elements
 */
static void
ats_request_address_change (void *cls,
                            const struct GNUNET_PeerIdentity *peer,
                            const struct GNUNET_HELLO_Address *address,
                            struct Session *session,
                            struct GNUNET_BANDWIDTH_Value32NBO bandwidth_out,
                            struct GNUNET_BANDWIDTH_Value32NBO bandwidth_in)
{
  uint32_t bw_in = ntohl (bandwidth_in.value__);
  uint32_t bw_out = ntohl (bandwidth_out.value__);

  /* ATS tells me to disconnect from peer */
  if ((0 == bw_in) && (0 == bw_out))
  {
    GNUNET_log(GNUNET_ERROR_TYPE_INFO,
        "ATS tells me to disconnect from peer `%s'\n",
        GNUNET_i2s (&address->peer));
    GST_neighbours_force_disconnect (&address->peer);
    return;
  }

  GST_neighbours_switch_to_address (&address->peer,
                                    address,
                                    session,
                                    bandwidth_in, bandwidth_out);
}


/**
 * Function called to notify transport users that another
 * peer connected to us.
 *
 * @param cls closure
 * @param peer the peer that connected
 * @param bandwidth_in inbound bandwidth in NBO
 * @param bandwidth_out outbound bandwidth in NBO
 */
static void
neighbours_connect_notification (void *cls,
    const struct GNUNET_PeerIdentity *peer,
    struct GNUNET_BANDWIDTH_Value32NBO bandwidth_in,
    struct GNUNET_BANDWIDTH_Value32NBO bandwidth_out)
{
  size_t len = sizeof(struct ConnectInfoMessage);
  char buf[len] GNUNET_ALIGN;
  struct ConnectInfoMessage *connect_msg = (struct ConnectInfoMessage *) buf;

  connections++;
  GNUNET_log(GNUNET_ERROR_TYPE_INFO,
      "We are now connected to peer `%s' and %u peers in total\n",
      GNUNET_i2s (peer), connections);
  connect_msg->header.size = htons (sizeof(buf));
  connect_msg->header.type = htons (GNUNET_MESSAGE_TYPE_TRANSPORT_CONNECT);
  connect_msg->id = *peer;
  connect_msg->quota_in = bandwidth_in;
  connect_msg->quota_out = bandwidth_out;
  GST_clients_broadcast (&connect_msg->header, GNUNET_NO);
}


/**
 * Function called to notify transport users that another
 * peer disconnected from us.
 *
 * @param cls closure
 * @param peer the peer that disconnected
 */
static void
neighbours_disconnect_notification (void *cls,
                                    const struct GNUNET_PeerIdentity *peer)
{
  struct DisconnectInfoMessage disconnect_msg;

  connections--;
  GNUNET_log(GNUNET_ERROR_TYPE_INFO,
      "Peer `%s' disconnected and we are connected to %u peers\n",
      GNUNET_i2s (peer), connections);

  GST_manipulation_peer_disconnect (peer);
  disconnect_msg.header.size = htons (sizeof(struct DisconnectInfoMessage));
  disconnect_msg.header.type = htons (GNUNET_MESSAGE_TYPE_TRANSPORT_DISCONNECT);
  disconnect_msg.reserved = htonl (0);
  disconnect_msg.peer = *peer;
  GST_clients_broadcast (&disconnect_msg.header, GNUNET_NO);
}


/**
 * Function called to notify transport users that a neighbour peer changed its
 * active address.
 *
 * @param cls closure
 * @param peer peer this update is about (never NULL)
 * @param address address, NULL on disconnect
 * @param state current state this peer is in
 * @param state_timeout timeout for the current state of the peer
 * @param bandwidth_in bandwidth assigned inbound
 * @param bandwidth_out bandwidth assigned outbound
 */
static void
neighbours_changed_notification (void *cls,
                                 const struct GNUNET_PeerIdentity *peer,
                                 const struct GNUNET_HELLO_Address *address,
                                 enum GNUNET_TRANSPORT_PeerState state,
                                 struct GNUNET_TIME_Absolute state_timeout,
                                 struct GNUNET_BANDWIDTH_Value32NBO bandwidth_in,
                                 struct GNUNET_BANDWIDTH_Value32NBO bandwidth_out)
{
  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
             "Notifying about change for peer `%s' with address `%s' in state `%s' timing out at %s\n",
             GNUNET_i2s (peer),
             (NULL != address) ? GST_plugins_a2s (address) : "<none>",
             GNUNET_TRANSPORT_ps2s (state),
             GNUNET_STRINGS_absolute_time_to_string (state_timeout));

  GST_clients_broadcast_peer_notification (peer,
                                           address,
                                           state,
                                           state_timeout);
}


/**
 * Function called when the service shuts down.  Unloads our plugins
 * and cancels pending validations.
 *
 * @param cls closure, unused
 * @param tc task context (unused)
 */
static void
shutdown_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  GST_neighbours_stop ();
  GST_validation_stop ();
  GST_plugins_unload ();

  GNUNET_ATS_scheduling_done (GST_ats);
  GST_ats = NULL;
  GST_clients_stop ();
  GST_blacklist_stop ();
  GST_hello_stop ();
  GST_manipulation_stop ();

  if (NULL != GST_peerinfo)
  {
    GNUNET_PEERINFO_disconnect (GST_peerinfo);
    GST_peerinfo = NULL;
  }
  if (NULL != GST_stats)
  {
    GNUNET_STATISTICS_destroy (GST_stats, GNUNET_NO);
    GST_stats = NULL;
  }
  if (NULL != GST_my_private_key)
  {
    GNUNET_free(GST_my_private_key);
    GST_my_private_key = NULL;
  }
  GST_server = NULL;
}


/**
 * Initiate transport service.
 *
 * @param cls closure
 * @param server the initialized server
 * @param c configuration to use
 */
static void
run (void *cls, struct GNUNET_SERVER_Handle *server,
    const struct GNUNET_CONFIGURATION_Handle *c)
{
  char *keyfile;
  struct GNUNET_CRYPTO_EddsaPrivateKey *pk;
  long long unsigned int max_fd_cfg;
  int max_fd_rlimit;
  int max_fd;
  int friend_only;

  /* setup globals */
  GST_cfg = c;
  if (GNUNET_OK
      != GNUNET_CONFIGURATION_get_value_filename (c, "PEER", "PRIVATE_KEY",
          &keyfile))
  {
    GNUNET_log(GNUNET_ERROR_TYPE_ERROR,
        _("Transport service is lacking key configuration settings. Exiting.\n"));
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_time (c,
                                           "transport",
                                           "HELLO_EXPIRATION",
                                           &hello_expiration))
  {
    hello_expiration = GNUNET_CONSTANTS_HELLO_ADDRESS_EXPIRATION;
  }
  GST_server = server;
  pk = GNUNET_CRYPTO_eddsa_key_create_from_file (keyfile);
  GNUNET_free (keyfile);
  GNUNET_assert (NULL != pk);
  GST_my_private_key = pk;

  GST_stats = GNUNET_STATISTICS_create ("transport", GST_cfg);
  GST_peerinfo = GNUNET_PEERINFO_connect (GST_cfg);
  GNUNET_CRYPTO_eddsa_key_get_public (GST_my_private_key,
      &GST_my_identity.public_key);
  GNUNET_assert(NULL != GST_my_private_key);

  GNUNET_log(GNUNET_ERROR_TYPE_INFO,
             "My identity is `%4s'\n",
             GNUNET_i2s_full (&GST_my_identity));

  GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_FOREVER_REL, &shutdown_task,
      NULL );
  if (NULL == GST_peerinfo)
  {
    GNUNET_log(GNUNET_ERROR_TYPE_ERROR,
        _("Could not access PEERINFO service.  Exiting.\n"));
    GNUNET_SCHEDULER_shutdown ();
    return;
  }

  max_fd_rlimit = 0;
  max_fd_cfg = 0;
#if HAVE_GETRLIMIT
  struct rlimit r_file;
  if (0 == getrlimit (RLIMIT_NOFILE, &r_file))
  {
    max_fd_rlimit = r_file.rlim_cur;
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
        "Maximum number of open files was: %u/%u\n",
        r_file.rlim_cur,
        r_file.rlim_max);
  }
  max_fd_rlimit = (9 * max_fd_rlimit) / 10; /* Keep 10% for rest of transport */
#endif
  GNUNET_CONFIGURATION_get_value_number (GST_cfg, "transport", "MAX_FD",
      &max_fd_cfg);

  if (max_fd_cfg > max_fd_rlimit)
    max_fd = max_fd_cfg;
  else
    max_fd = max_fd_rlimit;
  if (max_fd < DEFAULT_MAX_FDS)
    max_fd = DEFAULT_MAX_FDS;

  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
      "Limiting number of sockets to %u: validation %u, neighbors: %u\n",
      max_fd, (max_fd / 3), (max_fd / 3) * 2);

  friend_only = GNUNET_CONFIGURATION_get_value_yesno (GST_cfg, "topology",
      "FRIENDS-ONLY");
  if (GNUNET_SYSERR == friend_only)
    friend_only = GNUNET_NO; /* According to topology defaults */
  /* start subsystems */
  GST_hello_start (friend_only, &process_hello_update, NULL );
  GNUNET_assert(NULL != GST_hello_get());
  GST_blacklist_start (GST_server, GST_cfg, &GST_my_identity);
  GST_ats = GNUNET_ATS_scheduling_init (GST_cfg,
                                        &ats_request_address_change,
                                        NULL );
  GST_manipulation_init (GST_cfg);
  GST_plugins_load (&GST_manipulation_recv,
                    &GST_neighbours_register_quota_notification,
                    &GST_neighbours_unregister_quota_notification,
                    &plugin_env_address_change_notification,
                    &plugin_env_session_start,
                    &plugin_env_session_end,
                    &plugin_env_address_to_type,
                    &plugin_env_update_metrics);
  GST_neighbours_start (NULL,
                        &neighbours_connect_notification,
                        &neighbours_disconnect_notification,
                        &neighbours_changed_notification,
                        (max_fd / 3) * 2);
  GST_clients_start (GST_server);
  GST_validation_start ((max_fd / 3));
}


/**
 * The main function for the transport service.
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return 0 ok, 1 on error
 */
int
main (int argc, char * const *argv)
{
  return
      (GNUNET_OK
          == GNUNET_SERVICE_run (argc, argv, "transport",
              GNUNET_SERVICE_OPTION_NONE, &run, NULL )) ? 0 : 1;
}

/* end of file gnunet-service-transport.c */

/*
 This file is part of GNUnet.
 Copyright (C) 2010-2015 Christian Grothoff (and other contributing authors)

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
 * @brief main for gnunet-service-transport
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
#include "gnunet-service-transport_ats.h"
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
  struct GNUNET_SCHEDULER_Task *task;
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
 * ATS scheduling handle.
 */
struct GNUNET_ATS_SchedulingHandle *GST_ats;

/**
 * ATS connectivity handle.
 */
struct GNUNET_ATS_ConnectivityHandle *GST_ats_connect;

/**
 * Hello address expiration
 */
struct GNUNET_TIME_Relative hello_expiration;

/**
 * Head of DLL of asynchronous tasks to kill sessions.
 */
static struct SessionKiller *sk_head;

/**
 * Tail of DLL of asynchronous tasks to kill sessions.
 */
static struct SessionKiller *sk_tail;

/**
 * Interface scanner determines our LAN address range(s).
 */
struct GNUNET_ATS_InterfaceScanner *GST_is;


/**
 * Transmit our HELLO message to the given (connected) neighbour.
 *
 * @param cls the 'HELLO' message
 * @param peer identity of the peer
 * @param address the address
 * @param state current state this peer is in
 * @param state_timeout timeout for the current state of the peer
 * @param bandwidth_in inbound quota in NBO
 * @param bandwidth_out outbound quota in NBO
 */
static void
transmit_our_hello (void *cls,
                    const struct GNUNET_PeerIdentity *peer,
		    const struct GNUNET_HELLO_Address *address,
		    enum GNUNET_TRANSPORT_PeerState state,
		    struct GNUNET_TIME_Absolute state_timeout,
		    struct GNUNET_BANDWIDTH_Value32NBO bandwidth_in,
		    struct GNUNET_BANDWIDTH_Value32NBO bandwidth_out)
{
  const struct GNUNET_MessageHeader *hello = cls;

  if (0 ==
      memcmp (peer,
              &GST_my_identity,
              sizeof (struct GNUNET_PeerIdentity)))
    return; /* not to ourselves */
  if (GNUNET_NO == GST_neighbours_test_connected (peer))
    return;

  GST_neighbours_send (peer,
		       hello,
		       ntohs (hello->size),
		       hello_expiration,
                       NULL, NULL);
}


/**
 * My HELLO has changed. Tell everyone who should know.
 *
 * @param cls unused
 * @param hello new HELLO
 */
static void
process_hello_update (void *cls,
                      const struct GNUNET_MessageHeader *hello)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Broadcasting HELLO to clients\n");
  GST_clients_broadcast (hello, GNUNET_NO);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Broadcasting HELLO to neighbours\n");
  GST_neighbours_iterate (&transmit_our_hello,
                          (void *) hello);
}


/**
 * We received some payload.  Prepare to pass it on to our clients.
 *
 * @param address address and (claimed) identity of the other peer
 * @param session identifier used for this session (NULL for plugins
 *                that do not offer bi-directional communication to the sender
 *                using the same "connection")
 * @param message the message to process
 * @return how long the plugin should wait until receiving more data
 */
static struct GNUNET_TIME_Relative
process_payload (const struct GNUNET_HELLO_Address *address,
                 struct Session *session,
                 const struct GNUNET_MessageHeader *message)
{
  struct GNUNET_TIME_Relative ret;
  int do_forward;
  struct InboundMessage *im;
  size_t msg_size = ntohs (message->size);
  size_t size = sizeof(struct InboundMessage) + msg_size;
  char buf[size] GNUNET_ALIGN;

  do_forward = GNUNET_SYSERR;
  ret = GST_neighbours_calculate_receive_delay (&address->peer,
						msg_size,
						&do_forward);
  if (! GST_neighbours_test_connected (&address->peer))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Discarded %u bytes type %u payload from peer `%s'\n",
                msg_size,
                ntohs (message->type),
                GNUNET_i2s (&address->peer));
    GNUNET_STATISTICS_update (GST_stats, gettext_noop
                              ("# bytes payload discarded due to not connected peer"),
                              msg_size,
                              GNUNET_NO);
    return ret;
  }

  if (GNUNET_YES != do_forward)
    return ret;
  im = (struct InboundMessage *) buf;
  im->header.size = htons (size);
  im->header.type = htons (GNUNET_MESSAGE_TYPE_TRANSPORT_RECV);
  im->peer = address->peer;
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
kill_session_task (void *cls,
                   const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct SessionKiller *sk = cls;

  sk->task = NULL;
  GNUNET_CONTAINER_DLL_remove (sk_head, sk_tail, sk);
  sk->plugin->disconnect_session (sk->plugin->cls, sk->session);
  GNUNET_free(sk);
}


/**
 * Force plugin to terminate session due to communication
 * issue.
 *
 * @param plugin_name name of the plugin
 * @param session session to termiante
 */
static void
kill_session (const char *plugin_name,
              struct Session *session)
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
  GNUNET_CONTAINER_DLL_insert (sk_head,
                               sk_tail,
                               sk);
}


/**
 * Black list check result for try_connect call
 * If connection to the peer is allowed request adddress and ???
 *
 * @param cls the message
 * @param peer the peer
 * @param address the address
 * @param session the session
 * @param result the result
 */
static void
connect_bl_check_cont (void *cls,
                       const struct GNUNET_PeerIdentity *peer,
		       const struct GNUNET_HELLO_Address *address,
		       struct Session *session,
                       int result)
{
  struct GNUNET_MessageHeader *msg = cls;

  if (GNUNET_OK == result)
  {
    /* Blacklist allows to speak to this peer, forward SYN to neighbours  */
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                "Received SYN message from peer `%s' at `%s'\n",
                GNUNET_i2s (peer),
                GST_plugins_a2s (address));
    if (GNUNET_OK !=
        GST_neighbours_handle_session_syn (msg,
                                           peer))
    {
      GST_blacklist_abort_matching (address,
				    session);
      kill_session (address->transport_name,
                    session);
    }
    GNUNET_free (msg);
    return;
  }
  GNUNET_free (msg);
  if (GNUNET_SYSERR == result)
    return; /* check was aborted, session destroyed */
  /* Blacklist denies to speak to this peer */
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
	      "Discarding SYN message from `%s' due to denied blacklist check\n",
	      GNUNET_i2s (peer));
  kill_session (address->transport_name,
		session);
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
  uint16_t type;

  ret = GNUNET_TIME_UNIT_ZERO;
  if (NULL == message)
    goto end;
  type = ntohs (message->type);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received message with type %u from peer `%s'\n",
              type,
              GNUNET_i2s (&address->peer));

  GNUNET_STATISTICS_update (GST_stats,
                            gettext_noop ("# bytes total received"),
                            ntohs (message->size),
                            GNUNET_NO);
  GST_neighbours_notify_data_recv (address,
                                   message);
  switch (type)
  {
  case GNUNET_MESSAGE_TYPE_HELLO_LEGACY:
    /* Legacy HELLO message, discard  */
    return ret;
  case GNUNET_MESSAGE_TYPE_HELLO:
    if (GNUNET_OK != GST_validation_handle_hello (message))
    {
      GNUNET_break_op (0);
      GST_blacklist_abort_matching (address,
				    session);
    }
    return ret;
  case GNUNET_MESSAGE_TYPE_TRANSPORT_PING:
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Processing PING from `%s'\n",
                GST_plugins_a2s (address));
    if (GNUNET_OK !=
        GST_validation_handle_ping (&address->peer,
                                    message,
                                    address,
                                    session))
    {
      GST_blacklist_abort_matching (address,
				    session);
      kill_session (plugin_name,
                    session);
    }
    break;
  case GNUNET_MESSAGE_TYPE_TRANSPORT_PONG:
    GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
               "Processing PONG from `%s'\n",
               GST_plugins_a2s (address));
    if (GNUNET_OK != GST_validation_handle_pong (&address->peer, message))
    {
      GNUNET_break_op (0);
      GST_blacklist_abort_matching (address,
				    session);
      kill_session (plugin_name, session);
    }
    break;
  case GNUNET_MESSAGE_TYPE_TRANSPORT_SESSION_SYN:
    /* Do blacklist check if communication with this peer is allowed */
    (void) GST_blacklist_test_allowed (&address->peer,
				       NULL,
				       &connect_bl_check_cont,
				       GNUNET_copy_message (message),
				       address,
				       session);
    break;
  case GNUNET_MESSAGE_TYPE_TRANSPORT_SESSION_SYN_ACK:
    if (GNUNET_OK !=
        GST_neighbours_handle_session_syn_ack (message,
                                               address,
                                               session))
    {
      GST_blacklist_abort_matching (address, session);
      kill_session (plugin_name, session);
    }
    break;
  case GNUNET_MESSAGE_TYPE_TRANSPORT_SESSION_ACK:
    if (GNUNET_OK !=
        GST_neighbours_handle_session_ack (message,
                                           address,
                                           session))
    {
      GNUNET_break_op(0);
      GST_blacklist_abort_matching (address, session);
      kill_session (plugin_name, session);
    }
    break;
  case GNUNET_MESSAGE_TYPE_TRANSPORT_SESSION_DISCONNECT:
    GST_neighbours_handle_disconnect_message (&address->peer,
                                              message);
    break;
  case GNUNET_MESSAGE_TYPE_TRANSPORT_SESSION_KEEPALIVE:
    GST_neighbours_keepalive (&address->peer,
                              message);
    break;
  case GNUNET_MESSAGE_TYPE_TRANSPORT_SESSION_KEEPALIVE_RESPONSE:
    GST_neighbours_keepalive_response (&address->peer,
                                       message);
    break;
  default:
    /* should be payload */
    GNUNET_STATISTICS_update (GST_stats,
                              gettext_noop ("# bytes payload received"),
                              ntohs (message->size),
                              GNUNET_NO);
    ret = process_payload (address,
                           session,
                           message);
    break;
  }
 end:
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Allowing receive from peer %s to continue in %s\n",
              GNUNET_i2s (&address->peer),
              GNUNET_STRINGS_relative_time_to_string (ret,
                                                      GNUNET_YES));
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
plugin_env_address_change_notification (void *cls,
                                        int add_remove,
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

  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "Transport now has %u addresses to communicate\n",
              addresses);
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
plugin_env_session_end (void *cls,
                        const struct GNUNET_HELLO_Address *address,
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
  GNUNET_assert (strlen (address->transport_name) > 0);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Notification from plugin about terminated session %p from peer `%s' address `%s'\n",
              session,
              GNUNET_i2s (&address->peer),
              GST_plugins_a2s (address));

  GST_neighbours_session_terminated (&address->peer, session);
  GST_ats_del_session (address, session);
  GST_blacklist_abort_matching (address, session);

  for (sk = sk_head; NULL != sk; sk = sk->next)
  {
    if (sk->session == session)
    {
      GNUNET_CONTAINER_DLL_remove (sk_head, sk_tail, sk);
      GNUNET_SCHEDULER_cancel (sk->task);
      GNUNET_free(sk);
      break;
    }
  }
}


/**
 * Black list check result from blacklist check triggered when a
 * plugin gave us a new session in #plugin_env_session_start().  If
 * connection to the peer is disallowed, kill the session.
 *
 * @param cls NULL
 * @param peer the peer
 * @param address address associated with the request
 * @param session session associated with the request
 * @param result the result
 */
static void
plugin_env_session_start_bl_check_cont (void *cls,
                                        const struct GNUNET_PeerIdentity *peer,
					const struct GNUNET_HELLO_Address *address,
					struct Session *session,
                                        int result)
{
  if (GNUNET_OK != result)
  {
    kill_session (address->transport_name,
                  session);
    return;
  }
  if (GNUNET_YES !=
      GNUNET_HELLO_address_check_option (address,
					 GNUNET_HELLO_ADDRESS_INFO_INBOUND))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Informing verifier about inbound session's address `%s'\n",
                GST_plugins_a2s (address));
    GST_validation_handle_address (address);
  }
}


/**
 * Plugin tells transport service about a new inbound session
 *
 * @param cls unused
 * @param address the address
 * @param session the new session
 * @param scope network scope information
 */
static void
plugin_env_session_start (void *cls,
                          const struct GNUNET_HELLO_Address *address,
                          struct Session *session,
                          enum GNUNET_ATS_Network_Type scope)
{
  struct GNUNET_ATS_Properties prop;

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
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "Notification from plugin `%s' about new session from peer `%s' address `%s'\n",
              address->transport_name,
              GNUNET_i2s (&address->peer),
              GST_plugins_a2s (address));
  if (GNUNET_YES ==
      GNUNET_HELLO_address_check_option (address,
                                         GNUNET_HELLO_ADDRESS_INFO_INBOUND))
  {
    /* inbound is always new, but outbound MAY already be known, but
       for example for UNIX, we have symmetric connections and thus we
       may not know the address yet; add if necessary! */
    /* FIXME: maybe change API here so we just pass scope? */
    memset (&prop, 0, sizeof (prop));
    prop.scope = scope;
    GST_ats_add_inbound_address (address,
                                 session,
                                 &prop);
  }
  /* Do blacklist check if communication with this peer is allowed */
  (void) GST_blacklist_test_allowed (&address->peer,
				     address->transport_name,
				     &plugin_env_session_start_bl_check_cont,
				     NULL,
				     address,
				     session);
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

  if (NULL == peer)
  {
    /* ATS service died, all suggestions become invalid!
       (but we'll keep using the allocations for a little
       while, to keep going while ATS restarts) */
    /* FIXME: We should drop all
       connections now, as ATS won't explicitly tell
       us and be unaware of ongoing resource allocations! */
    return;
  }
  /* ATS tells me to disconnect from peer */
  if ((0 == bw_in) && (0 == bw_out))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                "ATS tells me to disconnect from peer `%s'\n",
                GNUNET_i2s (peer));
    GST_neighbours_force_disconnect (peer);
    return;
  }
  GNUNET_assert (NULL != address);
  GNUNET_STATISTICS_update (GST_stats,
                            "# ATS suggestions received",
                            1,
                            GNUNET_NO);
  GST_neighbours_switch_to_address (address,
                                    session,
                                    bandwidth_in,
                                    bandwidth_out);
}


/**
 * Function called when the service shuts down.  Unloads our plugins
 * and cancels pending validations.
 *
 * @param cls closure, unused
 * @param tc task context (unused)
 */
static void
shutdown_task (void *cls,
               const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  GST_neighbours_stop ();
  GST_plugins_unload ();
  GST_validation_stop ();
  GST_ats_done ();
  GNUNET_ATS_scheduling_done (GST_ats);
  GST_ats = NULL;
  GNUNET_ATS_connectivity_done (GST_ats_connect);
  GST_ats_connect = NULL;
  GNUNET_ATS_scanner_done (GST_is);
  GST_is = NULL;
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
run (void *cls,
     struct GNUNET_SERVER_Handle *server,
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
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_filename (c,
                                               "PEER",
                                               "PRIVATE_KEY",
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

  GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_FOREVER_REL,
                                &shutdown_task,
                                NULL);
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
  GNUNET_CONFIGURATION_get_value_number (GST_cfg,
                                         "transport",
                                         "MAX_FD",
                                         &max_fd_cfg);

  if (max_fd_cfg > max_fd_rlimit)
    max_fd = max_fd_cfg;
  else
    max_fd = max_fd_rlimit;
  if (max_fd < DEFAULT_MAX_FDS)
    max_fd = DEFAULT_MAX_FDS;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Limiting number of sockets to %u: validation %u, neighbors: %u\n",
             max_fd, (max_fd / 3), (max_fd / 3) * 2);

  friend_only = GNUNET_CONFIGURATION_get_value_yesno (GST_cfg,
                                                      "topology",
                                                      "FRIENDS-ONLY");
  if (GNUNET_SYSERR == friend_only)
    friend_only = GNUNET_NO; /* According to topology defaults */
  /* start subsystems */
  GST_blacklist_start (GST_server,
                       GST_cfg,
                       &GST_my_identity);
  GST_is = GNUNET_ATS_scanner_init ();
  GST_ats_connect = GNUNET_ATS_connectivity_init (GST_cfg);
  GST_ats = GNUNET_ATS_scheduling_init (GST_cfg,
                                        &ats_request_address_change,
                                        NULL);
  GST_ats_init ();
  GST_manipulation_init ();
  GST_plugins_load (&GST_manipulation_recv,
                    &plugin_env_address_change_notification,
                    &plugin_env_session_start,
                    &plugin_env_session_end);
  GST_hello_start (friend_only,
                   &process_hello_update,
                   NULL);
  GST_neighbours_start ((max_fd / 3) * 2);
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
main (int argc,
      char * const *argv)
{
  return
      (GNUNET_OK
          == GNUNET_SERVICE_run (argc, argv, "transport",
              GNUNET_SERVICE_OPTION_NONE, &run, NULL )) ? 0 : 1;
}

/* end of file gnunet-service-transport.c */

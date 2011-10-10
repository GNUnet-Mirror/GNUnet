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
 * @file transport/gnunet-service-transport-new.c
 * @brief
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_util_lib.h"
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
#include "transport.h"

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
 * Our public key.
 */
struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded GST_my_public_key;

/**
 * Our private key.
 */
struct GNUNET_CRYPTO_RsaPrivateKey *GST_my_private_key;

/**
 * ATS handle.
 */
struct GNUNET_ATS_Handle *GST_ats;


/**
 * Transmit our HELLO message to the given (connected) neighbour.
 *
 * @param cls the 'HELLO' message
 * @param target a connected neighbour
 * @param ats performance information (unused)
 * @param ats_count number of records in ats (unused)
 * @param transport plugin
 * @param addr address
 * @param addrlen address length
 */
static void
transmit_our_hello (void *cls, const struct GNUNET_PeerIdentity *target,
                    const struct GNUNET_TRANSPORT_ATS_Information *ats,
                    uint32_t ats_count,
                    const char * transport,
                    const void * addr,
                    size_t addrlen)
{
  const struct GNUNET_MessageHeader *hello = cls;

  GST_neighbours_send (target, (const char *) hello, ntohs (hello->size),
                       GNUNET_CONSTANTS_HELLO_ADDRESS_EXPIRATION, NULL, NULL);
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
 * Try to initiate a connection to the given peer if the blacklist
 * allowed it.
 *
 * @param cls closure (unused, NULL)
 * @param peer identity of peer that was tested
 * @param result GNUNET_OK if the connection is allowed,
 *               GNUNET_NO if not
 */
static void
try_connect_if_allowed (void *cls, const struct GNUNET_PeerIdentity *peer,
                        int result)
{
  if (GNUNET_OK != result)
    return;                     /* not allowed */
  GST_neighbours_try_connect (peer);
}


/**
 * Function called by the transport for each received message.
 * This function should also be called with "NULL" for the
 * message to signal that the other peer disconnected.
 *
 * @param cls closure, const char* with the name of the plugin we received the message from
 * @param peer (claimed) identity of the other peer
 * @param message the message, NULL if we only care about
 *                learning about the delay until we should receive again -- FIXME!
 * @param ats performance information
 * @param ats_count number of records in ats
 * @param session identifier used for this session (NULL for plugins
 *                that do not offer bi-directional communication to the sender
 *                using the same "connection")
 * @param sender_address binary address of the sender (if we established the
 *                connection or are otherwise sure of it; should be NULL
 *                for inbound TCP/UDP connections since it it not clear
 *                that we could establish ourselves a connection to that
 *                IP address and get the same system)
 * @param sender_address_len number of bytes in sender_address
 * @return how long the plugin should wait until receiving more data
 *         (plugins that do not support this, can ignore the return value)
 */
static struct GNUNET_TIME_Relative
plugin_env_receive_callback (void *cls, const struct GNUNET_PeerIdentity *peer,
                             const struct GNUNET_MessageHeader *message,
                             const struct GNUNET_TRANSPORT_ATS_Information *ats,
                             uint32_t ats_count, struct Session *session,
                             const char *sender_address,
                             uint16_t sender_address_len)
{
  const char *plugin_name = cls;
  int do_forward;
  struct GNUNET_TIME_Relative ret;
  uint16_t type;

  ret = GNUNET_TIME_UNIT_ZERO;
  if (NULL != message)
  {
    type = ntohs (message->type);
    switch (type)
    {
    case GNUNET_MESSAGE_TYPE_HELLO:
      GST_validation_handle_hello (message);
      return ret;
    case GNUNET_MESSAGE_TYPE_TRANSPORT_PING:
#if DEBUG_TRANSPORT
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG | GNUNET_ERROR_TYPE_BULK,
                  "Processing `%s' from `%s'\n", "PING",
                  (sender_address != NULL) ? GST_plugins_a2s (plugin_name,
                                                              sender_address,
                                                              sender_address_len)
                  : "<inbound>");
#endif
      GST_validation_handle_ping (peer, message, plugin_name, session,
                                  sender_address, sender_address_len);
      break;
    case GNUNET_MESSAGE_TYPE_TRANSPORT_PONG:
#if DEBUG_TRANSPORT
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG | GNUNET_ERROR_TYPE_BULK,
                  "Processing `%s' from `%s'\n", "PONG",
                  (sender_address != NULL) ? GST_plugins_a2s (plugin_name,
                                                              sender_address,
                                                              sender_address_len)
                  : "<inbound>");
#endif
      GST_validation_handle_pong (peer, message);
      break;
    case GNUNET_MESSAGE_TYPE_TRANSPORT_SESSION_CONNECT:
      (void) GST_blacklist_test_allowed (peer, NULL, &try_connect_if_allowed,
                                         NULL);
      /* TODO: if 'session != NULL', and timestamp more recent than the
       * previous one, maybe notify ATS that this is now the preferred
       * * way to communicate with this peer (other peer switched transport) */
      break;
    case GNUNET_MESSAGE_TYPE_TRANSPORT_SESSION_DISCONNECT:
      /* FIXME: do some validation to prevent an attacker from sending
       * a fake disconnect message... */     	  
      GST_neighbours_force_disconnect (peer);
      break;
    case GNUNET_MESSAGE_TYPE_TRANSPORT_SESSION_KEEPALIVE:
      GST_neighbours_keepalive (peer);
      break;
    default:
      /* should be payload */
      do_forward = GNUNET_SYSERR;
      ret =
          GST_neighbours_calculate_receive_delay (peer,
                                                  (message ==
                                                   NULL) ? 0 :
                                                  ntohs (message->size),
                                                  &do_forward);
      if (do_forward == GNUNET_YES)
      {
        struct InboundMessage *im;
        size_t size = sizeof (struct InboundMessage) + ntohs (message->size);

        im = GNUNET_malloc (size);
        im->header.size = htons (size);
        im->header.type = htons (GNUNET_MESSAGE_TYPE_TRANSPORT_RECV);
        im->ats_count = htonl (0);
        memcpy (&(im->peer), peer, sizeof (struct GNUNET_PeerIdentity));
        memcpy (&im[1], message, ntohs (message->size));
        GST_clients_broadcast ((const struct GNUNET_MessageHeader *) im,
                               GNUNET_YES);

        GNUNET_free (im);
      }
      break;
    }
  }
  GNUNET_assert ((ats_count > 0) && (ats != NULL));
  /*
     FIXME: this gives an address that might not have been validated to
     ATS for 'selection', which is probably not what we want; this 
     might be particularly wrong (as in, possibly hiding bugs with address
     validation) as 'GNUNET_ATS_address_update' currently ignores
     the expiration given.
  */
  GNUNET_ATS_address_update (GST_ats, peer, GNUNET_TIME_absolute_get (),        /* valid at least until right now... */
                             plugin_name, session, sender_address,
                             sender_address_len, ats, ats_count);
  return ret;
}


/**
 * Function that will be called for each address the transport
 * is aware that it might be reachable under.  Update our HELLO.
 *
 * @param cls name of the plugin (const char*)
 * @param add_remove should the address added (YES) or removed (NO) from the
 *                   set of valid addresses?
 * @param addr one of the addresses of the host
 *        the specific address format depends on the transport
 * @param addrlen length of the address
 */
static void
plugin_env_address_change_notification (void *cls, int add_remove,
                                        const void *addr, size_t addrlen)
{
  const char *plugin_name = cls;

  GST_hello_modify_addresses (add_remove, plugin_name, addr, addrlen);
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
 * @param peer which peer was the session for
 * @param session which session is being destoyed
 */
static void
plugin_env_session_end (void *cls, const struct GNUNET_PeerIdentity *peer,
                        struct Session *session)
{
#if DEBUG_TRANSPORT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Session %X to peer `%s' ended \n",
              session, GNUNET_i2s (peer));
#endif
  GNUNET_ATS_session_destroyed(GST_ats, peer, session);
  GST_neighbours_session_terminated (peer, session);
}


/**
 * Function called by ATS to notify the callee that the
 * assigned bandwidth or address for a given peer was changed.  If the
 * callback is called with address/bandwidth assignments of zero, the
 * ATS disconnect function will still be called once the disconnect
 * actually happened.
 *
 * @param cls closure
 * @param peer identity of the peer
 * @param plugin_name name of the transport plugin, NULL to disconnect
 * @param session session to use (if available)
 * @param plugin_addr address to use (if available)
 * @param plugin_addr_len number of bytes in addr
 * @param bandwidth_out assigned outbound bandwidth for the connection
 * @param bandwidth_in assigned inbound bandwidth for the connection
 */
static void
ats_request_address_change (void *cls, const struct GNUNET_PeerIdentity *peer,
                            const char *plugin_name, struct Session *session,
                            const void *plugin_addr, size_t plugin_addr_len,
                            struct GNUNET_BANDWIDTH_Value32NBO bandwidth_out,
                            struct GNUNET_BANDWIDTH_Value32NBO bandwidth_in)
{
  GST_neighbours_switch_to_address (peer, plugin_name, plugin_addr,
                                    plugin_addr_len, session, NULL, 0);
  GST_neighbours_set_incoming_quota (peer, bandwidth_in);
  // FIXME: use 'bandwidth_out'!
}


/**
 * Function called to notify transport users that another
 * peer connected to us.
 *
 * @param cls closure
 * @param peer the peer that connected
 * @param ats performance data
 * @param ats_count number of entries in ats (excluding 0-termination)
 */
static void
neighbours_connect_notification (void *cls,
                                 const struct GNUNET_PeerIdentity *peer,
                                 const struct GNUNET_TRANSPORT_ATS_Information
                                 *ats, uint32_t ats_count)
{
  char buf[sizeof (struct ConnectInfoMessage) +
           ats_count * sizeof (struct GNUNET_TRANSPORT_ATS_Information)];
  struct ConnectInfoMessage *connect_msg = (struct ConnectInfoMessage *) buf;
  struct GNUNET_TRANSPORT_ATS_Information *atsm = &connect_msg->ats;

  connect_msg->header.size = htons (sizeof (buf));
  connect_msg->header.type = htons (GNUNET_MESSAGE_TYPE_TRANSPORT_CONNECT);
  connect_msg->ats_count = htonl (ats_count);
  connect_msg->id = *peer;
  memcpy (&connect_msg->ats, ats,
          ats_count * sizeof (struct GNUNET_TRANSPORT_ATS_Information));
  atsm[ats_count].type = htonl (GNUNET_TRANSPORT_ATS_ARRAY_TERMINATOR);
  atsm[ats_count].value = htonl (0);
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

  disconnect_msg.header.size = htons (sizeof (struct DisconnectInfoMessage));
  disconnect_msg.header.type = htons (GNUNET_MESSAGE_TYPE_TRANSPORT_DISCONNECT);
  disconnect_msg.reserved = htonl (0);
  disconnect_msg.peer = *peer;
  GST_clients_broadcast (&disconnect_msg.header, GNUNET_NO);
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
  GST_validation_stop ();
  GST_plugins_unload ();
  GST_neighbours_stop ();
  GNUNET_ATS_shutdown (GST_ats);
  GST_ats = NULL;
  GST_clients_stop ();
  GST_blacklist_stop ();
  GST_hello_stop ();

  if (GST_peerinfo != NULL)
  {
    GNUNET_PEERINFO_disconnect (GST_peerinfo);
    GST_peerinfo = NULL;
  }
  if (GST_stats != NULL)
  {
    GNUNET_STATISTICS_destroy (GST_stats, GNUNET_NO);
    GST_stats = NULL;
  }
  if (GST_my_private_key != NULL)
  {
    GNUNET_CRYPTO_rsa_key_free (GST_my_private_key);
    GST_my_private_key = NULL;
  }
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

  /* setup globals */
  GST_cfg = c;
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_filename (c, "GNUNETD", "HOSTKEY",
                                               &keyfile))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _
                ("Transport service is lacking key configuration settings.  Exiting.\n"));
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  GST_my_private_key = GNUNET_CRYPTO_rsa_key_create_from_file (keyfile);
  GNUNET_free (keyfile);
  if (GST_my_private_key == NULL)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _("Transport service could not access hostkey.  Exiting.\n"));
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  GST_stats = GNUNET_STATISTICS_create ("transport", c);
  GST_peerinfo = GNUNET_PEERINFO_connect (c);
  GNUNET_CRYPTO_rsa_key_get_public (GST_my_private_key, &GST_my_public_key);
  GNUNET_CRYPTO_hash (&GST_my_public_key, sizeof (GST_my_public_key),
                      &GST_my_identity.hashPubKey);
  GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_FOREVER_REL, &shutdown_task,
                                NULL);
  if (GST_peerinfo == NULL)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _("Could not access PEERINFO service.  Exiting.\n"));
    GNUNET_SCHEDULER_shutdown ();
    return;
  }

  /* start subsystems */
  GST_hello_start (&process_hello_update, NULL);
  GST_blacklist_start (server);
  GST_plugins_load (&plugin_env_receive_callback,
                    &plugin_env_address_change_notification,
                    &plugin_env_session_end);
  GST_ats = GNUNET_ATS_init (GST_cfg, &ats_request_address_change, NULL);
  GST_neighbours_start (NULL, &neighbours_connect_notification,
                        &neighbours_disconnect_notification);
  GST_clients_start (server);
  GST_validation_start ();
}


/**
 * The main function for the transport service.
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return 0 ok, 1 on error
 */
int
main (int argc, char *const *argv)
{
  return (GNUNET_OK ==
          GNUNET_SERVICE_run (argc, argv, "transport",
                              GNUNET_SERVICE_OPTION_NONE, &run, NULL)) ? 0 : 1;
}

/* end of file gnunet-service-transport-new.c */

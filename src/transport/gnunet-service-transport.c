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
struct GNUNET_ATS_SchedulingHandle *GST_ats;

/**
 * DEBUGGING connection counter
 */
static int connections;


/**
 * Transmit our HELLO message to the given (connected) neighbour.
 *
 * @param cls the 'HELLO' message
 * @param target a connected neighbour
 * @param ats performance information (unused)
 * @param ats_count number of records in ats (unused)
 * @param address the address
 */
static void
transmit_our_hello (void *cls, const struct GNUNET_PeerIdentity *target,
                    const struct GNUNET_ATS_Information *ats,
                    uint32_t ats_count,
                    const struct GNUNET_HELLO_Address *address)
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
 * We received some payload.  Prepare to pass it on to our clients.
 *
 * @param peer (claimed) identity of the other peer
 * @param address the address
 * @param session session used
 * @param message the message to process
 * @param ats performance information
 * @param ats_count number of records in ats
 * @return how long the plugin should wait until receiving more data
 */
static struct GNUNET_TIME_Relative
process_payload (const struct GNUNET_PeerIdentity *peer,
                 const struct GNUNET_HELLO_Address *address,
                 struct Session *session,
                 const struct GNUNET_MessageHeader *message,
                 const struct GNUNET_ATS_Information *ats, uint32_t ats_count)
{
  struct GNUNET_TIME_Relative ret;
  int do_forward;
  struct InboundMessage *im;
  size_t msg_size = ntohs (message->size);
  size_t size =
      sizeof (struct InboundMessage) + msg_size +
      sizeof (struct GNUNET_ATS_Information) * (ats_count + 1);
  char buf[size] GNUNET_ALIGN;
  struct GNUNET_ATS_Information *ap;

  ret = GNUNET_TIME_UNIT_ZERO;
  do_forward = GNUNET_SYSERR;
  ret = GST_neighbours_calculate_receive_delay (peer, msg_size, &do_forward);

  if (!GST_neighbours_test_connected (peer))
  {

    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Discarded %u bytes type %u payload from peer `%s'\n", msg_size,
                ntohs (message->type), GNUNET_i2s (peer));

    GNUNET_STATISTICS_update (GST_stats,
                              gettext_noop
                              ("# bytes payload discarded due to not connected peer "),
                              msg_size, GNUNET_NO);
    return ret;
  }

  if (do_forward != GNUNET_YES)
    return ret;
  im = (struct InboundMessage *) buf;
  im->header.size = htons (size);
  im->header.type = htons (GNUNET_MESSAGE_TYPE_TRANSPORT_RECV);
  im->ats_count = htonl (ats_count + 1);
  im->peer = *peer;
  ap = (struct GNUNET_ATS_Information *) &im[1];
  memcpy (ap, ats, ats_count * sizeof (struct GNUNET_ATS_Information));
  ap[ats_count].type = htonl (GNUNET_ATS_QUALITY_NET_DELAY);
  ap[ats_count].value =
      htonl ((uint32_t) GST_neighbour_get_latency (peer).rel_value);
  memcpy (&ap[ats_count + 1], message, ntohs (message->size));

  GNUNET_ATS_address_update (GST_ats, address, session, ap, ats_count + 1);
  GST_clients_broadcast (&im->header, GNUNET_YES);

  return ret;
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
                             const struct GNUNET_ATS_Information *ats,
                             uint32_t ats_count, struct Session *session,
                             const char *sender_address,
                             uint16_t sender_address_len)
{
  const char *plugin_name = cls;
  struct GNUNET_TIME_Relative ret;
  struct GNUNET_HELLO_Address address;
  uint16_t type;

  address.peer = *peer;
  address.address = sender_address;
  address.address_length = sender_address_len;
  address.transport_name = plugin_name;
  ret = GNUNET_TIME_UNIT_ZERO;
  if (NULL == message)
    goto end;
  type = ntohs (message->type);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Received Message with type %u from peer `%s'\n", type, GNUNET_i2s (peer));

  GNUNET_STATISTICS_update (GST_stats,
                        gettext_noop
                        ("# bytes total received"),
                            ntohs (message->size), GNUNET_NO);

  switch (type)
  {
  case GNUNET_MESSAGE_TYPE_HELLO:
    GST_validation_handle_hello (message);
    return ret;
  case GNUNET_MESSAGE_TYPE_TRANSPORT_PING:
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG | GNUNET_ERROR_TYPE_BULK,
                "Processing `%s' from `%s'\n", "PING",
                (sender_address !=
                 NULL) ? GST_plugins_a2s (&address) : "<inbound>");
    GST_validation_handle_ping (peer, message, &address, session);
    break;
  case GNUNET_MESSAGE_TYPE_TRANSPORT_PONG:
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG | GNUNET_ERROR_TYPE_BULK,
                "Processing `%s' from `%s'\n", "PONG",
                (sender_address !=
                 NULL) ? GST_plugins_a2s (&address) : "<inbound>");
    GST_validation_handle_pong (peer, message);
    break;
  case GNUNET_MESSAGE_TYPE_TRANSPORT_SESSION_CONNECT:
    GST_neighbours_handle_connect (message, peer, &address, session, ats,
                                   ats_count);
    break;
  case GNUNET_MESSAGE_TYPE_TRANSPORT_SESSION_CONNECT_ACK:
    GST_neighbours_handle_connect_ack (message, peer, &address, session, ats,
                                       ats_count);
    break;
  case GNUNET_MESSAGE_TYPE_TRANSPORT_SESSION_ACK:
    GST_neighbours_handle_session_ack (message, peer, &address, session, ats,
				       ats_count);
    break;
  case GNUNET_MESSAGE_TYPE_TRANSPORT_SESSION_DISCONNECT:
    GST_neighbours_handle_disconnect_message (peer, message);
    break;
  case GNUNET_MESSAGE_TYPE_TRANSPORT_SESSION_KEEPALIVE:
    GST_neighbours_keepalive (peer);
    break;
  case GNUNET_MESSAGE_TYPE_TRANSPORT_SESSION_KEEPALIVE_RESPONSE:
    GST_neighbours_keepalive_response (peer, ats, ats_count);
    break;
  default:
    /* should be payload */
    GNUNET_STATISTICS_update (GST_stats,
                              gettext_noop
                              ("# bytes payload received"),
                              ntohs (message->size), GNUNET_NO);
    ret = process_payload (peer, &address, session, message, ats, ats_count);
    break;
  }
end:
#if 1
  /* FIXME: this should not be needed, and not sure it's good to have it, but without
   * this connections seem to go extra-slow */
  GNUNET_ATS_address_update (GST_ats, &address, session, ats, ats_count);
#endif
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Allowing receive from peer %s to continue in %llu ms\n",
              GNUNET_i2s (peer), (unsigned long long) ret.rel_value);
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
  struct GNUNET_HELLO_Address address;

  address.peer = GST_my_identity;
  address.transport_name = plugin_name;
  address.address = addr;
  address.address_length = addrlen;
  GST_hello_modify_addresses (add_remove, &address);
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
  const char *transport_name = cls;
  struct GNUNET_HELLO_Address address;

  GNUNET_assert (strlen (transport_name) > 0);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Session %X to peer `%s' ended \n",
              session, GNUNET_i2s (peer));
  if (NULL != session)
    GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG | GNUNET_ERROR_TYPE_BULK,
                     "transport-ats",
                     "Telling ATS to destroy session %p from peer %s\n",
                     session, GNUNET_i2s (peer));
  address.peer = *peer;
  address.address = NULL;
  address.address_length = 0;
  address.transport_name = transport_name;
  GST_neighbours_session_terminated (peer, session);
  GNUNET_ATS_address_destroyed (GST_ats, &address, session);
}


/**
 * Function that will be called to figure if an address is an loopback,
 * LAN, WAN etc. address
 *
 * @param cls closure
 * @param addr binary address
 * @param addrlen length of the address
 * @return ATS Information containing the network type
 */
static struct GNUNET_ATS_Information
plugin_env_address_to_type (void *cls,
                            const struct sockaddr *addr,
                            size_t addrlen)
{
  struct GNUNET_ATS_Information ats;
  ats.type = htonl (GNUNET_ATS_NETWORK_TYPE);
  ats.value = htonl (GNUNET_ATS_NET_UNSPECIFIED);
  if (GST_ats == NULL)
  {
    GNUNET_break (0);
    return ats;
  }
  if (((addr->sa_family != AF_INET) && (addrlen != sizeof (struct sockaddr_in))) &&
      ((addr->sa_family != AF_INET6) && (addrlen != sizeof (struct sockaddr_in6))) &&
      (addr->sa_family != AF_UNIX))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Malformed address with length %u `%s'\n",
                addrlen,
                GNUNET_a2s(addr, addrlen));
    GNUNET_break (0);
    return (const struct GNUNET_ATS_Information) ats;
  }
  return GNUNET_ATS_address_get_type(GST_ats, addr, addrlen);
}


/**
 * Function called by ATS to notify the callee that the
 * assigned bandwidth or address for a given peer was changed.  If the
 * callback is called with address/bandwidth assignments of zero, the
 * ATS disconnect function will still be called once the disconnect
 * actually happened.
 *
 * @param cls closure
 * @param address address to use (for peer given in address)
 * @param session session to use (if available)
 * @param bandwidth_out assigned outbound bandwidth for the connection, 0 to disconnect from peer
 * @param bandwidth_in assigned inbound bandwidth for the connection, 0 to disconnect from peer
 * @param ats ATS information
 * @param ats_count number of ATS elements
 */
static void
ats_request_address_change (void *cls,
                            const struct GNUNET_HELLO_Address *address,
                            struct Session *session,
                            struct GNUNET_BANDWIDTH_Value32NBO bandwidth_out,
                            struct GNUNET_BANDWIDTH_Value32NBO bandwidth_in,
                            const struct GNUNET_ATS_Information *ats,
                            uint32_t ats_count)
{
  uint32_t bw_in = ntohl (bandwidth_in.value__);
  uint32_t bw_out = ntohl (bandwidth_out.value__);

  /* ATS tells me to disconnect from peer */
  if ((bw_in == 0) && (bw_out == 0))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "ATS tells me to disconnect from peer `%s'\n",
                GNUNET_i2s (&address->peer));
    GST_neighbours_force_disconnect (&address->peer);
    return;
  }
  GST_neighbours_switch_to_address (&address->peer, address, session, ats,
                                         ats_count, bandwidth_in,
                                         bandwidth_out);
}


/**
 * Function called to notify transport users that another
 * peer connected to us.
 *
 * @param cls closure
 * @param peer the peer that connected
 * @param ats performance data
 * @param ats_count number of entries in ats
 */
static void
neighbours_connect_notification (void *cls,
                                 const struct GNUNET_PeerIdentity *peer,
                                 const struct GNUNET_ATS_Information *ats,
                                 uint32_t ats_count)
{
  size_t len =
      sizeof (struct ConnectInfoMessage) +
      ats_count * sizeof (struct GNUNET_ATS_Information);
  char buf[len] GNUNET_ALIGN;
  struct ConnectInfoMessage *connect_msg = (struct ConnectInfoMessage *) buf;
  struct GNUNET_ATS_Information *ap;

  connections++;
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "We are now connected to peer `%s' and %u peers in total\n",
              GNUNET_i2s (peer), connections);

  connect_msg->header.size = htons (sizeof (buf));
  connect_msg->header.type = htons (GNUNET_MESSAGE_TYPE_TRANSPORT_CONNECT);
  connect_msg->ats_count = htonl (ats_count);
  connect_msg->id = *peer;
  ap = (struct GNUNET_ATS_Information *) &connect_msg[1];
  memcpy (ap, ats, ats_count * sizeof (struct GNUNET_ATS_Information));
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
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "Peer `%s' disconnected and we are connected to %u peers\n",
              GNUNET_i2s (peer), connections);

  disconnect_msg.header.size = htons (sizeof (struct DisconnectInfoMessage));
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
 */
static void
neighbours_address_notification (void *cls,
                                 const struct GNUNET_PeerIdentity *peer,
                                 const struct GNUNET_HELLO_Address *address)
{
  GST_clients_broadcast_address_notification (peer, address);
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
  struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded tmp;
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
  memset (&GST_my_public_key, '\0', sizeof (GST_my_public_key));
  memset (&tmp, '\0', sizeof (tmp));
  GNUNET_CRYPTO_rsa_key_get_public (GST_my_private_key, &GST_my_public_key);
  GNUNET_CRYPTO_hash (&GST_my_public_key, sizeof (GST_my_public_key),
                      &GST_my_identity.hashPubKey);

  GNUNET_assert (NULL != GST_my_private_key);
  GNUNET_assert (0 != memcmp (&GST_my_public_key, &tmp, sizeof (GST_my_public_key)));

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
  GNUNET_assert (NULL != GST_hello_get());
  GST_blacklist_start (server);
  GST_ats =
      GNUNET_ATS_scheduling_init (GST_cfg, &ats_request_address_change, NULL);
  GST_plugins_load (&plugin_env_receive_callback,
                    &plugin_env_address_change_notification,
                    &plugin_env_session_end,
                    &plugin_env_address_to_type);
  GST_neighbours_start (NULL,
                        &neighbours_connect_notification,
                        &neighbours_disconnect_notification,
                        &neighbours_address_notification);
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

/* end of file gnunet-service-transport.c */

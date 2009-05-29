/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2003, 2004, 2005, 2006, 2007, 2009 Christian Grothoff (and other contributing authors)

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
 * @file include/gnunet_protocols.h
 * @brief constants for network protocols
 * @author Christian Grothoff
 */

#ifndef GNUNET_PROTOCOLS_H
#define GNUNET_PROTOCOLS_H

#ifdef __cplusplus
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif

/**
 * Test if service is online.
 */
#define GNUNET_MESSAGE_TYPE_TEST 0

/**
 * Request service shutdown.
 */
#define GNUNET_MESSAGE_TYPE_SHUTDOWN 1


/**
 * Request DNS resolution.
 */
#define GNUNET_MESSAGE_TYPE_RESOLVER_REQUEST 2

/**
 * Response to a DNS resolution request.
 */
#define GNUNET_MESSAGE_TYPE_RESOLVER_RESPONSE 3


/**
 * Set a statistical value.
 */
#define GNUNET_MESSAGE_TYPE_STATISTICS_SET 4

/**
 * Get a statistical value(s).
 */
#define GNUNET_MESSAGE_TYPE_STATISTICS_GET 5

/**
 * Response to a STATISTICS_GET message (with value).
 */
#define GNUNET_MESSAGE_TYPE_STATISTICS_VALUE 6

/**
 * Response to a STATISTICS_GET message (end of value stream).
 */
#define GNUNET_MESSAGE_TYPE_STATISTICS_END 7


/**
 * Request to ARM to start a service.
 */
#define GNUNET_MESSAGE_TYPE_ARM_START 8

/**
 * Request to ARM to stop a service.
 */
#define GNUNET_MESSAGE_TYPE_ARM_STOP 9

/**
 * Response from ARM: service is now up.
 */
#define GNUNET_MESSAGE_TYPE_ARM_IS_UP 10

/**
 * Response from ARM: service is now down.
 * (failed to start it).
 */
#define GNUNET_MESSAGE_TYPE_ARM_IS_DOWN 11


/**
 * HELLO message used for communicating peer addresses.
 * Managed by libgnunethello.
 */
#define GNUNET_MESSAGE_TYPE_HELLO 16

/**
 * FRAGMENT of a larger message.
 * Managed by libgnunetfragment.
 */
#define GNUNET_MESSAGE_TYPE_FRAGMENT 18


/**
 * Message from the core saying that the transport
 * server should start giving it messages.  This
 * should automatically trigger the transmission of
 * a HELLO message.
 */
#define GNUNET_MESSAGE_TYPE_TRANSPORT_START 20

/**
 * Message from TRANSPORT notifying about a
 * client that connected to us.
 */
#define GNUNET_MESSAGE_TYPE_TRANSPORT_CONNECT 21

/**
 * Message from TRANSPORT notifying about a
 * client that disconnected from us.
 */
#define GNUNET_MESSAGE_TYPE_TRANSPORT_DISCONNECT 22

/**
 * Request to TRANSPORT to transmit a message.
 */
#define GNUNET_MESSAGE_TYPE_TRANSPORT_SEND 23

/**
 * Confirmation from TRANSPORT that message for
 * transmission has been queued (and that the next
 * message to this peer can now be passed to the
 * service).  Note that this confirmation does NOT
 * imply that the message was fully transmitted.
 */
#define GNUNET_MESSAGE_TYPE_TRANSPORT_SEND_OK 24

/**
 * Message from TRANSPORT notifying about a
 * message that was received.
 */
#define GNUNET_MESSAGE_TYPE_TRANSPORT_RECV 25

/**
 * Message telling transport to limit its receive rate.
 */
#define GNUNET_MESSAGE_TYPE_TRANSPORT_SET_QUOTA 26

/**
 * Message telling transport to try to connect to the
 * given peer.
 */
#define GNUNET_MESSAGE_TYPE_TRANSPORT_TRY_CONNECT 27

/**
 * Request to other peer to confirm receipt.
 */
#define GNUNET_MESSAGE_TYPE_TRANSPORT_PING 28

/**
 * Message from other peer confirming receipt.
 */
#define GNUNET_MESSAGE_TYPE_TRANSPORT_PONG 29

/**
 * Response to another peer confirming that communication was
 * established.
 */
#define GNUNET_MESSAGE_TYPE_TRANSPORT_ACK 30


/**
 * Request addition of a HELLO
 */
#define GNUNET_MESSAGE_TYPE_PEERINFO_ADD 32

/**
 * Request update and listing of a peer.
 */
#define GNUNET_MESSAGE_TYPE_PEERINFO_GET 33

/**
 * Request update and listing of all peers.
 */
#define GNUNET_MESSAGE_TYPE_PEERINFO_GET_ALL 34

/**
 * Information about one of the peers.
 */
#define GNUNET_MESSAGE_TYPE_PEERINFO_INFO 35

/**
 * End of information about other peers.
 */
#define GNUNET_MESSAGE_TYPE_PEERINFO_INFO_END 36


/**
 * Welcome message between TCP transports.
 */
#define GNUNET_MESSAGE_TYPE_TRANSPORT_TCP_WELCOME 40

/**
 * Data message between TCP transports.
 */
#define GNUNET_MESSAGE_TYPE_TRANSPORT_TCP_DATA 41


/**
 * Initial setup message from core client to core.
 */
#define GNUNET_MESSAGE_TYPE_CORE_INIT 64

/**
 * Response from core to core client to INIT message.
 */
#define GNUNET_MESSAGE_TYPE_CORE_INIT_REPLY 65

/**
 * Notify clients about new peer-to-peer connections.
 */
#define GNUNET_MESSAGE_TYPE_CORE_NOTIFY_CONNECT 66

/**
 * Notify clients about peer disconnecting.
 */
#define GNUNET_MESSAGE_TYPE_CORE_NOTIFY_DISCONNECT 67

/**
 * Notify clients about incoming P2P messages.
 */
#define GNUNET_MESSAGE_TYPE_CORE_NOTIFY_INBOUND 68

/**
 * Notify clients about outgoing P2P transmissions.
 */
#define GNUNET_MESSAGE_TYPE_CORE_NOTIFY_OUTBOUND 69

/**
 * Request from client to "configure" P2P connection.
 */
#define GNUNET_MESSAGE_TYPE_CORE_REQUEST_CONFIGURE 70

/**
 * Response from server about (possibly updated) P2P
 * connection configuration.
 */
#define GNUNET_MESSAGE_TYPE_CORE_CONFIGURATION_INFO 71

/**
 * Solicitation from server for transmission (may have
 * been requested or also be transmitted without
 * client's request).
 */
#define GNUNET_MESSAGE_TYPE_CORE_SOLICIT_TRAFFIC 72

/**
 * Response from client with message to transmit.
 */
#define GNUNET_MESSAGE_TYPE_CORE_SEND 73


/**
 * Session key exchange between peers.
 */
#define GNUNET_MESSAGE_TYPE_CORE_SET_KEY 80

/**
 * Encapsulation for an encrypted message between peers.
 */
#define GNUNET_MESSAGE_TYPE_CORE_ENCRYPTED_MESSAGE 81

/**
 * Check that other peer is alife (challenge).
 */
#define GNUNET_MESSAGE_TYPE_CORE_PING 82

/**
 * Confirmation that other peer is alife.
 */
#define GNUNET_MESSAGE_TYPE_CORE_PONG 83

/**
 * Request by the other peer to terminate the connection.
 */
#define GNUNET_MESSAGE_TYPE_CORE_HANGUP 84


/*
  TODO:
  - DV
  - DHT
  - datastores
  - applications (FS, VPN, CHAT, TRACEKIT, TBENCH)
*/


#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

/* ifndef GNUNET_PROTOCOLS_H */
#endif
/* end of gnunet_protocols.h */

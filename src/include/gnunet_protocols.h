/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2003, 2004, 2005, 2006, 2007, 2009, 2010 Christian Grothoff (and other contributing authors)

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
 * (failed to start it or shut it down).
 */
#define GNUNET_MESSAGE_TYPE_ARM_IS_DOWN 11

/**
 * Response from ARM: service status is unknown.
 */
#define GNUNET_MESSAGE_TYPE_ARM_IS_UNKNOWN 12


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
 * Request to look addresses of peers in server.
 */
#define GNUNET_MESSAGE_TYPE_TRANSPORT_ADDRESS_LOOKUP 27

/**
 * Response to the address lookup request.
 */
#define GNUNET_MESSAGE_TYPE_TRANSPORT_ADDRESS_REPLY 28

/**
 * Register a client that wants to do blacklisting.
 */
#define GNUNET_MESSAGE_TYPE_TRANSPORT_BLACKLIST_INIT 29

/**
 * Query to a blacklisting client (is this peer blacklisted)?
 */
#define GNUNET_MESSAGE_TYPE_TRANSPORT_BLACKLIST_QUERY 30

/**
 * Reply from blacklisting client (answer to blacklist query).
 */
#define GNUNET_MESSAGE_TYPE_TRANSPORT_BLACKLIST_REPLY 31

/**
 * Transport PING message
 */
#define GNUNET_MESSAGE_TYPE_TRANSPORT_PING 32

/**
 * Transport PONG message
 */
#define GNUNET_MESSAGE_TYPE_TRANSPORT_PONG 33

/**
 * Request addition of a HELLO
 */
#define GNUNET_MESSAGE_TYPE_PEERINFO_ADD 36

/**
 * Request update and listing of a peer.
 */
#define GNUNET_MESSAGE_TYPE_PEERINFO_GET 37

/**
 * Request update and listing of all peers.
 */
#define GNUNET_MESSAGE_TYPE_PEERINFO_GET_ALL 38

/**
 * Information about one of the peers.
 */
#define GNUNET_MESSAGE_TYPE_PEERINFO_INFO 39

/**
 * End of information about other peers.
 */
#define GNUNET_MESSAGE_TYPE_PEERINFO_INFO_END 40

/**
 * Start notifying this client about all changes to
 * the known peers until it disconnects.
 */
#define GNUNET_MESSAGE_TYPE_PEERINFO_NOTIFY 41

/**
 * DV service to DV Plugin message, when a message is
 * unwrapped by the DV service and handed to the plugin
 * for processing
 */
#define GNUNET_MESSAGE_TYPE_TRANSPORT_DV_RECEIVE 44

/**
 * DV Plugin to DV service message, indicating a message
 * should be sent out.
 */
#define GNUNET_MESSAGE_TYPE_TRANSPORT_DV_SEND 45

/**
 * P2P DV message encapsulating some real message
 */
#define GNUNET_MESSAGE_TYPE_DV_DATA 46

/**
 * P2P DV message gossipping peer information
 */
#define GNUNET_MESSAGE_TYPE_DV_GOSSIP 47

/**
 * DV Plugin to DV service message, indicating
 * startup.
 */
#define GNUNET_MESSAGE_TYPE_DV_START 48

/**
 * UDP NAT probe message, send from NAT'd peer to
 * other peer to negotiate punched address/port
 */
#define GNUNET_MESSAGE_TYPE_TRANSPORT_UDP_NAT_PROBE 55

/**
 * UDP NAT probe reply, sent from a non-NAT'd peer to
 * a NAT'd one to inform it we got the probe and of the
 * address/port seen
 */
#define GNUNET_MESSAGE_TYPE_TRANSPORT_UDP_NAT_PROBE_REPLY 56

/**
 * UDP NAT probe confirmation, sent from a NAT'd peer to
 * a non-NAT'd one to inform it which port to send to us
 * on
 */
#define GNUNET_MESSAGE_TYPE_TRANSPORT_UDP_NAT_PROBE_CONFIRM 57

/**
 * UDP NAT probe keepalive, once a hole is punched the NAT'd peer
 * needs to keep the hole alive
 */
#define GNUNET_MESSAGE_TYPE_TRANSPORT_UDP_NAT_PROBE_KEEPALIVE 58

/**
 * Welcome message between TCP transports.
 */
#define GNUNET_MESSAGE_TYPE_TRANSPORT_TCP_WELCOME 60

/**
 * Initial setup message from core client to core.
 */
#define GNUNET_MESSAGE_TYPE_CORE_INIT 64

/**
 * Response from core to core client to INIT message.
 */
#define GNUNET_MESSAGE_TYPE_CORE_INIT_REPLY 65

/**
 * Notify clients about new peer-to-peer connections (before
 * key exchange and authentication).
 */
#define GNUNET_MESSAGE_TYPE_CORE_NOTIFY_PRE_CONNECT 66

/**
 * Notify clients about new peer-to-peer connections (triggered
 * after key exchange).
 */
#define GNUNET_MESSAGE_TYPE_CORE_NOTIFY_CONNECT 67

/**
 * Notify clients about peer disconnecting.
 */
#define GNUNET_MESSAGE_TYPE_CORE_NOTIFY_DISCONNECT 68

/**
 * Notify clients about incoming P2P messages.
 */
#define GNUNET_MESSAGE_TYPE_CORE_NOTIFY_INBOUND 69

/**
 * Notify clients about outgoing P2P transmissions.
 */
#define GNUNET_MESSAGE_TYPE_CORE_NOTIFY_OUTBOUND 70

/**
 * Request from client to "configure" P2P connection.
 */
#define GNUNET_MESSAGE_TYPE_CORE_REQUEST_INFO 71

/**
 * Response from server about (possibly updated) P2P
 * connection configuration.
 */
#define GNUNET_MESSAGE_TYPE_CORE_CONFIGURATION_INFO 72

/**
 * Request from client with message to transmit.
 */
#define GNUNET_MESSAGE_TYPE_CORE_SEND 73

/**
 * Request from client asking to connect to a peer.
 */
#define GNUNET_MESSAGE_TYPE_CORE_REQUEST_CONNECT 74


/**
 * Session key exchange between peers.
 */
#define GNUNET_MESSAGE_TYPE_CORE_SET_KEY 80

/**
 * Encapsulation for an encrypted message between peers.
 */
#define GNUNET_MESSAGE_TYPE_CORE_ENCRYPTED_MESSAGE 81

/**
 * Check that other peer is alive (challenge).
 */
#define GNUNET_MESSAGE_TYPE_CORE_PING 82

/**
 * Confirmation that other peer is alive.
 */
#define GNUNET_MESSAGE_TYPE_CORE_PONG 83

/**
 * Request by the other peer to terminate the connection.
 */
#define GNUNET_MESSAGE_TYPE_CORE_HANGUP 84

/**
 * Message sent by datastore client on join.
 */
#define GNUNET_MESSAGE_TYPE_DATASTORE_RESERVE 92

/**
 * Message sent by datastore client on join.
 */
#define GNUNET_MESSAGE_TYPE_DATASTORE_RELEASE_RESERVE 93

/**
 * Message sent by datastore to client informing about status
 * processing a request
 * (in response to RESERVE, RELEASE_RESERVE, PUT, UPDATE and REMOVE requests).
 */
#define GNUNET_MESSAGE_TYPE_DATASTORE_STATUS 94

/**
 * Message sent by datastore client to store data.
 */
#define GNUNET_MESSAGE_TYPE_DATASTORE_PUT 95

/**
 * Message sent by datastore client to update data.
 */
#define GNUNET_MESSAGE_TYPE_DATASTORE_UPDATE 96

/**
 * Message sent by datastore client to get data.
 */
#define GNUNET_MESSAGE_TYPE_DATASTORE_GET 97

/**
 * Message sent by datastore client to get random data.
 */
#define GNUNET_MESSAGE_TYPE_DATASTORE_GET_RANDOM 98

/**
 * Message sent by datastore to client providing requested data
 * (in response to GET or GET_RANDOM request).
 */
#define GNUNET_MESSAGE_TYPE_DATASTORE_DATA 99

/**
 * Message sent by datastore to client signaling end of matching data.
 * This message will also be sent for "GET_RANDOM", even though
 * "GET_RANDOM" returns at most one data item.
 */
#define GNUNET_MESSAGE_TYPE_DATASTORE_DATA_END 100

/**
 * Message sent by datastore client to remove data.
 */
#define GNUNET_MESSAGE_TYPE_DATASTORE_REMOVE 101

/**
 * Message sent by datastore client to drop the database.
 */
#define GNUNET_MESSAGE_TYPE_DATASTORE_DROP 102


/**
 * Message sent by fs client to start indexing.
 */
#define GNUNET_MESSAGE_TYPE_FS_INDEX_START 128

/**
 * Affirmative response to a request for start indexing.
 */
#define GNUNET_MESSAGE_TYPE_FS_INDEX_START_OK 129

/**
 * Response to a request for start indexing that
 * refuses.
 */
#define GNUNET_MESSAGE_TYPE_FS_INDEX_START_FAILED 130

/**
 * Request from client for list of indexed files.
 */
#define GNUNET_MESSAGE_TYPE_FS_INDEX_LIST_GET 131

/**
 * Reply to client with an indexed file name.
 */
#define GNUNET_MESSAGE_TYPE_FS_INDEX_LIST_ENTRY 132

/**
 * Reply to client indicating end of list.
 */
#define GNUNET_MESSAGE_TYPE_FS_INDEX_LIST_END 133

/**
 * Request from client to unindex a file.
 */
#define GNUNET_MESSAGE_TYPE_FS_UNINDEX 134

/**
 * Reply to client indicating unindex receipt.
 */
#define GNUNET_MESSAGE_TYPE_FS_UNINDEX_OK 135

/**
 * Client asks FS service to start a (keyword) search.
 */
#define GNUNET_MESSAGE_TYPE_FS_START_SEARCH 136

/**
 * P2P request for content (one FS to another).
 */
#define GNUNET_MESSAGE_TYPE_FS_GET 137

/**
 * P2P response with content or active migration of content.  Also
 * used between the service and clients (in response to START_SEARCH).
 */
#define GNUNET_MESSAGE_TYPE_FS_PUT 138


/**
 * DHT Message Types
 */

/**
 * Local and P2P generic DHT message start type
 */
#define GNUNET_MESSAGE_TYPE_DHT 142

/**
 * Local and P2P generic DHT message stop type
 */
#define GNUNET_MESSAGE_TYPE_DHT_STOP 143

/**
 * Local and message acknowledgment
 */
#define GNUNET_MESSAGE_TYPE_DHT_ACK 144

/**
 * Local DHT Put message, from API to service
 */
#define GNUNET_MESSAGE_TYPE_DHT_PUT 145

/**
 * Local DHT Get message, from API to service
 */
#define GNUNET_MESSAGE_TYPE_DHT_GET 146

/**
 * Local DHT Get stop message, from API to service
 */
#define GNUNET_MESSAGE_TYPE_DHT_GET_STOP 147

/**
 * Local DHT Get result message, from service to API
 */
#define GNUNET_MESSAGE_TYPE_DHT_GET_RESULT 148

/**
 * Local DHT Get message, from API to service
 */
#define GNUNET_MESSAGE_TYPE_DHT_FIND_PEER 150

/**
 * Local DHT Get stop message, from API to service
 */
#define GNUNET_MESSAGE_TYPE_DHT_FIND_PEER_STOP 151

/**
 * Local DHT find peer result message, from service to API
 */
#define GNUNET_MESSAGE_TYPE_DHT_FIND_PEER_RESULT 152

/**
 * Hostlist advertisement message
 */
#define GNUNET_MESSAGE_TYPE_HOSTLIST_ADVERTISEMENT 160

/**
 * Type used to match 'all' message types.
 */
#define GNUNET_MESSAGE_TYPE_ALL 65535

/*
  TODO:
  - DV
  - DHT
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

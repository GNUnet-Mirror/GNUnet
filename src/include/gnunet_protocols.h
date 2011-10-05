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

/*******************************************************************************
 * UTIL message types
 ******************************************************************************/

/**
 * Test if service is online.
 */
#define GNUNET_MESSAGE_TYPE_TEST 1

/*******************************************************************************
 * RESOLVER message types
 ******************************************************************************/

/**
 * Request DNS resolution.
 */
#define GNUNET_MESSAGE_TYPE_RESOLVER_REQUEST 4

/**
 * Response to a DNS resolution request.
 */
#define GNUNET_MESSAGE_TYPE_RESOLVER_RESPONSE 5

/*******************************************************************************
 * ARM message types
 ******************************************************************************/

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
 * Request ARM service shutdown.
 */
#define GNUNET_MESSAGE_TYPE_ARM_SHUTDOWN 13

/**
 * Acknowledge service shutting down, disconnect
 * indicates service stopped.
 */
#define GNUNET_MESSAGE_TYPE_ARM_SHUTDOWN_ACK 14

/*******************************************************************************
 * HELLO message types
 ******************************************************************************/

/**
 * HELLO message used for communicating peer addresses.
 * Managed by libgnunethello.
 */
#define GNUNET_MESSAGE_TYPE_HELLO 16

/*******************************************************************************
 * FRAGMENTATION message types
 ******************************************************************************/

/**
 * FRAGMENT of a larger message.
 * Managed by libgnunetfragment.
 */
#define GNUNET_MESSAGE_TYPE_FRAGMENT 18

/**
 * Acknowledgement of a FRAGMENT of a larger message.
 * Managed by libgnunetfragment.
 */
#define GNUNET_MESSAGE_TYPE_FRAGMENT_ACK 19

/*******************************************************************************
 * TRANSPORT message types
 ******************************************************************************/

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
 * Confirmation from TRANSPORT that message for transmission has been
 * queued (and that the next message to this peer can now be passed to
 * the service).  Note that this confirmation does NOT imply that the
 * message was fully transmitted.
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
 * Transport CONNECT message exchanged between transport services to
 * indicate that a session should be marked as 'connected'.
 */
#define GNUNET_MESSAGE_TYPE_TRANSPORT_SESSION_CONNECT 35

/**
 * Transport DISCONNECT message exchanged between transport services to
 * indicate that a connection should be dropped.
 */
#define GNUNET_MESSAGE_TYPE_TRANSPORT_SESSION_DISCONNECT 36

/**
 * Request to look up addresses of peers.
 */
#define GNUNET_MESSAGE_TYPE_TRANSPORT_PEER_ADDRESS_LOOKUP 37

/**
 * Request to iterate over all known addresses.
 */
#define GNUNET_MESSAGE_TYPE_TRANSPORT_ADDRESS_ITERATE 38

/**
 * Message send by a peer to notify the other to keep the session alive.
 */
#define GNUNET_MESSAGE_TYPE_TRANSPORT_SESSION_KEEPALIVE 39

/*******************************************************************************
 * Transport-WLAN message types
 ******************************************************************************/

/**
 * Type of messages between the gnunet-wlan-helper and the daemon
 *
 */
#define GNUNET_MESSAGE_TYPE_WLAN_HELPER_DATA 40

/**
 * Control messages between the gnunet-wlan-helper and the daemon
 */

#define GNUNET_MESSAGE_TYPE_WLAN_HELPER_CONTROL 41

/**
 * Type of messages for advertisement over wlan
 */
#define GNUNET_MESSAGE_TYPE_WLAN_ADVERTISEMENT 42

/**
 * Type of messages for data over the wlan
 */
#define GNUNET_MESSAGE_TYPE_WLAN_DATA 43


/*******************************************************************************
 * Transport-DV message types
 ******************************************************************************/

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
 * DV service to DV api message, containing a confirmation
 * or failure of a DV_SEND message.
 */
#define GNUNET_MESSAGE_TYPE_TRANSPORT_DV_SEND_RESULT 46

/**
 * P2P DV message encapsulating some real message
 */
#define GNUNET_MESSAGE_TYPE_DV_DATA 47

/**
 * P2P DV message gossipping peer information
 */
#define GNUNET_MESSAGE_TYPE_DV_GOSSIP 48

/**
 * DV Plugin to DV service message, indicating
 * startup.
 */
#define GNUNET_MESSAGE_TYPE_DV_START 49

/**
 * P2P DV message notifying connected peers of a disconnect
 */
#define GNUNET_MESSAGE_TYPE_DV_DISCONNECT 50

/*******************************************************************************
 * Transport-UDP message types
 ******************************************************************************/

/**
 * Normal UDP message type.
 */
#define GNUNET_MESSAGE_TYPE_TRANSPORT_UDP_MESSAGE 56

/**
 * UDP ACK.
 */
#define GNUNET_MESSAGE_TYPE_TRANSPORT_UDP_ACK 57

/*******************************************************************************
 * Transport-TCP message types
 ******************************************************************************/

/**
 * TCP NAT probe message, send from NAT'd peer to
 * other peer to establish bi-directional communication
 */
#define GNUNET_MESSAGE_TYPE_TRANSPORT_TCP_NAT_PROBE 60

/**
 * Welcome message between TCP transports.
 */
#define GNUNET_MESSAGE_TYPE_TRANSPORT_TCP_WELCOME 61

/**
 * Message to force transport to update bandwidth assignment (LEGACY)
 */
#define GNUNET_MESSAGE_TYPE_TRANSPORT_ATS 62

/*******************************************************************************
 * NAT message types
 ******************************************************************************/

/**
 * Message to ask NAT server to perform traversal test
 */
#define GNUNET_MESSAGE_TYPE_NAT_TEST 63

/*******************************************************************************
 * CORE message types
 ******************************************************************************/

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
 * Notify clients about peer status change.
 */
#define GNUNET_MESSAGE_TYPE_CORE_NOTIFY_STATUS_CHANGE 69

/**
 * Notify clients about incoming P2P messages.
 */
#define GNUNET_MESSAGE_TYPE_CORE_NOTIFY_INBOUND 70

/**
 * Notify clients about outgoing P2P transmissions.
 */
#define GNUNET_MESSAGE_TYPE_CORE_NOTIFY_OUTBOUND 71

/**
 * Request from client to "configure" P2P connection.
 */
#define GNUNET_MESSAGE_TYPE_CORE_REQUEST_INFO 72

/**
 * Response from server about (possibly updated) P2P
 * connection configuration.
 */
#define GNUNET_MESSAGE_TYPE_CORE_CONFIGURATION_INFO 73

/**
 * Request from client to transmit message.
 */
#define GNUNET_MESSAGE_TYPE_CORE_SEND_REQUEST 74

/**
 * Confirmation from core that message can now be sent
 */
#define GNUNET_MESSAGE_TYPE_CORE_SEND_READY 75

/**
 * Client with message to transmit (after SEND_READY confirmation
 * was received).
 */
#define GNUNET_MESSAGE_TYPE_CORE_SEND 76

/**
 * Request from client asking to connect to a peer.
 */
#define GNUNET_MESSAGE_TYPE_CORE_REQUEST_CONNECT 77

/**
 * Request for peer iteration from CORE service.
 */
#define GNUNET_MESSAGE_TYPE_CORE_ITERATE_PEERS 78

/**
 * Last reply from core to request for peer iteration from CORE service.
 */
#define GNUNET_MESSAGE_TYPE_CORE_ITERATE_PEERS_END 79

/**
 * Check whether a given peer is currently connected to CORE.
 */
#define GNUNET_MESSAGE_TYPE_CORE_PEER_CONNECTED 80

/**
 * Session key exchange between peers.
 */
#define GNUNET_MESSAGE_TYPE_CORE_SET_KEY 81

/**
 * Encapsulation for an encrypted message between peers.
 */
#define GNUNET_MESSAGE_TYPE_CORE_ENCRYPTED_MESSAGE 82

/**
 * Check that other peer is alive (challenge).
 */
#define GNUNET_MESSAGE_TYPE_CORE_PING 83

/**
 * Confirmation that other peer is alive.
 */
#define GNUNET_MESSAGE_TYPE_CORE_PONG 84

/**
 * Request by the other peer to terminate the connection.
 */
#define GNUNET_MESSAGE_TYPE_CORE_HANGUP 85

/**
 * gzip-compressed type map of the sender
 */
#define GNUNET_MESSAGE_TYPE_CORE_COMPRESSED_TYPE_MAP 86

/**
 * uncompressed type map of the sender
 */
#define GNUNET_MESSAGE_TYPE_CORE_BINARY_TYPE_MAP 87

/*******************************************************************************
 * DATASTORE message types
 ******************************************************************************/

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
#define GNUNET_MESSAGE_TYPE_DATASTORE_GET_REPLICATION 98

/**
 * Message sent by datastore client to get random data.
 */
#define GNUNET_MESSAGE_TYPE_DATASTORE_GET_ZERO_ANONYMITY 99

/**
 * Message sent by datastore to client providing requested data
 * (in response to GET or GET_RANDOM request).
 */
#define GNUNET_MESSAGE_TYPE_DATASTORE_DATA 100

/**
 * Message sent by datastore to client signaling end of matching data.
 * This message will also be sent for "GET_RANDOM", even though
 * "GET_RANDOM" returns at most one data item.
 */
#define GNUNET_MESSAGE_TYPE_DATASTORE_DATA_END 101

/**
 * Message sent by datastore client to remove data.
 */
#define GNUNET_MESSAGE_TYPE_DATASTORE_REMOVE 102

/**
 * Message sent by datastore client to drop the database.
 */
#define GNUNET_MESSAGE_TYPE_DATASTORE_DROP 103


/*******************************************************************************
 * FS message types
 ******************************************************************************/

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
 * Peer asks us to stop migrating content towards it for a while.
 */
#define GNUNET_MESSAGE_TYPE_FS_MIGRATION_STOP 139


/*******************************************************************************
 * DHT message types
 ******************************************************************************/

/**
 * Client wants to store item in DHT.
 */
#define GNUNET_MESSAGE_TYPE_DHT_CLIENT_PUT 142

/**
 * Client wants to lookup item in DHT.
 */
#define GNUNET_MESSAGE_TYPE_DHT_CLIENT_GET 143

/**
 * Client wants to stop search in DHT.
 */
#define GNUNET_MESSAGE_TYPE_DHT_CLIENT_GET_STOP 144

/**
 * Service returns result to client.
 */
#define GNUNET_MESSAGE_TYPE_DHT_CLIENT_RESULT 145

/**
 * Peer is storing data in DHT.
 */
#define GNUNET_MESSAGE_TYPE_DHT_P2P_PUT 146

/**
 * Peer tries to find data in DHT.
 */
#define GNUNET_MESSAGE_TYPE_DHT_P2P_GET 147

/**
 * Data is returned to peer from DHT.
 */
#define GNUNET_MESSAGE_TYPE_DHT_P2P_RESULT 148

// LEGACY types follow (pre3)......

/**
 * Local DHT route request type
 */
#define GNUNET_MESSAGE_TYPE_DHT_LOCAL_ROUTE 142

/**
 * Local generic DHT route result type
 */
#define GNUNET_MESSAGE_TYPE_DHT_LOCAL_ROUTE_RESULT 143

/**
 * P2P DHT route request type
 */
#define GNUNET_MESSAGE_TYPE_DHT_P2P_ROUTE 144

/**
 * P2P DHT route result type
 */
#define GNUNET_MESSAGE_TYPE_DHT_P2P_ROUTE_RESULT 145

/**
 * Local generic DHT message stop type
 */
#define GNUNET_MESSAGE_TYPE_DHT_LOCAL_ROUTE_STOP 146

/**
 * Local and P2P DHT PUT message
 * (encapsulated in DHT_ROUTE message)
 */
#define GNUNET_MESSAGE_TYPE_DHT_PUT 147

/**
 * Local and P2P DHT GET message
 * (encapsulated in DHT_ROUTE message)
 */
#define GNUNET_MESSAGE_TYPE_DHT_GET 148

/**
 * Local and P2P DHT Get result message
 */
#define GNUNET_MESSAGE_TYPE_DHT_GET_RESULT 149

/**
 * Local and P2P DHT find peer message
 */
#define GNUNET_MESSAGE_TYPE_DHT_FIND_PEER 150

/**
 * Local and P2P DHT find peer result message
 */
#define GNUNET_MESSAGE_TYPE_DHT_FIND_PEER_RESULT 151


/**
 * DHT Control message type, for telling the
 * DHT to alter its current operation somehow.
 */
#define GNUNET_MESSAGE_TYPE_DHT_CONTROL 153

/**
 * Local control message type, tells peer to start
 * issuing malicious GET requests.
 */
#define GNUNET_MESSAGE_TYPE_DHT_MALICIOUS_GET 154

/**
 * Local control message type, tells peer to start
 * issuing malicious PUT requests.
 */
#define GNUNET_MESSAGE_TYPE_DHT_MALICIOUS_PUT 155

/**
 * Local control message type, tells peer to start
 * dropping all requests.
 */
#define GNUNET_MESSAGE_TYPE_DHT_MALICIOUS_DROP  156

/*******************************************************************************
 * HOSTLIST message types
 ******************************************************************************/

/**
 * Hostlist advertisement message
 */
#define GNUNET_MESSAGE_TYPE_HOSTLIST_ADVERTISEMENT 160


/*******************************************************************************
 * STATISTICS message types
 ******************************************************************************/

/**
 * Set a statistical value.
 */
#define GNUNET_MESSAGE_TYPE_STATISTICS_SET 168

/**
 * Get a statistical value(s).
 */
#define GNUNET_MESSAGE_TYPE_STATISTICS_GET 169

/**
 * Response to a STATISTICS_GET message (with value).
 */
#define GNUNET_MESSAGE_TYPE_STATISTICS_VALUE 170

/**
 * Response to a STATISTICS_GET message (end of value stream).
 */
#define GNUNET_MESSAGE_TYPE_STATISTICS_END 171

/**
 * Watch changes to a statistical value.  Message format is the same
 * as for GET, except that the subsystem and entry name must be given.
 */
#define GNUNET_MESSAGE_TYPE_STATISTICS_WATCH 172

/**
 * Changes to a watched value.
 */
#define GNUNET_MESSAGE_TYPE_STATISTICS_WATCH_VALUE 173


/*******************************************************************************
 * VPN message types
 ******************************************************************************/

/**
 * Type of messages between the gnunet-vpn-helper and the daemon
 */
#define GNUNET_MESSAGE_TYPE_VPN_HELPER 185

/**
 * Type of messages containing an UDP packet for a service
 */
#define GNUNET_MESSAGE_TYPE_VPN_SERVICE_UDP 186

/**
 * Type of messages containing an UDP packet from a service
 */
#define GNUNET_MESSAGE_TYPE_VPN_SERVICE_UDP_BACK 187

/**
 * Type of messages containing an TCP packet for a service
 */
#define GNUNET_MESSAGE_TYPE_VPN_SERVICE_TCP 188

/**
 * Type of messages containing an TCP packet from a service
 */
#define GNUNET_MESSAGE_TYPE_VPN_SERVICE_TCP_BACK 189

/**
 * Type of messages containing an UDP packet for a remote host
 */
#define GNUNET_MESSAGE_TYPE_VPN_REMOTE_UDP 190

/**
 * Type of messages containing an UDP packet from a remote host
 */
#define GNUNET_MESSAGE_TYPE_VPN_REMOTE_UDP_BACK 191

/**
 * Type of messages containing an TCP packet for a remote host
 */
#define GNUNET_MESSAGE_TYPE_VPN_REMOTE_TCP 192

/**
 * Type of messages containing an TCP packet from a remote host
 */
#define GNUNET_MESSAGE_TYPE_VPN_REMOTE_TCP_BACK 193


/*******************************************************************************
 * VPN-DNS message types
 ******************************************************************************/

/**
 * Type of messages to query the local service-dns
 */
#define GNUNET_MESSAGE_TYPE_VPN_DNS_LOCAL_QUERY_DNS 205
/**
 * Type of messages the local service-dns responds with
 */
#define GNUNET_MESSAGE_TYPE_VPN_DNS_LOCAL_RESPONSE_DNS 206
/**
 * Type of messages to instruct the local service-dns to rehijack the dns
 */
#define GNUNET_MESSAGE_TYPE_REHIJACK 207
/**
 * Type of messages to send a DNS-query to another peer
 */
#define GNUNET_MESSAGE_TYPE_VPN_REMOTE_QUERY_DNS 208
/**
 * Type of messages to send a DNS-answer to another peer
 */
#define GNUNET_MESSAGE_TYPE_VPN_REMOTE_ANSWER_DNS 209



/*******************************************************************************
 * MESH message types
 ******************************************************************************/

/**
 * Type of message used to transport messages throug a MESH-tunnel (LEGACY)
 */
#define GNUNET_MESSAGE_TYPE_MESH 215

/**
 * Type of message used to send another peer which messages we want to receive
 * through a mesh-tunnel (LEGACY)
 */
#define GNUNET_MESSAGE_TYPE_MESH_HELLO 216


/**
 * Request the creation of a path
 */
#define GNUNET_MESSAGE_TYPE_MESH_PATH_CREATE            256

/**
 * Request the modification of an existing path
 */
#define GNUNET_MESSAGE_TYPE_MESH_PATH_CHANGE            257

/**
 * Request the addition to a new branch to a path
 */
#define GNUNET_MESSAGE_TYPE_MESH_PATH_ADD               258

/**
 * At some point, the route will spontaneously change
 */
#define GNUNET_MESSAGE_TYPE_MESH_PATH_CHANGED           259

/**
 * Transport data in the mesh (origin->end) unicast
 */
#define GNUNET_MESSAGE_TYPE_MESH_UNICAST                260

/**
 * Transport data to all peers in a tunnel
 */
#define GNUNET_MESSAGE_TYPE_MESH_MULTICAST              261

/**
 * Transport data back in the mesh (end->origin)
 */
#define GNUNET_MESSAGE_TYPE_MESH_TO_ORIGIN              262

/**
 * Send origin an ACK that the path is complete
 */
#define GNUNET_MESSAGE_TYPE_MESH_PATH_ACK               263

/**
 * We need flow control
 */
#define GNUNET_MESSAGE_TYPE_MESH_SPEED_NOTIFY           270

/**
 * Connect to the mesh service, specifying subscriptions
 */
#define GNUNET_MESSAGE_TYPE_MESH_LOCAL_CONNECT          272

/**
 * Ask the mesh service to create a new tunnel
 */
#define GNUNET_MESSAGE_TYPE_MESH_LOCAL_TUNNEL_CREATE    273

/**
 * Ask the mesh service to destroy a tunnel
 */
#define GNUNET_MESSAGE_TYPE_MESH_LOCAL_TUNNEL_DESTROY   274

/**
 * Ask the mesh service to add a peer to an existing tunnel
 */
#define GNUNET_MESSAGE_TYPE_MESH_LOCAL_PEER_ADD         275

/**
 * Ask the mesh service to remove a peer from a tunnel
 */
#define GNUNET_MESSAGE_TYPE_MESH_LOCAL_PEER_DEL         276

/**
 * Ask the mesh service to add a peer offering a service to an existing tunnel
 */
#define GNUNET_MESSAGE_TYPE_MESH_LOCAL_PEER_ADD_BY_TYPE 277

/**
 * 640kb should be enough for everybody
 */
#define GNUNET_MESSAGE_TYPE_MESH_RESERVE_END            288



/*******************************************************************************
 * CHAT message types START
 ******************************************************************************/

/**
 * Message sent from client to join a chat room.
 */
#define GNUNET_MESSAGE_TYPE_CHAT_JOIN_REQUEST 300

/**
 * Message sent to client to indicate joining of another room member.
 */
#define GNUNET_MESSAGE_TYPE_CHAT_JOIN_NOTIFICATION 301

/**
 * Message sent to client to indicate leaving of another room member.
 */
#define GNUNET_MESSAGE_TYPE_CHAT_LEAVE_NOTIFICATION 302

/**
 * Notification sent by service to client indicating that we've received a chat
 * message.
 */
#define GNUNET_MESSAGE_TYPE_CHAT_MESSAGE_NOTIFICATION 303

/**
 * Request sent by client to transmit a chat message to another room members.
 */
#define GNUNET_MESSAGE_TYPE_CHAT_TRANSMIT_REQUEST 304

/**
 * Receipt sent from a message receiver to the service to confirm delivery of
 * a chat message.
 */
#define GNUNET_MESSAGE_TYPE_CHAT_CONFIRMATION_RECEIPT 305

/**
 * Notification sent from the service to the original sender
 * to acknowledge delivery of a chat message.
 */
#define GNUNET_MESSAGE_TYPE_CHAT_CONFIRMATION_NOTIFICATION 306

/**
 * P2P message sent to indicate joining of another room member.
 */
#define GNUNET_MESSAGE_TYPE_CHAT_P2P_JOIN_NOTIFICATION 307

/**
 * P2P message sent to indicate leaving of another room member.
 */
#define GNUNET_MESSAGE_TYPE_CHAT_P2P_LEAVE_NOTIFICATION 308

/**
 * P2P message sent to a newly connected peer to request its known clients in
 * order to synchronize room members.
 */
#define GNUNET_MESSAGE_TYPE_CHAT_P2P_SYNC_REQUEST 309

/**
 * Notification sent from one peer to another to indicate that we have received
 * a chat message.
 */
#define GNUNET_MESSAGE_TYPE_CHAT_P2P_MESSAGE_NOTIFICATION 310

/**
 * P2P receipt confirming delivery of a chat message.
 */
#define GNUNET_MESSAGE_TYPE_CHAT_P2P_CONFIRMATION_RECEIPT 311


/*******************************************************************************
 * NSE (network size estimation) message types
 ******************************************************************************/

/**
 * client->service message indicating start
 */
#define GNUNET_MESSAGE_TYPE_NSE_START 321

/**
 * P2P message sent from nearest peer
 */
#define GNUNET_MESSAGE_TYPE_NSE_P2P_FLOOD 322

/**
 * service->client message indicating
 */
#define GNUNET_MESSAGE_TYPE_NSE_ESTIMATE 323


/*******************************************************************************
 * PEERINFO message types
 ******************************************************************************/

/**
 * Request update and listing of a peer.
 */
#define GNUNET_MESSAGE_TYPE_PEERINFO_GET 330

/**
 * Request update and listing of all peers.
 */
#define GNUNET_MESSAGE_TYPE_PEERINFO_GET_ALL 331

/**
 * Information about one of the peers.
 */
#define GNUNET_MESSAGE_TYPE_PEERINFO_INFO 332

/**
 * End of information about other peers.
 */
#define GNUNET_MESSAGE_TYPE_PEERINFO_INFO_END 333

/**
 * Start notifying this client about all changes to
 * the known peers until it disconnects.
 */
#define GNUNET_MESSAGE_TYPE_PEERINFO_NOTIFY 334

/*******************************************************************************
 * TODO: we need a way to register message types centrally (via some webpage).
 * For now: unofficial extensions should start at 48k, internal extensions
 * define here should leave some room (4-10 additional messages to the previous
 * extension).
 ******************************************************************************/

/**
 * Type used to match 'all' message types.
 */
#define GNUNET_MESSAGE_TYPE_ALL 65535


#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

/* ifndef GNUNET_PROTOCOLS_H */
#endif
/* end of gnunet_protocols.h */

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

/**
 * Dummy messages for testing / benchmarking.
 */
#define GNUNET_MESSAGE_TYPE_DUMMY 2

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
 * Request ARM service itself to shutdown.
 */
#define GNUNET_MESSAGE_TYPE_ARM_SHUTDOWN 10

/**
 * Response from ARM.
 */
#define GNUNET_MESSAGE_TYPE_ARM_RESULT 11

/**
 * Request to ARM to list all currently running services
 */
#define GNUNET_MESSAGE_TYPE_ARM_LIST 12

/**
 * Response from ARM for listing currently running services
 */
#define GNUNET_MESSAGE_TYPE_ARM_LIST_RESULT 13

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
 * Transport-WLAN message types
 ******************************************************************************/

/**
 * Type of data messages from the plugin to the gnunet-wlan-helper 
 */
#define GNUNET_MESSAGE_TYPE_WLAN_DATA_TO_HELPER 39

/**
 * Type of data messages from the gnunet-wlan-helper to the plugin
 */
#define GNUNET_MESSAGE_TYPE_WLAN_DATA_FROM_HELPER 40

/**
 * Control message between the gnunet-wlan-helper and the daemon (with the MAC).
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

/**
 * Receive information about transiting GETs
 */
#define GNUNET_MESSAGE_TYPE_DHT_MONITOR_GET             149

/**
 * Receive information about transiting GET responses
 */
#define GNUNET_MESSAGE_TYPE_DHT_MONITOR_GET_RESP        150

/**
 * Receive information about transiting PUTs
 */
#define GNUNET_MESSAGE_TYPE_DHT_MONITOR_PUT             151

/**
 * Receive information about transiting PUT responses (TODO)
 */
#define GNUNET_MESSAGE_TYPE_DHT_MONITOR_PUT_RESP        152

/**
 * Request information about transiting messages
 */
#define GNUNET_MESSAGE_TYPE_DHT_MONITOR_START             153

/**
 * Stop information about transiting messages
 */
#define GNUNET_MESSAGE_TYPE_DHT_MONITOR_STOP             154

/**
 * Acknowledge receiving PUT request
 */
#define GNUNET_MESSAGE_TYPE_DHT_CLIENT_PUT_OK             155


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
 * Type of messages containing an ICMP packet for a service.
 */
#define GNUNET_MESSAGE_TYPE_VPN_ICMP_TO_SERVICE 190

/**
 * Type of messages containing an ICMP packet for the Internet.
 */
#define GNUNET_MESSAGE_TYPE_VPN_ICMP_TO_INTERNET 191

/**
 * Type of messages containing an ICMP packet for the VPN
 */
#define GNUNET_MESSAGE_TYPE_VPN_ICMP_TO_VPN 192

/**
 * Type of messages containing an DNS request for a DNS exit service.
 */
#define GNUNET_MESSAGE_TYPE_VPN_DNS_TO_INTERNET 193

/**
 * Type of messages containing an DNS reply from a DNS exit service.
 */
#define GNUNET_MESSAGE_TYPE_VPN_DNS_FROM_INTERNET 194

/**
 * Type of messages containing an TCP packet for a service.
 */
#define GNUNET_MESSAGE_TYPE_VPN_TCP_TO_SERVICE_START 195

/**
 * Type of messages containing an TCP packet for the Internet.
 */
#define GNUNET_MESSAGE_TYPE_VPN_TCP_TO_INTERNET_START 196

/**
 * Type of messages containing an TCP packet of an established connection.
 */
#define GNUNET_MESSAGE_TYPE_VPN_TCP_DATA_TO_EXIT 197

/**
 * Type of messages containing an TCP packet of an established connection.
 */
#define GNUNET_MESSAGE_TYPE_VPN_TCP_DATA_TO_VPN 198

/**
 * Type of messages containing an UDP packet for a service.
 */
#define GNUNET_MESSAGE_TYPE_VPN_UDP_TO_SERVICE 199

/**
 * Type of messages containing an UDP packet for the Internet.
 */
#define GNUNET_MESSAGE_TYPE_VPN_UDP_TO_INTERNET 200

/**
 * Type of messages containing an UDP packet from a remote host
 */
#define GNUNET_MESSAGE_TYPE_VPN_UDP_REPLY 201


/**
 * Client asks VPN service to setup an IP to redirect traffic
 * via an exit node to some global IP address.
 */
#define GNUNET_MESSAGE_TYPE_VPN_CLIENT_REDIRECT_TO_IP 202

/**
 * Client asks VPN service to setup an IP to redirect traffic
 * to some peer offering a service.
 */
#define GNUNET_MESSAGE_TYPE_VPN_CLIENT_REDIRECT_TO_SERVICE 203

/**
 * VPN service responds to client with an IP to use for the
 * requested redirection.
 */
#define GNUNET_MESSAGE_TYPE_VPN_CLIENT_USE_IP 204


/*******************************************************************************
 * VPN-DNS message types
 ******************************************************************************/


/**
 * Initial message from client to DNS service for registration.
 */
#define GNUNET_MESSAGE_TYPE_DNS_CLIENT_INIT 211

/**
 * Type of messages between the gnunet-helper-dns and the service
 */
#define GNUNET_MESSAGE_TYPE_DNS_CLIENT_REQUEST 212

/**
 * Type of messages between the gnunet-helper-dns and the service
 */
#define GNUNET_MESSAGE_TYPE_DNS_CLIENT_RESPONSE 213

/**
 * Type of messages between the gnunet-helper-dns and the service
 */
#define GNUNET_MESSAGE_TYPE_DNS_HELPER 214


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
 * Notify that a connection of a path is no longer valid
 */
#define GNUNET_MESSAGE_TYPE_MESH_PATH_BROKEN            258

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
 * Avoid path timeouts
 */
#define GNUNET_MESSAGE_TYPE_MESH_PATH_KEEPALIVE         264

/**
 * Request the destuction of a path
 */
#define GNUNET_MESSAGE_TYPE_MESH_PATH_DESTROY           265

/**
 * Request the destruction of a whole tunnel
 */
#define GNUNET_MESSAGE_TYPE_MESH_TUNNEL_DESTROY         266

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
 * ATS message types
 ******************************************************************************/

/**
 * Type of the 'struct ClientStartMessage' sent by clients to ATS to
 * identify the type of the client.
 */
#define GNUNET_MESSAGE_TYPE_ATS_START 340

/**
 * Type of the 'struct RequestAddressMessage' sent by clients to ATS
 * to request an address to help connect.
 */
#define GNUNET_MESSAGE_TYPE_ATS_REQUEST_ADDRESS 341

/**
 * Type of the 'struct RequestAddressMessage' sent by clients to ATS
 * to request an address to help connect.
 */
#define GNUNET_MESSAGE_TYPE_ATS_REQUEST_ADDRESS_CANCEL 342

/**
 * Type of the 'struct AddressUpdateMessage' sent by clients to ATS
 * to inform ATS about performance changes.
 */
#define GNUNET_MESSAGE_TYPE_ATS_ADDRESS_UPDATE 343

/**
 * Type of the 'struct AddressDestroyedMessage' sent by clients to ATS
 * to inform ATS about an address being unavailable.
 */
#define GNUNET_MESSAGE_TYPE_ATS_ADDRESS_DESTROYED 344

/**
 * Type of the 'struct AddressSuggestionMessage' sent by ATS to clients
 * to suggest switching to a different address.
 */
#define GNUNET_MESSAGE_TYPE_ATS_ADDRESS_SUGGESTION 345

/**
 * Type of the 'struct PeerInformationMessage' sent by ATS to clients
 * to inform about QoS for a particular connection.
 */
#define GNUNET_MESSAGE_TYPE_ATS_PEER_INFORMATION 346

/**
 * Type of the 'struct ReservationRequestMessage' sent by clients to ATS
 * to ask for inbound bandwidth reservations.
 */
#define GNUNET_MESSAGE_TYPE_ATS_RESERVATION_REQUEST 347

/**
 * Type of the 'struct ReservationResultMessage' sent by ATS to clients
 * in response to a reservation request.
 */
#define GNUNET_MESSAGE_TYPE_ATS_RESERVATION_RESULT 348

/**
 * Type of the 'struct ChangePreferenceMessage' sent by clients to ATS
 * to ask for allocation preference changes.
 */
#define GNUNET_MESSAGE_TYPE_ATS_PREFERENCE_CHANGE 349

/**
 * Type of the 'struct SessionReleaseMessage' sent by ATS to client
 * to confirm that a session ID was destroyed.
 */
#define GNUNET_MESSAGE_TYPE_ATS_SESSION_RELEASE 350

/**
 * Type of the 'struct AddressUseMessage' sent by ATS to client
 * to confirm that an address is used or not used anymore
 */
#define GNUNET_MESSAGE_TYPE_ATS_ADDRESS_IN_USE 351

/**
 * Type of the 'struct AddressUseMessage' sent by ATS to client
 * to confirm that an address is used or not used anymore
 */
#define GNUNET_MESSAGE_TYPE_ATS_RESET_BACKOFF 352


/*******************************************************************************
 * TRANSPORT message types
 ******************************************************************************/

/**
 * Message from the core saying that the transport
 * server should start giving it messages.  This
 * should automatically trigger the transmission of
 * a HELLO message.
 */
#define GNUNET_MESSAGE_TYPE_TRANSPORT_START 360

/**
 * Message from TRANSPORT notifying about a
 * client that connected to us.
 */
#define GNUNET_MESSAGE_TYPE_TRANSPORT_CONNECT 361

/**
 * Message from TRANSPORT notifying about a
 * client that disconnected from us.
 */
#define GNUNET_MESSAGE_TYPE_TRANSPORT_DISCONNECT 362

/**
 * Request to TRANSPORT to transmit a message.
 */
#define GNUNET_MESSAGE_TYPE_TRANSPORT_SEND 363

/**
 * Confirmation from TRANSPORT that message for transmission has been
 * queued (and that the next message to this peer can now be passed to
 * the service).  Note that this confirmation does NOT imply that the
 * message was fully transmitted.
 */
#define GNUNET_MESSAGE_TYPE_TRANSPORT_SEND_OK 364

/**
 * Message from TRANSPORT notifying about a
 * message that was received.
 */
#define GNUNET_MESSAGE_TYPE_TRANSPORT_RECV 365

/**
 * Message telling transport to limit its receive rate.
 */
#define GNUNET_MESSAGE_TYPE_TRANSPORT_SET_QUOTA 366

/**
 * Request to look addresses of peers in server.
 */
#define GNUNET_MESSAGE_TYPE_TRANSPORT_ADDRESS_TO_STRING 367

/**
 * Response to the address lookup request.
 */
#define GNUNET_MESSAGE_TYPE_TRANSPORT_ADDRESS_TO_STRING_REPLY 368

/**
 * Register a client that wants to do blacklisting.
 */
#define GNUNET_MESSAGE_TYPE_TRANSPORT_BLACKLIST_INIT 369

/**
 * Query to a blacklisting client (is this peer blacklisted)?
 */
#define GNUNET_MESSAGE_TYPE_TRANSPORT_BLACKLIST_QUERY 370

/**
 * Reply from blacklisting client (answer to blacklist query).
 */
#define GNUNET_MESSAGE_TYPE_TRANSPORT_BLACKLIST_REPLY 371

/**
 * Transport PING message
 */
#define GNUNET_MESSAGE_TYPE_TRANSPORT_PING 372

/**
 * Transport PONG message
 */
#define GNUNET_MESSAGE_TYPE_TRANSPORT_PONG 373

/**
 * Message for transport service from a client asking that a
 * connection be initiated with another peer.
 */
#define GNUNET_MESSAGE_TYPE_TRANSPORT_REQUEST_CONNECT 374

/**
 * Transport CONNECT message exchanged between transport services to
 * indicate that a session should be marked as 'connected'.
 */
#define GNUNET_MESSAGE_TYPE_TRANSPORT_SESSION_CONNECT 375

/**
 * Transport CONNECT_ACK message exchanged between transport services to
 * indicate that a CONNECT message was accepted
 */
#define GNUNET_MESSAGE_TYPE_TRANSPORT_SESSION_CONNECT_ACK 376

/**
 * Transport CONNECT_ACK message exchanged between transport services to
 * indicate that a CONNECT message was accepted
 */
#define GNUNET_MESSAGE_TYPE_TRANSPORT_SESSION_ACK 377

/**
 * Transport DISCONNECT message exchanged between transport services to
 * indicate that a connection should be dropped.
 */
#define GNUNET_MESSAGE_TYPE_TRANSPORT_SESSION_DISCONNECT 378

/**
 * Request to monitor addresses used by a peer or all peers.
 */
#define GNUNET_MESSAGE_TYPE_TRANSPORT_ADDRESS_ITERATE 380

/**
 * Message send by a peer to notify the other to keep the session alive
 * and measure latency in a regular interval
 */
#define GNUNET_MESSAGE_TYPE_TRANSPORT_SESSION_KEEPALIVE 381

/**
 * Response to a GNUNET_MESSAGE_TYPE_TRANSPORT_SESSION_KEEPALIVE message to
 * measure latency in a regular interval
 */
#define GNUNET_MESSAGE_TYPE_TRANSPORT_SESSION_KEEPALIVE_RESPONSE 382


/**
 * Request to iterate over all known addresses.
 */
#define GNUNET_MESSAGE_TYPE_TRANSPORT_ADDRESS_ITERATE_RESPONSE 383

/**
 * Message send by a peer to notify the other to keep the session alive.
 */
#define GNUNET_MESSAGE_TYPE_TRANSPORT_BROADCAST_BEACON 384

/*******************************************************************************
 * STREAM LIRBRARY MESSAGES
 ******************************************************************************/

/**
 * Message containing data exchanged between stream end-points over mesh.
 */
#define GNUNET_MESSAGE_TYPE_STREAM_DATA 400

/**
 * ACK message
 */
#define GNUNET_MESSAGE_TYPE_STREAM_ACK 401

/**
 * Handshake hello message
 */
#define GNUNET_MESSAGE_TYPE_STREAM_HELLO 402

/**
 * Handshake hello acknowledgement message
 */
#define GNUNET_MESSAGE_TYPE_STREAM_HELLO_ACK 403

/**
 * Reset message
 */
#define GNUNET_MESSAGE_TYPE_STREAM_RESET 404

/**
 * Transmit close message (data transmission no longer possible after this
 * message) 
 */
#define GNUNET_MESSAGE_TYPE_STREAM_TRANSMIT_CLOSE 405

/**
 * Transmit close acknowledgement message
 */
#define GNUNET_MESSAGE_TYPE_STREAM_TRANSMIT_CLOSE_ACK 406

/**
 * Receive close message (data is no loger read by the receiver after this
 * message) 
 */
#define GNUNET_MESSAGE_TYPE_STREAM_RECEIVE_CLOSE 407

/**
 * Receive close acknowledgement message
 */
#define GNUNET_MESSAGE_TYPE_STREAM_RECEIVE_CLOSE_ACK 408

/**
 * Stream close message (data is no longer sent or read after this message)
 */
#define GNUNET_MESSAGE_TYPE_STREAM_CLOSE 409

/**
 * Close acknowledgement message
 */
#define GNUNET_MESSAGE_TYPE_STREAM_CLOSE_ACK 410

/*******************************************************************************
 * FS-PUBLISH-HELPER IPC Messages
 ******************************************************************************/

/**
 * Progress information from the helper: found a file
 */
#define GNUNET_MESSAGE_TYPE_FS_PUBLISH_HELPER_PROGRESS_FILE 420

/**
 * Progress information from the helper: found a directory
 */
#define GNUNET_MESSAGE_TYPE_FS_PUBLISH_HELPER_PROGRESS_DIRECTORY 421

/**
 * Error signal from the helper.
 */
#define GNUNET_MESSAGE_TYPE_FS_PUBLISH_HELPER_ERROR 422

/**
 * Signal that helper skipped a file.
 */
#define GNUNET_MESSAGE_TYPE_FS_PUBLISH_HELPER_SKIP_FILE 423

/**
 * Signal that helper is done scanning the directory tree.
 */
#define GNUNET_MESSAGE_TYPE_FS_PUBLISH_HELPER_COUNTING_DONE 424

/**
 * Extracted meta data from the helper.
 */
#define GNUNET_MESSAGE_TYPE_FS_PUBLISH_HELPER_META_DATA 425

/**
 * Signal that helper is done.
 */
#define GNUNET_MESSAGE_TYPE_FS_PUBLISH_HELPER_FINISHED 426

/*******************************************************************************
 * NAMESTORE message types
 ******************************************************************************/

/**
 * Request update and listing of a peer.
 */
#define GNUNET_MESSAGE_TYPE_NAMESTORE_START 430

/*******************************************************************************
 * LOCKMANAGER message types
 ******************************************************************************/

/**
 * Message to acquire Lock
 */
#define GNUNET_MESSAGE_TYPE_LOCKMANAGER_ACQUIRE 440

/**
 * Message to release lock
 */
#define GNUNET_MESSAGE_TYPE_LOCKMANAGER_RELEASE 441

/**
 * SUCESS reply from lockmanager
 */
#define GNUNET_MESSAGE_TYPE_LOCKMANAGER_SUCCESS 442

/**
 *  Next available: 450
 */

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

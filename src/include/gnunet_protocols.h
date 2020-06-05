/*
     This file is part of GNUnet.
     Copyright (C) 2001--2018 GNUnet e.V.

     GNUnet is free software: you can redistribute it and/or modify it
     under the terms of the GNU Affero General Public License as published
     by the Free Software Foundation, either version 3 of the License,
     or (at your option) any later version.

     GNUnet is distributed in the hope that it will be useful, but
     WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
     Affero General Public License for more details.

     You should have received a copy of the GNU Affero General Public License
     along with this program.  If not, see <http://www.gnu.org/licenses/>.

     SPDX-License-Identifier: AGPL3.0-or-later
 */

/**
 * @author Christian Grothoff
 *
 * @file
 * Constants for network protocols
 *
 * @defgroup protocols  Network protocol definitions
 * Types of messages used in GNUnet.
 *
 * @see [Documentation](https://gnunet.org/ipc)
 *
 * @{
 */

/*******************************************************************************
 * TODO: we need a way to register message types centrally (via some webpage).
 * For now: unofficial extensions should start at 48k, internal extensions
 * defined here should leave some room (4-10 additional messages to the previous
 * extension).
 ******************************************************************************/

#ifndef GNUNET_PROTOCOLS_H
#define GNUNET_PROTOCOLS_H

#ifdef __cplusplus
extern "C" {
#if 0 /* keep Emacsens' auto-indent happy */
}
#endif
#endif

/*******************************************************************************
* Deprecated
* *****************************************************************************/

/**
 * Test if service is online.
 *
 * @deprecated!
 */
#define GNUNET_MESSAGE_TYPE_TEST 0

/*******************************************************************************
* AGPL source code download
* *****************************************************************************/

/**
 * Message to request source code link.
 */
#define GNUNET_MESSAGE_TYPE_REQUEST_AGPL 1

/**
 * Source code link.
 */
#define GNUNET_MESSAGE_TYPE_RESPONSE_AGPL 2

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
 * UTIL message types
 ******************************************************************************/

/**
 * Dummy messages for testing / benchmarking.
 */
#define GNUNET_MESSAGE_TYPE_DUMMY 6

/**
 * Another dummy messages for testing / benchmarking.
 */
#define GNUNET_MESSAGE_TYPE_DUMMY2 7


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
 * Response from ARM.
 */
#define GNUNET_MESSAGE_TYPE_ARM_RESULT 10

/**
 * Status update from ARM.
 */
#define GNUNET_MESSAGE_TYPE_ARM_STATUS 11

/**
 * Request to ARM to list all currently running services
 */
#define GNUNET_MESSAGE_TYPE_ARM_LIST 12

/**
 * Response from ARM for listing currently running services
 */
#define GNUNET_MESSAGE_TYPE_ARM_LIST_RESULT 13

/**
 * Request to ARM to notify client of service status changes
 */
#define GNUNET_MESSAGE_TYPE_ARM_MONITOR 14

/**
 * Test if ARM service is online.
 */
#define GNUNET_MESSAGE_TYPE_ARM_TEST 15

/*******************************************************************************
 * HELLO message types
 ******************************************************************************/

/**
 * Previously used for HELLO messages used for communicating peer addresses.
 * Managed by libgnunethello.
 */
#define GNUNET_MESSAGE_TYPE_HELLO_LEGACY 16

/**
 * HELLO message with friend only flag used for communicating peer addresses.
 * Managed by libgnunethello.
 */

#define GNUNET_MESSAGE_TYPE_HELLO 17

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
#define GNUNET_MESSAGE_TYPE_DV_RECV 44

/**
 * DV Plugin to DV service message, indicating a message
 * should be sent out.
 */
#define GNUNET_MESSAGE_TYPE_DV_SEND 45

/**
 * DV service to DV api message, containing a confirmation
 * or failure of a DV_SEND message.
 */
#define GNUNET_MESSAGE_TYPE_DV_SEND_ACK 46

/**
 * P2P DV message encapsulating some real message
 */
#define GNUNET_MESSAGE_TYPE_DV_ROUTE 47

/**
 * DV Plugin to DV service message, indicating
 * startup.
 */
#define GNUNET_MESSAGE_TYPE_DV_START 48

/**
 * P2P DV message telling plugin that a peer connected
 */
#define GNUNET_MESSAGE_TYPE_DV_CONNECT 49

/**
 * P2P DV message telling plugin that a peer disconnected
 */
#define GNUNET_MESSAGE_TYPE_DV_DISCONNECT 50

/**
 * P2P DV message telling plugin that a message transmission failed (negative
 * ACK)
 */
#define GNUNET_MESSAGE_TYPE_DV_SEND_NACK 51

/**
 * P2P DV message telling plugin that our distance to a peer changed
 */
#define GNUNET_MESSAGE_TYPE_DV_DISTANCE_CHANGED 52

/**
 * DV message box for boxing multiple messages.
 */
#define GNUNET_MESSAGE_TYPE_DV_BOX 53


/**
 * Experimental message type.
 */
#define GNUNET_MESSAGE_TYPE_TRANSPORT_XU_MESSAGE 55


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
 * Request for connection monitoring from CORE service.
 */
#define GNUNET_MESSAGE_TYPE_CORE_MONITOR_PEERS 78

/**
 * Reply for monitor by CORE service.
 */
#define GNUNET_MESSAGE_TYPE_CORE_MONITOR_NOTIFY 79

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

/**
 * Session key exchange between peers.
 */
#define GNUNET_MESSAGE_TYPE_CORE_EPHEMERAL_KEY 88

/**
 * Other peer confirms having received the type map
 */
#define GNUNET_MESSAGE_TYPE_CORE_CONFIRM_TYPE_MAP 89


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

/**
 * Message sent by datastore client to get data by key.
 */
#define GNUNET_MESSAGE_TYPE_DATASTORE_GET_KEY 104


/*******************************************************************************
 * FS message types
 ******************************************************************************/

/**
 * Message sent by fs client to request LOC signature.
 */
#define GNUNET_MESSAGE_TYPE_FS_REQUEST_LOC_SIGN 126

/**
 * Reply sent by fs service with LOC signature.
 */
#define GNUNET_MESSAGE_TYPE_FS_REQUEST_LOC_SIGNATURE 127

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
 * used between the service and clients (in response to
 * #GNUNET_MESSAGE_TYPE_FS_START_SEARCH).
 */
#define GNUNET_MESSAGE_TYPE_FS_PUT 138

/**
 * Peer asks us to stop migrating content towards it for a while.
 */
#define GNUNET_MESSAGE_TYPE_FS_MIGRATION_STOP 139

/**
 * P2P request for content (one FS to another via a cadet).
 */
#define GNUNET_MESSAGE_TYPE_FS_CADET_QUERY 140

/**
 * P2P answer for content (one FS to another via a cadet).
 */
#define GNUNET_MESSAGE_TYPE_FS_CADET_REPLY 141


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
#define GNUNET_MESSAGE_TYPE_DHT_MONITOR_GET 149

/**
 * Receive information about transiting GET responses
 */
#define GNUNET_MESSAGE_TYPE_DHT_MONITOR_GET_RESP 150

/**
 * Receive information about transiting PUTs
 */
#define GNUNET_MESSAGE_TYPE_DHT_MONITOR_PUT 151

/**
 * Receive information about transiting PUT responses (TODO)
 */
#define GNUNET_MESSAGE_TYPE_DHT_MONITOR_PUT_RESP 152

/**
 * Request information about transiting messages
 */
#define GNUNET_MESSAGE_TYPE_DHT_MONITOR_START 153

/**
 * Stop information about transiting messages
 */
#define GNUNET_MESSAGE_TYPE_DHT_MONITOR_STOP 154

/**
 * Certain results are already known to the client, filter those.
 */
#define GNUNET_MESSAGE_TYPE_DHT_CLIENT_GET_RESULTS_KNOWN 156

/**
 * Further X-VINE DHT messages continued from 880
 */

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

/**
 * Client is done sending service requests and will now disconnect.
 */
#define GNUNET_MESSAGE_TYPE_STATISTICS_DISCONNECT 174

/**
 * Service confirms disconnect and that it is done processing
 * all requests from the client.
 */
#define GNUNET_MESSAGE_TYPE_STATISTICS_DISCONNECT_CONFIRM 175

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
 * Type of the 'struct AddressUpdateMessage' sent by client to ATS
 * to add a new address
 */
#define GNUNET_MESSAGE_TYPE_ATS_ADDRESS_ADD 353

/**
 * Type of the 'struct AddressListRequestMessage' sent by client to ATS
 * to request information about addresses
 */
#define GNUNET_MESSAGE_TYPE_ATS_ADDRESSLIST_REQUEST 354

/**
 * Type of the 'struct AddressListResponseMessage' sent by ATS to client
 * with information about addresses
 */
#define GNUNET_MESSAGE_TYPE_ATS_ADDRESSLIST_RESPONSE 355

/**
 * Type of the 'struct ChangePreferenceMessage' sent by clients to ATS
 * to ask for allocation preference changes.
 */
#define GNUNET_MESSAGE_TYPE_ATS_PREFERENCE_FEEDBACK 356


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
 * (FIXME: was the above comment ever accurate?)
 *
 * Note: dead in TNG, replaced by RECV_OK!
 */
#define GNUNET_MESSAGE_TYPE_TRANSPORT_SET_QUOTA 366

/**
 * Message telling transport to limit its receive rate.
 */
#define GNUNET_MESSAGE_TYPE_TRANSPORT_RECV_OK 366

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
 * Transport SYN message exchanged between transport services to
 * indicate that a session should be marked as 'connected'.
 */
#define GNUNET_MESSAGE_TYPE_TRANSPORT_SESSION_SYN 375

/**
 * Transport SYN_ACK message exchanged between transport services to
 * indicate that a SYN message was accepted
 */
#define GNUNET_MESSAGE_TYPE_TRANSPORT_SESSION_SYN_ACK 376

/**
 * Transport ACK message exchanged between transport services to
 * indicate that a SYN_ACK message was accepted
 */
#define GNUNET_MESSAGE_TYPE_TRANSPORT_SESSION_ACK 377

/**
 * Transport DISCONNECT message exchanged between transport services to
 * indicate that a connection should be dropped.
 */
#define GNUNET_MESSAGE_TYPE_TRANSPORT_SESSION_DISCONNECT 378

/**
 * Message exchanged between transport services to
 * indicate that the sender should limit its transmission
 * rate to the indicated quota.
 */
#define GNUNET_MESSAGE_TYPE_TRANSPORT_SESSION_QUOTA 379

/**
 * Request to monitor addresses used by a peer or all peers.
 */
#define GNUNET_MESSAGE_TYPE_TRANSPORT_MONITOR_PEER_REQUEST 380

/**
 * Message send by a peer to notify the other to keep the session alive
 * and measure latency in a regular interval
 */
#define GNUNET_MESSAGE_TYPE_TRANSPORT_SESSION_KEEPALIVE 381

/**
 * Response to a #GNUNET_MESSAGE_TYPE_TRANSPORT_SESSION_KEEPALIVE message to
 * measure latency in a regular interval
 */
#define GNUNET_MESSAGE_TYPE_TRANSPORT_SESSION_KEEPALIVE_RESPONSE 382

/**
 * Response to #GNUNET_MESSAGE_TYPE_TRANSPORT_MONITOR_PEER_REQUEST
 * request to iterate over all known addresses.
 */
#define GNUNET_MESSAGE_TYPE_TRANSPORT_MONITOR_PEER_RESPONSE 383

/**
 * Message send by a peer to notify the other to keep the session alive.
 */
#define GNUNET_MESSAGE_TYPE_TRANSPORT_BROADCAST_BEACON 384

/**
 * Message containing traffic metrics for transport service
 */
#define GNUNET_MESSAGE_TYPE_TRANSPORT_TRAFFIC_METRIC 385

/**
 * Request to start monitoring the connection state of plugins.
 */
#define GNUNET_MESSAGE_TYPE_TRANSPORT_MONITOR_PLUGIN_START 388

/**
 * Monitoring event about the connection state of plugins,
 * generated in response to a subscription initiated via
 * #GNUNET_MESSAGE_TYPE_TRANSPORT_MONITOR_PLUGIN_START
 */
#define GNUNET_MESSAGE_TYPE_TRANSPORT_MONITOR_PLUGIN_EVENT 389

/**
 * Monitoring event notifying client that the initial iteration
 * is now completed and we are in sync with the state of the subsystem.
 */
#define GNUNET_MESSAGE_TYPE_TRANSPORT_MONITOR_PLUGIN_SYNC 390

/**
 * Response to #GNUNET_MESSAGE_TYPE_TRANSPORT_MONITOR_PEER_RESPONSE_END
 * terminating list of replies.
 */
#define GNUNET_MESSAGE_TYPE_TRANSPORT_MONITOR_PEER_RESPONSE_END 391


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
 * NAMECACHE message types
 ******************************************************************************/

/**
 * Client to service: lookup block
 */
#define GNUNET_MESSAGE_TYPE_NAMECACHE_LOOKUP_BLOCK 431

/**
 * Service to client: result of block lookup
 */
#define GNUNET_MESSAGE_TYPE_NAMECACHE_LOOKUP_BLOCK_RESPONSE 432

/**
 * Client to service: cache a block
 */
#define GNUNET_MESSAGE_TYPE_NAMECACHE_BLOCK_CACHE 433

/**
 * Service to client: result of block cache request
 */
#define GNUNET_MESSAGE_TYPE_NAMECACHE_BLOCK_CACHE_RESPONSE 434

/*******************************************************************************
 * NAMESTORE message types
 ******************************************************************************/

/**
 * Client to service: store records (as authority)
 */
#define GNUNET_MESSAGE_TYPE_NAMESTORE_RECORD_STORE 435

/**
 * Service to client: result of store operation.
 */
#define GNUNET_MESSAGE_TYPE_NAMESTORE_RECORD_STORE_RESPONSE 436

/**
 * Client to service: lookup label
 */
#define GNUNET_MESSAGE_TYPE_NAMESTORE_RECORD_LOOKUP 437

/**
 * Service to client: lookup label
 */
#define GNUNET_MESSAGE_TYPE_NAMESTORE_RECORD_LOOKUP_RESPONSE 438

/**
 * Client to service: "reverse" lookup for zone name based on zone key
 */
#define GNUNET_MESSAGE_TYPE_NAMESTORE_ZONE_TO_NAME 439

/**
 * Service to client: result of zone-to-name lookup.
 */
#define GNUNET_MESSAGE_TYPE_NAMESTORE_ZONE_TO_NAME_RESPONSE 440

/**
 * Client to service: start monitoring (yields sequence of
 * "ZONE_ITERATION_RESPONSES" --- forever).
 */
#define GNUNET_MESSAGE_TYPE_NAMESTORE_MONITOR_START 441

/**
 * Service to client: you're now in sync.
 */
#define GNUNET_MESSAGE_TYPE_NAMESTORE_MONITOR_SYNC 442

/**
 * Service to client: here is a (plaintext) record you requested.
 */
#define GNUNET_MESSAGE_TYPE_NAMESTORE_RECORD_RESULT 443

/**
 * Client to service: I am now ready for the next (set of) monitor
 * events. Monitoring equivlaent of
 * #GNUNET_MESSAGE_TYPE_NAMESTORE_ZONE_ITERATION_NEXT.
 */
#define GNUNET_MESSAGE_TYPE_NAMESTORE_MONITOR_NEXT 444

/**
 * Client to service: please start iteration; receives
 * "GNUNET_MESSAGE_TYPE_NAMESTORE_LOOKUP_NAME_RESPONSE" messages in return.
 */
#define GNUNET_MESSAGE_TYPE_NAMESTORE_ZONE_ITERATION_START 445

/**
 * Client to service: next record(s) in iteration please.
 */
#define GNUNET_MESSAGE_TYPE_NAMESTORE_ZONE_ITERATION_NEXT 447

/**
 * Client to service: stop iterating.
 */
#define GNUNET_MESSAGE_TYPE_NAMESTORE_ZONE_ITERATION_STOP 448

/**
 * Service to client: end of list of results
 */
#define GNUNET_MESSAGE_TYPE_NAMESTORE_RECORD_RESULT_END 449


/*******************************************************************************
 * LOCKMANAGER message types
 ******************************************************************************/

/**
 * Message to acquire Lock
 */
#define GNUNET_MESSAGE_TYPE_LOCKMANAGER_ACQUIRE 450

/**
 * Message to release lock
 */
#define GNUNET_MESSAGE_TYPE_LOCKMANAGER_RELEASE 451

/**
 * SUCESS reply from lockmanager
 */
#define GNUNET_MESSAGE_TYPE_LOCKMANAGER_SUCCESS 452

/*******************************************************************************
 * TESTBED message types
 ******************************************************************************/

/**
 * Initial message from a client to a testing control service
 */
#define GNUNET_MESSAGE_TYPE_TESTBED_INIT 460

/**
 * Message to add host
 */
#define GNUNET_MESSAGE_TYPE_TESTBED_ADD_HOST 461

/**
 * Message to signal that a add host succeeded
 */
#define GNUNET_MESSAGE_TYPE_TESTBED_ADD_HOST_SUCCESS 462

/**
 * Message to link delegated controller to slave controller
 */
#define GNUNET_MESSAGE_TYPE_TESTBED_LINK_CONTROLLERS 463

/**
 * Message to create a peer at a host
 */
#define GNUNET_MESSAGE_TYPE_TESTBED_CREATE_PEER 464

/**
 * Message to reconfigure a peer
 */
#define GNUNET_MESSAGE_TYPE_TESTBED_RECONFIGURE_PEER 465

/**
 * Message to start a peer at a host
 */
#define GNUNET_MESSAGE_TYPE_TESTBED_START_PEER 466

/**
 * Message to stop a peer at a host
 */
#define GNUNET_MESSAGE_TYPE_TESTBED_STOP_PEER 467

/**
 * Message to destroy a peer
 */
#define GNUNET_MESSAGE_TYPE_TESTBED_DESTROY_PEER 468

/**
 * Configure underlay link message
 */
#define GNUNET_MESSAGE_TYPE_TESTBED_CONFIGURE_UNDERLAY_LINK 469

/**
 * Message to connect peers in a overlay
 */
#define GNUNET_MESSAGE_TYPE_TESTBED_OVERLAY_CONNECT 470

/**
 * Message for peer events
 */
#define GNUNET_MESSAGE_TYPE_TESTBED_PEER_EVENT 471

/**
 * Message for peer connect events
 */
#define GNUNET_MESSAGE_TYPE_TESTBED_PEER_CONNECT_EVENT 472

/**
 * Message for operation events
 */
#define GNUNET_MESSAGE_TYPE_TESTBED_OPERATION_FAIL_EVENT 473

/**
 * Message to signal successful peer creation
 */
#define GNUNET_MESSAGE_TYPE_TESTBED_CREATE_PEER_SUCCESS 474

/**
 * Message to signal a generic operation has been successful
 */
#define GNUNET_MESSAGE_TYPE_TESTBED_GENERIC_OPERATION_SUCCESS 475

/**
 * Message to get a peer's information
 */
#define GNUNET_MESSAGE_TYPE_TESTBED_GET_PEER_INFORMATION 476

/**
 * Message containing the peer's information
 */
#define GNUNET_MESSAGE_TYPE_TESTBED_PEER_INFORMATION 477

/**
 * Message to request a controller to make one of its peer to connect to another
 * peer using the contained HELLO
 */
#define GNUNET_MESSAGE_TYPE_TESTBED_REMOTE_OVERLAY_CONNECT 478

/**
 * Message to request configuration of a slave controller
 */
#define GNUNET_MESSAGE_TYPE_TESTBED_GET_SLAVE_CONFIGURATION 479

/**
 * Message which contains the configuration of slave controller
 */
#define GNUNET_MESSAGE_TYPE_TESTBED_SLAVE_CONFIGURATION 480

/**
 * Message to signal the result of #GNUNET_MESSAGE_TYPE_TESTBED_LINK_CONTROLLERS
 * request
 */
#define GNUNET_MESSAGE_TYPE_TESTBED_LINK_CONTROLLERS_RESULT 481

/**
 * A controller receiving this message floods it to its directly-connected
 * sub-controllers and then stops and destroys all peers
 */
#define GNUNET_MESSAGE_TYPE_TESTBED_SHUTDOWN_PEERS 482

/**
 * Message to start/stop a service of a peer
 */
#define GNUNET_MESSAGE_TYPE_TESTBED_MANAGE_PEER_SERVICE 483

/**
 * Message to initialise a barrier.  Messages of these type are flooded to all
 * sub-controllers
 */
#define GNUNET_MESSAGE_TYPE_TESTBED_BARRIER_INIT 484

/**
 * Message to cancel a barrier.  This message is flooded to all sub-controllers
 */
#define GNUNET_MESSAGE_TYPE_TESTBED_BARRIER_CANCEL 485

/**
 * Message for signalling status of a barrier
 */
#define GNUNET_MESSAGE_TYPE_TESTBED_BARRIER_STATUS 486

/**
 * Message sent by a peer when it has reached a barrier and is waiting for it to
 * be crossed
 */
#define GNUNET_MESSAGE_TYPE_TESTBED_BARRIER_WAIT 487

/**
 * Not really a message, but for careful checks on the testbed messages; Should
 * always be the maximum and never be used to send messages with this type
 */
#define GNUNET_MESSAGE_TYPE_TESTBED_MAX 488

/**
 * The initialization message towards gnunet-testbed-helper
 */
#define GNUNET_MESSAGE_TYPE_TESTBED_HELPER_INIT 495

/**
 * The reply message from gnunet-testbed-helper
 */
#define GNUNET_MESSAGE_TYPE_TESTBED_HELPER_REPLY 496


/******************************************************************************
 * GNS.
 *****************************************************************************/

/**
 * Client would like to resolve a name.
 */
#define GNUNET_MESSAGE_TYPE_GNS_LOOKUP 500

/**
 * Service response to name resolution request from client.
 */
#define GNUNET_MESSAGE_TYPE_GNS_LOOKUP_RESULT 501

/**
 * Reverse lookup
 */
#define GNUNET_MESSAGE_TYPE_GNS_REVERSE_LOOKUP 503

/**
 * Response to reverse lookup
 */
#define GNUNET_MESSAGE_TYPE_GNS_REVERSE_LOOKUP_RESULT 504


/*******************************************************************************
 * CONSENSUS message types
 ******************************************************************************/

/**
 * Join a consensus session. Sent by client to service as first message.
 */
#define GNUNET_MESSAGE_TYPE_CONSENSUS_CLIENT_JOIN 520

/**
 * Insert an element. Sent by client to service.
 */
#define GNUNET_MESSAGE_TYPE_CONSENSUS_CLIENT_INSERT 521

/**
 * Begin accepting new elements from other participants.
 * Sent by client to service.
 */
#define GNUNET_MESSAGE_TYPE_CONSENSUS_CLIENT_BEGIN 522

/**
 * Sent by service when a new element is added.
 */
#define GNUNET_MESSAGE_TYPE_CONSENSUS_CLIENT_RECEIVED_ELEMENT 523

/**
 * Sent by client to service in order to start the consensus conclusion.
 */
#define GNUNET_MESSAGE_TYPE_CONSENSUS_CLIENT_CONCLUDE 524

/**
 * Sent by service to client in order to signal a completed consensus
 * conclusion. Last message sent in a consensus session.
 */
#define GNUNET_MESSAGE_TYPE_CONSENSUS_CLIENT_CONCLUDE_DONE 525


/* message types 526-539 reserved for consensus client/service messages */


/**
 * Sent by client to service, telling whether a received element should
 * be accepted and propagated further or not.
 */
#define GNUNET_MESSAGE_TYPE_CONSENSUS_CLIENT_ACK 540

/**
 * Strata estimator.
 */
#define GNUNET_MESSAGE_TYPE_CONSENSUS_P2P_DELTA_ESTIMATE 541

/**
 * IBF containing all elements of a peer.
 */
#define GNUNET_MESSAGE_TYPE_CONSENSUS_P2P_DIFFERENCE_DIGEST 542

/**
 * One or more elements that are sent from peer to peer.
 */
#define GNUNET_MESSAGE_TYPE_CONSENSUS_P2P_ELEMENTS 543

/**
 * Elements, and requests for further elements
 */
#define GNUNET_MESSAGE_TYPE_CONSENSUS_P2P_ELEMENTS_REQUEST 544

/**
 * Elements that a peer reports to be missing at the remote peer.
 */
#define GNUNET_MESSAGE_TYPE_CONSENSUS_P2P_ELEMENTS_REPORT 545

/**
 * Provide context for a consensus round.
 */
#define GNUNET_MESSAGE_TYPE_CONSENSUS_P2P_ROUND_CONTEXT 547


/*******************************************************************************
 * SET message types
 ******************************************************************************/

/**
 * Demand the whole element from the other
 * peer, given only the hash code.
 */
#define GNUNET_MESSAGE_TYPE_SET_UNION_P2P_REQUEST_FULL 565

/**
 * Demand the whole element from the other
 * peer, given only the hash code.
 */
#define GNUNET_MESSAGE_TYPE_SET_UNION_P2P_DEMAND 566

/**
 * Tell the other peer to send us a list of
 * hashes that match an IBF key.
 */
#define GNUNET_MESSAGE_TYPE_SET_UNION_P2P_INQUIRY 567

/**
 * Tell the other peer which hashes match a
 * given IBF key.
 */
#define GNUNET_MESSAGE_TYPE_SET_UNION_P2P_OFFER 568

/**
 * Reject a set request.
 */
#define GNUNET_MESSAGE_TYPE_SET_REJECT 569

/**
 * Cancel a set operation
 */
#define GNUNET_MESSAGE_TYPE_SET_CANCEL 570

/**
 * Acknowledge result from iteration
 */
#define GNUNET_MESSAGE_TYPE_SET_ITER_ACK 571

/**
 * Create an empty set
 */
#define GNUNET_MESSAGE_TYPE_SET_RESULT 572

/**
 * Add element to set
 */
#define GNUNET_MESSAGE_TYPE_SET_ADD 573

/**
 * Remove element from set
 */
#define GNUNET_MESSAGE_TYPE_SET_REMOVE 574

/**
 * Listen for operation requests
 */
#define GNUNET_MESSAGE_TYPE_SET_LISTEN 575

/**
 * Accept a set request
 */
#define GNUNET_MESSAGE_TYPE_SET_ACCEPT 576

/**
 * Evaluate a set operation
 */
#define GNUNET_MESSAGE_TYPE_SET_EVALUATE 577

/**
 * Start a set operation with the given set
 */
#define GNUNET_MESSAGE_TYPE_SET_CONCLUDE 578

/**
 * Notify the client of a request from a remote peer
 */
#define GNUNET_MESSAGE_TYPE_SET_REQUEST 579

/**
 * Create a new local set
 */
#define GNUNET_MESSAGE_TYPE_SET_CREATE 580

/**
 * Request a set operation from a remote peer.
 */
#define GNUNET_MESSAGE_TYPE_SET_P2P_OPERATION_REQUEST 581

/**
 * Strata estimator.
 */
#define GNUNET_MESSAGE_TYPE_SET_UNION_P2P_SE 582

/**
 * Invertible bloom filter.
 */
#define GNUNET_MESSAGE_TYPE_SET_UNION_P2P_IBF 583

/**
 * Actual set elements.
 */
#define GNUNET_MESSAGE_TYPE_SET_P2P_ELEMENTS 584

/**
 * Requests for the elements with the given hashes.
 */
#define GNUNET_MESSAGE_TYPE_SET_P2P_ELEMENT_REQUESTS 585

/**
 * Set operation is done.
 */
#define GNUNET_MESSAGE_TYPE_SET_UNION_P2P_DONE 586

/**
 * Start iteration over set elements.
 */
#define GNUNET_MESSAGE_TYPE_SET_ITER_REQUEST 587

/**
 * Element result for the iterating client.
 */
#define GNUNET_MESSAGE_TYPE_SET_ITER_ELEMENT 588

/**
 * Iteration end marker for the client.
 */
#define GNUNET_MESSAGE_TYPE_SET_ITER_DONE 589

/**
 * Compressed strata estimator.
 */
#define GNUNET_MESSAGE_TYPE_SET_UNION_P2P_SEC 590

/**
 * Information about the element count for intersection
 */
#define GNUNET_MESSAGE_TYPE_SET_INTERSECTION_P2P_ELEMENT_INFO 591

/**
 * Bloom filter message for intersection exchange started by Bob.
 */
#define GNUNET_MESSAGE_TYPE_SET_INTERSECTION_P2P_BF 592

/**
 * Intersection operation is done.
 */
#define GNUNET_MESSAGE_TYPE_SET_INTERSECTION_P2P_DONE 593

/**
 * Ask the set service to prepare a copy of a set.
 */
#define GNUNET_MESSAGE_TYPE_SET_COPY_LAZY_PREPARE 594

/**
 * Give the client an ID for connecting to the set's copy.
 */
#define GNUNET_MESSAGE_TYPE_SET_COPY_LAZY_RESPONSE 595

/**
 * Sent by the client to the server to connect to an existing,
 * lazily copied set.
 */
#define GNUNET_MESSAGE_TYPE_SET_COPY_LAZY_CONNECT 596

/**
 * Request all missing elements from the other peer,
 * based on their sets and the elements we previously sent
 * with #GNUNET_MESSAGE_TYPE_SET_P2P_ELEMENTS.
 */
#define GNUNET_MESSAGE_TYPE_SET_UNION_P2P_FULL_DONE 597

/**
 * Send a set element, not as response to a demand but because
 * we're sending the full set.
 */
#define GNUNET_MESSAGE_TYPE_SET_UNION_P2P_FULL_ELEMENT 598

/**
 * Request all missing elements from the other peer,
 * based on their sets and the elements we previously sent
 * with #GNUNET_MESSAGE_TYPE_SET_P2P_ELEMENTS.
 */
#define GNUNET_MESSAGE_TYPE_SET_UNION_P2P_OVER 599


/*******************************************************************************
 * TESTBED LOGGER message types
 ******************************************************************************/

/**
 * Message for TESTBED LOGGER
 */
#define GNUNET_MESSAGE_TYPE_TESTBED_LOGGER_MSG 600

/**
 * Message for TESTBED LOGGER acknowledgement
 */
#define GNUNET_MESSAGE_TYPE_TESTBED_LOGGER_ACK 601


/**
 * Advertise regex capability.
 */
#define GNUNET_MESSAGE_TYPE_REGEX_ANNOUNCE 620

/**
 * Search for peer with matching capability.
 */
#define GNUNET_MESSAGE_TYPE_REGEX_SEARCH 621

/**
 * Result in response to regex search.
 */
#define GNUNET_MESSAGE_TYPE_REGEX_RESULT 622

/*******************************************************************************
 * IDENTITY message types
 ******************************************************************************/

/**
 * First message send from identity client to service (to subscribe to
 * updates).
 */
#define GNUNET_MESSAGE_TYPE_IDENTITY_START 624

/**
 * Generic response from identity service with success and/or error message.
 */
#define GNUNET_MESSAGE_TYPE_IDENTITY_RESULT_CODE 625

/**
 * Update about identity status from service to clients.
 */
#define GNUNET_MESSAGE_TYPE_IDENTITY_UPDATE 626

/**
 * Client requests to know default identity for a subsystem.
 */
#define GNUNET_MESSAGE_TYPE_IDENTITY_GET_DEFAULT 627

/**
 * Client sets default identity; or service informs about default identity.
 */
#define GNUNET_MESSAGE_TYPE_IDENTITY_SET_DEFAULT 628

/**
 * Create new identity (client->service).
 */
#define GNUNET_MESSAGE_TYPE_IDENTITY_CREATE 629

/**
 * Rename existing identity (client->service).
 */
#define GNUNET_MESSAGE_TYPE_IDENTITY_RENAME 630

/**
 * Delete identity (client->service).
 */
#define GNUNET_MESSAGE_TYPE_IDENTITY_DELETE 631

/**
 * First message send from identity client to service to
 * lookup a single ego.  The service will respond with a
 * #GNUNET_MESSAGE_TYPE_IDENTITY_UPDATE message if the ego
 * exists, or a #GNUNET_MESSAGE_TYPE_IDENTITY_RESULT_CODE if not.
 */
#define GNUNET_MESSAGE_TYPE_IDENTITY_LOOKUP 632

/**
 * First message send from identity client to service to lookup a
 * single ego matching the given suffix (longest match).  The service
 * will respond with a #GNUNET_MESSAGE_TYPE_IDENTITY_UPDATE message if
 * the ego exists, or a #GNUNET_MESSAGE_TYPE_IDENTITY_RESULT_CODE if
 * not.
 */
#define GNUNET_MESSAGE_TYPE_IDENTITY_LOOKUP_BY_SUFFIX 633


/*******************************************************************************
 * REVOCATION message types
 ******************************************************************************/

/**
 * Client to service: was this key revoked?
 */
#define GNUNET_MESSAGE_TYPE_REVOCATION_QUERY 636

/**
 * Service to client: answer if key was revoked!
 */
#define GNUNET_MESSAGE_TYPE_REVOCATION_QUERY_RESPONSE 637

/**
 * Client to service OR peer-to-peer: revoke this key!
 */
#define GNUNET_MESSAGE_TYPE_REVOCATION_REVOKE 638

/**
 * Service to client: revocation confirmed
 */
#define GNUNET_MESSAGE_TYPE_REVOCATION_REVOKE_RESPONSE 639


/*******************************************************************************
 * SCALARPRODUCT message types
 ******************************************************************************/

/**
 * Client -> Alice
 */
#define GNUNET_MESSAGE_TYPE_SCALARPRODUCT_CLIENT_TO_ALICE 640

/**
 * Client -> Bob
 */
#define GNUNET_MESSAGE_TYPE_SCALARPRODUCT_CLIENT_TO_BOB 641

/**
 * Client -> Alice multipart
 */
#define GNUNET_MESSAGE_TYPE_SCALARPRODUCT_CLIENT_MULTIPART_ALICE 642

/**
 * Client -> Bob multipart
 */
#define GNUNET_MESSAGE_TYPE_SCALARPRODUCT_CLIENT_MULTIPART_BOB 643

/**
 * Alice -> Bob session initialization
 */
#define GNUNET_MESSAGE_TYPE_SCALARPRODUCT_SESSION_INITIALIZATION 644

/**
 * Alice -> Bob SP crypto-data (after intersection)
 */
#define GNUNET_MESSAGE_TYPE_SCALARPRODUCT_ALICE_CRYPTODATA 645

/**
 * Bob -> Alice SP crypto-data
 */
#define GNUNET_MESSAGE_TYPE_SCALARPRODUCT_BOB_CRYPTODATA 647

/**
 * Bob -> Alice SP crypto-data multipart
 */
#define GNUNET_MESSAGE_TYPE_SCALARPRODUCT_BOB_CRYPTODATA_MULTIPART 648

/**
 * Alice/Bob -> Client Result
 */
#define GNUNET_MESSAGE_TYPE_SCALARPRODUCT_RESULT 649

/**
 * Alice -> Bob ECC session initialization
 */
#define GNUNET_MESSAGE_TYPE_SCALARPRODUCT_ECC_SESSION_INITIALIZATION 650

/**
 * Alice -> Bob ECC crypto data
 */
#define GNUNET_MESSAGE_TYPE_SCALARPRODUCT_ECC_ALICE_CRYPTODATA 651

/**
 * Bob -> Alice ECC crypto data
 */
#define GNUNET_MESSAGE_TYPE_SCALARPRODUCT_ECC_BOB_CRYPTODATA 652


/*******************************************************************************
 * PSYCSTORE message types
 ******************************************************************************/

/**
 * Store a membership event.
 */
#define GNUNET_MESSAGE_TYPE_PSYCSTORE_MEMBERSHIP_STORE 660

/**
 * Test for membership of a member at a particular point in time.
 */
#define GNUNET_MESSAGE_TYPE_PSYCSTORE_MEMBERSHIP_TEST 661

#define GNUNET_MESSAGE_TYPE_PSYCSTORE_FRAGMENT_STORE 662

#define GNUNET_MESSAGE_TYPE_PSYCSTORE_FRAGMENT_GET 663

#define GNUNET_MESSAGE_TYPE_PSYCSTORE_MESSAGE_GET 664

#define GNUNET_MESSAGE_TYPE_PSYCSTORE_MESSAGE_GET_FRAGMENT 665

#define GNUNET_MESSAGE_TYPE_PSYCSTORE_COUNTERS_GET 666

/* 657 */

#define GNUNET_MESSAGE_TYPE_PSYCSTORE_STATE_MODIFY 668

#define GNUNET_MESSAGE_TYPE_PSYCSTORE_STATE_SYNC 669

#define GNUNET_MESSAGE_TYPE_PSYCSTORE_STATE_RESET 670

#define GNUNET_MESSAGE_TYPE_PSYCSTORE_STATE_HASH_UPDATE 671

#define GNUNET_MESSAGE_TYPE_PSYCSTORE_STATE_GET 672

#define GNUNET_MESSAGE_TYPE_PSYCSTORE_STATE_GET_PREFIX 673

/**
 * Generic response from PSYCstore service with success and/or error message.
 */
#define GNUNET_MESSAGE_TYPE_PSYCSTORE_RESULT_CODE 674

#define GNUNET_MESSAGE_TYPE_PSYCSTORE_RESULT_FRAGMENT 675

#define GNUNET_MESSAGE_TYPE_PSYCSTORE_RESULT_COUNTERS 676

#define GNUNET_MESSAGE_TYPE_PSYCSTORE_RESULT_STATE 677


/*******************************************************************************
 * PSYC message types
 ******************************************************************************/

/**
 * C: client
 * S: service
 * M: multicast
 */

/** S->C: result of an operation */
#define GNUNET_MESSAGE_TYPE_PSYC_RESULT_CODE 680

/** C->S: request to start a channel as a master */
#define GNUNET_MESSAGE_TYPE_PSYC_MASTER_START 681

/** S->C: master start acknowledgement */
#define GNUNET_MESSAGE_TYPE_PSYC_MASTER_START_ACK 682

/** C->S: request to join a channel as a slave */
#define GNUNET_MESSAGE_TYPE_PSYC_SLAVE_JOIN 683

/** S->C: slave join acknowledgement */
#define GNUNET_MESSAGE_TYPE_PSYC_SLAVE_JOIN_ACK 684

/** C->S: request to part from a channel */
#define GNUNET_MESSAGE_TYPE_PSYC_PART_REQUEST 685

/** S->C: acknowledgement that a slave of master parted from a channel */
#define GNUNET_MESSAGE_TYPE_PSYC_PART_ACK 686

/** M->S->C: incoming join request from multicast */
#define GNUNET_MESSAGE_TYPE_PSYC_JOIN_REQUEST 687

/** C->S->M: decision about a join request */
#define GNUNET_MESSAGE_TYPE_PSYC_JOIN_DECISION 688


/** C->S: request to add/remove channel slave in the membership database. */
#define GNUNET_MESSAGE_TYPE_PSYC_CHANNEL_MEMBERSHIP_STORE 689

/* 690 */

/** S<--C: PSYC message which contains one or more message parts. */
#define GNUNET_MESSAGE_TYPE_PSYC_MESSAGE 691

/** M<->S<->C: PSYC message which contains a header and one or more message
 * parts. */
#define GNUNET_MESSAGE_TYPE_PSYC_MESSAGE_HEADER \
  692 // FIXME: start using this where appropriate

/** Message part: method */
#define GNUNET_MESSAGE_TYPE_PSYC_MESSAGE_METHOD 693

/** Message part: modifier */
#define GNUNET_MESSAGE_TYPE_PSYC_MESSAGE_MODIFIER 694

/** Message part: modifier continuation */
#define GNUNET_MESSAGE_TYPE_PSYC_MESSAGE_MOD_CONT 695

/** Message part: data */
#define GNUNET_MESSAGE_TYPE_PSYC_MESSAGE_DATA 696

/** Message part: end of message */
#define GNUNET_MESSAGE_TYPE_PSYC_MESSAGE_END 697

/** Message part: message cancelled */
#define GNUNET_MESSAGE_TYPE_PSYC_MESSAGE_CANCEL 698

/** S->C: message acknowledgement */
#define GNUNET_MESSAGE_TYPE_PSYC_MESSAGE_ACK 699

/* 700 */

/** C->S: request channel history replay from PSYCstore. */
#define GNUNET_MESSAGE_TYPE_PSYC_HISTORY_REPLAY 701

/** S->C: result for a channel history request */
#define GNUNET_MESSAGE_TYPE_PSYC_HISTORY_RESULT 702


/** C->S: request best matching state variable from PSYCstore. */
#define GNUNET_MESSAGE_TYPE_PSYC_STATE_GET 703

/** C->S: request state variables with a given prefix from PSYCstore. */
#define GNUNET_MESSAGE_TYPE_PSYC_STATE_GET_PREFIX 704

/** S->C: result for a state request. */
#define GNUNET_MESSAGE_TYPE_PSYC_STATE_RESULT 705


/*******************************************************************************
 * CONVERSATION message types
 ******************************************************************************/

/**
 * Message to transmit the audio between helper and speaker/microphone library.
 */
#define GNUNET_MESSAGE_TYPE_CONVERSATION_AUDIO 730

/**
 * Client -> Server message to register a phone.
 */
#define GNUNET_MESSAGE_TYPE_CONVERSATION_CS_PHONE_REGISTER 731

/**
 * Client -> Server message to reject/hangup a call
 */
#define GNUNET_MESSAGE_TYPE_CONVERSATION_CS_PHONE_PICK_UP 732

/**
 * Client -> Server message to reject/hangup a call
 */
#define GNUNET_MESSAGE_TYPE_CONVERSATION_CS_PHONE_HANG_UP 733

/**
 * Client <- Server message to indicate a ringing phone
 */
#define GNUNET_MESSAGE_TYPE_CONVERSATION_CS_PHONE_CALL 734

/**
 * Client <- Server message to indicate a ringing phone
 */
#define GNUNET_MESSAGE_TYPE_CONVERSATION_CS_PHONE_RING 735

/**
 * Client <-> Server message to suspend connection.
 */
#define GNUNET_MESSAGE_TYPE_CONVERSATION_CS_PHONE_SUSPEND 736

/**
 * Client <-> Server message to resume connection.
 */
#define GNUNET_MESSAGE_TYPE_CONVERSATION_CS_PHONE_RESUME 737

/**
 * Service -> Client message to notify that phone was picked up.
 */
#define GNUNET_MESSAGE_TYPE_CONVERSATION_CS_PHONE_PICKED_UP 738

/**
 * Client <-> Server message to send audio data.
 */
#define GNUNET_MESSAGE_TYPE_CONVERSATION_CS_AUDIO 739

/**
 * Cadet: call initiation
 */
#define GNUNET_MESSAGE_TYPE_CONVERSATION_CADET_PHONE_RING 740

/**
 * Cadet: hang up / refuse call
 */
#define GNUNET_MESSAGE_TYPE_CONVERSATION_CADET_PHONE_HANG_UP 741

/**
 * Cadet: pick up phone (establish audio channel)
 */
#define GNUNET_MESSAGE_TYPE_CONVERSATION_CADET_PHONE_PICK_UP 742

/**
 * Cadet: phone suspended.
 */
#define GNUNET_MESSAGE_TYPE_CONVERSATION_CADET_PHONE_SUSPEND 743

/**
 * Cadet: phone resumed.
 */
#define GNUNET_MESSAGE_TYPE_CONVERSATION_CADET_PHONE_RESUME 744

/**
 * Cadet: audio data
 */
#define GNUNET_MESSAGE_TYPE_CONVERSATION_CADET_AUDIO 745


/*******************************************************************************
 * MULTICAST message types
 ******************************************************************************/

/**
 * C: client
 * S: service
 * T: cadet
 */

/**
 * C->S: Start the origin.
 */
#define GNUNET_MESSAGE_TYPE_MULTICAST_ORIGIN_START 750

/**
 * C->S: Join group as a member.
 */
#define GNUNET_MESSAGE_TYPE_MULTICAST_MEMBER_JOIN 751

/**
 * C<--S<->T: A peer wants to join the group.
 *
 * Unicast message to the origin or another group member.
 */
#define GNUNET_MESSAGE_TYPE_MULTICAST_JOIN_REQUEST 752

/**
 * C<->S<->T: Response to a join request.
 *
 * Unicast message from a group member to the peer wanting to join.
 */
#define GNUNET_MESSAGE_TYPE_MULTICAST_JOIN_DECISION 753

/**
 * A peer wants to part the group.
 */
#define GNUNET_MESSAGE_TYPE_MULTICAST_PART_REQUEST 754

/**
 * Acknowledgement sent in response to a part request.
 *
 * Unicast message from a group member to the peer wanting to part.
 */
#define GNUNET_MESSAGE_TYPE_MULTICAST_PART_ACK 755

// FIXME: this is never used!
/**
 * Group terminated.
 */
#define GNUNET_MESSAGE_TYPE_MULTICAST_GROUP_END 756

/**
 * C<->S<->T: Multicast message from the origin to all members.
 */
#define GNUNET_MESSAGE_TYPE_MULTICAST_MESSAGE 757

/**
 * C<->S<->T: Unicast request from a group member to the origin.
 */
#define GNUNET_MESSAGE_TYPE_MULTICAST_REQUEST 758

/**
 * C->S: Acknowledgement of a message or request fragment for the client.
 */
#define GNUNET_MESSAGE_TYPE_MULTICAST_FRAGMENT_ACK 759

/**
 * C<->S<->T: Replay request from a group member to another member.
 */
#define GNUNET_MESSAGE_TYPE_MULTICAST_REPLAY_REQUEST 760

/**
 * C<->S<->T: Replay response from a group member to another member.
 */
#define GNUNET_MESSAGE_TYPE_MULTICAST_REPLAY_RESPONSE 761

/**
 * C<->S: End of replay response.
 */
#define GNUNET_MESSAGE_TYPE_MULTICAST_REPLAY_RESPONSE_END 762


/*******************************************************************************
 * SECRETSHARING message types
 ******************************************************************************/


/**
 * Establish a new session.
 */
#define GNUNET_MESSAGE_TYPE_SECRETSHARING_CLIENT_GENERATE 780

/**
 * Request the decryption of a ciphertext.
 */
#define GNUNET_MESSAGE_TYPE_SECRETSHARING_CLIENT_DECRYPT 781

/**
 * The service succeeded in decrypting a ciphertext.
 */
#define GNUNET_MESSAGE_TYPE_SECRETSHARING_CLIENT_DECRYPT_DONE 782

/**
 * The cryptosystem has been established.
 * Contains the peer's share.
 */
#define GNUNET_MESSAGE_TYPE_SECRETSHARING_CLIENT_SECRET_READY 783


/*******************************************************************************
 * PEERSTORE message types
 ******************************************************************************/

/**
 * Store request message
 */
#define GNUNET_MESSAGE_TYPE_PEERSTORE_STORE 820

/**
 * Iteration request
 */
#define GNUNET_MESSAGE_TYPE_PEERSTORE_ITERATE 821

/**
 * Iteration record message
 */
#define GNUNET_MESSAGE_TYPE_PEERSTORE_ITERATE_RECORD 822

/**
 * Iteration end message
 */
#define GNUNET_MESSAGE_TYPE_PEERSTORE_ITERATE_END 823

/**
 * Watch request
 */
#define GNUNET_MESSAGE_TYPE_PEERSTORE_WATCH 824

/**
 * Watch response
 */
#define GNUNET_MESSAGE_TYPE_PEERSTORE_WATCH_RECORD 825

/**
 * Watch cancel request
 */
#define GNUNET_MESSAGE_TYPE_PEERSTORE_WATCH_CANCEL 826

/*******************************************************************************
 * SOCIAL message types
 ******************************************************************************/

/**
 * C: client
 * S: service
 * P: PSYC
 */

/** S->C: result of an operation */
#define GNUNET_MESSAGE_TYPE_SOCIAL_RESULT_CODE 840

/** C->S: request to enter a place as the host */
#define GNUNET_MESSAGE_TYPE_SOCIAL_HOST_ENTER 841

/** S->C: host enter acknowledgement */
#define GNUNET_MESSAGE_TYPE_SOCIAL_HOST_ENTER_ACK 842

/** C->S: request to enter a place as a guest */
#define GNUNET_MESSAGE_TYPE_SOCIAL_GUEST_ENTER 843

/** C->S: request to enter a place as a guest, using a GNS address */
#define GNUNET_MESSAGE_TYPE_SOCIAL_GUEST_ENTER_BY_NAME 844

/** S->C: guest enter acknowledgement */
#define GNUNET_MESSAGE_TYPE_SOCIAL_GUEST_ENTER_ACK 845

/** P->S->C: incoming entry request from PSYC */
#define GNUNET_MESSAGE_TYPE_SOCIAL_ENTRY_REQUEST 846

/** C->S->P: decision about an entry request */
#define GNUNET_MESSAGE_TYPE_SOCIAL_ENTRY_DECISION 847

/** C->S: request to leave a place */
#define GNUNET_MESSAGE_TYPE_SOCIAL_PLACE_LEAVE 848

/** S->C: place leave acknowledgement */
#define GNUNET_MESSAGE_TYPE_SOCIAL_PLACE_LEAVE_ACK 849

/** C->S: add place to GNS zone */
#define GNUNET_MESSAGE_TYPE_SOCIAL_ZONE_ADD_PLACE 850

/** C->S: add nym to GNS zone */
#define GNUNET_MESSAGE_TYPE_SOCIAL_ZONE_ADD_NYM 851

/** C->S: connect application */
#define GNUNET_MESSAGE_TYPE_SOCIAL_APP_CONNECT 852

/** C->S: detach a place from application */
#define GNUNET_MESSAGE_TYPE_SOCIAL_APP_DETACH 853

/** S->C: notify about an existing ego */
#define GNUNET_MESSAGE_TYPE_SOCIAL_APP_EGO 854

/** S->C: end of ego list */
#define GNUNET_MESSAGE_TYPE_SOCIAL_APP_EGO_END 855

/** S->C: notify about an existing place */
#define GNUNET_MESSAGE_TYPE_SOCIAL_APP_PLACE 856

/** S->C: end of place list */
#define GNUNET_MESSAGE_TYPE_SOCIAL_APP_PLACE_END 857

/** C->S: set message processing flags */
#define GNUNET_MESSAGE_TYPE_SOCIAL_MSG_PROC_SET 858

/** C->S: clear message processing flags */
#define GNUNET_MESSAGE_TYPE_SOCIAL_MSG_PROC_CLEAR 859

/*******************************************************************************
 * X-VINE DHT messages
 ******************************************************************************/

/**
 * Trail setup request is received by a peer.
 */
#define GNUNET_MESSAGE_TYPE_XDHT_P2P_TRAIL_SETUP 880

/**
 * Trail to a particular peer is returned to this peer.
 */
#define GNUNET_MESSAGE_TYPE_XDHT_P2P_TRAIL_SETUP_RESULT 881

/**
 * Verify if your immediate successor is still your immediate successor.
 */
#define GNUNET_MESSAGE_TYPE_XDHT_P2P_VERIFY_SUCCESSOR 882

/**
 * Notify your new immediate successor that you are its new predecessor.
 */
#define GNUNET_MESSAGE_TYPE_XDHT_P2P_NOTIFY_NEW_SUCCESSOR 883

/**
 * Message which contains the immediate predecessor of requested successor
 */
#define GNUNET_MESSAGE_TYPE_XDHT_P2P_VERIFY_SUCCESSOR_RESULT 884

/**
 * Message which contains the get result.
 */
#define GNUNET_MESSAGE_TYPE_XDHT_P2P_GET_RESULT 885

/**
 * Trail Rejection Message.
 */
#define GNUNET_MESSAGE_TYPE_XDHT_P2P_TRAIL_SETUP_REJECTION 886

/**
 * Trail Tear down Message.
 */
#define GNUNET_MESSAGE_TYPE_XDHT_P2P_TRAIL_TEARDOWN 887

/**
 * Routing table add message.
 */
#define GNUNET_MESSAGE_TYPE_XDHT_P2P_ADD_TRAIL 888

/**
 * Peer is storing the data in DHT.
 */
#define GNUNET_MESSAGE_TYPE_XDHT_P2P_PUT 890

/**
 * Peer tries to find data in DHT.
 */
#define GNUNET_MESSAGE_TYPE_XDHT_P2P_GET 891

/**
 * Send back peer that considers you are its successor, a confirmation
 * that you got the notify successor message.
 */
#define GNUNET_MESSAGE_TYPE_XDHT_P2P_NOTIFY_SUCCESSOR_CONFIRMATION 892

#if ENABLE_MALICIOUS
/**
 * Turn X-VINE DHT service malicious
 */
#define GNUNET_MESSAGE_TYPE_DHT_ACT_MALICIOUS 893

/**
 * Acknowledge receiving ACT MALICIOUS request
 */
#define GNUNET_MESSAGE_TYPE_DHT_CLIENT_ACT_MALICIOUS_OK 894

#endif


/*******************************************************************************
 * Whanau DHT messages
 ******************************************************************************/


/**
 * This message contains the query for performing a random walk
 */
#define GNUNET_MESSAGE_TYPE_WDHT_RANDOM_WALK 910

/**
 * This message contains the result of a random walk
 */
#define GNUNET_MESSAGE_TYPE_WDHT_RANDOM_WALK_RESPONSE 911

/**
 * This message contains a notification for the death of a trail
 */
#define GNUNET_MESSAGE_TYPE_WDHT_TRAIL_DESTROY 912

/**
 * This message are used to route a query to a peer
 */
#define GNUNET_MESSAGE_TYPE_WDHT_TRAIL_ROUTE 913

/**
 * This message contains the query to transfer successor values.
 */
#define GNUNET_MESSAGE_TYPE_WDHT_SUCCESSOR_FIND 914

/**
 * Message which contains the get query
 */
#define GNUNET_MESSAGE_TYPE_WDHT_GET 915

/**
 * Message which contains the "put", a response to
 * #GNUNET_MESSAGE_TYPE_WDHT_SUCCESSOR_FIND.
 */
#define GNUNET_MESSAGE_TYPE_WDHT_PUT 916

/**
 * Message which contains the get result, a response
 * to #GNUNET_MESSAGE_TYPE_WDHT_GET.
 */
#define GNUNET_MESSAGE_TYPE_WDHT_GET_RESULT 917


/*******************************************************************************
 * RPS messages
 ******************************************************************************/

/* P2P Messages */

/**
 * RPS check liveliness message to check liveliness of other peer
 */
#define GNUNET_MESSAGE_TYPE_RPS_PP_CHECK_LIVE 950

/**
 * RPS PUSH message to push own ID to another peer
 */
#define GNUNET_MESSAGE_TYPE_RPS_PP_PUSH 951

/**
 * RPS PULL REQUEST message to request the local view of another peer
 */
#define GNUNET_MESSAGE_TYPE_RPS_PP_PULL_REQUEST 952

/**
 * RPS PULL REPLY message which contains the view of the other peer
 */
#define GNUNET_MESSAGE_TYPE_RPS_PP_PULL_REPLY 953


/* Client-Service Messages */


/**
 * RPS CS SEED Message for the Client to seed peers into rps
 */
#define GNUNET_MESSAGE_TYPE_RPS_CS_SEED 954

#if ENABLE_MALICIOUS
/**
 * Turn RPS service malicious
 */
#define GNUNET_MESSAGE_TYPE_RPS_ACT_MALICIOUS 955

#endif /* ENABLE_MALICIOUS */

/**
 * RPS client-service message to start a sub sampler
 */
#define GNUNET_MESSAGE_TYPE_RPS_CS_SUB_START 956

/**
 * RPS client-service message to stop a sub sampler
 */
#define GNUNET_MESSAGE_TYPE_RPS_CS_SUB_STOP 957

/* Debugging API continues at 1130 */

/******************************************************************************/


/**************************************************
 *
 * IDENTITY PROVIDER MESSAGE TYPES
 */
#define GNUNET_MESSAGE_TYPE_RECLAIM_ATTRIBUTE_STORE 961

#define GNUNET_MESSAGE_TYPE_RECLAIM_SUCCESS_RESPONSE 962

#define GNUNET_MESSAGE_TYPE_RECLAIM_ATTRIBUTE_ITERATION_START 963

#define GNUNET_MESSAGE_TYPE_RECLAIM_ATTRIBUTE_ITERATION_STOP 964

#define GNUNET_MESSAGE_TYPE_RECLAIM_ATTRIBUTE_ITERATION_NEXT 965

#define GNUNET_MESSAGE_TYPE_RECLAIM_ATTRIBUTE_RESULT 966

#define GNUNET_MESSAGE_TYPE_RECLAIM_ISSUE_TICKET 967

#define GNUNET_MESSAGE_TYPE_RECLAIM_TICKET_RESULT 968

#define GNUNET_MESSAGE_TYPE_RECLAIM_REVOKE_TICKET 969

#define GNUNET_MESSAGE_TYPE_RECLAIM_REVOKE_TICKET_RESULT 970

#define GNUNET_MESSAGE_TYPE_RECLAIM_CONSUME_TICKET 971

#define GNUNET_MESSAGE_TYPE_RECLAIM_CONSUME_TICKET_RESULT 972

#define GNUNET_MESSAGE_TYPE_RECLAIM_TICKET_ITERATION_START 973

#define GNUNET_MESSAGE_TYPE_RECLAIM_TICKET_ITERATION_STOP 974

#define GNUNET_MESSAGE_TYPE_RECLAIM_TICKET_ITERATION_NEXT 975

#define GNUNET_MESSAGE_TYPE_RECLAIM_ATTRIBUTE_DELETE 976

#define GNUNET_MESSAGE_TYPE_RECLAIM_ATTESTATION_STORE 977

#define GNUNET_MESSAGE_TYPE_RECLAIM_ATTESTATION_DELETE 978

#define GNUNET_MESSAGE_TYPE_RECLAIM_ATTESTATION_RESULT 979

#define GNUNET_MESSAGE_TYPE_RECLAIM_ATTESTATION_ITERATION_START 980

#define GNUNET_MESSAGE_TYPE_RECLAIM_ATTESTATION_ITERATION_STOP 981

#define GNUNET_MESSAGE_TYPE_RECLAIM_ATTESTATION_ITERATION_NEXT 982


/**************************************************
 *
 * ABD MESSAGE TYPES
 */
#define GNUNET_MESSAGE_TYPE_ABD_VERIFY 991

#define GNUNET_MESSAGE_TYPE_ABD_VERIFY_RESULT 992

#define GNUNET_MESSAGE_TYPE_ABD_COLLECT 993

#define GNUNET_MESSAGE_TYPE_ABD_COLLECT_RESULT 994

#define GNUNET_MESSAGE_TYPE_ABD_INTERMEDIATE_RESULT 995

/******************************************************************************/


/******************************************************************************/
/***********************************  CADET  **********************************/
/******************************************************************************/
/* CADET: message types 1000-1059
 * 1000-1009 Connection-level Messages
 * 1010-1019 Channel-level Messages
 * 1020-1029 Local Client-Service
 * 1030-1049 Local Service Monitoring
 * 1050-1059 Application Data
 */

/********************************  Connection  ********************************/

/**
 * Request the creation of a connection
 */
#define GNUNET_MESSAGE_TYPE_CADET_CONNECTION_CREATE 1000

/**
 * Send origin an ACK that the connection is complete
 */
#define GNUNET_MESSAGE_TYPE_CADET_CONNECTION_CREATE_ACK 1001

/**
 * Notify that a connection is no longer valid
 */
#define GNUNET_MESSAGE_TYPE_CADET_CONNECTION_BROKEN 1002

/**
 * Request the destuction of a connection
 */
#define GNUNET_MESSAGE_TYPE_CADET_CONNECTION_DESTROY 1003

/**
 * At some point, the route will spontaneously change TODO
 */
#define GNUNET_MESSAGE_TYPE_CADET_CONNECTION_PATH_CHANGED_UNIMPLEMENTED 1004

/**
 * Hop-by-hop, connection dependent ACK.
 *
 * @deprecated
 */
#define GNUNET_MESSAGE_TYPE_CADET_CONNECTION_HOP_BY_HOP_ENCRYPTED_ACK 1005

/**
 * We do not bother with ACKs for
 * #GNUNET_MESSAGE_TYPE_CADET_TUNNEL_ENCRYPTED messages, but we instead
 * poll for one if we got nothing for a while and start to be worried.
 *
 * @deprecated
 */
#define GNUNET_MESSAGE_TYPE_CADET_TUNNEL_ENCRYPTED_POLL 1006

/**
 * Axolotl key exchange.
 */
#define GNUNET_MESSAGE_TYPE_CADET_TUNNEL_KX 1007

/**
 * Axolotl encrypted data.
 */
#define GNUNET_MESSAGE_TYPE_CADET_TUNNEL_ENCRYPTED 1008

/**
 * Axolotl key exchange response with authentication.
 */
#define GNUNET_MESSAGE_TYPE_CADET_TUNNEL_KX_AUTH 1009


/**********************************  Channel  *********************************/

/**
 * Payload data (inside an encrypted tunnel).
 */
#define GNUNET_MESSAGE_TYPE_CADET_CHANNEL_APP_DATA 1010

/**
 * Confirm payload data end-to-end.
 */
#define GNUNET_MESSAGE_TYPE_CADET_CHANNEL_APP_DATA_ACK 1011

/**
 * Announce connection is still alive (direction sensitive).
 */
#define GNUNET_MESSAGE_TYPE_CADET_CHANNEL_KEEPALIVE 1012

/**
 * Ask the cadet service to create a new channel.
 */
#define GNUNET_MESSAGE_TYPE_CADET_CHANNEL_OPEN 1013

/**
 * Ask the cadet service to destroy a channel.
 */
#define GNUNET_MESSAGE_TYPE_CADET_CHANNEL_DESTROY 1014

/**
 * Confirm the creation of a channel
 */
#define GNUNET_MESSAGE_TYPE_CADET_CHANNEL_OPEN_ACK 1015

/**
 * Reject the creation of a channel
 *
 * @deprecated
 */
#define GNUNET_MESSAGE_TYPE_CADET_CHANNEL_OPEN_NACK_DEPRECATED 1016

/***********************************  Local  **********************************/

/**
 * Payload client <-> service
 */
#define GNUNET_MESSAGE_TYPE_CADET_LOCAL_DATA 1020

/**
 * Local ACK for data.
 */
#define GNUNET_MESSAGE_TYPE_CADET_LOCAL_ACK 1021

/**
 * Start listening on a port.
 */
#define GNUNET_MESSAGE_TYPE_CADET_LOCAL_PORT_OPEN 1022

/**
 * Stop listening on a port.
 */
#define GNUNET_MESSAGE_TYPE_CADET_LOCAL_PORT_CLOSE 1023

/**
 * Ask the cadet service to create a new channel.
 */
#define GNUNET_MESSAGE_TYPE_CADET_LOCAL_CHANNEL_CREATE 1024

/**
 * Tell client that a channel was destroyed.
 */
#define GNUNET_MESSAGE_TYPE_CADET_LOCAL_CHANNEL_DESTROY 1025

/**********************************  Monitor  *********************************/


/**
 * Local information about all channels of service.
 */
#define GNUNET_MESSAGE_TYPE_CADET_LOCAL_REQUEST_INFO_CHANNEL 1030

/**
 * Local information of service about a specific channel.
 */
#define GNUNET_MESSAGE_TYPE_CADET_LOCAL_INFO_CHANNEL 1031

/**
 * End of local information of service about channels.
 */
#define GNUNET_MESSAGE_TYPE_CADET_LOCAL_INFO_CHANNEL_END 1032

/**
 * Request local information about all peers known to the service.
 */
#define GNUNET_MESSAGE_TYPE_CADET_LOCAL_REQUEST_INFO_PEERS 1033

/**
 * Local information about all peers known to the service.
 */
#define GNUNET_MESSAGE_TYPE_CADET_LOCAL_INFO_PEERS 1034

/**
 * End of local information about all peers known to the service.
 */
#define GNUNET_MESSAGE_TYPE_CADET_LOCAL_INFO_PEERS_END 1035

/**
 * Request local information of service about paths to specific peer.
 */
#define GNUNET_MESSAGE_TYPE_CADET_LOCAL_REQUEST_INFO_PATH 1036

/**
 * Local information of service about a specific path.
 */
#define GNUNET_MESSAGE_TYPE_CADET_LOCAL_INFO_PATH 1037

/**
 * End of local information of service about a specific path.
 */
#define GNUNET_MESSAGE_TYPE_CADET_LOCAL_INFO_PATH_END 1038

/**
 * Request local information about all tunnels of service.
 */
#define GNUNET_MESSAGE_TYPE_CADET_LOCAL_REQUEST_INFO_TUNNELS 1039

/**
 * Local information about all tunnels of service.
 */
#define GNUNET_MESSAGE_TYPE_CADET_LOCAL_INFO_TUNNELS 1040

/**
 * End of local information about all tunnels of service.
 */
#define GNUNET_MESSAGE_TYPE_CADET_LOCAL_INFO_TUNNELS_END 1041

/**
 * Request to drop a message of type X to peer y.
 */
#define GNUNET_MESSAGE_TYPE_CADET_DROP_CADET_MESSAGE 1042


/********************************  Application  *******************************/

/**
 * Traffic (net-cat style) used by the Command Line Interface.
 */
#define GNUNET_MESSAGE_TYPE_CADET_CLI 1059

/******************************************************************************/


/******************************************************************************/
/*************************************  NAT  **********************************/
/******************************************************************************/

/**
 * Message to ask NAT service to register a client.
 */
#define GNUNET_MESSAGE_TYPE_NAT_REGISTER 1060

/**
 * Message to ask NAT service to handle a STUN packet.
 */
#define GNUNET_MESSAGE_TYPE_NAT_HANDLE_STUN 1061

/**
 * Message to ask NAT service to request connection reversal.
 */
#define GNUNET_MESSAGE_TYPE_NAT_REQUEST_CONNECTION_REVERSAL 1062

/**
 * Message to from NAT service notifying us that connection reversal
 * was requested by another peer.
 */
#define GNUNET_MESSAGE_TYPE_NAT_CONNECTION_REVERSAL_REQUESTED 1063

/**
 * Message to from NAT service notifying us that one of our
 * addresses changed.
 */
#define GNUNET_MESSAGE_TYPE_NAT_ADDRESS_CHANGE 1064

/**
 * Message to ask NAT service to request autoconfiguration.
 */
#define GNUNET_MESSAGE_TYPE_NAT_AUTO_REQUEST_CFG 1067

/**
 * Message from NAT service with the autoconfiguration result.
 */
#define GNUNET_MESSAGE_TYPE_NAT_AUTO_CFG_RESULT 1068


/* 1080-1109 reserved for TMCG (Heiko Stamer, see gnunet-developers, January
 * 2017) */


/******************************************************************************/
/***********************************  AUCTION  ********************************/
/******************************************************************************/

/**
 * Client wants to create a new auction.
 */
#define GNUNET_MESSAGE_TYPE_AUCTION_CLIENT_CREATE 1110

/**
 * Client wants to join an existing auction.
 */
#define GNUNET_MESSAGE_TYPE_AUCTION_CLIENT_JOIN 1111

/**
 * Service reports the auction outcome to the client.
 */
#define GNUNET_MESSAGE_TYPE_AUCTION_CLIENT_OUTCOME 1112


/******************************************************************************/
/*********************************  RPS DEBUG  ********************************/
/******************************************************************************/

/**
 * @brief Request updates of the view
 */
#define GNUNET_MESSAGE_TYPE_RPS_CS_DEBUG_VIEW_REQUEST 1130

/**
 * @brief Send update of the view
 */
#define GNUNET_MESSAGE_TYPE_RPS_CS_DEBUG_VIEW_REPLY 1131

/**
 * @brief Cancel getting updates of the view
 */
#define GNUNET_MESSAGE_TYPE_RPS_CS_DEBUG_VIEW_CANCEL 1132


/**
 * @brief Request biased input stream
 */
#define GNUNET_MESSAGE_TYPE_RPS_CS_DEBUG_STREAM_REQUEST 1133

/**
 * @brief Send peer of biased stream
 */
#define GNUNET_MESSAGE_TYPE_RPS_CS_DEBUG_STREAM_REPLY 1134

/**
 * @brief Cancel getting biased strem
 */
#define GNUNET_MESSAGE_TYPE_RPS_CS_DEBUG_STREAM_CANCEL 1135


/*******************************************************
   NEW (TNG) Transport service
 ******************************************************* */

/**
 * @brief inform transport to add an address of this peer
 */
#define GNUNET_MESSAGE_TYPE_TRANSPORT_ADD_ADDRESS 1200

/**
 * @brief inform transport to delete an address of this peer
 */
#define GNUNET_MESSAGE_TYPE_TRANSPORT_DEL_ADDRESS 1201

/**
 * @brief inform transport about an incoming message
 */
#define GNUNET_MESSAGE_TYPE_TRANSPORT_INCOMING_MSG 1202

/**
 * @brief transport acknowledges processing an incoming message
 */
#define GNUNET_MESSAGE_TYPE_TRANSPORT_INCOMING_MSG_ACK 1203

/**
 * @brief inform transport that a queue was setup to talk to some peer
 */
#define GNUNET_MESSAGE_TYPE_TRANSPORT_QUEUE_SETUP 1204

/**
 * @brief inform transport that a queue was torn down
 */
#define GNUNET_MESSAGE_TYPE_TRANSPORT_QUEUE_TEARDOWN 1205

/**
 * @brief transport tells communicator it wants a queue
 */
#define GNUNET_MESSAGE_TYPE_TRANSPORT_QUEUE_CREATE 1206

/**
 * Response from communicator: will try to create queue.
 */
#define GNUNET_MESSAGE_TYPE_TRANSPORT_QUEUE_CREATE_OK 1207

/**
 * Response from communicator: address bogus, will not try to create queue.
 */
#define GNUNET_MESSAGE_TYPE_TRANSPORT_QUEUE_CREATE_FAIL 1208

/**
 * @brief transport tells communicator it wants to transmit
 */
#define GNUNET_MESSAGE_TYPE_TRANSPORT_SEND_MSG 1209

/**
 * @brief communicator tells transports that message was sent
 */
#define GNUNET_MESSAGE_TYPE_TRANSPORT_SEND_MSG_ACK 1210

/**
 * Message sent to indicate to the transport which address
 * prefix is supported by a communicator.
 */
#define GNUNET_MESSAGE_TYPE_TRANSPORT_NEW_COMMUNICATOR 1211

/**
 * Tell transport that it should assist with exchanging a
 * message between communicators.  Usually used when
 * communciators are uni-directional and need an alternative
 * back-channel.
 */
#define GNUNET_MESSAGE_TYPE_TRANSPORT_COMMUNICATOR_BACKCHANNEL 1212

/**
 * Message type used between transport services when they
 * internally forward communicator backchannel messages.
 */
#define GNUNET_MESSAGE_TYPE_TRANSPORT_BACKCHANNEL_ENCAPSULATION 1213

/**
 * Type of a fragment of a CORE message created by transport to adjust
 * message length to a queue's MTU.
 */
#define GNUNET_MESSAGE_TYPE_TRANSPORT_FRAGMENT 1214

/**
 * Wrapper around non-fragmented CORE message used to measure RTT
 * and ensure reliability.
 */
#define GNUNET_MESSAGE_TYPE_TRANSPORT_RELIABILITY_BOX 1216

/**
 * Confirmation for a #GNUNET_MESSAGE_TYPE_TRANSPORT_RELIABILITY_BOX.
 */
#define GNUNET_MESSAGE_TYPE_TRANSPORT_RELIABILITY_ACK 1217

/**
 * Message sent for topology discovery at transport level.
 */
#define GNUNET_MESSAGE_TYPE_TRANSPORT_DV_LEARN 1218

/**
 * Source-routed transport message based DV information gathered.
 */
#define GNUNET_MESSAGE_TYPE_TRANSPORT_DV_BOX 1219

/**
 * Transport signalling incoming backchannel message to a communicator.
 */
#define GNUNET_MESSAGE_TYPE_TRANSPORT_COMMUNICATOR_BACKCHANNEL_INCOMING 1220

/**
 * Transport signalling incoming backchannel message to a communicator.
 */
#define GNUNET_MESSAGE_TYPE_TRANSPORT_FLOW_CONTROL 1221

/**
 * @brief inform transport that a queue was updated
 */
#define GNUNET_MESSAGE_TYPE_TRANSPORT_QUEUE_UPDATE 1222

/**
 * Message sent to indicate to the transport that a monitor
 * wants to observe certain events.
 */
#define GNUNET_MESSAGE_TYPE_TRANSPORT_MONITOR_START 1250

/**
 * Message sent to indicate to a monitor about events.
 */
#define GNUNET_MESSAGE_TYPE_TRANSPORT_MONITOR_DATA 1251

/**
 * Message sent to indicate to a monitor that a one-shot
 * iteration over events is done.
 */
#define GNUNET_MESSAGE_TYPE_TRANSPORT_MONITOR_END 1252

/**
 * Message exchanged between communicators to confirm
 * successful KX (and address validation).
 */
#define GNUNET_MESSAGE_TYPE_TRANSPORT_COMMUNICATOR_KX_CONFIRMATION 1275

/**
 * Message exchanged between communicators to exchange
 * flow control (FC) limits and acknowledgemets.
 */
#define GNUNET_MESSAGE_TYPE_TRANSPORT_COMMUNICATOR_FC_LIMITS 1276

/**
 * Type of the 'struct ExpressPreferenceMessage' send by clients to TRANSPORT
 * to establish bandwidth preference.
 */
#define GNUNET_MESSAGE_TYPE_TRANSPORT_SUGGEST 1300

/**
 * Type of the 'struct ExpressPreferenceMessage' send by clients to TRANSPORT
 * to abandon bandwidth preference.
 */
#define GNUNET_MESSAGE_TYPE_TRANSPORT_SUGGEST_CANCEL 1301

/**
 * Type of the 'struct RequestHelloValidationMessage' send by clients to
 * TRANSPORT to trigger validation of addresses.
 */
#define GNUNET_MESSAGE_TYPE_TRANSPORT_REQUEST_HELLO_VALIDATION 1302


/**
 * P2P message: transport requests confirmation that an address works.
 */
#define GNUNET_MESSAGE_TYPE_TRANSPORT_ADDRESS_VALIDATION_CHALLENGE 1303

/**
 * P2P message: transport proves that an address worked.
 */
#define GNUNET_MESSAGE_TYPE_TRANSPORT_ADDRESS_VALIDATION_RESPONSE 1304


/* ************** NEW (NG) ATS Messages ************* */
/* NOTE: it is not clear ATS will survive in TNG      */

/**
 * Type of the 'struct ExpressPreferenceMessage' send by clients to ATS
 * to establish bandwidth preference.
 */
#define GNUNET_MESSAGE_TYPE_ATS_SUGGEST 1400

/**
 * Type of the 'struct ExpressPreferenceMessage' send by clients to ATS
 * to abandon bandwidth preference.
 */
#define GNUNET_MESSAGE_TYPE_ATS_SUGGEST_CANCEL 1401


/**
 * Type of the 'struct SessionAddMessage' send by transport clients to ATS
 * to ask ATS to allocate resources to a session.
 */
#define GNUNET_MESSAGE_TYPE_ATS_SESSION_ADD 1402

/**
 * Type of the 'struct SessionAddMessage' send by transport clients to ATS
 * to inform ATS about a session where resources are consumed but allocation
 * is impossible (unidirectional).
 */
#define GNUNET_MESSAGE_TYPE_ATS_SESSION_ADD_INBOUND_ONLY 1403

/**
 * Type of the 'struct SessionUpdateMessage' send by transport clients to ATS
 * to inform ATS about property changes of a session.
 */
#define GNUNET_MESSAGE_TYPE_ATS_SESSION_UPDATE 1404

/**
 * Type of the 'struct SessionDelMessage' send by transport clients to ATS
 * to tell ATS that a session is no longer available.
 */
#define GNUNET_MESSAGE_TYPE_ATS_SESSION_DEL 1405

/**
 * Type of the 'struct SessionAllocationMessage' send by ATS to the
 * transport to tell it about resources to allocate to the session.
 */
#define GNUNET_MESSAGE_TYPE_ATS_SESSION_ALLOCATION 1406


/**
 * TCP communicator rekey message.
 */
#define GNUNET_MESSAGE_TYPE_COMMUNICATOR_TCP_REKEY 1450

/**
 * TCP communicator payload box
 */
#define GNUNET_MESSAGE_TYPE_COMMUNICATOR_TCP_BOX 1451

/**
 * TCP communicator end of stream.
 */
#define GNUNET_MESSAGE_TYPE_COMMUNICATOR_TCP_FINISH 1452

/**
 * UDP KX acknowledgement.
 */
#define GNUNET_MESSAGE_TYPE_COMMUNICATOR_UDP_ACK 1460

/**
 * UDP communicator padding.
 */
#define GNUNET_MESSAGE_TYPE_COMMUNICATOR_UDP_PAD 1461

/**
 * Next available: 1500
 */
#define GNUNET_MESSAGE_TYPE_RECLAIM_REFERENCE_DELETE 1500

#define GNUNET_MESSAGE_TYPE_RECLAIM_REFERENCE_RESULT 1501


/**
 * Type used to match 'all' message types.
 */
#define GNUNET_MESSAGE_TYPE_ALL 65535


#if 0 /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

/* ifndef GNUNET_PROTOCOLS_H */
#endif

/** @} */ /* end of group protocols */

/* end of gnunet_protocols.h */

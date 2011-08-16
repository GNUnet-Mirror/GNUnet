/*
     This file is part of GNUnet.
     (C) 2009 Christian Grothoff (and other contributing authors)

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
 * @file include/gnunet_transport_service.h
 * @brief low-level P2P IO
 * @author Christian Grothoff
 */

#ifndef GNUNET_TRANSPORT_SERVICE_H
#define GNUNET_TRANSPORT_SERVICE_H

#ifdef __cplusplus
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif

#include "gnunet_bandwidth_lib.h"
#include "gnunet_configuration_lib.h"
#include "gnunet_crypto_lib.h"
#include "gnunet_connection_lib.h"
#include "gnunet_scheduler_lib.h"
#include "gnunet_time_lib.h"

/**
 * Version number of the transport API.
 */
#define GNUNET_TRANSPORT_VERSION 0x00000000


/**
 * Enum defining all known property types for ATS Enum values are used
 * in the GNUNET_TRANSPORT_ATS_Information struct as
 * (key,value)-pairs.
 *
 * Cost are always stored in uint32_t, so all units used to define costs
 * have to be normalized to fit in uint32_t [0 .. 4.294.967.295]
 *
 * To keep the elements ordered
 *    1..1024 : Values with a relation to cost
 * 1025..2048 : Values with a relation to quality
 * 2049..3072 : Values with a relation to availability
 *
 */
enum GNUNET_TRANSPORT_ATS_Property
{

  /**
   * End of the array.
   */
  GNUNET_TRANSPORT_ATS_ARRAY_TERMINATOR = 0,

  /* Cost related values */
  /* =================== */

  /**
   * Volume based cost in financial units to transmit data
   *
   * Note: This value is not bound to a specific currency or unit and only
   * used locally.
   * "cent" just refers the smallest amount of money in the respective
   * currency.
   *
   * Unit: [cent/MB]
   *
   * Interpretation: less is better
   *
   * Examples:
   * LAN:  0 [cent/MB]
   * 2G : 10 [cent/MB]
   */
  GNUNET_TRANSPORT_ATS_COST_FINANCIAL_PER_VOLUME = 1,

  /**
   * Time based cost in financial units to transmit data
   *
   * Note: This value is not bound to a specific currency or unit and only
   * used locally.
   * "cent" just refers the smallest amount of money in the respective
   * currency.
   *
   * Unit: [cent/h]
   *
   * Interpretation: less is better
   *
   * Examples:
   * LAN   :  0 [cent/h]
   * Dialup: 10 [cent/h]
   */
  GNUNET_TRANSPORT_ATS_COST_FINANCIAL_PER_TIME = 2,

  /**
   * Computational costs
   *
   * Effort of preparing data to be sent with this transport
   * Includes encoding, encryption and conversion of data
   * Partial values can be summed up: c_sum = c_enc + c_enc + c_conv
   * Resulting values depend on local system properties, e.g. CPU
   *
   * Unit: [ms/GB]
   *
   * Interpretation: less is better
   *
   * Examples:
   *
   * HTTPS with AES CBC-256: 	7,382
   * HTTPS with AES CBC-128: 	5,279
   * HTTPS with RC4-1024: 	2,652
   */
  GNUNET_TRANSPORT_ATS_COST_COMPUTATIONAL = 3,

  /**
   * Energy consumption
   *
   * Energy consumption using this transport when sending with a certain
   * power at a certain bitrate. This is only an approximation based on:
   * Energy consumption E = P / D
   *
   * with:
   * Power P in Watt (J/s)
   * Datarate D in MBit/s
   *
   * Conversion between power P and dBm used by WLAN in radiotap's dBm TX power:
   *
   * Lp(dbm) = 10 log10 (P/ 1mW)
   *
   * => P = 1 mW  * 10^(Lp(dbm)/10)
   *
   * Unit: [mJ/MB]
   *
   * Interpretation: less is better
   *
   * Examples:
   *
   * LAN:       0
   * WLAN:      89 (600 mW @ 802.11g /w 54 MBit/s)
   * Bluetooth: 267 (100 mW @ BT2.0 EDR /w 3 MBit/s)
   */
  GNUNET_TRANSPORT_ATS_COST_ENERGY_CONSUMPTION = 4,

  /**
   * Connect cost
   * How many bytes are transmitted to initiate a new connection using
   * this transport?
   *
   * Unit: [bytes]
   *
   * Interpretation: less is better
   *
   * Examples:
   *
   * UDP (No connection)      :
   *     0 bytes
   * TCP (TCP 3-Way handshake):
   *   220 bytes Ethernet,  172 bytes TCP/IP,  122 bytes TCP
   * HTTP (TCP + Header)      :
   *   477 bytes Ethernet,  429 bytes TCP/IP,  374 bytes TCP,  278 bytes HTTP
   * HTTPS  HTTP+TLS Handshake:
   *  2129 bytes Ethernet, 1975 bytes TCP/IP, 1755 bytes TCP, 1403 bytes HTTPS
   *
   * */
  GNUNET_TRANSPORT_ATS_COST_CONNECT = 5,

  /**
   * Bandwidth cost
   *
   * How many bandwidth is available to consume?
   * Used to calculate which impact sending data with this transport has
   *
   * Unit: [kB/s]
   *
   * Interpretation: more is better
   *
   * Examples:
   * LAN:     12,800  (100 MBit/s)
   * WLAN:    6,912   (54 MBit/s)
   * Dial-up: 8       (64 Kbit/s)
   *
   */
  GNUNET_TRANSPORT_ATS_COST_BANDWITH_AVAILABLE = 6,

  /**
   *  Network overhead
   *
   * How many bytes are sent over the wire when 1 kilobyte (1024 bytes)
   * of application data is transmitted?
   * A factor used with connect cost, bandwidth cost and energy cost
   * to describe the overhead produced by the transport protocol
   *
   * Unit: [bytes/kb]
   *
   * Interpretation: less is better
   *
   * Examples:
   *
   * TCP/IPv4 over Ethernet: 1024 + 38 + 20 + 20 = 1102 [bytes/kb]
   * TCP/IPv6 over Ethernet: 1024 + 38 + 20 + 40 = 1122 [bytes/kb]
   * UDP/IPv4 over Ethernet: 1024 + 38 + 20 + 8  = 1090 [bytes/kb]
   * UDP/IPv6 over Ethernet: 1024 + 38 + 40 + 8  = 1110 [bytes/kb]
   */
  GNUNET_TRANSPORT_ATS_COST_NETWORK_OVERHEAD = 7,


  /* Quality related values */
  /* ====================== */

  /* Physical layer quality properties */

  /**
   * Signal strength on physical layer
   *
   * Unit: [dBm]
   */
  GNUNET_TRANSPORT_ATS_QUALITY_PHY_SIGNAL_STRENGTH = 1025,

  /**
   * Collision rate on physical layer
   *
   * Unit: [B/s]
   */
  GNUNET_TRANSPORT_ATS_QUALITY_PHY_COLLISION_RATE = 1026,

  /**
   * Error rate on physical layer
   *
   * Unit: [B/s]
   */
  GNUNET_TRANSPORT_ATS_QUALITY_PHY_ERROR_RATE = 1027,

  /* Network layer quality properties */

  /**
   * Delay
   * Time between when the time packet is sent and the packet arrives
   *
   * Unit: [ms]
   *
   * Examples:
   *
   * LAN   :    1
   * WLAN  :    2
   * Dialup:  500
   */
  GNUNET_TRANSPORT_ATS_QUALITY_NET_DELAY = 1028,

  /**
   * Jitter
   * Time variations of the delay
   * 1st derivative of a delay function
   *
   * Unit: [ms]
   */
  GNUNET_TRANSPORT_ATS_QUALITY_NET_JITTER = 1029,

  /**
   * Error rate on network layer
   *
   * Unit: [B/s]
   *
   * Examples:
   *
   * LAN       :    0
   * WLAN      :  400
   * Bluetooth :  100
   * Note: This numbers are just assumptions as an example, not
   * measured or somehow determined
   */
  GNUNET_TRANSPORT_ATS_QUALITY_NET_ERRORRATE = 1030,

  /**
   * Drop rate on network layer
   * Bytes actively dismissed by a network component during transmission
   * Reasons for dropped data can be full queues, congestion, quota violations...
   *
   * Unit: [B/s]
   *
   * Examples:
   *
   * LAN       :    0
   * WLAN      :  400
   * Bluetooth :  100
   * Note: This numbers are just assumptions as an example, not
   * measured or somehow determined
   */
  GNUNET_TRANSPORT_ATS_QUALITY_NET_DROPRATE = 1031,

  /**
   * Loss rate on network layer
   * Bytes lost during transmission
   * Reasons can be collisions, ...
   *
   * Unit: [B/s]
   *
   * Examples:
   *
   * LAN       :    0
   * WLAN      :   40
   * Bluetooth :   10
   * Note: This numbers are just assumptions as an example, not measured
   * or somehow determined
   */
  GNUNET_TRANSPORT_ATS_QUALITY_NET_LOSSRATE = 1032,

  /**
   * Throughput on network layer
   *
   * Unit: [kB/s]
   *
   * Examples:
   *
   * LAN   : 3400
   * WLAN  : 1200
   * Dialup: 	  4
   *
   */
  GNUNET_TRANSPORT_ATS_QUALITY_NET_THROUGHPUT = 1033,

 /**
  * Distance on network layer
  *
  * Unit: []
  */
  GNUNET_TRANSPORT_ATS_QUALITY_NET_DISTANCE = 1034,


  /* Availability related values */
  /* =========================== */

  /**
   * Is a peer reachable?
   */
  GNUNET_TRANSPORT_ATS_AVAILABILITY_REACHABLE = 2048,

  /**
   * Is there a connection established to a peer using this transport
   */
  GNUNET_TRANSPORT_ATS_AVAILABILITY_CONNECTED = 2049
};


/**
 * struct used to communicate the transport's properties like cost and
 * quality of service as well as high-level constraints on resource
 * consumption.
 *
 *                             +---+
 *  +-----------+ Constraints  |   |  Plugin properties +---------+
 *  | Highlevel |------------> |ATS| <------------------|Transport|
 *  | Component | ATS struct   |   |    ATS struct      | Plugin  |
 *  +-----------+              |   |                    +---------+
 *                             +---+
 *
 * This structure will be used by transport plugins to communicate
 * costs to ATS or by higher level components to tell ATS their
 * constraints.  Always a pair of (GNUNET_TRANSPORT_ATS_Property,
 * uint32_t value).  Value is always uint32_t, so all units used to
 * define costs have to be normalized to fit uint32_t.
 */
struct GNUNET_TRANSPORT_ATS_Information
{
  /**
   * ATS property type, in network byte order.
   */
  uint32_t type;

  /**
   * ATS property value, in network byte order.
   */
  uint32_t value;
};



/**
 * Function called by the transport for each received message.
 *
 * @param cls closure
 * @param peer (claimed) identity of the other peer
 * @param message the message
 * @param ats performance data
 * @param ats_count number of entries in ats (excluding 0-termination)
 */
typedef void (*GNUNET_TRANSPORT_ReceiveCallback) (void *cls,
                                                  const struct
                                                  GNUNET_PeerIdentity * peer,
                                                  const struct
                                                  GNUNET_MessageHeader *
                                                  message,
                                                  const struct
                                                  GNUNET_TRANSPORT_ATS_Information
                                                  * ats, uint32_t ats_count);


/**
 * Opaque handle to the service.
 */
struct GNUNET_TRANSPORT_Handle;


/**
 * Function called to notify transport users that another
 * peer connected to us.
 *
 * @param cls closure
 * @param peer the peer that connected
 * @param ats performance data
 * @param ats_count number of entries in ats (excluding 0-termination)
 */
typedef void (*GNUNET_TRANSPORT_NotifyConnect) (void *cls,
                                                const struct GNUNET_PeerIdentity
                                                * peer,
                                                const struct
                                                GNUNET_TRANSPORT_ATS_Information
                                                * ats, uint32_t ats_count);

/**
 * Function called to notify transport users that another
 * peer disconnected from us.
 *
 * @param cls closure
 * @param peer the peer that disconnected
 */
typedef void (*GNUNET_TRANSPORT_NotifyDisconnect) (void *cls,
                                                   const struct
                                                   GNUNET_PeerIdentity * peer);


/**
 * Function to call with a human-readable format of an address
 *
 * @param cls closure
 * @param address NULL on error, otherwise 0-terminated printable UTF-8 string
 */
typedef void (*GNUNET_TRANSPORT_AddressLookUpCallback) (void *cls,
                                                        const char *address);


/**
 * Connect to the transport service.  Note that the connection may
 * complete (or fail) asynchronously.
 *
 * @param cfg configuration to use
 * @param self our own identity (API should check that it matches
 *             the identity found by transport), or NULL (no check)
 * @param cls closure for the callbacks
 * @param rec receive function to call
 * @param nc function to call on connect events
 * @param nd function to call on disconnect events
 * @return NULL on error
 */
struct GNUNET_TRANSPORT_Handle *
GNUNET_TRANSPORT_connect (const struct GNUNET_CONFIGURATION_Handle *cfg,
                          const struct GNUNET_PeerIdentity *self, void *cls,
                          GNUNET_TRANSPORT_ReceiveCallback rec,
                          GNUNET_TRANSPORT_NotifyConnect nc,
                          GNUNET_TRANSPORT_NotifyDisconnect nd);


/**
 * Disconnect from the transport service.
 *
 * @param handle handle returned from connect
 */
void
GNUNET_TRANSPORT_disconnect (struct GNUNET_TRANSPORT_Handle *handle);


/**
 * Ask the transport service to establish a connection to 
 * the given peer.
 *
 * @param handle connection to transport service
 * @param target who we should try to connect to
 */
void
GNUNET_TRANSPORT_try_connect (struct GNUNET_TRANSPORT_Handle *handle,
                              const struct GNUNET_PeerIdentity *target);


/**
 * Set the share of incoming/outgoing bandwidth for the given
 * peer to the specified amount.
 *
 * @param handle connection to transport service
 * @param target who's bandwidth quota is being changed
 * @param quota_in incoming bandwidth quota
 * @param quota_out outgoing bandwidth quota
 */
void
GNUNET_TRANSPORT_set_quota (struct GNUNET_TRANSPORT_Handle *handle,
                            const struct GNUNET_PeerIdentity *target,
                            struct GNUNET_BANDWIDTH_Value32NBO quota_in,
                            struct GNUNET_BANDWIDTH_Value32NBO quota_out);


/**
 * Opaque handle for a transmission-ready request.
 */
struct GNUNET_TRANSPORT_TransmitHandle;


/**
 * Check if we could queue a message of the given size for
 * transmission.  The transport service will take both its internal
 * buffers and bandwidth limits imposed by the other peer into
 * consideration when answering this query.
 *
 * @param handle connection to transport service
 * @param target who should receive the message
 * @param size how big is the message we want to transmit?
 * @param priority how important is the message?
 * @param timeout after how long should we give up (and call
 *        notify with buf NULL and size 0)?
 * @param notify function to call when we are ready to
 *        send such a message
 * @param notify_cls closure for notify
 * @return NULL if someone else is already waiting to be notified
 *         non-NULL if the notify callback was queued (can be used to cancel
 *         using GNUNET_TRANSPORT_notify_transmit_ready_cancel)
 */
struct GNUNET_TRANSPORT_TransmitHandle *
GNUNET_TRANSPORT_notify_transmit_ready (struct GNUNET_TRANSPORT_Handle *handle,
                                        const struct GNUNET_PeerIdentity
                                        *target, size_t size, uint32_t priority,
                                        struct GNUNET_TIME_Relative timeout,
                                        GNUNET_CONNECTION_TransmitReadyNotify
                                        notify, void *notify_cls);


/**
 * Cancel the specified transmission-ready notification.
 *
 * @param th handle of the transmission notification request to cancel
 */
void
GNUNET_TRANSPORT_notify_transmit_ready_cancel (struct
                                               GNUNET_TRANSPORT_TransmitHandle
                                               *th);



/**
 * Function called whenever there is an update to the
 * HELLO of this peer.
 *
 * @param cls closure
 * @param hello our updated HELLO
 */
typedef void (*GNUNET_TRANSPORT_HelloUpdateCallback) (void *cls,
                                                      const struct
                                                      GNUNET_MessageHeader *
                                                      hello);


/**
 * Obtain updates on changes to the HELLO message for this peer.
 *
 * @param handle connection to transport service
 * @param rec function to call with the HELLO
 * @param rec_cls closure for rec
 */
void
GNUNET_TRANSPORT_get_hello (struct GNUNET_TRANSPORT_Handle *handle,
                            GNUNET_TRANSPORT_HelloUpdateCallback rec,
                            void *rec_cls);


/**
 * Stop receiving updates about changes to our HELLO message.
 *
 * @param handle connection to transport service
 * @param rec function previously registered to be called with the HELLOs
 * @param rec_cls closure for rec
 */
void
GNUNET_TRANSPORT_get_hello_cancel (struct GNUNET_TRANSPORT_Handle *handle,
                                   GNUNET_TRANSPORT_HelloUpdateCallback rec,
                                   void *rec_cls);


/**
 * Offer the transport service the HELLO of another peer.  Note that
 * the transport service may just ignore this message if the HELLO is
 * malformed or useless due to our local configuration.
 *
 * @param handle connection to transport service
 * @param hello the hello message
 * @param cont continuation to call when HELLO has been sent
 * @param cls closure for continuation
 *
 */
void
GNUNET_TRANSPORT_offer_hello (struct GNUNET_TRANSPORT_Handle *handle,
                              const struct GNUNET_MessageHeader *hello,
                              GNUNET_SCHEDULER_Task cont, void *cls);


/**
 * Convert a binary address into a human readable address.
 *
 * @param cfg configuration to use
 * @param address address to convert (binary format)
 * @param addressLen number of bytes in address
 * @param numeric should (IP) addresses be displayed in numeric form 
 *                (otherwise do reverse DNS lookup)
 * @param nameTrans name of the transport to which the address belongs
 * @param timeout how long is the lookup allowed to take at most
 * @param aluc function to call with the results
 * @param aluc_cls closure for aluc
 */
void
GNUNET_TRANSPORT_address_lookup (const struct GNUNET_CONFIGURATION_Handle *cfg,
                                 const char *address, size_t addressLen,
                                 int numeric, const char *nameTrans,
                                 struct GNUNET_TIME_Relative timeout,
                                 GNUNET_TRANSPORT_AddressLookUpCallback aluc,
                                 void *aluc_cls);


/**
 * Return all the known addresses for a peer. FIXME: document better!
 * FIXME: use better name!
 *
 * @param cfg configuration to use
 * @param peer peer identity to look up the addresses of
 * @param timeout how long is the lookup allowed to take at most
 * @param peer_address_callback function to call with the results
 * @param peer_address_callback_cls closure for peer_address_callback
 */
void
GNUNET_TRANSPORT_peer_address_lookup (const struct GNUNET_CONFIGURATION_Handle
                                      *cfg,
                                      const struct GNUNET_PeerIdentity *peer,
                                      struct GNUNET_TIME_Relative timeout,
                                      GNUNET_TRANSPORT_AddressLookUpCallback
                                      peer_address_callback,
                                      void *peer_address_callback_cls);


/**
 * Return all the known addresses. FIXME: document better!
 * FIXME: use better name!
 *
 * @param cfg configuration to use
 * @param timeout how long is the lookup allowed to take at most
 * @param peer_address_callback function to call with the results
 * @param peer_address_callback_cls closure for peer_address_callback
 */
void
GNUNET_TRANSPORT_address_iterate (const struct GNUNET_CONFIGURATION_Handle *cfg,
                                  struct GNUNET_TIME_Relative timeout,
                                  GNUNET_TRANSPORT_AddressLookUpCallback
                                  peer_address_callback,
                                  void *peer_address_callback_cls);


/**
 * Handle for blacklisting peers.
 */
struct GNUNET_TRANSPORT_Blacklist;


/**
 * Function that decides if a connection is acceptable or not.
 *
 * @param cls closure
 * @param pid peer to approve or disapproave
 * @return GNUNET_OK if the connection is allowed
 */
typedef int (*GNUNET_TRANSPORT_BlacklistCallback) (void *cls,
                                                   const struct
                                                   GNUNET_PeerIdentity * pid);


/**
 * Install a blacklist callback.  The service will be queried for all
 * existing connections as well as any fresh connections to check if
 * they are permitted.  If the blacklisting callback is unregistered,
 * all hosts that were denied in the past will automatically be
 * whitelisted again.  Cancelling the blacklist handle is also the
 * only way to re-enable connections from peers that were previously
 * blacklisted.
 *
 * @param cfg configuration to use
 * @param cb callback to invoke to check if connections are allowed
 * @param cb_cls closure for cb
 * @return NULL on error, otherwise handle for cancellation
 */
struct GNUNET_TRANSPORT_Blacklist *
GNUNET_TRANSPORT_blacklist (const struct GNUNET_CONFIGURATION_Handle *cfg,
                            GNUNET_TRANSPORT_BlacklistCallback cb,
                            void *cb_cls);


/**
 * Abort the blacklist.  Note that this function is the only way for
 * removing a peer from the blacklist.
 *
 * @param br handle of the request that is to be cancelled
 */
void
GNUNET_TRANSPORT_blacklist_cancel (struct GNUNET_TRANSPORT_Blacklist *br);



#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

/* ifndef GNUNET_TRANSPORT_SERVICE_H */
#endif
/* end of gnunet_transport_service.h */

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
 * @file transport/transport_selection.h
 * @brief structure definition for automatic transport selection (ATS)
 * @author Matthias Wachs
 */

/**
 *  The structs defined here are used by the transport plugin to tell ATS about the transport's properties like cost and quality
 *  and on the other side the structs are used by highlevel components to communicate the constraints they have for a transport to ATS
 *
 *                             +---+
 *  +-----------+ Constraints  |   |  Plugin properties +---------+
 *  | Highlevel |------------> |ATS| <------------------|Transport|
 *  | Component | ATS struct   |   |    ATS struct      | Plugin  |
 *  +-----------+              |   |                    +---------+
 *                             +---+
 *
 */

#define GNUNET_ATS_ARRAY_TERMINATOR 0

/**
 * Enum defining all known property types for ATS
 * Enum values are used in the GNUNET_ATS_Information struct as (key,value)-pair
 * Cost are always stored in uint32_t, so all units used to define costs have to be normalized to fit in uint32_t [0 .. 4.294.967.295]
 * To keep the elements ordered
 *    1..1024 : Values with a relation to cost
 * 1025..2048 : Values with a relation to quality
 *
 */
enum GNUNET_ATS_Property
{

	/* Cost related values */
	/* =================== */

	/**
	 * Volume based cost in financial units to transmit data
	 *
	 * Note: This value is not bound to a specific currency or unit and only used locally
	 * "cent" just refers the smallest amount of money in the respective currency
	 *
	 * Unit: [cent/MB]
	 *
	 * Interpretation: less is better
	 *
	 * Examples:
	 * LAN:  0 [cent/MB]
	 * 2G : 10 [cent/MB]
	 */
	GNUNET_ATS_COST_FINANCIAL_PER_VOLUME = 1,

	/**
	 * Time based cost in financial units to transmit data
	 *
	 * Note: This value is not bound to a specific currency or unit and only used locally
	 * "cent" just refers the smallest amount of money in the respective currency
	 *
	 * Unit: [cent/h]
	 *
	 * Interpretation: less is better
	 *
	 * Examples:
	 * LAN   :  0 [cent/h]
	 * Dialup: 10 [cent/h]
	 */
	GNUNET_ATS_COST_FINANCIAL_PER_TIME = 2,

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
	GNUNET_ATS_COST_COMPUTATIONAL = 3,

	/**
	 * Energy consumption
	 *
	 * Energy consumption using this transport when sending with a certain power at a certain bitrate
	 * This is only an approximation based on:
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
	GNUNET_ATS_COST_ENERGY_CONSUMPTION = 4,

	/**
	 * Connect cost
	 * How many bytes are transmitted to initiate a new connection using this transport?
	 *
	 * Unit: [bytes]
	 *
	 * Interpretation: less is better
	 *
	 * Examples:
	 *
	 * UDP (No connection)      :    0 bytes
	 * TCP (TCP 3-Way handshake):  220 bytes Ethernet,  172 bytes TCP/IP,  122 bytes TCP
	 * HTTP (TCP + Header)      :  477 bytes Ethernet,  429 bytes TCP/IP,  374 bytes TCP,  278 bytes HTTP
	 * HTTPS  HTTP+TLS Handshake: 2129 bytes Ethernet, 1975 bytes TCP/IP, 1755 bytes TCP, 1403 bytes HTTPS
	 *
	 * */
	GNUNET_ATS_COST_CONNECT = 5,

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
	GNUNET_ATS_COST_BANDWITH_AVAILABLE = 6,

	/**
	 *  Network overhead
	 *
	 * How many bytes are sent over the wire when 1 kilobyte (1024 bytes) of application data is transmitted?
	 * A factor used with connect cost, bandwidth cost and energy cost to describe the overhead produced by the transport protocol
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
	GNUNET_ATS_COST_NETWORK_OVERHEAD = 7,


	/* Quality related values */
	/* ====================== */

    /* Physical layer quality properties */

	/**
	 * Signal strength on physical layer
	 *
	 * Unit: [dBm]
	 */
	GNUNET_ATS_QUALITY_PHY_SIGNAL_STRENGTH = 1025,

	/**
	 * Collision rate on physical layer
	 *
	 * Unit: [B/s]
	 */
	GNUNET_ATS_QUALITY_PHY_COLLISION_RATE = 1026,

	/**
	 * Error rate on physical layer
	 *
	 * Unit: [B/s]
	 */
	GNUNET_ATS_QUALITY_PHY_ERROR_RATE = 1027,

    /* Network layer quality properties */

	/**
	 * Delay
	 * Time between when the time packet is sent and the packet arrives
	 *
	 * Unit: [μs]
	 *
	 * Examples:
	 *
	 * LAN   :  180
	 * Dialup: 4000
	 * WLAN  : 7000
	 */
	GNUNET_ATS_QUALITY_NET_DELAY = 1028,

	/**
	 * Jitter
	 * Time variations of the delay
	 * 1st derivative of a delay function
	 *
	 * Unit: [μs]
	 */
	GNUNET_ATS_QUALITY_NET_JITTER = 1029,

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
	 * Note: This numbers are just assumptions as an example, not measured or somehow determined
	 */
	GNUNET_ATS_QUALITY_NET_ERRORRATE = 1030,

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
	 * Note: This numbers are just assumptions as an example, not measured or somehow determined
	 */
	GNUNET_ATS_QUALITY_NET_DROPRATE = 1031,

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
	 * Note: This numbers are just assumptions as an example, not measured or somehow determined
	 */
	GNUNET_ATS_QUALITY_NET_LOSSRATE = 1032,

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
	GNUNET_ATS_QUALITY_NET_THROUGHPUT = 1033
};

/**
 * This structure will be used by plugins to communicate costs to ATS or by higher level components to tell ATS their constraints
 * Always a pair of (GNUNET_ATS_Property, uint32_t value)
 * Value is always uint32_t, so all units used to define costs have to be normalized to fit uint32_t
 */
struct GNUNET_ATS_Information
{
	/**
	 * ATS property type
	 */
	uint32_t type;

	/**
	 * ATS property value
	 */
	uint32_t value;
};



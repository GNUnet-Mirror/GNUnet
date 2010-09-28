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
 * Enum defining all known cost types for ATS
 * Enum values are used in the GNUNET_ATS_Cost_Information struct as (key,value)-pair
 * Cost are always stored in uint32_t, so all units used to define costs have to be normalized to fit in uint32_t [0 .. 4.294.967.295]
 */

enum GNUNET_ATS_Cost_Type
{
	/*
	 * Cost will be passed as struct GNUNET_ATS_Cost_Information[]
	 * array is 0-terminated:
	 * the last element in the array is the pair (GNUNET_ATS_ARRAY_TERMINATOR, 0)
	 */
	GNUNET_ATS_ARRAY_TERMINATOR= 0,

	/* Volume based cost in financial units to transmit data
	 * Note: this value is not bound to a specific currency or unit and only used locally
	 *
	 * Unit: [1/MB]
	 *
	 * Interpretation: less is better
	 *
	 * Examples:
	 * LAN: 0
	 * 2G:  10
	 */
	GNUNET_ATS_FINANCIAL_PER_VOLUME_COST = 1,

	/* Time based cost in financial units to transmit data
	 * Note: this value is not bound to a specific currency or unit
	 *
	 * Unit: [1/h]
	 *
	 * Interpretation: less is better
	 *
	 * Examples:
	 * LAN: 0
	 * Dialup: 10
	 */
	GNUNET_ATS_FINANCIAL_PER_TIME_COST = 2,

	/* Computational costs
	 * Effort of preparing data to send with this transport
	 * Includes encoding, encryption and conversion of data
	 * Partial values can be summed: c_sum = c_enc + c_conv + c_enc
	 * Resulting value depends on local system properties, e.g. CPU
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
	GNUNET_ATS_COMPUTATIONAL_COST = 3,

	/* Energy consumption
	 * Energy consumption using this transport when sending with a certain power at a certain bitrate
	 * This is only an approximation based on:
	 * Energy consumption E = P / D
	 *
	 * with:
	 * Power P in Watt (J/s)
	 * Datarate D in MBit/s
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
	GNUNET_ATS_ENERGY_CONSUMPTION = 4,

	/* Connect cost
	 * How expensive is it to initiate a new connection using this transport
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
	GNUNET_ATS_CONNECT_COST = 5,

	/* Bandwidth cost
	 * How many bandwidth is available to consume
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
	GNUNET_ATS_BANDWITH_COST = 6,

	/* Network overhead
	 * a factor used with connect cost, bandwidth cost and energy cost to describe the overhead produced by the transport protocol
	 *
	 * Unit: [10,000 - (Efficiency in Percent * 100)]
	 *
	 * Interpretation: less is better
	 *
	 * Examples:
	 *
	 * TCP/IPv4 over Ethernet: 507 (Efficiency: 94,93 %)
	 * TCP/IPv6 over Ethernet: 646 (Efficiency: 93,64 %)
	 * UDP/IPv4 over Ethernet: 429 (Efficiency: 95,71 %)
	 * UDP/IPv6 over Ethernet: 559 (Efficiency: 94,41 %)
	 */
	GNUNET_ATS_NETWORK_OVERHEAD_COST = 7,
};

/**
 * This structure will be used by plugins to communicate costs to ATS
 * Always a pair of (GNUNET_ATS_Cost_Types, uint32_t value)
 * Value is always uint32_t, so all units used to define costs have to be normalized to fit uint32_t
 */
struct GNUNET_ATS_Cost_Information
{
	/**
	 * ATS Cost Type
	 */
	uint32_t cost_type;

	/**
	 * ATS Cost value
	 */
	uint32_t cost_value;
};

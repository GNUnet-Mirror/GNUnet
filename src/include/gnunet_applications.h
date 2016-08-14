/*
     This file is part of GNUnet.
     Copyright (C) 2011, 2016 GNUnet e.V.

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
     Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
     Boston, MA 02110-1301, USA.
*/

/**
 * @author Christian Grothoff
 *
 * @file
 * Constants for network applications operating on top of the CADET service
 *
 * @defgroup applications  CADET application definitions
 * Constants for network applications operating on top of the CADET service.
 * @{
 */

#ifndef GNUNET_APPLICATIONS_H
#define GNUNET_APPLICATIONS_H

#ifdef __cplusplus
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif

/**
 * End of list marker.
 */
#define GNUNET_APPLICATION_TYPE_END 0

/**
 * Test.
 */
#define GNUNET_APPLICATION_TYPE_TEST 1

/**
 * Transfer of blocks for non-anonymmous file-sharing.
 */
#define GNUNET_APPLICATION_PORT_FS_BLOCK_TRANSFER "fs-block"

/**
 * Transfer of blocks for random peer sampling.
 */
#define GNUNET_APPLICATION_PORT_RPS "rps"

/**
 * Internet DNS resolution (external DNS gateway).  This is a "well-known"
 * service a peer may offer over CADET where the port is the hash of this
 * string.
 */
#define GNUNET_APPLICATION_PORT_INTERNET_RESOLVER "exit-dns"

/**
 * Internet IPv4 gateway (any TCP/UDP/ICMP).
 */
#define GNUNET_APPLICATION_PORT_IPV4_GATEWAY "exit-ipv4"

/**
 * Internet IPv6 gateway (any TCP/UDP/ICMP).
 */
#define GNUNET_APPLICATION_PORT_IPV6_GATEWAY "exit-ipv6"

/**
 * Internet exit regex prefix. Consisting of application ID, followed
 * by version and padding.
 */
#define GNUNET_APPLICATION_TYPE_EXIT_REGEX_PREFIX "GNUNET-VPN-VER-0001-"

/**
 * Consensus.
 *
 * @deprecated
 */
#define GNUNET_APPLICATION_TYPE_CONSENSUS 18

/**
 * Set. Used for two-peer set operations implemented using stream.
 * @deprecated
 */
#define GNUNET_APPLICATION_TYPE_SET 19

/**
 * Conversation control data.
 * @deprecated
 */
#define GNUNET_APPLICATION_TYPE_CONVERSATION_CONTROL 21

/**
 * Conversation audio data.
 * @deprecated
 */
#define GNUNET_APPLICATION_TYPE_CONVERSATION_AUDIO 22

/**
 * MQTT publish-subscribe.
 * @deprecated
 */
#define GNUNET_APPLICATION_TYPE_MQTT 23

/**
 * Multicast data.
 * @deprecated
 */
#define GNUNET_APPLICATION_TYPE_MULTICAST 26


#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

/* ifndef GNUNET_APPLICATIONS_H */
#endif

/** @} */  /* end of group */

/* end of gnunet_applications.h */

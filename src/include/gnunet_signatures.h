/*
     This file is part of GNUnet.
     Copyright (C) 2009 GNUnet e.V.

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
 * Constants for network signatures
 *
 * @defgroup signatures  Network signature definitions
 * @{
 */

#ifndef GNUNET_SIGNATURES_H
#define GNUNET_SIGNATURES_H

#ifdef __cplusplus
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif

/**
 * Test signature, not valid for anything other than writing
 * a test. (Note that the signature verification code will
 * accept this value).
 */
#define GNUNET_SIGNATURE_PURPOSE_TEST 0

/**
 * Signature for confirming that this peer uses a particular address.
 */
#define GNUNET_SIGNATURE_PURPOSE_TRANSPORT_PONG_OWN 1

/**
 * Signature for confirming that this peer intends to disconnect.
 */
#define GNUNET_SIGNATURE_PURPOSE_TRANSPORT_DISCONNECT 2

/**
 * Signature for confirming a key revocation.
 */
#define GNUNET_SIGNATURE_PURPOSE_REVOCATION 3

/**
 * Signature for a namespace/pseudonym advertisement (by
 * the namespace owner).
 */
#define GNUNET_SIGNATURE_PURPOSE_NAMESPACE_ADVERTISEMENT 4

/**
 * Signature by which a peer affirms that it is
 * providing a certain bit of content (used
 * in LOCation URIs).
 */
#define GNUNET_SIGNATURE_PURPOSE_PEER_PLACEMENT 5

/**
 * Obsolete, legacy value.
 */
#define GNUNET_SIGNATURE_PURPOSE_FS_KBLOCK 6

/**
 * Obsolete, legacy value.
 */
#define GNUNET_SIGNATURE_PURPOSE_FS_SBLOCK 7

/**
 * Obsolete, legacy value.
 */
#define GNUNET_SIGNATURE_PURPOSE_FS_NBLOCK 8

/**
 * Obsolete, legacy value.
 */
#define GNUNET_SIGNATURE_PURPOSE_FS_NBLOCK_KSIG 9

/**
 *
 */
#define GNUNET_SIGNATURE_PURPOSE_RESOLVER_RESPONSE 10

/**
 * Signature of an GNUNET_DNS_Advertisement
 */
#define GNUNET_SIGNATURE_PURPOSE_DNS_RECORD 11

/**
 * Signature of a chat message.
 */
#define GNUNET_SIGNATURE_PURPOSE_CHAT_MESSAGE 12

/**
 * Signature of confirmation receipt for a chat message.
 */
#define GNUNET_SIGNATURE_PURPOSE_CHAT_RECEIPT 13

/**
 * Signature of a network size estimate message.
 */
#define GNUNET_SIGNATURE_PURPOSE_NSE_SEND 14

/**
 * Signature of a gnunet naming system record block
 */
#define GNUNET_SIGNATURE_PURPOSE_GNS_RECORD_SIGN 15

/**
 * Purpose is to set a session key.
 */
#define GNUNET_SIGNATURE_PURPOSE_SET_ECC_KEY 16

/**
 * UBlock Signature, done using DSS, not ECC
 */
#define GNUNET_SIGNATURE_PURPOSE_FS_UBLOCK 17

/**
 * Accept state in regex DFA.  Peer affirms that
 * it offers the matching service.
 */
#define GNUNET_SIGNATURE_PURPOSE_REGEX_ACCEPT 18

/**
 * Signature of a multicast message sent by the origin.
 */
#define GNUNET_SIGNATURE_PURPOSE_MULTICAST_MESSAGE 19

/**
 * Signature of a conversation ring.
 */
#define GNUNET_SIGNATURE_PURPOSE_CONVERSATION_RING 20

/**
 * Signature for the first round of distributed key generation.
 */
#define GNUNET_SIGNATURE_PURPOSE_SECRETSHARING_DKG1 21

/**
 * Signature for the second round of distributed key generation.
 */
#define GNUNET_SIGNATURE_PURPOSE_SECRETSHARING_DKG2 22

/**
 * Signature for cooperatice decryption.
 */
#define GNUNET_SIGNATURE_PURPOSE_SECRETSHARING_DECRYPTION 23

/**
 * Signature of a multicast request sent by a member.
 */
#define GNUNET_SIGNATURE_PURPOSE_MULTICAST_REQUEST 24

/**
 * Signature for a sensor anomaly report message.
 */
#define GNUNET_SIGNATURE_PURPOSE_SENSOR_ANOMALY_REPORT 25

/**
 * Signature for a GNUid Token
 */
#define GNUNET_SIGNATURE_PURPOSE_GNUID_TOKEN 26

/**
 * Signature for a GNUid Ticket
 */
#define GNUNET_SIGNATURE_PURPOSE_RECLAIM_CODE_SIGN 27

/**
 * Signature for a GNUnet credential
 */
#define GNUNET_SIGNATURE_PURPOSE_CREDENTIAL 28

/**
 * Signature by a peer affirming that this is one of its
 * addresses (for the given time period).
 */
#define GNUNET_SIGNATURE_PURPOSE_TRANSPORT_ADDRESS 29

/**
 * Signature by a peer affirming that the given ephemeral
 * key is currently in use by that peer's transport service.
 */
#define GNUNET_SIGNATURE_PURPOSE_TRANSPORT_EPHEMERAL 30

/**
 * Signature used by TCP communicator handshake,
 */
#define GNUNET_SIGNATURE_COMMUNICATOR_TCP_HANDSHAKE 31

/**
 * Signature used by TCP communicator rekey.
 */
#define GNUNET_SIGNATURE_COMMUNICATOR_TCP_REKEY 32

/**
 * Signature used by UDP communicator handshake
 */
#define GNUNET_SIGNATURE_COMMUNICATOR_UDP_HANDSHAKE 33

/**
 * Signature used by UDP broadcasts.
 */
#define GNUNET_SIGNATURE_COMMUNICATOR_UDP_BROADCAST 34

/**
 * Signature by a peer affirming that it received a
 * challenge (and stating how long it expects the
 * address on which the challenge was received to
 * remain valid).
 */
#define GNUNET_SIGNATURE_PURPOSE_TRANSPORT_CHALLENGE 35


#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

/* ifndef GNUNET_SIGNATURES_H */
#endif

/** @} */  /* end of group */

/* end of gnunet_signatures.h */

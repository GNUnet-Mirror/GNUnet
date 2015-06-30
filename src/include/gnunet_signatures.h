/*
     This file is part of GNUnet.
     Copyright (C) 2009 Christian Grothoff (and other contributing authors)

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
 * @file include/gnunet_signatures.h
 * @brief constants for network signatures
 * @author Christian Grothoff
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
 * he offers the matching service.
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
 * Key exchange in CADET
 */
#define GNUNET_SIGNATURE_PURPOSE_CADET_KX 21

/**
 * Signature for the first round of distributed key generation.
 */
#define GNUNET_SIGNATURE_PURPOSE_SECRETSHARING_DKG1 22

/**
 * Signature for the second round of distributed key generation.
 */
#define GNUNET_SIGNATURE_PURPOSE_SECRETSHARING_DKG2 23

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


#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

/* ifndef GNUNET_SIGNATURES_H */
#endif
/* end of gnunet_signatures.h */

/*
     This file is part of GNUnet.
     (C) 2009, 2010, 2011 Christian Grothoff (and other contributing authors)

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
 * @file core/gnunet-service-core_kx.h
 * @brief code for managing the key exchange (SET_KEY, PING, PONG) with other peers
 * @author Christian Grothoff
 */
#ifndef GNUNET_SERVICE_CORE_KX_H
#define GNUNET_SERVICE_CORE_KX_H

#include "gnunet_util_lib.h"


/**
 * State machine for our P2P encryption handshake.  Everyone starts in
 * "DOWN", if we receive the other peer's key (other peer initiated)
 * we start in state RECEIVED (since we will immediately send our
 * own); otherwise we start in SENT.  If we get back a PONG from
 * within either state, we move up to CONFIRMED (the PONG will always
 * be sent back encrypted with the key we sent to the other peer).
 */
enum KxStateMachine
{
  /**
   * No handshake yet.
   */
  KX_STATE_DOWN,

  /**
   * We've sent our session key.
   */
  KX_STATE_KEY_SENT,

  /**
   * We've received the other peers session key.
   */
  KX_STATE_KEY_RECEIVED,

  /**
   * The other peer has confirmed our session key with a message
   * encrypted with his session key (which we got).  Key exchange
   * is done.
   */
  KX_STATE_UP
};


/**
 * Information about the status of a key exchange with another peer.
 */
struct GSC_KeyExchangeInfo
{
  /**
   * Identity of the peer.
   */
  struct GNUNET_PeerIdentity peer;

  /**
   * SetKeyMessage to transmit (initialized the first
   * time our status goes past 'KX_STATE_KEY_SENT').
   */
  struct SetKeyMessage skm;

  /**
   * PING message we transmit to the other peer.
   */
  struct PingMessage ping;

  /**
   * SetKeyMessage we received and did not process yet.
   */
  struct SetKeyMessage *skm_received;

  /**
   * PING message we received from the other peer and
   * did not process yet (or NULL).
   */
  struct PingMessage *ping_received;

  /**
   * PONG message we received from the other peer and
   * did not process yet (or NULL).
   */
  struct PongMessage *pong_received;

  /**
   * Non-NULL if we are currently looking up HELLOs for this peer.
   * for this peer.
   */
  struct GNUNET_PEERINFO_IteratorContext *pitr;

  /**
   * Public key of the neighbour, NULL if we don't have it yet.
   */
  struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded *public_key;

  /**
   * We received a PONG message before we got the "public_key"
   * (or the SET_KEY).  We keep it here until we have a key
   * to decrypt it.  NULL if no PONG is pending.
   */
  struct PongMessage *pending_pong;

  /**
   * Key we use to encrypt our messages for the other peer
   * (initialized by us when we do the handshake).
   */
  struct GNUNET_CRYPTO_AesSessionKey encrypt_key;

  /**
   * Key we use to decrypt messages from the other peer
   * (given to us by the other peer during the handshake).
   */
  struct GNUNET_CRYPTO_AesSessionKey decrypt_key;

  /**
   * At what time did we generate our encryption key?
   */
  struct GNUNET_TIME_Absolute encrypt_key_created;

  /**
   * At what time did the other peer generate the decryption key?
   */
  struct GNUNET_TIME_Absolute decrypt_key_created;

  /**
   * When should the session time out (if there are no PONGs)?
   */
  struct GNUNET_TIME_Absolute timeout;

  /**
   * At what frequency are we currently re-trying SET_KEY messages?
   */
  struct GNUNET_TIME_Relative set_key_retry_frequency;

  /**
   * ID of task used for re-trying SET_KEY and PING message.
   */
  GNUNET_SCHEDULER_TaskIdentifier retry_set_key_task;

  /**
   * ID of task used for sending keep-alive pings.
   */
  GNUNET_SCHEDULER_TaskIdentifier keep_alive_task;

  /**
   * What was our PING challenge number (for this peer)?
   */
  uint32_t ping_challenge;

  /**
   * What is our connection status?
   */
  enum KxStateMachine status;

};


/**
 * We received a SET_KEY message.  Validate and update
 * our key material and status.
 *
 * @param kx key exchange status for the corresponding peer
 * @param msg the set key message we received
 */
void
GSC_KX_handle_set_key (struct GSC_KeyExchangeInfo *kx, 
		       const struct GNUNET_MessageHandler *msg);


/**
 * We received a PING message.  Validate and transmit
 * a PONG message.
 *
 * @param kx key exchange status for the corresponding peer
 * @param msg the encrypted PING message itself
 */
void
GSC_KX_handle_ping (struct GSC_KeyExchangeInfo *kx, 
		    const struct GNUNET_MessageHeader *msg);


/**
 * We received a PONG message.  Validate and update our status.
 *
 * @param kx key exchange status for the corresponding peer
 * @param msg the encrypted PONG message itself
 */
void
GSC_KX_handle_pong (struct GSC_KeyExchangeInfo *kx,
		    const struct GNUNET_MessageHeader *msg);


/**
 * Encrypt and transmit a message with the given payload.
 *
 * @param kx key exchange context
 * @param bw_in bandwidth limit to transmit to the other peer;
 *              the other peer shall not send us more than the
 *              given rate
 * @param payload payload of the message
 * @param payload_size number of bytes in 'payload'
 */
void
GSC_KX_encrypt_and_transmit (struct GSC_KeyExchangeInfo *kx,
			     struct GNUNET_BANDWIDTH_Value32NBO bw_in,
			     const void *payload,
			     size_t payload_size);


/**
 * We received an encrypted message.  Decrypt, validate and
 * pass on to the appropriate clients.
 *
 * @param kx key exchange information context
 * @param msg encrypted message
 * @param atsi performance data
 * @param atsi_count number of entries in ats (excluding 0-termination)
 */
void
GSC_KX_handle_encrypted_message (struct GSC_KeyExchangeInfo *kx, 
				 const struct GNUNET_MessageHeader *msg,
				 const struct GNUNET_TRANSPORT_ATS_Information *atsi,
				 uint32_t atsi_count);


/**
 * Start the key exchange with the given peer.
 *
 * @param pid identity of the peer to do a key exchange with
 * @return key exchange information context
 */
struct GSC_KeyExchangeInfo *
GSC_KX_start (const struct GNUNET_PeerIdentity *pid);


/**
 * Stop key exchange with the given peer.  Clean up key material.
 *
 * @param kx key exchange to stop
 */
void
GSC_KX_stop (struct GSC_KeyExchangeInfo *kx);


/**
 * Initialize KX subsystem.
 *
 * @return GNUNET_OK on success, GNUNET_SYSERR on failure
 */
int 
GSC_KX_init (void);


/**
 * Shutdown KX subsystem.
 */
void 
GSC_KX_done (void);

#endif
/* end of gnunet-service-core_kx.h */

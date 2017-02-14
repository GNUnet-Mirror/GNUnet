/*
     This file is part of GNUnet.
     Copyright (C) 2013-2016 GNUnet e.V.

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
 * @file conversation/conversation.h
 * @brief constants for network protocols
 * @author Siomon Dieterle
 * @author Andreas Fuchs
 */
#ifndef CONVERSATION_H
#define CONVERSATION_H

#ifdef __cplusplus
extern "C"
{
#if 0				/* keep Emacsens' auto-indent happy */
}
#endif
#endif


#define MAX_TRANSMIT_DELAY GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 60)


/**
 * Highest bit in a 32-bit unsigned integer,
 * bit set if we are making an outgoing call,
 * bit unset for local lines.
 */
#define HIGH_BIT ((uint32_t) (1LL << 31))

GNUNET_NETWORK_STRUCT_BEGIN


/**
 * Message to transmit the audio (between client and helpers).
 */
struct AudioMessage
{
  /**
   * Type is #GNUNET_MESSAGE_TYPE_CONVERSATION_AUDIO
   */
  struct GNUNET_MessageHeader header;

  // FIXME: make compilation of record_timestamp and network_send_timestamp optional
  /**
   * the timestamp the record helper sets before encoding
   */
  struct GNUNET_TIME_AbsoluteNBO encode_begin_time; 

  /**
   * the round-trip time the conversation api calculates when receiving an
   * echo from the other call participant
   */
  struct GNUNET_TIME_AbsoluteNBO encode_end_time;

  /* followed by audio data */
  
};


/**
 * Client -> Service message to register a phone.
 */
struct ClientPhoneRegisterMessage
{
  /**
   * Type is: #GNUNET_MESSAGE_TYPE_CONVERSATION_CS_PHONE_REGISTER
   */
  struct GNUNET_MessageHeader header;

  /**
   * Always zero.
   */
  uint32_t reserved GNUNET_PACKED;

  /**
   * Phone line / CADET port to register.
   */
  struct GNUNET_HashCode line_port;
};


/**
 * Service -> Client message for phone is ringing.
 */
struct ClientPhoneRingMessage
{
  /**
   * Type is: #GNUNET_MESSAGE_TYPE_CONVERSATION_CS_PHONE_RING
   */
  struct GNUNET_MessageHeader header;

  /**
   * CID, internal caller ID number used in the future to identify
   * which active call we are talking about.
   */
  uint32_t cid GNUNET_PACKED;

  /**
   * Who is calling us?
   */
  struct GNUNET_CRYPTO_EcdsaPublicKey caller_id;

};


/**
 * Service <-> Client message for phone was suspended.
 */
struct ClientPhoneSuspendMessage
{
  /**
   * Type is: #GNUNET_MESSAGE_TYPE_CONVERSATION_CS_PHONE_SUSPEND
   */
  struct GNUNET_MessageHeader header;

  /**
   * CID, internal caller ID to identify which active call we are
   * talking about.
   */
  uint32_t cid GNUNET_PACKED;

};


/**
 * Service <-> Client message for phone was resumed.
 */
struct ClientPhoneResumeMessage
{
  /**
   * Type is: #GNUNET_MESSAGE_TYPE_CONVERSATION_CS_PHONE_RESUME
   */
  struct GNUNET_MessageHeader header;

  /**
   * CID, internal caller ID to identify which active call we are
   * talking about.
   */
  uint32_t cid GNUNET_PACKED;

};


/**
 * Client -> Service pick up phone that is ringing.
 */
struct ClientPhonePickupMessage
{
  /**
   * Type is: #GNUNET_MESSAGE_TYPE_CONVERSATION_CS_PHONE_PICK_UP
   */
  struct GNUNET_MessageHeader header;

  /**
   * CID, internal caller ID to identify which active call we are
   * talking about.
   */
  uint32_t cid GNUNET_PACKED;

};


/**
 * Client <-> Service hang up phone that may or may not be ringing.
 * Also sent in response to a (failed) `struct ClientCallMessage`.
 */
struct ClientPhoneHangupMessage
{
  /**
   * Type is: #GNUNET_MESSAGE_TYPE_CONVERSATION_CS_PHONE_HANG_UP
   */
  struct GNUNET_MessageHeader header;

  /**
   * CID, internal caller ID to identify which active call we are
   * talking about.
   */
  uint32_t cid GNUNET_PACKED;

};


/**
 * Message Client <-> Service to transmit the audio.
 */
struct ClientAudioMessage
{
  /**
   * Type is #GNUNET_MESSAGE_TYPE_CONVERSATION_CS_AUDIO
   */
  struct GNUNET_MessageHeader header;

  /**
   * CID, internal caller ID to identify which active call we are
   * sending data to.
   */
  uint32_t cid GNUNET_PACKED;

  /* followed by audio data */

};


/**
 * Client -> Service message to call a phone.
 */
struct ClientCallMessage
{
  /**
   * Type is: #GNUNET_MESSAGE_TYPE_CONVERSATION_CS_PHONE_CALL
   */
  struct GNUNET_MessageHeader header;

  /**
   * Always zero.
   */
  uint32_t reserved GNUNET_PACKED;

  /**
   * Which peer is hosting the line?
   */
  struct GNUNET_PeerIdentity target;

  /**
   * Which phone line to call at the peer?
   */
  struct GNUNET_HashCode line_port;

  /**
   * Identity of the caller.
   */
  struct GNUNET_CRYPTO_EcdsaPrivateKey caller_id;
};


/**
 * Service -> Client: other peer has picked up the phone, we are
 * now talking.
 */
struct ClientPhonePickedupMessage
{
  /**
   * Type is: #GNUNET_MESSAGE_TYPE_CONVERSATION_CS_PHONE_PICKED_UP
   */
  struct GNUNET_MessageHeader header;

  /**
   * Call ID of the corresponding
   * #GNUNET_MESSAGE_TYPE_CONVERSATION_CS_PHONE_CALL
   */
  uint32_t cid GNUNET_PACKED;

};


/**
 * Information signed in a `struct CadetPhoneRingMessage`
 * whereby the caller self-identifies to the receiver.
 */
struct CadetPhoneRingInfoPS
{
  /**
   * Purpose for the signature, must be
   * #GNUNET_SIGNATURE_PURPOSE_CONVERSATION_RING.
   */
  struct GNUNET_CRYPTO_EccSignaturePurpose purpose;

  /**
   * Which port did the call go to?
   */
  struct GNUNET_HashCode line_port;

  /**
   * Which peer is the call for?
   */
  struct GNUNET_PeerIdentity target_peer;

  /**
   * When does the signature expire?
   */
  struct GNUNET_TIME_AbsoluteNBO expiration_time;
};


/**
 * Cadet message to make a phone ring.  Sent to the port
 * of the respective phone.
 */
struct CadetPhoneRingMessage
{
  /**
   * Type is: #GNUNET_MESSAGE_TYPE_CONVERSATION_CADET_PHONE_RING
   */
  struct GNUNET_MessageHeader header;

  /**
   * Always zero.
   */
  uint32_t reserved GNUNET_PACKED;

  /**
   * Who is calling us? (also who is signing).
   */
  struct GNUNET_CRYPTO_EcdsaPublicKey caller_id;

  /**
   * When does the signature expire?
   */
  struct GNUNET_TIME_AbsoluteNBO expiration_time;

  /**
   * Signature over a `struct CadetPhoneRingInfoPS`
   */
  struct GNUNET_CRYPTO_EcdsaSignature signature;

};


/**
 * Cadet message for hanging up.
 */
struct CadetPhoneHangupMessage
{
  /**
   * Type is: #GNUNET_MESSAGE_TYPE_CONVERSATION_CADET_PHONE_HANG_UP
   */
  struct GNUNET_MessageHeader header;

};


/**
 * Cadet message for picking up.
 */
struct CadetPhonePickupMessage
{
  /**
   * Type is: #GNUNET_MESSAGE_TYPE_CONVERSATION_CADET_PHONE_PICK_UP
   */
  struct GNUNET_MessageHeader header;

};


/**
 * Cadet message for phone suspended.
 */
struct CadetPhoneSuspendMessage
{
  /**
   * Type is: #GNUNET_MESSAGE_TYPE_CONVERSATION_CADET_PHONE_SUSPEND
   */
  struct GNUNET_MessageHeader header;

};


/**
 * Cadet message for phone resumed.
 */
struct CadetPhoneResumeMessage
{
  /**
   * Type is: #GNUNET_MESSAGE_TYPE_CONVERSATION_CADET_PHONE_RESUME
   */
  struct GNUNET_MessageHeader header;

};


/**
 * Cadet message to transmit the audio.
 */
struct CadetAudioMessage
{
  /**
   * Type is #GNUNET_MESSAGE_TYPE_CONVERSATION_CADET_AUDIO
   */
  struct GNUNET_MessageHeader header;

  /* followed by audio data */

};


GNUNET_NETWORK_STRUCT_END


#if 0				/* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

/* ifndef GNUNET_PROTOCOLS_CONVERSATION_H */
#endif
/* end of gnunet_protocols_conversation.h */

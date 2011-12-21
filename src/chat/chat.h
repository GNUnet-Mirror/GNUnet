/*
     This file is part of GNUnet
     (C) 2008, 2011 Christian Grothoff (and other contributing authors)

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
 * @file chat/chat.h
 * @brief support for chat
 * @author Christian Grothoff
 * @author Nathan Evans
 * @author Vitaly Minko
 */

#ifndef CHAT_H
#define CHAT_H

#include "gnunet_chat_service.h"

/**
 * Constant IV since we generate a new session key per each message.
 */
#define INITVALUE "InitializationVectorValue"


/**
 * Client-service messages
 */

GNUNET_NETWORK_STRUCT_BEGIN

/**
 * Notification sent by service to client indicating that we've received a chat
 * message.  After this struct, the remaining bytes are the actual text message.
 * If the mesasge is private, then the text is encrypted, otherwise it's
 * plaintext.
 */
struct ReceiveNotificationMessage
{
  /**
   * Message type will be GNUNET_MESSAGE_TYPE_CHAT_MESSAGE_NOTIFICATION
   */
  struct GNUNET_MessageHeader header;

  /**
   * Message options, see GNUNET_CHAT_MsgOptions.
   */
  uint32_t msg_options GNUNET_PACKED;

  /**
   * Sequence number of the message (unique per sender).
   */
  uint32_t sequence_number GNUNET_PACKED;

  /**
   * For alignment (should be zero).
   */
  uint32_t reserved GNUNET_PACKED;

  /**
   * Timestamp of the message.
   */
  struct GNUNET_TIME_AbsoluteNBO timestamp;

  /**
   * Hash of the public key of the pseudonym of the sender of the message.
   * Should be all zeros for anonymous.
   */
  GNUNET_HashCode sender;

  /**
   * The encrypted session key.
   */
  struct GNUNET_CRYPTO_RsaEncryptedData encrypted_key;

};


/**
 * Request sent by client to transmit a chat message to another room members.
 * After this struct, the remaining bytes are the actual message in plaintext.
 * Private messages are encrypted on the service side.
 */
struct TransmitRequestMessage
{
  /**
   * Message type will be GNUNET_MESSAGE_TYPE_CHAT_TRANSMIT_REQUEST
   */
  struct GNUNET_MessageHeader header;

  /**
   * For alignment (should be zero).
   */
  uint32_t reserved GNUNET_PACKED;

  /**
   * Signature confirming receipt.  Signature covers everything from header
   * through content.
   */
  struct GNUNET_CRYPTO_RsaSignature signature;

  /**
   * What is being signed and why?
   */
  struct GNUNET_CRYPTO_RsaSignaturePurpose purpose;

  /**
   * Desired message options, see GNUNET_CHAT_MsgOptions.
   */
  uint32_t msg_options GNUNET_PACKED;

  /**
   * Sequence number of the message (unique per sender).
   */
  uint32_t sequence_number GNUNET_PACKED;

  /**
   * Timestamp of the message.
   */
  struct GNUNET_TIME_AbsoluteNBO timestamp;

  /**
   * Who should receive this message?  Set to all zeros for "everyone".
   */
  GNUNET_HashCode target;

};


/**
 * Receipt sent from a message receiver to the service to confirm delivery of
 * a chat message and from the service to sender of the original message to
 * acknowledge delivery.
 */
struct ConfirmationReceiptMessage
{
  /**
   * Message type will be
   * GNUNET_MESSAGE_TYPE_CHAT_CONFIRMATION_RECEIPT when sending from client,
   * GNUNET_MESSAGE_TYPE_CHAT_CONFIRMATION_NOTIFICATION when sending to client.
   */
  struct GNUNET_MessageHeader header;

  /**
   * For alignment (should be zero).
   */
  uint32_t reserved GNUNET_PACKED;

  /**
   * Signature confirming receipt.  Signature covers everything from header
   * through content.
   */
  struct GNUNET_CRYPTO_RsaSignature signature;

  /**
   * What is being signed and why?
   */
  struct GNUNET_CRYPTO_RsaSignaturePurpose purpose;

  /**
   * Sequence number of the original message.
   */
  uint32_t sequence_number GNUNET_PACKED;

  /**
   * For alignment (should be zero).
   */
  uint32_t reserved2 GNUNET_PACKED;

  /**
   * Time of receipt.
   */
  struct GNUNET_TIME_AbsoluteNBO timestamp;

  /**
   * Who is confirming the receipt?
   */
  GNUNET_HashCode target;

  /**
   * Who is the author of the chat message?
   */
  GNUNET_HashCode author;

  /**
   * Hash of the (possibly encrypted) content.
   */
  GNUNET_HashCode content;

};


/**
 * Message send from client to daemon to join a chat room.
 * This struct is followed by the room name and then
 * the serialized ECRS meta data describing the new member.
 */
struct JoinRequestMessage
{
  /**
   * Message type will be GNUNET_MESSAGE_TYPE_CHAT_JOIN_REQUEST
   */
  struct GNUNET_MessageHeader header;

  /**
   * Options.  Set all options that this client is willing to receive.
   * For example, if the client does not want to receive anonymous or
   * OTR messages but is willing to generate acknowledgements and
   * receive private messages, this should be set to
   * GNUNET_CHAT_MSG_PRIVATE | GNUNET_CHAT_MSG_ACKNOWLEDGED.
   */
  uint32_t msg_options GNUNET_PACKED;

  /**
   * Length of the room name.
   */
  uint16_t room_name_len GNUNET_PACKED;

  /**
   * For alignment (should be zero).
   */
  uint16_t reserved GNUNET_PACKED;
  uint32_t reserved2 GNUNET_PACKED;

  /**
   * Public key of the joining member.
   */
  struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded public_key;

};


/**
 * Message send by server to client to indicate joining of another room member.
 * This struct is followed by the serialized ECRS MetaData describing the new
 * member.
 */
struct JoinNotificationMessage
{
  /**
   * Message type will be GNUNET_MESSAGE_TYPE_CHAT_JOIN_NOTIFICATION
   */
  struct GNUNET_MessageHeader header;

  /**
   * Options.  Set to all options that the new user is willing to
   * process.  For example, if the client does not want to receive
   * anonymous or OTR messages but is willing to generate
   * acknowledgements and receive private messages, this should be set
   * to GNUNET_CHAT_MSG_PRIVATE | GNUNET_CHAT_MSG_ACKNOWLEDGED.
   */
  uint32_t msg_options GNUNET_PACKED;

  /**
   * Public key of the new user.
   */
  struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded public_key;

};


/**
 * Message send by server to client to indicate leaving of another room member.
 */
struct LeaveNotificationMessage
{
  /**
   * Message type will be GNUNET_MESSAGE_TYPE_CHAT_LEAVE_NOTIFICATION
   */
  struct GNUNET_MessageHeader header;

  /**
   * Reserved (for alignment).
   */
  uint32_t reserved GNUNET_PACKED;

  /**
   * Who is leaving?
   */
  struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded user;

};


/**
 * Peer-to-peer messages
 */

/**
 * Message send by one peer to another to indicate joining of another room
 * member.  This struct is followed by the room name and then the serialized
 * ECRS MetaData describing the new member.
 */
struct P2PJoinNotificationMessage
{
  /**
   * Message type will be GNUNET_MESSAGE_TYPE_CHAT_P2P_JOIN_NOTIFICATION
   */
  struct GNUNET_MessageHeader header;

  /**
   * Options.  Set all options that this client is willing to receive.
   * For example, if the client does not want to receive anonymous or
   * OTR messages but is willing to generate acknowledgements and
   * receive private messages, this should be set to
   * GNUNET_CHAT_MSG_PRIVATE | GNUNET_CHAT_MSG_ACKNOWLEDGED.
   */
  uint32_t msg_options GNUNET_PACKED;

  /**
   * Length of the room name.
   */
  uint16_t room_name_len GNUNET_PACKED;

  /**
   * Reserved (should be zero).
   */
  uint16_t reserved GNUNET_PACKED;
  uint32_t reserved2 GNUNET_PACKED;

  /**
   * Public key of the joining member.
   */
  struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded public_key;

};


/**
 * Message send by one peer to another to indicate leaving of another room
 * member.
 */
struct P2PLeaveNotificationMessage
{
  /**
   * Message type will be GNUNET_MESSAGE_TYPE_CHAT_P2P_LEAVE_NOTIFICATION
   */
  struct GNUNET_MessageHeader header;

  /**
   * Reserved (for alignment).
   */
  uint32_t reserved GNUNET_PACKED;

  /**
   * Who is leaving?
   */
  struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded user;

};


/**
 * Message send by one peer to another to indicate receiving of a chat message.
 * This struct is followed by the room name (only if the message is anonymous)
 * and then the remaining bytes are the actual text message.  If the mesasge is
 * private, then the text is encrypted, otherwise it's plaintext.
 */
struct P2PReceiveNotificationMessage
{
  /**
   * Message type will be GNUNET_MESSAGE_TYPE_CHAT_P2P_MESSAGE_NOTIFICATION
   */
  struct GNUNET_MessageHeader header;

  /**
   * Message options, see GNUNET_CHAT_MsgOptions.
   */
  uint32_t msg_options GNUNET_PACKED;

  /**
   * Sequence number of the message (unique per sender).
   */
  uint32_t sequence_number GNUNET_PACKED;

  /**
   * Length of the room name. This is only used for anonymous messages.
   */
  uint16_t room_name_len GNUNET_PACKED;

  /**
   * Reserved (for alignment).
   */
  uint16_t reserved GNUNET_PACKED;

  /**
   * Timestamp of the message.
   */
  struct GNUNET_TIME_AbsoluteNBO timestamp;

  /**
   * Hash of the public key of the pseudonym of the sender of the message
   * Should be all zeros for anonymous.
   */
  GNUNET_HashCode sender;

  /**
   * Who should receive this message?  Set to all zeros for "everyone".
   */
  GNUNET_HashCode target;

  /**
   * The encrypted session key.
   */
  struct GNUNET_CRYPTO_RsaEncryptedData encrypted_key;

};


/**
 * Receipt sent from one peer to another to confirm delivery of a chat message.
 */
struct P2PConfirmationReceiptMessage
{
  /**
   * Message type will be GNUNET_MESSAGE_TYPE_CHAT_P2P_CONFIRMATION_RECEIPT
   */
  struct GNUNET_MessageHeader header;

  /**
   * For alignment (should be zero).
   */
  uint32_t reserved GNUNET_PACKED;

  /**
   * Signature confirming receipt.  Signature covers everything from header
   * through content.
   */
  struct GNUNET_CRYPTO_RsaSignature signature;

  /**
   * What is being signed and why?
   */
  struct GNUNET_CRYPTO_RsaSignaturePurpose purpose;

  /**
   * Sequence number of the original message.
   */
  uint32_t msg_sequence_number GNUNET_PACKED;

  /**
   * Sequence number of the receipt.
   */
  uint32_t sequence_number GNUNET_PACKED;

  /**
   * Time of receipt.
   */
  struct GNUNET_TIME_AbsoluteNBO timestamp;

  /**
   * Who is confirming the receipt?
   */
  GNUNET_HashCode target;

  /**
   * Who is the author of the chat message?
   */
  GNUNET_HashCode author;

  /**
   * Hash of the (possibly encrypted) content.
   */
  GNUNET_HashCode content;

};
GNUNET_NETWORK_STRUCT_END

#endif

/* end of chat.h */

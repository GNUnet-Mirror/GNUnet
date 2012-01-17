/*
     This file is part of GNUnet.
     (C) 2012 Christian Grothoff (and other contributing authors)

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
 * @file stream/stream_protocol.h
 * @brief P2P protocol for the stream connections
 * @author Sree Harsha Totakura
 */

#ifndef STREAM_PROTOCOL_H
#define STREAM_PROTOCOL_H

#ifdef	__cplusplus
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif

#include <sys/types.h>

#include "gnunet_stream_lib.h"
#include "gnunet_mesh_service.h"


/**
 * Stream message types
 */
enum GNUNET_STREAM_MessageType
  {
    /**
     * Message containing data
     */
    GNUNET_STREAM_MESSAGE_DATA,

    /**
     * ACK message
     */
    GNUNET_STREAM_MESSAGE_ACK,

    /**
     * Handshake hello message
     */
    GNUNET_STREAM_MESSAGE_HELLO,

    /**
     * Handshake hello acknowledgement message
     */
    GNUNET_STREAM_MESSAGE_HELLO_ACK,

    /**
     * Reset message
     */
    GNUNET_STREAM_MESSAGE_RESET,

    /**
     * Transmit close message (data transmission no longer possible after this
     * message) 
     */
    GNUNET_STREAM_MESSAGE_TRANSMIT_CLOSE,

    /**
     * Transmit close acknowledgement message
     */
    GNUNET_STREAM_MESSAGE_TRANSMIT_CLOSE_ACK,
    
    /**
     * Receive close message (data is no loger read by the receiver after this
     * message) 
     */
    GNUNET_STREAM_MESSAGE_RECEIVE_CLOSE,

    /**
     * Receive close acknowledgement message
     */
    GNUNET_STREAM_MESSAGE_RECEIVE_CLOSE_ACK,

    /**
     * Stream close message (data is no longer sent or read after this message)
     */
    GNUNET_STREAM_MESSAGE_CLOSE,

    /**
     * Close acknowledgement message
     */
    GNUNET_STREAM_MESSAGE_CLOSE_ACK
  };


/**
 * The stream message header
 *
 * The message can be of Data, Acknowledgement or both
 */
struct GNUNET_STREAM_MessageHeader
{
  /**
   * The GNUNET message header
   */
  struct GNUNET_MessageHeader header;

  /**
   * A number which identifies a session
   */
  uint16_t session_id;

  /**
   * The message type
   * ? Should we rather use the type field in GNUNET_MessageHeader ?
   */
  enum GNUNET_STREAM_MessageType type;

};


/**
 * The Data message, should be prefixed with stream header with its type set to
 * GNUNET_STREAM_Data 
 */
struct GNUNET_STREAM_DataMessage
{
  /**
   * Sequence number; Always starts with 0 and should wrap around. 
   * Immune to Sequence Prediction Attack as we take cover under GNUNET's secure
   * messaging
   */
  uint32_t seq;

  /**
   * number of milliseconds to the soft deadline for sending acknowledgement
   * measured from the time this message is received. It is optimal for the
   * communication to send the ack within the soft deadline
   */
  uint16_t ack_deadline;

  /**
   * The data should be appended here
   */
};

/**
 * The Selective Acknowledgement Bitmap
 * 
 * ? WARNING ? Possibility for Denial of Service ??
 * ? Receiver may force the sender to mantain a buffer of ~ 64*64k !??
 */
typedef uint64_t GNUNET_STREAM_AckBitmap;


/**
 * The Acknowledgment Message, should be prefixed with Stream Message header
 * with its type set to GNUNET_STREAM_MESSAGE_ACK
 */
struct GNUNET_STREAM_AckMessage
{
  /**
   * The sequence number of the Data Message upto which the receiver has filled
   * its buffer without any missing packets
   */
  uint32_t base_seq;

  /**
   * The Selective Acknowledgement Bitmap. Computed relative to the base_seq
   * (bit n corresponds to the Data message with sequence number base_seq+n)
   */
  GNUNET_STREAM_AckBitmap bitmap;
};


/**
 * states in the Protocol
 */
enum GNUNET_STREAM_State
  {
    GNUNET_STREAM_STATE_INIT,

    GNUNET_STREAM_STATE_LISTEN,

    GNUNET_STREAM_STATE_HANDSHAKE_WAIT,

    GNUNET_STREAM_STATE_ESTABLISHED,

    GNUNET_STREAM_STATE_RECEIVE_CLOSE_WAIT,

    GNUNET_STREAM_STATE_RECEIVE_CLOSED,

    GNUNET_STREAM_STATE_TRANSMIT_CLOSE_WAIT,

    GNUNET_STREAM_STATE_TRANSMIT_CLOSED,

    GNUNET_STREAM_STATE_CLOSE_WAIT,

    GNUNET_STREAM_STATE_CLOSED 
  }


#if 0                           /** keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

#endif  /* STREAM_PROTOCOL_H */

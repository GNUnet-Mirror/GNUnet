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

#include "gnunet_util_lib.h"

GNUNET_NETWORK_STRUCT_BEGIN


/**
 * The stream message header
 * All messages of STREAM should commonly have this as header
 */
struct GNUNET_STREAM_MessageHeader
{
  /**
   * The GNUNET message header, types are from GNUNET_MESSAGE_TYPE_STREAM_*-range.
   */
  struct GNUNET_MessageHeader header;

  /**
   * A number which identifies a session between the two peers. FIXME: not needed
   */
  uint32_t session_id GNUNET_PACKED;

};


/**
 * The Data message, should be prefixed with stream header with its type set to
 * GNUNET_STREAM_Data 
 */
struct GNUNET_STREAM_DataMessage
{

  /**
   * Type is  GNUNET_MESSAGE_TYPE_STREAM_DATA 
   */
  struct GNUNET_STREAM_MessageHeader header;

  /**
   * Sequence number; starts with a random value.  (Just in case
   * someone breaks mesh and is able to try to do a Sequence
   * Prediction Attack on us.)
   */
  uint32_t sequence_number GNUNET_PACKED;

  /**
   * number of milliseconds to the soft deadline for sending acknowledgement
   * measured from the time this message is received. It is optimal for the
   * communication to send the ack within the soft deadline
   */
  struct GNUNET_TIME_RelativeNBO ack_deadline;

  /**
   * Offset of the packet in the overall stream, modulo 2^32; allows
   * the receiver to calculate where in the destination buffer the
   * message should be placed.  In network byte order.
   */
  uint32_t offset GNUNET_PACKED;

  /**
   * The data should be appended here
   */
};


/**
 * Number of bits in GNUNET_STREAM_AckBitmap
 */
#define GNUNET_STREAM_ACK_BITMAP_BIT_LENGTH 64

/**
 * The Selective Acknowledgement Bitmap
 */
typedef uint64_t GNUNET_STREAM_AckBitmap;


/**
 * The Acknowledgment Message to confirm receipt of DATA.
 */
struct GNUNET_STREAM_AckMessage
{

  /**
   * Type is  GNUNET_MESSAGE_TYPE_STREAM_ACK
   */
  struct GNUNET_STREAM_MessageHeader header;

  /**
   * The Selective Acknowledgement Bitmap. Computed relative to the base_seq
   * (bit n corresponds to the Data message with sequence number base_seq+n)
   */
  GNUNET_STREAM_AckBitmap bitmap GNUNET_PACKED;

  /**
   * The sequence number of the Data Message upto which the receiver has filled
   * its buffer without any missing packets
   *
   * FIXME: Do we need this?
   */
  uint32_t base_sequence_number GNUNET_PACKED;

  /**
   * Available buffer space past the last acknowledged buffer (for flow control),
   * in bytes.
   */
  uint32_t receive_window_remaining GNUNET_PACKED;
};


/**
 * Message for Acknowledging HELLO
 */
struct GNUNET_STREAM_HelloAckMessage
{
  /**
   * The stream message header
   */
  struct GNUNET_STREAM_MessageHeader header;

  /**
   * The selected sequence number. Following data tranmissions from the sender
   * start with this sequence
   */
  uint32_t sequence_number;

  /**
   * The size(in bytes) of the receive window on the peer sending this message
   *
   * FIXME: Remove if not needed
   */
  uint32_t receive_window_size;
};


/**
 * The Transmit close message(used to signal transmission is closed)
 */
struct GNUNET_STREAM_TransmitCloseMessage
{
  /**
   * The stream message header
   */
  struct GNUNET_STREAM_MessageHeader header;

  /**
   * The last sequence number of the packet after which the transmission has
   * ended 
   */
  uint32_t final_sequence_number GNUNET_PACKED;
};

GNUNET_NETWORK_STRUCT_END


#if 0                           /** keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

#endif  /* STREAM_PROTOCOL_H */

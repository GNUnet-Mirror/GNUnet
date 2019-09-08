/*
     This file is part of GNUnet.
     Copyright (C) 2009-2014 GNUnet e.V.

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
 * @file transport/communicator.h
 * @brief common internal definitions for communicator services
 * @author Christian Grothoff
 */
#ifndef COMMUNICATOR_H
#define COMMUNICAOTR_H

#include "gnunet_util_lib.h"
#include "gnunet_protocols.h"

GNUNET_NETWORK_STRUCT_BEGIN

/**
 * Message used to tell a communicator about a successful
 * key exchange.
 *
 * Note that this style of KX acknowledgement typically only applies
 * for communicators where the underlying network protocol is
 * unidirectional and/or lacks cryptography.  Furthermore, this is
 * just the recommended "generic" style, communicators are always free
 * to implement original designs that better fit their requirements.
 */
struct GNUNET_TRANSPORT_CommunicatorGenericKXConfirmation {
  /**
   * Type is #GNUNET_MESSAGE_TYPE_TRANSPORT_COMMUNICATOR_KX_CONFIRMATION
   */
  struct GNUNET_MessageHeader header;

  /**
   * Timestamp from the original sender which identifies the original KX.
   */
  struct GNUNET_TIME_AbsoluteNBO monotonic_time;

  /**
   * How long does the receiver of the KX believe that the address
   * on which the KX was received will continue to be valid.
   */
  struct GNUNET_TIME_RelativeNBO validity;

  /**
   * Hash of the shared secret. Specific hash function may depend on
   * the communicator's protocol details.
   */
  struct GNUNET_HashCode token;
};


/**
 * Message used to tell a communicator about the receiver's
 * flow control limits and to acknowledge receipt of certain
 * messages.
 *
 * Note that a sender MAY choose to violate the flow-control
 * limits provided in this message by a receiver, which may
 * result in messages being lost (after all, transport is an
 * unreliable channel).  So if the sender violates these
 * constraints, it should expect that the receive will simply
 * discard the (partially) received "old" messages.
 *
 * This way, if a sender or receiver crashes, there is no protocol
 * violation.
 *
 * Note that this style of flow control typically only applies
 * for communicators where the underlying network protocol does
 * not already implement flow control.  Furthermore, this is
 * just the recommended "generic" style, communicators are always
 * free to implement original designs that better fit their
 * requirements.
 */
struct GNUNET_TRANSPORT_CommunicatorGenericFCLimits {
  /**
   * Type is #GNUNET_MESSAGE_TYPE_TRANSPORT_COMMUNICATOR_FC_LIMITS
   */
  struct GNUNET_MessageHeader header;

  /**
   * Maximum number of messages beyond the acknowledged message
   * number that can still be transmitted concurrently without
   * further acknowledgements.
   */
  uint32_t msg_window_size;

  /**
   * Up to which message number were all messages received.
   */
  uint64_t msg_cummulative_ack;

  /**
   * Maximum number of payload bytes beyond the acknowledged
   * number of bytes can still be transmitted without further
   * acknowledgements.
   */
  uint64_t bytes_window_size;

  /**
   * Cummulative acknowledgement for number of bytes received.
   */
  uint64_t bytes_cummulative_ack;

  /**
   * Followed by a variable-size bitfield for messages received
   * beyond @e msg_cummulative_ack. Index at offset 0 must thus
   * be zero, otherwise @e msg_cummulative_ack should be
   * increased.  Note that this field can be overall of 0 bytes.
   * The variable-size bitfield must be a multiple of 64 bits
   * long.
   */
  /* uint64_t msg_selective_ack_field[]; */
};


GNUNET_NETWORK_STRUCT_END

/* end of communicator.h */
#endif

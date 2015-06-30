/*
     This file is part of GNUnet.
     Copyright (C) 2012 Christian Grothoff (and other contributing authors)

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
 * @author Florian Dold
 * @file consensus/consensus.h
 * @brief
 */
#ifndef CONSENSUS_H
#define CONSENSUS_H

#include "gnunet_common.h"

GNUNET_NETWORK_STRUCT_BEGIN

/**
 * Sent by the client to the service,
 * when the client wants the service to join a consensus session.
 */
struct GNUNET_CONSENSUS_JoinMessage
{
  /**
   * Type: GNUNET_MESSAGE_TYPE_CONSENSUS_CLIENT_JOIN
   */
  struct GNUNET_MessageHeader header;

  /**
   * Number of peers (at the end of this message) that want to
   * participate in the consensus.
   */
  uint32_t num_peers GNUNET_PACKED;

  /**
   * Session id of the consensus.
   */
  struct GNUNET_HashCode session_id;

  /**
   * Start time for the consensus.
   */
  struct GNUNET_TIME_AbsoluteNBO start;

  /**
   * Deadline for conclude.
   */
  struct GNUNET_TIME_AbsoluteNBO deadline;

  /* GNUNET_PeerIdentity[num_peers] */
};


/**
 * Message with an element
 */
struct GNUNET_CONSENSUS_ElementMessage
{

  /**
   * Type:
   * Either GNUNET_MESSAGE_TYPE_CONSENSUS_CLIENT_RECEIVED_ELEMENT
   * or GNUNET_MESSAGE_TYPE_CONSENSUS_CLIENT_INSERT_ELEMENT
   */
  struct GNUNET_MessageHeader header;

  /**
   * Type: GNUNET_MESSAGE_TYPE_CONSENSUS_CLIENT_NEW_ELEMENT
   */
  uint16_t element_type GNUNET_PACKED; /* FIXME: alignment? => uint32_t */

  /* rest: element data */
};


GNUNET_NETWORK_STRUCT_END

#endif

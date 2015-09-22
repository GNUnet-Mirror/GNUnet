/*
      This file is part of GNUnet
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
 * @file consensus/consensus_protocol.h
 * @brief p2p message definitions for consensus
 * @author Florian Dold
 */

#ifndef GNUNET_CONSENSUS_PROTOCOL_H
#define GNUNET_CONSENSUS_PROTOCOL_H

#include "platform.h"
#include "gnunet_common.h"
#include "gnunet_protocols.h"


GNUNET_NETWORK_STRUCT_BEGIN

/**
 * Sent as context message for set reconciliation.
 *
 * Essentially contains all the fields
 * from 'struct TaskKey', but in NBO.
 */
struct GNUNET_CONSENSUS_RoundContextMessage
{
  /**
   * Type: GNUNET_MESSAGE_TYPE_CONSENSUS_P2P_ROUND_CONTEXT
   */
  struct GNUNET_MessageHeader header;

  /**
   * A value from 'enum PhaseKind'.
   */
  uint16_t kind;

  /**
   * Number of the first peer
   * in canonical order.
   */
  int16_t peer1;

  /**
   * Number of the second peer in canonical order.
   */
  int16_t peer2;

  /**
   * Repetition of the gradecast phase.
   */
  int16_t repetition;

  /**
   * Leader in the gradecast phase.
   *
   * Can be different from both peer1 and peer2.
   */
  int16_t leader;

  /**
   * Non-zero if this set reconciliation
   * had elements removed because they were contested.
   *
   * Will be considered when grading broadcasts.
   *
   * Ignored for set operations that are not within gradecasts.
   */
  uint16_t is_contested;
};

GNUNET_NETWORK_STRUCT_END

#endif

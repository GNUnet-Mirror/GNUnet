/*
      This file is part of GNUnet
      Copyright (C) 2012 GNUnet e.V.

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
 * @file consensus/consensus_protocol.h
 * @brief p2p message definitions for consensus
 * @author Florian Dold
 */

#ifndef GNUNET_CONSENSUS_PROTOCOL_H
#define GNUNET_CONSENSUS_PROTOCOL_H

#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_common.h"
#include "gnunet_protocols.h"


GNUNET_NETWORK_STRUCT_BEGIN

/**
 * Sent as context message for set reconciliation.
 *
 * Essentially contains all the fields
 * from 'struct TaskKey', but in NBO.
 */
struct GNUNET_CONSENSUS_RoundContextMessage {
  /**
   * Type: #GNUNET_MESSAGE_TYPE_CONSENSUS_P2P_ROUND_CONTEXT
   */
  struct GNUNET_MessageHeader header;

  /**
   * A value from 'enum PhaseKind'.
   */
  uint16_t kind GNUNET_PACKED;

  /**
   * Number of the first peer
   * in canonical order.
   */
  int16_t peer1 GNUNET_PACKED;

  /**
   * Number of the second peer in canonical order.
   */
  int16_t peer2 GNUNET_PACKED;

  /**
   * Repetition of the gradecast phase.
   */
  int16_t repetition GNUNET_PACKED;

  /**
   * Leader in the gradecast phase.
   *
   * Can be different from both peer1 and peer2.
   */
  int16_t leader GNUNET_PACKED;

  /**
   * Non-zero if this set reconciliation
   * had elements removed because they were contested.
   *
   * Will be considered when grading broadcasts.
   *
   * Ignored for set operations that are not within gradecasts.
   */
  uint16_t is_contested GNUNET_PACKED;
};


enum {
  CONSENSUS_MARKER_CONTESTED = 1,
  CONSENSUS_MARKER_SIZE = 2,
};


/**
 * Consensus element, either marker or payload.
 */
struct ConsensusElement {
  /**
   * Payload element_type, only valid
   * if this is not a marker element.
   */
  uint16_t payload_type GNUNET_PACKED;

  /**
   * Is this a marker element?
   */
  uint8_t marker;

  /* rest: element data */
};


struct ConsensusSizeElement {
  struct ConsensusElement ce;

  uint64_t size GNUNET_PACKED;
  uint8_t sender_index;
};

struct ConsensusStuffedElement {
  struct ConsensusElement ce;
  struct GNUNET_HashCode rand GNUNET_PACKED;
};


GNUNET_NETWORK_STRUCT_END

#endif

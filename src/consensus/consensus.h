/*
     This file is part of GNUnet.
     (C) 2012 Christian Grothoff (and other contributing authors)

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
 * @author Florian Dold
 * @file consensus/consensus.h
 * @brief
 */
#ifndef CONSENSUS_H
#define CONSENSUS_H

#include "gnunet_common.h"

GNUNET_NETWORK_STRUCT_BEGIN

struct GNUNET_CONSENSUS_JoinMessage
{
  /**
   * Type: GNUNET_MESSAGE_TYPE_CONSENSUS_CLIENT_JOIN
   */
  struct GNUNET_MessageHeader header;

  struct GNUNET_HashCode session_id;

  uint16_t num_peers;

  /* GNUNET_PeerIdentity[num_peers] */
};


struct GNUNET_CONSENSUS_ConcludeMessage
{
  /**
   * Type: GNUNET_MESSAGE_TYPE_CONSENSUS_CLIENT_CONCLUDE
   */
  struct GNUNET_MessageHeader header;

  struct GNUNET_TIME_RelativeNBO timeout;
};


struct GNUNET_CONSENSUS_ConcludeDoneMessage
{
  /**
   * Type: GNUNET_MESSAGE_TYPE_CONSENSUS_CLIENT_CONCLUDE_DONE
   */
  struct GNUNET_MessageHeader header;

  uint16_t num_peers;

  /** PeerIdentity[num_peers] */
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
  uint16_t element_type;

  /* rest: element data */
};

GNUNET_NETWORK_STRUCT_END

#endif

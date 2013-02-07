/*
      This file is part of GNUnet
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

struct StrataMessage
{
  struct GNUNET_MessageHeader header;
  /**
   * Number of strata in this estimator.
   */
  uint16_t num_strata;
  /* struct GNUNET_HashCode hash_buckets[ibf_size*num_strata] */
  /* struct GNUNET_HashCode id_buckets[ibf_size*num_strata] */
  /* uint8_t count_buckets[ibf_size*num_strata] */
};

struct DifferenceDigest
{
  struct GNUNET_MessageHeader header;
  uint8_t order;
  uint8_t round;
};

struct Element
{
  struct GNUNET_MessageHeader header;
  struct GNUNET_HashCode hash;
};


struct ElementRequest
{
  struct GNUNET_MessageHeader header;
  /* struct GNUNET_HashCode[] rest */
};

struct ConsensusHello
{
  struct GNUNET_MessageHeader header;
  struct GNUNET_HashCode global_id;
  uint8_t round;
};


GNUNET_NETWORK_STRUCT_END

#endif

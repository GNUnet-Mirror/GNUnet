/*
     This file is part of GNUnet.
     (C) 2013 Christian Grothoff (and other contributing authors)

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
 * @author Florian Dold
 * @file set/set_protocol.h
 * @brief Peer-to-Peer messages for gnunet set
 */
#ifndef SET_PROTOCOL_H
#define SET_PROTOCOL_H

#include "platform.h"
#include "gnunet_common.h"


GNUNET_NETWORK_STRUCT_BEGIN

struct OperationRequestMessage
{
  /**
   * Type: #GNUNET_MESSAGE_TYPE_SET_P2P_OPERATION_REQUEST
   */
  struct GNUNET_MessageHeader header;

  /**
   * Operation to request, values from `enum GNUNET_SET_OperationType`
   */
  uint32_t operation GNUNET_PACKED;

  /**
   * Salt to use for this operation.
   */
  uint32_t salt GNUNET_PACKED;

  /**
   * For Intersection: my element count
   */
  uint32_t element_count GNUNET_PACKED;

  /**
   * Application-specific identifier of the request.
   */
  struct GNUNET_HashCode app_id;

  /* rest: optional message */
};


struct IBFMessage
{
  /**
   * Type: #GNUNET_MESSAGE_TYPE_SET_P2P_IBF
   */
  struct GNUNET_MessageHeader header;

  /**
   * Order of the whole ibf, where
   * num_buckets = 2^order
   */
  uint8_t order;

  /**
   * Padding, must be 0.
   */
  uint8_t reserved;

  /**
   * Offset of the strata in the rest of the message
   */
  uint16_t offset GNUNET_PACKED;

  /**
   * Salt used when hashing elements for this IBF.
   */
  uint32_t salt GNUNET_PACKED;

  /* rest: strata */
};


/**
 * During intersection, the first (and possibly second) message
 * send it the number of elements in the set, to allow the peers
 * to decide who should start with the Bloom filter.
 */
struct IntersectionElementInfoMessage
{
  /**
   * Type: #GNUNET_MESSAGE_TYPE_SET_INTERSECTION_P2P_ELEMENT_INFO
   */
  struct GNUNET_MessageHeader header;

  /**
   * mutator used with this bloomfilter.
   */
  uint32_t sender_element_count GNUNET_PACKED;

};


/**
 * Bloom filter messages exchanged for set intersection calculation.
 */
struct BFMessage
{
  /**
   * Type: #GNUNET_MESSAGE_TYPE_SET_INTERSECTION_P2P_BF
   */
  struct GNUNET_MessageHeader header;

  /**
   * mutator used with this bloomfilter.
   */
  uint32_t sender_element_count GNUNET_PACKED;

  /**
   * mutator used with this bloomfilter.
   */
  uint32_t sender_mutator GNUNET_PACKED;

  /**
   * Length of the bloomfilter data
   */
  uint32_t bloomfilter_total_length GNUNET_PACKED;

  /**
   * Length of the appended bloomfilter data block
   */
  uint32_t bloomfilter_length GNUNET_PACKED;

  /**
   * Length of the bloomfilter data
   */
  uint32_t bits_per_element GNUNET_PACKED;

  /**
   * rest: the sender's bloomfilter
   */
};


struct BFPart
{
  /**
   * Type: #GNUNET_MESSAGE_TYPE_SET_INTERSECTION_P2P_BF
   */
  struct GNUNET_MessageHeader header;

  /**
   * Length of the appended bloomfilter data block
   */
  uint32_t chunk_length GNUNET_PACKED;

  /**
   * offset in the bloolfilter data block, if multipart message
   */
  uint32_t chunk_offset GNUNET_PACKED;

  /**
   * rest: the sender's bloomfilter
   */
};

GNUNET_NETWORK_STRUCT_END

#endif

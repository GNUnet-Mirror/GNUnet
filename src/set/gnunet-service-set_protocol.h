/*
     This file is part of GNUnet.
     (C) 2013, 2014 Christian Grothoff (and other contributing authors)

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
 * @author Christian Grothoff
 * @file set/gnunet-service-set_protocol.h
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
   * Type: #GNUNET_MESSAGE_TYPE_SET_UNION_P2P_IBF
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
   * Number of elements the sender still has in the set.
   */
  uint32_t sender_element_count GNUNET_PACKED;

  /**
   * XOR of all hashes over all elements remaining in the set.
   * Used to determine termination.
   */
  struct GNUNET_HashCode element_xor_hash;

  /**
   * Mutator used with this bloomfilter.
   */
  uint32_t sender_mutator GNUNET_PACKED;

  /**
   * Total length of the bloomfilter data.
   */
  uint32_t bloomfilter_total_length GNUNET_PACKED;

  /**
   * Number of bits (k-value) used in encoding the bloomfilter.
   */
  uint32_t bits_per_element GNUNET_PACKED;

  /**
   * rest: the sender's bloomfilter
   */
};


/**
 * Last message, send to confirm the final set.  Contains the element
 * count as it is possible that the peer determined that we were done
 * by getting the empty set, which in that case also needs to be
 * communicated.
 */
struct IntersectionDoneMessage
{
  /**
   * Type: #GNUNET_MESSAGE_TYPE_SET_INTERSECTION_P2P_DONE
   */
  struct GNUNET_MessageHeader header;

  /**
   * Final number of elements in intersection.
   */
  uint32_t final_element_count GNUNET_PACKED;

  /**
   * XOR of all hashes over all elements remaining in the set.
   */
  struct GNUNET_HashCode element_xor_hash;
};

GNUNET_NETWORK_STRUCT_END

#endif

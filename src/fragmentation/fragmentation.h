/*
     This file is part of GNUnet
     Copyright (C) 2009, 2011 GNUnet e.V.

     GNUnet is free software: you can redistribute it and/or modify it
     under the terms of the GNU Affero General Public License as published
     by the Free Software Foundation, either version 3 of the License,
     or (at your option) any later version.

     GNUnet is distributed in the hope that it will be useful, but
     WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
     Affero General Public License for more details.
*/
/**
 * @file src/fragmentation/fragmentation.h
 * @brief library to help fragment messages
 * @author Christian Grothoff
 */
#ifndef FRAGMENTATION_H
#define FRAGMENTATION_H
#include "platform.h"
#include "gnunet_fragmentation_lib.h"

GNUNET_NETWORK_STRUCT_BEGIN

/**
 * Header for a message fragment.  Followed by the
 * original message.
 */
struct FragmentHeader
{

  /**
   * Message header.
   */
  struct GNUNET_MessageHeader header;

  /**
   * Unique fragment ID.
   */
  uint32_t fragment_id GNUNET_PACKED;

  /**
   * Total message size of the original message.
   */
  uint16_t total_size GNUNET_PACKED;

  /**
   * Absolute offset (in bytes) of this fragment in the original
   * message.  Will be a multiple of the MTU.
   */
  uint16_t offset GNUNET_PACKED;

};


/**
 * Message fragment acknowledgement.
 */
struct FragmentAcknowledgement
{

  /**
   * Message header.
   */
  struct GNUNET_MessageHeader header;

  /**
   * Unique fragment ID.
   */
  uint32_t fragment_id GNUNET_PACKED;

  /**
   * Bits that are being acknowledged, in big-endian.
   * (bits that are set correspond to fragments that
   * have not yet been received).
   */
  uint64_t bits GNUNET_PACKED;

};
GNUNET_NETWORK_STRUCT_END

#endif

/*
     This file is part of GNUnet
     Copyright (C) 2009, 2011 GNUnet e.V.

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
  uint32_t fragment_id;

  /**
   * Total message size of the original message.
   */
  uint16_t total_size;

  /**
   * Absolute offset (in bytes) of this fragment in the original
   * message.  Will be a multiple of the MTU.
   */
  uint16_t offset;

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
  uint32_t fragment_id;

  /**
   * Bits that are being acknowledged, in big-endian.
   * (bits that are set correspond to fragments that
   * have not yet been received).
   */
  uint64_t bits;

};
GNUNET_NETWORK_STRUCT_END

#endif

/*
     This file is part of GNUnet.
     Copyright (C) 2001-2011 GNUnet e.V.

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
 * @author Markus Teich
 * @file auction/auction.h
 *
 * @brief Common type definitions for the auction service and API.
 */
#ifndef AUCTION_H
#define AUCTION_H

#include "gnunet_common.h"

GNUNET_NETWORK_STRUCT_BEGIN

/**
 * Auction creation request sent from the client to the service
 */
struct GNUNET_AUCTION_ClientCreateMessage
{
  /**
   * Type: GNUNET_MESSAGE_TYPE_AUCTION_CLIENT_CREATE
   */
  struct GNUNET_MessageHeader header;

  /**
   * When should the auction start
   */
  struct GNUNET_TIME_AbsoluteNBO time_start;

  /**
   * How long is each round allowed to be maximally
   */
  struct GNUNET_TIME_RelativeNBO time_round;

  /**
   * Auction parameter m.
   * 0 for first price auctions.
   * >0 for M+1st price auctions.
   */
  uint16_t m GNUNET_PACKED;

  /**
   * Should the auction outcome be public?
   * 0 for private outcome auctions.
   * 1 for public outcome auctions.
   */
  uint16_t outcome_public GNUNET_PACKED;

  /**
   * TODO: Price mapping.
   */

  /* DESCRIPTION text copied to end of this message */
};

GNUNET_NETWORK_STRUCT_END

#endif

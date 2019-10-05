/*
     This file is part of GNUnet.
     Copyright (C) 2001-2011 GNUnet e.V.

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
 * @author Nathan Evans
 * @file nse/nse.h
 *
 * @brief Common type definitions for the network size estimation
 *        service and API.
 */
#ifndef NSE_H
#define NSE_H

#include "gnunet_common.h"

GNUNET_NETWORK_STRUCT_BEGIN

/**
 * Network size estimate sent from the service
 * to clients.  Contains the current size estimate
 * (or 0 if none has been calculated) and the
 * standard deviation of known estimates.
 *
 */
struct GNUNET_NSE_ClientMessage
{
  /**
   * Type: GNUNET_MESSAGE_TYPE_NSE_ESTIMATE
   */
  struct GNUNET_MessageHeader header;

  /**
   * For alignment.
   */
  uint32_t reserved GNUNET_PACKED;

  /**
   * Timestamp at which the server received the message.
   */
  struct GNUNET_TIME_AbsoluteNBO timestamp;

  /**
   * The current estimated network size.
   */
  double size_estimate GNUNET_PACKED;

  /**
   * The standard deviation (rounded down
   * to the nearest integer) of size
   * estimations.
   */
  double std_deviation GNUNET_PACKED;
};
GNUNET_NETWORK_STRUCT_END

#endif

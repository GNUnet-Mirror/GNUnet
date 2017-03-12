
/*
      This file is part of GNUnet
      Copyright (C) 2013-2017 GNUnet e.V.

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
 * @file set/gnunet-service-set_intersection.h
 * @brief two-peer set operations
 * @author Florian Dold
 * @author Christian Grothoff
 */
#ifndef GNUNET_SERVICE_SET_INTERSECTION_H
#define GNUNET_SERVICE_SET_INTERSECTION_H

#include "gnunet-service-set.h"


/**
 * Check an BF message from a remote peer.
 *
 * @param cls the intersection operation
 * @param msg the header of the message
 * @return #GNUNET_OK if @a msg is well-formed
 */
int
check_intersection_p2p_bf (void *cls,
                           const struct BFMessage *msg);


/**
 * Handle an BF message from a remote peer.
 *
 * @param cls the intersection operation
 * @param msg the header of the message
 */
void
handle_intersection_p2p_bf (void *cls,
                            const struct BFMessage *msg);


/**
 * Handle the initial `struct IntersectionElementInfoMessage` from a
 * remote peer.
 *
 * @param cls the intersection operation
 * @param mh the header of the message
 */
void
handle_intersection_p2p_element_info (void *cls,
                                      const struct IntersectionElementInfoMessage *msg);


/**
 * Handle a done message from a remote peer
 *
 * @param cls the intersection operation
 * @param mh the message
 */
void
handle_intersection_p2p_done (void *cls,
                              const struct IntersectionDoneMessage *idm);


#endif

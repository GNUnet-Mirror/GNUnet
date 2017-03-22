
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
 * @file set/gnunet-service-set_union.h
 * @brief two-peer set operations
 * @author Florian Dold
 * @author Christian Grothoff
 */
#ifndef GNUNET_SERVICE_SET_UNION_H
#define GNUNET_SERVICE_SET_UNION_H

#include "gnunet-service-set.h"
#include "gnunet-service-set_protocol.h"


/**
 * Handle a strata estimator from a remote peer
 *
 * @param cls the union operation
 * @param msg the message
 */
int
check_union_p2p_strata_estimator (void *cls,
                                  const struct StrataEstimatorMessage *msg);


/**
 * Handle a strata estimator from a remote peer
 *
 * @param cls the union operation
 * @param msg the message
 */
void
handle_union_p2p_strata_estimator (void *cls,
                                   const struct StrataEstimatorMessage *msg);


/**
 * Check an IBF message from a remote peer.
 *
 * Reassemble the IBF from multiple pieces, and
 * process the whole IBF once possible.
 *
 * @param cls the union operation
 * @param msg the header of the message
 * @return #GNUNET_OK if @a msg is well-formed
 */
int
check_union_p2p_ibf (void *cls,
                     const struct IBFMessage *msg);


/**
 * Handle an IBF message from a remote peer.
 *
 * Reassemble the IBF from multiple pieces, and
 * process the whole IBF once possible.
 *
 * @param cls the union operation
 * @param msg the header of the message
 */
void
handle_union_p2p_ibf (void *cls,
                      const struct IBFMessage *msg);


/**
 * Check an element message from a remote peer.
 *
 * @param cls the union operation
 * @param emsg the message
 */
int
check_union_p2p_elements (void *cls,
                          const struct GNUNET_SET_ElementMessage *emsg);


/**
 * Handle an element message from a remote peer.
 * Sent by the other peer either because we decoded an IBF and placed a demand,
 * or because the other peer switched to full set transmission.
 *
 * @param cls the union operation
 * @param emsg the message
 */
void
handle_union_p2p_elements (void *cls,
                           const struct GNUNET_SET_ElementMessage *emsg);


/**
 * Check a full element message from a remote peer.
 *
 * @param cls the union operation
 * @param emsg the message
 */
int
check_union_p2p_full_element (void *cls,
                              const struct GNUNET_SET_ElementMessage *emsg);


/**
 * Handle an element message from a remote peer.
 *
 * @param cls the union operation
 * @param emsg the message
 */
void
handle_union_p2p_full_element (void *cls,
                               const struct GNUNET_SET_ElementMessage *emsg);


/**
 * Send offers (for GNUNET_Hash-es) in response
 * to inquiries (for IBF_Key-s).
 *
 * @param cls the union operation
 * @param msg the message
 */
int
check_union_p2p_inquiry (void *cls,
                         const struct InquiryMessage *msg);


/**
 * Send offers (for GNUNET_Hash-es) in response
 * to inquiries (for IBF_Key-s).
 *
 * @param cls the union operation
 * @param msg the message
 */
void
handle_union_p2p_inquiry (void *cls,
                          const struct InquiryMessage *msg);



/**
 * Handle a request for full set transmission.
 *
 * @parem cls closure, a set union operation
 * @param mh the demand message
 */
void
handle_union_p2p_request_full (void *cls,
                               const struct GNUNET_MessageHeader *mh);



/**
 * Handle a "full done" message.
 *
 * @parem cls closure, a set union operation
 * @param mh the demand message
 */
void
handle_union_p2p_full_done (void *cls,
                            const struct GNUNET_MessageHeader *mh);


/**
 * Check a demand by the other peer for elements based on a list
 * of `struct GNUNET_HashCode`s.
 *
 * @parem cls closure, a set union operation
 * @param mh the demand message
 * @return #GNUNET_OK if @a mh is well-formed
 */
int
check_union_p2p_demand (void *cls,
                        const struct GNUNET_MessageHeader *mh);


/**
 * Handle a demand by the other peer for elements based on a list
 * of `struct GNUNET_HashCode`s.
 *
 * @parem cls closure, a set union operation
 * @param mh the demand message
 */
void
handle_union_p2p_demand (void *cls,
                         const struct GNUNET_MessageHeader *mh);


/**
 * Check offer (of `struct GNUNET_HashCode`s).
 *
 * @param cls the union operation
 * @param mh the message
 * @return #GNUNET_OK if @a mh is well-formed
 */
int
check_union_p2p_offer (void *cls,
                       const struct GNUNET_MessageHeader *mh);


/**
 * Handle offers (of `struct GNUNET_HashCode`s) and
 * respond with demands (of `struct GNUNET_HashCode`s).
 *
 * @param cls the union operation
 * @param mh the message
 */
void
handle_union_p2p_offer (void *cls,
                        const struct GNUNET_MessageHeader *mh);


/**
 * Handle a done message from a remote peer
 *
 * @param cls the union operation
 * @param mh the message
 */
void
handle_union_p2p_done (void *cls,
                       const struct GNUNET_MessageHeader *mh);


#endif

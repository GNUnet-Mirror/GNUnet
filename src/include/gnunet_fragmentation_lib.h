/*
     This file is part of GNUnet
     (C) 2009 Christian Grothoff (and other contributing authors)

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
 * @file include/gnunet_fragmentation_lib.h
 * @brief library to help fragment messages
 * @author Christian Grothoff
 */

#ifndef GNUNET_FRAGMENTATION_LIB_H
#define GNUNET_FRAGMENTATION_LIB_H

#include "gnunet_common.h"
#include "gnunet_statistics_service.h"

#ifdef __cplusplus
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif

/**
 * Function that is called with messages
 * created by the fragmentation module.
 *
 * @param cls closure
 * @param msg the message that was created
 */
typedef void (*GNUNET_FRAGMENT_MessageProcessor) (void *cls,
                                                  const struct
                                                  GNUNET_MessageHeader * msg);


/**
 * Fragment an over-sized message.
 *
 * @param msg the message to fragment
 * @param mtu the maximum message size
 * @param proc function to call for each fragment
 * @param proc_cls closure for proc
 */
void GNUNET_FRAGMENT_fragment (const struct GNUNET_MessageHeader *msg,
                               uint16_t mtu,
                               GNUNET_FRAGMENT_MessageProcessor proc,
                               void *proc_cls);

/**
 * Defragmentation context.
 */
struct GNUNET_FRAGMENT_Context;

/**
 * Create a defragmentation context.
 *
 * @param stats statistics context
 * @param proc function to call with defragmented messages
 * @param proc_cls closure for proc
 * @return the defragmentation context
 */
struct GNUNET_FRAGMENT_Context *GNUNET_FRAGMENT_context_create (struct
                                                                GNUNET_STATISTICS_Handle
                                                                *stats,
                                                                GNUNET_FRAGMENT_MessageProcessor
                                                                proc,
                                                                void
                                                                *proc_cls);


/**
 * Destroy the given defragmentation context.
 */
void GNUNET_FRAGMENT_context_destroy (struct GNUNET_FRAGMENT_Context *ctx);


/**
 * We have received a fragment.  Process it.
 *
 * @param ctx the context
 * @param sender who transmitted the fragment
 * @param msg the message that was received
 */
void GNUNET_FRAGMENT_process (struct GNUNET_FRAGMENT_Context *ctx,
                              const struct GNUNET_PeerIdentity *sender,
                              const struct GNUNET_MessageHeader *msg);


#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

/* end of gnunet_fragmentation_lib.h */
#endif

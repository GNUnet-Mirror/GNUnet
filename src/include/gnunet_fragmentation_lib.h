/*
     This file is part of GNUnet
     Copyright (C) 2009, 2011, 2015 Christian Grothoff (and other contributing authors)

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
 * @file include/gnunet_fragmentation_lib.h
 * @brief library to help fragment messages
 * @author Christian Grothoff
 *
 * TODO: consider additional flow-control for sending from
 *       fragmentation based on continuations.
 */

#ifndef GNUNET_FRAGMENTATION_LIB_H
#define GNUNET_FRAGMENTATION_LIB_H

#include "gnunet_util_lib.h"
#include "gnunet_bandwidth_lib.h"
#include "gnunet_statistics_service.h"

#ifdef __cplusplus
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif


/**
 * Fragmentation context.
 */
struct GNUNET_FRAGMENT_Context;


/**
 * Function that is called with messages created by the fragmentation
 * module.  In the case of the 'proc' callback of the
 * #GNUNET_FRAGMENT_context_create() function, this function must
 * eventually call #GNUNET_FRAGMENT_context_transmission_done().
 *
 * @param cls closure
 * @param msg the message that was created
 */
typedef void
(*GNUNET_FRAGMENT_MessageProcessor) (void *cls,
                                     const struct GNUNET_MessageHeader *msg);


/**
 * Create a fragmentation context for the given message.
 * Fragments the message into fragments of size @a mtu or
 * less.  Calls @a proc on each un-acknowledged fragment,
 * using both the expected @a msg_delay between messages and
 * acknowledgements and the given @a tracker to guide the
 * frequency of calls to @a proc.
 *
 * @param stats statistics context
 * @param mtu the maximum message size for each fragment
 * @param tracker bandwidth tracker to use for flow control (can be NULL)
 * @param msg_delay initial delay to insert between fragment transmissions
 *              based on previous messages
 * @param ack_delay expected delay between fragment transmission
 *              and ACK based on previous messages
 * @param msg the message to fragment
 * @param proc function to call for each fragment to transmit
 * @param proc_cls closure for proc
 * @return the fragmentation context
 */
struct GNUNET_FRAGMENT_Context *
GNUNET_FRAGMENT_context_create (struct GNUNET_STATISTICS_Handle *stats,
                                uint16_t mtu,
                                struct GNUNET_BANDWIDTH_Tracker *tracker,
                                struct GNUNET_TIME_Relative msg_delay,
                                struct GNUNET_TIME_Relative ack_delay,
                                const struct GNUNET_MessageHeader *msg,
                                GNUNET_FRAGMENT_MessageProcessor proc,
                                void *proc_cls);


/**
 * Continuation to call from the 'proc' function after the fragment
 * has been transmitted (and hence the next fragment can now be
 * given to proc).
 *
 * @param fc fragmentation context
 */
void
GNUNET_FRAGMENT_context_transmission_done (struct GNUNET_FRAGMENT_Context *fc);


/**
 * Process an acknowledgement message we got from the other
 * side (to control re-transmits).
 *
 * @param fc fragmentation context
 * @param msg acknowledgement message we received
 * @return #GNUNET_OK if this ack completes the work of the 'fc'
 *                   (all fragments have been received);
 *         #GNUNET_NO if more messages are pending
 *         #GNUNET_SYSERR if this ack is not valid for this fc
 */
int
GNUNET_FRAGMENT_process_ack (struct GNUNET_FRAGMENT_Context *fc,
                             const struct GNUNET_MessageHeader *msg);


/**
 * Destroy the given fragmentation context (stop calling 'proc', free
 * resources).
 *
 * @param fc fragmentation context
 * @param msg_delay where to store average delay between individual message transmissions the
 *         last message (OUT only)
 * @param ack_delay where to store average delay between transmission and ACK for the
 *         last message, set to FOREVER if the message was not fully transmitted (OUT only)
 */
void
GNUNET_FRAGMENT_context_destroy (struct GNUNET_FRAGMENT_Context *fc,
				 struct GNUNET_TIME_Relative *msg_delay,
				 struct GNUNET_TIME_Relative *ack_delay);


/**
 * Convert an ACK message to a printable format suitable for logging.
 *
 * @param ack message to print
 * @return ack in human-readable format
 */
const char *
GNUNET_FRAGMENT_print_ack (const struct GNUNET_MessageHeader *ack);


/**
 * Defragmentation context (one per connection).
 */
struct GNUNET_DEFRAGMENT_Context;


/**
 * Function that is called with acknowledgement messages created by
 * the fragmentation module.  Acknowledgements are cummulative,
 * so it is OK to only transmit the 'latest' ack message for the same
 * message ID.
 *
 * @param cls closure
 * @param id unique message ID (modulo collisions)
 * @param msg the message that was created
 */
typedef void
(*GNUNET_DEFRAGMENT_AckProcessor) (void *cls,
                                   uint32_t id,
                                   const struct GNUNET_MessageHeader *msg);


/**
 * Create a defragmentation context.
 *
 * @param stats statistics context
 * @param mtu the maximum message size for each fragment
 * @param num_msgs how many fragmented messages
 *                 to we defragment at most at the same time?
 * @param cls closure for @a proc and @a ackp
 * @param proc function to call with defragmented messages
 * @param ackp function to call with acknowledgements (to send
 *             back to the other side)
 * @return the defragmentation context
 */
struct GNUNET_DEFRAGMENT_Context *
GNUNET_DEFRAGMENT_context_create (struct GNUNET_STATISTICS_Handle *stats,
                                  uint16_t mtu,
                                  unsigned int num_msgs,
                                  void *cls,
                                  GNUNET_FRAGMENT_MessageProcessor proc,
                                  GNUNET_DEFRAGMENT_AckProcessor ackp);


/**
 * Destroy the given defragmentation context.
 *
 * @param dc defragmentation context
 */
void
GNUNET_DEFRAGMENT_context_destroy (struct GNUNET_DEFRAGMENT_Context *dc);


/**
 * We have received a fragment.  Process it.
 *
 * @param dc the context
 * @param msg the message that was received
 * @return #GNUNET_OK on success,
 *         #GNUNET_NO if this was a duplicate,
 *         #GNUNET_SYSERR on error
 */
int
GNUNET_DEFRAGMENT_process_fragment (struct GNUNET_DEFRAGMENT_Context *dc,
                                    const struct GNUNET_MessageHeader *msg);


#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

/* end of gnunet_fragmentation_lib.h */
#endif

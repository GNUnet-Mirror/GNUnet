/*
     This file is part of GNUnet
     (C) 2009, 2011 Christian Grothoff (and other contributing authors)

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
 * @file src/fragmentation/defragmentation_new.c
 * @brief library to help defragment messages
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_fragmentation_lib.h"
#include "fragmentation.h"


/**
 * Timestamps for fragments.
 */
struct FragTimes
{
  /**
   * The time the fragment was received.
   */
  GNUNET_TIME_Absolute time;

  /**
   * Number of the bit for the fragment (in [0,..,63]).
   */
  unsigned int bit;
};


/**
 * Information we keep for one message that is being assembled.
 */
struct MessageContext
{
  /**
   * This is a DLL.
   */
  struct MessageContext *next;

  /**
   * This is a DLL.
   */
  struct MessageContext *prev;

  /**
   * Pointer to the assembled message, allocated at the
   * end of this struct.
   */ 
  const struct GNUNET_MessageHeader *msg;

  /**
   * Last time we received any update for this message
   * (least-recently updated message will be discarded
   * if we hit the queue size).
   */
  struct GNUNET_TIME_Absolute last_update;

  /**
   * Task scheduled for transmitting the next ACK to the
   * other peer.
   */
  struct GNUNET_SCHEDULER_TaskIdentifier ack_task;

  /**
   * When did we receive which fragment? Used to calculate
   * the time we should send the ACK.
   */
  struct FragTimes frag_times[64];

  /**
   * Which fragments have we gotten yet? bits that are 1
   * indicate missing fragments.
   */
  uint64_t bits;

  /**
   * Unique ID for this message.
   */
  uint32_t fragment_id;

  /**
   * For the current ACK round, which is the first relevant
   * offset in 'frag_times'?
   */
  unsigned int frag_times_start_offset;

  /**
   * Which offset whould we write the next frag value into
   * in the 'frag_times' array? All smaller entries are valid.
   */
  unsigned int frag_times_write_offset;

  /**
   * Total size of the message that we are assembling.
   */
  uint16_t total_size;

};


/**
 * Defragmentation context (one per connection).
 */
struct GNUNET_DEFRAGMENT_Context
{

  /**
   * For statistics.
   */
  struct GNUNET_STATISTICS_Handle *stats;

  /**
   * Closure for 'proc' and 'ackp'.
   */
  void *cls;

  /**
   * Head of list of messages we're defragmenting.
   */
  struct MessageContext *head;

  /**
   * Tail of list of messages we're defragmenting.
   */
  struct MessageContext *tail;

  /**
   * Function to call with defragmented messages.
   */
  GNUNET_FRAGMENT_MessageProcessor proc;

  /**
   * Function to call with acknowledgements.
   */
  GNUNET_FRAGMENT_MessageProcessor ackp;

  /**
   * Running average of the latency (delay between messages) for this
   * connection.
   */
  struct GNUNET_TIME_Relative latency;

  /**
   * num_msgs how many fragmented messages
   * to we defragment at most at the same time?
   */
  unsigned int num_msgs;

  /**
   * Current number of messages in the 'struct MessageContext'
   * DLL (smaller or equal to 'num_msgs').
   */
  unsigned int list_size;


};


/**
 * Create a defragmentation context.
 *
 * @param stats statistics context
 * @param num_msgs how many fragmented messages
 *                 to we defragment at most at the same time?
 * @param cls closure for proc and ackp
 * @param proc function to call with defragmented messages
 * @param ackp function to call with acknowledgements (to send
 *             back to the other side)
 * @return the defragmentation context
 */
struct GNUNET_DEFRAGMENT_Context *
GNUNET_DEFRAGMENT_context_create (struct GNUNET_STATISTICS_Handle *stats,
				  unsigned int num_msgs,
				  void *cls,
				  GNUNET_FRAGMENT_MessageProcessor proc,
				  GNUNET_FRAGMENT_MessageProcessor ackp)
{
  struct GNUNET_DEFRAGMENT_Context *dc;

  dc = GNUNET_malloc (sizeof (struct GNUNET_DEFRAGMENT_Context));
  dc->stats = stats;
  dc->cls = cls;
  dc->proc = proc;
  dc->ackp = ackp;
  dc->num_msgs = num_msgs;
  dc->latency = GNUNET_TIME_UNIT_SECONDS; /* start with likely overestimate */
  return dc;
}


/**
 * Destroy the given defragmentation context.
 *
 * @param dc defragmentation context
 */
void 
GNUNET_DEFRAGMENT_context_destroy (struct GNUNET_DEFRAGMENT_Context *dc)
{
  GNUNET_free (dc);
}


/**
 * We have received a fragment.  Process it.
 *
 * @param dc the context
 * @param msg the message that was received
 */
void 
GNUNET_DEFRAGMENT_process_fragment (struct GNUNET_DEFRAGMENT_Context *dc,
				    const struct GNUNET_MessageHeader *msg)
{
}

/* end of defragmentation_new.c */


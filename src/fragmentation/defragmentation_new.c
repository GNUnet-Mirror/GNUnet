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
  struct GNUNET_TIME_Absolute time;

  /**
   * Number of the bit for the fragment (in [0,..,63]).
   */
  unsigned int bit;
};


/**
 * Information we keep for one message that is being assembled.  Note
 * that we keep the context around even after the assembly is done to
 * handle 'stray' messages that are received 'late'.  A message
 * context is ONLY discarded when the queue gets too big.
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
   * Associated defragmentation context.
   */
  struct GNUNET_DEFRAGMENT_Context *dc;

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
  GNUNET_SCHEDULER_TaskIdentifier ack_task;

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
   * Head of list of messages we're defragmenting.
   */
  struct MessageContext *head;

  /**
   * Tail of list of messages we're defragmenting.
   */
  struct MessageContext *tail;

  /**
   * Closure for 'proc' and 'ackp'.
   */
  void *cls;

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

  /**
   * Maximum message size for each fragment.
   */ 
  uint16_t mtu;
};


/**
 * Create a defragmentation context.
 *
 * @param stats statistics context
 * @param mtu the maximum message size for each fragment 
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
				  uint16_t mtu,
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
  dc->mtu = mtu;
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
  struct MessageContext *mc;

  while (NULL != (mc = dc->head))
    {
      GNUNET_CONTAINER_DLL_remove (dc->head,
				   dc->tail,
				   mc);
      dc->list_size--;
      if (GNUNET_SCHEDULER_NO_TASK != mc->ack_task)
	{
	  GNUNET_SCHEDULER_cancel (mc->ack_task);
	  mc->ack_task = GNUNET_SCHEDULER_NO_TASK;
	}
      GNUNET_free (mc);
    }
  GNUNET_assert (0 == dc->list_size);
  GNUNET_free (dc);
}


/**
 * Send acknowledgement to the other peer now.
 *
 * @param cls the message context
 * @param tc the scheduler context
 */
static void
send_ack (void *cls,
	  const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct MessageContext *mc = cls;
  struct GNUNET_DEFRAGMENT_Context *dc = mc->dc;
  struct FragmentAcknowledgement fa;

  mc->ack_task = GNUNET_SCHEDULER_NO_TASK;
  fa.header.size = htons (sizeof (struct FragmentAcknowledgement));
  fa.header.type = htons (GNUNET_MESSAGE_TYPE_FRAGMENT_ACK);
  fa.fragment_id = htonl (mc->fragment_id);
  fa.bits = GNUNET_htonll (mc->bits);
  dc->ackp (dc->cls, &fa.header);
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
  struct MessageContext *mc;
  const struct FragmentHeader *fh;
  uint16_t msize;
  uint16_t foff;
  uint32_t fid;
  char *mbuf;
  unsigned int bit;
  struct GNUNET_TIME_Absolute now;
  struct GNUNET_TIME_Relative delay;

  if (ntohs(msg->size) < sizeof (struct FragmentHeader))
    {
      GNUNET_break_op (0);
      return;
    }
  if (ntohs (msg->size) > dc->mtu)
    {
      GNUNET_break_op (0);
      return;
    }
  fh = (const struct FragmentHeader*) msg;
  msize = ntohs (fh->total_size);
  fid = ntohl (fh->fragment_id);
  foff = ntohl (fh->offset);
  if (foff >= msize)
    {
      GNUNET_break_op (0);
      return;
    }
  GNUNET_STATISTICS_update (dc->stats,
			    _("Fragments received"),
			    1,
			    GNUNET_NO);
  mc = dc->head;
  while ( (NULL != mc) &&
	  (fid != mc->fragment_id) )
    mc = mc->next;
  bit = foff / dc->mtu;
  if (bit * dc->mtu + ntohs (msg->size) 
      - sizeof (struct FragmentHeader) > msize)
    {
      /* payload extends past total message size */
      GNUNET_break_op (0);
      return;
    }
  if ( (NULL != mc) && (msize != mc->total_size) )
    {
      /* inconsistent message size */
      GNUNET_break_op (0);
      return;
    }
  now = GNUNET_TIME_absolute_get ();
  if (NULL == mc)
    {
      mc = GNUNET_malloc (sizeof (struct MessageContext) + msize);
      mc->msg = (const struct GNUNET_MessageHeader*) &mc[1];
      mc->dc = dc;
      mc->total_size = msize;
      mc->fragment_id = fid;      
      mc->last_update = now;
      mc->bits = (msize + dc->mtu - 1) / (dc->mtu - sizeof (struct FragmentHeader));   
      GNUNET_CONTAINER_DLL_insert (dc->head,
				   dc->tail,
				   mc);
      dc->list_size++;
      if (dc->list_size > dc->num_msgs)
	{
	  /* FIXME: discard oldest entry... */
	}
    }

  /* copy data to 'mc' */
  if (0 != (mc->bits & (1 << bit)))
    {
      mc->bits -= 1 << bit;
      mbuf = (char* )&mc[1];
      memcpy (&mbuf[bit * dc->mtu],
	      &fh[1],
	      ntohs (msg->size) - sizeof (struct FragmentHeader));
      mc->last_update = now;
      mc->frag_times[mc->frag_times_write_offset].time = now;
      mc->frag_times[mc->frag_times_write_offset].bit = bit;
      mc->frag_times_write_offset++;
      if (0 == mc->bits)	
	{
	  /* message complete, notify! */
	  dc->proc (dc->cls,
		    mc->msg);
	  GNUNET_STATISTICS_update (dc->stats,
				    _("Messages defragmented"),
				    1,
				    GNUNET_NO);
	}
    }
  else
    {
      GNUNET_STATISTICS_update (dc->stats,
				_("Duplicate fragments received"),
				1,
				GNUNET_NO);
    }

  /* FIXME: update ACK timer (if 0==mc->bits, always ACK now!) */
  delay = GNUNET_TIME_UNIT_SECONDS; /* FIXME: bad! */
  if (mc->frag_times_write_offset == 1)
    {
      /* FIXME: use number-of-fragments * dc->delay */
    }
  else
    {
      /* FIXME: use best-fit regression */
    }
  /* FIXME: update dc->latency! */

  if (0 == mc->bits)
    delay = GNUNET_TIME_UNIT_ZERO;
  if (GNUNET_SCHEDULER_NO_TASK != mc->ack_task)
    GNUNET_SCHEDULER_cancel (mc->ack_task);
  mc->ack_task = GNUNET_SCHEDULER_add_delayed (delay,
					       &send_ack,
					       mc);
}

/* end of defragmentation_new.c */


/*
     This file is part of GNUnet
     Copyright (C) 2009-2013 Christian Grothoff (and other contributing authors)

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
 * @file src/fragmentation/fragmentation.c
 * @brief library to help fragment messages
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_fragmentation_lib.h"
#include "gnunet_protocols.h"
#include "fragmentation.h"


/**
 * Absolute minimum delay we impose between sending and expecting ACK to arrive.
 */
#define MIN_ACK_DELAY GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MILLISECONDS, 1)


/**
 * Fragmentation context.
 */
struct GNUNET_FRAGMENT_Context
{
  /**
   * Statistics to use.
   */
  struct GNUNET_STATISTICS_Handle *stats;

  /**
   * Tracker for flow control.
   */
  struct GNUNET_BANDWIDTH_Tracker *tracker;

  /**
   * Current expected delay for ACKs.
   */
  struct GNUNET_TIME_Relative ack_delay;

  /**
   * Current expected delay between messages.
   */
  struct GNUNET_TIME_Relative msg_delay;

  /**
   * Next allowed transmission time.
   */
  struct GNUNET_TIME_Absolute delay_until;

  /**
   * Time we transmitted the last message of the last round.
   */
  struct GNUNET_TIME_Absolute last_round;

  /**
   * Message to fragment (allocated at the end of this struct).
   */
  const struct GNUNET_MessageHeader *msg;

  /**
   * Function to call for transmissions.
   */
  GNUNET_FRAGMENT_MessageProcessor proc;

  /**
   * Closure for @e proc.
   */
  void *proc_cls;

  /**
   * Bitfield, set to 1 for each unacknowledged fragment.
   */
  uint64_t acks;

  /**
   * Bitfield with all possible bits for 'acks' (used to mask the
   * ack we get back).
   */
  uint64_t acks_mask;

  /**
   * Task performing work for the fragmenter.
   */
  struct GNUNET_SCHEDULER_Task *task;

  /**
   * Our fragmentation ID. (chosen at random)
   */
  uint32_t fragment_id;

  /**
   * Round-robin selector for the next transmission.
   */
  unsigned int next_transmission;

  /**
   * How many rounds of transmission have we completed so far?
   */
  unsigned int num_rounds;

  /**
   * How many transmission have we completed in this round?
   */
  unsigned int num_transmissions;

  /**
   * #GNUNET_YES if we called @e proc and are now waiting for #GNUNET_FRAGMENT_transmission_done()
   */
  int8_t proc_busy;

  /**
   * #GNUNET_YES if we are waiting for an ACK.
   */
  int8_t wack;

  /**
   * Target fragment size.
   */
  uint16_t mtu;

};


/**
 * Convert an ACK message to a printable format suitable for logging.
 *
 * @param ack message to print
 * @return ack in human-readable format
 */
const char *
GNUNET_FRAGMENT_print_ack (const struct GNUNET_MessageHeader *ack)
{
  static char buf[128];
  const struct FragmentAcknowledgement *fa;

  if (sizeof (struct FragmentAcknowledgement) !=
      htons (ack->size))
    return "<malformed ack>";
  fa = (const struct FragmentAcknowledgement *) ack;
  GNUNET_snprintf (buf,
                   sizeof (buf),
                   "%u-%llX",
                   ntohl (fa->fragment_id),
                   GNUNET_ntohll (fa->bits));
  return buf;
}


/**
 * Transmit the next fragment to the other peer.
 *
 * @param cls the `struct GNUNET_FRAGMENT_Context`
 * @param tc scheduler context
 */
static void
transmit_next (void *cls,
               const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_FRAGMENT_Context *fc = cls;
  char msg[fc->mtu];
  const char *mbuf;
  struct FragmentHeader *fh;
  struct GNUNET_TIME_Relative delay;
  unsigned int bit;
  size_t size;
  size_t fsize;
  int wrap;

  fc->task = NULL;
  GNUNET_assert (GNUNET_NO == fc->proc_busy);
  if (0 == fc->acks)
    return;                     /* all done */
  /* calculate delay */
  wrap = 0;
  while (0 == (fc->acks & (1LL << fc->next_transmission)))
  {
    fc->next_transmission = (fc->next_transmission + 1) % 64;
    wrap |= (0 == fc->next_transmission);
  }
  bit = fc->next_transmission;
  size = ntohs (fc->msg->size);
  if (bit == size / (fc->mtu - sizeof (struct FragmentHeader)))
    fsize =
        (size % (fc->mtu - sizeof (struct FragmentHeader))) +
        sizeof (struct FragmentHeader);
  else
    fsize = fc->mtu;
  if (NULL != fc->tracker)
    delay = GNUNET_BANDWIDTH_tracker_get_delay (fc->tracker, fsize);
  else
    delay = GNUNET_TIME_UNIT_ZERO;
  if (delay.rel_value_us > 0)
  {
    fc->task = GNUNET_SCHEDULER_add_delayed (delay, &transmit_next, fc);
    return;
  }
  fc->next_transmission = (fc->next_transmission + 1) % 64;
  wrap |= (0 == fc->next_transmission);
  while (0 == (fc->acks & (1LL << fc->next_transmission)))
  {
    fc->next_transmission = (fc->next_transmission + 1) % 64;
    wrap |= (0 == fc->next_transmission);
  }

  /* assemble fragmentation message */
  mbuf = (const char *) &fc[1];
  fh = (struct FragmentHeader *) msg;
  fh->header.size = htons (fsize);
  fh->header.type = htons (GNUNET_MESSAGE_TYPE_FRAGMENT);
  fh->fragment_id = htonl (fc->fragment_id);
  fh->total_size = fc->msg->size;       /* already in big-endian */
  fh->offset = htons ((fc->mtu - sizeof (struct FragmentHeader)) * bit);
  memcpy (&fh[1], &mbuf[bit * (fc->mtu - sizeof (struct FragmentHeader))],
          fsize - sizeof (struct FragmentHeader));
  if (NULL != fc->tracker)
    GNUNET_BANDWIDTH_tracker_consume (fc->tracker, fsize);
  GNUNET_STATISTICS_update (fc->stats, _("# fragments transmitted"), 1,
                            GNUNET_NO);
  if (0 != fc->last_round.abs_value_us)
    GNUNET_STATISTICS_update (fc->stats, _("# fragments retransmitted"), 1,
                              GNUNET_NO);

  /* select next message to calculate delay */
  bit = fc->next_transmission;
  size = ntohs (fc->msg->size);
  if (bit == size / (fc->mtu - sizeof (struct FragmentHeader)))
    fsize = size % (fc->mtu - sizeof (struct FragmentHeader));
  else
    fsize = fc->mtu;
  if (NULL != fc->tracker)
    delay = GNUNET_BANDWIDTH_tracker_get_delay (fc->tracker, fsize);
  else
    delay = GNUNET_TIME_UNIT_ZERO;
  delay = GNUNET_TIME_relative_max (delay,
				    GNUNET_TIME_relative_multiply (fc->msg_delay,
								   (1 << fc->num_rounds)));
  if (wrap)
  {
    /* full round transmitted wait 2x delay for ACK before going again */
    fc->num_rounds++;
    delay = GNUNET_TIME_relative_multiply (fc->ack_delay, 2);
    /* never use zero, need some time for ACK always */
    delay = GNUNET_TIME_relative_max (MIN_ACK_DELAY, delay);
    fc->wack = GNUNET_YES;
    fc->last_round = GNUNET_TIME_absolute_get ();
    GNUNET_STATISTICS_update (fc->stats, _("# fragments wrap arounds"), 1,
                              GNUNET_NO);
  }
  fc->proc_busy = GNUNET_YES;
  fc->delay_until = GNUNET_TIME_relative_to_absolute (delay);
  fc->num_transmissions++;
  fc->proc (fc->proc_cls, &fh->header);
}


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
 * @param proc_cls closure for @a proc
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
                                void *proc_cls)
{
  struct GNUNET_FRAGMENT_Context *fc;
  size_t size;
  uint64_t bits;

  GNUNET_STATISTICS_update (stats, _("# messages fragmented"), 1, GNUNET_NO);
  GNUNET_assert (mtu >= 1024 + sizeof (struct FragmentHeader));
  size = ntohs (msg->size);
  GNUNET_STATISTICS_update (stats, _("# total size of fragmented messages"),
                            size, GNUNET_NO);
  GNUNET_assert (size >= sizeof (struct GNUNET_MessageHeader));
  fc = GNUNET_malloc (sizeof (struct GNUNET_FRAGMENT_Context) + size);
  fc->stats = stats;
  fc->mtu = mtu;
  fc->tracker = tracker;
  fc->ack_delay = ack_delay;
  fc->msg_delay = msg_delay;
  fc->msg = (const struct GNUNET_MessageHeader *) &fc[1];
  fc->proc = proc;
  fc->proc_cls = proc_cls;
  fc->fragment_id =
      GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK, UINT32_MAX);
  memcpy (&fc[1], msg, size);
  bits =
      (size + mtu - sizeof (struct FragmentHeader) - 1) / (mtu -
                                                           sizeof (struct
                                                                   FragmentHeader));
  GNUNET_assert (bits <= 64);
  if (bits == 64)
    fc->acks_mask = UINT64_MAX; /* set all 64 bit */
  else
    fc->acks_mask = (1LL << bits) - 1;  /* set lowest 'bits' bit */
  fc->acks = fc->acks_mask;
  fc->task = GNUNET_SCHEDULER_add_now (&transmit_next, fc);
  return fc;
}


/**
 * Continuation to call from the 'proc' function after the fragment
 * has been transmitted (and hence the next fragment can now be
 * given to proc).
 *
 * @param fc fragmentation context
 */
void
GNUNET_FRAGMENT_context_transmission_done (struct GNUNET_FRAGMENT_Context *fc)
{
  GNUNET_assert (fc->proc_busy == GNUNET_YES);
  fc->proc_busy = GNUNET_NO;
  GNUNET_assert (fc->task == NULL);
  fc->task =
      GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_absolute_get_remaining
                                    (fc->delay_until), &transmit_next, fc);
}


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
                             const struct GNUNET_MessageHeader *msg)
{
  const struct FragmentAcknowledgement *fa;
  uint64_t abits;
  struct GNUNET_TIME_Relative ndelay;
  unsigned int ack_cnt;
  unsigned int snd_cnt;
  unsigned int i;

  if (sizeof (struct FragmentAcknowledgement) != ntohs (msg->size))
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  fa = (const struct FragmentAcknowledgement *) msg;
  if (ntohl (fa->fragment_id) != fc->fragment_id)
    return GNUNET_SYSERR;       /* not our ACK */
  abits = GNUNET_ntohll (fa->bits);
  if ( (GNUNET_YES == fc->wack) &&
       (0 != fc->num_transmissions) )
  {
    /* normal ACK, can update running average of delay... */
    fc->wack = GNUNET_NO;
    ndelay = GNUNET_TIME_absolute_get_duration (fc->last_round);
    fc->ack_delay.rel_value_us =
        (ndelay.rel_value_us / fc->num_transmissions + 3 * fc->ack_delay.rel_value_us) / 4;
    fc->num_transmissions = 0;
    /* calculate ratio msg sent vs. msg acked */
    ack_cnt = 0;
    snd_cnt = 0;
    for (i=0;i<64;i++)
    {
      if (1 == (fc->acks_mask & (1 << i)))
      {
	snd_cnt++;
	if (0 == (abits & (1 << i)))
	  ack_cnt++;
      }
    }
    if (0 == ack_cnt)
    {
      /* complete loss */
      fc->msg_delay = GNUNET_TIME_relative_multiply (fc->msg_delay,
						     snd_cnt);
    }
    else if (snd_cnt > ack_cnt)
    {
      /* some loss, slow down proportionally */
      fprintf (stderr, "Prop loss\n");
      fc->msg_delay.rel_value_us = ((fc->msg_delay.rel_value_us * ack_cnt) / snd_cnt);
    }
    else if (100 < fc->msg_delay.rel_value_us)
    {
      fc->msg_delay.rel_value_us -= 100; /* try a bit faster */
    }
    fc->msg_delay = GNUNET_TIME_relative_min (fc->msg_delay,
					      GNUNET_TIME_UNIT_SECONDS);
  }
  GNUNET_STATISTICS_update (fc->stats,
                            _("# fragment acknowledgements received"), 1,
                            GNUNET_NO);
  if (abits != (fc->acks & abits))
  {
    /* ID collission or message reordering, count! This should be rare! */
    GNUNET_STATISTICS_update (fc->stats,
                              _("# bits removed from fragmentation ACKs"), 1,
                              GNUNET_NO);
  }
  fc->acks = abits & fc->acks_mask;
  if (0 != fc->acks)
  {
    /* more to transmit, do so right now (if tracker permits...) */
    if (fc->task != NULL)
    {
      /* schedule next transmission now, no point in waiting... */
      GNUNET_SCHEDULER_cancel (fc->task);
      fc->task = GNUNET_SCHEDULER_add_now (&transmit_next, fc);
    }
    else
    {
      /* only case where there is no task should be if we're waiting
       * for the right to transmit again (proc_busy set to YES) */
      GNUNET_assert (GNUNET_YES == fc->proc_busy);
    }
    return GNUNET_NO;
  }

  /* all done */
  GNUNET_STATISTICS_update (fc->stats,
                            _("# fragmentation transmissions completed"), 1,
                            GNUNET_NO);
  if (fc->task != NULL)
  {
    GNUNET_SCHEDULER_cancel (fc->task);
    fc->task = NULL;
  }
  return GNUNET_OK;
}


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
				 struct GNUNET_TIME_Relative *ack_delay)
{
  if (fc->task != NULL)
    GNUNET_SCHEDULER_cancel (fc->task);
  if (NULL != ack_delay)
    *ack_delay = fc->ack_delay;
  if (NULL != msg_delay)
    *msg_delay = GNUNET_TIME_relative_multiply (fc->msg_delay,
						fc->num_rounds);
  GNUNET_free (fc);
}


/* end of fragmentation.c */

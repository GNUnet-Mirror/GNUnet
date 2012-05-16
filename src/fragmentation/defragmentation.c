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
 * @file src/fragmentation/defragmentation.c
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
   * Which 'bit' did the last fragment we received correspond to?
   */
  unsigned int last_bit;

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
  GNUNET_DEFRAGMENT_AckProcessor ackp;

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
                                  uint16_t mtu, unsigned int num_msgs,
                                  void *cls,
                                  GNUNET_FRAGMENT_MessageProcessor proc,
                                  GNUNET_DEFRAGMENT_AckProcessor ackp)
{
  struct GNUNET_DEFRAGMENT_Context *dc;

  dc = GNUNET_malloc (sizeof (struct GNUNET_DEFRAGMENT_Context));
  dc->stats = stats;
  dc->cls = cls;
  dc->proc = proc;
  dc->ackp = ackp;
  dc->num_msgs = num_msgs;
  dc->mtu = mtu;
  dc->latency = GNUNET_TIME_UNIT_SECONDS;       /* start with likely overestimate */
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
    GNUNET_CONTAINER_DLL_remove (dc->head, dc->tail, mc);
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
send_ack (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct MessageContext *mc = cls;
  struct GNUNET_DEFRAGMENT_Context *dc = mc->dc;
  struct FragmentAcknowledgement fa;

  mc->ack_task = GNUNET_SCHEDULER_NO_TASK;
  fa.header.size = htons (sizeof (struct FragmentAcknowledgement));
  fa.header.type = htons (GNUNET_MESSAGE_TYPE_FRAGMENT_ACK);
  fa.fragment_id = htonl (mc->fragment_id);
  fa.bits = GNUNET_htonll (mc->bits);
  GNUNET_STATISTICS_update (mc->dc->stats,
                            _("# acknowledgements sent for fragment"), 1,
                            GNUNET_NO);
  dc->ackp (dc->cls, mc->fragment_id, &fa.header);
}


/**
 * This function is from the GNU Scientific Library, linear/fit.c,
 * (C) 2000 Brian Gough
 */
static void
gsl_fit_mul (const double *x, const size_t xstride, const double *y,
             const size_t ystride, const size_t n, double *c1, double *cov_11,
             double *sumsq)
{
  double m_x = 0, m_y = 0, m_dx2 = 0, m_dxdy = 0;

  size_t i;

  for (i = 0; i < n; i++)
  {
    m_x += (x[i * xstride] - m_x) / (i + 1.0);
    m_y += (y[i * ystride] - m_y) / (i + 1.0);
  }

  for (i = 0; i < n; i++)
  {
    const double dx = x[i * xstride] - m_x;
    const double dy = y[i * ystride] - m_y;

    m_dx2 += (dx * dx - m_dx2) / (i + 1.0);
    m_dxdy += (dx * dy - m_dxdy) / (i + 1.0);
  }

  /* In terms of y =  b x */

  {
    double s2 = 0, d2 = 0;
    double b = (m_x * m_y + m_dxdy) / (m_x * m_x + m_dx2);

    *c1 = b;

    /* Compute chi^2 = \sum (y_i -  b * x_i)^2 */

    for (i = 0; i < n; i++)
    {
      const double dx = x[i * xstride] - m_x;
      const double dy = y[i * ystride] - m_y;
      const double d = (m_y - b * m_x) + dy - b * dx;

      d2 += d * d;
    }

    s2 = d2 / (n - 1.0);        /* chisq per degree of freedom */

    *cov_11 = s2 * 1.0 / (n * (m_x * m_x + m_dx2));

    *sumsq = d2;
  }
}


/**
 * Estimate the latency between messages based on the most recent
 * message time stamps.
 *
 * @param mc context with time stamps
 * @return average delay between time stamps (based on least-squares fit)
 */
static struct GNUNET_TIME_Relative
estimate_latency (struct MessageContext *mc)
{
  struct FragTimes *first;
  size_t total = mc->frag_times_write_offset - mc->frag_times_start_offset;
  double x[total];
  double y[total];
  size_t i;
  double c1;
  double cov11;
  double sumsq;
  struct GNUNET_TIME_Relative ret;

  first = &mc->frag_times[mc->frag_times_start_offset];
  GNUNET_assert (total > 1);
  for (i = 0; i < total; i++)
  {
    x[i] = (double) i;
    y[i] = (double) (first[i].time.abs_value - first[0].time.abs_value);
  }
  gsl_fit_mul (x, 1, y, 1, total, &c1, &cov11, &sumsq);
  c1 += sqrt (sumsq);           /* add 1 std dev */
  ret.rel_value = (uint64_t) c1;
  if (ret.rel_value == 0)
    ret = GNUNET_TIME_UNIT_MILLISECONDS;        /* always at least 1 */
  return ret;
}


/**
 * Discard the message context that was inactive for the longest time.
 *
 * @param dc defragmentation context
 */
static void
discard_oldest_mc (struct GNUNET_DEFRAGMENT_Context *dc)
{
  struct MessageContext *old;
  struct MessageContext *pos;

  old = NULL;
  pos = dc->head;
  while (NULL != pos)
  {
    if ((old == NULL) ||
        (old->last_update.abs_value > pos->last_update.abs_value))
      old = pos;
    pos = pos->next;
  }
  GNUNET_assert (NULL != old);
  GNUNET_CONTAINER_DLL_remove (dc->head, dc->tail, old);
  dc->list_size--;
  if (GNUNET_SCHEDULER_NO_TASK != old->ack_task)
  {
    GNUNET_SCHEDULER_cancel (old->ack_task);
    old->ack_task = GNUNET_SCHEDULER_NO_TASK;
  }
  GNUNET_free (old);
}


/**
 * We have received a fragment.  Process it.
 *
 * @param dc the context
 * @param msg the message that was received
 * @return GNUNET_OK on success, GNUNET_NO if this was a duplicate, GNUNET_SYSERR on error
 */
int
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
  unsigned int bc;
  unsigned int b;
  unsigned int n;
  unsigned int num_fragments;
  int duplicate;
  int last;

  if (ntohs (msg->size) < sizeof (struct FragmentHeader))
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  if (ntohs (msg->size) > dc->mtu)
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  fh = (const struct FragmentHeader *) msg;
  msize = ntohs (fh->total_size);
  if (msize < sizeof (struct GNUNET_MessageHeader))
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  fid = ntohl (fh->fragment_id);
  foff = ntohs (fh->offset);
  if (foff >= msize)
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  if (0 != (foff % (dc->mtu - sizeof (struct FragmentHeader))))
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  GNUNET_STATISTICS_update (dc->stats, _("# fragments received"), 1, GNUNET_NO);
  num_fragments = (ntohs (msg->size) + dc->mtu - sizeof (struct FragmentHeader)-1) / (dc->mtu - sizeof (struct FragmentHeader));
  last = 0;
  for (mc = dc->head; NULL != mc; mc = mc->next)
    if (mc->fragment_id > fid)
      last++;
  
  mc = dc->head;
  while ((NULL != mc) && (fid != mc->fragment_id))
    mc = mc->next;
  bit = foff / (dc->mtu - sizeof (struct FragmentHeader));
  if (bit * (dc->mtu - sizeof (struct FragmentHeader)) + ntohs (msg->size) -
      sizeof (struct FragmentHeader) > msize)
  {
    /* payload extends past total message size */
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  if ((NULL != mc) && (msize != mc->total_size))
  {
    /* inconsistent message size */
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  now = GNUNET_TIME_absolute_get ();
  if (NULL == mc)
  {
    mc = GNUNET_malloc (sizeof (struct MessageContext) + msize);
    mc->msg = (const struct GNUNET_MessageHeader *) &mc[1];
    mc->dc = dc;
    mc->total_size = msize;
    mc->fragment_id = fid;
    mc->last_update = now;
    n = (msize + dc->mtu - sizeof (struct FragmentHeader) - 1) / (dc->mtu -
                                                                  sizeof (struct
                                                                          FragmentHeader));
    if (n == 64)
      mc->bits = UINT64_MAX;    /* set all 64 bit */
    else
      mc->bits = (1LL << n) - 1;        /* set lowest 'bits' bit */
    if (dc->list_size >= dc->num_msgs)
      discard_oldest_mc (dc);
    GNUNET_CONTAINER_DLL_insert (dc->head, dc->tail, mc);
    dc->list_size++;
  }

  /* copy data to 'mc' */
  if (0 != (mc->bits & (1LL << bit)))
  {
    mc->bits -= 1LL << bit;
    mbuf = (char *) &mc[1];
    memcpy (&mbuf[bit * (dc->mtu - sizeof (struct FragmentHeader))], &fh[1],
            ntohs (msg->size) - sizeof (struct FragmentHeader));
    mc->last_update = now;
    if (bit < mc->last_bit)
      mc->frag_times_start_offset = mc->frag_times_write_offset;
    mc->last_bit = bit;
    mc->frag_times[mc->frag_times_write_offset].time = now;
    mc->frag_times[mc->frag_times_write_offset].bit = bit;
    mc->frag_times_write_offset++;
    duplicate = GNUNET_NO;
  }
  else
  {
    duplicate = GNUNET_YES;
    GNUNET_STATISTICS_update (dc->stats, _("# duplicate fragments received"), 1,
                              GNUNET_NO);
  }

  /* count number of missing fragments */
  bc = 0;
  for (b = 0; b < 64; b++)
    if (0 != (mc->bits & (1LL << b)))
      bc++;

  /* notify about complete message */
  if ((duplicate == GNUNET_NO) && (0 == mc->bits))
  {
    GNUNET_STATISTICS_update (dc->stats, _("# messages defragmented"), 1,
                              GNUNET_NO);
    /* message complete, notify! */
    dc->proc (dc->cls, mc->msg);
  }
  /* send ACK */
  if (mc->frag_times_write_offset - mc->frag_times_start_offset > 1)
  { 
    dc->latency = estimate_latency (mc);
  }
  delay = GNUNET_TIME_relative_multiply (dc->latency, bc + 1);
  if ( (last + fid == num_fragments) ||
       (0 == mc->bits) || 
       (GNUNET_YES == duplicate))     
  {
    /* message complete or duplicate or last missing fragment in
       linear sequence; ACK now! */
    delay = GNUNET_TIME_UNIT_ZERO;
  }
  if (GNUNET_SCHEDULER_NO_TASK != mc->ack_task)
    GNUNET_SCHEDULER_cancel (mc->ack_task);
  mc->ack_task = GNUNET_SCHEDULER_add_delayed (delay, &send_ack, mc);
  if (duplicate == GNUNET_YES)
    return GNUNET_NO;
  return GNUNET_YES;
}

/* end of defragmentation.c */

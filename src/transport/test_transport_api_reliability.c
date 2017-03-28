/*
     This file is part of GNUnet.
     Copyright (C) 2009, 2010, 2016 GNUnet e.V.

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
 * @file transport/test_transport_api_reliability.c
 * @brief base test case for transport implementations
 *
 * This test case serves ensures that messages are reliably sent between peers
 *
 * This test sends TOTAL_MSGS with message type MTYPE from peer 1 to peer 2
 * and ensures that all message were received.
 */
#include "platform.h"
#include "gnunet_transport_service.h"
#include "gauger.h"
#include "transport-testing.h"

/**
 * Allow making the problem "bigger".
 */
#define FACTOR 1

/**
 * Total number of messages to send
 *
 * Note that this value must not significantly exceed
 * 'MAX_PENDING' in 'gnunet-service-transport_clients.c', otherwise
 * messages may be dropped even for a reliable transport.
 */
#define TOTAL_MSGS (1024 * 3 * FACTOR)

/**
 * Testcase timeout
 */
#define TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 450 * FACTOR)

/**
 * If we are in an "xhdr" test, the factor by which we divide
 * #TOTAL_MSGS for a more sane test duration.
 */
static unsigned int xhdr = 1;

static struct GNUNET_TRANSPORT_TESTING_ConnectCheckContext *ccc;

/**
 * Total amount of bytes sent
 */
static unsigned long long total_bytes;

/**
 * Time of start
 */
static struct GNUNET_TIME_Absolute start_time;

/**
 * No. of last message received
 */
static unsigned int msg_recv;

/**
 * Bitmap storing which messages were received
 */
static char bitmap[TOTAL_MSGS / 8];


/**
 * Get the desired message size for message number @a iter.
 */
static size_t
get_size (unsigned int iter)
{
  size_t ret;

  ret = (iter * iter * iter);
#ifndef LINUX
  /* FreeBSD/OSX etc. Unix DGRAMs do not work
   * with large messages */
  if (0 == strcmp ("unix", ccc->test_plugin))
    ret = sizeof (struct GNUNET_TRANSPORT_TESTING_TestMessage) + (ret % 1024);
#endif
  ret = sizeof (struct GNUNET_TRANSPORT_TESTING_TestMessage) + (ret % 60000);
  return ret;
}


/**
 * Implementation of the callback for obtaining the
 * size of messages for transmission.  Counts the total
 * number of bytes sent as a side-effect.
 *
 * @param cnt_down count down from `TOTAL_MSGS - 1`
 * @return message size of the message
 */
static size_t
get_size_cnt (unsigned int cnt_down)
{
  size_t ret = get_size (TOTAL_MSGS / xhdr - 1 - cnt_down);

  total_bytes += ret;
  return ret;
}


/**
 * Sets a bit active in the bitmap.
 *
 * @param bitIdx which bit to set
 * @return #GNUNET_SYSERR on error, #GNUNET_OK on success
 */
static int
set_bit (unsigned int bitIdx)
{
  size_t arraySlot;
  unsigned int targetBit;

  if (bitIdx >= sizeof (bitmap) * 8)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "tried to set bit %u of %u(!?!?)\n",
                bitIdx,
                (unsigned int) sizeof (bitmap) * 8);
    return GNUNET_SYSERR;
  }
  arraySlot = bitIdx / 8;
  targetBit = (1L << (bitIdx % 8));
  bitmap[arraySlot] |= targetBit;
  return GNUNET_OK;
}


/**
 * Obtain a bit from bitmap.
 * @param map the bitmap
 * @param bit index from bitmap
 *
 * @return Bit @a bit from @a map
 */
static int
get_bit (const char *map,
         unsigned int bit)
{
  if (bit > TOTAL_MSGS)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "get bit %u of %u(!?!?)\n",
                bit,
                (unsigned int) sizeof (bitmap) * 8);
    return 0;
  }
  return ((map)[bit >> 3] & (1 << (bit & 7))) > 0;
}


static void
custom_shutdown (void *cls)
{
  unsigned long long delta;
  unsigned long long rate;
  int ok;

  /* Calculcate statistics   */
  delta = GNUNET_TIME_absolute_get_duration (start_time).rel_value_us;
  rate = (1000LL* 1000ll * total_bytes) / (1024 * delta);
  FPRINTF (stderr,
           "\nThroughput was %llu KiBytes/s\n",
           rate);
  {
    char *value_name;

    GNUNET_asprintf (&value_name,
                     "unreliable_%s",
                     ccc->test_plugin);
    GAUGER ("TRANSPORT",
            value_name,
            (int) rate,
            "kb/s");
    GNUNET_free (value_name);
  }

  ok = 0;
  for (unsigned int i = 0; i < TOTAL_MSGS / xhdr; i++)
  {
    if (get_bit (bitmap, i) == 0)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  "Did not receive message %d\n",
                  i);
      ok = -1;
    }
  }
  if (0 != ok)
    ccc->global_ret = GNUNET_SYSERR; /* fail: messages missing! */
}


static void
notify_receive (void *cls,
                struct GNUNET_TRANSPORT_TESTING_PeerContext *receiver,
                const struct GNUNET_PeerIdentity *sender,
                const struct GNUNET_TRANSPORT_TESTING_TestMessage *hdr)
{
  static int n;
  unsigned int s;
  char cbuf[GNUNET_MAX_MESSAGE_SIZE - 1];

  if (GNUNET_TRANSPORT_TESTING_SIMPLE_MTYPE != ntohs (hdr->header.type))
    return;
  msg_recv = ntohl (hdr->num);
  s = get_size (ntohl (hdr->num));

  if (ntohs (hdr->header.size) != s)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Expected message %u of size %u, got %u bytes of message %u\n",
                (uint32_t) ntohl (hdr->num),
                s,
                ntohs (hdr->header.size),
                (uint32_t) ntohl (hdr->num));
    ccc->global_ret = GNUNET_SYSERR;
    GNUNET_SCHEDULER_shutdown ();
    return;
  }

  memset (cbuf,
	  ntohl (hdr->num),
	  s - sizeof (struct GNUNET_TRANSPORT_TESTING_TestMessage));
  if (0 !=
      memcmp (cbuf,
	      &hdr[1],
	      s - sizeof (struct GNUNET_TRANSPORT_TESTING_TestMessage)))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Expected message %u with bits %u, but body did not match\n",
                (uint32_t) ntohl (hdr->num),
                (unsigned char) ntohl (hdr->num));
    ccc->global_ret = GNUNET_SYSERR;
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
#if VERBOSE
  if (0 == ntohl (hdr->num) % 5)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Got message %u of size %u\n",
                (uint32_t) ntohl (hdr->num),
                ntohs (hdr->header.size));
  }
#endif
  n++;
  if (GNUNET_SYSERR == set_bit (ntohl (hdr->num)))
  {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  "Message id %u is bigger than maxmimum number of messages %u expected\n",
                  (uint32_t) ntohl (hdr->num),
                  TOTAL_MSGS / xhdr);
  }
  if (0 == (n % (TOTAL_MSGS / xhdr / 100)))
  {
    FPRINTF (stderr, "%s",  ".");
  }
  if (n == TOTAL_MSGS / xhdr)
  {
    /* end testcase with success */
    ccc->global_ret = GNUNET_OK;
    GNUNET_SCHEDULER_shutdown ();
  }
}


int
main (int argc, char *argv[])
{
  if (0 == strstr (argv[0], "xhdr"))
    xhdr = 30;
  struct GNUNET_TRANSPORT_TESTING_SendClosure sc = {
    .num_messages = TOTAL_MSGS / xhdr,
    .get_size_cb = &get_size_cnt
  };
  struct GNUNET_TRANSPORT_TESTING_ConnectCheckContext my_ccc = {
    .connect_continuation = &GNUNET_TRANSPORT_TESTING_simple_send,
    .connect_continuation_cls = &sc,
    .config_file = "test_transport_api_data.conf",
    .rec = &notify_receive,
    .nc = &GNUNET_TRANSPORT_TESTING_log_connect,
    .nd = &GNUNET_TRANSPORT_TESTING_log_disconnect,
    .shutdown_task = &custom_shutdown,
    .timeout = TIMEOUT,
    .global_ret = GNUNET_SYSERR
  };

  ccc = &my_ccc;
  sc.ccc = ccc;
  start_time = GNUNET_TIME_absolute_get ();
  if (GNUNET_OK !=
      GNUNET_TRANSPORT_TESTING_main (2,
                                     &GNUNET_TRANSPORT_TESTING_connect_check,
                                     ccc))
    return 1;
  return 0;
}


/* end of test_transport_api_reliability.c */

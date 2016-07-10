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
 * Message type of test messages
 */
#define MTYPE 12345

/**
 * Testcase timeout
 */
#define TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 90 * FACTOR)

/**
 * How long until we give up on transmitting the message?
 */
#define TIMEOUT_TRANSMIT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 60 * FACTOR)


GNUNET_NETWORK_STRUCT_BEGIN

/**
 * Struct for the test message
 */
struct TestMessage
{
  struct GNUNET_MessageHeader header;
  uint32_t num GNUNET_PACKED;
};
GNUNET_NETWORK_STRUCT_END


static struct GNUNET_TRANSPORT_TESTING_ConnectCheckContext *ccc;

static struct GNUNET_TRANSPORT_TransmitHandle *th;

/**
 * Total amount of bytes sent
 */
static unsigned long long total_bytes;

/**
 * Time of start
 */
static struct GNUNET_TIME_Absolute start_time;

/**
 * No. of message currently scheduled to be send
 */
static int msg_scheduled;

/**
 * No. of last message sent
 */
static int msg_sent;

/**
 * No. of last message received
 */
static int msg_recv;

/**
 * Bitmap storing which messages were received
 */
static char bitmap[TOTAL_MSGS / 8];


static unsigned int
get_size (unsigned int iter)
{
  unsigned int ret;

  ret = (iter * iter * iter);

#ifndef LINUX
  /* FreeBSD/OSX etc. Unix DGRAMs do not work
   * with large messages */
  if (0 == strcmp ("unix", test_plugin))
    return sizeof (struct TestMessage) + (ret % 1024);
#endif
  return sizeof (struct TestMessage) + (ret % 60000);
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
  unsigned int i;
  int ok;

  if (NULL != th)
  {
    GNUNET_TRANSPORT_notify_transmit_ready_cancel (th);
    th = NULL;
  }
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
  for (i = 0; i < TOTAL_MSGS; i++)
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
                const struct GNUNET_MessageHeader *message)
{
  static int n;

  unsigned int s;
  char cbuf[GNUNET_SERVER_MAX_MESSAGE_SIZE - 1];
  const struct TestMessage *hdr;

  hdr = (const struct TestMessage *) message;

  if (MTYPE != ntohs (message->type))
    return;
  msg_recv = ntohl (hdr->num);
  s = get_size (ntohl (hdr->num));

  if (ntohs (message->size) != s)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Expected message %u of size %u, got %u bytes of message %u\n",
                ntohl (hdr->num),
                s,
                ntohs (message->size),
                ntohl (hdr->num));
    ccc->global_ret = GNUNET_SYSERR;
    GNUNET_SCHEDULER_shutdown ();
    return;
  }

  memset (cbuf, ntohl (hdr->num), s - sizeof (struct TestMessage));
  if (0 != memcmp (cbuf, &hdr[1], s - sizeof (struct TestMessage)))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Expected message %u with bits %u, but body did not match\n",
                ntohl (hdr->num),
                (unsigned char) n);
    ccc->global_ret = GNUNET_SYSERR;
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
#if VERBOSE
  if (ntohl (hdr->num) % 5 == 0)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Got message %u of size %u\n",
                ntohl (hdr->num),
                ntohs (message->size));
  }
#endif
  n++;
  if (GNUNET_SYSERR == set_bit (ntohl (hdr->num)))
  {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  "Message id %u is bigger than maxmimum number of messages %u expected\n",
                  ntohl (hdr->num),
                  TOTAL_MSGS);
  }
  if (0 == (n % (TOTAL_MSGS / 100)))
  {
    FPRINTF (stderr, "%s",  ".");
  }
  if (n == TOTAL_MSGS)
  {
    /* end testcase with success */
    GNUNET_SCHEDULER_shutdown ();
  }
}


static size_t
notify_ready (void *cls,
              size_t size,
              void *buf)
{
  static int n;
  char *cbuf = buf;
  struct TestMessage hdr;
  unsigned int s;
  unsigned int ret;

  th = NULL;
  if (NULL == buf)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Timeout occurred while waiting for transmit_ready for msg %u of %u\n",
                msg_scheduled,
                TOTAL_MSGS);
    GNUNET_SCHEDULER_shutdown ();
    ccc->global_ret = 42;
    return 0;
  }
  ret = 0;
  s = get_size (n);
  GNUNET_assert (size >= s);
  GNUNET_assert (buf != NULL);
  GNUNET_assert (n < TOTAL_MSGS);
  cbuf = buf;
  do
  {
    GNUNET_assert (n < TOTAL_MSGS);
    hdr.header.size = htons (s);
    hdr.header.type = htons (MTYPE);
    hdr.num = htonl (n);
    msg_sent = n;
    GNUNET_memcpy (&cbuf[ret], &hdr, sizeof (struct TestMessage));
    ret += sizeof (struct TestMessage);
    memset (&cbuf[ret], n, s - sizeof (struct TestMessage));
    ret += s - sizeof (struct TestMessage);

#if VERBOSE
    if (0 == n % 5000)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Sending message %u of size %u\n",
                  n,
                  s);
    }
#endif
    n++;
    s = get_size (n);
    if (0 == GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK, 16))
      break;                    /* sometimes pack buffer full, sometimes not */
  }
  while ((size - ret >= s) && (n < TOTAL_MSGS));
  if (n < TOTAL_MSGS)
  {
    th = GNUNET_TRANSPORT_notify_transmit_ready (ccc->p[1]->th,
                                                 &ccc->p[0]->id,
                                                 s,
                                                 TIMEOUT_TRANSMIT,
                                                 &notify_ready,
                                                 NULL);
    msg_scheduled = n;
  }
  else
  {
    FPRINTF (stderr,
             "%s",
             "\n");
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "All messages scheduled to be sent\n");
  }
  if (0 == n % 5000)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Returning total message block of size %u\n",
                ret);
  }
  total_bytes += ret;
  return ret;
}


static void
sendtask (void *cls)
{
  start_time = GNUNET_TIME_absolute_get ();
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Starting to send %u messages\n",
              TOTAL_MSGS);
  th = GNUNET_TRANSPORT_notify_transmit_ready (ccc->p[1]->th,
                                               &ccc->p[0]->id,
                                               get_size (0),
                                               TIMEOUT_TRANSMIT,
                                               &notify_ready,
                                               NULL);
}


static void
notify_disconnect (void *cls,
                   struct GNUNET_TRANSPORT_TESTING_PeerContext *me,
                   const struct GNUNET_PeerIdentity *other)
{
  GNUNET_TRANSPORT_TESTING_log_disconnect (cls,
                                           me,
                                           other);
  if (NULL != th)
  {
    GNUNET_TRANSPORT_notify_transmit_ready_cancel (th);
    th = NULL;
  }
}


int
main (int argc, char *argv[])
{
  struct GNUNET_TRANSPORT_TESTING_ConnectCheckContext my_ccc = {
    .connect_continuation = &sendtask,
    .config_file = "test_transport_api_data.conf",
    .rec = &notify_receive,
    .nc = &GNUNET_TRANSPORT_TESTING_log_connect,
    .nd = &notify_disconnect,
    .shutdown_task = &custom_shutdown,
    .timeout = TIMEOUT
  };

  ccc = &my_ccc;
  if (GNUNET_OK !=
      GNUNET_TRANSPORT_TESTING_main (2,
                                     &GNUNET_TRANSPORT_TESTING_connect_check,
                                     ccc))
    return 1;
  return 0;
}


/* end of test_transport_api_reliability.c */

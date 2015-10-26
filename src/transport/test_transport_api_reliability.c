/*
     This file is part of GNUnet.
     Copyright (C) 2009, 2010 Christian Grothoff (and other contributing authors)

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


/**
 * Struct for the test message
 */
GNUNET_NETWORK_STRUCT_BEGIN

struct TestMessage
{
  struct GNUNET_MessageHeader header;
  uint32_t num;
};
GNUNET_NETWORK_STRUCT_END


/**
 * Name of the plugin to test
 */
static char *test_plugin;

/**
 * Name of the test
 */
static char *test_name;

/**
 * Return value of the test
 */
static int ok;

/**
 * Context of peer 1
 */
static struct PeerContext *p1;

/**
 * Configuration file of peer 1
 */
static char *cfg_file_p1;

/**
 * Context of peer 2
 */
static struct PeerContext *p2;

/**
 * Configuration file of peer 1
 */
static char *cfg_file_p2;

/**
 * Timeout task
 */
static struct GNUNET_SCHEDULER_Task * die_task;

/**
 * Transport transmit handle used
 */
static struct GNUNET_TRANSPORT_TransmitHandle *th;

/**
 * Transport testing handle
 */
static struct GNUNET_TRANSPORT_TESTING_handle *tth;

/*
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

static int test_connected;

static int test_sending;

static int test_send_timeout;


/**
 * Bitmap storing which messages were received
 */
static char bitmap[TOTAL_MSGS / 8];

static GNUNET_TRANSPORT_TESTING_ConnectRequest cc;

/*
 * END Testcase specific declarations
 */

#if VERBOSE
#define OKPP do { ok++; FPRINTF (stderr, "Now at stage %u at %s:%u\n", ok, __FILE__, __LINE__); } while (0)
#else
#define OKPP do { ok++; } while (0)
#endif


static int
get_bit (const char *map, unsigned int bit);


static void
end ()
{
  unsigned long long delta;
  unsigned long long rate;
  char *value_name;
  unsigned int i;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Stopping peers\n");

  /* Calculcate statistics   */
  delta = GNUNET_TIME_absolute_get_duration (start_time).rel_value_us;
  rate = (1000LL* 1000ll * total_bytes) / (1024 * delta);
  FPRINTF (stderr,
           "\nThroughput was %llu KiBytes/s\n",
           rate);

  GNUNET_asprintf (&value_name,
                   "unreliable_%s",
                   test_plugin);
  GAUGER ("TRANSPORT",
          value_name,
          (int) rate,
          "kb/s");
  GNUNET_free (value_name);

  if (die_task != NULL)
    GNUNET_SCHEDULER_cancel (die_task);

  if (th != NULL)
  {
    GNUNET_TRANSPORT_notify_transmit_ready_cancel (th);
    th = NULL;
  }
  if (cc != NULL)
  {
    GNUNET_TRANSPORT_TESTING_connect_peers_cancel (tth, cc);
    cc = NULL;
  }
  GNUNET_TRANSPORT_TESTING_stop_peer (tth, p1);
  GNUNET_TRANSPORT_TESTING_stop_peer (tth, p2);
  GNUNET_TRANSPORT_TESTING_done (tth);
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
}


static void
end_badly ()
{
  unsigned int i;

  die_task = NULL;
  GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
              "Fail! Stopping peers\n");
  if (test_connected == GNUNET_YES)
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                "Peers got connected\n");
  else
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Peers got NOT connected\n");

  if (test_sending == GNUNET_NO)
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Testcase did not send any messages before timeout\n");
  if (test_send_timeout == GNUNET_YES)
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Test had timeout while waiting to send data\n");
  for (i = 0; i < TOTAL_MSGS; i++)
  {
    if (get_bit (bitmap, i) == 0)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  "Did not receive message %u\n",
                  i);
      ok = -1;
    }
  }

  if (th != NULL)
  {
    GNUNET_TRANSPORT_notify_transmit_ready_cancel (th);
    th = NULL;
  }
  if (cc != NULL)
  {
    GNUNET_TRANSPORT_TESTING_connect_peers_cancel (tth, cc);
    cc = NULL;
  }
  if (p1 != NULL)
    GNUNET_TRANSPORT_TESTING_stop_peer (tth, p1);
  if (p2 != NULL)
    GNUNET_TRANSPORT_TESTING_stop_peer (tth, p2);
  GNUNET_TRANSPORT_TESTING_done (tth);
  ok = GNUNET_SYSERR;
}


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
                "tried to set bit %d of %d(!?!?)\n",
                bitIdx, sizeof (bitmap) * 8);
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
 * @return Bit \a bit from hashcode \a code
 */
static int
get_bit (const char *map, unsigned int bit)
{
  if (bit > TOTAL_MSGS)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "get bit %d of %d(!?!?)\n", bit,
                sizeof (bitmap) * 8);
    return 0;
  }
  return ((map)[bit >> 3] & (1 << (bit & 7))) > 0;
}


static void
notify_receive (void *cls, const struct GNUNET_PeerIdentity *peer,
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
                ntohl (hdr->num), s, ntohs (message->size), ntohl (hdr->num));
    if (NULL != die_task)
      GNUNET_SCHEDULER_cancel (die_task);
    test_sending = GNUNET_YES;
    die_task = GNUNET_SCHEDULER_add_now (&end_badly, NULL);
    return;
  }

  memset (cbuf, ntohl (hdr->num), s - sizeof (struct TestMessage));
  if (0 != memcmp (cbuf, &hdr[1], s - sizeof (struct TestMessage)))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Expected message %u with bits %u, but body did not match\n",
                ntohl (hdr->num), (unsigned char) n);
    if (NULL != die_task)
      GNUNET_SCHEDULER_cancel (die_task);
    test_sending = GNUNET_YES;
    die_task = GNUNET_SCHEDULER_add_now (&end_badly, NULL);
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
  test_sending = GNUNET_YES;
  if (0 == (n % (TOTAL_MSGS / 100)))
  {
    FPRINTF (stderr, "%s",  ".");
    if (NULL != die_task)
      GNUNET_SCHEDULER_cancel (die_task);
    die_task = GNUNET_SCHEDULER_add_delayed (TIMEOUT, &end_badly, NULL);
  }
  if (n == TOTAL_MSGS)
  {
    end ();
  }
}


static size_t
notify_ready (void *cls, size_t size, void *buf)
{
  static int n;
  char *cbuf = buf;
  struct TestMessage hdr;
  unsigned int s;
  unsigned int ret;

  th = NULL;

  if (buf == NULL)
  {
    test_send_timeout = GNUNET_YES;
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Timeout occurred while waiting for transmit_ready for msg %u of %u\n",
                msg_scheduled, TOTAL_MSGS);
    if (NULL != die_task)
      GNUNET_SCHEDULER_cancel (die_task);
    die_task = GNUNET_SCHEDULER_add_now (&end_badly, NULL);
    ok = 42;
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
    memcpy (&cbuf[ret], &hdr, sizeof (struct TestMessage));
    ret += sizeof (struct TestMessage);
    memset (&cbuf[ret], n, s - sizeof (struct TestMessage));
    ret += s - sizeof (struct TestMessage);

#if VERBOSE
    if (n % 5000 == 0)
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
    th = GNUNET_TRANSPORT_notify_transmit_ready (p2->th, &p1->id, s,
                                                 TIMEOUT_TRANSMIT,
                                                 &notify_ready, NULL);
    msg_scheduled = n;
  }
  else
  {
    FPRINTF (stderr, "%s",  "\n");
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "All messages scheduled to be sent\n");
    if (NULL != die_task)
      GNUNET_SCHEDULER_cancel (die_task);
    die_task = GNUNET_SCHEDULER_add_delayed (TIMEOUT, &end_badly, NULL);
  }
  if (n % 5000 == 0)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Returning total message block of size %u\n", ret);
  }
  total_bytes += ret;
  return ret;
}


static void
notify_connect (void *cls, const struct GNUNET_PeerIdentity *peer)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Peer `%4s' connected to us (%p)!\n",
              GNUNET_i2s (peer), cls);
}


static void
notify_disconnect (void *cls, const struct GNUNET_PeerIdentity *peer)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Peer `%4s' disconnected (%p)!\n",
              GNUNET_i2s (peer), cls);
  if (th != NULL)
    GNUNET_TRANSPORT_notify_transmit_ready_cancel (th);
  th = NULL;
}


static void
sendtask (void *cls,
          const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  start_time = GNUNET_TIME_absolute_get ();
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Starting to send %u messages\n",
              TOTAL_MSGS);
  th = GNUNET_TRANSPORT_notify_transmit_ready (p2->th, &p1->id, get_size (0),
                                               TIMEOUT_TRANSMIT, &notify_ready,
                                               NULL);
}


static void
testing_connect_cb (struct PeerContext *p1,
                    struct PeerContext *p2,
                    void *cls)
{
  char *p1_c = GNUNET_strdup (GNUNET_i2s (&p1->id));

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Peers connected: %s <-> %s\n",
              p1_c,
              GNUNET_i2s (&p2->id));
  GNUNET_free (p1_c);

  test_connected = GNUNET_YES;
  cc = NULL;

  GNUNET_SCHEDULER_add_now (&sendtask, NULL);
}


static void
start_cb (struct PeerContext *p, void *cls)
{
  static int started;
  started++;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Peer %u (`%s') started\n",
              p->no,
              GNUNET_i2s (&p->id));

  if (started != 2)
    return;

  test_connected = GNUNET_NO;
  cc = GNUNET_TRANSPORT_TESTING_connect_peers (tth, p1, p2, &testing_connect_cb,
                                               NULL);

}


static void
run (void *cls,
     char *const *args,
     const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  die_task = GNUNET_SCHEDULER_add_delayed (TIMEOUT,
                                           &end_badly, NULL);
  test_send_timeout = GNUNET_NO;

  p1 = GNUNET_TRANSPORT_TESTING_start_peer (tth, cfg_file_p1, 1,
                                            &notify_receive, &notify_connect,
                                            &notify_disconnect, &start_cb,
                                            NULL);
  p2 = GNUNET_TRANSPORT_TESTING_start_peer (tth, cfg_file_p2, 2,
                                            &notify_receive, &notify_connect,
                                            &notify_disconnect, &start_cb,
                                            NULL);
  if ((p1 == NULL) || (p2 == NULL))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Fail! Could not start peers!\n");
    if (die_task != NULL)
      GNUNET_SCHEDULER_cancel (die_task);
    //die_task = GNUNET_SCHEDULER_add_now (&end_badly, NULL);
    return;
  }
}


int
main (int argc, char *argv[])
{
  char *test_source;
  int ret;

  static char *const argv_new[] = {
    "test-transport-api-reliability",
    "-c",
    "test_transport_api_data.conf",
    NULL
  };
  static struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_OPTION_END
  };

  GNUNET_TRANSPORT_TESTING_get_test_name (argv[0],
                                          &test_name);
  GNUNET_log_setup (test_name,
                    "WARNING",
                    NULL);
  GNUNET_TRANSPORT_TESTING_get_test_source_name (__FILE__,
                                                 &test_source);
  GNUNET_TRANSPORT_TESTING_get_test_plugin_name (argv[0],
                                                 test_source,
                                                 &test_plugin);

  tth = GNUNET_TRANSPORT_TESTING_init ();

  GNUNET_TRANSPORT_TESTING_get_config_name (argv[0], &cfg_file_p1, 1);
  GNUNET_TRANSPORT_TESTING_get_config_name (argv[0], &cfg_file_p2, 2);

#if WRITECONFIG
  setTransportOptions ("test_transport_api_data.conf");
#endif
  ok = GNUNET_SYSERR;

  ret = GNUNET_PROGRAM_run ((sizeof (argv_new) / sizeof (char *)) - 1,
                            argv_new, test_name,
                            "nohelp", options,
                            &run, &ok);
  if (GNUNET_SYSERR == ret)
  {
    fprintf (stderr,
             "Test failed: %d\n",
             ok);
    ok = -1;
  }
  GNUNET_free (cfg_file_p1);
  GNUNET_free (cfg_file_p2);
  GNUNET_free (test_source);
  GNUNET_free (test_plugin);
  GNUNET_free (test_name);

  return ok;
}

/* end of test_transport_api_reliability.c */

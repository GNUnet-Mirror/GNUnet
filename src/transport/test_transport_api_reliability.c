/*
     This file is part of GNUnet.
     (C) 2009, 2010 Christian Grothoff (and other contributing authors)

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
 * @file transport/test_transport_api_reliability.c
 * @brief base test case for transport implementations
 *
 * This test case serves as a base for tcp and http
 * transport test cases to check that the transports
 * achieve reliable message delivery.
 */
#include "platform.h"
#include "gnunet_common.h"
#include "gnunet_hello_lib.h"
#include "gnunet_getopt_lib.h"
#include "gnunet_os_lib.h"
#include "gnunet_program_lib.h"
#include "gnunet_scheduler_lib.h"
#include "gnunet_server_lib.h"
#include "gnunet_transport_service.h"
#include "gauger.h"
#include "transport.h"
#include "transport-testing.h"

#define VERBOSE GNUNET_NO

#define VERBOSE_ARM GNUNET_NO

#define START_ARM GNUNET_YES

/**
 * Testcase timeout
 */
#define TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 60)

/**
 * How long until we give up on transmitting the message?
 */
#define TIMEOUT_TRANSMIT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 10)


static char *test_source;

static char *test_plugin;

static char *test_name;

static int ok;

static GNUNET_SCHEDULER_TaskIdentifier die_task;

struct PeerContext *p1;

struct PeerContext *p2;

struct PeerContext *sender;

struct PeerContext *receiver;

struct GNUNET_TRANSPORT_TransmitHandle *th;

char *cfg_file_p1;

char *cfg_file_p2;

struct GNUNET_TRANSPORT_TESTING_handle *tth;

static GNUNET_TRANSPORT_TESTING_ConnectRequest cc;


/*
 * Testcase specific declarations
 */

/**
 * Note that this value must not significantly exceed
 * 'MAX_PENDING' in 'gnunet-service-transport.c', otherwise
 * messages may be dropped even for a reliable transport.
 */
#define TOTAL_MSGS (1024 * 2)

#define MTYPE 12345

GNUNET_NETWORK_STRUCT_BEGIN

struct TestMessage
{
  struct GNUNET_MessageHeader header;
  uint32_t num;
};
GNUNET_NETWORK_STRUCT_END

static int msg_scheduled;
static int msg_sent;
static int msg_recv_expected;
static int msg_recv;

static int test_failed;
static int test_connected;

static unsigned long long total_bytes;

static struct GNUNET_TIME_Absolute start_time;

/*
 * END Testcase specific declarations
 */

#if VERBOSE
#define OKPP do { ok++; FPRINTF (stderr, "Now at stage %u at %s:%u\n", ok, __FILE__, __LINE__); } while (0)
#else
#define OKPP do { ok++; } while (0)
#endif


static void
end ()
{
  unsigned long long delta;

  char *value_name;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Stopping peers\n");

  delta = GNUNET_TIME_absolute_get_duration (start_time).rel_value;
  FPRINTF (stderr, "\nThroughput was %llu kb/s\n",
           total_bytes * 1000 / 1024 / delta);
  GNUNET_asprintf (&value_name, "reliable_%s", test_plugin);
  GAUGER ("TRANSPORT", value_name, (int) (total_bytes * 1000 / 1024 / delta),
          "kb/s");
  GNUNET_free (value_name);

  if (die_task != GNUNET_SCHEDULER_NO_TASK)
    GNUNET_SCHEDULER_cancel (die_task);

  if (th != NULL)
    GNUNET_TRANSPORT_notify_transmit_ready_cancel (th);
  th = NULL;

  if (cc != NULL)
    GNUNET_TRANSPORT_TESTING_connect_peers_cancel (tth, cc);

  GNUNET_TRANSPORT_TESTING_stop_peer (tth, p1);
  GNUNET_TRANSPORT_TESTING_stop_peer (tth, p2);

  GNUNET_TRANSPORT_TESTING_done (tth);
}

static void
end_badly ()
{
  die_task = GNUNET_SCHEDULER_NO_TASK;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Fail! Stopping peers\n");

  if (test_connected == GNUNET_YES)
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Peers got connected\n");
  else
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Peers got NOT connected\n");

  if (th != NULL)
    GNUNET_TRANSPORT_notify_transmit_ready_cancel (th);
  th = NULL;

  if (cc != NULL)
    GNUNET_TRANSPORT_TESTING_connect_peers_cancel (tth, cc);

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
  return sizeof (struct TestMessage) + (ret % 60000);
}


static void
notify_receive (void *cls, const struct GNUNET_PeerIdentity *peer,
                const struct GNUNET_MessageHeader *message,
                const struct GNUNET_ATS_Information *ats, uint32_t ats_count)
{
  static int n;
  unsigned int s;
  char cbuf[GNUNET_SERVER_MAX_MESSAGE_SIZE - 1];
  const struct TestMessage *hdr;

  hdr = (const struct TestMessage *) message;
  s = get_size (n);
  if (MTYPE != ntohs (message->type))
    return;
  msg_recv_expected = n;
  msg_recv = ntohl (hdr->num);
  if (ntohs (message->size) != (s))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Expected message %u of size %u, got %u bytes of message %u\n",
                n, s, ntohs (message->size), ntohl (hdr->num));
    if (die_task != GNUNET_SCHEDULER_NO_TASK)
      GNUNET_SCHEDULER_cancel (die_task);
    test_failed = GNUNET_YES;
    die_task = GNUNET_SCHEDULER_add_now (&end_badly, NULL);
    return;
  }
  if (ntohl (hdr->num) != n)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Expected message %u of size %u, got %u bytes of message %u\n",
                n, s, ntohs (message->size), ntohl (hdr->num));
    if (die_task != GNUNET_SCHEDULER_NO_TASK)
      GNUNET_SCHEDULER_cancel (die_task);
    test_failed = GNUNET_YES;
    die_task = GNUNET_SCHEDULER_add_now (&end_badly, NULL);
    return;
  }
  memset (cbuf, n, s - sizeof (struct TestMessage));
  if (0 != memcmp (cbuf, &hdr[1], s - sizeof (struct TestMessage)))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Expected message %u with bits %u, but body did not match at position %u\n", n,
                (unsigned char) n);
    if (die_task != GNUNET_SCHEDULER_NO_TASK)
      GNUNET_SCHEDULER_cancel (die_task);
    test_failed = GNUNET_YES;
    die_task = GNUNET_SCHEDULER_add_now (&end_badly, NULL);
    return;
  }
#if VERBOSE
  if (ntohl (hdr->num) % 5000 == 0)
  {
    struct PeerContext *p = cls;
    char *ps = GNUNET_strdup (GNUNET_i2s (&p->id));

    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Peer %u (`%s') got message %u of size %u from peer (`%s')\n",
                p->no, ps, ntohl (hdr->num), ntohs (message->size),
                GNUNET_i2s (peer));
    GNUNET_free (ps);
  }
#endif
  n++;
  if (0 == (n % (TOTAL_MSGS / 100)))
  {
    FPRINTF (stderr, "%s",  ".");
    if (die_task != GNUNET_SCHEDULER_NO_TASK)
      GNUNET_SCHEDULER_cancel (die_task);
    die_task = GNUNET_SCHEDULER_add_delayed (TIMEOUT, &end_badly, NULL);
  }
  if (n == TOTAL_MSGS)
  {
    ok = 0;
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "\nAll messages received\n");
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
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Timeout occurred while waiting for transmit_ready for message %u of %u\n",
                msg_scheduled, TOTAL_MSGS);
    if (GNUNET_SCHEDULER_NO_TASK != die_task)
      GNUNET_SCHEDULER_cancel (die_task);
    die_task = GNUNET_SCHEDULER_add_now (&end_badly, NULL);
    ok = 42;
    return 0;
  }

  ret = 0;
  s = get_size (n);
  GNUNET_assert (size >= s);
  GNUNET_assert (buf != NULL);
  cbuf = buf;
  do
  {
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

      char *receiver_s = GNUNET_strdup (GNUNET_i2s (&receiver->id));

      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Sending message of size %u from peer %u (`%4s') -> peer %u (`%s') !\n",
                  n, sender->no, GNUNET_i2s (&sender->id), receiver->no,
                  receiver_s);
      GNUNET_free (receiver_s);
    }
#endif
    n++;
    s = get_size (n);
    if (0 == GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK, 16))
      break;                    /* sometimes pack buffer full, sometimes not */
  }
  while (size - ret >= s);
  if (n < TOTAL_MSGS)
  {
    if (th == NULL)
      th = GNUNET_TRANSPORT_notify_transmit_ready (p2->th, &p1->id, s, 0,
                                                   TIMEOUT_TRANSMIT,
                                                   &notify_ready, NULL);
    msg_scheduled = n;
  }
  if (n % 5000 == 0)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Returning total message block of size %u\n", ret);
  }
  total_bytes += ret;
  if (n == TOTAL_MSGS)
  {
    FPRINTF (stderr, "%s",  "\n");
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "All messages sent\n");
  }
  return ret;
}


static void
notify_connect (void *cls, const struct GNUNET_PeerIdentity *peer,
                const struct GNUNET_ATS_Information *ats, uint32_t ats_count)
{

  struct PeerContext *p = cls;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Peer %u (`%4s') connected to us!\n",
              p->no, GNUNET_i2s (peer));
}


static void
notify_disconnect (void *cls, const struct GNUNET_PeerIdentity *peer)
{
  struct PeerContext *p = cls;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Peer %u (`%4s') disconnected!\n", p->no,
              GNUNET_i2s (peer));
  if (th != NULL)
    GNUNET_TRANSPORT_notify_transmit_ready_cancel (th);
  th = NULL;

}

static void
sendtask ()
{
  start_time = GNUNET_TIME_absolute_get ();
  th = GNUNET_TRANSPORT_notify_transmit_ready (p2->th, &p1->id, get_size (0), 0,
                                               TIMEOUT_TRANSMIT, &notify_ready,
                                               NULL);
}

static void
testing_connect_cb (struct PeerContext *p1, struct PeerContext *p2, void *cls)
{
  char *p1_c = GNUNET_strdup (GNUNET_i2s (&p1->id));

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Peers connected: %u (%s) <-> %u (%s)\n",
              p1->no, p1_c, p2->no, GNUNET_i2s (&p2->id));
  GNUNET_free (p1_c);

  test_connected = GNUNET_YES;
  cc = NULL;

  GNUNET_SCHEDULER_add_now (&sendtask, NULL);

}

void
start_cb (struct PeerContext *p, void *cls)
{
  static int started;

  started++;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Peer %u (`%s') started\n", p->no,
              GNUNET_i2s (&p->id));

  if (started != 2)
    return;

  test_connected = GNUNET_NO;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Peer %u: `%s' using configuration file `%s'\n", p1->no,
              GNUNET_i2s (&p1->id), cfg_file_p1);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Peer %u: `%s' using configuration file `%s'\n", p2->no,
              GNUNET_i2s (&p2->id), cfg_file_p2);

  sender = p2;
  receiver = p1;

  char *sender_c = GNUNET_strdup (GNUNET_i2s (&sender->id));

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Test triest to send from %u (%s) -> peer %u (%s)\n", sender->no,
              sender_c, receiver->no, GNUNET_i2s (&receiver->id));
  GNUNET_free (sender_c);

  cc = GNUNET_TRANSPORT_TESTING_connect_peers (tth, p1, p2, &testing_connect_cb,
                                               NULL);

}


static void
run (void *cls, char *const *args, const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  die_task = GNUNET_SCHEDULER_add_delayed (TIMEOUT, &end_badly, NULL);

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
    if (die_task != GNUNET_SCHEDULER_NO_TASK)
      GNUNET_SCHEDULER_cancel (die_task);
    die_task = GNUNET_SCHEDULER_add_now (&end_badly, NULL);
    return;
  }
}

static int
check ()
{
  static char *argv[] = { "test_transport",
    "-c",
    "test_transport_api_data.conf",
#if VERBOSE
    "-L", "DEBUG",
#endif
    NULL
  };
  static struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_OPTION_END
  };

#if WRITECONFIG
  setTransportOptions ("test_transport_api_data.conf");
#endif
  ok = 1;
  GNUNET_PROGRAM_run ((sizeof (argv) / sizeof (char *)) - 1, argv, test_name,
                      "nohelp", options, &run, &ok);

  return ok;
}

int
main (int argc, char *argv[])
{
  int ret;

  GNUNET_TRANSPORT_TESTING_get_test_name (argv[0], &test_name);

  GNUNET_log_setup (test_name,
#if VERBOSE
                    "DEBUG",
#else
                    "WARNING",
#endif
                    NULL);

  GNUNET_TRANSPORT_TESTING_get_test_source_name (__FILE__, &test_source);
  GNUNET_TRANSPORT_TESTING_get_test_plugin_name (argv[0], test_source,
                                                 &test_plugin);

  tth = GNUNET_TRANSPORT_TESTING_init ();

  GNUNET_TRANSPORT_TESTING_get_config_name (argv[0], &cfg_file_p1, 1);
  GNUNET_TRANSPORT_TESTING_get_config_name (argv[0], &cfg_file_p2, 2);

  ret = check ();

  GNUNET_free (cfg_file_p1);
  GNUNET_free (cfg_file_p2);

  GNUNET_free (test_source);
  GNUNET_free (test_plugin);
  GNUNET_free (test_name);

  return ret;
}


/* end of test_transport_api_reliability.c */

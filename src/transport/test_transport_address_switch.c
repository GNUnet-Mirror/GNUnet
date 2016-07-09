/*
 This file is part of GNUnet.
 Copyright (C) 2009, 2010, 2011 GNUnet e.V.

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
 * @file transport/test_transport_address_switch.c
 * @brief base test case for transport implementations
 *
 * This test case tests if peers can successfully switch addresses when
 * connected for plugins supporting multiple addresses by monitoring transport's
 * statistic values.
 *
 * This test starts 2 peers and connects them. When connected test messages
 * are transmitted from peer 2 to peer 1. The test monitors transport's
 * statistics values for information about address switch attempts.
 *
 * The test passes with success if one of the peers could successfully switch
 * addresses in connected state and a test message was successfully transmitted
 * after this switch.
 *
 * Since it is not possible to trigger an address switch from
 * outside, the test still passes when no address switching attempt takes
 * place. It fails if an address switch attempt fails.
 */
#include "platform.h"
#include "gnunet_transport_service.h"
#include "gnunet_ats_service.h"
#include "gauger.h"
#include "transport-testing.h"

/*
 * Testcase specific declarations
 */

GNUNET_NETWORK_STRUCT_BEGIN
struct TestMessage
{
  struct GNUNET_MessageHeader header;
  uint32_t num GNUNET_PACKED;
};
GNUNET_NETWORK_STRUCT_END

/**
 * Message type for test messages
 */
#define MTYPE 12345

/**
 * Message size for test messages
 */
#define MSIZE 2048

/**
 * Testcase timeout
 */
#define TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 120)

/**
 * How long until we give up on transmitting the message?
 */
#define TIMEOUT_TRANSMIT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 60)

#define DURATION GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 30)


/**
 * Timeout task to send messages
 */
static struct GNUNET_SCHEDULER_Task *die_task;


static struct GNUNET_SCHEDULER_Task *delayed_end_task;

/**
 * Measurement task to send messages
 */
static struct GNUNET_SCHEDULER_Task *measure_task;


static struct GNUNET_TRANSPORT_TESTING_PeerContext *p1;
static char *cfg_file_p1;
static struct GNUNET_STATISTICS_Handle *p1_stat;

static struct GNUNET_TRANSPORT_TESTING_PeerContext *p2;
static char *cfg_file_p2;
static struct GNUNET_STATISTICS_Handle *p2_stat;

static struct GNUNET_TRANSPORT_TESTING_PeerContext *sender;

static struct GNUNET_TRANSPORT_TESTING_PeerContext *receiver;

static struct GNUNET_TRANSPORT_TransmitHandle *th;

static struct GNUNET_TRANSPORT_TESTING_Handle *tth;

static struct GNUNET_TRANSPORT_TESTING_ConnectRequest * cc;

static int test_connected;

static int res;


/**
 * Statistics about peer 1
 */
static unsigned int p1_addresses_avail;
static unsigned int p1_switch_attempts;
static unsigned int p1_switch_success;
static unsigned int p1_switch_fail;


/**
 * Statistics about peer 2
 */
static unsigned int p2_switch_attempts;
static unsigned int p2_switch_success;
static unsigned int p2_switch_fail;
static unsigned int p2_addresses_avail;

/**
 * Transmission statistics
 */

/* Amount of data transfered since last switch attempt */
static unsigned long long bytes_sent_after_switch;
static unsigned long long bytes_recv_after_switch;


#if VERBOSE
#define OKPP do { ok++; FPRINTF (stderr, "Now at stage %u at %s:%u\n", ok, __FILE__, __LINE__); } while (0)
#else
#define OKPP do { ok++; } while (0)
#endif


static int
stat_start_attempt_cb (void *cls,
                       const char *subsystem,
                       const char *name,
                       uint64_t value,
                       int is_persistent)
{
  if (cls == p1)
  {
    p1_switch_attempts++;
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "(1:s)");
  }
  else if (cls == p2)
  {
    p2_switch_attempts++;
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "(2:s)");
  }

  bytes_recv_after_switch = 0;
  bytes_sent_after_switch = 0;

  return GNUNET_OK;
}


static int
stat_success_attempt_cb (void *cls,
                         const char *subsystem,
                         const char *name,
                         uint64_t value,
                         int is_persistent)
{
  if (cls == p1)
  {
    p1_switch_success++;
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "(1:+)");
  }
  if (cls == p2)
  {
    p2_switch_success++;
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "(2:+)");
  }

  return GNUNET_OK;
}


static int
stat_fail_attempt_cb (void *cls,
                      const char *subsystem,
                      const char *name,
                      uint64_t value,
                      int is_persistent)
{
  if (value == 0)
    return GNUNET_OK;

  if (cls == p1)
  {
    p1_switch_fail++;
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "(1:-)");
  }
  if (cls == p2)
  {
    p2_switch_fail++;
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "(2:-)");
  }

  return GNUNET_OK;
}


static int
stat_addresses_available (void *cls,
                          const char *subsystem,
                          const char *name,
                          uint64_t value,
                          int is_persistent)
{
  if (cls == p1)
  {
    p1_addresses_avail++;
  }
  if (cls == p2)
  {
    p2_addresses_avail++;
  }
  return GNUNET_OK;
}


static void
clean_up ()
{
  if (measure_task != NULL)
  {
    GNUNET_SCHEDULER_cancel (measure_task);
    measure_task = NULL;
  }

  if (delayed_end_task != NULL)
  {
    GNUNET_SCHEDULER_cancel (delayed_end_task);
    delayed_end_task = NULL;
  }

  if (die_task != NULL)
  {
    GNUNET_SCHEDULER_cancel (die_task);
    die_task = NULL;
  }

  if (NULL != p1_stat)
  {
    GNUNET_STATISTICS_watch_cancel (p1_stat, "transport",
        "# Attempts to switch addresses",
        stat_start_attempt_cb, p1);
    GNUNET_STATISTICS_watch_cancel (p1_stat, "transport",
        "# Successful attempts to switch addresses",
        stat_success_attempt_cb, p1);
    GNUNET_STATISTICS_watch_cancel (p1_stat, "transport",
        "# Failed attempts to switch addresses (failed to send CONNECT CONT)",
        stat_fail_attempt_cb, p1);
    GNUNET_STATISTICS_watch_cancel (p1_stat, "transport",
        "# Failed attempts to switch addresses (failed to send CONNECT)",
        stat_fail_attempt_cb, p1);
    GNUNET_STATISTICS_watch_cancel (p1_stat, "transport",
        "# Failed attempts to switch addresses (no response)",
        stat_fail_attempt_cb, p1);
    GNUNET_STATISTICS_watch (p1_stat, "transport",
        "# transport addresses",
        stat_addresses_available, p1);
    GNUNET_STATISTICS_destroy (p1_stat, GNUNET_NO);
    p1_stat = NULL;
  }
  if (NULL != p2_stat)
  {
    GNUNET_STATISTICS_watch_cancel (p2_stat, "transport",
        "# Attempts to switch addresses", stat_start_attempt_cb, p2);
    GNUNET_STATISTICS_watch_cancel (p2_stat, "transport",
        "# Successful attempts to switch addresses", stat_success_attempt_cb, p2);
    GNUNET_STATISTICS_watch_cancel (p2_stat, "transport",
        "# Failed attempts to switch addresses (failed to send CONNECT CONT)",
        stat_fail_attempt_cb, p2);
    GNUNET_STATISTICS_watch_cancel (p2_stat, "transport",
        "# Failed attempts to switch addresses (failed to send CONNECT)",
        stat_fail_attempt_cb, p2);
    GNUNET_STATISTICS_watch_cancel (p2_stat, "transport",
        "# Failed attempts to switch addresses (no response)",
        stat_fail_attempt_cb, p2);
    GNUNET_STATISTICS_watch (p2_stat, "transport",
        "# transport addresses",
        stat_addresses_available, p2);
    GNUNET_STATISTICS_destroy (p2_stat, GNUNET_NO);
    p2_stat = NULL;
  }

  if (th != NULL)
  {
    GNUNET_TRANSPORT_notify_transmit_ready_cancel (th);
    th = NULL;
  }
  if (cc != NULL)
  {
    GNUNET_TRANSPORT_TESTING_connect_peers_cancel (cc);
    cc = NULL;
  }
  if (p1 != NULL)
  {
    GNUNET_TRANSPORT_TESTING_stop_peer (p1);
    p1 = NULL;
  }
  if (p2 != NULL)
  {
    GNUNET_TRANSPORT_TESTING_stop_peer (p2);
    p2 = NULL;
  }
}


static void
end ()
{
  int result = 0;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Stopping peers\n");

  delayed_end_task = NULL;
  FPRINTF (stderr, "\n");
  if (p1_switch_attempts > 0)
  {
    FPRINTF (stderr,
             "Peer 1 tried %u times to switch and succeeded %u times, failed %u times\n",
             p1_switch_attempts,
             p1_switch_success,
             p1_switch_fail);
    if (p1_switch_success != p1_switch_attempts)
    {
      GNUNET_break (0);
      result ++;
    }
  }
  else if (p1_addresses_avail > 1)
  {
    FPRINTF (stderr,
             "Peer 1 had %u addresses available, but did not try to switch\n",
             p1_addresses_avail);
  }
  if (p2_switch_attempts > 0)
  {
    FPRINTF (stderr,
             "Peer 2 tried %u times to switch and succeeded %u times, failed %u times\n",
             p2_switch_attempts,
             p2_switch_success,
             p2_switch_fail);
    if (p2_switch_success != p2_switch_attempts)
    {
      GNUNET_break (0);
      result++;
    }
  }
  else if (p2_addresses_avail > 1)
  {
    FPRINTF (stderr,
             "Peer 2 had %u addresses available, but did not try to switch\n",
             p2_addresses_avail);
  }

  if ( ((p1_switch_attempts > 0) || (p2_switch_attempts > 0)) &&
       (bytes_sent_after_switch == 0) )
  {
    FPRINTF (stderr, "No data sent after switching!\n");
    GNUNET_break (0);
    res++;
  }
  if ( ((p1_switch_attempts > 0) || (p2_switch_attempts > 0)) &&
       (bytes_recv_after_switch == 0) )
  {
    FPRINTF (stderr, "No data received after switching!\n");
    GNUNET_break (0);
    res++;
  }

  clean_up();

  res = result;
}


static void
end_badly ()
{
  die_task = NULL;
  clean_up();
  if (0 == p1_switch_attempts + p2_switch_attempts)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "Test did not work, as peers didn't switch (flawed testcase)!\n");
    res = 0;
  }
  else
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
              "Fail (timeout)! No transmission after switch! Stopping peers\n");
    res = GNUNET_YES;
  }
  if (test_connected == GNUNET_YES)
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Peers got connected\n");
  else
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Peers got NOT EVEN connected\n");
}


static void
notify_receive (void *cls,
                const struct GNUNET_PeerIdentity *peer,
                const struct GNUNET_MessageHeader *message)
{
  const struct TestMessage *hdr;

  hdr = (const struct TestMessage *) message;
  if (MTYPE != ntohs (message->type))
    return;

  struct GNUNET_TRANSPORT_TESTING_PeerContext *p = cls;
  char *ps = GNUNET_strdup (GNUNET_i2s (&p->id));

  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "Peer %u (`%s') got message %u of size %u from peer (`%s')\n", p->no, ps,
              ntohl (hdr->num),
              ntohs (message->size),
              GNUNET_i2s (peer));
  if ( ((p1_switch_attempts >= 1) || (p2_switch_attempts >= 1)) &&
        (p1_switch_attempts == p1_switch_fail + p1_switch_success) &&
        (p2_switch_attempts == p2_switch_fail + p2_switch_success) )
  {
    bytes_recv_after_switch += ntohs(hdr->header.size);
    if ((bytes_sent_after_switch > 0) && (bytes_recv_after_switch > 0))
    {
      /* A peer switched addresses and sent and received data after the
       * switch operations */
      end ();
    }
  }

  GNUNET_free(ps);
}


static size_t
notify_ready (void *cls, size_t size, void *buf)
{
  static uint32_t counter;
  char *cbuf = buf;
  struct TestMessage hdr;

  th = NULL;
  if (buf == NULL)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
               "Timeout occurred while waiting for transmit_ready for message\n");
    if (NULL != die_task)
      GNUNET_SCHEDULER_cancel (die_task);
    die_task = GNUNET_SCHEDULER_add_now (&end_badly, NULL);
    res = 1;
    return 0;
  }

  GNUNET_assert(size >= MSIZE);
  GNUNET_assert(buf != NULL);
  cbuf = buf;

  hdr.header.size = htons (MSIZE);
  hdr.header.type = htons (MTYPE);
  hdr.num = htonl (counter++);
  GNUNET_memcpy (&cbuf[0], &hdr, sizeof(struct TestMessage));
  memset (&cbuf[sizeof(struct TestMessage)], '0', MSIZE - sizeof(struct TestMessage));

  char *receiver_s = GNUNET_strdup (GNUNET_i2s (&receiver->id));
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "Sending message %u of size %u from peer %u (`%4s') -> peer %u (`%s') !\n",
              (unsigned int) (counter - 1),
              MSIZE,
              sender->no,
              GNUNET_i2s (&sender->id),
              receiver->no,
              receiver_s);
  GNUNET_free(receiver_s);

  if (th == NULL)
    th = GNUNET_TRANSPORT_notify_transmit_ready (p2->th,
                                                 &p1->id,
                                                 MSIZE,
                                                 TIMEOUT_TRANSMIT,
                                                 &notify_ready, NULL);

  if ( ((p1_switch_attempts >= 1) || (p2_switch_attempts >= 1)) &&
        (p1_switch_attempts == p1_switch_fail + p1_switch_success) &&
        (p2_switch_attempts == p2_switch_fail + p2_switch_success) )
  {
    bytes_sent_after_switch += MSIZE;
  }
  return MSIZE;
}


static void
notify_connect (void *cls,
                const struct GNUNET_PeerIdentity *peer)
{
  struct GNUNET_TRANSPORT_TESTING_PeerContext *p = cls;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Peer %u (`%4s') connected to us!\n",
              p->no,
              GNUNET_i2s (peer));
}


static void
notify_disconnect (void *cls,
                   const struct GNUNET_PeerIdentity *peer)
{
  struct GNUNET_TRANSPORT_TESTING_PeerContext *p = cls;

  if (NULL != p1)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Peer %u (`%4s') disconnected early!\n",
                p->no,
                GNUNET_i2s (peer));
    GNUNET_SCHEDULER_shutdown ();
  }
  if (NULL != th)
  {
    GNUNET_TRANSPORT_notify_transmit_ready_cancel (th);
    th = NULL;
  }
}


static void
sendtask ()
{
  /* Transmit test messages */
  th = GNUNET_TRANSPORT_notify_transmit_ready (p2->th,
                                               &p1->id, MSIZE,
                                               TIMEOUT_TRANSMIT,
                                               &notify_ready, NULL);
}


static void
progress_indicator (void *cls)
{
  static int counter;

  measure_task = NULL;
  counter++;
  if ((DURATION.rel_value_us / 1000 / 1000LL) < counter)
  {
    FPRINTF (stderr, "%s", ".\n");
  }
  else
  {
    FPRINTF (stderr, "%s", ".");
    measure_task = GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_SECONDS,
                                                 &progress_indicator, NULL);
  }
}


static void
testing_connect_cb (void *cls)
{
  char *p1_c = GNUNET_strdup (GNUNET_i2s (&p1->id));

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Peers connected: %u (%s) <-> %u (%s)\n",
              p1->no, p1_c, p2->no,
              GNUNET_i2s (&p2->id));
  GNUNET_free (p1_c);

  cc = NULL;
  test_connected = GNUNET_YES;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "(i:s/+/-) \t i == peer 1/2, s/+/- : switch attempt/switch ok/switch fail\n");

  /* Show progress */
  measure_task = GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_SECONDS,
                                               &progress_indicator,
                                               NULL);
  /* Peers are connected, start transmit test messages */
  GNUNET_SCHEDULER_add_now (&sendtask, NULL);
}


static void
start_cb (struct GNUNET_TRANSPORT_TESTING_PeerContext *p, void *cls)
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
  sender = p2;
  receiver = p1;

  char *sender_c = GNUNET_strdup (GNUNET_i2s (&sender->id));
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Test tries to send from %u (%s) -> peer %u (%s)\n",
              sender->no,
              sender_c,
              receiver->no,
              GNUNET_i2s (&receiver->id));
  GNUNET_free (sender_c);

  /* Connect the peers */
  cc = GNUNET_TRANSPORT_TESTING_connect_peers (p1,
                                               p2,
                                               &testing_connect_cb,
                                               NULL);
}


static void
run (void *cls,
     char * const *args,
     const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  die_task = GNUNET_SCHEDULER_add_delayed (TIMEOUT, &end_badly, NULL);

  p1 = GNUNET_TRANSPORT_TESTING_start_peer (tth, cfg_file_p1, 1,
      &notify_receive, &notify_connect, &notify_disconnect, &start_cb, NULL);

  p2 = GNUNET_TRANSPORT_TESTING_start_peer (tth, cfg_file_p2, 2,
      &notify_receive, &notify_connect, &notify_disconnect, &start_cb, NULL);

  if ((p1 == NULL )|| (p2 == NULL))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Fail! Could not start peers!\n");
    GNUNET_SCHEDULER_shutdown ();
    return;
  }

  /* Start to watch statistics for peer 1 */
  p1_stat = GNUNET_STATISTICS_create ("transport", p1->cfg);
  GNUNET_STATISTICS_watch (p1_stat, "transport",
      "# Attempts to switch addresses",
      stat_start_attempt_cb, p1);
  GNUNET_STATISTICS_watch (p1_stat, "transport",
      "# Successful attempts to switch addresses",
      stat_success_attempt_cb, p1);
  GNUNET_STATISTICS_watch (p1_stat, "transport",
      "# Failed attempts to switch addresses (failed to send CONNECT CONT)",
      stat_fail_attempt_cb, p1);
  GNUNET_STATISTICS_watch (p1_stat, "transport",
      "# Failed attempts to switch addresses (failed to send CONNECT)",
      stat_fail_attempt_cb, p1);
  GNUNET_STATISTICS_watch (p1_stat, "transport",
      "# Failed attempts to switch addresses (no response)",
      stat_fail_attempt_cb, p1);
  GNUNET_STATISTICS_watch (p1_stat, "transport",
      "# transport addresses",
      stat_addresses_available, p1);

  /* Start to watch statistics for peer 2  */
  p2_stat = GNUNET_STATISTICS_create ("transport", p2->cfg);
  GNUNET_STATISTICS_watch (p2_stat, "transport",
      "# Attempts to switch addresses",
      stat_start_attempt_cb, p2);
  GNUNET_STATISTICS_watch (p2_stat, "transport",
      "# Successful attempts to switch addresses",
      stat_success_attempt_cb, p2);
  GNUNET_STATISTICS_watch (p2_stat, "transport",
      "# Failed attempts to switch addresses (failed to send CONNECT CONT)",
      stat_fail_attempt_cb, p2);
  GNUNET_STATISTICS_watch (p2_stat, "transport",
      "# Failed attempts to switch addresses (failed to send CONNECT)",
      stat_fail_attempt_cb, p2);
  GNUNET_STATISTICS_watch (p2_stat, "transport",
      "# Failed attempts to switch addresses (no response)",
      stat_fail_attempt_cb, p2);
  GNUNET_STATISTICS_watch (p2_stat, "transport",
      "# transport addresses",
      stat_addresses_available, p2);

  if ((p1_stat == NULL )|| (p2_stat == NULL))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Fail! Could not create statistics for peers!\n");
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
}

int
main (int argc, char *argv[])
{
  char *test_plugin;
  char *test_source;
  char *test_name;

  static char *argv_new[] = { "test-transport-address-switch", "-c",
      "test_transport_startonly.conf", NULL };

  static struct GNUNET_GETOPT_CommandLineOption options[] = {
      GNUNET_GETOPT_OPTION_END };

  test_name = GNUNET_TRANSPORT_TESTING_get_test_name (argv[0]);

  GNUNET_log_setup (test_name, "WARNING", NULL );

  test_source = GNUNET_TRANSPORT_TESTING_get_test_source_name (__FILE__);
  test_plugin = GNUNET_TRANSPORT_TESTING_get_test_plugin_name (argv[0],
                                                               test_source);

  tth = GNUNET_TRANSPORT_TESTING_init ();

  cfg_file_p1 = GNUNET_TRANSPORT_TESTING_get_config_name (argv[0], 1);
  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "Using cfg [%u] : %s \n", 1, cfg_file_p1);
  cfg_file_p2 = GNUNET_TRANSPORT_TESTING_get_config_name (argv[0], 2);
  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "Using cfg [%u] : %s \n", 2, cfg_file_p2);

  GNUNET_PROGRAM_run ((sizeof(argv_new) / sizeof(char *)) - 1, argv_new,
      test_name, "nohelp", options, &run, NULL );

  GNUNET_free(cfg_file_p1);
  GNUNET_free(cfg_file_p2);

  GNUNET_free(test_source);
  GNUNET_free(test_plugin);
  GNUNET_free(test_name);

  GNUNET_TRANSPORT_TESTING_done (tth);

  return res;
}

/* end of test_transport_address_switch.c */

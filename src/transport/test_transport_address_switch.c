/*
 This file is part of GNUnet.
 (C) 2009, 2010, 2011 Christian Grothoff (and other contributing authors)

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
 * @file transport/test_transport_address_switch.c
 * @brief base test case for transport implementations
 *
 * This test case tests if peers can successfully switch address when connected
 * connected
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
  uint32_t num;
};
GNUNET_NETWORK_STRUCT_END

/**
 * Note that this value must not significantly exceed
 * 'MAX_PENDING' in 'gnunet-service-transport.c', otherwise
 * messages may be dropped even for a reliable transport.
 */
#define TOTAL_MSGS (4096 * 2)

/**
 * Message type for test messages
 */
#define MTYPE 12345

/**
 * Testcase timeout
 */
#define TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 120)

/**
 * How long until we give up on transmitting the message?
 */
#define TIMEOUT_TRANSMIT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 60)

#define DURATION GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 30)
#define DELAY GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 5)

static GNUNET_SCHEDULER_TaskIdentifier die_task;

static GNUNET_SCHEDULER_TaskIdentifier delayed_end_task;

static GNUNET_SCHEDULER_TaskIdentifier measure_task;

struct PeerContext *p1;
char *cfg_file_p1;
struct GNUNET_STATISTICS_Handle *p1_stat;

struct PeerContext *p2;
char *cfg_file_p2;
struct GNUNET_STATISTICS_Handle *p2_stat;

struct PeerContext *sender;

struct PeerContext *receiver;

struct GNUNET_TRANSPORT_TransmitHandle *th;

static int test_connected;
static int res;

struct GNUNET_TRANSPORT_TESTING_handle *tth;

static GNUNET_TRANSPORT_TESTING_ConnectRequest cc;

static unsigned int p1_switch_attempts;
static unsigned int p1_switch_success;
static unsigned int p1_switch_fail;
static unsigned int p1_addresses_avail;

static unsigned int p2_switch_attempts;
static unsigned int p2_switch_success;
static unsigned int p2_switch_fail;
static unsigned int p2_addresses_avail;

static unsigned long long bytes_sent_total;
static unsigned long long bytes_recv_total;

static unsigned long long bytes_sent_after_switch;
static unsigned long long bytes_recv_after_switch;

static struct GNUNET_TIME_Absolute start_time;
static struct GNUNET_TIME_Absolute start_time;

/*
 * END Testcase specific declarations
 */

#if VERBOSE
#define OKPP do { ok++; FPRINTF (stderr, "Now at stage %u at %s:%u\n", ok, __FILE__, __LINE__); } while (0)
#else
#define OKPP do { ok++; } while (0)
#endif

static void end ();

static int
stat_start_attempt_cb (void *cls, const char *subsystem, const char *name,
    uint64_t value, int is_persistent)
{
  if (cls == p1)
  {
    p1_switch_attempts++;
    FPRINTF (stderr, "Peer 1 tries to switch.");
  }
  else if (cls == p2)
  {
    p2_switch_attempts++;
    FPRINTF (stderr, "Peer 2 tries to switch.");
  }
  else
    return GNUNET_OK;

  if (GNUNET_SCHEDULER_NO_TASK == delayed_end_task)
    delayed_end_task = GNUNET_SCHEDULER_add_delayed (DELAY, &end, NULL );
  return GNUNET_OK;
}


static int
stat_success_attempt_cb (void *cls, const char *subsystem, const char *name,
    uint64_t value, int is_persistent)
{
  if (cls == p1)
  {
    p1_switch_success++;
    FPRINTF (stderr, "Peer 1 switched successfully.");
  }
  if (cls == p2)
  {
    p2_switch_success++;
    FPRINTF (stderr, "Peer 2 switched successfully.");
  }

  return GNUNET_OK;
}


static int
stat_fail_attempt_cb (void *cls, const char *subsystem, const char *name,
    uint64_t value, int is_persistent)
{
  if (value == 0)
    return GNUNET_OK;

  if (cls == p1)
  {
    p1_switch_fail++;
    FPRINTF (stderr, "Peer 1 failed to switch.");
  }
  if (cls == p2)
  {
    p2_switch_fail++;
    FPRINTF (stderr, "Peer 2 failed to switch.");
  }

  return GNUNET_OK;
}

static int
stat_addresses_available (void *cls, const char *subsystem, const char *name,
    uint64_t value, int is_persistent)
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
  if (measure_task != GNUNET_SCHEDULER_NO_TASK )
  {
    GNUNET_SCHEDULER_cancel (measure_task);
    measure_task = GNUNET_SCHEDULER_NO_TASK;
  }

  if (delayed_end_task != GNUNET_SCHEDULER_NO_TASK )
  {
    GNUNET_SCHEDULER_cancel (delayed_end_task);
    delayed_end_task = GNUNET_SCHEDULER_NO_TASK;
  }

  if (die_task != GNUNET_SCHEDULER_NO_TASK )
  {
    GNUNET_SCHEDULER_cancel (die_task);
    die_task = GNUNET_SCHEDULER_NO_TASK;
  }

  if (NULL != p1_stat)
  {
    GNUNET_STATISTICS_watch_cancel (p1_stat, "transport",
        "# Attempts to switch addresses", stat_start_attempt_cb, p1);
    GNUNET_STATISTICS_watch_cancel (p1_stat, "transport",
        "# Successful attempts to switch addresses", stat_success_attempt_cb, p1);
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
    GNUNET_STATISTICS_watch (p1_stat, "transport",
        "# transport addresses",
        stat_addresses_available, p1);
    GNUNET_STATISTICS_destroy (p2_stat, GNUNET_NO);
    p2_stat = NULL;
  }

  if (die_task != GNUNET_SCHEDULER_NO_TASK )
  {
    GNUNET_SCHEDULER_cancel (die_task);
    die_task = GNUNET_SCHEDULER_NO_TASK;
  }

  if (th != NULL )
  {
    GNUNET_TRANSPORT_notify_transmit_ready_cancel (th);
    th = NULL;
  }

  if (cc != NULL )
  {
    GNUNET_TRANSPORT_TESTING_connect_peers_cancel (tth, cc);
    cc = NULL;
  }

  if (p1 != NULL )
  {
    GNUNET_TRANSPORT_TESTING_stop_peer (tth, p1);
    p1 = NULL;
  }
  if (p2 != NULL )
  {
    GNUNET_TRANSPORT_TESTING_stop_peer (tth, p2);
    p2 = NULL;
  }

}


static void
end ()
{
  int result = 0;
  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "Stopping peers\n");

  delayed_end_task = GNUNET_SCHEDULER_NO_TASK;
  FPRINTF (stderr, "\n");
  if (p1_switch_attempts > 0)
  {
    FPRINTF (stderr, "Peer 1 tried %u times to switch and succeeded %u times, failed %u times\n",
        p1_switch_attempts, p1_switch_success, p1_switch_fail);
    if (p1_switch_success != p1_switch_attempts)
      result ++;
  }
  else
  {
    FPRINTF (stderr, "Peer 1 had %u addresses available, but did not try to switch\n",
        p1_addresses_avail);
  }
  if (p2_switch_attempts > 0)
  {
    FPRINTF (stderr, "Peer 2 tried %u times to switch and succeeded %u times, failed %u times\n",
        p2_switch_attempts, p2_switch_success, p2_switch_fail);
    if (p2_switch_success != p2_switch_attempts)
      result ++;
  }
  else
  {
    FPRINTF (stderr, "Peer 2 had %u addresses available, but did not try to switch\n",
        p2_addresses_avail);
  }

  if ( ((p1_switch_attempts > 0) || (p2_switch_attempts > 0)) &&
       (bytes_sent_after_switch == 0) )
  {
    FPRINTF (stderr, "No data sent after switching!\n");
    res ++;
  }
  if ( ((p1_switch_attempts > 0) || (p2_switch_attempts > 0)) &&
       (bytes_recv_after_switch == 0) )
  {
    FPRINTF (stderr, "No data received after switching!\n");
    res ++;
  }

  clean_up();

  res = result;
}


static void
end_badly ()
{
  die_task = GNUNET_SCHEDULER_NO_TASK;
  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "Fail! Stopping peers\n");

  FPRINTF (stderr, "Peer 1 had %u addresses available, but did not try to switch\n",
      p1_addresses_avail);
  FPRINTF (stderr, "Peer 2 had %u addresses available, but did not try to switch\n",
      p2_addresses_avail);

  if (test_connected == GNUNET_YES)
    GNUNET_log(GNUNET_ERROR_TYPE_ERROR, "Peers got connected\n");
  else
    GNUNET_log(GNUNET_ERROR_TYPE_ERROR, "Peers got NOT connected\n");

  clean_up();

  res = GNUNET_YES;
}


static unsigned int
get_size (unsigned int iter)
{
  unsigned int ret;
  ret = (iter * iter * iter);
  return sizeof(struct TestMessage) + (ret % 60000);
}


static void
notify_receive (void *cls, const struct GNUNET_PeerIdentity *peer,
    const struct GNUNET_MessageHeader *message)
{
  const struct TestMessage *hdr;

  hdr = (const struct TestMessage *) message;
  if (MTYPE != ntohs (message->type))
    return;

  struct PeerContext *p = cls;
  char *ps = GNUNET_strdup (GNUNET_i2s (&p->id));

  GNUNET_log(GNUNET_ERROR_TYPE_INFO,
      "Peer %u (`%s') got message %u of size %u from peer (`%s')\n", p->no, ps,
      ntohl (hdr->num), ntohs (message->size), GNUNET_i2s (peer));

  bytes_recv_total += ntohs(hdr->header.size);
  if ((p1_switch_attempts > 0) || (p2_switch_attempts > 0))
    bytes_recv_after_switch += ntohs(hdr->header.size);

  GNUNET_free(ps);
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
  if (buf == NULL )
  {
    GNUNET_log(GNUNET_ERROR_TYPE_ERROR,
        "Timeout occurred while waiting for transmit_ready for message\n");
    if (GNUNET_SCHEDULER_NO_TASK != die_task)
      GNUNET_SCHEDULER_cancel (die_task);
    die_task = GNUNET_SCHEDULER_add_now (&end_badly, NULL );
    res = 1;
    return 0;
  }

  ret = 0;
  s = get_size (n);
  GNUNET_assert(size >= s);
  GNUNET_assert(buf != NULL);
  cbuf = buf;
  do
  {
    hdr.header.size = htons (s);
    hdr.header.type = htons (MTYPE);
    hdr.num = htonl (n);
    memcpy (&cbuf[ret], &hdr, sizeof(struct TestMessage));
    ret += sizeof(struct TestMessage);
    memset (&cbuf[ret], n, s - sizeof(struct TestMessage));
    ret += s - sizeof(struct TestMessage);
#if VERBOSE
    if (n % 5000 == 0)
    {
#endif
    char *receiver_s = GNUNET_strdup (GNUNET_i2s (&receiver->id));

    GNUNET_log(GNUNET_ERROR_TYPE_INFO,
        "Sending message %u of size %u from peer %u (`%4s') -> peer %u (`%s') !\n",
        n, s, sender->no, GNUNET_i2s (&sender->id), receiver->no, receiver_s);
    GNUNET_free(receiver_s);
#if 0
  }
#endif
    n++;
    s = get_size (n);
    if (0 == GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK, 16))
      break; /* sometimes pack buffer full, sometimes not */
  }
  while (size - ret >= s);
  if (n < TOTAL_MSGS)
  {
    if (th == NULL )
      th = GNUNET_TRANSPORT_notify_transmit_ready (p2->th, &p1->id, s,
          TIMEOUT_TRANSMIT, &notify_ready, NULL );
  }
  if (n % 5000 == 0)
  {

  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
      "Returning total message block of size %u\n", ret);

  bytes_sent_total += ret;
  if ((p1_switch_attempts > 0) || (p2_switch_attempts > 0))
    bytes_sent_after_switch += ret;

  if (n == TOTAL_MSGS)
  {
    FPRINTF (stderr, "%s", "\n");
    GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "All messages sent\n");
  }
  return ret;
}


static void
notify_connect (void *cls, const struct GNUNET_PeerIdentity *peer)
{
  struct PeerContext *p = cls;
  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "Peer %u (`%4s') connected to us!\n",
      p->no, GNUNET_i2s (peer));
}


static void
notify_disconnect (void *cls, const struct GNUNET_PeerIdentity *peer)
{
  struct PeerContext *p = cls;
  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "Peer %u (`%4s') disconnected!\n", p->no,
      GNUNET_i2s (peer));
  if (th != NULL )
    GNUNET_TRANSPORT_notify_transmit_ready_cancel (th);
  th = NULL;

}


static void
sendtask ()
{
  start_time = GNUNET_TIME_absolute_get ();
  th = GNUNET_TRANSPORT_notify_transmit_ready (p2->th, &p1->id, get_size (0),
      TIMEOUT_TRANSMIT, &notify_ready, NULL );
}


static void
measure (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  static int counter;

  measure_task = GNUNET_SCHEDULER_NO_TASK;

  counter++;
  if ((DURATION.rel_value_us / 1000 / 1000LL) < counter)
  {
    FPRINTF (stderr, "%s", ".\n");
  }
  else
  {
    FPRINTF (stderr, "%s", ".");
    measure_task = GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_SECONDS,
        &measure, NULL );
  }
}


static void
testing_connect_cb (struct PeerContext *p1, struct PeerContext *p2, void *cls)
{
  char *p1_c = GNUNET_strdup (GNUNET_i2s (&p1->id));

  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "Peers connected: %u (%s) <-> %u (%s)\n",
      p1->no, p1_c, p2->no, GNUNET_i2s (&p2->id));
  GNUNET_free(p1_c);

  cc = NULL;
  test_connected = GNUNET_YES;

  measure_task = GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_SECONDS,
      &measure, NULL );
 GNUNET_SCHEDULER_add_now (&sendtask, NULL );
}


static void
start_cb (struct PeerContext *p, void *cls)
{
  static int started;
  started++;

  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "Peer %u (`%s') started\n", p->no,
      GNUNET_i2s (&p->id));
  if (started != 2)
    return;

  test_connected = GNUNET_NO;
  sender = p2;
  receiver = p1;

  char *sender_c = GNUNET_strdup (GNUNET_i2s (&sender->id));
  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
      "Test tries to send from %u (%s) -> peer %u (%s)\n", sender->no, sender_c,
      receiver->no, GNUNET_i2s (&receiver->id));
  GNUNET_free(sender_c);
  cc = GNUNET_TRANSPORT_TESTING_connect_peers (tth, p1, p2, &testing_connect_cb,
      NULL );
}


static void
run (void *cls, char * const *args, const char *cfgfile,
    const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  die_task = GNUNET_SCHEDULER_add_delayed (TIMEOUT, &end_badly, NULL );

  p1 = GNUNET_TRANSPORT_TESTING_start_peer (tth, cfg_file_p1, 1,
      &notify_receive, &notify_connect, &notify_disconnect, &start_cb, NULL );
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

  p2 = GNUNET_TRANSPORT_TESTING_start_peer (tth, cfg_file_p2, 2,
      &notify_receive, &notify_connect, &notify_disconnect, &start_cb, NULL );

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

  if ((p1 == NULL )|| (p2 == NULL))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Fail! Could not start peers!\n");
    if (die_task != GNUNET_SCHEDULER_NO_TASK)
    GNUNET_SCHEDULER_cancel (die_task);
    die_task = GNUNET_SCHEDULER_add_now (&end_badly, NULL);
    return;
  }

  if ((p1_stat == NULL )|| (p2_stat == NULL))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Fail! Could not create statistics for peers!\n");
    if (die_task != GNUNET_SCHEDULER_NO_TASK)
    GNUNET_SCHEDULER_cancel (die_task);
    die_task = GNUNET_SCHEDULER_add_now (&end_badly, NULL);
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

  GNUNET_TRANSPORT_TESTING_get_test_name (argv[0], &test_name);

  GNUNET_log_setup (test_name, "WARNING", NULL );

  GNUNET_TRANSPORT_TESTING_get_test_source_name (__FILE__, &test_source);
  GNUNET_TRANSPORT_TESTING_get_test_plugin_name (argv[0], test_source,
      &test_plugin);

  tth = GNUNET_TRANSPORT_TESTING_init ();

  GNUNET_TRANSPORT_TESTING_get_config_name (argv[0], &cfg_file_p1, 1);
  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "Using cfg [%u] : %s \n", 1, cfg_file_p1);
  GNUNET_TRANSPORT_TESTING_get_config_name (argv[0], &cfg_file_p2, 2);
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

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
 * @file transport/test_quota_compliance.c
 * @brief base test case for transport implementations
 *
 * This test case tests quota compliance both on transport level
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
#define TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 120)

/**
 * How long until we give up on transmitting the message?
 */
#define TIMEOUT_TRANSMIT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 20)

#define DURATION GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 5)

static char *test_source;

static char *test_plugin;

static char *test_name;

static int ok;

static GNUNET_SCHEDULER_TaskIdentifier die_task;

static GNUNET_SCHEDULER_TaskIdentifier measure_task;

struct PeerContext *p1;

struct PeerContext *p2;

struct PeerContext *sender;

struct PeerContext *receiver;

struct GNUNET_TRANSPORT_TransmitHandle *th;

char *cfg_file_p1;
char *gen_cfg_p2;
unsigned long long quota_in_p1;
unsigned long long quota_out_p1;

char *cfg_file_p2;
char *gen_cfg_p1;
unsigned long long quota_in_p2;
unsigned long long quota_out_p2;

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

static unsigned long long total_bytes_sent;

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
  unsigned long long datarate;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Stopping peers\n");

  delta = GNUNET_TIME_absolute_get_duration (start_time).rel_value;
  datarate = (total_bytes_sent * 1000) / delta;

  FPRINTF (stderr, "Throughput was %llu b/s\n", datarate);

  test_failed = GNUNET_NO;
  if (datarate > quota_in_p2)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Datarate of %llu b/s higher than allowed inbound quota of %llu b/s\n",
                datarate, quota_in_p2);
    test_failed = GNUNET_YES;
  }
  if (datarate > quota_out_p1)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Datarate of %llu b/s higher than allowed outbound quota of %llu b/s\n",
                datarate, quota_out_p1);
    test_failed = GNUNET_YES;
  }
  if (test_failed == GNUNET_NO)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Datarate of %llu b/s complied to allowed outbound quota of %llu b/s and inbound quota of %llu b/s\n",
                datarate, quota_out_p1, quota_in_p2);
  }

  if (die_task != GNUNET_SCHEDULER_NO_TASK)
    GNUNET_SCHEDULER_cancel (die_task);

  if (th != NULL)
    GNUNET_TRANSPORT_notify_transmit_ready_cancel (th);
  th = NULL;

  if (cc != NULL)
    GNUNET_TRANSPORT_TESTING_connect_peers_cancel (tth, cc);

  GNUNET_TRANSPORT_TESTING_stop_peer (tth, p1);
  GNUNET_TRANSPORT_TESTING_stop_peer (tth, p2);

}

static void
end_badly ()
{
  die_task = GNUNET_SCHEDULER_NO_TASK;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Fail! Stopping peers\n");

  if (measure_task != GNUNET_SCHEDULER_NO_TASK)
    GNUNET_SCHEDULER_cancel (measure_task);

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
                "Expected message %u with bits %u, but body did not match\n", n,
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
  total_bytes_sent += ret;
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
measure (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  static int counter;

  measure_task = GNUNET_SCHEDULER_NO_TASK;

  counter++;
  if ((DURATION.rel_value / 1000) < counter)
  {
    FPRINTF (stderr, "%s",  ".\n");
    GNUNET_SCHEDULER_add_now (&end, NULL);
  }
  else
  {
    FPRINTF (stderr, "%s",  ".");
    measure_task =
        GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_SECONDS, &measure, NULL);
  }
}


static void
testing_connect_cb (struct PeerContext *p1, struct PeerContext *p2, void *cls)
{
  char *p1_c = GNUNET_strdup (GNUNET_i2s (&p1->id));

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Peers connected: %u (%s) <-> %u (%s)\n",
              p1->no, p1_c, p2->no, GNUNET_i2s (&p2->id));
  GNUNET_free (p1_c);

  cc = NULL;
  test_connected = GNUNET_YES;

  measure_task =
      GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_SECONDS, &measure, NULL);
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

  sender = p2;
  receiver = p1;

  char *sender_c = GNUNET_strdup (GNUNET_i2s (&sender->id));

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Test tries to send from %u (%s) -> peer %u (%s)\n", sender->no,
              sender_c, receiver->no, GNUNET_i2s (&receiver->id));

  cc = GNUNET_TRANSPORT_TESTING_connect_peers (tth, p1, p2, &testing_connect_cb,
                                               NULL);

}

static char *
generate_config (char *cfg_file, unsigned long long quota_in,
                 unsigned long long quota_out)
{
  char *fname = NULL;
  struct GNUNET_CONFIGURATION_Handle *cfg = GNUNET_CONFIGURATION_create ();

  GNUNET_assert (GNUNET_OK == GNUNET_CONFIGURATION_load (cfg, cfg_file));
  GNUNET_asprintf (&fname, "q_in_%llu_q_out_%llu_%s", quota_in, quota_out,
                   cfg_file);
  GNUNET_CONFIGURATION_set_value_string (cfg, "PATHS", "DEFAULTCONFIG", fname);
  GNUNET_CONFIGURATION_set_value_number (cfg, "ats", "WAN_QUOTA_IN", quota_in);
  GNUNET_CONFIGURATION_set_value_number (cfg, "ats", "WAN_QUOTA_OUT",
                                         quota_out);
  GNUNET_assert (GNUNET_OK == GNUNET_CONFIGURATION_write (cfg, fname));
  GNUNET_CONFIGURATION_destroy (cfg);
  return fname;
}

static void
run_measurement (unsigned long long p1_quota_in,
                 unsigned long long p1_quota_out,
                 unsigned long long p2_quota_in,
                 unsigned long long p2_quota_out)
{
  die_task = GNUNET_SCHEDULER_add_delayed (TIMEOUT, &end_badly, NULL);

  /* setting ATS quota */
  quota_out_p1 = p1_quota_out;
  gen_cfg_p1 = generate_config (cfg_file_p1, p1_quota_in, p1_quota_out);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Generated config file `%s'\n",
              gen_cfg_p1);

  quota_in_p2 = p2_quota_in;
  gen_cfg_p2 = generate_config (cfg_file_p2, p2_quota_in, p2_quota_out);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Generated config file `%s'\n",
              gen_cfg_p2);

  p1 = GNUNET_TRANSPORT_TESTING_start_peer (tth, gen_cfg_p1, 1, &notify_receive,
                                            &notify_connect, &notify_disconnect,
                                            &start_cb, NULL);

  p2 = GNUNET_TRANSPORT_TESTING_start_peer (tth, gen_cfg_p2, 2, &notify_receive,
                                            &notify_connect, &notify_disconnect,
                                            &start_cb, NULL);

  if ((p1 == NULL) || (p2 == NULL))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Fail! Could not start peers!\n");
    if (die_task != GNUNET_SCHEDULER_NO_TASK)
      GNUNET_SCHEDULER_cancel (die_task);
    die_task = GNUNET_SCHEDULER_add_now (&end_badly, NULL);
    return;
  }
}

static void
run (void *cls, char *const *args, const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  unsigned long long p1_quota_in = 10000;
  unsigned long long p1_quota_out = 10000;
  unsigned long long p2_quota_in = 10000;
  unsigned long long p2_quota_out = 10000;

  if (NULL != strstr (test_name, "asymmetric"))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Running asymmetric test with sending peer unlimited, receiving peer (in/out): %llu/%llu b/s \n",
                p2_quota_in, p2_quota_out);
    p1_quota_out = 1024 * 1024 * 1024;
    p1_quota_in = 1024 * 1024 * 1024;
  }
  else
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Running symmetric test with (in/out) %llu/%llu b/s \n",
                p2_quota_in, p2_quota_out);
  }
  run_measurement (p1_quota_in, p1_quota_out, p2_quota_in, p2_quota_out);
}

static int
check ()
{
  static char *argv[] = { "test_transport-quota-compliance",
    "-c",
    "test_quota_compliance_data.conf",
#if VERBOSE
    "-L", "DEBUG",
#endif
    NULL
  };
  static struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_OPTION_END
  };

  ok = 1;
  GNUNET_PROGRAM_run ((sizeof (argv) / sizeof (char *)) - 1, argv, test_name,
                      "nohelp", options, &run, &ok);

  return ok;
}

int
main (int argc, char *argv[])
{
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

  check ();

  GNUNET_free (cfg_file_p1);
  GNUNET_free (cfg_file_p2);

  if (GNUNET_YES == GNUNET_DISK_file_test (gen_cfg_p1))
  {
    GNUNET_DISK_directory_remove (gen_cfg_p1);
    GNUNET_free (gen_cfg_p1);
  }

  if (GNUNET_YES == GNUNET_DISK_file_test (gen_cfg_p2))
  {
    GNUNET_DISK_directory_remove (gen_cfg_p2);
    GNUNET_free (gen_cfg_p2);
  }

  GNUNET_free (test_source);
  GNUNET_free (test_plugin);
  GNUNET_free (test_name);

  GNUNET_TRANSPORT_TESTING_done (tth);

  return test_failed;
}


/* end of test_quota_compliance.c */

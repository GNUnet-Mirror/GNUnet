/*
     This file is part of GNUnet.
     Copyright (C) 2009, 2010, 2015 GNUnet e.V.

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
 * @file core/test_core_quota_compliance.c
 * @brief testcase for core_api.c focusing quota compliance on core level
 */
#include "platform.h"
#include "gnunet_arm_service.h"
#include "gnunet_core_service.h"
#include "gnunet_util_lib.h"
#include "gnunet_ats_service.h"
#include "gnunet_transport_service.h"
#include "gnunet_statistics_service.h"


#define SYMMETRIC 0
#define ASYMMETRIC_SEND_LIMITED 1
#define ASYMMETRIC_RECV_LIMITED 2

/**
 * Note that this value must not significantly exceed
 * 'MAX_PENDING' in 'gnunet-service-transport.c', otherwise
 * messages may be dropped even for a reliable transport.
 */
#define TOTAL_MSGS (60000 * 10)

/**
 * How long until we give up on transmitting the message?
 */
#define TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 300)

/**
 * What delay do we request from the core service for transmission?
 */
#define FAST_TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 150)

#define MTYPE 12345
#define MESSAGESIZE 1024
#define MEASUREMENT_LENGTH GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 30)

static unsigned long long total_bytes_sent;
static unsigned long long total_bytes_recv;

static struct GNUNET_TIME_Absolute start_time;

static struct GNUNET_SCHEDULER_Task *err_task;

static struct GNUNET_SCHEDULER_Task *measure_task;


struct PeerContext
{
  struct GNUNET_CONFIGURATION_Handle *cfg;
  struct GNUNET_CORE_Handle *ch;
  struct GNUNET_CORE_TransmitHandle *nth;
  struct GNUNET_PeerIdentity id;
  struct GNUNET_TRANSPORT_Handle *th;
  struct GNUNET_MessageHeader *hello;
  struct GNUNET_STATISTICS_Handle *stats;
  struct GNUNET_TRANSPORT_GetHelloHandle *ghh;
  struct GNUNET_ATS_ConnectivityHandle *ats;
  struct GNUNET_ATS_ConnectivitySuggestHandle *ats_sh;
  int connect_status;
  struct GNUNET_OS_Process *arm_proc;
};

static struct PeerContext p1;
static struct PeerContext p2;

static unsigned long long current_quota_p1_in;
static unsigned long long current_quota_p1_out;
static unsigned long long current_quota_p2_in;
static unsigned long long current_quota_p2_out;

static int ok;
static int test;
static int32_t tr_n;

static int running;


#if VERBOSE
#define OKPP do { ok++; GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Now at stage %u at %s:%u\n", ok, __FILE__, __LINE__); } while (0)
#else
#define OKPP do { ok++; } while (0)
#endif

struct TestMessage
{
  struct GNUNET_MessageHeader header;
  uint32_t num;
};


static void
terminate_peer (struct PeerContext *p)
{
  if (p->nth != NULL)
  {
    GNUNET_CORE_notify_transmit_ready_cancel (p->nth);
    p->nth = NULL;
  }
  if (NULL != p->ch)
  {
    GNUNET_CORE_disconnect (p->ch);
    p->ch = NULL;
  }
  if (NULL != p->th)
  {
    GNUNET_TRANSPORT_get_hello_cancel (p->ghh);
    GNUNET_TRANSPORT_disconnect (p->th);
    p->th = NULL;
  }
  if (NULL != p->ats_sh)
  {
    GNUNET_ATS_connectivity_suggest_cancel (p->ats_sh);
    p->ats_sh = NULL;
  }
  if (NULL != p->ats)
  {
    GNUNET_ATS_connectivity_done (p->ats);
    p->ats = NULL;
  }
  if (NULL != p->stats)
  {
    GNUNET_STATISTICS_destroy (p->stats, GNUNET_NO);
    p->stats = NULL;
  }
  if (NULL != p->hello)
  {
    GNUNET_free (p->hello);
    p->hello = NULL;
  }
}


static void
terminate_task (void *cls)
{
  err_task = NULL;
  terminate_peer (&p1);
  terminate_peer (&p2);
}


static void
terminate_task_error (void *cls)
{
  const struct GNUNET_SCHEDULER_TaskContext *tc;

  err_task = NULL;
  tc = GNUNET_SCHEDULER_get_task_context ();
  if (0 != (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN))
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Testcase failed!\n");
  terminate_peer (&p1);
  terminate_peer (&p2);
  //GNUNET_break (0);
  if (NULL != measure_task)
  {
    GNUNET_SCHEDULER_cancel (measure_task);
    measure_task = NULL;
  }
  ok = 42;
}


/**
 * Callback function to process statistic values.
 *
 * @param cls closure
 * @param subsystem name of subsystem that created the statistic
 * @param name the name of the datum
 * @param value the current value
 * @param is_persistent #GNUNET_YES if the value is persistent, #GNUNET_NO if not
 * @return #GNUNET_OK to continue, #GNUNET_SYSERR to abort iteration
 */
static int
print_stat (void *cls,
            const char *subsystem,
            const char *name,
            uint64_t value,
            int is_persistent)
{
  if (cls == &p1)
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Peer1 %50s = %12llu\n",
                name,
                (unsigned long long) value);
  if (cls == &p2)
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Peer2 %50s = %12llu\n",
                name,
                (unsigned long long) value);
  return GNUNET_OK;
}


static void
measurement_stop (void *cls)
{
  unsigned long long delta;
  unsigned long long throughput_out;
  unsigned long long throughput_in;
  unsigned long long max_quota_in;
  unsigned long long max_quota_out;
  unsigned long long quota_delta;
  enum GNUNET_ErrorType kind = GNUNET_ERROR_TYPE_DEBUG;

  measure_task = NULL;
  FPRINTF (stdout, "%s",  "\n");
  running = GNUNET_NO;

  delta = GNUNET_TIME_absolute_get_duration (start_time).rel_value_us;

  throughput_out = total_bytes_sent * 1000000LL / delta;     /* convert to bytes/s */
  throughput_in = total_bytes_recv * 1000000LL / delta;      /* convert to bytes/s */

  max_quota_in = GNUNET_MIN (current_quota_p1_in, current_quota_p2_in);
  max_quota_out = GNUNET_MIN (current_quota_p1_out, current_quota_p2_out);
  if (max_quota_out < max_quota_in)
    quota_delta = max_quota_in / 3;
  else
    quota_delta = max_quota_out / 3;

  if ((throughput_out > (max_quota_out + quota_delta)) ||
      (throughput_in > (max_quota_in + quota_delta)))
    ok = 1; /* fail */
  else
    ok = 0; /* pass */
  GNUNET_STATISTICS_get (p1.stats, "core", "# discarded CORE_SEND requests",
                         GNUNET_TIME_UNIT_FOREVER_REL, NULL, &print_stat, &p1);

  GNUNET_STATISTICS_get (p1.stats, "core",
                         "# discarded CORE_SEND request bytes",
                         GNUNET_TIME_UNIT_FOREVER_REL, NULL, &print_stat, &p1);
  GNUNET_STATISTICS_get (p1.stats, "core",
                         "# discarded lower priority CORE_SEND requests",
                         GNUNET_TIME_UNIT_FOREVER_REL, NULL, &print_stat, NULL);
  GNUNET_STATISTICS_get (p1.stats, "core",
                         "# discarded lower priority CORE_SEND request bytes",
                         GNUNET_TIME_UNIT_FOREVER_REL, NULL, &print_stat, &p1);
  GNUNET_STATISTICS_get (p2.stats, "core", "# discarded CORE_SEND requests",
                         GNUNET_TIME_UNIT_FOREVER_REL, NULL, &print_stat, &p2);

  GNUNET_STATISTICS_get (p2.stats, "core",
                         "# discarded CORE_SEND request bytes",
                         GNUNET_TIME_UNIT_FOREVER_REL, NULL, &print_stat, &p2);
  GNUNET_STATISTICS_get (p2.stats, "core",
                         "# discarded lower priority CORE_SEND requests",
                         GNUNET_TIME_UNIT_FOREVER_REL, NULL, &print_stat, &p2);
  GNUNET_STATISTICS_get (p2.stats, "core",
                         "# discarded lower priority CORE_SEND request bytes",
                         GNUNET_TIME_UNIT_FOREVER_REL, NULL, &print_stat, &p2);

  if (ok != 0)
    kind = GNUNET_ERROR_TYPE_ERROR;
  switch (test)
  {
  case SYMMETRIC:
    GNUNET_log (kind, "Core quota compliance test with symmetric quotas: %s\n",
                (0 == ok) ? "PASSED" : "FAILED");
    break;
  case ASYMMETRIC_SEND_LIMITED:
    GNUNET_log (kind,
                "Core quota compliance test with limited sender quota: %s\n",
                (0 == ok) ? "PASSED" : "FAILED");
    break;
  case ASYMMETRIC_RECV_LIMITED:
    GNUNET_log (kind,
                "Core quota compliance test with limited receiver quota: %s\n",
                (0 == ok) ? "PASSED" : "FAILED");
    break;
  };
  GNUNET_log (kind, "Peer 1 send  rate: %llu b/s (%llu bytes in %llu ms)\n",
              throughput_out, total_bytes_sent, delta);
  GNUNET_log (kind, "Peer 1 send quota: %llu b/s\n", current_quota_p1_out);
  GNUNET_log (kind, "Peer 2 receive  rate: %llu b/s (%llu bytes in %llu ms)\n",
              throughput_in, total_bytes_recv, delta);
  GNUNET_log (kind, "Peer 2 receive quota: %llu b/s\n", current_quota_p2_in);
/*
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,"Max. inbound  quota allowed: %llu b/s\n",max_quota_in );
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,"Max. outbound quota allowed: %llu b/s\n",max_quota_out);
*/
  GNUNET_SCHEDULER_cancel (err_task);
  err_task = GNUNET_SCHEDULER_add_now (&terminate_task, NULL);

}


static size_t
transmit_ready (void *cls, size_t size, void *buf)
{
  char *cbuf = buf;
  struct TestMessage hdr;
  unsigned int ret;

  p1.nth = NULL;
  GNUNET_assert (size <= GNUNET_CONSTANTS_MAX_ENCRYPTED_MESSAGE_SIZE);
  if (buf == NULL)
  {
    if ((p1.ch != NULL) && (p1.connect_status == 1))
      GNUNET_break (NULL !=
                    (p1.nth =
                     GNUNET_CORE_notify_transmit_ready (p1.ch, GNUNET_NO,
                                                        GNUNET_CORE_PRIO_BEST_EFFORT,
                                                        FAST_TIMEOUT, &p2.id,
                                                        MESSAGESIZE,
                                                        &transmit_ready, &p1)));
    return 0;
  }
  GNUNET_assert (tr_n < TOTAL_MSGS);
  ret = 0;
  GNUNET_assert (size >= MESSAGESIZE);
  GNUNET_assert (buf != NULL);
  cbuf = buf;
  do
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Sending message %u of size %u at offset %u\n", tr_n,
                MESSAGESIZE, ret);
    hdr.header.size = htons (MESSAGESIZE);
    hdr.header.type = htons (MTYPE);
    hdr.num = htonl (tr_n);
    memcpy (&cbuf[ret], &hdr, sizeof (struct TestMessage));
    ret += sizeof (struct TestMessage);
    memset (&cbuf[ret], tr_n, MESSAGESIZE - sizeof (struct TestMessage));
    ret += MESSAGESIZE - sizeof (struct TestMessage);
    tr_n++;
    if (0 == GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK, 16))
      break;                    /* sometimes pack buffer full, sometimes not */
  }
  while (size - ret >= MESSAGESIZE);
  GNUNET_SCHEDULER_cancel (err_task);
  err_task =
      GNUNET_SCHEDULER_add_delayed (TIMEOUT, &terminate_task_error, NULL);

  total_bytes_sent += ret;
  return ret;
}



static void
connect_notify (void *cls, const struct GNUNET_PeerIdentity *peer)
{
  struct PeerContext *pc = cls;

  if (0 == memcmp (&pc->id, peer, sizeof (struct GNUNET_PeerIdentity)))
    return;                     /* loopback */
  GNUNET_assert (pc->connect_status == 0);
  pc->connect_status = 1;
  if (pc == &p1)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Encrypted connection established to peer `%4s'\n",
                GNUNET_i2s (peer));
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Asking core (1) for transmission to peer `%4s'\n",
                GNUNET_i2s (&p2.id));
    if (err_task != NULL)
      GNUNET_SCHEDULER_cancel (err_task);
    err_task =
        GNUNET_SCHEDULER_add_delayed (TIMEOUT, &terminate_task_error, NULL);
    start_time = GNUNET_TIME_absolute_get ();
    running = GNUNET_YES;
    measure_task =
        GNUNET_SCHEDULER_add_delayed (MEASUREMENT_LENGTH, &measurement_stop,
                                      NULL);

    GNUNET_break (NULL !=
                  (p1.nth =
                   GNUNET_CORE_notify_transmit_ready (p1.ch, GNUNET_NO,
                                                      GNUNET_CORE_PRIO_BEST_EFFORT,
                                                      TIMEOUT, &p2.id,
                                                      MESSAGESIZE,
                                                      &transmit_ready, &p1)));
  }
}


static void
disconnect_notify (void *cls, const struct GNUNET_PeerIdentity *peer)
{
  struct PeerContext *pc = cls;

  if (0 == memcmp (&pc->id, peer, sizeof (struct GNUNET_PeerIdentity)))
    return;                     /* loopback */
  pc->connect_status = 0;
  if (NULL != measure_task)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Measurement aborted due to disconnect!\n");
    GNUNET_SCHEDULER_cancel (measure_task);
    measure_task = NULL;
  }
  if (pc->nth != NULL)
  {
    GNUNET_CORE_notify_transmit_ready_cancel (pc->nth);
    pc->nth = NULL;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Encrypted connection to `%4s' cut\n",
              GNUNET_i2s (peer));
}


static int
inbound_notify (void *cls, const struct GNUNET_PeerIdentity *other,
                const struct GNUNET_MessageHeader *message)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Core provides inbound data from `%4s' %llu.\n",
              GNUNET_i2s (other), ntohs (message->size));
  total_bytes_recv += ntohs (message->size);
  return GNUNET_OK;
}


static int
outbound_notify (void *cls, const struct GNUNET_PeerIdentity *other,
                 const struct GNUNET_MessageHeader *message)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Core notifies about outbound data for `%4s'.\n",
              GNUNET_i2s (other));
  return GNUNET_OK;
}


static size_t
transmit_ready (void *cls, size_t size, void *buf);


static int
process_mtype (void *cls, const struct GNUNET_PeerIdentity *peer,
               const struct GNUNET_MessageHeader *message)
{
  static int n;
  const struct TestMessage *hdr;

  hdr = (const struct TestMessage *) message;
  if (MTYPE != ntohs (message->type))
    return GNUNET_SYSERR;
  if (ntohs (message->size) != MESSAGESIZE)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Expected message %u of size %u, got %u bytes of message %u\n",
                n, MESSAGESIZE, ntohs (message->size), ntohl (hdr->num));
    GNUNET_SCHEDULER_cancel (err_task);
    err_task = GNUNET_SCHEDULER_add_now (&terminate_task_error, NULL);
    return GNUNET_SYSERR;
  }
  if (ntohl (hdr->num) != n)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Expected message %u of size %u, got %u bytes of message %u\n",
                n, MESSAGESIZE, ntohs (message->size), ntohl (hdr->num));
    GNUNET_SCHEDULER_cancel (err_task);
    err_task = GNUNET_SCHEDULER_add_now (&terminate_task_error, NULL);
    return GNUNET_SYSERR;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Got message %u of size %u\n",
              ntohl (hdr->num), ntohs (message->size));
  n++;
  if (0 == (n % 10))
    FPRINTF (stderr, "%s",  ".");


  if (running == GNUNET_YES)
    GNUNET_break (NULL !=
                  GNUNET_CORE_notify_transmit_ready (p1.ch, GNUNET_NO,
                                                     GNUNET_CORE_PRIO_BEST_EFFORT,
                                                     FAST_TIMEOUT, &p2.id,
                                                     MESSAGESIZE,
                                                     &transmit_ready, &p1));
  return GNUNET_OK;
}


static struct GNUNET_CORE_MessageHandler handlers[] = {
  {&process_mtype, MTYPE, 0},
  {NULL, 0, 0}
};



static void
init_notify (void *cls,
             const struct GNUNET_PeerIdentity *my_identity)
{
  struct PeerContext *p = cls;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Connection to CORE service of `%4s' established\n",
              GNUNET_i2s (my_identity));
  GNUNET_assert (NULL != my_identity);
  p->id = *my_identity;
  if (cls == &p1)
  {
    GNUNET_assert (ok == 2);
    OKPP;
    /* connect p2 */
    p2.ch =
        GNUNET_CORE_connect (p2.cfg, &p2, &init_notify, &connect_notify,
                             &disconnect_notify, &inbound_notify, GNUNET_YES,
                             &outbound_notify, GNUNET_YES, handlers);
  }
  else
  {
    GNUNET_assert (ok == 3);
    OKPP;
    GNUNET_assert (cls == &p2);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Asking core (1) to connect to peer `%s' and vice-versa\n",
                GNUNET_i2s (&p2.id));
    p1.ats_sh = GNUNET_ATS_connectivity_suggest (p1.ats,
                                                 &p2.id,
                                                 1);
    p2.ats_sh = GNUNET_ATS_connectivity_suggest (p2.ats,
                                                 &p1.id,
                                                 1);
  }
}


static void
process_hello (void *cls, const struct GNUNET_MessageHeader *message)
{
  struct PeerContext *p = cls;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received (my) `%s' from transport service\n", "HELLO");
  GNUNET_assert (message != NULL);
  p->hello = GNUNET_malloc (ntohs (message->size));
  memcpy (p->hello, message, ntohs (message->size));
  if ((p == &p1) && (p2.th != NULL))
    GNUNET_TRANSPORT_offer_hello (p2.th, message, NULL, NULL);
  if ((p == &p2) && (p1.th != NULL))
    GNUNET_TRANSPORT_offer_hello (p1.th, message, NULL, NULL);

  if ((p == &p1) && (p2.hello != NULL))
    GNUNET_TRANSPORT_offer_hello (p1.th, p2.hello, NULL, NULL);
  if ((p == &p2) && (p1.hello != NULL))
    GNUNET_TRANSPORT_offer_hello (p2.th, p1.hello, NULL, NULL);
}



static void
setup_peer (struct PeerContext *p, const char *cfgname)
{
  char *binary;

  binary = GNUNET_OS_get_libexec_binary_path ("gnunet-service-arm");
  p->cfg = GNUNET_CONFIGURATION_create ();
  p->arm_proc =
    GNUNET_OS_start_process (GNUNET_YES, GNUNET_OS_INHERIT_STD_OUT_AND_ERR,
                             NULL, NULL, NULL,
                             binary,
                             "gnunet-service-arm",
                             "-c", cfgname, NULL);
  GNUNET_assert (GNUNET_OK == GNUNET_CONFIGURATION_load (p->cfg, cfgname));
  p->stats = GNUNET_STATISTICS_create ("core", p->cfg);
  GNUNET_assert (p->stats != NULL);
  p->th = GNUNET_TRANSPORT_connect (p->cfg, NULL, p, NULL, NULL, NULL);
  GNUNET_assert (p->th != NULL);
  p->ats = GNUNET_ATS_connectivity_init (p->cfg);
  GNUNET_assert (NULL != p->ats);
  p->ghh = GNUNET_TRANSPORT_get_hello (p->th, &process_hello, p);
  GNUNET_free (binary);
}


static void
run (void *cls, char *const *args, const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  GNUNET_assert (ok == 1);
  OKPP;
  err_task =
      GNUNET_SCHEDULER_add_delayed (TIMEOUT, &terminate_task_error, NULL);
  if (test == SYMMETRIC)
  {
    setup_peer (&p1, "test_core_quota_peer1.conf");
    setup_peer (&p2, "test_core_quota_peer2.conf");
  }
  else if (test == ASYMMETRIC_SEND_LIMITED)
  {
    setup_peer (&p1, "test_core_quota_asymmetric_send_limit_peer1.conf");
    setup_peer (&p2, "test_core_quota_asymmetric_send_limit_peer2.conf");
  }
  else if (test == ASYMMETRIC_RECV_LIMITED)
  {
    setup_peer (&p1, "test_core_quota_asymmetric_recv_limited_peer1.conf");
    setup_peer (&p2, "test_core_quota_asymmetric_recv_limited_peer2.conf");
  }

  GNUNET_assert (test != -1);
  GNUNET_assert (GNUNET_SYSERR !=
                 GNUNET_CONFIGURATION_get_value_size (p1.cfg, "ATS",
                                                      "WAN_QUOTA_IN",
                                                      &current_quota_p1_in));
  GNUNET_assert (GNUNET_SYSERR !=
                 GNUNET_CONFIGURATION_get_value_size (p2.cfg, "ATS",
                                                      "WAN_QUOTA_IN",
                                                      &current_quota_p2_in));
  GNUNET_assert (GNUNET_SYSERR !=
                 GNUNET_CONFIGURATION_get_value_size (p1.cfg, "ATS",
                                                      "WAN_QUOTA_OUT",
                                                      &current_quota_p1_out));
  GNUNET_assert (GNUNET_SYSERR !=
                 GNUNET_CONFIGURATION_get_value_size (p2.cfg, "ATS",
                                                      "WAN_QUOTA_OUT",
                                                      &current_quota_p2_out));

  p1.ch =
      GNUNET_CORE_connect (p1.cfg, &p1, &init_notify, &connect_notify,
                           &disconnect_notify, &inbound_notify, GNUNET_YES,
                           &outbound_notify, GNUNET_YES, handlers);
}


static void
stop_arm (struct PeerContext *p)
{
  if (0 != GNUNET_OS_process_kill (p->arm_proc, GNUNET_TERM_SIG))
    GNUNET_log_strerror (GNUNET_ERROR_TYPE_WARNING, "kill");
  if (GNUNET_OS_process_wait (p->arm_proc) != GNUNET_OK)
    GNUNET_log_strerror (GNUNET_ERROR_TYPE_WARNING, "waitpid");
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "ARM process %u stopped\n",
              GNUNET_OS_process_get_pid (p->arm_proc));
  GNUNET_OS_process_destroy (p->arm_proc);
  p->arm_proc = NULL;
  GNUNET_CONFIGURATION_destroy (p->cfg);
}


static int
check ()
{
  char *const argv[] = { "test-core-quota-compliance",
    "-c",
    "test_core_api_data.conf",
    NULL
  };
  struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_OPTION_END
  };
  ok = 1;
  GNUNET_PROGRAM_run ((sizeof (argv) / sizeof (char *)) - 1, argv,
                      "test-core-quota-compliance", "nohelp", options, &run,
                      &ok);
  stop_arm (&p1);
  stop_arm (&p2);
  return ok;
}


int
main (int argc, char *argv[])
{
  int ret;

  test = -1;
  if (strstr (argv[0], "_symmetric") != NULL)
  {
    test = SYMMETRIC;
  }
  else if (strstr (argv[0], "_asymmetric_send") != NULL)
  {
    test = ASYMMETRIC_SEND_LIMITED;
  }
  else if (strstr (argv[0], "_asymmetric_recv") != NULL)
  {
    test = ASYMMETRIC_RECV_LIMITED;
  }
  GNUNET_assert (test != -1);
  if (test == SYMMETRIC)
  {
    GNUNET_DISK_directory_remove ("/tmp/test-gnunet-core-quota-sym-peer-1/");
    GNUNET_DISK_directory_remove ("/tmp/test-gnunet-core-quota-sym-peer-2/");
  }
  else if (test == ASYMMETRIC_SEND_LIMITED)
  {
    GNUNET_DISK_directory_remove
        ("/tmp/test-gnunet-core-quota-asym-send-lim-peer-1/");
    GNUNET_DISK_directory_remove
        ("/tmp/test-gnunet-core-quota-asym-send-lim-peer-2/");
  }
  else if (test == ASYMMETRIC_RECV_LIMITED)
  {
    GNUNET_DISK_directory_remove
        ("/tmp/test-gnunet-core-quota-asym-recv-lim-peer-1/");
    GNUNET_DISK_directory_remove
        ("/tmp/test-gnunet-core-quota-asym-recv-lim-peer-2/");
  }

  GNUNET_log_setup ("test-core-quota-compliance",
                    "WARNING",
                    NULL);
  ret = check ();
  if (test == SYMMETRIC)
  {
    GNUNET_DISK_directory_remove ("/tmp/test-gnunet-core-quota-sym-peer-1/");
    GNUNET_DISK_directory_remove ("/tmp/test-gnunet-core-quota-sym-peer-2/");
  }
  else if (test == ASYMMETRIC_SEND_LIMITED)
  {
    GNUNET_DISK_directory_remove
        ("/tmp/test-gnunet-core-quota-asym-send-lim-peer-1/");
    GNUNET_DISK_directory_remove
        ("/tmp/test-gnunet-core-quota-asym-send-lim-peer-2/");
  }
  else if (test == ASYMMETRIC_RECV_LIMITED)
  {
    GNUNET_DISK_directory_remove
        ("/tmp/test-gnunet-core-quota-asym-recv-lim-peer-1/");
    GNUNET_DISK_directory_remove
        ("/tmp/test-gnunet-core-quota-asym-recv-lim-peer-2/");
  }
  return ret;
}

/* end of test_core_quota_compliance.c */

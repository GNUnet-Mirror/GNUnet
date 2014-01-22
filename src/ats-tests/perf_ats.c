/*
 This file is part of GNUnet.
 (C) 2010-2013 Christian Grothoff (and other contributing authors)

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
 * @file ats/perf_ats.c
 * @brief ats benchmark: start peers and modify preferences, monitor change over time
 * @author Christian Grothoff
 * @author Matthias Wachs
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_testbed_service.h"
#include "gnunet_ats_service.h"
#include "gnunet_core_service.h"
#include "ats-testing.h"


#define TEST_ATS_PREFRENCE_FREQUENCY GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 1)
#define TEST_ATS_PREFRENCE_START 1.0
#define TEST_ATS_PREFRENCE_DELTA 1.0

#define TEST_MESSAGE_TYPE_PING 12345
#define TEST_MESSAGE_TYPE_PONG 12346
#define TEST_MESSAGE_SIZE 1000
#define TEST_MESSAGE_FREQUENCY GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 1)

#define TEST_TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 120)
#define BENCHMARK_DURATION GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 10)
#define LOGGING_FREQUENCY GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MILLISECONDS, 500)
#define TESTNAME_PREFIX "perf_ats_"
#define DEFAULT_SLAVES_NUM 2
#define DEFAULT_MASTERS_NUM 1
/**
 * Shutdown task
 */
static GNUNET_SCHEDULER_TaskIdentifier shutdown_task;

/**
 * Progress task
 */
static GNUNET_SCHEDULER_TaskIdentifier progress_task;

/**
 * Test result
 */
static int result;

/**
 * Test result logging
 */
static int logging;

/**Test core (GNUNET_YES) or transport (GNUNET_NO)
 */
static int test_core;

/**
 * Solver string
 */
static char *solver;

/**
 * Preference string
 */
static char *testname;

/**
 * Preference string
 */
static char *pref_str;

/**
 * ATS preference value
 */
static int pref_val;

/**
 * Benchmark duration
 */
static struct GNUNET_TIME_Relative perf_duration;

/**
 * Logging frequency
 */
static struct GNUNET_TIME_Relative log_frequency;

/**
 * Number master peers
 */
static unsigned int num_masters;

/**
 * Array of master peers
 */
static struct BenchmarkPeer *mps;

/**
 * Number slave peers
 */
static unsigned int num_slaves;

/**
 * Array of master peers
 */
static struct BenchmarkPeer *sps;

static void
evaluate ()
{
  int c_m;
  int c_s;
  unsigned int duration;
  struct BenchmarkPeer *mp;
  struct BenchmarkPartner *p;

  unsigned int kb_sent_sec;
  double kb_sent_percent;
  unsigned int kb_recv_sec;
  double kb_recv_percent;
  unsigned int rtt;

  duration = (perf_duration.rel_value_us / (1000 * 1000));
  for (c_m = 0; c_m < num_masters; c_m++)
  {
    mp = &mps[c_m];
    fprintf (stderr,
        _("Master [%u]: sent: %u KiB in %u sec. = %u KiB/s, received: %u KiB in %u sec. = %u KiB/s\n"),
        mp->no, mp->total_bytes_sent / 1024, duration,
        (mp->total_bytes_sent / 1024) / duration,
        mp->total_bytes_received / 1024, duration,
        (mp->total_bytes_received / 1024) / duration);

    for (c_s = 0; c_s < num_slaves; c_s++)
    {
      p = &mp->partners[c_s];

      fprintf (stderr , "%u  %u %u\n", p->bytes_sent, (p->bytes_sent / 1024) / duration, duration);
      fprintf (stderr , "%u %u %u \n", p->bytes_received, (p->bytes_sent / 1024) / duration, duration);

      kb_sent_sec = 0;
      kb_recv_sec = 0;
      kb_sent_percent = 0.0;
      kb_recv_percent = 0.0;
      rtt = 0;

      if (duration > 0)
      {
    	  kb_sent_sec = (p->bytes_sent / 1024) / duration;
    	  kb_recv_sec = (p->bytes_received / 1024) / duration;
      }

      if (mp->total_bytes_sent > 0)
    	  kb_sent_percent = ((double) p->bytes_sent * 100) / mp->total_bytes_sent;
      if (mp->total_bytes_received > 0)
    	  kb_recv_percent = ((double) p->bytes_received * 100) / mp->total_bytes_received;
      if (1000 * p->messages_sent > 0)
    	  rtt = p->total_app_rtt / (1000 * p->messages_sent);



      fprintf (stderr,
          "%c Master [%u] -> Slave [%u]: sent %u KiB/s (%.2f %%), received %u KiB/s (%.2f %%)\n",
          (mp->pref_partner == p->dest) ? '*' : ' ',
          mp->no, p->dest->no,
          kb_sent_sec, kb_sent_percent,
		  kb_recv_sec, kb_recv_percent);

      fprintf (stderr,
          "%c Master [%u] -> Slave [%u]: Average application layer RTT: %u ms\n",
          (mp->pref_partner == p->dest) ? '*' : ' ',
          mp->no, p->dest->no, rtt);
    }
  }
}

/**
 * Shutdown nicely
 *
 * @param cls NULL
 * @param tc the task context
 */
static void
do_shutdown (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{

  if (GNUNET_YES == logging)
    GNUNET_ATS_TEST_logging_stop();

  shutdown_task = GNUNET_SCHEDULER_NO_TASK;
  if (GNUNET_SCHEDULER_NO_TASK != progress_task)
  {
    fprintf (stderr, "0\n");
    GNUNET_SCHEDULER_cancel (progress_task);
  }
  progress_task = GNUNET_SCHEDULER_NO_TASK;

  evaluate ();
  GNUNET_log(GNUNET_ERROR_TYPE_INFO, _("Benchmarking done\n"));

  GNUNET_ATS_TEST_shutdown_topology();
}

static size_t
comm_send_ready (void *cls, size_t size, void *buf)
{
  static char msgbuf[TEST_MESSAGE_SIZE];
  struct BenchmarkPartner *p = cls;
  struct GNUNET_MessageHeader *msg;

  if (GNUNET_YES == test_core)
    p->cth = NULL;
  else
    p->tth = NULL;

  if (NULL == buf)
  {
    GNUNET_break (0);
    return 0;
  }
  if (size < TEST_MESSAGE_SIZE)
  {
    GNUNET_break (0);
    return 0;
  }

  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "Master [%u]: Sending PING to [%u]\n",
      p->me->no, p->dest->no);

  p->messages_sent++;
  p->bytes_sent += TEST_MESSAGE_SIZE;
  p->me->total_messages_sent++;
  p->me->total_bytes_sent += TEST_MESSAGE_SIZE;

  msg = (struct GNUNET_MessageHeader *) &msgbuf;
  memset (&msgbuf, 'a', TEST_MESSAGE_SIZE);
  msg->type = htons (TEST_MESSAGE_TYPE_PING);
  msg->size = htons (TEST_MESSAGE_SIZE);
  memcpy (buf, msg, TEST_MESSAGE_SIZE);
  return TEST_MESSAGE_SIZE;
}

static void
comm_schedule_send (struct BenchmarkPartner *p)
{
  p->last_message_sent = GNUNET_TIME_absolute_get();
  if (GNUNET_YES == test_core)
  {
    p->cth = GNUNET_CORE_notify_transmit_ready (
      p->me->ch, GNUNET_NO, 0, GNUNET_TIME_UNIT_MINUTES, &p->dest->id,
      TEST_MESSAGE_SIZE, &comm_send_ready, p);
  }
  else
  {
    p->tth = GNUNET_TRANSPORT_notify_transmit_ready (
      p->me->th, &p->dest->id, TEST_MESSAGE_SIZE, 0,GNUNET_TIME_UNIT_MINUTES,
      &comm_send_ready, p);
  }

}

static void
print_progress ()
{
  static int calls;
  progress_task = GNUNET_SCHEDULER_NO_TASK;

  fprintf (stderr, "%llu..",
      (long long unsigned) perf_duration.rel_value_us / (1000 * 1000) - calls);
  calls++;

  progress_task = GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_SECONDS,
      &print_progress, NULL );
}

static void
ats_pref_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct BenchmarkPeer *me = cls;

  me->ats_task = GNUNET_SCHEDULER_NO_TASK;

  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, " Master [%u] set preference for slave [%u] to %f\n",
      me->no, me->pref_partner->no, me->pref_value);
  GNUNET_ATS_performance_change_preference (me->ats_perf_handle,
      &me->pref_partner->id,
      pref_val, me->pref_value, GNUNET_ATS_PREFERENCE_END);
  me->pref_value += TEST_ATS_PREFRENCE_DELTA;
  me->ats_task = GNUNET_SCHEDULER_add_delayed (TEST_ATS_PREFRENCE_FREQUENCY,
      &ats_pref_task, cls);
}

static void
do_benchmark (void *cls, struct BenchmarkPeer *masters, struct BenchmarkPeer *slaves)
{
  int c_m;
  int c_s;

  mps = masters;
  sps = slaves;

  GNUNET_log(GNUNET_ERROR_TYPE_INFO, _("Benchmarking start\n"));

  if (GNUNET_SCHEDULER_NO_TASK != shutdown_task)
    GNUNET_SCHEDULER_cancel (shutdown_task);
  shutdown_task = GNUNET_SCHEDULER_add_delayed (perf_duration,
      &do_shutdown, NULL );

  progress_task = GNUNET_SCHEDULER_add_now (&print_progress, NULL );

  GNUNET_log(GNUNET_ERROR_TYPE_INFO, "Topology connected, start benchmarking...\n");

  /* Start sending test messages */
  for (c_m = 0; c_m < num_masters; c_m++)
  {
    for (c_s = 0; c_s < num_slaves; c_s++)
      comm_schedule_send (&masters[c_m].partners[c_s]);
    if (pref_val != GNUNET_ATS_PREFERENCE_END)
      masters[c_m].ats_task = GNUNET_SCHEDULER_add_now (&ats_pref_task, &masters[c_m]);
  }

  if (GNUNET_YES == logging)
    GNUNET_ATS_TEST_logging_start (log_frequency, testname, mps, num_masters);
}


static size_t
comm_send_pong_ready (void *cls, size_t size, void *buf)
{
  static char msgbuf[TEST_MESSAGE_SIZE];
  struct BenchmarkPartner *p = cls;
  struct GNUNET_MessageHeader *msg;

  if (GNUNET_YES == test_core)
    p->cth = NULL;
  else
    p->tth = NULL;

  p->messages_sent++;
  p->bytes_sent += TEST_MESSAGE_SIZE;
  p->me->total_messages_sent++;
  p->me->total_bytes_sent += TEST_MESSAGE_SIZE;

  msg = (struct GNUNET_MessageHeader *) &msgbuf;
  memset (&msgbuf, 'a', TEST_MESSAGE_SIZE);
  msg->type = htons (TEST_MESSAGE_TYPE_PONG);
  msg->size = htons (TEST_MESSAGE_SIZE);
  memcpy (buf, msg, TEST_MESSAGE_SIZE);

  return TEST_MESSAGE_SIZE;
}

static struct BenchmarkPartner *
find_partner (struct BenchmarkPeer *me, const struct GNUNET_PeerIdentity * peer)
{
  int c_m;
  GNUNET_assert (NULL != me);
  GNUNET_assert (NULL != peer);

  for (c_m = 0; c_m < me->num_partners; c_m++)
  {
    /* Find a partner with other as destination */
    if (0 == memcmp (peer, &me->partners[c_m].dest->id,
            sizeof(struct GNUNET_PeerIdentity)))
    {
      return &me->partners[c_m];
    }
  }
  return NULL;
}

static int
comm_handle_ping (void *cls, const struct GNUNET_PeerIdentity *other,
    const struct GNUNET_MessageHeader *message)
{

  struct BenchmarkPeer *me = cls;
  struct BenchmarkPartner *p = NULL;

  if (NULL == (p = find_partner(me, other)))
  {
    GNUNET_break(0);
    return GNUNET_SYSERR;
  }

  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
      "Slave [%u]: Received PING from [%u], sending PONG\n", me->no,
      p->dest->no);

  p->messages_received++;
  p->bytes_received += TEST_MESSAGE_SIZE;
  p->me->total_messages_received++;
  p->me->total_bytes_received += TEST_MESSAGE_SIZE;

  if (GNUNET_YES == test_core)
  {
    GNUNET_assert (NULL == p->cth);
    p->cth = GNUNET_CORE_notify_transmit_ready (me->ch, GNUNET_NO, 0,
        GNUNET_TIME_UNIT_MINUTES, &p->dest->id, TEST_MESSAGE_SIZE,
        &comm_send_pong_ready, p);
  }
  else
  {
    GNUNET_assert (NULL == p->tth);
    p->tth = GNUNET_TRANSPORT_notify_transmit_ready (me->th, &p->dest->id,
        TEST_MESSAGE_SIZE, 0, GNUNET_TIME_UNIT_MINUTES, &comm_send_pong_ready,
        p);
  }
  return GNUNET_OK;
}

static int
comm_handle_pong (void *cls, const struct GNUNET_PeerIdentity *other,
    const struct GNUNET_MessageHeader *message)
{
  struct BenchmarkPeer *me = cls;
  struct BenchmarkPartner *p = NULL;

  if (NULL == (p = find_partner (me, other)))
  {
    GNUNET_break(0);
    return GNUNET_SYSERR;
  }

  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
      "Master [%u]: Received PONG from [%u], next message\n", me->no,
      p->dest->no);

  p->messages_received++;
  p->bytes_received += TEST_MESSAGE_SIZE;
  p->me->total_messages_received++;
  p->me->total_bytes_received += TEST_MESSAGE_SIZE;
  p->total_app_rtt += GNUNET_TIME_absolute_get_difference(p->last_message_sent,
      GNUNET_TIME_absolute_get()).rel_value_us;

  comm_schedule_send (p);
  return GNUNET_OK;
}


static void
test_recv_cb (void *cls,
		      const struct GNUNET_PeerIdentity * peer,
		      const struct GNUNET_MessageHeader * message)
{
  if (TEST_MESSAGE_SIZE != ntohs (message->size) ||
      (TEST_MESSAGE_TYPE_PING != ntohs (message->type) &&
      TEST_MESSAGE_TYPE_PONG != ntohs (message->type)))
  {
    return;
  }
  if (TEST_MESSAGE_TYPE_PING == ntohs (message->type))
    comm_handle_ping (cls, peer, message);

  if (TEST_MESSAGE_TYPE_PONG == ntohs (message->type))
    comm_handle_pong (cls, peer, message);
}


static void
ats_performance_info_cb (void *cls, const struct GNUNET_HELLO_Address *address,
    int address_active, struct GNUNET_BANDWIDTH_Value32NBO bandwidth_out,
    struct GNUNET_BANDWIDTH_Value32NBO bandwidth_in,
    const struct GNUNET_ATS_Information *ats, uint32_t ats_count)
{
  struct BenchmarkPeer *me = cls;
  struct BenchmarkPartner *p;
  int c_a;
  int log;
  char *peer_id;

  p = find_partner (me, &address->peer);
  if (NULL == p)
  {
    /* This is not one of my partners
     * Will happen since the peers will connect to each other due to gossiping
     */
    return;
  }
  peer_id = GNUNET_strdup (GNUNET_i2s (&me->id));

  log = GNUNET_NO;
  if ((p->bandwidth_in != ntohl (bandwidth_in.value__)) ||
      (p->bandwidth_out != ntohl (bandwidth_out.value__)))
      log = GNUNET_YES;
  p->bandwidth_in = ntohl (bandwidth_in.value__);
  p->bandwidth_out = ntohl (bandwidth_out.value__);

  for (c_a = 0; c_a < ats_count; c_a++)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "%s [%u] received ATS information: %s %s %u\n",
        (GNUNET_YES == p->me->master) ? "Master" : "Slave",
        p->me->no,
        GNUNET_i2s (&p->dest->id),
        GNUNET_ATS_print_property_type(ntohl(ats[c_a].type)),
        ntohl(ats[c_a].value));
    switch (ntohl (ats[c_a].type ))
    {
      case GNUNET_ATS_ARRAY_TERMINATOR:
        break;
      case GNUNET_ATS_UTILIZATION_OUT:
        if (p->ats_utilization_up != ntohl (ats[c_a].value))
            log = GNUNET_YES;
        p->ats_utilization_up = ntohl (ats[c_a].value);

        break;
      case GNUNET_ATS_UTILIZATION_IN:
        if (p->ats_utilization_down != ntohl (ats[c_a].value))
            log = GNUNET_YES;
        p->ats_utilization_down = ntohl (ats[c_a].value);
        break;
      case GNUNET_ATS_NETWORK_TYPE:
        if (p->ats_network_type != ntohl (ats[c_a].value))
            log = GNUNET_YES;
        p->ats_network_type = ntohl (ats[c_a].value);
        break;
      case GNUNET_ATS_QUALITY_NET_DELAY:
        if (p->ats_delay != ntohl (ats[c_a].value))
            log = GNUNET_YES;
        p->ats_delay = ntohl (ats[c_a].value);
        break;
      case GNUNET_ATS_QUALITY_NET_DISTANCE:
        if (p->ats_distance != ntohl (ats[c_a].value))
            log = GNUNET_YES;
        p->ats_distance = ntohl (ats[c_a].value);
        GNUNET_break (0);
        break;
      case GNUNET_ATS_COST_WAN:
        if (p->ats_cost_wan != ntohl (ats[c_a].value))
            log = GNUNET_YES;
        p->ats_cost_wan = ntohl (ats[c_a].value);
        break;
      case GNUNET_ATS_COST_LAN:
        if (p->ats_cost_lan != ntohl (ats[c_a].value))
            log = GNUNET_YES;
        p->ats_cost_lan = ntohl (ats[c_a].value);
        break;
      case GNUNET_ATS_COST_WLAN:
        if (p->ats_cost_wlan != ntohl (ats[c_a].value))
            log = GNUNET_YES;
        p->ats_cost_wlan = ntohl (ats[c_a].value);
        break;
      default:
        break;
    }
  }

  if ((GNUNET_YES == logging) && (GNUNET_YES == log))
    GNUNET_ATS_TEST_logging_now();

  GNUNET_free(peer_id);
}


/*
 * Start the performance test case
 */
int
main (int argc, char *argv[])
{
  char *tmp;
  char *tmp_sep;
  char *test_name;
  char *conf_name;
  char *comm_name;
  char *dotexe;
  char *prefs[GNUNET_ATS_PreferenceCount] = GNUNET_ATS_PreferenceTypeString;
  int c;

  result = 0;

  /* figure out testname */
  tmp = strstr (argv[0], TESTNAME_PREFIX);
  if (NULL == tmp)
  {
    fprintf (stderr, "Unable to parse test name `%s'\n", argv[0]);
    return GNUNET_SYSERR;
  }
  tmp += strlen (TESTNAME_PREFIX);
  solver = GNUNET_strdup (tmp);
  if (NULL != (dotexe = strstr (solver, ".exe")) && dotexe[4] == '\0')
    dotexe[0] = '\0';
  tmp_sep = strchr (solver, '_');
  if (NULL == tmp_sep)
  {
    fprintf (stderr, "Unable to parse test name `%s'\n", argv[0]);
    GNUNET_free(solver);
    return GNUNET_SYSERR;
  }
  tmp_sep[0] = '\0';
  comm_name = GNUNET_strdup (&tmp_sep[1]);
  tmp_sep = strchr (comm_name, '_');
  if (NULL == tmp_sep)
  {
    fprintf (stderr, "Unable to parse test name `%s'\n", argv[0]);
    GNUNET_free(solver);
    return GNUNET_SYSERR;
  }
  tmp_sep[0] = '\0';
  for (c = 0; c <= strlen (comm_name); c++)
    comm_name[c] = toupper (comm_name[c]);
  if (0 == strcmp (comm_name, "CORE"))
    test_core = GNUNET_YES;
  else if (0 == strcmp (comm_name, "TRANSPORT"))
    test_core = GNUNET_NO;
  else
  {
    GNUNET_free (comm_name);
    GNUNET_free (solver);
    return GNUNET_SYSERR;
  }

  pref_str = GNUNET_strdup(tmp_sep + 1);

  GNUNET_asprintf (&conf_name, "%s%s_%s.conf", TESTNAME_PREFIX, solver,
      pref_str);
  GNUNET_asprintf (&test_name, "%s%s_%s", TESTNAME_PREFIX, solver, pref_str);

  for (c = 0; c <= strlen (pref_str); c++)
    pref_str[c] = toupper (pref_str[c]);
  pref_val = -1;

  if (0 != strcmp (pref_str, "NONE"))
  {
    for (c = 1; c < GNUNET_ATS_PreferenceCount; c++)
    {
      if (0 == strcmp (pref_str, prefs[c]))
      {
        pref_val = c;
        break;
      }
    }
  }
  else
  {
    /* abuse terminator to indicate no pref */
    pref_val = GNUNET_ATS_PREFERENCE_END;
  }
  if (-1 == pref_val)
  {
    fprintf (stderr, "Unknown preference: `%s'\n", pref_str);
    GNUNET_free(solver);
    GNUNET_free(pref_str);
    GNUNET_free (comm_name);
    return -1;
  }

  for (c = 0; c < (argc - 1); c++)
  {
    if (0 == strcmp (argv[c], "-d"))
      break;
  }
  if (c < argc - 1)
  {
    if (GNUNET_OK != GNUNET_STRINGS_fancy_time_to_relative (argv[c + 1], &perf_duration))
        fprintf (stderr, "Failed to parse duration `%s'\n", argv[c + 1]);
  }
  else
  {
    perf_duration = BENCHMARK_DURATION;
  }
  fprintf (stderr, "Running benchmark for %llu secs\n", (unsigned long long) (perf_duration.rel_value_us) / (1000 * 1000));

  for (c = 0; c < (argc - 1); c++)
  {
    if (0 == strcmp (argv[c], "-s"))
      break;
  }
  if (c < argc - 1)
  {
    if ((0L != (num_slaves = strtol (argv[c + 1], NULL, 10)))
        && (num_slaves >= 1))
      fprintf (stderr, "Starting %u slave peers\n", num_slaves);
    else
      num_slaves = DEFAULT_SLAVES_NUM;
  }
  else
    num_slaves = DEFAULT_SLAVES_NUM;

  for (c = 0; c < (argc - 1); c++)
  {
    if (0 == strcmp (argv[c], "-m"))
      break;
  }
  if (c < argc - 1)
  {
    if ((0L != (num_masters = strtol (argv[c + 1], NULL, 10)))
        && (num_masters >= 2))
      fprintf (stderr, "Starting %u master peers\n", num_masters);
    else
      num_masters = DEFAULT_MASTERS_NUM;
  }
  else
    num_masters = DEFAULT_MASTERS_NUM;

  logging = GNUNET_NO;
  for (c = 0; c < argc; c++)
  {
    if (0 == strcmp (argv[c], "-l"))
      logging = GNUNET_YES;
  }

  if (GNUNET_YES == logging)
  {
    for (c = 0; c < (argc - 1); c++)
    {
      if (0 == strcmp (argv[c], "-f"))
        break;
    }
    if (c < argc - 1)
    {
      if (GNUNET_OK != GNUNET_STRINGS_fancy_time_to_relative (argv[c + 1], &log_frequency))
          fprintf (stderr, "Failed to parse duration `%s'\n", argv[c + 1]);
    }
    else
    {
      log_frequency = LOGGING_FREQUENCY;
    }
    fprintf (stderr, "Using log frequency %llu ms\n",
        (unsigned long long) (log_frequency.rel_value_us) / (1000));
  }

  GNUNET_asprintf (&testname, "%s_%s_%s",solver, comm_name, pref_str);

  if (num_slaves < num_masters)
  {
    fprintf (stderr, "Number of master peers is lower than slaves! exit...\n");
    GNUNET_free(test_name);
    GNUNET_free(solver);
    GNUNET_free(pref_str);
    GNUNET_free (comm_name);
    return GNUNET_SYSERR;
  }

  /**
   * Core message handler to use for PING/PONG messages
   */
  static struct GNUNET_CORE_MessageHandler handlers[] = {
      {&comm_handle_ping, TEST_MESSAGE_TYPE_PING, 0 },
      {&comm_handle_pong, TEST_MESSAGE_TYPE_PONG, 0 },
      { NULL, 0, 0 } };

  /**
   * Setup the topology
   */
  GNUNET_ATS_TEST_create_topology ("perf-ats", conf_name,
      num_slaves, num_masters,
      test_core,
      &do_benchmark,
      NULL, handlers,
      &test_recv_cb,
      &ats_performance_info_cb);

  return result;
}

/* end of file perf_ats.c */

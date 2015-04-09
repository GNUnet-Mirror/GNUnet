/*
 This file is part of GNUnet.
 Copyright (C) 2010-2013 Christian Grothoff (and other contributing authors)

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
static struct GNUNET_SCHEDULER_Task * shutdown_task;

/**
 * Progress task
 */
static struct GNUNET_SCHEDULER_Task * progress_task;

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

static struct LoggingHandle *l;

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
    GNUNET_ATS_TEST_logging_clean_up(l);

  shutdown_task = NULL;
  if (NULL != progress_task)
  {
    fprintf (stderr, "0\n");
    GNUNET_SCHEDULER_cancel (progress_task);
  }
  progress_task = NULL;

  evaluate ();
  GNUNET_log(GNUNET_ERROR_TYPE_INFO, _("Benchmarking done\n"));

  GNUNET_ATS_TEST_shutdown_topology();
}


static void
print_progress ()
{
  static int calls;
  progress_task = NULL;

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

  me->ats_task = NULL;

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
start_benchmark()
{
  int c_m;
  int c_s;

  GNUNET_log(GNUNET_ERROR_TYPE_INFO, _("Benchmarking start\n"));

  if (NULL != shutdown_task)
    GNUNET_SCHEDULER_cancel(shutdown_task);
  shutdown_task = GNUNET_SCHEDULER_add_delayed(perf_duration, &do_shutdown,
      NULL );

  progress_task = GNUNET_SCHEDULER_add_now(&print_progress, NULL );

  GNUNET_log(GNUNET_ERROR_TYPE_INFO,
      "Topology connected, start benchmarking...\n");

  /* Start sending test messages */
  for (c_m = 0; c_m < num_masters; c_m++)
    {
      for (c_s = 0; c_s < num_slaves; c_s++)
      {
        GNUNET_ATS_TEST_generate_traffic_start (&mps[c_m], &mps[c_m].partners[c_s],
            GNUNET_ATS_TEST_TG_LINEAR, UINT32_MAX, UINT32_MAX,
            GNUNET_TIME_UNIT_MINUTES, GNUNET_TIME_UNIT_FOREVER_REL);
      }
      if (pref_val != GNUNET_ATS_PREFERENCE_END)
        mps[c_m].ats_task = GNUNET_SCHEDULER_add_now(&ats_pref_task, &mps[c_m]);
    }

  if (GNUNET_YES == logging)
    l = GNUNET_ATS_TEST_logging_start (log_frequency, testname, mps,
        num_masters, num_slaves, GNUNET_NO);
}

static void
do_benchmark (void *cls, struct BenchmarkPeer *masters, struct BenchmarkPeer *slaves)
{
  mps = masters;
  sps = slaves;

  GNUNET_SCHEDULER_add_now(&start_benchmark, NULL);
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

static void
test_recv_cb (void *cls,
		      const struct GNUNET_PeerIdentity * peer,
		      const struct GNUNET_MessageHeader * message)
{

}


static void
log_request_cb (void *cls, const struct GNUNET_HELLO_Address *address,
    int address_active, struct GNUNET_BANDWIDTH_Value32NBO bandwidth_out,
    struct GNUNET_BANDWIDTH_Value32NBO bandwidth_in,
    const struct GNUNET_ATS_Properties *ats)
{
  struct BenchmarkPeer *me = cls;
  struct BenchmarkPartner *p;
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

  if ((p->bandwidth_in != ntohl (bandwidth_in.value__)) ||
      (p->bandwidth_out != ntohl (bandwidth_out.value__)))
  p->bandwidth_in = ntohl (bandwidth_in.value__);
  p->bandwidth_out = ntohl (bandwidth_out.value__);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "%s [%u] received ATS information for peers `%s'\n",
      (GNUNET_YES == p->me->master) ? "Master" : "Slave",
          p->me->no,
          GNUNET_i2s (&p->dest->id));

  GNUNET_free(peer_id);
  if (NULL != l)
    GNUNET_ATS_TEST_logging_now (l);
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

  /* Determine testname
   * perf_ats_<solver>_<transport>_<preference>[.exe]*/

  /* Find test prefix, store in temp */
  tmp = strstr (argv[0], TESTNAME_PREFIX);
  if (NULL == tmp)
  {
    fprintf (stderr, "Unable to parse test name `%s'\n", argv[0]);
    return GNUNET_SYSERR;
  }

  /* Set tmp to end of test name prefix */
  tmp += strlen (TESTNAME_PREFIX);

  /* Determine solver name */
  solver = GNUNET_strdup (tmp);
  /* Remove .exe prefix */
  if (NULL != (dotexe = strstr (solver, ".exe")) && dotexe[4] == '\0')
    dotexe[0] = '\0';

  /* Determine first '_' after solver */
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
   * Setup the topology
   */
  GNUNET_ATS_TEST_create_topology ("perf-ats", conf_name,
      num_slaves, num_masters,
      test_core,
      &do_benchmark,
      NULL,
      &test_recv_cb,
      &log_request_cb);

  return result;
}

/* end of file perf_ats.c */

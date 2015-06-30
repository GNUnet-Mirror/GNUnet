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
 Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 Boston, MA 02110-1301, USA.
 */
/**
 * @file ats-tests/gnunet-ats-sim.c
 * @brief ats traffic simulator: this tool uses the ats-test library to setup a
 * topology and generate traffic between these peers. The traffic description
 * is loaded from a experiment description file
 * @author Christian Grothoff
 * @author Matthias Wachs
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_testbed_service.h"
#include "gnunet_ats_service.h"
#include "gnunet_core_service.h"
#include "ats-testing.h"

#define TEST_TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 10)

static struct BenchmarkPeer *masters_p;
static struct BenchmarkPeer *slaves_p;

/**
 * cmd option -e: experiment file
 */
static char *opt_exp_file;

/**
 * cmd option -l: enable logging
 */
static int opt_log;

/**
 * cmd option -p: enable plots
 */
static int opt_plot;

/**
 * cmd option -v: verbose logs
 */
static int opt_verbose;

struct GNUNET_SCHEDULER_Task * timeout_task;

struct Experiment *e;
struct LoggingHandle *l;

static void
evaluate (struct GNUNET_TIME_Relative duration_total)
{
  int c_m;
  int c_s;
  unsigned int duration;
  struct BenchmarkPeer *mp;
  struct BenchmarkPartner *p;

  unsigned int b_sent_sec;
  double kb_sent_percent;
  unsigned int b_recv_sec;
  double kb_recv_percent;
  unsigned int rtt;


  duration = (duration_total.rel_value_us / (1000 * 1000));
  for (c_m = 0; c_m < e->num_masters; c_m++)
  {
    mp = &masters_p[c_m];
    fprintf (stderr,
        _("Master [%u]: sent: %u KiB in %u sec. = %u KiB/s, received: %u KiB in %u sec. = %u KiB/s\n"),
        mp->no, mp->total_bytes_sent / 1024, duration,
        (mp->total_bytes_sent / 1024) / duration,
        mp->total_bytes_received / 1024, duration,
        (mp->total_bytes_received / 1024) / duration);

    for (c_s = 0; c_s < e->num_slaves; c_s++)
    {
      p = &mp->partners[c_s];

      b_sent_sec = 0;
      b_recv_sec = 0;
      kb_sent_percent = 0.0;
      kb_recv_percent = 0.0;
      rtt = 0;

      if (duration > 0)
      {
          b_sent_sec = p->bytes_sent / duration;
          b_recv_sec = p->bytes_received / duration;
      }

      if (mp->total_bytes_sent > 0)
          kb_sent_percent = ((double) p->bytes_sent * 100) / mp->total_bytes_sent;
      if (mp->total_bytes_received > 0)
          kb_recv_percent = ((double) p->bytes_received * 100) / mp->total_bytes_received;
      if (1000 * p->messages_sent > 0)
          rtt = p->total_app_rtt / (1000 * p->messages_sent);
      fprintf (stderr,
          "%c Master [%u] -> Slave [%u]: sent %u Bips (%.2f %%), received %u Bips (%.2f %%)\n",
          (mp->pref_partner == p->dest) ? '*' : ' ',
          mp->no, p->dest->no,
          b_sent_sec, kb_sent_percent,
                  b_recv_sec, kb_recv_percent);
      fprintf (stderr,
          "%c Master [%u] -> Slave [%u]: Average application layer RTT: %u ms\n",
          (mp->pref_partner == p->dest) ? '*' : ' ',
          mp->no, p->dest->no, rtt);
    }
  }
}

static void
do_shutdown ()
{
  fprintf (stderr, "Shutdown\n");
  /* timeout */
  if (NULL != l)
  {
    GNUNET_ATS_TEST_logging_stop (l);
    GNUNET_ATS_TEST_logging_clean_up (l);
    l = NULL;
  }

  /* Stop traffic generation */
  GNUNET_ATS_TEST_generate_traffic_stop_all();

  /* Stop all preference generations */
  GNUNET_ATS_TEST_generate_preferences_stop_all ();

  if (NULL != e)
  {
    GNUNET_ATS_TEST_experimentation_stop (e);
    e = NULL;
  }
  GNUNET_ATS_TEST_shutdown_topology ();
}


static void
transport_recv_cb (void *cls,
                   const struct GNUNET_PeerIdentity * peer,
                   const struct GNUNET_MessageHeader * message)
{

}

static void
log_request__cb (void *cls, const struct GNUNET_HELLO_Address *address,
    int address_active, struct GNUNET_BANDWIDTH_Value32NBO bandwidth_out,
    struct GNUNET_BANDWIDTH_Value32NBO bandwidth_in,
    const struct GNUNET_ATS_Properties *ats)
{

  if (NULL != l)
  {
    //GNUNET_break (0);
    //GNUNET_ATS_TEST_logging_now (l);
  }

}

static void
experiment_done_cb (struct Experiment *e, struct GNUNET_TIME_Relative duration,int success)
{
  if (GNUNET_OK == success)
    GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Experiment done successful in %s\n",
        GNUNET_STRINGS_relative_time_to_string (duration, GNUNET_YES));
  else
    GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Experiment failed \n");
  if (NULL != timeout_task)
  {
    GNUNET_SCHEDULER_cancel (timeout_task);
    timeout_task = NULL;
  }
  /* Stop logging */
  GNUNET_ATS_TEST_logging_stop (l);

  /* Stop traffic generation */
  GNUNET_ATS_TEST_generate_traffic_stop_all();

  /* Stop all preference generations */
  GNUNET_ATS_TEST_generate_preferences_stop_all ();

  evaluate (duration);
  if (opt_log)
    GNUNET_ATS_TEST_logging_write_to_file(l, opt_exp_file, opt_plot);

  if (NULL != l)
  {
    GNUNET_ATS_TEST_logging_stop (l);
    GNUNET_ATS_TEST_logging_clean_up (l);
    l = NULL;
  }

  /* Clean up experiment */
  GNUNET_ATS_TEST_experimentation_stop (e);
  e = NULL;

  /* Shutdown topology */
  GNUNET_ATS_TEST_shutdown_topology ();
}

static void
episode_done_cb (struct Episode *ep)
{
  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Episode %u done\n", ep->id);
}

static void topology_setup_done (void *cls,
    struct BenchmarkPeer *masters,
    struct BenchmarkPeer *slaves)
{
  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Topology setup complete!\n");

  masters_p = masters;
  slaves_p = slaves;

  l = GNUNET_ATS_TEST_logging_start (e->log_freq,
      e->name,
      masters_p,
      e->num_masters, e->num_slaves,
      opt_verbose);
  GNUNET_ATS_TEST_experimentation_run (e, &episode_done_cb, &experiment_done_cb);
/*
  GNUNET_ATS_TEST_generate_preferences_start(&masters[0],&masters[0].partners[0],
      GNUNET_ATS_TEST_TG_CONSTANT, 1, 1, GNUNET_TIME_UNIT_SECONDS,
      GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_MILLISECONDS, 250),
      GNUNET_ATS_PREFERENCE_BANDWIDTH);
*/
/*
  GNUNET_ATS_TEST_generate_preferences_start(&masters[0],&masters[0].partners[0],
      GNUNET_ATS_TEST_TG_LINEAR, 1, 50,
      GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_SECONDS, 2),
      GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_MILLISECONDS, 250),
      GNUNET_ATS_PREFERENCE_BANDWIDTH);
*/
/*
  GNUNET_ATS_TEST_generate_preferences_start(&masters[0],&masters[0].partners[0],
        GNUNET_ATS_TEST_TG_RANDOM, 1, 50,
        GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_SECONDS, 2),
        GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_MILLISECONDS, 250),
        GNUNET_ATS_PREFERENCE_BANDWIDTH);
*/
  /*
  GNUNET_ATS_TEST_generate_preferences_start(&masters[0],&masters[0].partners[0],
        GNUNET_ATS_TEST_TG_SINUS, 10, 5,
        GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_SECONDS, 5),
        GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_MILLISECONDS, 250),
        GNUNET_ATS_PREFERENCE_BANDWIDTH);
*/
#if 0
  int c_m;
  int c_s;
  for (c_m = 0; c_m < e->num_masters; c_m++)
  {
      for (c_s = 0; c_s < e->num_slaves; c_s++)
      {
        /* Generate maximum traffic to all peers */
        /* Example: Generate traffic with constant 10,000 Bytes/s */
        GNUNET_ATS_TEST_generate_traffic_start (&masters[c_m],
            &masters[c_m].partners[c_s],
            GNUNET_ATS_TEST_TG_CONSTANT,
            10000,
            GNUNET_TIME_UNIT_FOREVER_REL);
        /* Example: Generate traffic with an increasing rate from 1000 to 2000
         * Bytes/s with in a minute */
        GNUNET_ATS_TEST_generate_traffic_start (&masters[c_m],
            &masters[c_m].partners[c_s],
            GNUNET_ATS_TEST_TG_LINEAR,
            1000,
            2000,
            GNUNET_TIME_UNIT_MINUTES,
            GNUNET_TIME_UNIT_FOREVER_REL);
        /* Example: Generate traffic with a random rate between 1000 to 2000
         * Bytes/s */
        GNUNET_ATS_TEST_generate_traffic_start (&masters[c_m],
            &masters[c_m].partners[c_s],
            GNUNET_ATS_TEST_TG_RANDOM,
            1000,
            2000,
            GNUNET_TIME_UNIT_FOREVER_REL,
            GNUNET_TIME_UNIT_FOREVER_REL);
        /* Example: Generate traffic with a sinus form, a base rate of
         * 1000 Bytes/s, an amplitude of (max-base), and a period of 1 minute */
        GNUNET_ATS_TEST_generate_traffic_start (&masters[c_m],
            &masters[c_m].partners[c_s],
            GNUNET_ATS_TEST_TG_SINUS,
            1000,
            2000,
            GNUNET_TIME_UNIT_MINUTES,
            GNUNET_TIME_UNIT_FOREVER_REL);
      }
  }
#endif

  timeout_task = GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_relative_add (GNUNET_TIME_UNIT_MINUTES,
      e->max_duration), &do_shutdown, NULL);
}

static void
parse_args (int argc, char *argv[])
{
  int c;
  opt_exp_file = NULL;
  opt_log = GNUNET_NO;
  opt_plot = GNUNET_NO;

  for (c = 0; c < argc; c++)
  {
    if ((c < (argc - 1)) && (0 == strcmp (argv[c], "-e")))
    {
      opt_exp_file = GNUNET_strdup ( argv[c + 1]);
    }
    if (0 == strcmp (argv[c], "-l"))
    {
      opt_log = GNUNET_YES;
    }
    if (0 == strcmp (argv[c], "-p"))
    {
      opt_plot = GNUNET_YES;
    }
    if (0 == strcmp (argv[c], "-v"))
    {
      opt_verbose = GNUNET_YES;
    }
  }
}

int
main (int argc, char *argv[])
{
  GNUNET_log_setup("gnunet-ats-sim", "INFO", NULL);

  parse_args (argc, argv);
  if (NULL == opt_exp_file )
  {
    fprintf (stderr, "No experiment given...\n");
    return 1;
  }

  fprintf (stderr, "Loading experiment `%s' \n", opt_exp_file );
  e = GNUNET_ATS_TEST_experimentation_load (opt_exp_file);
  if (NULL == e)
  {
    fprintf (stderr, "Invalid experiment\n");
    return 1;
  }
  if (0 == e->num_episodes)
  {
    fprintf (stderr, "No episodes included\n");
    return 1;
  }

  /* Setup a topology with */
  GNUNET_ATS_TEST_create_topology ("gnunet-ats-sim", e->cfg_file,
      e->num_slaves,
      e->num_masters,
      GNUNET_NO,
      &topology_setup_done,
      NULL,
      &transport_recv_cb,
      &log_request__cb);
  GNUNET_free (opt_exp_file);
  return 0;
}
/* end of file gnunet-ats-sim.c */

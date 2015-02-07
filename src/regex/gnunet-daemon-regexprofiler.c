/*
     This file is part of GNUnet.
     Copyright (C) 2012, 2013 Christian Grothoff

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
 * @file regex/gnunet-daemon-regexprofiler.c
 * @brief daemon that uses cadet to announce a regular expression. Used in
 * conjunction with gnunet-regex-profiler to announce regexes on serveral peers
 * without the need to explicitly connect to the cadet service running on the
 * peer from within the profiler.
 * @author Maximilian Szengel
 * @author Bartlomiej Polot
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "regex_internal_lib.h"
#include "regex_test_lib.h"
#include "gnunet_dht_service.h"
#include "gnunet_statistics_service.h"

/**
 * Return value from 'main'.
 */
static int global_ret;

/**
 * Configuration we use.
 */
static const struct GNUNET_CONFIGURATION_Handle *cfg;

/**
 * Handle to the statistics service.
 */
static struct GNUNET_STATISTICS_Handle *stats_handle;

/**
 * Peer's dht handle.
 */
static struct GNUNET_DHT_Handle *dht_handle;

/**
 * Peer's regex announce handle.
 */
static struct REGEX_INTERNAL_Announcement *announce_handle;

/**
 * Periodically reannounce regex.
 */
static struct GNUNET_SCHEDULER_Task * reannounce_task;

/**
 * What's the maximum reannounce period.
 */
static struct GNUNET_TIME_Relative reannounce_period_max;

/**
 * Maximal path compression length for regex announcing.
 */
static unsigned long long max_path_compression;

/**
 * Name of the file containing policies that this peer should announce. One
 * policy per line.
 */
static char * policy_filename;

/**
 * Prefix to add before every regex we're announcing.
 */
static char * regex_prefix;

/**
 * Regex with prefix.
 */
static char *rx_with_pfx;

/**
 * How many put rounds should we do.
 */
static unsigned int rounds = 3;

/**
 * Private key for this peer.
 */
static struct GNUNET_CRYPTO_EddsaPrivateKey *my_private_key;



/**
 * Task run during shutdown.
 *
 * @param cls unused
 * @param tc unused
 */
static void
shutdown_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "shutting down\n");

  if (NULL != announce_handle)
  {
    REGEX_INTERNAL_announce_cancel (announce_handle);
    announce_handle = NULL;
  }

  if (NULL != dht_handle)
  {
    GNUNET_DHT_disconnect (dht_handle);
    dht_handle = NULL;
  }
  GNUNET_free (my_private_key);
  my_private_key = NULL;

  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "Daemon for %s shutting down\n",
              policy_filename);
}


/**
 * Announce a previously announced regex re-using cached data.
 *
 * @param cls Closure (regex to announce if needed).
 * @param tc TaskContext.
 */
static void
reannounce_regex (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_TIME_Relative random_delay;
  char *regex = cls;

  reannounce_task = NULL;
  if (0 != (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN))
  {
    GNUNET_free (regex);
    return;
  }

  if (0 == rounds--)
  {
    global_ret = 0;
    GNUNET_SCHEDULER_shutdown ();
    GNUNET_free (regex);
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Announcing regex: %s\n", regex);
  GNUNET_STATISTICS_update (stats_handle, "# regexes announced", 1, GNUNET_NO);
  if (NULL == announce_handle && NULL != regex)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "First time, creating regex: %s\n",
                regex);
    announce_handle = REGEX_INTERNAL_announce (dht_handle,
					       my_private_key,
					       regex,
					       (unsigned int) max_path_compression,
					       stats_handle);
  }
  else
  {
    GNUNET_assert (NULL != announce_handle);
    REGEX_INTERNAL_reannounce (announce_handle);
  }

  random_delay =
    GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MICROSECONDS,
                                   GNUNET_CRYPTO_random_u32 (
                                     GNUNET_CRYPTO_QUALITY_WEAK,
                                     reannounce_period_max.rel_value_us));
  reannounce_task = GNUNET_SCHEDULER_add_delayed (random_delay,
                                                  &reannounce_regex, cls);
}


/**
 * Announce the given regular expression using regex and the path compression
 * length read from config.
 *
 * @param regex regular expression to announce on this peer's cadet.
 */
static void
announce_regex (const char * regex)
{
  char *copy;

  if (NULL == regex || 0 == strlen (regex))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Cannot announce empty regex\n");
    return;
  }

  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "Daemon for %s starting\n",
              policy_filename);
  GNUNET_assert (NULL == reannounce_task);
  copy = GNUNET_strdup (regex);
  reannounce_task = GNUNET_SCHEDULER_add_now (reannounce_regex, (void *) copy);
}


/**
 * Scan through the policy_dir looking for the n-th filename.
 *
 * @param cls Closure (target number n).
 * @param filename complete filename (absolute path).
 * @return GNUNET_OK to continue to iterate,
 *  GNUNET_NO to stop when found
 */
static int
scan (void *cls, const char *filename)
{
  long n = (long) cls;
  static long c = 0;

  if (c == n)
  {
    policy_filename = GNUNET_strdup (filename);
    return GNUNET_NO;
  }
  c++;
  return GNUNET_OK;
}


/**
 * @brief Main function that will be run by the scheduler.
 *
 * @param cls closure
 * @param args remaining command-line arguments
 * @param cfgfile name of the configuration file used (for saving, can be NULL!)
 * @param cfg_ configuration
 */
static void
run (void *cls, char *const *args GNUNET_UNUSED,
     const char *cfgfile GNUNET_UNUSED,
     const struct GNUNET_CONFIGURATION_Handle *cfg_)
{
  char *regex = NULL;
  char **components;
  char *policy_dir;
  long long unsigned int peer_id;

  cfg = cfg_;

  my_private_key = GNUNET_CRYPTO_eddsa_key_create_from_configuration (cfg);
  GNUNET_assert (NULL != my_private_key);
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_number (cfg, "REGEXPROFILER",
                                             "MAX_PATH_COMPRESSION",
                                             &max_path_compression))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _
                ("%s service is lacking key configuration settings (%s).  Exiting.\n"),
                "regexprofiler", "max_path_compression");
    global_ret = GNUNET_SYSERR;
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_string (cfg, "REGEXPROFILER",
                                             "POLICY_DIR", &policy_dir))
  {
    GNUNET_log_config_missing (GNUNET_ERROR_TYPE_ERROR, "REGEXPROFILER", "POLICY_DIR");
    global_ret = GNUNET_SYSERR;
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_number (cfg, "TESTBED",
                                             "PEERID", &peer_id))
  {
    GNUNET_log_config_missing (GNUNET_ERROR_TYPE_ERROR, "TESTBED", "PEERID");
    global_ret = GNUNET_SYSERR;
    GNUNET_free (policy_dir);
    GNUNET_SCHEDULER_shutdown ();
    return;
  }

  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_string (cfg, "REGEXPROFILER",
                                             "REGEX_PREFIX", &regex_prefix))
  {
    GNUNET_log_config_missing (GNUNET_ERROR_TYPE_ERROR, "REGEXPROFILER", "REGEX_PREFIX");
    global_ret = GNUNET_SYSERR;
    GNUNET_free (policy_dir);
    GNUNET_SCHEDULER_shutdown ();
    return;
  }

  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_time (cfg, "REGEXPROFILER",
                                           "REANNOUNCE_PERIOD_MAX",
                                           &reannounce_period_max))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "reannounce_period_max not given. Using 10 minutes.\n");
    reannounce_period_max =
      GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MINUTES, 10);
  }

  stats_handle = GNUNET_STATISTICS_create ("regexprofiler", cfg);

  dht_handle = GNUNET_DHT_connect (cfg, 1);

  if (NULL == dht_handle)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Could not acquire dht handle. Exiting.\n");
    global_ret = GNUNET_SYSERR;
    GNUNET_free (policy_dir);
    GNUNET_SCHEDULER_shutdown ();
    return;
  }

  /* Read regexes from policy files */
  GNUNET_assert (-1 != GNUNET_DISK_directory_scan (policy_dir, &scan,
                                                   (void *) (long) peer_id));
  if (NULL == (components = REGEX_TEST_read_from_file (policy_filename)))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Policy file %s contains no policies. Exiting.\n",
                policy_filename);
    global_ret = GNUNET_SYSERR;
    GNUNET_free (policy_dir);
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  GNUNET_free (policy_dir);
  regex = REGEX_TEST_combine (components);
  REGEX_TEST_free_from_file (components);

  /* Announcing regexes from policy_filename */
  GNUNET_asprintf (&rx_with_pfx, "%s(%s)(0|1|2|3|4|5|6|7|8|9|a|b|c|d|e|f)*", regex_prefix, regex);
  announce_regex (rx_with_pfx);
  GNUNET_free (regex);
  GNUNET_free (rx_with_pfx);

  /* Scheduled the task to clean up when shutdown is called */
  GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_FOREVER_REL, &shutdown_task,
                                NULL);
}


/**
 * The main function of the regexprofiler service.
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return 0 ok, 1 on error
 */
int
main (int argc, char *const *argv)
{
  static const struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_OPTION_END
  };

  if (GNUNET_OK != GNUNET_STRINGS_get_utf8_args (argc, argv, &argc, &argv))
    return 2;
  return (GNUNET_OK ==
          GNUNET_PROGRAM_run (argc, argv, "regexprofiler",
                              gettext_noop
                              ("Daemon to announce regular expressions for the peer using cadet."),
                              options, &run, NULL)) ? global_ret : 1;
}


#ifdef LINUX
#include <malloc.h>

/**
 * MINIMIZE heap size (way below 128k) since this process doesn't need much.
 */
void __attribute__ ((constructor)) GNUNET_ARM_memory_init ()
{
  mallopt (M_TRIM_THRESHOLD, 4 * 1024);
  mallopt (M_TOP_PAD, 1 * 1024);
  malloc_trim (0);
}
#endif


/* end of gnunet-daemon-regexprofiler.c */

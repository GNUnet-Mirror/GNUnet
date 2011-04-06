/*
     This file is part of GNUnet.
     (C) 2009 Christian Grothoff (and other contributing authors)

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
 * @file testing/test_transport_ats.c
 * @brief testcase for ats functionality
 */
#include "platform.h"
#include "gnunet_testing_lib.h"
#include "gnunet_scheduler_lib.h"
#include "gauger.h"

#define VERBOSE GNUNET_NO

#define NUM_PEERS 11
#define MEASUREMENTS 5

#define DELAY GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 300)
#define TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 300)


static int ok;

static int peers_left;

static int failed_peers;

static int measurement_started = GNUNET_NO;

static struct GNUNET_TESTING_PeerGroup *pg;

static  GNUNET_SCHEDULER_TaskIdentifier shutdown_task;
static  GNUNET_SCHEDULER_TaskIdentifier stats_task;
struct GNUNET_TESTING_Daemon * master_deamon;

struct GNUNET_STATISTICS_Handle * stats;

struct TEST_result
{
	uint64_t timestamp;
	uint64_t duration;
	uint64_t mechs;
	uint64_t peers;
	uint64_t solution;
};

static int r_index;
//static int measurements;
static int connected;
static int peers;
static struct TEST_result results[MEASUREMENTS];

struct GNUNET_STATISTICS_GetHandle * s_solution;
struct GNUNET_STATISTICS_GetHandle * s_time;
struct GNUNET_STATISTICS_GetHandle * s_peers;
struct GNUNET_STATISTICS_GetHandle * s_mechs;
struct GNUNET_STATISTICS_GetHandle * s_duration;
struct GNUNET_STATISTICS_GetHandle * s_invalid;

/**
 * Check whether peers successfully shut down.
 */
void
shutdown_callback (void *cls, const char *emsg)
{
  if (emsg != NULL)
    {
#if VERBOSE
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Shutdown of peers failed!\n");
#endif
      if (ok == 0)
        ok = 666;
    }
  else
    {
#if VERBOSE
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "All peers successfully shut down!\n");
      	if (stats != NULL)
      		GNUNET_STATISTICS_destroy(stats, GNUNET_NO);
      	stats = NULL;
#endif
    }
}

static void shutdown_peers()
{
	if (shutdown_task != GNUNET_SCHEDULER_NO_TASK)
	{
		GNUNET_SCHEDULER_cancel(shutdown_task);
		shutdown_task = GNUNET_SCHEDULER_NO_TASK;
	}
	if (stats_task != GNUNET_SCHEDULER_NO_TASK)
	{
		GNUNET_SCHEDULER_cancel(stats_task);
		stats_task = GNUNET_SCHEDULER_NO_TASK;
	}

	if (s_time != NULL)
	{
		GNUNET_STATISTICS_get_cancel(s_time);
		s_time = NULL;
	}
	if (s_peers != NULL)
	{
		GNUNET_STATISTICS_get_cancel(s_peers);
		s_peers = NULL;
	}
	if (s_mechs != NULL)
	{
		GNUNET_STATISTICS_get_cancel(s_mechs);
		s_mechs = NULL;
	}
	if (s_solution != NULL)
	{
		GNUNET_STATISTICS_get_cancel(s_solution);
		s_solution = NULL;
	}
	if (s_duration != NULL)
	{
		GNUNET_STATISTICS_get_cancel(s_duration);
		s_duration = NULL;
	}
	if (s_invalid != NULL)
	{
		GNUNET_STATISTICS_get_cancel(s_invalid);
		s_invalid = NULL;
	}

    GNUNET_TESTING_daemons_stop (pg, TIMEOUT, &shutdown_callback, NULL);
}

static void evaluate_measurements()
{
	int c;
	char * output = NULL;
	char * temp;
	double average;
	double stddev;
	double measure = MEASUREMENTS;
	for (c=0; c<MEASUREMENTS;c++)
	{
		average += (double) results[c].duration;
		GNUNET_asprintf(&temp, "%sm%i,%llu,%llu,%llu,%llu,", (output==NULL) ? "" : output, c, results[c].peers, results[c].mechs, results[c].duration, results[c].solution);
		GNUNET_free_non_null (output);
		output = temp;
	}
	average /= measure;

	for (c=0; c<MEASUREMENTS;c++)
	{
		stddev += (results[c].duration - average) * (results[c].duration - average);
	}
	stddev /= measure;
	stddev = sqrt (stddev);

	GNUNET_log (GNUNET_ERROR_TYPE_ERROR,"%savg,%f,stddev,%f\n",output,average,stddev);
	/* only log benchmark time for 10 peers */
	if (results[MEASUREMENTS-1].peers == (10))
	 	{
			GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,"Send data to gauger: %f \n", average);
	 		GAUGER ("TRANSPORT", "ATS execution time 10 peers", average , "ms");
	 	}
	shutdown_peers();
}

int stats_cb (void *cls,
			   const char *subsystem,
			   const char *name,
			   uint64_t value,
			   int is_persistent)
{
	if (0 == strcmp (name,"ATS invalid solutions"))
	{
		if (stats_task != GNUNET_SCHEDULER_NO_TASK)
		{
			GNUNET_SCHEDULER_cancel(stats_task);
			stats_task = GNUNET_SCHEDULER_NO_TASK;
		}
		GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,"MLP produced invalid %llu result(s)!\n", value);
		shutdown_peers();
		return GNUNET_SYSERR;
	}

	if (0 == strcmp (name,"ATS solution"))
	{
		s_solution = NULL;
	}

	if (0 == strcmp (name,"ATS peers"))
	{
		s_peers = NULL;
	}

	if (0 == strcmp (name,"ATS mechanisms"))
	{
		s_mechs = NULL;
	}

	if (0 == strcmp (name,"ATS duration"))
	{
		s_duration = NULL;
	}
	if (0 == strcmp (name,"ATS timestamp"))
	{
		s_time = NULL;
	}

    if ((measurement_started == GNUNET_NO) && (0 == strcmp (name, "ATS peers")) && (value == peers-1))
    {
		measurement_started = GNUNET_YES;
		r_index = 0;
		GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "All %llu peers connected\n", value);
    }

    if (measurement_started == GNUNET_YES)
    {
		// GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "%s == %llu\n", name ,value);
		if (0 == strcmp (name,"ATS timestamp"))
		{
			if (results[r_index].timestamp == 0)
				results[r_index].timestamp = value;
			if (results[r_index].timestamp != value)
			{
				r_index++;
				fprintf(stderr, "(%i/%i)", r_index, MEASUREMENTS);
				if (r_index >= MEASUREMENTS)
				{
					fprintf(stderr, "\n");
					if (stats_task != GNUNET_SCHEDULER_NO_TASK)
					{
						GNUNET_SCHEDULER_cancel(stats_task);
						stats_task = GNUNET_SCHEDULER_NO_TASK;
					}
					evaluate_measurements();
					return GNUNET_SYSERR;
				}
				fprintf(stderr, "..");

				results[r_index].timestamp = value;
				return GNUNET_OK;
			}
		}

		if (0 == strcmp (name,"ATS solution"))
		{
			results[r_index].solution = value;
			GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "[%i] ATS solution: %s %llu \n", r_index, name, value);
		}

		if (0 == strcmp (name,"ATS peers"))
		{
			results[r_index].peers = value;
			GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "[%i] ATS peers: %s %llu \n", r_index, name, value);
		}

		if (0 == strcmp (name,"ATS mechanisms"))
		{
			results[r_index].mechs = value;
			GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "[%i] ATS mechanisms: %s %llu \n", r_index, name, value);
		}

		if (0 == strcmp (name,"ATS duration"))
		{
			results[r_index].duration = value;
			GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "[%i] ATS duration: %s %llu \n", r_index, name, value);
		}
    }
    return GNUNET_OK;
}


void
stats_get_task (void *cls,
			  const struct GNUNET_SCHEDULER_TaskContext *tc)
{
	stats_task = GNUNET_SCHEDULER_NO_TASK;
	if ( (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN) != 0)
	    return;

	s_time = GNUNET_STATISTICS_get (stats, "transport", "ATS timestamp", TIMEOUT, NULL, &stats_cb, NULL);
	s_solution = GNUNET_STATISTICS_get (stats, "transport", "ATS solution", TIMEOUT, NULL, &stats_cb, NULL);
	s_duration = GNUNET_STATISTICS_get (stats, "transport","ATS duration", TIMEOUT, NULL, &stats_cb, NULL);
	s_peers = GNUNET_STATISTICS_get (stats, "transport", "ATS peers", TIMEOUT, NULL, &stats_cb, NULL);
	s_mechs = GNUNET_STATISTICS_get (stats, "transport", "ATS mechanisms", TIMEOUT, NULL, &stats_cb, NULL);
	s_invalid = GNUNET_STATISTICS_get (stats, "transport", "ATS invalid solutions", TIMEOUT, NULL, &stats_cb, NULL);


	stats_task = GNUNET_SCHEDULER_add_delayed(GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MILLISECONDS, 250), &stats_get_task, NULL);
}

void
delay (void *cls,
			  const struct GNUNET_SCHEDULER_TaskContext *tc)
{
	shutdown_task = GNUNET_SCHEDULER_NO_TASK;
	if ( (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN) != 0)
	    return;

#if VERBOSE
	GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Delay over\n");
#endif
	shutdown_peers ();
}

static void connect_peers()
{
    shutdown_task = GNUNET_SCHEDULER_add_delayed(DELAY, &delay, NULL);

}

void daemon_connect_cb(void *cls,
						const struct GNUNET_PeerIdentity *first,
						const struct GNUNET_PeerIdentity *second,
						uint32_t distance,
						const struct GNUNET_CONFIGURATION_Handle *first_cfg,
						const struct GNUNET_CONFIGURATION_Handle *second_cfg,
						struct GNUNET_TESTING_Daemon *first_daemon,
						struct GNUNET_TESTING_Daemon *second_daemon,
						const char *emsg)
{
	char * firstc =  strdup(GNUNET_i2s(first));
	char * secondc =  strdup(GNUNET_i2s(second));
	connected++;
	GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Connected peers `%s'<->`%s' (%i/%i)\n", firstc, secondc, connected, peers-1);
	GNUNET_free(firstc);
	GNUNET_free(secondc);
}

void cont_cb (void *cls, int success)
{
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "STATS cont_cb: %i\n", success);
}

static void
daemon_start_cb (void *cls,
       const struct GNUNET_PeerIdentity *id,
       const struct GNUNET_CONFIGURATION_Handle *cfg,
       struct GNUNET_TESTING_Daemon *d, const char *emsg)
{
  if (id == NULL)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Start callback called with error (too long starting peers), aborting test!\n");
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Error from testing: `%s'\n");
      failed_peers++;
      if (failed_peers == peers_left)
        {
          GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                      "Too many peers failed, ending test!\n");
          ok = 1;
      	shutdown_peers ();
        }
      return;
    }
  peers_left--;

  if (master_deamon == NULL)
  {
	  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Master peer `%s' '%s'\n", GNUNET_i2s(id), d->cfgfile);

	  master_deamon = d;
	  stats = GNUNET_STATISTICS_create("transport", master_deamon->cfg);
	  GNUNET_assert (stats != NULL);
	  stats_task = GNUNET_SCHEDULER_add_now(&stats_get_task, NULL);
  }
  else
  {
	  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Connecting peer `%s'\n", GNUNET_i2s(id), GNUNET_i2s(&master_deamon->id));
	  GNUNET_TESTING_daemons_connect(d, master_deamon, TIMEOUT, 0, GNUNET_YES,&daemon_connect_cb, NULL);
  }

  if (peers_left == 0)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "All peers started successfully!\n");
      connect_peers();
      ok = 0;
    }
  else if (failed_peers == peers_left)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Too many peers failed, ending test!\n");
      shutdown_peers();
      ok = 1;
    }
}


static void
run (void *cls,
     char *const *args,
     const char *cfgfile, const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  ok = 1;
  measurement_started = GNUNET_NO;
#if VERBOSE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Starting %i peers.\n", peers);
#endif
  peers_left = peers;
  pg = GNUNET_TESTING_daemons_start (cfg,
                                     peers_left, /* Total number of peers */
                                     peers_left, /* Number of outstanding connections */
                                     peers_left, /* Number of parallel ssh connections, or peers being started at once */
                                     TIMEOUT,
                                     NULL, NULL,
                                     &daemon_start_cb, NULL, NULL, NULL, NULL);
  GNUNET_assert (pg != NULL);
}

static int
check ()
{
  char *const argv[] = { "test-testing",
    "-c",
    "test_transport_ats.conf",
#if VERBOSE
    "-L", "DEBUG",
#endif
    NULL
  };
  struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_OPTION_END
  };
  GNUNET_PROGRAM_run ((sizeof (argv) / sizeof (char *)) - 1,
                      argv, "test-transport-ats", "nohelp",
                      options, &run, &ok);
  return ok;
}

int
main (int argc, char *argv[])
{
  int ret;

  GNUNET_log_setup ("test-transport-ats",
#if VERBOSE
                    "DEBUG",
#else
                    "WARNING",
#endif
                    NULL);
  GNUNET_DISK_directory_remove ("/tmp/test-gnunet-testing");

  peers = NUM_PEERS;
  if (argc >= 2)
  {
	  peers = atoi(argv[1]);
	  peers++;
  }
  ret = check ();
  /**
   * Still need to remove the base testing directory here,
   * because group starts will create subdirectories under this
   * main dir.  However, we no longer need to sleep, as the
   * shutdown sequence won't return until everything is cleaned
   * up.
   */
  GNUNET_DISK_directory_remove ("/tmp/test-gnunet-testing");
  return ret;
}

/* end of test_transport_ats.c*/

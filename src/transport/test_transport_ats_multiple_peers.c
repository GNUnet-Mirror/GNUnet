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
 * @file testing/test_transport_ats_multiple_peers.c
 * @brief testcase for ats functionality by starting multiple peers
 */

#include "platform.h"
#include "gnunet_util_lib.h"

#include "gnunet_testing_lib.h"
#include "gnunet_transport_service.h"
#include "gauger.h"
#include "gnunet-service-transport_ats.h"

#define VERBOSE GNUNET_NO

#define NUM_PEERS 11
#define MEASUREMENTS 5

#define DELAY GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 300)
#define TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 300)
#define SEND_TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 1)

static int ok;

static int peers_left;

static int failed_peers;

static int measurement_started = GNUNET_NO;
static char * config_file;

static struct GNUNET_TESTING_PeerGroup *pg;

static GNUNET_SCHEDULER_TaskIdentifier shutdown_task;
static GNUNET_SCHEDULER_TaskIdentifier stats_task;
static GNUNET_SCHEDULER_TaskIdentifier send_task;
struct GNUNET_TESTING_Daemon * master_deamon;
struct GNUNET_TESTING_Daemon * ping_deamon;

struct GNUNET_STATISTICS_Handle * stats;

struct TEST_result
{
  uint64_t timestamp;
  uint64_t duration;
  uint64_t mechs;
  uint64_t peers;
  uint64_t solution;
  uint64_t state;
};

struct TestMessage
{
  struct GNUNET_MessageHeader header;
  uint32_t num;
};


static int count;
static int c_new;
static int c_unmodified;
static int c_modified;
static int connected;
static int peers;

static int force_q_updates;
static int force_rebuild;
static int send_msg;
static int machine_parsable;

static struct TEST_result results_new       [MEASUREMENTS+1];
static struct TEST_result results_modified  [MEASUREMENTS+1];
static struct TEST_result results_unmodified[MEASUREMENTS+1];
static struct TEST_result current;

static struct GNUNET_STATISTICS_GetHandle * s_solution;
static struct GNUNET_STATISTICS_GetHandle * s_time;
static struct GNUNET_STATISTICS_GetHandle * s_peers;
static struct GNUNET_STATISTICS_GetHandle * s_mechs;
static struct GNUNET_STATISTICS_GetHandle * s_duration;
static struct GNUNET_STATISTICS_GetHandle * s_invalid;
static struct GNUNET_STATISTICS_GetHandle * s_state;

struct GNUNET_TRANSPORT_TransmitHandle * t;
struct GNUNET_TRANSPORT_Handle * th;

/**
 * Check whether peers successfully shut down.
 */
static void
shutdown_callback (void *cls, const char *emsg)
{
  if (emsg != NULL)
    {
#if VERBOSE
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, 
		  "Shutdown of peers failed!\n");
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

static void
shutdown_peers()
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
  if (send_task != GNUNET_SCHEDULER_NO_TASK)
    {
      GNUNET_SCHEDULER_cancel(send_task);
      send_task = GNUNET_SCHEDULER_NO_TASK;
    }
  
  if (t != NULL)
    {
      GNUNET_TRANSPORT_notify_transmit_ready_cancel(t);
      t = NULL;
    }
  GNUNET_TRANSPORT_disconnect(th);  
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
  if (s_state != NULL)
    {
      GNUNET_STATISTICS_get_cancel(s_state);
      s_state = NULL;
    }
  GNUNET_TESTING_daemons_stop (pg, TIMEOUT, &shutdown_callback, NULL);
}

static void 
evaluate_measurements()
{
  int c;
  //int mechs = 0;
  double average[3];
  double stddev[3];
  //char * output;
  c = 1;
  
  //GNUNET_asprintf(&output, "p,%i,m,%i,",peers, MEASUREMENTS, results_modified[0].mechs,
  
  average[0] = 0.0;
  for (c=0; c<c_new;c++)
    {
      average[0] += (double) results_new[c].duration;
    }
  average[0] /= c_new;
  
  stddev[0] = 0.0;
  for (c=0; c<c_new;c++)
    {
      stddev[0] += (results_new[c].duration - average[0]) *
          (results_new[c].duration - average[0]);
    }
  stddev[0] /= c_new;
  stddev[0] = sqrt (stddev[0]);
  if (!machine_parsable)
    fprintf (stderr,
	     "new, %i measurements, average: %f stddev: %f\n",
	     c_new, average[0], stddev[0]);
  
  average[1] = 0.0;
  for (c=0; c<c_modified;c++)
    {
      average[1] += (double) results_modified[c].duration;
    }
  average[1] /= c_modified;
  
  stddev[1] = 0.0;
  for (c=0; c<c_modified;c++)
    {
      stddev[1] += (results_modified[c].duration - average[1]) *
          (results_modified[c].duration - average[1]);
    }
  stddev[1] /= c_modified;
  stddev[1] = sqrt (stddev[1]);
  if (!machine_parsable) 
    fprintf (stderr,
	     "modified, %i measurements, average: %f stddev: %f\n",
	     c_modified, average[1], stddev[1]);
  
  average[2] = 0.0;
  for (c=0; c<c_unmodified;c++)
    {
      average[2] += (double) results_unmodified[c].duration;
    }
  average[2] /= c_unmodified;
  stddev[2] = 0.0;
  for (c=0; c<c_unmodified;c++)
    {
      stddev[2] += (results_unmodified[c].duration - average[2]) *
          (results_unmodified[c].duration - average[2]);
    }
  stddev[2] /= c_unmodified;
  stddev[2] = sqrt (stddev[2]);
  
  if (!machine_parsable) 
    fprintf (stderr,
	     "unmodified, %i measurements, average: %f stddev: %f\n",
	     c_unmodified, average[2], stddev[2]);
  
  if (machine_parsable)
    fprintf (stderr,
	     "peers,%i,mechs,%llu,"
	     "new,%i,%f,%f,"
	     "mod,%i,%f,%f,"
	     "unmod,%i,%f,%f\n",
	     peers-1, (unsigned long long) results_unmodified[0].mechs,
	     c_new, average[0], stddev[0],
	     c_modified, average[1], stddev[1],
	     c_unmodified, average[2], stddev[2]);
  shutdown_peers();
}


static int 
stats_cb (void *cls,
	  const char *subsystem,
	  const char *name,
	  uint64_t value,
	  int is_persistent)
{
  static int printed = GNUNET_NO;
#if VERBOSE_ATS
  GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "%s = %llu\n", name ,value);
#endif
  if (0 == strcmp (name,"ATS invalid solutions"))
    {
      if (stats_task != GNUNET_SCHEDULER_NO_TASK)
	{
	  GNUNET_SCHEDULER_cancel(stats_task);
	  stats_task = GNUNET_SCHEDULER_NO_TASK;
	}
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,"MLP produced invalid %llu result(s)!\n",
          value);
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
  if (0 == strcmp (name,"ATS state"))
    {
      s_state = NULL;
    }
  
  if ( (measurement_started == GNUNET_NO) && 
       (0 == strcmp (name, "ATS peers")) && 
       (value == peers-1) )
    {
      measurement_started = GNUNET_YES;
      count = 1;
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, 
		  "All %llu peers connected\n", 
		  value);
#if !VERBOSE
      if (! machine_parsable)	
	fprintf(stderr, "%i", count);
#endif
    }
  
  if (measurement_started == GNUNET_YES)
    {
      // GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "%s == %llu\n", name ,value);
      if (0 == strcmp (name,"ATS timestamp"))
	{
	  if (current.timestamp == 0)
	    {
	      printed = GNUNET_NO;
	      current.timestamp = value;
	    }
	  if (current.timestamp == value)
	    {
	      printed = GNUNET_YES;
	    }
	  if (current.timestamp != value)
	    {
	      if (current.state == ATS_NEW)
		{
		  if (c_new < MEASUREMENTS)
		    {
		      results_new[c_new] = current;
		      c_new++;
		    }
		  else
		    {
		      force_rebuild = GNUNET_NO;
		      force_q_updates = GNUNET_NO;
		      send_msg = GNUNET_NO;
		    }
		}
	      if (current.state == ATS_UNMODIFIED)
		{
		  if (c_unmodified < MEASUREMENTS)
		    {
		      results_unmodified[c_unmodified] = current;
		      c_unmodified++;
		    }
		  
		}
	      if (current.state == ATS_QUALITY_UPDATED)
		{
		  if (c_modified < MEASUREMENTS)
		    {
		      results_modified[c_modified] = current;
		      c_modified++;
		    }
		  else
		    {
		      force_q_updates = GNUNET_NO;
		      force_rebuild = GNUNET_YES;
		    }
		}
	      count ++;
#if VERBOSE
	      fprintf (stderr,
		       "(new: %i / modified: %i / unmodified: %i) of %i \n", 
		       c_new, c_modified, c_unmodified , MEASUREMENTS);
#endif
	      if ((c_modified >= MEASUREMENTS) &&
	          (c_new >= MEASUREMENTS) &&
	          (c_unmodified >= MEASUREMENTS))
		{
#if !VERBOSE
		  if (!machine_parsable)
		    fprintf(stdout, "\n");
#endif
		  if (stats_task != GNUNET_SCHEDULER_NO_TASK)
		    {
		      GNUNET_SCHEDULER_cancel(stats_task);
		      stats_task = GNUNET_SCHEDULER_NO_TASK;
		    }
		  evaluate_measurements();
		  return GNUNET_SYSERR;
		}
	      
	      printed = GNUNET_NO;
	      current.timestamp = value;
#if !VERBOSE
	      if (! machine_parsable)
		fprintf(stderr, "..%i", count);
#endif
	      return GNUNET_OK;
	    }
	}
      
      if (0 == strcmp (name,"ATS solution"))
	{
	  current.solution = value;
	  if (printed == GNUNET_NO)
	    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "[%i] %s: %llu \n",
	        count, name, value);
	}
      
      if (0 == strcmp (name,"ATS peers"))
	{
	  current.peers = value;
	  if (printed == GNUNET_NO)
	    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "[%i] %s: %llu \n",
	        count, name, value);
	}
      
      if (0 == strcmp (name,"ATS mechanisms"))
	{
	  current.mechs = value;
	  if (printed == GNUNET_NO) 
	    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "[%i] %s: %llu \n",
	        count, name, value);
	}
      
      if (0 == strcmp (name,"ATS duration"))
	{
	  current.duration = value;
	  if (printed == GNUNET_NO) 
	    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "[%i] %s: %llu \n",
	        count, name, value);
	}
      if (0 == strcmp (name,"ATS state"))
	{
	  current.state = value;
	  const char * cont;
	  switch (value)
	    {
	    case ATS_NEW:
	      cont = "NEW";
	      break;
	    case ATS_COST_UPDATED:
	      cont = "C_UPDATED";
	      break;
	    case ATS_QUALITY_UPDATED:
	      cont = "Q_UPDATED";
	      break;
	    case ATS_QUALITY_COST_UPDATED:
	      cont = "QC_UPDATED";
	      break;
	    case ATS_UNMODIFIED:
	      cont = "UNMODIFIED";
	      break;
	    default:
	      GNUNET_break (0);
	      cont = "<undefined>";
	      break;
	    }
	  if (printed == GNUNET_NO) 
	    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, 
			"[%i] ATS state: %s\n", 
			count, 
			cont);
	}
    }
  return GNUNET_OK;
}


static void
stats_get_task (void *cls,
		const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  stats_task = GNUNET_SCHEDULER_NO_TASK;
  if ( (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN) != 0)
    return;
  
  s_time = GNUNET_STATISTICS_get (stats, "transport", "ATS timestamp",
      TIMEOUT, NULL, &stats_cb, NULL);
  s_solution = GNUNET_STATISTICS_get (stats, "transport", "ATS solution",
      TIMEOUT, NULL, &stats_cb, NULL);
  s_duration = GNUNET_STATISTICS_get (stats, "transport","ATS duration",
      TIMEOUT, NULL, &stats_cb, NULL);
  s_peers = GNUNET_STATISTICS_get (stats, "transport", "ATS peers",
      TIMEOUT, NULL, &stats_cb, NULL);
  s_mechs = GNUNET_STATISTICS_get (stats, "transport", "ATS mechanisms",
      TIMEOUT, NULL, &stats_cb, NULL);
  s_invalid = GNUNET_STATISTICS_get (stats, "transport", "ATS invalid solutions",
      TIMEOUT, NULL, &stats_cb, NULL);
  s_state = GNUNET_STATISTICS_get (stats, "transport", "ATS state",
      TIMEOUT, NULL, &stats_cb, NULL);
  
  stats_task = GNUNET_SCHEDULER_add_delayed(
      GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MILLISECONDS, 100),
      &stats_get_task,
      NULL);
}


static void
delay (void *cls,
       const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  shutdown_task = GNUNET_SCHEDULER_NO_TASK;
  if ( (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN) != 0)
    return;
#if VERBOSE
  GNUNET_log (GNUNET_ERROR_TYPE_ERROR, 
	      "Delay over\n");
#endif
  shutdown_peers ();
}

static void
connect_peers()
{
  shutdown_task = GNUNET_SCHEDULER_add_delayed(DELAY, &delay, NULL);
}


/* To make compiler happy */
void dummy(void)
{
  struct ATS_quality_metric * q = qm;
  q = NULL;
  q++;
  struct ATS_ressource * r = ressources;
  r = NULL;
  r++;
}

static size_t 
send_dummy_data_task (void *cls, size_t size, void *buf)
{
  int s = sizeof (struct TestMessage);
  struct TestMessage hdr;
  
  hdr.header.size = htons (s);
  hdr.header.type = htons (GNUNET_MESSAGE_TYPE_TRANSPORT_ATS);
  if (force_rebuild)
    hdr.num = htonl (1);
  else if (force_q_updates)
    hdr.num = htonl (2);
  else
    hdr.num = htonl (0); 
  memcpy (buf, &hdr, s);
  // GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Sent bytes: %i of %i\n", s, s);
  t = NULL;
  return s;
}


static void 
send_task_f (void *cls,
	     const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  send_task = GNUNET_SCHEDULER_NO_TASK;
  if ( (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN) != 0)
    return;
  
  if (t!=NULL)
    {
      GNUNET_TRANSPORT_notify_transmit_ready_cancel(t);
      t = NULL;
    }

  if (send_msg == GNUNET_YES)
    t = GNUNET_TRANSPORT_notify_transmit_ready(th, 
					       &master_deamon->id, 
					       sizeof (struct TestMessage), 0, 
					       SEND_TIMEOUT, 
					       &send_dummy_data_task, NULL);
  send_task = GNUNET_SCHEDULER_add_delayed(
      GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_MILLISECONDS,1000),
      &send_task_f,
      NULL);

}

static void
notify_connect (void *cls,
                const struct GNUNET_PeerIdentity *peer,
                const struct GNUNET_TRANSPORT_ATS_Information *ats,
                uint32_t ats_count)
{
  send_task = GNUNET_SCHEDULER_add_now(&send_task_f, NULL);
}

static void
notify_disconnect (void *cls,
		   const struct GNUNET_PeerIdentity *peer)
{
  if (GNUNET_SCHEDULER_NO_TASK != send_task)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "Disconnect event before transmission request could be scheduled!\n");
      GNUNET_SCHEDULER_cancel (send_task);
      send_task = GNUNET_SCHEDULER_NO_TASK;
    }
  if (NULL != t)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "Disconnect event before transmission request could be completed!\n");
      GNUNET_TRANSPORT_notify_transmit_ready_cancel (t);
      t = NULL;
    }
}

static void 
daemon_connect_cb(void *cls,
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
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Connected peers `%s'<->`%s' (%i/%i)\n", 
	      firstc, secondc, connected, peers-1);
  GNUNET_free(firstc);
  GNUNET_free(secondc);
  
  if ( ( (first_daemon == ping_deamon) || 
	 (second_daemon == ping_deamon) ) && 
       (master_deamon != NULL) && 
       (ping_deamon != NULL) )
    {
      th = GNUNET_TRANSPORT_connect (ping_deamon->cfg,
				     &ping_deamon->id, 
				     NULL, NULL,
				     &notify_connect, 
				     &notify_disconnect);
      force_q_updates = GNUNET_YES;
      send_msg = GNUNET_YES;
    }
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
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "Error from testing: `%s'\n");
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
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, 
		  "Master peer `%s' '%s'\n",
		  GNUNET_i2s(id), d->cfgfile);      
      master_deamon = d;
      stats = GNUNET_STATISTICS_create("transport", master_deamon->cfg);
      GNUNET_assert (stats != NULL);
      stats_task = GNUNET_SCHEDULER_add_now(&stats_get_task, NULL);
    }
  else
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, 
		  "Connecting peer `%s'\n", 
		  GNUNET_i2s(id), GNUNET_i2s(&master_deamon->id));
      GNUNET_TESTING_daemons_connect(d,
          master_deamon,
          TIMEOUT,
          0,
          GNUNET_YES,
          &daemon_connect_cb,
          NULL);
    }
  
  if (peers_left == 0)
    {
      if (ping_deamon == NULL)
	{
	  ping_deamon = d;
	  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, 
		      "Ping peer `%s' '%s'\n", GNUNET_i2s(id), d->cfgfile);
	}
      
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
    config_file,
#if VERBOSE
    "-L", "DEBUG",
#endif
    NULL
  };
  struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_OPTION_END
  };
  GNUNET_PROGRAM_run ((sizeof (argv) / sizeof (char *)) - 1,
                      argv, "test_transport_ats_multiple_peers", "nohelp",
                      options, &run, &ok);
  return ok;
}

int
main (int argc, char *argv[])
{
  int ret = 0;

  GNUNET_log_setup ("test-transport-ats-multiple-peers",
#if VERBOSE
                    "DEBUG",
#else
                    "INFO",
#endif
                    NULL);

  GNUNET_DISK_directory_remove ("/tmp/test-gnunet-testing");
  machine_parsable = GNUNET_NO;
  peers = NUM_PEERS;
  config_file = "test_transport_ats_4addr.conf";

  int c = 0;
  if (argc >= 2)
    {
      for (c=0; c<argc; c++)
	{
	  /* set peers */
	  if ((strcmp(argv[c], "-p") == 0) && c < (argc-1))
	    {
	      peers = atoi(argv[c+1]);
	      peers++;
	    }
	  /* set machine parsable */
	  if (strcmp(argv[c], "-m") == 0)
	    {
	      machine_parsable = GNUNET_YES;
	    }
	  /* set config file */
	  if ((strcmp(argv[c], "-c") == 0) && c < (argc-1))
	    {
	      config_file = argv[c+1];
	    }
	 }
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

/* end of test_transport_ats_multiple_peers.c*/

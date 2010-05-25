/*
     This file is part of GNUnet
     (C) 2009 Christian Grothoff (and other contributing authors)

     GNUnet is free software; you can redistribute it and/or modify
     it under the terms of the GNU General Public License as published
     by the Free Software Foundation; either version 2, or (at your
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
 * @file hostlist/test_gnunet_daemon_hostlist.c
 * @brief test for gnunet_daemon_hostslist.c
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_arm_service.h"
#include "gnunet_core_service.h"
#include "gnunet_transport_service.h"
#include "gnunet_resolver_service.h"
#include "gnunet_statistics_service.h"

#define VERBOSE GNUNET_YES

#define START_ARM GNUNET_YES
#define MAX_URL_LEN 1000

/**
 * How long until wait until testcases fails
 */
#define TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 90)
#define CHECK_INTERVALL GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 1)

static int timeout;
static int adv_sent;
static int adv_arrived;

static int learned_hostlist_saved;
static int learned_hostlist_downloaded;

static char * current_adv_uri;

static const struct GNUNET_CONFIGURATION_Handle *cfg;
static struct GNUNET_SCHEDULER_Handle *sched;

static GNUNET_SCHEDULER_TaskIdentifier timeout_task;
static GNUNET_SCHEDULER_TaskIdentifier check_task;
    
struct PeerContext
{
  struct GNUNET_CONFIGURATION_Handle *cfg;
  struct GNUNET_TRANSPORT_Handle *th;
  struct GNUNET_MessageHeader *hello;
  struct GNUNET_CORE_Handle *core;
  struct GNUNET_STATISTICS_Handle *stats;
#if START_ARM
  pid_t arm_pid;
#endif
};

static struct PeerContext adv_peer;

static struct PeerContext learn_peer;

static struct GNUNET_STATISTICS_GetHandle * download_stats;
static struct GNUNET_STATISTICS_GetHandle * urisrecv_stat;
static struct GNUNET_STATISTICS_GetHandle * advsent_stat;

static void shutdown_testcase()
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Shutdown testcase....\n");
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Stopping Timeout Task.\n");
  if (timeout_task != GNUNET_SCHEDULER_NO_TASK)
  {
    GNUNET_SCHEDULER_cancel (sched, timeout_task);
    timeout_task = GNUNET_SCHEDULER_NO_TASK;
  }

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Stopping Statistics Task.\n");
/*
  if ((NULL != learn_peer.stats) && (NULL != download_stats))
    GNUNET_STATISTICS_get_cancel (download_stats);
  if ((NULL != learn_peer.stats) && (NULL != urisrecv_stat))
    GNUNET_STATISTICS_get_cancel (urisrecv_stat);
  if ((NULL != adv_peer.stats) && (NULL != advsent_stat))
    GNUNET_STATISTICS_get_cancel (advsent_stat);
*/
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Stopping Statistics Check Task.\n");
  if ((check_task != GNUNET_SCHEDULER_NO_TASK) && (sched !=NULL))
  {
    GNUNET_SCHEDULER_cancel (sched, check_task);
    check_task = GNUNET_SCHEDULER_NO_TASK;
  }

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Freeing uri\n");
  if ( NULL != current_adv_uri ) GNUNET_free (current_adv_uri);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Disconnecting from Transport.\n");
  if (adv_peer.th != NULL)
  {
    GNUNET_TRANSPORT_disconnect (adv_peer.th);
    adv_peer.th = NULL;
  }
  if (learn_peer.th != NULL)
  {
    GNUNET_TRANSPORT_disconnect (learn_peer.th);
    learn_peer.th = NULL;
  }

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Disconnecting from Core.\n");
  if (adv_peer.core != NULL)
  {
    GNUNET_CORE_disconnect (adv_peer.core);
    adv_peer.core = NULL;
  }
  if (learn_peer.core != NULL)
  {
    GNUNET_CORE_disconnect (learn_peer.core);
    learn_peer.core = NULL;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Asking ARM to stop core services\n");


#if START_ARM
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Killing hostlist server ARM process.\n");
  if (0 != PLIBC_KILL (adv_peer.arm_pid, SIGTERM))
    GNUNET_log_strerror (GNUNET_ERROR_TYPE_WARNING, "kill");
  if (GNUNET_OS_process_wait(adv_peer.arm_pid) != GNUNET_OK)
    GNUNET_log_strerror (GNUNET_ERROR_TYPE_WARNING, "waitpid");
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Hostlist server ARM process %u stopped\n", adv_peer.arm_pid);
#endif
  

#if START_ARM
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Killing hostlist client ARM process.\n");
  if (0 != PLIBC_KILL (learn_peer.arm_pid, SIGTERM))
    GNUNET_log_strerror (GNUNET_ERROR_TYPE_WARNING, "kill");
  if (GNUNET_OS_process_wait(learn_peer.arm_pid) != GNUNET_OK)
    GNUNET_log_strerror (GNUNET_ERROR_TYPE_WARNING, "waitpid");
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Hostlist client ARM process %u stopped\n", learn_peer.arm_pid);
#endif

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Shutting down scheduler\n");
  GNUNET_SCHEDULER_shutdown (sched);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Shutdown complete....\n");

}

/**
 * Timeout, give up.
 */
static void
timeout_error (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  timeout_task = GNUNET_SCHEDULER_NO_TASK;
  if (0 != (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN))
    return;
  GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
              "Timeout while executing testcase, test failed.\n");
  timeout = GNUNET_YES;
  shutdown_testcase();
}

static int
process_downloads (void *cls,
              const char *subsystem,
              const char *name,
              uint64_t value,
              int is_persistent)
{
  download_stats = NULL;
  if ( (value == 2) && (learned_hostlist_downloaded == GNUNET_NO) )
  {
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                _("Peer has successfully downloaded advertised URI \n"));
    learned_hostlist_downloaded = GNUNET_YES;
    shutdown_testcase();
  }
  return GNUNET_OK;
}

static int
process_uris_recv (void *cls,
              const char *subsystem,
              const char *name,
              uint64_t value,
              int is_persistent)
{
  urisrecv_stat = NULL;
  if ( ((struct PeerContext *) cls == &learn_peer) && (value == 1) && (learned_hostlist_saved == GNUNET_NO))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                _("Peer has successfully saved advertised URI \n"));
    learned_hostlist_saved = GNUNET_YES;
  }
  return GNUNET_OK;
}

static int
process_adv_sent (void *cls,
              const char *subsystem,
              const char *name,
              uint64_t value,
              int is_persistent)
{
  advsent_stat = NULL;
  if ( (value >= 1) && (adv_sent == GNUNET_NO))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                _("Server has successfully sent advertisement\n"));
    adv_sent = GNUNET_YES;
  }
  return GNUNET_OK;
}


/**
 * Check the server statistics regularly
 */
static void
check_statistics (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  char *stat;

  check_task = GNUNET_SCHEDULER_NO_TASK;
    if (0 != (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN))
      return;

  GNUNET_asprintf (&stat,
                   gettext_noop("# advertised URI `%s' downloaded"),
                   current_adv_uri);
  if ( NULL != learn_peer.stats)
  {
    download_stats = GNUNET_STATISTICS_get (learn_peer.stats,
                           "hostlist",
                           stat,
                           GNUNET_TIME_UNIT_MINUTES,
                           NULL,
                           &process_downloads,
                           &learn_peer);

    urisrecv_stat = GNUNET_STATISTICS_get (learn_peer.stats,
                           "hostlist",
                           gettext_noop("# advertised hostlist URIs"),
                           GNUNET_TIME_UNIT_MINUTES,
                           NULL,
                           &process_uris_recv,
                           &learn_peer);
  }
  GNUNET_free (stat);
  if ( NULL != adv_peer.stats)
  {
    advsent_stat = GNUNET_STATISTICS_get (adv_peer.stats,
                           "hostlist",
                           gettext_noop("# hostlist advertisements send"),
                           GNUNET_TIME_UNIT_MINUTES,
                           NULL,
                           &process_adv_sent,
                           NULL);
  }
  check_task = GNUNET_SCHEDULER_add_delayed (sched,
                                CHECK_INTERVALL,
                                &check_statistics,
                                NULL);
}

/**
 * Core handler for p2p hostlist advertisements
 */
static int ad_arrive_handler (void *cls,
                             const struct GNUNET_PeerIdentity * peer,
                             const struct GNUNET_MessageHeader * message,
                             struct GNUNET_TIME_Relative latency,
                             uint32_t distance)
{
  char *hostname;
  char *expected_uri = GNUNET_malloc (MAX_URL_LEN);

  unsigned long long port;
  size_t size;
  const struct GNUNET_MessageHeader * incoming;

  if (-1 == GNUNET_CONFIGURATION_get_value_number (adv_peer.cfg,
                                                   "HOSTLIST",
                                                   "HTTPPORT",
                                                   &port))
    {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Could not read advertising server's configuration\n" );
    if ( NULL != expected_uri ) GNUNET_free ( expected_uri );
    return GNUNET_SYSERR;
    }

  if ( GNUNET_SYSERR  == GNUNET_CONFIGURATION_get_value_string (adv_peer.cfg,
                                                   "HOSTLIST",
                                                   "EXTERNAL_DNS_NAME",
                                                   &hostname))
    hostname = GNUNET_RESOLVER_local_fqdn_get ();

  if (NULL != hostname)
    {
      size = strlen (hostname);
      if (size + 15 > MAX_URL_LEN)
        {
          GNUNET_break (0);
        }
      else
        {
          GNUNET_asprintf (&expected_uri,
                           "http://%s:%u/",
                           hostname,
                           (unsigned int) port);
        }
    }

  incoming = (const struct GNUNET_MessageHeader *) message;
  current_adv_uri = strdup ((char*) &incoming[1]);
  if ( 0 == strcmp( expected_uri, current_adv_uri ) )
  {
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                "Recieved hostlist advertisement with URI `%s' as expected\n", current_adv_uri);
    adv_arrived = GNUNET_YES;
    adv_sent = GNUNET_YES;
  }
  else
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Expected URI `%s' and recieved URI `%s' differ\n", expected_uri, current_adv_uri);
  GNUNET_free_non_null (expected_uri);
  GNUNET_free_non_null (hostname);
  return GNUNET_OK;
}

/**
 * List of handlers if we are learning.
 */
static struct GNUNET_CORE_MessageHandler learn_handlers[] = {
  { &ad_arrive_handler, GNUNET_MESSAGE_TYPE_HOSTLIST_ADVERTISEMENT, 0},
  { NULL, 0, 0 }
};

static void
setup_learn_peer (struct PeerContext *p, const char *cfgname)
{
  char * filename;
  unsigned int result;
  p->cfg = GNUNET_CONFIGURATION_create ();
#if START_ARM
  p->arm_pid = GNUNET_OS_start_process (NULL, NULL, "gnunet-service-arm",
                                        "gnunet-service-arm",
#if VERBOSE
                                        "-L", "DEBUG",
#endif
                                        "-c", cfgname, NULL);
#endif
  GNUNET_assert (GNUNET_OK == GNUNET_CONFIGURATION_load (p->cfg, cfgname));
  if (GNUNET_OK == GNUNET_CONFIGURATION_get_value_string (p->cfg,
                                                          "HOSTLIST",
                                                          "HOSTLISTFILE",
                                                          &filename))
  {
  if ( GNUNET_YES == GNUNET_DISK_file_test (filename) )
    {
      result = remove (filename);
      if (result == 0)
      GNUNET_log (GNUNET_ERROR_TYPE_INFO,
            _("Hostlist file `%s' was removed\n"),filename);
    }
  }
  if ( NULL != filename)  GNUNET_free ( filename );

  p->core = GNUNET_CORE_connect (sched, p->cfg,
                              GNUNET_TIME_UNIT_FOREVER_REL,
                              NULL,
                              NULL,
                              NULL, NULL,
                              NULL, GNUNET_NO,
                              NULL, GNUNET_NO,
                              learn_handlers );
  GNUNET_assert ( NULL != p->core );
  p->stats = GNUNET_STATISTICS_create (sched, "hostlist", p->cfg);
  GNUNET_assert ( NULL != p->stats );
}


static void
setup_adv_peer (struct PeerContext *p, const char *cfgname)
{

  p->cfg = GNUNET_CONFIGURATION_create ();
#if START_ARM
  p->arm_pid = GNUNET_OS_start_process (NULL, NULL, "gnunet-service-arm",
                                        "gnunet-service-arm",
#if VERBOSE
                                        "-L", "DEBUG",
#endif
                                        "-c", cfgname, NULL);
#endif
  GNUNET_assert (GNUNET_OK == GNUNET_CONFIGURATION_load (p->cfg, cfgname));
  p->stats = GNUNET_STATISTICS_create (sched, "hostlist", p->cfg);
  GNUNET_assert ( NULL != p->stats );

}

static void
run (void *cls,
     struct GNUNET_SCHEDULER_Handle *s,
     char *const *args,
     const char *cfgfile, 
     const struct GNUNET_CONFIGURATION_Handle *c)
{
  timeout = GNUNET_NO;
  adv_sent =GNUNET_NO;

  adv_arrived = 0;
  learned_hostlist_saved = GNUNET_NO;
  learned_hostlist_downloaded = GNUNET_NO;

  cfg = c;
  sched = s;

  setup_adv_peer (&adv_peer, "test_learning_adv_peer.conf");
  setup_learn_peer (&learn_peer, "test_learning_learn_peer.conf");
  timeout_task = GNUNET_SCHEDULER_add_delayed (sched,
                                               TIMEOUT,
                                               &timeout_error,
                                               NULL);

  check_task = GNUNET_SCHEDULER_add_delayed (sched,
                                CHECK_INTERVALL,
                                &check_statistics,
                                NULL);
}

static int
check ()
{
  unsigned int failed;
  char *const argv[] = { "test-gnunet-daemon-hostlist-learning",
    "-c", "learning_data.conf",
#if VERBOSE
    "-L", "DEBUG",
#endif
    NULL
  };
  struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_OPTION_END
  };

  GNUNET_PROGRAM_run ((sizeof (argv) / sizeof (char *)) - 1,
                      argv, "test-gnunet-daemon-hostlist-learning",
                      "nohelp", options, &run, NULL);

  failed = GNUNET_NO;

  if (learned_hostlist_downloaded == GNUNET_YES)
    return GNUNET_YES;

  if (timeout == GNUNET_YES)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Testcase could not set up two communicating peers, timeout\n");
    failed = GNUNET_YES;
  }
  if (adv_arrived != GNUNET_YES)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Learning peer did not receive advertisement from server\n");
    failed = GNUNET_YES;
  }
  if ( learned_hostlist_saved == GNUNET_NO )
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  "Peer1: Advertised hostlist was not saved in datastore\n");
      failed = GNUNET_YES;
    }
  if (learned_hostlist_downloaded == GNUNET_NO)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Peer1: Advertised hostlist could not be downloaded from server\n");
    failed = GNUNET_YES;
  }
  if (adv_sent == GNUNET_NO)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Advertised was not sent from server to client\n");
    failed = GNUNET_YES;
  }
  if ( GNUNET_YES == failed )
    return GNUNET_YES;
  else
    return GNUNET_NO;
}

int
main (int argc, char *argv[])
{
  
  int ret;

  GNUNET_DISK_directory_remove ("/tmp/test-gnunetd-hostlist-peer-1");
  GNUNET_DISK_directory_remove ("/tmp/test-gnunetd-hostlist-peer-2");
  GNUNET_log_setup ("test-gnunet-daemon-hostlist",
#if VERBOSE
                    "DEBUG",
#else
                    "WARNING",
#endif
                    NULL);
  ret = check ();
  GNUNET_DISK_directory_remove ("/tmp/test-gnunetd-hostlist-peer-1");
  GNUNET_DISK_directory_remove ("/tmp/test-gnunetd-hostlist-peer-2");
  if ( GNUNET_YES == GNUNET_DISK_file_test ("hostlists_learn_peer.file") )
    {
      if ( remove ("hostlists_learn_peer.file")  == 0)
      GNUNET_log (GNUNET_ERROR_TYPE_INFO,
            _("Hostlist file hostlists_learn_peer.file was removed\n"));
    }
  return ret; 
}

/* end of test_gnunet_daemon_hostlist.c */

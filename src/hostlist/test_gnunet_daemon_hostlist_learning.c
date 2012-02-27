/*
     This file is part of GNUnet
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

#define VERBOSE GNUNET_NO

#define START_ARM GNUNET_YES

#define MAX_URL_LEN 1000

/**
 * How long until wait until testcases fails
 */
#define TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 180)

#define CHECK_INTERVALL GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 1)


struct PeerContext
{
  struct GNUNET_CONFIGURATION_Handle *cfg;
  struct GNUNET_TRANSPORT_Handle *th;
  struct GNUNET_MessageHeader *hello;
  struct GNUNET_CORE_Handle *core;
  struct GNUNET_STATISTICS_Handle *stats;
#if START_ARM
  struct GNUNET_OS_Process *arm_proc;
#endif
};

static int timeout;

static int adv_sent;

static int adv_arrived;

static int learned_hostlist_saved;

static int learned_hostlist_downloaded;

static char *current_adv_uri;

static const struct GNUNET_CONFIGURATION_Handle *cfg;

static GNUNET_SCHEDULER_TaskIdentifier timeout_task;

static GNUNET_SCHEDULER_TaskIdentifier check_task;

static struct PeerContext adv_peer;

static struct PeerContext learn_peer;

static struct GNUNET_STATISTICS_GetHandle *download_stats;

static struct GNUNET_STATISTICS_GetHandle *urisrecv_stat;

static struct GNUNET_STATISTICS_GetHandle *advsent_stat;


static void
shutdown_testcase ()
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Shutdown testcase....\n");
  if (timeout_task != GNUNET_SCHEDULER_NO_TASK)
  {
    GNUNET_SCHEDULER_cancel (timeout_task);
    timeout_task = GNUNET_SCHEDULER_NO_TASK;
  }
  if (NULL != download_stats)
  {
    GNUNET_STATISTICS_get_cancel (download_stats);
    download_stats = NULL;
  }
  if (NULL != urisrecv_stat)
  {
    GNUNET_STATISTICS_get_cancel (urisrecv_stat);
    urisrecv_stat = NULL;
  }
  if (NULL != advsent_stat)
  {
    GNUNET_STATISTICS_get_cancel (advsent_stat);
    advsent_stat = NULL;
  }
  if (check_task != GNUNET_SCHEDULER_NO_TASK)
  {
    GNUNET_SCHEDULER_cancel (check_task);
    check_task = GNUNET_SCHEDULER_NO_TASK;
  }
  if (NULL != current_adv_uri)
  {
    GNUNET_free (current_adv_uri);
    current_adv_uri = NULL;
  }
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
#if START_ARM
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Killing hostlist server ARM process.\n");
  if (0 != GNUNET_OS_process_kill (adv_peer.arm_proc, SIGTERM))
    GNUNET_log_strerror (GNUNET_ERROR_TYPE_WARNING, "kill");
  if (GNUNET_OS_process_wait (adv_peer.arm_proc) != GNUNET_OK)
    GNUNET_log_strerror (GNUNET_ERROR_TYPE_WARNING, "waitpid");
  GNUNET_OS_process_close (adv_peer.arm_proc);
  adv_peer.arm_proc = NULL;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Killing hostlist client ARM process.\n");
  if (0 != GNUNET_OS_process_kill (learn_peer.arm_proc, SIGTERM))
    GNUNET_log_strerror (GNUNET_ERROR_TYPE_WARNING, "kill");
  if (GNUNET_OS_process_wait (learn_peer.arm_proc) != GNUNET_OK)
    GNUNET_log_strerror (GNUNET_ERROR_TYPE_WARNING, "waitpid");
  GNUNET_OS_process_close (learn_peer.arm_proc);
  learn_peer.arm_proc = NULL;
#endif
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Shutdown complete....\n");
}

/**
 * Timeout, give up.
 */
static void
timeout_error (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  timeout_task = GNUNET_SCHEDULER_NO_TASK;
  GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
              "Timeout while executing testcase, test failed.\n");
  timeout = GNUNET_YES;
  shutdown_testcase ();
}


static void
process_downloads_done (void *cls, int success)
{
  download_stats = NULL;
}


static int
process_downloads (void *cls, const char *subsystem, const char *name,
                   uint64_t value, int is_persistent)
{
  if ((value >= 2) && (learned_hostlist_downloaded == GNUNET_NO))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                "Peer has successfully downloaded advertised URI\n");
    learned_hostlist_downloaded = GNUNET_YES;
    if ((learned_hostlist_saved == GNUNET_YES) && (adv_sent == GNUNET_YES))
      shutdown_testcase ();
  }
  return GNUNET_OK;
}


static void
process_uris_recv_done (void *cls, int success)
{
  urisrecv_stat = NULL;
}


static int
process_uris_recv (void *cls, const char *subsystem, const char *name,
                   uint64_t value, int is_persistent)
{
  if (((struct PeerContext *) cls == &learn_peer) && (value == 1) &&
      (learned_hostlist_saved == GNUNET_NO))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                "Peer has successfully saved advertised URI\n");
    learned_hostlist_saved = GNUNET_YES;
    if ((learned_hostlist_downloaded == GNUNET_YES) && (adv_sent == GNUNET_YES))
      shutdown_testcase ();
  }
  return GNUNET_OK;
}


static void
process_adv_sent_done (void *cls, int success)
{
  advsent_stat = NULL;
}


static int
process_adv_sent (void *cls, const char *subsystem, const char *name,
                  uint64_t value, int is_persistent)
{
  if ((value >= 1) && (adv_sent == GNUNET_NO))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                "Server has successfully sent advertisement\n");
    adv_sent = GNUNET_YES;
    if ((learned_hostlist_downloaded == GNUNET_YES) &&
        (learned_hostlist_saved == GNUNET_YES))
      shutdown_testcase ();
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
  GNUNET_asprintf (&stat, gettext_noop ("# advertised URI `%s' downloaded"),
                   current_adv_uri);
  if (NULL != learn_peer.stats)
  {
    if (NULL != download_stats)
      GNUNET_STATISTICS_get_cancel (download_stats);
    download_stats =
        GNUNET_STATISTICS_get (learn_peer.stats, "hostlist", stat,
                               GNUNET_TIME_UNIT_MINUTES,
                               &process_downloads_done, &process_downloads,
                               &learn_peer);
    if (NULL != urisrecv_stat)
      GNUNET_STATISTICS_get_cancel (urisrecv_stat);
    urisrecv_stat =
        GNUNET_STATISTICS_get (learn_peer.stats, "hostlist",
                               gettext_noop ("# advertised hostlist URIs"),
                               GNUNET_TIME_UNIT_MINUTES,
                               &process_uris_recv_done, &process_uris_recv,
                               &learn_peer);
  }
  GNUNET_free (stat);
  if (NULL != adv_peer.stats)
  {
    if (NULL != advsent_stat)
      GNUNET_STATISTICS_get_cancel (advsent_stat);
    advsent_stat =
        GNUNET_STATISTICS_get (adv_peer.stats, "hostlist",
                               gettext_noop ("# hostlist advertisements send"),
                               GNUNET_TIME_UNIT_MINUTES, &process_adv_sent_done,
                               &process_adv_sent, NULL);
  }
  check_task =
      GNUNET_SCHEDULER_add_delayed (CHECK_INTERVALL, &check_statistics, NULL);
}


/**
 * Core handler for p2p hostlist advertisements
 */
static int
ad_arrive_handler (void *cls, const struct GNUNET_PeerIdentity *peer,
                   const struct GNUNET_MessageHeader *message,
                   const struct GNUNET_ATS_Information *atsi,
                   unsigned int atsi_count)
{
  char *hostname;
  char *expected_uri;
  unsigned long long port;
  const struct GNUNET_MessageHeader *incoming;
  const char *end;

  if (-1 ==
      GNUNET_CONFIGURATION_get_value_number (adv_peer.cfg, "HOSTLIST",
                                             "HTTPPORT", &port))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Could not read advertising server's configuration\n");
    return GNUNET_SYSERR;
  }

  if (GNUNET_SYSERR ==
      GNUNET_CONFIGURATION_get_value_string (adv_peer.cfg, "HOSTLIST",
                                             "EXTERNAL_DNS_NAME", &hostname))
    hostname = GNUNET_RESOLVER_local_fqdn_get ();
  GNUNET_asprintf (&expected_uri, "http://%s:%u/",
                   hostname != NULL ? hostname : "localhost",
                   (unsigned int) port);
  incoming = (const struct GNUNET_MessageHeader *) message;
  end = (const char *) &incoming[1];
  if ('\0' !=
      end[ntohs (message->size) - sizeof (struct GNUNET_MessageHeader) - 1])
  {
    GNUNET_break (0);
    GNUNET_free (expected_uri);
    GNUNET_free_non_null (hostname);
    return GNUNET_SYSERR;
  }
  current_adv_uri = GNUNET_strdup (end);
  if (0 == strcmp (expected_uri, current_adv_uri))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                "Received hostlist advertisement with URI `%s' as expected\n",
                current_adv_uri);
    adv_arrived = GNUNET_YES;
    adv_sent = GNUNET_YES;
  }
  else
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Expected URI `%s' and recieved URI `%s' differ\n",
                expected_uri, current_adv_uri);
  GNUNET_free (expected_uri);
  GNUNET_free_non_null (hostname);
  return GNUNET_OK;
}


/**
 * List of handlers if we are learning.
 */
static struct GNUNET_CORE_MessageHandler learn_handlers[] = {
  {&ad_arrive_handler, GNUNET_MESSAGE_TYPE_HOSTLIST_ADVERTISEMENT, 0},
  {NULL, 0, 0}
};


static void
setup_learn_peer (struct PeerContext *p, const char *cfgname)
{
  char *filename;
  unsigned int result;

  p->cfg = GNUNET_CONFIGURATION_create ();
#if START_ARM
  p->arm_proc =
    GNUNET_OS_start_process (GNUNET_YES, NULL, NULL, "gnunet-service-arm",
                               "gnunet-service-arm",
#if VERBOSE
                               "-L", "DEBUG",
#endif
                               "-c", cfgname, NULL);
#endif
  GNUNET_assert (GNUNET_OK == GNUNET_CONFIGURATION_load (p->cfg, cfgname));
  if (GNUNET_OK ==
      GNUNET_CONFIGURATION_get_value_string (p->cfg, "HOSTLIST", "HOSTLISTFILE",
                                             &filename))
  {
    if (GNUNET_YES == GNUNET_DISK_file_test (filename))
    {
      result = UNLINK (filename);
      if (result == 0)
        GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                    _("Hostlist file `%s' was removed\n"), filename);
    }
    GNUNET_free (filename);
  }
  p->core =
      GNUNET_CORE_connect (p->cfg, 1, NULL, NULL, NULL, NULL, NULL, GNUNET_NO,
                           NULL, GNUNET_NO, learn_handlers);
  GNUNET_assert (NULL != p->core);
  p->stats = GNUNET_STATISTICS_create ("hostlist", p->cfg);
  GNUNET_assert (NULL != p->stats);
}


static void
setup_adv_peer (struct PeerContext *p, const char *cfgname)
{
  p->cfg = GNUNET_CONFIGURATION_create ();
#if START_ARM
  p->arm_proc =
    GNUNET_OS_start_process (GNUNET_YES, NULL, NULL, "gnunet-service-arm",
                               "gnunet-service-arm",
#if VERBOSE
                               "-L", "DEBUG",
#endif
                               "-c", cfgname, NULL);
#endif
  GNUNET_assert (GNUNET_OK == GNUNET_CONFIGURATION_load (p->cfg, cfgname));
  p->stats = GNUNET_STATISTICS_create ("hostlist", p->cfg);
  GNUNET_assert (NULL != p->stats);
}


static void
run (void *cls, char *const *args, const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *c)
{
  timeout = GNUNET_NO;
  adv_sent = GNUNET_NO;

  adv_arrived = 0;
  learned_hostlist_saved = GNUNET_NO;
  learned_hostlist_downloaded = GNUNET_NO;

  cfg = c;

  setup_adv_peer (&adv_peer, "test_learning_adv_peer.conf");
  setup_learn_peer (&learn_peer, "test_learning_learn_peer.conf");
  timeout_task = GNUNET_SCHEDULER_add_delayed (TIMEOUT, &timeout_error, NULL);

  check_task =
      GNUNET_SCHEDULER_add_delayed (CHECK_INTERVALL, &check_statistics, NULL);
}


static int
check ()
{
  unsigned int failed;

  char *const argv[] = {
    "test-gnunet-daemon-hostlist-learning",
    "-c", "learning_data.conf",
#if VERBOSE
    "-L", "DEBUG",
#endif
    NULL
  };
  struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_OPTION_END
  };

  GNUNET_PROGRAM_run ((sizeof (argv) / sizeof (char *)) - 1, argv,
                      "test-gnunet-daemon-hostlist-learning", "nohelp", options,
                      &run, NULL);
  failed = GNUNET_NO;
  if (timeout == GNUNET_YES)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Testcase timeout\n");
    failed = GNUNET_YES;
  }
  if (adv_arrived != GNUNET_YES)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Learning peer did not receive advertisement from server\n");
    failed = GNUNET_YES;
  }
  if (learned_hostlist_saved == GNUNET_NO)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Advertised hostlist was not saved in datastore\n");
    failed = GNUNET_YES;
  }
  if (learned_hostlist_downloaded == GNUNET_NO)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Advertised hostlist could not be downloaded from server\n");
    failed = GNUNET_YES;
  }
  if (adv_sent == GNUNET_NO)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Advertised was not sent from server to client\n");
    failed = GNUNET_YES;
  }
  if (GNUNET_YES == failed)
    return GNUNET_YES;
  return GNUNET_NO;
}


int
main (int argc, char *argv[])
{
  int ret;

  GNUNET_DISK_directory_remove ("/tmp/test-gnunet-hostlist-peer-1");
  GNUNET_DISK_directory_remove ("/tmp/test-gnunet-hostlist-peer-2");
  GNUNET_log_setup ("test-gnunet-daemon-hostlist",
#if VERBOSE
                    "DEBUG",
#else
                    "WARNING",
#endif
                    NULL);
#if !WINDOWS
  system ("gnunet-peerinfo -s -c test_learning_adv_peer.conf > /dev/null");
  system ("gnunet-peerinfo -s -c test_learning_learn_peer.conf > /dev/null");
#else
  system ("gnunet-peerinfo -s -c test_learning_adv_peer.conf > NUL");
  system ("gnunet-peerinfo -s -c test_learning_learn_peer.conf > NUL");
#endif
  ret = check ();
  GNUNET_DISK_directory_remove ("/tmp/test-gnunet-hostlist-peer-1");
  GNUNET_DISK_directory_remove ("/tmp/test-gnunet-hostlist-peer-2");
  if (GNUNET_YES == GNUNET_DISK_file_test ("hostlists_learn_peer.file"))
  {
    if (0 == UNLINK ("hostlists_learn_peer.file"))
      GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                  "Hostlist file hostlists_learn_peer.file was removed\n");
  }
  return ret;
}

/* end of test_gnunet_daemon_hostlist.c */

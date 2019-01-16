/*
     This file is part of GNUnet
     Copyright (C) 2009, 2010, 2011, 2012, 2016 GNUnet e.V.

     GNUnet is free software: you can redistribute it and/or modify it
     under the terms of the GNU Affero General Public License as published
     by the Free Software Foundation, either version 3 of the License,
     or (at your option) any later version.

     GNUnet is distributed in the hope that it will be useful, but
     WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
     Affero General Public License for more details.
    
     You should have received a copy of the GNU Affero General Public License
     along with this program.  If not, see <http://www.gnu.org/licenses/>.

     SPDX-License-Identifier: AGPL3.0-or-later
*/
/**
 * @file hostlist/test_gnunet_daemon_hostlist_learning.c
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

#define MAX_URL_LEN 1000

/**
 * How long until wait until testcases fails
 */
#define TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 180)

#define CHECK_INTERVAL GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 1)


struct PeerContext
{
  struct GNUNET_CONFIGURATION_Handle *cfg;
  struct GNUNET_MessageHeader *hello;
  struct GNUNET_CORE_Handle *core;
  struct GNUNET_STATISTICS_Handle *stats;
  struct GNUNET_OS_Process *arm_proc;
};

static int timeout;

static int adv_sent;

static int adv_arrived;

static int learned_hostlist_saved;

static int learned_hostlist_downloaded;

static char *current_adv_uri;

static const struct GNUNET_CONFIGURATION_Handle *cfg;

static struct GNUNET_SCHEDULER_Task *timeout_task;

static struct GNUNET_SCHEDULER_Task *check_task;

static struct PeerContext adv_peer;

static struct PeerContext learn_peer;

static struct GNUNET_STATISTICS_GetHandle *download_stats;

static struct GNUNET_STATISTICS_GetHandle *urisrecv_stat;

static struct GNUNET_STATISTICS_GetHandle *advsent_stat;


static void
shutdown_testcase ()
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Shutdown testcase....\n");
  if (NULL != timeout_task)
  {
    GNUNET_SCHEDULER_cancel (timeout_task);
    timeout_task = NULL;
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
  if (NULL != adv_peer.stats)
  {
    GNUNET_STATISTICS_destroy (adv_peer.stats, GNUNET_NO);
    adv_peer.stats = NULL;
  }
  if (NULL != learn_peer.stats)
  {
    GNUNET_STATISTICS_destroy (learn_peer.stats, GNUNET_NO);
    learn_peer.stats = NULL;
  }
  if (NULL != check_task)
  {
    GNUNET_SCHEDULER_cancel (check_task);
    check_task = NULL;
  }
  if (NULL != current_adv_uri)
  {
    GNUNET_free (current_adv_uri);
    current_adv_uri = NULL;
  }
  if (NULL != adv_peer.core)
  {
    GNUNET_CORE_disconnect (adv_peer.core);
    adv_peer.core = NULL;
  }
  if (NULL != learn_peer.core)
  {
    GNUNET_CORE_disconnect (learn_peer.core);
    learn_peer.core = NULL;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Killing hostlist server ARM process.\n");
  if (0 != GNUNET_OS_process_kill (adv_peer.arm_proc,
				   GNUNET_TERM_SIG))
    GNUNET_log_strerror (GNUNET_ERROR_TYPE_WARNING,
			 "kill");
  if (GNUNET_OK !=
      GNUNET_OS_process_wait (adv_peer.arm_proc))
    GNUNET_log_strerror (GNUNET_ERROR_TYPE_WARNING,
			 "waitpid");
  GNUNET_OS_process_destroy (adv_peer.arm_proc);
  adv_peer.arm_proc = NULL;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Killing hostlist client ARM process.\n");
  if (0 != GNUNET_OS_process_kill (learn_peer.arm_proc,
				   GNUNET_TERM_SIG))
    GNUNET_log_strerror (GNUNET_ERROR_TYPE_WARNING,
			 "kill");
  if (GNUNET_OK !=
      GNUNET_OS_process_wait (learn_peer.arm_proc))
    GNUNET_log_strerror (GNUNET_ERROR_TYPE_WARNING,
			 "waitpid");
  GNUNET_OS_process_destroy (learn_peer.arm_proc);
  learn_peer.arm_proc = NULL;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Shutdown complete....\n");
}


/**
 * Timeout, give up.
 */
static void
timeout_error (void *cls)
{
  timeout_task = NULL;
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


static void
do_shutdown (void *cls)
{
  shutdown_testcase ();
}


static int
process_downloads (void *cls,
		   const char *subsystem,
		   const char *name,
                   uint64_t value,
		   int is_persistent)
{
  if ( (value >= 2) &&
       (GNUNET_NO == learned_hostlist_downloaded) )
  {
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                "Peer has successfully downloaded advertised URI\n");
    learned_hostlist_downloaded = GNUNET_YES;
    if ((learned_hostlist_saved == GNUNET_YES) && (adv_sent == GNUNET_YES))
    {
      GNUNET_SCHEDULER_add_now (&do_shutdown, NULL);
    }
  }
  return GNUNET_OK;
}


static void
process_uris_recv_done (void *cls, int success)
{
  urisrecv_stat = NULL;
}


static int
process_uris_recv (void *cls,
		   const char *subsystem,
		   const char *name,
                   uint64_t value,
		   int is_persistent)
{
  struct PeerContext *pc = cls;
  if ( (pc == &learn_peer) &&
       (value == 1) &&
       (learned_hostlist_saved == GNUNET_NO) )
  {
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                "Peer has successfully saved advertised URI\n");
    learned_hostlist_saved = GNUNET_YES;
    if ( (learned_hostlist_downloaded == GNUNET_YES) &&
	 (adv_sent == GNUNET_YES) )
    {
      GNUNET_SCHEDULER_add_now (&do_shutdown,
				NULL);
    }
  }
  return GNUNET_OK;
}


static void
process_adv_sent_done (void *cls, int success)
{
  advsent_stat = NULL;
}


static int
process_adv_sent (void *cls,
		  const char *subsystem,
		  const char *name,
                  uint64_t value,
		  int is_persistent)
{
  if ((value >= 1) && (adv_sent == GNUNET_NO))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                "Server has successfully sent advertisement\n");
    adv_sent = GNUNET_YES;
    if ((learned_hostlist_downloaded == GNUNET_YES) &&
        (learned_hostlist_saved == GNUNET_YES))
    {
      GNUNET_SCHEDULER_add_now (&do_shutdown,
				NULL);
    }
  }
  return GNUNET_OK;
}


/**
 * Check the server statistics regularly
 */
static void
check_statistics (void *cls)
{
  char *stat;

  check_task = NULL;
  GNUNET_asprintf (&stat,
		   gettext_noop ("# advertised URI `%s' downloaded"),
                   current_adv_uri);
  if (NULL != learn_peer.stats)
  {
    if (NULL != download_stats)
      GNUNET_STATISTICS_get_cancel (download_stats);
    download_stats =
        GNUNET_STATISTICS_get (learn_peer.stats,
			       "hostlist",
			       stat,
                               &process_downloads_done,
			       &process_downloads,
                               &learn_peer);
    if (NULL != urisrecv_stat)
      GNUNET_STATISTICS_get_cancel (urisrecv_stat);
    urisrecv_stat =
        GNUNET_STATISTICS_get (learn_peer.stats, "hostlist",
                               gettext_noop ("# advertised hostlist URIs"),
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
                               &process_adv_sent_done,
                               &process_adv_sent,
			       NULL);
  }
  check_task =
      GNUNET_SCHEDULER_add_delayed (CHECK_INTERVAL,
				    &check_statistics,
				    NULL);
}


static int
check_ad_arrive (void *cls,
		 const struct GNUNET_MessageHeader *message)
{
  const char *end = (const char *) &message[1];
  if ('\0' != end[ntohs (message->size) - sizeof (struct GNUNET_MessageHeader) - 1])
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


static void
handle_ad_arrive (void *cls,
                   const struct GNUNET_MessageHeader *message)
{
  char *hostname;
  char *expected_uri;
  unsigned long long port;
  const char *end;

  if (GNUNET_SYSERR ==
      GNUNET_CONFIGURATION_get_value_number (adv_peer.cfg,
					     "HOSTLIST",
                                             "HTTPPORT",
					     &port))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Could not read advertising server's configuration\n");
    return;
  }

  if (GNUNET_SYSERR ==
      GNUNET_CONFIGURATION_get_value_string (adv_peer.cfg,
					     "HOSTLIST",
                                             "EXTERNAL_DNS_NAME",
					     &hostname))
    hostname = GNUNET_RESOLVER_local_fqdn_get ();
  GNUNET_asprintf (&expected_uri,
		   "http://%s:%u/",
                   hostname != NULL ? hostname : "localhost",
                   (unsigned int) port);
  end = (const char *) &message[1];
  current_adv_uri = GNUNET_strdup (end);
  if (0 == strcmp (expected_uri,
		   current_adv_uri))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                "Received hostlist advertisement with URI `%s' as expected\n",
                current_adv_uri);
    adv_arrived = GNUNET_YES;
    adv_sent = GNUNET_YES;
  }
  else
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Expected URI `%s' and received URI `%s' differ\n",
                expected_uri,
		current_adv_uri);
  GNUNET_free (expected_uri);
  GNUNET_free_non_null (hostname);
}


static void
setup_learn_peer (struct PeerContext *p,
		  const char *cfgname)
{
  struct GNUNET_MQ_MessageHandler learn_handlers[] = {
    GNUNET_MQ_hd_var_size (ad_arrive,
                           GNUNET_MESSAGE_TYPE_HOSTLIST_ADVERTISEMENT,
                           struct GNUNET_MessageHeader,
                           NULL),
    GNUNET_MQ_handler_end ()
  };
  char *filename;
  unsigned int result;
  char *binary;

  binary = GNUNET_OS_get_libexec_binary_path ("gnunet-service-arm");
  p->cfg = GNUNET_CONFIGURATION_create ();
  p->arm_proc =
    GNUNET_OS_start_process (GNUNET_YES, GNUNET_OS_INHERIT_STD_OUT_AND_ERR,
                             NULL, NULL, NULL,
                             binary,
                             "gnunet-service-arm",
                             "-c", cfgname, NULL);
  GNUNET_assert (GNUNET_OK ==
		 GNUNET_CONFIGURATION_load (p->cfg,
					    cfgname));
  if (GNUNET_OK ==
      GNUNET_CONFIGURATION_get_value_string (p->cfg,
					     "HOSTLIST",
					     "HOSTLISTFILE",
                                             &filename))
  {
    if (GNUNET_YES == GNUNET_DISK_file_test (filename))
    {
      result = UNLINK (filename);
      if (result == 0)
        GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                    _("Hostlist file `%s' was removed\n"),
		    filename);
    }
    GNUNET_free (filename);
  }
  p->core = GNUNET_CORE_connect (p->cfg,
				 NULL,
				 NULL,
				 NULL,
				 NULL,
				 learn_handlers);
  GNUNET_assert (NULL != p->core);
  p->stats = GNUNET_STATISTICS_create ("hostlist",
				       p->cfg);
  GNUNET_assert (NULL != p->stats);
  GNUNET_free (binary);
}


static void
setup_adv_peer (struct PeerContext *p,
		const char *cfgname)
{
  char *binary;

  binary = GNUNET_OS_get_libexec_binary_path ("gnunet-service-arm");
  p->cfg = GNUNET_CONFIGURATION_create ();
  p->arm_proc =
    GNUNET_OS_start_process (GNUNET_YES,
			     GNUNET_OS_INHERIT_STD_OUT_AND_ERR,
                             NULL, NULL, NULL,
                             binary,
			     "gnunet-service-arm",
			     "-c", cfgname, NULL);
  GNUNET_assert (GNUNET_OK ==
		 GNUNET_CONFIGURATION_load (p->cfg,
					    cfgname));
  p->stats = GNUNET_STATISTICS_create ("hostlist", p->cfg);
  GNUNET_assert (NULL != p->stats);
  GNUNET_free (binary);
}


static void
run (void *cls,
     char *const *args,
     const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *c)
{
  timeout = GNUNET_NO;
  adv_sent = GNUNET_NO;

  adv_arrived = 0;
  learned_hostlist_saved = GNUNET_NO;
  learned_hostlist_downloaded = GNUNET_NO;

  cfg = c;

  setup_adv_peer (&adv_peer,
		  "test_learning_adv_peer.conf");
  setup_learn_peer (&learn_peer,
		    "test_learning_learn_peer.conf");
  timeout_task = GNUNET_SCHEDULER_add_delayed (TIMEOUT,
					       &timeout_error,
					       NULL);
  check_task =
      GNUNET_SCHEDULER_add_delayed (CHECK_INTERVAL,
				    &check_statistics,
				    NULL);
}


static int
check ()
{
  unsigned int failed;

  char *const argv[] = {
    "test-gnunet-daemon-hostlist-learning",
    "-c", "learning_data.conf",
    NULL
  };
  struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_OPTION_END
  };

  GNUNET_PROGRAM_run ((sizeof (argv) / sizeof (char *)) - 1,
		      argv,
                      "test-gnunet-daemon-hostlist-learning",
		      "nohelp",
		      options,
                      &run,
		      NULL);
  failed = GNUNET_NO;
  if (timeout == GNUNET_YES)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		"Testcase timeout\n");
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

  GNUNET_DISK_purge_cfg_dir ("test_learning_learn_peer.conf",
                             "GNUNET_TEST_HOME");
  GNUNET_DISK_purge_cfg_dir ("test_learning_adv_peer.conf",
                             "GNUNET_TEST_HOME");
  GNUNET_log_setup ("test-gnunet-daemon-hostlist",
                    "WARNING",
                    NULL);
  ret = check ();
  GNUNET_DISK_purge_cfg_dir ("test_learning_learn_peer.conf",
                             "GNUNET_TEST_HOME");
  GNUNET_DISK_purge_cfg_dir ("test_learning_adv_peer.conf",
                             "GNUNET_TEST_HOME");
  if (GNUNET_YES ==
      GNUNET_DISK_file_test ("hostlists_learn_peer.file"))
  {
    if (0 == UNLINK ("hostlists_learn_peer.file"))
      GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                  "Hostlist file hostlists_learn_peer.file was removed\n");
  }
  return ret;
}

/* end of test_gnunet_daemon_hostlist_learning.c */

/*
     This file is part of GNUnet.
     (C) 2010 Christian Grothoff (and other contributing authors)

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
 * @file fs/test_fs_lib.c
 * @brief library routines for testing FS publishing and downloading
 *        with multiple peers; this code is limited to flat files
 *        and no keywords (those functions can be tested with
 *        single-peer setups; this is for testing routing).
 * @author Christian Grothoff
 */
#include "platform.h"
#include "test_fs_lib.h"
#include "gnunet_testing_lib.h"


/**
 * Handle for a daemon started for testing FS.
 */
struct GNUNET_FS_TestDaemon
{

  /**
   * Handle to the file sharing context using this daemon.
   */
  struct GNUNET_FS_Handle *fs;

  /**
   * Handle to the daemon via testing.
   */
  struct GNUNET_TESTING_Daemon *daemon;

  /**
   * Note that 'group' will be the same value for all of the
   * daemons started jointly.
   */
  struct GNUNET_TESTING_PeerGroup *group;

  /**
   * Configuration for accessing this peer.
   */
  struct GNUNET_CONFIGURATION_Handle *cfg;

  /**
   * ID of this peer.
   */
  struct GNUNET_PeerIdentity id;

  /**
   * Function to call when upload is done.
   */
  GNUNET_FS_TEST_UriContinuation publish_cont;
  
  /**
   * Closure for publish_cont.
   */
  void *publish_cont_cls;

  /**
   * Task to abort publishing (timeout).
   */
  GNUNET_SCHEDULER_TaskIdentifier publish_timeout_task;

  /**
   * Scheduler to use (for download_cont).
   */
  struct GNUNET_SCHEDULER_Handle *download_sched;

  /**
   * Function to call when download is done.
   */
  GNUNET_SCHEDULER_Task download_cont;

  /**
   * Closure for download_cont.
   */
  void *download_cont_cls;

  /**
   * Seed for download verification.
   */
  uint32_t download_seed;

  /**
   * Task to abort downloading (timeout).
   */
  GNUNET_SCHEDULER_TaskIdentifier download_timeout_task;

  /**
   * Verbosity level of the current operation.
   */
  int verbose;

		
};


static void*
progress_cb (void *cls,
	     const struct GNUNET_FS_ProgressInfo *info)
{
  struct GNUNET_FS_TestDaemon *daemon = cls;

  if (daemon->verbose > 2)
    {
      
    }
  return NULL;
}



struct StartContext
{
  struct GNUNET_SCHEDULER_Handle *sched;
  struct GNUNET_TIME_Relative timeout;
  unsigned int total;
  unsigned int have;
  struct GNUNET_FS_TestDaemon **daemons;
  GNUNET_SCHEDULER_Task cont;
  void *cont_cls;
  struct GNUNET_TESTING_PeerGroup *group;
  struct GNUNET_CONFIGURATION_Handle *cfg;
  GNUNET_SCHEDULER_TaskIdentifier timeout_task;
};


static void 
notify_running (void *cls,
		const struct GNUNET_PeerIdentity *id,
		const struct GNUNET_CONFIGURATION_Handle *cfg,
		struct GNUNET_TESTING_Daemon *d,
		const char *emsg)
{
  struct StartContext *sctx = cls;
  unsigned int i;

  if (emsg != NULL)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		  _("Failed to start daemon: %s\n"),
		  emsg);
      return;
    }
  GNUNET_assert (sctx->have < sctx->total);
  sctx->daemons[sctx->have]->cfg = GNUNET_CONFIGURATION_dup (cfg);
  sctx->daemons[sctx->have]->group = sctx->group;
  sctx->daemons[sctx->have]->daemon = d;
  sctx->daemons[sctx->have]->id = *id;
  sctx->have++;
  if (sctx->have == sctx->total)
    {
      GNUNET_SCHEDULER_add_continuation (sctx->sched,
					 sctx->cont,
					 sctx->cont_cls,
					 GNUNET_SCHEDULER_REASON_PREREQ_DONE);
      GNUNET_CONFIGURATION_destroy (sctx->cfg);
      GNUNET_SCHEDULER_cancel (sctx->sched,
			       sctx->timeout_task);
      for (i=0;i<sctx->total;i++)
	sctx->daemons[i]->fs = GNUNET_FS_start (sctx->sched,
						sctx->daemons[i]->cfg,
						"<tester>",
						&progress_cb,
						sctx->daemons[i],
						GNUNET_FS_FLAGS_NONE,
						GNUNET_FS_OPTIONS_END);
      GNUNET_free (sctx);
    }
}


static void
start_timeout (void *cls,
	       const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct StartContext *sctx = cls;
  unsigned int i;

  GNUNET_TESTING_daemons_stop (sctx->group);
  for (i=0;i<sctx->total;i++)
    {
      if (i < sctx->have)
	GNUNET_CONFIGURATION_destroy (sctx->daemons[i]->cfg);
      GNUNET_free (sctx->daemons[i]);
    }
  GNUNET_CONFIGURATION_destroy (sctx->cfg);
  GNUNET_SCHEDULER_add_continuation (sctx->sched,
				     sctx->cont,
				     sctx->cont_cls,
				     GNUNET_SCHEDULER_REASON_TIMEOUT);
  GNUNET_free (sctx);
}


/**
 * Start daemons for testing.
 *
 * @param sched scheduler to use
 * @param timeout if this operation cannot be completed within the
 *                given period, call the continuation with an error code
 * @param total number of daemons to start
 * @param daemons array of 'total' entries to be initialized
 *                (array must already be allocated, will be filled)
 * @param cont function to call when done
 * @param cont_cls closure for cont
 */
void
GNUNET_FS_TEST_daemons_start (struct GNUNET_SCHEDULER_Handle *sched,
			      struct GNUNET_TIME_Relative timeout,
			      unsigned int total,
			      struct GNUNET_FS_TestDaemon **daemons,
			      GNUNET_SCHEDULER_Task cont,
			      void *cont_cls)
{
  struct StartContext *sctx;
  unsigned int i;

  GNUNET_assert (total > 0);
  sctx = GNUNET_malloc (sizeof (struct StartContext));
  sctx->sched = sched;
  sctx->daemons = daemons;
  sctx->total = total;
  sctx->cont = cont;
  sctx->cont_cls = cont_cls;
  sctx->cfg = GNUNET_CONFIGURATION_create ();
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_load (sctx->cfg,
				 "test_fs_lib_data.conf"))
    {
      GNUNET_break (0);
      GNUNET_CONFIGURATION_destroy (sctx->cfg);
      GNUNET_free (sctx);
      GNUNET_SCHEDULER_add_continuation (sched,
					 cont,
					 cont_cls,
					 GNUNET_SCHEDULER_REASON_TIMEOUT);
      return;
    }
  for (i=0;i<total;i++)
    daemons[i] = GNUNET_malloc (sizeof (struct GNUNET_FS_TestDaemon));
  sctx->group = GNUNET_TESTING_daemons_start (sched,
					      sctx->cfg,
					      total,
					      &notify_running,
					      sctx,
					      NULL, NULL,
					      NULL);
  sctx->timeout_task = GNUNET_SCHEDULER_add_delayed (sched,
						     timeout,
						     &start_timeout,
						     sctx);
}


struct ConnectContext
{
  struct GNUNET_SCHEDULER_Handle *sched;
  GNUNET_SCHEDULER_Task cont;
  void *cont_cls;
};


static void
notify_connection (void *cls,
		   const struct GNUNET_PeerIdentity *first,
		   const struct GNUNET_PeerIdentity *second,
		   const struct GNUNET_CONFIGURATION_Handle *first_cfg,
		   const struct GNUNET_CONFIGURATION_Handle *second_cfg,
		   struct GNUNET_TESTING_Daemon *first_daemon,
		   struct GNUNET_TESTING_Daemon *second_daemon,
		   const char *emsg)
{
  struct ConnectContext *cc = cls;
  
  if (emsg != NULL)
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
		_("Failed to connect peers: %s\n"),
		emsg);
  GNUNET_SCHEDULER_add_continuation (cc->sched,
				     cc->cont,
				     cc->cont_cls,
				     (emsg != NULL) 
				     ? GNUNET_SCHEDULER_REASON_TIMEOUT 
				     : GNUNET_SCHEDULER_REASON_PREREQ_DONE);
  GNUNET_free (cc);
}


/**
 * Connect two daemons for testing.
 *
 * @param sched scheduler to use
 * @param daemon1 first daemon to connect
 * @param daemon2 second first daemon to connect
 * @param timeout if this operation cannot be completed within the
 *                given period, call the continuation with an error code
 * @param cont function to call when done
 * @param cont_cls closure for cont
 */
void
GNUNET_FS_TEST_daemons_connect (struct GNUNET_SCHEDULER_Handle *sched,
				struct GNUNET_FS_TestDaemon *daemon1,
				struct GNUNET_FS_TestDaemon *daemon2,
				struct GNUNET_TIME_Relative timeout,
				GNUNET_SCHEDULER_Task cont,
				void *cont_cls)
{
  struct ConnectContext *ncc;

  ncc = GNUNET_malloc (sizeof (struct ConnectContext));
  ncc->sched = sched;
  ncc->cont = cont;
  ncc->cont_cls = cont_cls;
  GNUNET_TESTING_daemons_connect (daemon1->daemon,
				  daemon2->daemon,
				  timeout,
				  &notify_connection,
				  ncc);
}


/**
 * Stop daemons used for testing.
 *
 * @param sched scheduler to use
 * @param timeout if this operation cannot be completed within the
 *                given period, call the continuation with an error code
 * @param total number of daemons to stop
 * @param daemons array with the daemons (values will be clobbered)
 * @param cont function to call when done
 * @param cont_cls closure for cont
 */
void
GNUNET_FS_TEST_daemons_stop (struct GNUNET_SCHEDULER_Handle *sched,
			     unsigned int total,
			     struct GNUNET_FS_TestDaemon **daemons)
{
  unsigned int i;

  GNUNET_assert (total > 0);
  GNUNET_TESTING_daemons_stop (daemons[0]->group);
  for (i=0;i<total;i++)
    {
      GNUNET_CONFIGURATION_destroy (daemons[i]->cfg);
      GNUNET_free (daemons[i]);
      daemons[i] = NULL;
    }  
}


static void
publish_timeout (void *cls,
		 const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_FS_TestDaemon *daemon = cls;
  GNUNET_FS_TEST_UriContinuation cont;
  
  cont = daemon->publish_cont;
  daemon->publish_timeout_task = GNUNET_SCHEDULER_NO_TASK;
  daemon->publish_cont = NULL;
  cont (daemon->publish_cont_cls,
	NULL);
}


/**
 * Publish a file at the given daemon.
 *
 * @param sched scheduler to use
 * @param daemon where to publish
 * @param timeout if this operation cannot be completed within the
 *                given period, call the continuation with an error code
 * @param anonymity option for publication
 * @param do_index GNUNET_YES for index, GNUNET_NO for insertion,
 *                GNUNET_SYSERR for simulation
 * @param size size of the file to publish
 * @param seed seed to use for file generation
 * @param verbose how verbose to be in reporting
 * @param cont function to call when done
 * @param cont_cls closure for cont
 */
void
GNUNET_FS_TEST_publish (struct GNUNET_SCHEDULER_Handle *sched,
			struct GNUNET_FS_TestDaemon *daemon,
			struct GNUNET_TIME_Relative timeout,
			uint32_t anonymity,
			int do_index,
			uint64_t size,
			uint32_t seed,
			unsigned int verbose,
			GNUNET_FS_TEST_UriContinuation cont,
			void *cont_cls)
{
  GNUNET_assert (daemon->publish_cont == NULL);

  daemon->publish_cont = cont;
  daemon->publish_cont_cls = cont_cls;
  daemon->download_timeout_task = GNUNET_SCHEDULER_add_delayed (sched,
								timeout,
								&publish_timeout,
								daemon);
}


static void
download_timeout (void *cls,
		  const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_FS_TestDaemon *daemon = cls;

  daemon->download_timeout_task = GNUNET_SCHEDULER_NO_TASK;
  GNUNET_SCHEDULER_add_continuation (daemon->download_sched,
				     daemon->download_cont,
				     daemon->download_cont_cls,
				     GNUNET_SCHEDULER_REASON_TIMEOUT);
  daemon->download_cont = NULL;
  daemon->download_sched = NULL;
}


/**
 * Perform test download.
 *
 * @param sched scheduler to use
 * @param daemon which peer to download from
 * @param timeout if this operation cannot be completed within the
 *                given period, call the continuation with an error code
 * @param anonymity option for download
 * @param seed used for file validation
 * @param verbose how verbose to be in reporting
 * @param cont function to call when done
 * @param cont_cls closure for cont
 */
void
GNUNET_FS_TEST_download (struct GNUNET_SCHEDULER_Handle *sched,
			 struct GNUNET_FS_TestDaemon *daemon,
			 struct GNUNET_TIME_Relative timeout,
			 uint32_t anonymity,
			 uint32_t seed,
			 const struct GNUNET_FS_Uri *uri,
			 unsigned int verbose,
			 GNUNET_SCHEDULER_Task cont,
			 void *cont_cls)
{
  GNUNET_assert (daemon->download_cont == NULL);
  daemon->download_sched = sched;
  daemon->download_cont = cont;
  daemon->download_cont_cls = cont_cls;
  daemon->download_seed = seed;  
  daemon->download_timeout_task = GNUNET_SCHEDULER_add_delayed (sched,
								timeout,
								&download_timeout,
								daemon);
}

/* end of test_fs_lib.c */

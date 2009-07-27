/*
      This file is part of GNUnet
      (C) 2008, 2009 Christian Grothoff (and other contributing authors)

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
 * @file testing/testing.c
 * @brief convenience API for writing testcases for GNUnet
 *        Many testcases need to start and stop gnunetd,
 *        and this library is supposed to make that easier
 *        for TESTCASES.  Normal programs should always
 *        use functions from gnunet_{util,arm}_lib.h.  This API is
 *        ONLY for writing testcases!
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_arm_service.h"
#include "gnunet_core_service.h"
#include "gnunet_constants.h"
#include "gnunet_testing_lib.h"

#define DEBUG_TESTING GNUNET_YES

/**
 * How long do we wait after starting gnunet-service-arm
 * for the core service to be alive?
 */
#define ARM_START_WAIT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 120)

/**
 * How many times are we willing to try to 
 * wait for "scp" or "gnunet-service-arm" to
 * complete (waitpid) before giving up?
 */
#define MAX_EXEC_WAIT_RUNS 50

/**
 * Phases of starting GNUnet on a system.
 */
enum StartPhase
  {
    SP_COPYING,
    SP_COPIED,
    SP_START_ARMING,
    SP_START_CORE,
    SP_START_DONE,
    SP_CLEANUP
  };


/**
 * Handle for a GNUnet daemon (technically a set of
 * daemons; the handle is really for the master ARM
 * daemon) started by the testing library.
 */
struct GNUNET_TESTING_Daemon
{
  /**
   * Our scheduler.
   */
  struct GNUNET_SCHEDULER_Handle *sched;

  /**
   * Our configuration.
   */
  const struct GNUNET_CONFIGURATION_Handle *cfg;

  /**
   * Host to run GNUnet on.
   */
  char *hostname;

  /**
   * Username we are using.
   */
  char *username;

  /**
   * Name of the configuration file
   */
  char *cfgfile;

  /**
   * Function to call when the peer is running.
   */
  GNUNET_TESTING_NotifyDaemonRunning cb;

  /**
   * Closure for cb.
   */
  void *cb_cls;

  /**
   * Arguments from "daemon_stop" call.
   */
  GNUNET_TESTING_NotifyCompletion dead_cb;

  /**
   * Closure for 'dead_cb'.
   */
  void *dead_cb_cls;

  /**
   * Identity of this peer (once started).
   */
  struct GNUNET_PeerIdentity id;

  /**
   * Flag to indicate that we've already been asked
   * to terminate (but could not because some action
   * was still pending).
   */
  int dead;

  /**
   * PID of the process that we started last.
   */
  pid_t pid;

  /**
   * How many iterations have we been waiting for
   * the started process to complete?
   */
  unsigned int wait_runs;

  /**
   * In which phase are we during the start of
   * this process?
   */
  enum StartPhase phase;

  /**
   * ID of the current task.
   */
  GNUNET_SCHEDULER_TaskIdentifier task;

};


/**
 * Function called after GNUNET_CORE_connect has succeeded
 * (or failed for good).  Note that the private key of the
 * peer is intentionally not exposed here; if you need it,
 * your process should try to read the private key file
 * directly (which should work if you are authorized...).
 *
 * @param cls closure
 * @param server handle to the server, NULL if we failed
 * @param my_identity ID of this peer, NULL if we failed
 * @param publicKey public key of this peer, NULL if we failed
 */
static void
testing_init (void *cls,
	      struct GNUNET_CORE_Handle * server,
	      const struct GNUNET_PeerIdentity *
	      my_identity,
	      const struct
	      GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded *
	      publicKey)
{
  struct GNUNET_TESTING_Daemon *d = cls;
  GNUNET_TESTING_NotifyDaemonRunning cb;

  d->phase = SP_START_DONE;
  cb = d->cb;
  d->cb = NULL;
  if (server == NULL)
    {
      cb (d->cb_cls, NULL, d->cfg, d,
	  _("Failed to connect to core service\n"));
      if (GNUNET_YES == d->dead)
	GNUNET_TESTING_daemon_stop (d, d->dead_cb, d->dead_cb_cls);
      return;
    }
#if DEBUG_TESTING
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Successfully started peer `%4s'.\n",
	      GNUNET_i2s(my_identity));
#endif
  d->id = *my_identity;
  if (GNUNET_YES == d->dead)
    GNUNET_TESTING_daemon_stop (d, d->dead_cb, d->dead_cb_cls);
  else
    cb (d->cb_cls, my_identity, d->cfg, d, NULL);
}


/**
 * Finite-state machine for starting GNUnet.
 *
 * @param cls our "struct GNUNET_TESTING_Daemon"
 * @param tc unused
 */
static void
start_fsm (void *cls,
	   const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  static struct GNUNET_CORE_MessageHandler no_handlers[] =
    { { NULL, 0, 0 } };
  struct GNUNET_TESTING_Daemon * d = cls;
  GNUNET_TESTING_NotifyDaemonRunning cb;
  enum GNUNET_OS_ProcessStatusType type;
  unsigned long code;
  char *dst;
 
  d->task = GNUNET_SCHEDULER_NO_TASK;
  switch (d->phase)
    {
    case SP_COPYING:
      /* confirm copying complete */
      if (GNUNET_OK != 
	  GNUNET_OS_process_status (d->pid,
				    &type,
				    &code))
	{
	  d->wait_runs++;
	  if (d->wait_runs > MAX_EXEC_WAIT_RUNS)
	    {
	      cb = d->cb;
	      d->cb = NULL;
	      cb (d->cb_cls,
		  NULL,
		  d->cfg,
		  d,
		  _("`scp' does not seem to terminate.\n"));
	      return;
	    }
	  /* wait some more */
	  d->task
	    = GNUNET_SCHEDULER_add_delayed (d->sched, 
					    GNUNET_NO,
					    GNUNET_SCHEDULER_PRIORITY_KEEP,
					    GNUNET_SCHEDULER_NO_TASK,
					    GNUNET_CONSTANTS_EXEC_WAIT,
					    &start_fsm,
					    d);
	  return;
	}
      if ( (type != GNUNET_OS_PROCESS_EXITED) ||
	   (code != 0) )
	{
	  cb = d->cb;
	  d->cb = NULL;
	  cb (d->cb_cls,
	      NULL,
	      d->cfg,
	      d,
	      _("`scp' did not complete cleanly.\n"));	  
	  return;
	}	  
#if DEBUG_TESTING
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "Successfully copied configuration file.\n");
#endif
      d->phase = SP_COPIED;
      /* fall-through */
    case SP_COPIED:
      /* start GNUnet on remote host */
      if (NULL == d->hostname)        
	{
	  d->pid = GNUNET_OS_start_process ("gnunet-service-arm",
					    "gnunet-service-arm",
					    "-c",
					    d->cfgfile,
					    "-d",
					    NULL);
	}
      else
	{
	  if (d->username != NULL)
	    GNUNET_asprintf (&dst,
			     "%s@%s",
			     d->username,
			     d->hostname);
	  else
	    dst = GNUNET_strdup (d->hostname);
	  d->pid = GNUNET_OS_start_process ("ssh",
					    "ssh",
					    dst,
					    "gnunet-service-arm",
					    "-c",
					    d->cfgfile,
					    "-d",
					    NULL);
	  GNUNET_free (dst);
	}
      if (-1 == d->pid)
	{
	  GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		      _("Could not start `%s' process to start GNUnet.\n"),
		      (NULL == d->hostname) ? "gnunet-service-arm" : "ssh");
	  cb = d->cb;
	  d->cb = NULL;
	  cb (d->cb_cls,
	      NULL,
	      d->cfg,
	      d,
	      (NULL == d->hostname) 
	      ? _("Failed to start `gnunet-service-arm' process.\n") 
	      : _("Failed to start `ssh' process.\n"));
	}      
      d->phase = SP_START_ARMING;
      d->wait_runs = 0;
      break;     
    case SP_START_ARMING:
      if (GNUNET_OK != 
	  GNUNET_OS_process_status (d->pid,
				    &type,
				    &code))
	{
	  d->wait_runs++;
	  if (d->wait_runs > MAX_EXEC_WAIT_RUNS)
	    {
	      cb = d->cb;
	      d->cb = NULL;
	      cb (d->cb_cls,
		  NULL,
		  d->cfg,
		  d,
		  (NULL == d->hostname) 
		  ? _("`gnunet-service-arm' does not seem to terminate.\n") 
		  : _("`ssh' does not seem to terminate.\n"));
	      return;
	    }
	  /* wait some more */
	  d->task
	    = GNUNET_SCHEDULER_add_delayed (d->sched, 
					    GNUNET_NO,
					    GNUNET_SCHEDULER_PRIORITY_KEEP,
					    GNUNET_SCHEDULER_NO_TASK,
					    GNUNET_CONSTANTS_EXEC_WAIT,
					    &start_fsm,
					    d);
	  return;
	}
#if DEBUG_TESTING
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "Successfully started `%s'.\n",
		  "gnunet-service-arm");
#endif
      d->phase = SP_START_CORE;
      GNUNET_CORE_connect (d->sched,
			   d->cfg,
			   ARM_START_WAIT,
			   d,
			   &testing_init,
			   NULL, NULL, NULL, 
			   NULL, GNUNET_NO,
			   NULL, GNUNET_NO,
			   no_handlers);     
      break;
    case SP_START_CORE:
      GNUNET_break (0);
      break;
    case SP_START_DONE:
      GNUNET_break (0);
      break;
    case SP_CLEANUP:
      /* confirm copying complete */
      if (GNUNET_OK != 
	  GNUNET_OS_process_status (d->pid,
				    &type,
				    &code))
	{
	  d->wait_runs++;
	  if (d->wait_runs > MAX_EXEC_WAIT_RUNS)
	    {
	      d->dead_cb (d->dead_cb_cls,
			  _("`ssh' does not seem to terminate.\n"));
	      GNUNET_free (d->cfgfile);
	      GNUNET_free_non_null (d->hostname);
	      GNUNET_free_non_null (d->username);
	      GNUNET_free (d);
	      return;
	    }
	  /* wait some more */
	  d->task
	    = GNUNET_SCHEDULER_add_delayed (d->sched, 
					    GNUNET_NO,
					    GNUNET_SCHEDULER_PRIORITY_KEEP,
					    GNUNET_SCHEDULER_NO_TASK,
					    GNUNET_CONSTANTS_EXEC_WAIT,
					    &start_fsm,
					    d);
	  return;
	}
      if ( (type != GNUNET_OS_PROCESS_EXITED) ||
	   (code != 0) )
	{
	  d->dead_cb (d->dead_cb_cls,
		      _("`sshp' did not complete cleanly.\n"));	  
	  GNUNET_free (d->cfgfile);
	  GNUNET_free_non_null (d->hostname);
	  GNUNET_free_non_null (d->username);
	  GNUNET_free (d);
	  return;
	}	 
      GNUNET_free (d->cfgfile);
      GNUNET_free_non_null (d->hostname);
      GNUNET_free_non_null (d->username);
      d->dead_cb (d->dead_cb_cls, NULL);
      GNUNET_free (d);
      break;
    }
}


/**
 * Starts a GNUnet daemon.  GNUnet must be installed on the target
 * system and available in the PATH.  The machine must furthermore be
 * reachable via "ssh" (unless the hostname is "NULL") without the
 * need to enter a password.
 *
 * @param sched scheduler to use 
 * @param cfg configuration to use
 * @param hostname name of the machine where to run GNUnet
 *        (use NULL for localhost).
 * @param cb function to call with the result
 * @param cb_cls closure for cb
 * @return handle to the daemon (actual start will be completed asynchronously)
 */
struct GNUNET_TESTING_Daemon *
GNUNET_TESTING_daemon_start (struct GNUNET_SCHEDULER_Handle *sched,
			     struct GNUNET_CONFIGURATION_Handle *cfg,
			     const char *hostname,
			     GNUNET_TESTING_NotifyDaemonRunning cb,
			     void *cb_cls)
{
  struct GNUNET_TESTING_Daemon * ret;
  char *arg;
  char *username;

  ret = GNUNET_malloc (sizeof(struct GNUNET_TESTING_Daemon));
  ret->sched = sched;
  ret->cfg = cfg;
  ret->hostname = (hostname == NULL) ? NULL : GNUNET_strdup (hostname);
  ret->cfgfile = GNUNET_DISK_mktemp ("gnunet-testing-config");
  if (NULL == ret->cfgfile)
    {						
      GNUNET_free_non_null (ret->hostname);
      GNUNET_free (ret);
      return NULL;
    }
  ret->cb = cb;
  ret->cb_cls = cb_cls;
  /* 1) write configuration to temporary file */
  if (GNUNET_OK != 
      GNUNET_CONFIGURATION_write (cfg,
				  ret->cfgfile))
    {
      if (0 != UNLINK (ret->cfgfile))
	  GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_WARNING,
				    "unlink",
				    ret->cfgfile);
      GNUNET_free_non_null (ret->hostname);
      GNUNET_free (ret->cfgfile);
      GNUNET_free (ret);
      return NULL;
    }
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_string (cfg,
					     "TESTING",
					     "USERNAME",
					     &username))
    {
      if (NULL != getenv ("USER"))
	username = GNUNET_strdup (getenv("USER"));
      else
	username = NULL;
    }
  ret->username = username;

  /* 2) copy file to remote host */  
  if (NULL != hostname)
    {
      ret->phase = SP_COPYING;
      if (NULL != username)
	GNUNET_asprintf (&arg,
			 "%s@%s:%s", 
			 username,
			 hostname,
			 ret->cfgfile);
      else
	GNUNET_asprintf (&arg,
			 "%s:%s", 
			 hostname,
			 ret->cfgfile);
      ret->pid = GNUNET_OS_start_process ("scp",
					  "scp",
					  ret->cfgfile,
					  arg,
					  NULL);
      if (-1 == ret->pid)
	{
	  GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		      _("Could not start `%s' process to copy configuration file.\n"),
		      "scp");
	  if (0 != UNLINK (ret->cfgfile))
	    GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_WARNING,
				      "unlink",
				      ret->cfgfile);
	  GNUNET_free_non_null (ret->hostname);
	  GNUNET_free_non_null (ret->username);
	  GNUNET_free (ret->cfgfile);
	  GNUNET_free (ret);
 	  return NULL;
	}
      ret->task
	= GNUNET_SCHEDULER_add_delayed (sched, 
					GNUNET_NO,
					GNUNET_SCHEDULER_PRIORITY_KEEP,
					GNUNET_SCHEDULER_NO_TASK,
					GNUNET_CONSTANTS_EXEC_WAIT,
					&start_fsm,
					ret);
      GNUNET_free (arg);
      return ret;
    }
  ret->phase = SP_COPIED;
  GNUNET_SCHEDULER_add_continuation (sched,
				     GNUNET_NO,
				     &start_fsm,
				     ret,
				     GNUNET_SCHEDULER_REASON_PREREQ_DONE);
  return ret;
}


/**
 * Stops a GNUnet daemon.
 *
 * @param d the daemon that should be stopped
 * @param cb function called once the daemon was stopped
 * @param cb_cls closure for cb
 */
void GNUNET_TESTING_daemon_stop (struct GNUNET_TESTING_Daemon *d,
				 GNUNET_TESTING_NotifyCompletion cb,
				 void * cb_cls)
{
  struct GNUNET_CLIENT_Connection *cc;
  char *dst;

  if (NULL != d->cb)
    {
      d->dead = GNUNET_YES;
      d->dead_cb = cb;
      d->dead_cb_cls = cb_cls;
      return;
    }
  /* shutdown ARM process (will also terminate others) */
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      _("Terminating peer `%4s'\n"),
	      GNUNET_i2s(&d->id));
  cc = GNUNET_CLIENT_connect (d->sched,
			      "arm",
			      d->cfg);
  GNUNET_CLIENT_service_shutdown (cc);
  GNUNET_CLIENT_disconnect (cc);
  
  /* state clean up and notifications */
  if (0 != UNLINK (d->cfgfile))
    GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_WARNING,
			      "unlink",
			      d->cfgfile);
  if (d->hostname != NULL)
    {
      if (NULL != d->username)
	GNUNET_asprintf (&dst,
			 "%s@%s",
			 d->username,
			 d->hostname);
      else
	dst = GNUNET_strdup (d->hostname);
      d->pid = GNUNET_OS_start_process ("ssh",
					"ssh",
					dst,
					"rm",
					d->cfgfile,
					NULL);
      GNUNET_free (dst);
      if (-1 == d->pid)
	{
	  GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		      _("Could not start `%s' process to delete configuration file.\n"),
		      "ssh");
	  GNUNET_free (d->cfgfile);
	  GNUNET_free_non_null (d->hostname);
	  GNUNET_free_non_null (d->username);
	  GNUNET_free (d);
	  cb (cb_cls, _("Error cleaning up configuration file.\n"));
	  return;
	}
      d->phase = SP_CLEANUP;
      d->dead_cb = cb;
      d->dead_cb_cls = cb_cls;
      d->task
	= GNUNET_SCHEDULER_add_delayed (d->sched, 
					GNUNET_NO,
					GNUNET_SCHEDULER_PRIORITY_KEEP,
					GNUNET_SCHEDULER_NO_TASK,
					GNUNET_CONSTANTS_EXEC_WAIT,
					&start_fsm,
					d);
      return;
    }
  GNUNET_free (d->cfgfile);
  GNUNET_free_non_null (d->hostname);
  GNUNET_free_non_null (d->username);
  GNUNET_free (d);
  cb (cb_cls, NULL);
}


/**
 * Changes the configuration of a GNUnet daemon.
 *
 * @param d the daemon that should be modified
 * @param cfg the new configuration for the daemon
 * @param cb function called once the configuration was changed
 * @param cb_cls closure for cb
 */
void GNUNET_TESTING_daemon_reconfigure (struct GNUNET_TESTING_Daemon *d,
					const struct GNUNET_CONFIGURATION_Handle *cfg,
					GNUNET_TESTING_NotifyCompletion cb,
					void * cb_cls)
{
  cb (cb_cls, "not implemented");
}


/**
 * Establish a connection between two GNUnet daemons.
 *
 * @param d1 handle for the first daemon
 * @param d2 handle for the second daemon
 * @param timeout how long is the connection attempt
 *        allowed to take?
 * @param cb function to call at the end
 * @param cb_cls closure for cb
 */
void GNUNET_TESTING_daemons_connect (struct GNUNET_TESTING_Daemon *d1,
				     struct GNUNET_TESTING_Daemon *d2,
				     struct GNUNET_TIME_Relative timeout,
				     GNUNET_TESTING_NotifyCompletion cb,
				     void *cb_cls)
{
  cb (cb_cls, "not implemented");
}


/* end of testing.c */

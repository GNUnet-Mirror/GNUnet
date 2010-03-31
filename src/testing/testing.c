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
 *
 */
#include "platform.h"
#include "gnunet_arm_service.h"
#include "gnunet_core_service.h"
#include "gnunet_constants.h"
#include "gnunet_testing_lib.h"
#include "gnunet_transport_service.h"

#define DEBUG_TESTING GNUNET_YES

/**
 * How long do we wait after starting gnunet-service-arm
 * for the core service to be alive?
 */
#define ARM_START_WAIT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 60)

/**
 * How many times are we willing to try to wait for "scp" or
 * "gnunet-service-arm" to complete (waitpid) before giving up?
 */
#define MAX_EXEC_WAIT_RUNS 50


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
              struct GNUNET_CORE_Handle *server,
              const struct GNUNET_PeerIdentity *my_identity,
              const struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded *publicKey)
{
  struct GNUNET_TESTING_Daemon *d = cls;
  GNUNET_TESTING_NotifyDaemonRunning cb;

  GNUNET_assert (d->phase == SP_START_CORE);
  d->phase = SP_START_DONE;
  cb = d->cb;
  d->cb = NULL;
  if (server == NULL)
    {
      d->server = NULL;
      if (GNUNET_YES == d->dead)
        GNUNET_TESTING_daemon_stop (d, d->dead_cb, d->dead_cb_cls);
      else if (NULL != cb)
        cb (d->cb_cls, NULL, d->cfg, d,
            _("Failed to connect to core service\n"));
      return;
    }
#if DEBUG_TESTING
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Successfully started peer `%4s'.\n", GNUNET_i2s (my_identity));
#endif
  d->id = *my_identity;
  d->shortname = strdup (GNUNET_i2s (my_identity));
  d->server = server;
  if (GNUNET_YES == d->dead)
    GNUNET_TESTING_daemon_stop (d, d->dead_cb, d->dead_cb_cls);
  else if (NULL != cb)
    cb (d->cb_cls, my_identity, d->cfg, d, NULL);
}


/**
 * Finite-state machine for starting GNUnet.
 *
 * @param cls our "struct GNUNET_TESTING_Daemon"
 * @param tc unused
 */
static void
start_fsm (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  static struct GNUNET_CORE_MessageHandler no_handlers[] = { {NULL, 0, 0} };
  struct GNUNET_TESTING_Daemon *d = cls;
  GNUNET_TESTING_NotifyDaemonRunning cb;
  enum GNUNET_OS_ProcessStatusType type;
  unsigned long code;
  char *dst;

#if DEBUG_TESTING
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Peer FSM is in phase %u.\n", d->phase);
#endif
  d->task = GNUNET_SCHEDULER_NO_TASK;
  switch (d->phase)
    {
    case SP_COPYING:
      /* confirm copying complete */
      if (GNUNET_OK != GNUNET_OS_process_status (d->pid, &type, &code))
        {
          d->wait_runs++;
          if (d->wait_runs > MAX_EXEC_WAIT_RUNS)
            {
              cb = d->cb;
              d->cb = NULL;
              if (NULL != cb)
                cb (d->cb_cls,
                    NULL,
                    d->cfg, d, _("`scp' does not seem to terminate.\n"));
              return;
            }
          /* wait some more */
          d->task
            = GNUNET_SCHEDULER_add_delayed (d->sched,
                                            GNUNET_CONSTANTS_EXEC_WAIT,
                                            &start_fsm, d);
          return;
        }
      if ((type != GNUNET_OS_PROCESS_EXITED) || (code != 0))
        {
          cb = d->cb;
          d->cb = NULL;
          if (NULL != cb)
            cb (d->cb_cls,
                NULL, d->cfg, d, _("`scp' did not complete cleanly.\n"));
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
#if DEBUG_TESTING
          GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                      "Starting `%s', with command `%s %s %s %s %s %s'.\n",
                      "gnunet-arm", "gnunet-arm", "-c", d->cfgfile,
                      "-L", "DEBUG",
                      "-s");
#endif
          d->pid = GNUNET_OS_start_process (NULL, NULL, "gnunet-arm",
                                            "gnunet-arm",
                                            "-c", d->cfgfile,
#if DEBUG_TESTING
                                            "-L", "DEBUG",
#endif
                                            "-s", NULL);
        }
      else
        {
          if (d->username != NULL)
            GNUNET_asprintf (&dst, "%s@%s", d->username, d->hostname);
          else
            dst = GNUNET_strdup (d->hostname);

#if DEBUG_TESTING
          GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                      "Starting `%s', with command `%s %s %s %s %s %s %s %s'.\n",
                      "gnunet-arm", "ssh", dst, "gnunet-arm", "-c", d->cfgfile,
                      "-L", "DEBUG", "-s");
#endif
          d->pid = GNUNET_OS_start_process (NULL, NULL, "ssh",
                                            "ssh",
                                            dst,
                                            "gnunet-arm",
#if DEBUG_TESTING
                                            "-L", "DEBUG",
#endif
                                            "-c", d->cfgfile, "-s", NULL);
          GNUNET_free (dst);
        }
      if (-1 == d->pid)
        {
          GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                      _("Could not start `%s' process to start GNUnet.\n"),
                      (NULL == d->hostname) ? "gnunet-arm" : "ssh");
          cb = d->cb;
          d->cb = NULL;
          if (NULL != cb)
            cb (d->cb_cls,
                NULL,
                d->cfg,
                d,
                (NULL == d->hostname)
                ? _("Failed to start `gnunet-arm' process.\n")
                : _("Failed to start `ssh' process.\n"));
        }
#if DEBUG_TESTING
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Started `%s', waiting for `%s' to be up.\n",
                  "gnunet-arm", "gnunet-service-core");
#endif
      d->phase = SP_START_ARMING;
      d->wait_runs = 0;
      d->task
        = GNUNET_SCHEDULER_add_delayed (d->sched,
                                        GNUNET_CONSTANTS_EXEC_WAIT,
                                        &start_fsm, d);
      break;
    case SP_START_ARMING:
      if (GNUNET_OK != GNUNET_OS_process_status (d->pid, &type, &code))
        {
          d->wait_runs++;
          if (d->wait_runs > MAX_EXEC_WAIT_RUNS)
            {
              cb = d->cb;
              d->cb = NULL;
              if (NULL != cb)
                cb (d->cb_cls,
                    NULL,
                    d->cfg,
                    d,
                    (NULL == d->hostname)
                    ? _("`gnunet-arm' does not seem to terminate.\n")
                    : _("`ssh' does not seem to terminate.\n"));
              return;
            }
          /* wait some more */
          d->task
            = GNUNET_SCHEDULER_add_delayed (d->sched,
                                            GNUNET_CONSTANTS_EXEC_WAIT,
                                            &start_fsm, d);
          return;
        }
#if DEBUG_TESTING
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Successfully started `%s'.\n", "gnunet-arm");
#endif
      d->phase = SP_START_CORE;
      d->server = GNUNET_CORE_connect (d->sched,
                                       d->cfg,
                                       ARM_START_WAIT,
                                       d,
                                       &testing_init,
                                       NULL, NULL, NULL,
                                       NULL, GNUNET_NO,
                                       NULL, GNUNET_NO, no_handlers);
      break;
    case SP_START_CORE:
      GNUNET_break (0);
      break;
    case SP_START_DONE:
      GNUNET_break (0);
      break;
    case SP_SHUTDOWN_START:
      /* confirm copying complete */
      if (GNUNET_OK != GNUNET_OS_process_status (d->pid, &type, &code))
        {
          d->wait_runs++;
          if (d->wait_runs > MAX_EXEC_WAIT_RUNS)
            {
              d->dead_cb (d->dead_cb_cls,
                          _("either `gnunet-arm' or `ssh' does not seem to terminate.\n"));
              GNUNET_CONFIGURATION_destroy (d->cfg);
              GNUNET_free (d->cfgfile);
              GNUNET_free_non_null (d->hostname);
              GNUNET_free_non_null (d->username);
              GNUNET_free_non_null (d->shortname);
              GNUNET_free (d);
              return;
            }
          /* wait some more */
          d->task
            = GNUNET_SCHEDULER_add_delayed (d->sched,
                                            GNUNET_CONSTANTS_EXEC_WAIT,
                                            &start_fsm, d);
          return;
        }
      if ((type != GNUNET_OS_PROCESS_EXITED) || (code != 0))
        {
          if (NULL != d->dead_cb)
            d->dead_cb (d->dead_cb_cls,
                        _("shutdown (either `gnunet-arm' or `ssh') did not complete cleanly.\n"));
          GNUNET_CONFIGURATION_destroy (d->cfg);
          GNUNET_free (d->cfgfile);
          GNUNET_free_non_null (d->hostname);
          GNUNET_free_non_null (d->username);
          GNUNET_free_non_null (d->shortname);
          GNUNET_free (d);
          return;
        }
#if DEBUG_TESTING
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Peer shutdown complete.\n");
#endif
      /* state clean up and notifications */
      GNUNET_CONFIGURATION_destroy (d->cfg);
      GNUNET_free (d->cfgfile);
      GNUNET_free_non_null (d->hostname);
      GNUNET_free_non_null (d->username);
      GNUNET_free_non_null (d->shortname);
      if (NULL != d->dead_cb)
        d->dead_cb (d->dead_cb_cls, NULL);
      GNUNET_free (d);
      break;
    case SP_CONFIG_UPDATE:
      /* confirm copying complete */
      if (GNUNET_OK != GNUNET_OS_process_status (d->pid, &type, &code))
        {
          d->wait_runs++;
          if (d->wait_runs > MAX_EXEC_WAIT_RUNS)
            {
              cb = d->cb;
              d->cb = NULL;
              if (NULL != cb)
                cb (d->cb_cls,
                    NULL,
                    d->cfg, d, _("`scp' does not seem to terminate.\n"));
              return;
            }
          /* wait some more */
          d->task
            = GNUNET_SCHEDULER_add_delayed (d->sched,
                                            GNUNET_CONSTANTS_EXEC_WAIT,
                                            &start_fsm, d);
          return;
        }
      if ((type != GNUNET_OS_PROCESS_EXITED) || (code != 0))
        {
          if (NULL != d->update_cb)
            d->update_cb (d->update_cb_cls,
                          _("`scp' did not complete cleanly.\n"));
          return;
        }
#if DEBUG_TESTING
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Successfully copied configuration file.\n");
#endif
      if (NULL != d->update_cb)
        d->update_cb (d->update_cb_cls, NULL);
      d->phase = SP_START_DONE;
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
                             const struct GNUNET_CONFIGURATION_Handle *cfg,
                             const char *hostname,
                             GNUNET_TESTING_NotifyDaemonRunning cb,
                             void *cb_cls)
{
  struct GNUNET_TESTING_Daemon *ret;
  char *arg;
  char *username;

  ret = GNUNET_malloc (sizeof (struct GNUNET_TESTING_Daemon));
  ret->sched = sched;
  ret->hostname = (hostname == NULL) ? NULL : GNUNET_strdup (hostname);
  ret->cfgfile = GNUNET_DISK_mktemp ("gnunet-testing-config");
#if DEBUG_TESTING
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Setting up peer with configuration file `%s'.\n",
              ret->cfgfile);
#endif
  if (NULL == ret->cfgfile)
    {
      GNUNET_free_non_null (ret->hostname);
      GNUNET_free (ret);
      return NULL;
    }
  ret->cb = cb;
  ret->cb_cls = cb_cls;
  ret->cfg = GNUNET_CONFIGURATION_dup (cfg);
  GNUNET_CONFIGURATION_set_value_string (ret->cfg,
                                         "PATHS",
                                         "DEFAULTCONFIG", ret->cfgfile);
  /* 1) write configuration to temporary file */
  if (GNUNET_OK != GNUNET_CONFIGURATION_write (ret->cfg, ret->cfgfile))
    {
      if (0 != UNLINK (ret->cfgfile))
        GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_WARNING,
                                  "unlink", ret->cfgfile);
      GNUNET_CONFIGURATION_destroy (ret->cfg);
      GNUNET_free_non_null (ret->hostname);
      GNUNET_free (ret->cfgfile);
      GNUNET_free (ret);
      return NULL;
    }
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_string (cfg,
                                             "TESTING",
                                             "USERNAME", &username))
    {
      if (NULL != getenv ("USER"))
        username = GNUNET_strdup (getenv ("USER"));
      else
        username = NULL;
    }
  ret->username = username;

  /* 2) copy file to remote host */
  if (NULL != hostname)
    {
#if DEBUG_TESTING
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Copying configuration file to host `%s'.\n", hostname);
#endif
      ret->phase = SP_COPYING;
      if (NULL != username)
        GNUNET_asprintf (&arg, "%s@%s:%s", username, hostname, ret->cfgfile);
      else
        GNUNET_asprintf (&arg, "%s:%s", hostname, ret->cfgfile);
      ret->pid = GNUNET_OS_start_process (NULL, NULL, "scp",
                                          "scp", ret->cfgfile, arg, NULL);
      GNUNET_free (arg);
      if (-1 == ret->pid)
        {
          GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                      _
                      ("Could not start `%s' process to copy configuration file.\n"),
                      "scp");
          if (0 != UNLINK (ret->cfgfile))
            GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_WARNING,
                                      "unlink", ret->cfgfile);
          GNUNET_CONFIGURATION_destroy (ret->cfg);
          GNUNET_free_non_null (ret->hostname);
          GNUNET_free_non_null (ret->username);
          GNUNET_free (ret->cfgfile);
          GNUNET_free (ret);
          return NULL;
        }
      ret->task
        = GNUNET_SCHEDULER_add_delayed (sched,
                                        GNUNET_CONSTANTS_EXEC_WAIT,
                                        &start_fsm, ret);
      return ret;
    }
#if DEBUG_TESTING
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "No need to copy configuration file since we are running locally.\n");
#endif
  ret->phase = SP_COPIED;
  GNUNET_SCHEDULER_add_continuation (sched,
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
void
GNUNET_TESTING_daemon_stop (struct GNUNET_TESTING_Daemon *d,
                            GNUNET_TESTING_NotifyCompletion cb, void *cb_cls)
{
  char *arg;

  d->dead_cb = cb;
  d->dead_cb_cls = cb_cls;

  if (NULL != d->cb)
    {
      d->dead = GNUNET_YES;
      return;
    }
  if (d->phase == SP_CONFIG_UPDATE)
    {
      GNUNET_SCHEDULER_cancel (d->sched, d->task);
      d->phase = SP_START_DONE;
    }
  if (d->server != NULL)
    {
      GNUNET_CORE_disconnect (d->server);
      d->server = NULL;
    }
  /* shutdown ARM process (will terminate others) */
#if DEBUG_TESTING
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              _("Terminating peer `%4s'\n"), GNUNET_i2s (&d->id));
  /* sleep(15); Manual check for running */
#endif

  d->phase = SP_SHUTDOWN_START;

  /* Check if this is a local or remote process */
  if (NULL != d->hostname)
    {
#if DEBUG_TESTING
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Stopping gnunet-arm with config `%s' on host `%s'.\n", d->cfgfile, d->hostname);
#endif

      if (d->username != NULL)
        GNUNET_asprintf (&arg, "%s@%s", d->username, d->hostname);
      else
        arg = GNUNET_strdup (d->hostname);

      d->pid = GNUNET_OS_start_process (NULL, NULL, "ssh", "ssh",
                                              arg, "gnunet-arm",
#if DEBUG_TESTING
                                              "-L", "DEBUG",
#endif
                                              "-c", d->cfgfile, "-e", NULL);
      /* Use -e to end arm, and -d to remove temp files */

      GNUNET_free (arg);
    }
  else
  {
#if DEBUG_TESTING
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Stopping gnunet-arm with config `%s' locally.\n", d->cfgfile);
#endif
    d->pid = GNUNET_OS_start_process (NULL, NULL, "gnunet-arm",
                                            "gnunet-arm",
#if DEBUG_TESTING
                                            "-L", "DEBUG",
#endif
                                            "-c", d->cfgfile, "-e", "-d", NULL);
  }

  d->wait_runs = 0;
  d->task
    = GNUNET_SCHEDULER_add_delayed (d->sched,
                                    GNUNET_CONSTANTS_EXEC_WAIT,
                                    &start_fsm, d);
  return;
}


/**
 * Changes the configuration of a GNUnet daemon.
 *
 * @param d the daemon that should be modified
 * @param cfg the new configuration for the daemon
 * @param cb function called once the configuration was changed
 * @param cb_cls closure for cb
 */
void
GNUNET_TESTING_daemon_reconfigure (struct GNUNET_TESTING_Daemon *d,
                                   struct GNUNET_CONFIGURATION_Handle *cfg,
                                   GNUNET_TESTING_NotifyCompletion cb,
                                   void *cb_cls)
{
  char *arg;

  if (d->phase != SP_START_DONE)
    {
      if (NULL != cb)
        cb (cb_cls,
            _
            ("Peer not yet running, can not change configuration at this point."));
      return;
    }

  /* 1) write configuration to temporary file */
  if (GNUNET_OK != GNUNET_CONFIGURATION_write (cfg, d->cfgfile))
    {
      if (NULL != cb)
        cb (cb_cls, _("Failed to write new configuration to disk."));
      return;
    }

  /* 2) copy file to remote host (if necessary) */
  if (NULL == d->hostname)
    {
      /* signal success */
      if (NULL != cb)
        cb (cb_cls, NULL);
      return;
    }
#if DEBUG_TESTING
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Copying updated configuration file to remote host `%s'.\n",
              d->hostname);
#endif
  d->phase = SP_CONFIG_UPDATE;
  if (NULL != d->username)
    GNUNET_asprintf (&arg, "%s@%s:%s", d->username, d->hostname, d->cfgfile);
  else
    GNUNET_asprintf (&arg, "%s:%s", d->hostname, d->cfgfile);
  d->pid = GNUNET_OS_start_process (NULL, NULL, "scp", "scp", d->cfgfile, arg, NULL);
  GNUNET_free (arg);
  if (-1 == d->pid)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  _
                  ("Could not start `%s' process to copy configuration file.\n"),
                  "scp");
      if (NULL != cb)
        cb (cb_cls, _("Failed to copy new configuration to remote machine."));
      d->phase = SP_START_DONE;
      return;
    }
  d->update_cb = cb;
  d->update_cb_cls = cb_cls;
  d->task
    = GNUNET_SCHEDULER_add_delayed (d->sched,
                                    GNUNET_CONSTANTS_EXEC_WAIT,
                                    &start_fsm, d);
}


/**
 * Data kept for each pair of peers that we try
 * to connect.
 */
struct ConnectContext
{
  /**
   * Testing handle to the first daemon.
   */
  struct GNUNET_TESTING_Daemon *d1;

  /**
   * Handle to core of first daemon (to check connect)
   */
  struct GNUNET_CORE_Handle * d1core;

  /**
   * Testing handle to the second daemon.
   */
  struct GNUNET_TESTING_Daemon *d2;

  /**
   * Handle to core of second daemon (to check connect)
   */
  struct GNUNET_CORE_Handle * d2core;

  /**
   * Transport handle to the first daemon.
   */
  struct GNUNET_TRANSPORT_Handle *d1th;

  /**
   * Transport handle to the second daemon.
   */
  struct GNUNET_TRANSPORT_Handle *d2th;

  /**
   * Function to call once we are done (or have timed out).
   */
  GNUNET_TESTING_NotifyConnection cb;

  /**
   * Closure for "nb".
   */
  void *cb_cls;

  /**
   * Transmit handle for our request for transmission
   * (as given to d2 asking to talk to d1).
   */
  struct GNUNET_CORE_TransmitHandle *ntr;

  /**
   * When should this operation be complete (or we must trigger
   * a timeout).
   */
  struct GNUNET_TIME_Absolute timeout;

  /**
   * Hello timeout task
   */
  GNUNET_SCHEDULER_TaskIdentifier hello_send_task;

  /**
   * Connect timeout task
   */
  GNUNET_SCHEDULER_TaskIdentifier timeout_task;

  /**
   * When should this operation be complete (or we must trigger
   * a timeout).
   */
  struct GNUNET_TIME_Relative timeout_hello;

  /**
   * The current hello message we have (for d1)
   */
  struct GNUNET_MessageHeader *hello;

  /**
   * Was the connection successful?
   */
  int connected;
};


/**
 * Receive the HELLO from one peer, give it to the other
 * and ask them to connect.
 *
 * @param cls "struct ConnectContext"
 * @param message HELLO message of peer
 */
static void
process_hello (void *cls, const struct GNUNET_MessageHeader *message)
{
  struct ConnectContext *ctx = cls;

#if DEBUG_TESTING
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received `%s' from transport service of `%4s'\n",
              "HELLO", GNUNET_i2s (&ctx->d1->id));
#endif

  GNUNET_assert (message != NULL);
  GNUNET_free_non_null(ctx->hello);
  ctx->hello = GNUNET_malloc(ntohs(message->size));
  memcpy(ctx->hello, message, ntohs(message->size));

}


/**
 * Notify callback about success or failure of the attempt
 * to connect the two peers
 *
 * @param cls our "struct ConnectContext" (freed)
 * @param tc reason tells us if we succeeded or failed
 */
static void
notify_connect_result (void *cls,
                       const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct ConnectContext *ctx = cls;

  GNUNET_TRANSPORT_get_hello_cancel (ctx->d1th, &process_hello, ctx);
  GNUNET_SCHEDULER_cancel(ctx->d1->sched, ctx->hello_send_task);

  if (ctx->cb != NULL)
    {
      if (ctx->connected == GNUNET_NO)
        {
          ctx->cb (ctx->cb_cls, &ctx->d1->id, &ctx->d2->id, ctx->d1->cfg,
                  ctx->d2->cfg, ctx->d1, ctx->d2,
                  _("Peers failed to connect"));
        }
      else
        {
          ctx->cb (ctx->cb_cls, &ctx->d1->id, &ctx->d2->id, ctx->d1->cfg,
                   ctx->d2->cfg, ctx->d1, ctx->d2, NULL);
          GNUNET_SCHEDULER_cancel(ctx->d1->sched, ctx->timeout_task);
        }
    }

  ctx->ntr = NULL;
  GNUNET_TRANSPORT_disconnect (ctx->d1th);
  ctx->d1th = NULL;
  GNUNET_TRANSPORT_disconnect (ctx->d2th);
  ctx->d2th = NULL;
  GNUNET_CORE_disconnect (ctx->d1core);
  ctx->d1core = NULL;
  GNUNET_free_non_null (ctx->hello);
  GNUNET_free (ctx);
}


/**
 * Success, connection is up.  Signal client our success.
 *
 * @param cls our "struct ConnectContext"
 * @param peer identity of the peer that has connected
 * @param latency the round trip latency of the connection to this peer
 * @param distance distance the transport level distance to this peer
 *
 */
static void
connect_notify (void *cls, const struct GNUNET_PeerIdentity * peer, struct GNUNET_TIME_Relative latency,
                uint32_t distance)
{
  struct ConnectContext *ctx = cls;

#if DEBUG_TESTING
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Core notified us about connection to a peer\n");
#endif
  if (memcmp(&ctx->d2->id, peer, sizeof(struct GNUNET_PeerIdentity)) == 0)
    {
#if DEBUG_TESTING
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Core notified us about connection to peer %s\n", GNUNET_i2s(peer));
#endif
      /*
       * If we disconnect here, then the hello may never get sent (if it was delayed!)
       * However I'm sure there was a reason it was here... so I'm just commenting.
       */
      ctx->connected = GNUNET_YES;
      GNUNET_SCHEDULER_add_now (ctx->d1->sched,
                                &notify_connect_result,
                                ctx);
    }

}

static void
send_hello(void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct ConnectContext *ctx = cls;

  if (ctx->hello != NULL)
    {
      GNUNET_TRANSPORT_offer_hello (ctx->d2th, ctx->hello);
      ctx->timeout_hello = GNUNET_TIME_relative_add(ctx->timeout_hello,
						    GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_MILLISECONDS,
										  200));
    }
  ctx->hello_send_task = GNUNET_SCHEDULER_add_delayed(ctx->d1->sched,
						      ctx->timeout_hello,
						      &send_hello, ctx);
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
void
GNUNET_TESTING_daemons_connect (struct GNUNET_TESTING_Daemon *d1,
                                struct GNUNET_TESTING_Daemon *d2,
                                struct GNUNET_TIME_Relative timeout,
                                GNUNET_TESTING_NotifyConnection cb,
                                void *cb_cls)
{
  struct ConnectContext *ctx;
  static struct GNUNET_CORE_MessageHandler no_handlers[] = { {NULL, 0, 0} };

  if ((d1->server == NULL) || (d2->server == NULL))
    {
      if (NULL != cb)
        cb (cb_cls, &d1->id, &d2->id, d1->cfg, d2->cfg, d1, d2,
            _("Peers are not fully running yet, can not connect!\n"));
      return;
    }
  ctx = GNUNET_malloc (sizeof (struct ConnectContext));
  ctx->d1 = d1;
  ctx->d2 = d2;
  ctx->timeout = GNUNET_TIME_relative_to_absolute (timeout);
  ctx->cb = cb;
  ctx->cb_cls = cb_cls;
  ctx->timeout_hello = GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_MILLISECONDS, 400);
  ctx->connected = GNUNET_NO;
#if DEBUG_TESTING
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Asked to connect peer %s to peer %s\n",
              d1->shortname, d2->shortname);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Connecting to transport service of peer %s\n", d1->shortname);
#endif

  ctx->d1core = GNUNET_CORE_connect (d1->sched,
                                     d1->cfg,
                                     timeout,
                                     ctx,
                                     NULL,
                                     NULL, &connect_notify, NULL,
                                     NULL, GNUNET_NO,
                                     NULL, GNUNET_NO, no_handlers);
  if (ctx->d1core == NULL)
    {
      GNUNET_free (ctx);
      if (NULL != cb)
        cb (cb_cls, &d1->id, &d2->id, d1->cfg, d2->cfg, d1, d2,
            _("Failed to connect to core service of first peer!\n"));
      return;
    }

  ctx->d1th = GNUNET_TRANSPORT_connect (d1->sched,
                                        d1->cfg, d1, NULL, NULL, NULL);
  if (ctx->d1th == NULL)
    {
      GNUNET_free (ctx);
      if (NULL != cb)
        cb (cb_cls, &d1->id, &d2->id, d1->cfg, d2->cfg, d1, d2,
            _("Failed to connect to transport service!\n"));
      return;
    }
#if DEBUG_TESTING
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Asked to connect peer %s to peer %s\n",
              d1->shortname, d2->shortname);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Connecting to transport service of peer %s\n", d2->shortname);

#endif

  ctx->d2th = GNUNET_TRANSPORT_connect (d2->sched,
                                        d2->cfg, d2, NULL, NULL, NULL);
  if (ctx->d2th == NULL)
    {
      GNUNET_TRANSPORT_disconnect (ctx->d1th);
      GNUNET_free (ctx);
      if (NULL != cb)
        cb (cb_cls, &d1->id, &d2->id, d1->cfg, d2->cfg, d1, d2,
            _("Failed to connect to transport service!\n"));
      return;
    }

#if DEBUG_TESTING
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Asking for HELLO from peer %s\n", GNUNET_i2s (&d1->id));
#endif

  ctx->timeout_task = GNUNET_SCHEDULER_add_delayed (d1->sched,
                                                    timeout,
                                                    &notify_connect_result, ctx);

  GNUNET_TRANSPORT_get_hello (ctx->d1th, &process_hello, ctx);
  ctx->hello_send_task = GNUNET_SCHEDULER_add_delayed(ctx->d1->sched, ctx->timeout_hello,
						      &send_hello, ctx);
}


/* end of testing.c */

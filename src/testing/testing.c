/*
      This file is part of GNUnet
      (C) 2008, 2009 Christian Grothoff (and other contributing authors)

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
#include "gnunet_hello_lib.h"

#define DEBUG_TESTING GNUNET_EXTRA_LOGGING

#define DEBUG_TESTING_RECONNECT GNUNET_EXTRA_LOGGING

/**
 * Hack to deal with initial HELLO's being often devoid of addresses.
 * This hack causes 'process_hello' to ignore HELLOs without addresses.
 * The correct implementation would continue with 'process_hello' until
 * the connection could be established...
 */
#define EMPTY_HACK GNUNET_YES

/**
 * How long do we wait after starting gnunet-service-arm
 * for the core service to be alive?
 */
#define ARM_START_WAIT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 120)

/**
 * How many times are we willing to try to wait for "scp" or
 * "gnunet-service-arm" to complete (waitpid) before giving up?
 */
#define MAX_EXEC_WAIT_RUNS 250

static struct GNUNET_CORE_MessageHandler no_handlers[] = { {NULL, 0, 0} };

#if EMPTY_HACK
static int
test_address (void *cls, const struct GNUNET_HELLO_Address *address,
              struct GNUNET_TIME_Absolute expiration)
{
  int *empty = cls;

  *empty = GNUNET_NO;
  return GNUNET_OK;
}
#endif

/**
 * Receive the HELLO from one peer, give it to the other
 * and ask them to connect.
 *
 * @param cls Closure (daemon whose hello is this).
 * @param message HELLO message of peer
 */
static void
process_hello (void *cls, const struct GNUNET_MessageHeader *message)
{
  struct GNUNET_TESTING_Daemon *daemon = cls;
  int msize;

#if EMPTY_HACK
  int empty;

  empty = GNUNET_YES;
  GNUNET_assert (message != NULL);
  GNUNET_HELLO_iterate_addresses ((const struct GNUNET_HELLO_Message *) message,
                                  GNUNET_NO, &test_address, &empty);
  if (GNUNET_YES == empty)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Skipping empty HELLO address of peer %s\n",
                GNUNET_i2s (&daemon->id));
    return;
  }
#endif
  GNUNET_assert (daemon->phase == SP_GET_HELLO ||
                 daemon->phase == SP_START_DONE);
  daemon->cb = NULL;            // FIXME: why??? (see fsm:SP_START_CORE, notify_daemon_started)
  if (daemon->task != GNUNET_SCHEDULER_NO_TASK) /* Assertion here instead? */
    GNUNET_SCHEDULER_cancel (daemon->task);

  if (daemon->server != NULL)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Received `%s' from transport service of `%4s', disconnecting core!\n",
                "HELLO", GNUNET_i2s (&daemon->id));
    GNUNET_CORE_disconnect (daemon->server);
    daemon->server = NULL;
  }

  msize = ntohs (message->size);
  if (msize < 1)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "HELLO message of peer %s is of size 0\n",
                GNUNET_i2s (&daemon->id));
    return;
  }
  if (daemon->ghh != NULL)
  {
    GNUNET_TRANSPORT_get_hello_cancel (daemon->ghh);
    daemon->ghh = NULL;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received `%s' from transport service of `%4s'\n", "HELLO",
              GNUNET_i2s (&daemon->id));
  GNUNET_free_non_null (daemon->hello);
  daemon->hello = GNUNET_malloc (msize);
  memcpy (daemon->hello, message, msize);

  if (daemon->th != NULL)
  {
    GNUNET_TRANSPORT_disconnect (daemon->th);
    daemon->th = NULL;
  }
  daemon->phase = SP_START_DONE;
}


/**
 * Notify of a peer being up and running.  Scheduled as a task
 * so that variables which may need to be set are set before
 * the connect callback can set up new operations.
 * FIXME: what variables?????? where from????
 *
 * @param cls the testing daemon
 * @param tc task scheduler context
 */
static void
notify_daemon_started (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_TESTING_Daemon *d = cls;
  GNUNET_TESTING_NotifyDaemonRunning cb;

  cb = d->cb;
  d->cb = NULL;
  if (NULL != cb)
    cb (d->cb_cls, &d->id, d->cfg, d, NULL);
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
  struct GNUNET_TESTING_Daemon *d = cls;
  GNUNET_TESTING_NotifyDaemonRunning cb;
  enum GNUNET_OS_ProcessStatusType type;
  unsigned long code;
  char *dst;
  int bytes_read;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Peer %s FSM is in phase %u.\n",
              GNUNET_i2s (&d->id), d->phase);
  d->task = GNUNET_SCHEDULER_NO_TASK;
  switch (d->phase)
  {
  case SP_COPYING:
    /* confirm copying complete */
    if (GNUNET_OK != GNUNET_OS_process_status (d->proc, &type, &code))
    {
      if (GNUNET_TIME_absolute_get_remaining (d->max_timeout).rel_value == 0)
      {
        cb = d->cb;
        d->cb = NULL;
        if (NULL != cb)
          cb (d->cb_cls, NULL, d->cfg, d,
              _
              ("`scp' does not seem to terminate (timeout copying config).\n"));
        return;
      }
      /* wait some more */
      d->task =
          GNUNET_SCHEDULER_add_delayed (GNUNET_CONSTANTS_EXEC_WAIT, &start_fsm,
                                        d);
      return;
    }
    if ((type != GNUNET_OS_PROCESS_EXITED) || (code != 0))
    {
      cb = d->cb;
      d->cb = NULL;
      if (NULL != cb)
        cb (d->cb_cls, NULL, d->cfg, d, _("`scp' did not complete cleanly.\n"));
      return;
    }
    GNUNET_OS_process_close (d->proc);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Successfully copied configuration file.\n");
    d->phase = SP_COPIED;
    /* fall-through */
  case SP_COPIED:
    /* Start create hostkey process if we don't already know the peer identity! */
    if (GNUNET_NO == d->have_hostkey)
    {
      d->pipe_stdout = GNUNET_DISK_pipe (GNUNET_NO, GNUNET_NO, GNUNET_NO, GNUNET_YES);
      if (d->pipe_stdout == NULL)
      {
        cb = d->cb;
        d->cb = NULL;
        if (NULL != cb)
          cb (d->cb_cls, NULL, d->cfg, d,
              (NULL ==
               d->hostname) ?
              _("Failed to create pipe for `gnunet-peerinfo' process.\n") :
              _("Failed to create pipe for `ssh' process.\n"));
        return;
      }
      if (NULL == d->hostname)
      {
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                    "Starting `%s', with command `%s %s %s %s'.\n",
                    "gnunet-peerinfo", "gnunet-peerinfo", "-c", d->cfgfile,
                    "-sq");
        d->proc =
	    GNUNET_OS_start_process (GNUNET_YES, NULL, d->pipe_stdout, "gnunet-peerinfo",
                                     "gnunet-peerinfo", "-c", d->cfgfile, "-sq",
                                     NULL);
        GNUNET_DISK_pipe_close_end (d->pipe_stdout, GNUNET_DISK_PIPE_END_WRITE);
      }
      else
      {
        if (d->username != NULL)
          GNUNET_asprintf (&dst, "%s@%s", d->username, d->hostname);
        else
          dst = GNUNET_strdup (d->hostname);

        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                    "Starting `%s', with command `%s %s %s %s %s %s'.\n",
                    "gnunet-peerinfo", "ssh", dst, "gnunet-peerinfo", "-c",
                    d->cfgfile, "-sq");
        if (d->ssh_port_str == NULL)
        {
          d->proc = GNUNET_OS_start_process (GNUNET_NO, NULL, d->pipe_stdout, "ssh", "ssh",
#if !DEBUG_TESTING
                                             "-q",
#endif
                                             dst, "gnunet-peerinfo", "-c",
                                             d->cfgfile, "-sq", NULL);
        }
        else
        {
          d->proc =
	      GNUNET_OS_start_process (GNUNET_NO, NULL, d->pipe_stdout, "ssh", "ssh", "-p",
                                       d->ssh_port_str,
#if !DEBUG_TESTING
                                       "-q",
#endif
                                       dst, "gnunet-peerinfo", "-c", d->cfgfile,
                                       "-sq", NULL);
        }
        GNUNET_DISK_pipe_close_end (d->pipe_stdout, GNUNET_DISK_PIPE_END_WRITE);
        GNUNET_free (dst);
      }
      if (NULL == d->proc)
      {
        GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                    _("Could not start `%s' process to create hostkey.\n"),
                    (NULL == d->hostname) ? "gnunet-peerinfo" : "ssh");
        cb = d->cb;
        d->cb = NULL;
        if (NULL != cb)
          cb (d->cb_cls, NULL, d->cfg, d,
              (NULL ==
               d->hostname) ? _("Failed to start `gnunet-peerinfo' process.\n")
              : _("Failed to start `ssh' process.\n"));
        GNUNET_DISK_pipe_close (d->pipe_stdout);
        return;
      }
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Started `%s', waiting for hostkey.\n", "gnunet-peerinfo");
      d->phase = SP_HOSTKEY_CREATE;
      d->task =
          GNUNET_SCHEDULER_add_read_file (GNUNET_TIME_absolute_get_remaining
                                          (d->max_timeout),
                                          GNUNET_DISK_pipe_handle
                                          (d->pipe_stdout,
                                           GNUNET_DISK_PIPE_END_READ),
                                          &start_fsm, d);
    }
    else                        /* Already have a hostkey! */
    {
      if (d->hostkey_callback != NULL)
      {
        d->hostkey_callback (d->hostkey_cls, &d->id, d, NULL);
        d->hostkey_callback = NULL;
        d->phase = SP_HOSTKEY_CREATED;
      }
      else
        d->phase = SP_TOPOLOGY_SETUP;

      /* wait some more */
      d->task = GNUNET_SCHEDULER_add_now (&start_fsm, d);
    }
    break;
  case SP_HOSTKEY_CREATE:
    bytes_read =
        GNUNET_DISK_file_read (GNUNET_DISK_pipe_handle
                               (d->pipe_stdout, GNUNET_DISK_PIPE_END_READ),
                               &d->hostkeybuf[d->hostkeybufpos],
                               sizeof (d->hostkeybuf) - d->hostkeybufpos);
    if (bytes_read > 0)
      d->hostkeybufpos += bytes_read;

    if ((d->hostkeybufpos < 104) && (bytes_read > 0))
    {
      /* keep reading */
      d->task =
          GNUNET_SCHEDULER_add_read_file (GNUNET_TIME_absolute_get_remaining
                                          (d->max_timeout),
                                          GNUNET_DISK_pipe_handle
                                          (d->pipe_stdout,
                                           GNUNET_DISK_PIPE_END_READ),
                                          &start_fsm, d);
      return;
    }
    d->hostkeybuf[103] = '\0';

    if ((bytes_read < 0) ||
        (GNUNET_OK !=
         GNUNET_CRYPTO_hash_from_string (d->hostkeybuf, &d->id.hashPubKey)))
    {
      /* error */
      if (bytes_read < 0)
        GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                    _("Error reading from gnunet-peerinfo: %s\n"),
                    STRERROR (errno));
      else
        GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                    _("Malformed output from gnunet-peerinfo!\n"));
      cb = d->cb;
      d->cb = NULL;
      GNUNET_DISK_pipe_close (d->pipe_stdout);
      d->pipe_stdout = NULL;
      (void) GNUNET_OS_process_kill (d->proc, SIGKILL);
      GNUNET_break (GNUNET_OK == GNUNET_OS_process_wait (d->proc));
      GNUNET_OS_process_close (d->proc);
      d->proc = NULL;
      if (NULL != cb)
        cb (d->cb_cls, NULL, d->cfg, d, _("Failed to get hostkey!\n"));
      return;
    }
    d->shortname = GNUNET_strdup (GNUNET_i2s (&d->id));
    GNUNET_DISK_pipe_close (d->pipe_stdout);
    d->pipe_stdout = NULL;
    (void) GNUNET_OS_process_kill (d->proc, SIGKILL);
    GNUNET_break (GNUNET_OK == GNUNET_OS_process_wait (d->proc));
    GNUNET_OS_process_close (d->proc);
    d->proc = NULL;
    d->have_hostkey = GNUNET_YES;
    if (d->hostkey_callback != NULL)
    {
      d->hostkey_callback (d->hostkey_cls, &d->id, d, NULL);
      d->hostkey_callback = NULL;
      d->phase = SP_HOSTKEY_CREATED;
    }
    else
    {
      d->phase = SP_TOPOLOGY_SETUP;
    }
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Successfully got hostkey!\n");
    /* Fall through */
  case SP_HOSTKEY_CREATED:
    /* wait for topology finished */
    if ((GNUNET_YES == d->dead) ||
        (GNUNET_TIME_absolute_get_remaining (d->max_timeout).rel_value == 0))
    {
      cb = d->cb;
      d->cb = NULL;
      if (NULL != cb)
        cb (d->cb_cls, NULL, d->cfg, d,
            _("`Failed while waiting for topology setup!\n"));
      return;
    }

    d->task =
        GNUNET_SCHEDULER_add_delayed (GNUNET_CONSTANTS_EXEC_WAIT, &start_fsm,
                                      d);
    break;
  case SP_TOPOLOGY_SETUP:      /* Indicates topology setup has completed! */
    /* start GNUnet on remote host */
    if (NULL == d->hostname)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Starting `%s', with command `%s %s %s %s %s %s'.\n",
                  "gnunet-arm", "gnunet-arm", "-c", d->cfgfile, "-L", "DEBUG",
                  "-s");
      d->proc =
	  GNUNET_OS_start_process (GNUNET_YES, NULL, NULL, "gnunet-arm", "gnunet-arm", "-c",
                                   d->cfgfile,
                                   "-L", "DEBUG",
                                   "-s", "-q", "-T",
                                   GNUNET_TIME_relative_to_string
                                   (GNUNET_TIME_absolute_get_remaining
                                    (d->max_timeout)), NULL);
    }
    else
    {
      if (d->username != NULL)
        GNUNET_asprintf (&dst, "%s@%s", d->username, d->hostname);
      else
        dst = GNUNET_strdup (d->hostname);

      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  "Starting `%s', with command `%s %s %s %s %s %s %s %s'.\n",
                  "gnunet-arm", "ssh", dst, "gnunet-arm", "-c", d->cfgfile,
                  "-L", "DEBUG", "-s", "-q");
      if (d->ssh_port_str == NULL)
      {
        d->proc = GNUNET_OS_start_process (GNUNET_NO, NULL, NULL, "ssh", "ssh",
#if !DEBUG_TESTING
                                           "-q",
#endif
                                           dst, "gnunet-arm",
#if DEBUG_TESTING
                                           "-L", "DEBUG",
#endif
                                           "-c", d->cfgfile, "-s", "-q", "-T",
                                           GNUNET_TIME_relative_to_string
                                           (GNUNET_TIME_absolute_get_remaining
                                            (d->max_timeout)), NULL);
      }
      else
      {

        d->proc =
	    GNUNET_OS_start_process (GNUNET_NO, NULL, NULL, "ssh", "ssh", "-p",
                                     d->ssh_port_str,
#if !DEBUG_TESTING
                                     "-q",
#endif
                                     dst, "gnunet-arm",
#if DEBUG_TESTING
                                     "-L", "DEBUG",
#endif
                                     "-c", d->cfgfile, "-s", "-q", "-T",
                                     GNUNET_TIME_relative_to_string
                                     (GNUNET_TIME_absolute_get_remaining
                                      (d->max_timeout)), NULL);
      }
      GNUNET_free (dst);
    }
    if (NULL == d->proc)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  _("Could not start `%s' process to start GNUnet.\n"),
                  (NULL == d->hostname) ? "gnunet-arm" : "ssh");
      cb = d->cb;
      d->cb = NULL;
      if (NULL != cb)
        cb (d->cb_cls, NULL, d->cfg, d,
            (NULL ==
             d->hostname) ? _("Failed to start `gnunet-arm' process.\n") :
            _("Failed to start `ssh' process.\n"));
      return;
    }
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Started `%s', waiting for `%s' to be up.\n", "gnunet-arm",
                "gnunet-service-core");
    d->phase = SP_START_ARMING;
    d->task =
        GNUNET_SCHEDULER_add_delayed (GNUNET_CONSTANTS_EXEC_WAIT, &start_fsm,
                                      d);
    break;
  case SP_START_ARMING:
    if (GNUNET_OK != GNUNET_OS_process_status (d->proc, &type, &code))
    {
      if (GNUNET_TIME_absolute_get_remaining (d->max_timeout).rel_value == 0)
      {
        cb = d->cb;
        d->cb = NULL;
        if (NULL != cb)
          cb (d->cb_cls, NULL, d->cfg, d,
              (NULL ==
               d->hostname) ? _("`gnunet-arm' does not seem to terminate.\n") :
              _("`ssh' does not seem to terminate.\n"));
        if (d->cfg != NULL)
        {
          GNUNET_CONFIGURATION_destroy (d->cfg);
          d->cfg = NULL;
        }
        if (d->cfgfile != NULL)
        {
          GNUNET_free (d->cfgfile);
          d->cfgfile = NULL;
        }
        GNUNET_free_non_null (d->hostname);
        GNUNET_free_non_null (d->username);
        GNUNET_free (d->proc);
//         GNUNET_free (d); // FIXME (could this leak)
        d->hostname = NULL;     // Quick hack to avoid crashing (testing need to be
        d->cfg = NULL;          // overhauled anyway, and the error managing is
        // pretty broken anyway.
        return;
      }
      /* wait some more */
      d->task =
          GNUNET_SCHEDULER_add_delayed (GNUNET_CONSTANTS_EXEC_WAIT, &start_fsm,
                                        d);
      return;
    }
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Successfully started `%s'.\n",
                "gnunet-arm");
    GNUNET_free (d->proc);
    d->phase = SP_START_CORE;
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Calling CORE_connect\n");
    /* Fall through */
  case SP_START_CORE:
    if (d->server != NULL)
      GNUNET_CORE_disconnect (d->server);

    d->th = GNUNET_TRANSPORT_connect (d->cfg, &d->id, d, NULL, NULL, NULL);
    if (d->th == NULL)
    {
      if (GNUNET_YES == d->dead)
        GNUNET_TESTING_daemon_stop (d,
                                    GNUNET_TIME_absolute_get_remaining
                                    (d->max_timeout), d->dead_cb,
                                    d->dead_cb_cls, GNUNET_YES, GNUNET_NO);
      else if (NULL != d->cb)
        d->cb (d->cb_cls, &d->id, d->cfg, d,
               _("Failed to connect to transport service!\n"));
      return;
    }
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Connected to transport service `%s', getting HELLO\n",
                GNUNET_i2s (&d->id));
    d->ghh = GNUNET_TRANSPORT_get_hello (d->th, &process_hello, d);
    /* FIXME: store task ID somewhere! */
    GNUNET_SCHEDULER_add_now (&notify_daemon_started, d);
    /*cb = d->cb;
     * d->cb = NULL;
     * if (NULL != cb)
     * cb (d->cb_cls, &d->id, d->cfg, d, NULL); */
    d->running = GNUNET_YES;
    d->phase = SP_GET_HELLO;
    break;
  case SP_GET_HELLO:
    if (GNUNET_TIME_absolute_get_remaining (d->max_timeout).rel_value == 0)
    {
      if (d->server != NULL)
        GNUNET_CORE_disconnect (d->server);
      if (d->th != NULL)
        GNUNET_TRANSPORT_disconnect (d->th);
      cb = d->cb;
      d->cb = NULL;
      if (NULL != cb)
        cb (d->cb_cls, NULL, d->cfg, d, _("Unable to get HELLO for peer!\n"));
      GNUNET_CONFIGURATION_destroy (d->cfg);
      GNUNET_free (d->cfgfile);
      GNUNET_free_non_null (d->hostname);
      GNUNET_free_non_null (d->username);
      GNUNET_free (d);
      return;
    }
    if (d->hello != NULL)
      return;
    GNUNET_assert (d->task == GNUNET_SCHEDULER_NO_TASK);
    d->task =
        GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_relative_multiply
                                      (GNUNET_CONSTANTS_SERVICE_RETRY, 2),
                                      &start_fsm, d);
    break;
  case SP_START_DONE:
    GNUNET_break (0);
    break;
  case SP_SERVICE_START:
    /* confirm gnunet-arm exited */
    if (GNUNET_OK != GNUNET_OS_process_status (d->proc, &type, &code))
    {
      if (GNUNET_TIME_absolute_get_remaining (d->max_timeout).rel_value == 0)
      {
        cb = d->cb;
        d->cb = NULL;
        if (NULL != cb)
          cb (d->cb_cls, NULL, d->cfg, d,
              (NULL ==
               d->hostname) ? _("`gnunet-arm' does not seem to terminate.\n") :
              _("`ssh' does not seem to terminate.\n"));
        return;
      }
      /* wait some more */
      d->task =
          GNUNET_SCHEDULER_add_delayed (GNUNET_CONSTANTS_EXEC_WAIT, &start_fsm,
                                        d);
      return;
    }
#if EXTRA_CHECKS
    if ((type != GNUNET_OS_PROCESS_EXITED) || (code != 0))
    {
      cb = d->cb;
      d->cb = NULL;
      if (NULL != cb)
        cb (d->cb_cls, NULL, d->cfg, d,
            (NULL ==
             d->hostname) ?
            _
            ("`gnunet-arm' terminated with non-zero exit status (or timed out)!\n")
            : _("`ssh' does not seem to terminate.\n"));
      return;
    }
#endif
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Service startup complete!\n");
    cb = d->cb;
    d->cb = NULL;
    d->phase = SP_START_DONE;
    if (NULL != cb)
      cb (d->cb_cls, &d->id, d->cfg, d, NULL);
    break;
  case SP_SERVICE_SHUTDOWN_START:
    /* confirm copying complete */
    if (GNUNET_OK != GNUNET_OS_process_status (d->proc, &type, &code))
    {
      if (GNUNET_TIME_absolute_get_remaining (d->max_timeout).rel_value == 0)
      {
        if (NULL != d->dead_cb)
          d->dead_cb (d->dead_cb_cls,
                      _
                      ("either `gnunet-arm' or `ssh' does not seem to terminate.\n"));
        return;
      }
      /* wait some more */
      d->task =
          GNUNET_SCHEDULER_add_delayed (GNUNET_CONSTANTS_EXEC_WAIT, &start_fsm,
                                        d);
      return;
    }
#if EXTRA_CHECKS
    if ((type != GNUNET_OS_PROCESS_EXITED) || (code != 0))
    {
      if (NULL != d->dead_cb)
        d->dead_cb (d->dead_cb_cls,
                    _
                    ("shutdown (either `gnunet-arm' or `ssh') did not complete cleanly.\n"));
      return;
    }
#endif
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Service shutdown complete.\n");
    if (NULL != d->dead_cb)
      d->dead_cb (d->dead_cb_cls, NULL);
    break;
  case SP_SHUTDOWN_START:
    /* confirm copying complete */
    if (GNUNET_OK != GNUNET_OS_process_status (d->proc, &type, &code))
    {
      if (GNUNET_TIME_absolute_get_remaining (d->max_timeout).rel_value == 0)
      {
        if (NULL != d->dead_cb)
          d->dead_cb (d->dead_cb_cls,
                      _
                      ("either `gnunet-arm' or `ssh' does not seem to terminate.\n"));
        if (d->th != NULL)
        {
          GNUNET_TRANSPORT_get_hello_cancel (d->ghh);
          d->ghh = NULL;
          GNUNET_TRANSPORT_disconnect (d->th);
          d->th = NULL;
        }
        if (d->cfg != NULL)
        {
          GNUNET_CONFIGURATION_destroy (d->cfg);
          d->cfg = NULL;
        }
        if (d->cfgfile != NULL)
        {
          GNUNET_free (d->cfgfile);
          d->cfgfile = NULL;
        }
        GNUNET_free_non_null (d->hello);
        GNUNET_free_non_null (d->hostname);
        GNUNET_free_non_null (d->username);
        GNUNET_free_non_null (d->shortname);
        GNUNET_free_non_null (d->proc);
        d->proc = NULL;
        GNUNET_free (d);
        return;
      }
      /* wait some more */
      d->task =
          GNUNET_SCHEDULER_add_delayed (GNUNET_CONSTANTS_EXEC_WAIT, &start_fsm,
                                        d);
      return;
    }
    if ((type != GNUNET_OS_PROCESS_EXITED) || (code != 0))
    {
      if (NULL != d->dead_cb)
        d->dead_cb (d->dead_cb_cls,
                    _
                    ("shutdown (either `gnunet-arm' or `ssh') did not complete cleanly.\n"));
      if (d->th != NULL)
      {
        GNUNET_TRANSPORT_get_hello_cancel (d->ghh);
        d->ghh = NULL;
        GNUNET_TRANSPORT_disconnect (d->th);
        d->th = NULL;
      }
      if (d->server != NULL)
      {
        GNUNET_CORE_disconnect (d->server);
        d->server = NULL;
      }
      GNUNET_CONFIGURATION_destroy (d->cfg);
      d->cfg = NULL;
      GNUNET_free (d->cfgfile);
      GNUNET_free_non_null (d->hello);
      GNUNET_free_non_null (d->hostname);
      GNUNET_free_non_null (d->username);
      GNUNET_free_non_null (d->shortname);
      GNUNET_free_non_null (d->proc);
      d->proc = NULL;
      GNUNET_free (d);
      return;
    }
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Peer shutdown complete.\n");
    if (d->server != NULL)
    {
      GNUNET_CORE_disconnect (d->server);
      d->server = NULL;
    }

    if (d->th != NULL)
    {
      GNUNET_TRANSPORT_get_hello_cancel (d->ghh);
      d->ghh = NULL;
      GNUNET_TRANSPORT_disconnect (d->th);
      d->th = NULL;
    }

    if (NULL != d->dead_cb)
      d->dead_cb (d->dead_cb_cls, NULL);

    /* state clean up and notifications */
    if (d->churn == GNUNET_NO)
    {
      GNUNET_CONFIGURATION_destroy (d->cfg);
      d->cfg = NULL;
      GNUNET_free (d->cfgfile);
      GNUNET_free_non_null (d->hostname);
      GNUNET_free_non_null (d->username);
    }

    GNUNET_free_non_null (d->hello);
    d->hello = NULL;
    GNUNET_free_non_null (d->shortname);
    GNUNET_free_non_null (d->proc);
    d->proc = NULL;
    d->shortname = NULL;
    if (d->churn == GNUNET_NO)
      GNUNET_free (d);

    break;
  case SP_CONFIG_UPDATE:
    /* confirm copying complete */
    if (GNUNET_OK != GNUNET_OS_process_status (d->proc, &type, &code))
    {
      if (GNUNET_TIME_absolute_get_remaining (d->max_timeout).rel_value == 0)   /* FIXME: config update should take timeout parameter! */
      {
        cb = d->cb;
        d->cb = NULL;
        if (NULL != cb)
          cb (d->cb_cls, NULL, d->cfg, d,
              _("`scp' does not seem to terminate.\n"));
        return;
      }
      /* wait some more */
      d->task =
          GNUNET_SCHEDULER_add_delayed (GNUNET_CONSTANTS_EXEC_WAIT, &start_fsm,
                                        d);
      return;
    }
    if ((type != GNUNET_OS_PROCESS_EXITED) || (code != 0))
    {
      if (NULL != d->update_cb)
        d->update_cb (d->update_cb_cls, _("`scp' did not complete cleanly.\n"));
      return;
    }
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Successfully copied configuration file.\n");
    if (NULL != d->update_cb)
      d->update_cb (d->update_cb_cls, NULL);
    d->phase = SP_START_DONE;
    break;
  }
}

/**
 * Continues GNUnet daemon startup when user wanted to be notified
 * once a hostkey was generated (for creating friends files, blacklists,
 * etc.).
 *
 * @param daemon the daemon to finish starting
 */
void
GNUNET_TESTING_daemon_continue_startup (struct GNUNET_TESTING_Daemon *daemon)
{
  GNUNET_assert (daemon->phase == SP_HOSTKEY_CREATED);
  daemon->phase = SP_TOPOLOGY_SETUP;
}

/**
 * Check whether the given daemon is running.
 *
 * @param daemon the daemon to check
 *
 * @return GNUNET_YES if the daemon is up, GNUNET_NO if the
 *         daemon is down, GNUNET_SYSERR on error.
 */
int
GNUNET_TESTING_test_daemon_running (struct GNUNET_TESTING_Daemon *daemon)
{
  if (daemon == NULL)
    return GNUNET_SYSERR;

  if (daemon->running == GNUNET_YES)
    return GNUNET_YES;
  return GNUNET_NO;
}


/**
 * Starts a GNUnet daemon service which has been previously stopped.
 *
 * @param d the daemon for which the service should be started
 * @param service the name of the service to start
 * @param timeout how long to wait for process for shutdown to complete
 * @param cb function called once the service starts
 * @param cb_cls closure for cb
 */
void
GNUNET_TESTING_daemon_start_stopped_service (struct GNUNET_TESTING_Daemon *d,
                                             char *service,
                                             struct GNUNET_TIME_Relative
                                             timeout,
                                             GNUNET_TESTING_NotifyDaemonRunning
                                             cb, void *cb_cls)
{
  char *arg;

  d->cb = cb;
  d->cb_cls = cb_cls;

  GNUNET_assert (d->running == GNUNET_YES);

  if (d->phase == SP_CONFIG_UPDATE)
  {
    GNUNET_SCHEDULER_cancel (d->task);
    d->phase = SP_START_DONE;
  }

  if (d->churned_services == NULL)
  {
    d->cb (d->cb_cls, &d->id, d->cfg, d,
           "No service has been churned off yet!!");
    return;
  }
  d->phase = SP_SERVICE_START;
  GNUNET_free (d->churned_services);
  d->churned_services = NULL;
  d->max_timeout = GNUNET_TIME_relative_to_absolute (timeout);
  /* Check if this is a local or remote process */
  if (NULL != d->hostname)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Starting gnunet-arm with config `%s' on host `%s'.\n",
                d->cfgfile, d->hostname);
    if (d->username != NULL)
      GNUNET_asprintf (&arg, "%s@%s", d->username, d->hostname);
    else
      arg = GNUNET_strdup (d->hostname);

    d->proc = GNUNET_OS_start_process (GNUNET_NO, NULL, NULL, "ssh", "ssh",
#if !DEBUG_TESTING
                                       "-q",
#endif
                                       arg, "gnunet-arm",
#if DEBUG_TESTING
                                       "-L", "DEBUG",
#endif
                                       "-c", d->cfgfile, "-i", service, "-q",
                                       "-T",
                                       GNUNET_TIME_relative_to_string (timeout),
                                       NULL);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Starting gnunet-arm with command ssh %s gnunet-arm -c %s -i %s -q\n",
                arg, "gnunet-arm", d->cfgfile, service);
    GNUNET_free (arg);
  }
  else
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Starting gnunet-arm with config `%s' locally.\n", d->cfgfile);
    d->proc = GNUNET_OS_start_process (GNUNET_YES, NULL, NULL, "gnunet-arm", "gnunet-arm",
#if DEBUG_TESTING
                                       "-L", "DEBUG",
#endif
                                       "-c", d->cfgfile, "-i", service, "-q",
                                       "-T",
                                       GNUNET_TIME_relative_to_string (timeout),
                                       NULL);
  }

  d->max_timeout = GNUNET_TIME_relative_to_absolute (timeout);
  d->task = GNUNET_SCHEDULER_add_now (&start_fsm, d);
}

/**
 * Starts a GNUnet daemon's service.
 *
 * @param d the daemon for which the service should be started
 * @param service the name of the service to start
 * @param timeout how long to wait for process for startup
 * @param cb function called once gnunet-arm returns
 * @param cb_cls closure for cb
 */
void
GNUNET_TESTING_daemon_start_service (struct GNUNET_TESTING_Daemon *d,
                                     const char *service,
                                     struct GNUNET_TIME_Relative timeout,
                                     GNUNET_TESTING_NotifyDaemonRunning cb,
                                     void *cb_cls)
{
  char *arg;

  d->cb = cb;
  d->cb_cls = cb_cls;

  GNUNET_assert (service != NULL);
  GNUNET_assert (d->running == GNUNET_YES);
  GNUNET_assert (d->phase == SP_START_DONE);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              _("Starting service %s for peer `%4s'\n"), service,
              GNUNET_i2s (&d->id));
  d->phase = SP_SERVICE_START;
  d->max_timeout = GNUNET_TIME_relative_to_absolute (timeout);
  /* Check if this is a local or remote process */
  if (NULL != d->hostname)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Starting gnunet-arm with config `%s' on host `%s'.\n",
                d->cfgfile, d->hostname);
    if (d->username != NULL)
      GNUNET_asprintf (&arg, "%s@%s", d->username, d->hostname);
    else
      arg = GNUNET_strdup (d->hostname);

    d->proc = GNUNET_OS_start_process (GNUNET_NO, NULL, NULL, "ssh", "ssh",
#if !DEBUG_TESTING
                                       "-q",
#endif
                                       arg, "gnunet-arm",
#if DEBUG_TESTING
                                       "-L", "DEBUG",
#endif
                                       "-c", d->cfgfile, "-i", service, "-q",
                                       "-T",
                                       GNUNET_TIME_relative_to_string (timeout),
                                       NULL);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Starting gnunet-arm with command ssh %s gnunet-arm -c %s -i %s -q -T %s\n",
                arg, "gnunet-arm", d->cfgfile, service,
                GNUNET_TIME_relative_to_string (timeout));
    GNUNET_free (arg);
  }
  else
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Starting gnunet-arm with config `%s' locally.\n", d->cfgfile);
    d->proc = GNUNET_OS_start_process (GNUNET_YES, NULL, NULL, "gnunet-arm", "gnunet-arm",
#if DEBUG_TESTING
                                       "-L", "DEBUG",
#endif
                                       "-c", d->cfgfile, "-i", service, "-q",
                                       "-T",
                                       GNUNET_TIME_relative_to_string (timeout),
                                       NULL);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Starting gnunet-arm with command %s -c %s -i %s -q -T %s\n",
                "gnunet-arm", d->cfgfile, service,
                GNUNET_TIME_relative_to_string (timeout));
  }

  d->max_timeout = GNUNET_TIME_relative_to_absolute (timeout);
  d->task = GNUNET_SCHEDULER_add_now (&start_fsm, d);
}

/**
 * Start a peer that has previously been stopped using the daemon_stop
 * call (and files weren't deleted and the allow restart flag)
 *
 * @param daemon the daemon to start (has been previously stopped)
 * @param timeout how long to wait for restart
 * @param cb the callback for notification when the peer is running
 * @param cb_cls closure for the callback
 */
void
GNUNET_TESTING_daemon_start_stopped (struct GNUNET_TESTING_Daemon *daemon,
                                     struct GNUNET_TIME_Relative timeout,
                                     GNUNET_TESTING_NotifyDaemonRunning cb,
                                     void *cb_cls)
{
  if (daemon->running == GNUNET_YES)
  {
    cb (cb_cls, &daemon->id, daemon->cfg, daemon,
        "Daemon already running, can't restart!");
    return;
  }

  daemon->cb = cb;
  daemon->cb_cls = cb_cls;
  daemon->phase = SP_TOPOLOGY_SETUP;
  daemon->max_timeout = GNUNET_TIME_relative_to_absolute (timeout);
  /* FIXME: why add_continuation? */
  GNUNET_SCHEDULER_add_continuation (&start_fsm, daemon,
                                     GNUNET_SCHEDULER_REASON_PREREQ_DONE);
}

/**
 * Starts a GNUnet daemon.  GNUnet must be installed on the target
 * system and available in the PATH.  The machine must furthermore be
 * reachable via "ssh" (unless the hostname is "NULL") without the
 * need to enter a password.
 *
 * @param cfg configuration to use
 * @param timeout how long to wait starting up peers
 * @param pretend GNUNET_YES to set up files but not start peer GNUNET_NO
 *                to really start the peer (default)
 * @param hostname name of the machine where to run GNUnet
 *        (use NULL for localhost).
 * @param ssh_username ssh username to use when connecting to hostname
 * @param sshport port to pass to ssh process when connecting to hostname
 * @param hostkey pointer to a hostkey to be written to disk (instead of being generated)
 * @param hostkey_callback function to call once the hostkey has been
 *        generated for this peer, but it hasn't yet been started
 *        (NULL to start immediately, otherwise waits on GNUNET_TESTING_daemon_continue_start)
 * @param hostkey_cls closure for hostkey callback
 * @param cb function to call once peer is up, or failed to start
 * @param cb_cls closure for cb
 * @return handle to the daemon (actual start will be completed asynchronously)
 */
struct GNUNET_TESTING_Daemon *
GNUNET_TESTING_daemon_start (const struct GNUNET_CONFIGURATION_Handle *cfg,
                             struct GNUNET_TIME_Relative timeout, int pretend,
                             const char *hostname, const char *ssh_username,
                             uint16_t sshport, const char *hostkey,
                             GNUNET_TESTING_NotifyHostkeyCreated
                             hostkey_callback, void *hostkey_cls,
                             GNUNET_TESTING_NotifyDaemonRunning cb,
                             void *cb_cls)
{
  struct GNUNET_TESTING_Daemon *ret;
  char *arg;
  char *username;
  char *servicehome;
  char *baseservicehome;
  char *slash;
  char *hostkeyfile;
  char *temp_file_name;
  struct GNUNET_DISK_FileHandle *fn;
  struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded public_key;
  struct GNUNET_CRYPTO_RsaPrivateKey *private_key;

  ret = GNUNET_malloc (sizeof (struct GNUNET_TESTING_Daemon));
  ret->hostname = (hostname == NULL) ? NULL : GNUNET_strdup (hostname);
  if (sshport != 0)
  {
    GNUNET_asprintf (&ret->ssh_port_str, "%d", sshport);
  }
  else
    ret->ssh_port_str = NULL;

  /* Find service home and base service home directories, create it if it doesn't exist */
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_CONFIGURATION_get_value_string (cfg, "PATHS",
                                                        "SERVICEHOME",
                                                        &servicehome));

  GNUNET_assert (GNUNET_OK == GNUNET_DISK_directory_create (servicehome));
  GNUNET_asprintf (&temp_file_name, "%s/gnunet-testing-config", servicehome);
  ret->cfgfile = GNUNET_DISK_mktemp (temp_file_name);
  GNUNET_free (temp_file_name);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Setting up peer with configuration file `%s'.\n", ret->cfgfile);
  if (NULL == ret->cfgfile)
  {
    GNUNET_free_non_null (ret->ssh_port_str);
    GNUNET_free_non_null (ret->hostname);
    GNUNET_free (ret);
    return NULL;
  }
  ret->hostkey_callback = hostkey_callback;
  ret->hostkey_cls = hostkey_cls;
  ret->cb = cb;
  ret->cb_cls = cb_cls;
  ret->max_timeout = GNUNET_TIME_relative_to_absolute (timeout);
  ret->cfg = GNUNET_CONFIGURATION_dup (cfg);
  GNUNET_CONFIGURATION_set_value_string (ret->cfg, "PATHS", "DEFAULTCONFIG",
                                         ret->cfgfile);

  if (hostkey != NULL)          /* Get the peer identity from the hostkey */
  {
    private_key = GNUNET_CRYPTO_rsa_decode_key (hostkey, HOSTKEYFILESIZE);
    GNUNET_assert (private_key != NULL);
    GNUNET_CRYPTO_rsa_key_get_public (private_key, &public_key);
    GNUNET_CRYPTO_hash (&public_key,
                        sizeof (struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded),
                        &ret->id.hashPubKey);
    ret->shortname = GNUNET_strdup (GNUNET_i2s (&ret->id));
    ret->have_hostkey = GNUNET_YES;
    GNUNET_CRYPTO_rsa_key_free (private_key);
  }

  /* Write hostkey to file, if we were given one */
  hostkeyfile = NULL;
  if (hostkey != NULL)
  {
    GNUNET_asprintf (&hostkeyfile, "%s/.hostkey", servicehome);
    fn = GNUNET_DISK_file_open (hostkeyfile,
                                GNUNET_DISK_OPEN_READWRITE |
                                GNUNET_DISK_OPEN_CREATE,
                                GNUNET_DISK_PERM_USER_READ |
                                GNUNET_DISK_PERM_USER_WRITE);
    GNUNET_assert (fn != NULL);
    GNUNET_assert (HOSTKEYFILESIZE ==
                   GNUNET_DISK_file_write (fn, hostkey, HOSTKEYFILESIZE));
    GNUNET_assert (GNUNET_OK == GNUNET_DISK_file_close (fn));
  }

  /* write configuration to temporary file */
  if (GNUNET_OK != GNUNET_CONFIGURATION_write (ret->cfg, ret->cfgfile))
  {
    if (0 != UNLINK (ret->cfgfile))
      GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_WARNING, "unlink",
                                ret->cfgfile);
    GNUNET_CONFIGURATION_destroy (ret->cfg);
    GNUNET_free_non_null (ret->hostname);
    GNUNET_free (ret->cfgfile);
    GNUNET_free (ret);
    return NULL;
  }
  if (ssh_username != NULL)
    username = GNUNET_strdup (ssh_username);
  if ((ssh_username == NULL) &&
      (GNUNET_OK !=
       GNUNET_CONFIGURATION_get_value_string (cfg, "TESTING", "USERNAME",
                                              &username)))
  {
    if (NULL != getenv ("USER"))
      username = GNUNET_strdup (getenv ("USER"));
    else
      username = NULL;
  }
  ret->username = username;

  if (GNUNET_NO == pretend)     /* Copy files, enter finite state machine */
  {
    /* copy directory to remote host */
    if (NULL != hostname)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Copying configuration directory to host `%s'.\n", hostname);
      baseservicehome = GNUNET_strdup (servicehome);
      /* Remove trailing /'s */
      while (baseservicehome[strlen (baseservicehome) - 1] == '/')
        baseservicehome[strlen (baseservicehome) - 1] = '\0';
      /* Find next directory /, jump one ahead */
      slash = strrchr (baseservicehome, '/');
      if (slash != NULL)
        *(++slash) = '\0';

      ret->phase = SP_COPYING;
      if (NULL != username)
        GNUNET_asprintf (&arg, "%s@%s:%s", username, hostname, baseservicehome);
      else
        GNUNET_asprintf (&arg, "%s:%s", hostname, baseservicehome);
      GNUNET_free (baseservicehome);
      if (ret->ssh_port_str == NULL)
      {
        ret->proc = GNUNET_OS_start_process (GNUNET_NO, NULL, NULL, "scp", "scp", "-r",
#if !DEBUG_TESTING
                                             "-q",
#endif
                                             servicehome, arg, NULL);
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                    "copying directory with command scp -r %s %s\n",
                    servicehome, arg);
      }
      else
      {
        ret->proc =
	    GNUNET_OS_start_process (GNUNET_NO, NULL, NULL, "scp", "scp", "-r", "-P",
                                     ret->ssh_port_str,
#if !DEBUG_TESTING
                                     "-q",
#endif
                                     servicehome, arg, NULL);
      }
      GNUNET_free (arg);
      if (NULL == ret->proc)
      {
        GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                    _
                    ("Could not start `%s' process to copy configuration directory.\n"),
                    "scp");
        if (0 != UNLINK (ret->cfgfile))
          GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_WARNING, "unlink",
                                    ret->cfgfile);
        GNUNET_CONFIGURATION_destroy (ret->cfg);
        GNUNET_free_non_null (ret->hostname);
        GNUNET_free_non_null (ret->username);
        GNUNET_free (ret->cfgfile);
        GNUNET_free (ret);
        if ((hostkey != NULL) && (0 != UNLINK (hostkeyfile)))
          GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_WARNING, "unlink",
                                    hostkeyfile);
        GNUNET_free_non_null (hostkeyfile);
        GNUNET_assert (GNUNET_OK == GNUNET_DISK_directory_remove (servicehome));
        GNUNET_free (servicehome);
        return NULL;
      }

      ret->task =
          GNUNET_SCHEDULER_add_delayed (GNUNET_CONSTANTS_EXEC_WAIT, &start_fsm,
                                        ret);
      GNUNET_free_non_null (hostkeyfile);
      GNUNET_free (servicehome);
      return ret;
    }
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "No need to copy configuration file since we are running locally.\n");
    ret->phase = SP_COPIED;
    /* FIXME: why add_cont? */
    GNUNET_SCHEDULER_add_continuation (&start_fsm, ret,
                                       GNUNET_SCHEDULER_REASON_PREREQ_DONE);
  }
  GNUNET_free_non_null (hostkeyfile);
  GNUNET_free (servicehome);
  return ret;
}


/**
 * Restart (stop and start) a GNUnet daemon.
 *
 * @param d the daemon that should be restarted
 * @param cb function called once the daemon is (re)started
 * @param cb_cls closure for cb
 */
void
GNUNET_TESTING_daemon_restart (struct GNUNET_TESTING_Daemon *d,
                               GNUNET_TESTING_NotifyDaemonRunning cb,
                               void *cb_cls)
{
  char *arg;
  char *del_arg;

  del_arg = NULL;
  if (NULL != d->cb)
  {
    d->dead = GNUNET_YES;
    return;
  }

  d->cb = cb;
  d->cb_cls = cb_cls;

  if (d->phase == SP_CONFIG_UPDATE)
  {
    GNUNET_SCHEDULER_cancel (d->task);
    d->phase = SP_START_DONE;
  }
  if (d->server != NULL)
  {
    GNUNET_CORE_disconnect (d->server);
    d->server = NULL;
  }

  if (d->th != NULL)
  {
    GNUNET_TRANSPORT_get_hello_cancel (d->ghh);
    d->ghh = NULL;
    GNUNET_TRANSPORT_disconnect (d->th);
    d->th = NULL;
  }
  /* state clean up and notifications */
  GNUNET_free_non_null (d->hello);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, _("Terminating peer `%4s'\n"),
              GNUNET_i2s (&d->id));
  d->phase = SP_START_ARMING;

  /* Check if this is a local or remote process */
  if (NULL != d->hostname)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Stopping gnunet-arm with config `%s' on host `%s'.\n",
                d->cfgfile, d->hostname);
    if (d->username != NULL)
      GNUNET_asprintf (&arg, "%s@%s", d->username, d->hostname);
    else
      arg = GNUNET_strdup (d->hostname);

    d->proc = GNUNET_OS_start_process (GNUNET_NO, NULL, NULL, "ssh", "ssh",
#if !DEBUG_TESTING
                                       "-q",
#endif
                                       arg, "gnunet-arm",
#if DEBUG_TESTING
                                       "-L", "DEBUG",
#endif
                                       "-c", d->cfgfile, "-e", "-r", NULL);
    /* Use -r to restart arm and all services */

    GNUNET_free (arg);
  }
  else
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Stopping gnunet-arm with config `%s' locally.\n", d->cfgfile);
    d->proc = GNUNET_OS_start_process (GNUNET_YES, NULL, NULL, "gnunet-arm", "gnunet-arm",
#if DEBUG_TESTING
                                       "-L", "DEBUG",
#endif
                                       "-c", d->cfgfile, "-e", "-r", NULL);
  }

  GNUNET_free_non_null (del_arg);
  d->task =
      GNUNET_SCHEDULER_add_delayed (GNUNET_CONSTANTS_EXEC_WAIT, &start_fsm, d);

}


/**
 * Stops a GNUnet daemon.
 *
 * @param d the daemon that should be stopped
 * @param service the name of the service to stop
 * @param timeout how long to wait for process for shutdown to complete
 * @param cb function called once the daemon was stopped
 * @param cb_cls closure for cb
 */
void
GNUNET_TESTING_daemon_stop_service (struct GNUNET_TESTING_Daemon *d,
                                    const char *service,
                                    struct GNUNET_TIME_Relative timeout,
                                    GNUNET_TESTING_NotifyCompletion cb,
                                    void *cb_cls)
{
  char *arg;

  d->dead_cb = cb;
  d->dead_cb_cls = cb_cls;

  GNUNET_assert (d->running == GNUNET_YES);

  if (d->phase == SP_CONFIG_UPDATE)
  {
    GNUNET_SCHEDULER_cancel (d->task);
    d->phase = SP_START_DONE;
  }

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, _("Terminating peer `%4s'\n"),
              GNUNET_i2s (&d->id));
  if (d->churned_services != NULL)
  {
    d->dead_cb (d->dead_cb_cls, "A service has already been turned off!!");
    return;
  }
  d->phase = SP_SERVICE_SHUTDOWN_START;
  d->churned_services = GNUNET_strdup (service);
  d->max_timeout = GNUNET_TIME_relative_to_absolute (timeout);
  /* Check if this is a local or remote process */
  if (NULL != d->hostname)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Stopping gnunet-arm with config `%s' on host `%s'.\n",
                d->cfgfile, d->hostname);
    if (d->username != NULL)
      GNUNET_asprintf (&arg, "%s@%s", d->username, d->hostname);
    else
      arg = GNUNET_strdup (d->hostname);

    d->proc = GNUNET_OS_start_process (GNUNET_NO, NULL, NULL, "ssh", "ssh",
#if !DEBUG_TESTING
                                       "-q",
#endif
                                       arg, "gnunet-arm",
#if DEBUG_TESTING
                                       "-L", "DEBUG",
#endif
                                       "-c", d->cfgfile, "-k", service, "-q",
                                       "-T",
                                       GNUNET_TIME_relative_to_string (timeout),
                                       NULL);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Stopping gnunet-arm with command ssh %s gnunet-arm -c %s -k %s -q\n",
                arg, "gnunet-arm", d->cfgfile, service);
    GNUNET_free (arg);
  }
  else
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Stopping gnunet-arm with config `%s' locally.\n", d->cfgfile);
    d->proc = GNUNET_OS_start_process (GNUNET_YES, NULL, NULL, "gnunet-arm", "gnunet-arm",
#if DEBUG_TESTING
                                       "-L", "DEBUG",
#endif
                                       "-c", d->cfgfile, "-k", service, "-q",
                                       "-T",
                                       GNUNET_TIME_relative_to_string (timeout),
                                       NULL);
  }

  d->max_timeout = GNUNET_TIME_relative_to_absolute (timeout);
  d->task = GNUNET_SCHEDULER_add_now (&start_fsm, d);
}


/**
 * Stops a GNUnet daemon.
 *
 * @param d the daemon that should be stopped
 * @param timeout how long to wait for process for shutdown to complete
 * @param cb function called once the daemon was stopped
 * @param cb_cls closure for cb
 * @param delete_files GNUNET_YES to remove files, GNUNET_NO
 *        to leave them
 * @param allow_restart GNUNET_YES to restart peer later (using this API)
 *        GNUNET_NO to kill off and clean up for good
 */
void
GNUNET_TESTING_daemon_stop (struct GNUNET_TESTING_Daemon *d,
                            struct GNUNET_TIME_Relative timeout,
                            GNUNET_TESTING_NotifyCompletion cb, void *cb_cls,
                            int delete_files, int allow_restart)
{
  char *arg;
  char *del_arg;

  d->dead_cb = cb;
  d->dead_cb_cls = cb_cls;

  if (NULL != d->cb)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, _("Setting d->dead on peer `%4s'\n"),
                GNUNET_i2s (&d->id));
    d->dead = GNUNET_YES;
    return;
  }

  if ((d->running == GNUNET_NO) && (d->churn == GNUNET_YES))    /* Peer has already been stopped in churn context! */
  {
    /* Free what was left from churning! */
    GNUNET_assert (d->cfg != NULL);
    GNUNET_CONFIGURATION_destroy (d->cfg);
    if (delete_files == GNUNET_YES)
    {
      if (0 != UNLINK (d->cfgfile))
      {
        GNUNET_log_strerror (GNUNET_ERROR_TYPE_WARNING, "unlink");
      }
    }
    GNUNET_free (d->cfgfile);
    GNUNET_free_non_null (d->hostname);
    GNUNET_free_non_null (d->username);
    if (NULL != d->dead_cb)
      d->dead_cb (d->dead_cb_cls, NULL);
    GNUNET_free (d);
    return;
  }

  del_arg = NULL;
  if (delete_files == GNUNET_YES)
  {
    GNUNET_asprintf (&del_arg, "-d");
  }

  if (d->phase == SP_CONFIG_UPDATE)
  {
    GNUNET_SCHEDULER_cancel (d->task);
    d->phase = SP_START_DONE;
  }
  /** Move this call to scheduled shutdown as fix for CORE_connect calling daemon_stop?
  if (d->server != NULL)
    {
      GNUNET_CORE_disconnect (d->server);
      d->server = NULL;
    }
    */
  /* shutdown ARM process (will terminate others) */
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Terminating peer `%4s'\n" ,
              GNUNET_i2s (&d->id));
  d->phase = SP_SHUTDOWN_START;
  d->running = GNUNET_NO;
  if (allow_restart == GNUNET_YES)
    d->churn = GNUNET_YES;
  if (d->th != NULL)
  {
    GNUNET_TRANSPORT_get_hello_cancel (d->ghh);
    d->ghh = NULL;
    GNUNET_TRANSPORT_disconnect (d->th);
    d->th = NULL;
  }
  /* Check if this is a local or remote process */
  if (NULL != d->hostname)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Stopping gnunet-arm with config `%s' on host `%s'.\n",
                d->cfgfile, d->hostname);
    if (d->username != NULL)
      GNUNET_asprintf (&arg, "%s@%s", d->username, d->hostname);
    else
      arg = GNUNET_strdup (d->hostname);

    d->proc = GNUNET_OS_start_process (GNUNET_NO, NULL, NULL, "ssh", "ssh",
#if !DEBUG_TESTING
                                       "-q",
#endif
                                       arg, "gnunet-arm",
#if DEBUG_TESTING
                                       "-L", "DEBUG",
#endif
                                       "-c", d->cfgfile, "-e", "-q", "-T",
                                       GNUNET_TIME_relative_to_string (timeout),
                                       del_arg, NULL);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Stopping gnunet-arm with command ssh %s gnunet-arm -c %s -e -q %s\n",
                arg, "gnunet-arm", d->cfgfile, del_arg);
    /* Use -e to end arm, and -d to remove temp files */
    GNUNET_free (arg);
  }
  else
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Stopping gnunet-arm with config `%s' locally.\n", d->cfgfile);
    d->proc = GNUNET_OS_start_process (GNUNET_NO, NULL, NULL, "gnunet-arm", "gnunet-arm",
#if DEBUG_TESTING
                                       "-L", "DEBUG",
#endif
                                       "-c", d->cfgfile, "-e", "-q", "-T",
                                       GNUNET_TIME_relative_to_string (timeout),
                                       del_arg, NULL);
    GNUNET_assert (NULL != d->proc);
  }

  GNUNET_free_non_null (del_arg);
  d->max_timeout = GNUNET_TIME_relative_to_absolute (timeout);
  if (GNUNET_SCHEDULER_NO_TASK != d->task)
    GNUNET_SCHEDULER_cancel(d->task);
  d->task = GNUNET_SCHEDULER_add_now (&start_fsm, d);
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
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Copying updated configuration file to remote host `%s'.\n",
              d->hostname);
  d->phase = SP_CONFIG_UPDATE;
  if (NULL != d->username)
    GNUNET_asprintf (&arg, "%s@%s:%s", d->username, d->hostname, d->cfgfile);
  else
    GNUNET_asprintf (&arg, "%s:%s", d->hostname, d->cfgfile);
  d->proc = GNUNET_OS_start_process (GNUNET_NO, NULL, NULL, "scp", "scp",
#if !DEBUG_TESTING
                                     "-q",
#endif
                                     d->cfgfile, arg, NULL);
  GNUNET_free (arg);
  if (NULL == d->proc)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _("Could not start `%s' process to copy configuration file.\n"),
                "scp");
    if (NULL != cb)
      cb (cb_cls, _("Failed to copy new configuration to remote machine."));
    d->phase = SP_START_DONE;
    return;
  }
  d->update_cb = cb;
  d->update_cb_cls = cb_cls;
  d->task =
      GNUNET_SCHEDULER_add_delayed (GNUNET_CONSTANTS_EXEC_WAIT, &start_fsm, d);
}


/**
 * Data kept for each pair of peers that we try
 * to connect.
 */
struct GNUNET_TESTING_ConnectContext
{
  /**
   * Testing handle to the first daemon.
   */
  struct GNUNET_TESTING_Daemon *d1;

  /**
   * Handle to core of first daemon (to check connect)
   */
  struct GNUNET_CORE_Handle *d1core;

  /**
   * Have we actually connected to the core of the first daemon yet?
   */
  int d1core_ready;

  /**
   * Testing handle to the second daemon.
   */
  struct GNUNET_TESTING_Daemon *d2;

  /**
   * Transport handle to the first daemon (to offer the HELLO of the second daemon to).
   */
  struct GNUNET_TRANSPORT_Handle *d1th;

  /**
   * Function to call once we are done (or have timed out).
   */
  GNUNET_TESTING_NotifyConnection cb;

  /**
   * Closure for "nb".
   */
  void *cb_cls;

  /**
   * The relative timeout from whence this connect attempt was
   * started.  Allows for reconnect attempts.
   */
  struct GNUNET_TIME_Relative relative_timeout;

  /**
   * Maximum number of connect attempts, will retry connection
   * this number of times on failures.
   */
  unsigned int connect_attempts;

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
   * Was the connection attempt successful?
   */
  int connected;

  /**
   * When connecting, do we need to send the HELLO?
   */
  int send_hello;

  /**
   * The distance between the two connected peers
   */
  uint32_t distance;
};


/** Forward declaration **/
static void
reattempt_daemons_connect (void *cls,
                           const struct GNUNET_SCHEDULER_TaskContext *tc);


/**
 * Notify callback about success or failure of the attempt
 * to connect the two peers
 *
 * @param cls our "struct GNUNET_TESTING_ConnectContext" (freed)
 * @param tc reason tells us if we succeeded or failed
 */
static void
notify_connect_result (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_TESTING_ConnectContext *ctx = cls;

  ctx->timeout_task = GNUNET_SCHEDULER_NO_TASK;
  if (ctx->hello_send_task != GNUNET_SCHEDULER_NO_TASK)
  {
    GNUNET_SCHEDULER_cancel (ctx->hello_send_task);
    ctx->hello_send_task = GNUNET_SCHEDULER_NO_TASK;
  }

  if (ctx->d1th != NULL)
    GNUNET_TRANSPORT_disconnect (ctx->d1th);
  ctx->d1th = NULL;
  if (ctx->d1core != NULL)
    GNUNET_CORE_disconnect (ctx->d1core);
  ctx->d1core = NULL;

  if ((tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN) != 0)
  {
    GNUNET_free (ctx);
    return;
  }

  if (ctx->connected == GNUNET_YES)
  {
    if (ctx->cb != NULL)
    {
      ctx->cb (ctx->cb_cls, &ctx->d1->id, &ctx->d2->id, ctx->distance,
               ctx->d1->cfg, ctx->d2->cfg, ctx->d1, ctx->d2, NULL);
    }
  }
  else if (ctx->connect_attempts > 0)
  {
    ctx->d1core_ready = GNUNET_NO;
    ctx->timeout_task =
        GNUNET_SCHEDULER_add_now (&reattempt_daemons_connect, ctx);
    return;
  }
  else
  {
    if (ctx->cb != NULL)
    {
      ctx->cb (ctx->cb_cls, &ctx->d1->id, &ctx->d2->id, 0, ctx->d1->cfg,
               ctx->d2->cfg, ctx->d1, ctx->d2, _("Peers failed to connect"));
    }
  }
  GNUNET_free (ctx);
}


/**
 * Success, connection is up.  Signal client our success.
 *
 * @param cls our "struct GNUNET_TESTING_ConnectContext"
 * @param peer identity of the peer that has connected
 * @param atsi performance information
 * @param atsi_count number of records in 'atsi'
 *
 */
static void
connect_notify (void *cls, const struct GNUNET_PeerIdentity *peer,
                const struct GNUNET_ATS_Information *atsi,
                unsigned int atsi_count)
{
  struct GNUNET_TESTING_ConnectContext *ctx = cls;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Connected peer %s to peer %s\n",
              ctx->d1->shortname, GNUNET_i2s (peer));
  if (0 != memcmp (&ctx->d2->id, peer, sizeof (struct GNUNET_PeerIdentity)))
    return;
  ctx->connected = GNUNET_YES;
  ctx->distance = 0;            /* FIXME: distance */
  if (ctx->hello_send_task != GNUNET_SCHEDULER_NO_TASK)
  {
    GNUNET_SCHEDULER_cancel (ctx->hello_send_task);
    ctx->hello_send_task = GNUNET_SCHEDULER_NO_TASK;
  }
  GNUNET_SCHEDULER_cancel (ctx->timeout_task);
  ctx->timeout_task = GNUNET_SCHEDULER_add_now (&notify_connect_result, ctx);
}


static void
send_hello (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_TESTING_ConnectContext *ctx = cls;
  struct GNUNET_MessageHeader *hello;

  ctx->hello_send_task = GNUNET_SCHEDULER_NO_TASK;
  if ((tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN) != 0)
    return;
  if ((ctx->d1core_ready == GNUNET_YES) && (ctx->d2->hello != NULL) &&
      (NULL != GNUNET_HELLO_get_header (ctx->d2->hello)) &&
      (ctx->d1->phase == SP_START_DONE) && (ctx->d2->phase == SP_START_DONE))
  {
    hello = GNUNET_HELLO_get_header (ctx->d2->hello);
    GNUNET_assert (hello != NULL);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Offering hello of %s to %s\n",
                ctx->d2->shortname, ctx->d1->shortname);
    GNUNET_TRANSPORT_offer_hello (ctx->d1th, hello, NULL, NULL);
    GNUNET_assert (ctx->d1core != NULL);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Sending connect request to TRANSPORT of %s for peer %s\n",
                GNUNET_i2s (&ctx->d1->id),
                GNUNET_h2s (&ctx->d2->id.hashPubKey));
    GNUNET_TRANSPORT_try_connect (ctx->d1th, &ctx->d2->id);
    ctx->timeout_hello =
        GNUNET_TIME_relative_add (ctx->timeout_hello,
                                  GNUNET_TIME_relative_multiply
                                  (GNUNET_TIME_UNIT_MILLISECONDS, 500));
  }
  ctx->hello_send_task =
      GNUNET_SCHEDULER_add_delayed (ctx->timeout_hello, &send_hello, ctx);
}

/**
 * Notify of a successful connection to the core service.
 *
 * @param cls a ConnectContext
 * @param server handle to the core service
 * @param my_identity the peer identity of this peer
 */
void
core_init_notify (void *cls, struct GNUNET_CORE_Handle *server,
                  const struct GNUNET_PeerIdentity *my_identity)
{
  struct GNUNET_TESTING_ConnectContext *connect_ctx = cls;

  connect_ctx->d1core_ready = GNUNET_YES;

  if (connect_ctx->send_hello == GNUNET_NO)
  {
    GNUNET_TRANSPORT_try_connect (connect_ctx->d1th, &connect_ctx->d2->id);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Sending connect request to TRANSPORT of %s for peer %s\n",
                connect_ctx->d1->shortname, connect_ctx->d2->shortname);
  }
}


/**
 * Try to connect again some peers that failed in an earlier attempt. This will
 * be tried as many times as connection_attempts in the configuration file.
 *
 * @param cls Closure (connection context between the two peers).
 * @param tc TaskContext.
 */
static void
reattempt_daemons_connect (void *cls,
                           const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_TESTING_ConnectContext *ctx = cls;

  ctx->timeout_task = GNUNET_SCHEDULER_NO_TASK;
  if ((tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN) != 0)
    return;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "re-attempting connect of peer %s to peer %s\n",
              ctx->d1->shortname, ctx->d2->shortname);
  ctx->connect_attempts--;
  GNUNET_assert (ctx->d1core == NULL);
  ctx->d1core_ready = GNUNET_NO;
  ctx->d1core =
      GNUNET_CORE_connect (ctx->d1->cfg, 1, ctx, &core_init_notify,
                           &connect_notify, NULL, NULL, GNUNET_NO, NULL,
                           GNUNET_NO, no_handlers);
  if (ctx->d1core == NULL)
  {
    if (NULL != ctx->cb)
      ctx->cb (ctx->cb_cls, &ctx->d1->id, &ctx->d2->id, 0, ctx->d1->cfg,
               ctx->d2->cfg, ctx->d1, ctx->d2,
               _("Failed to connect to core service of first peer!\n"));
    GNUNET_free (ctx);
    return;
  }

  /* Don't know reason for initial connect failure, update the HELLO for the second peer */
  if (NULL != ctx->d2->hello)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "updating %s's HELLO\n",
                ctx->d2->shortname);
    GNUNET_free (ctx->d2->hello);
    ctx->d2->hello = NULL;
    if (NULL != ctx->d2->th)
    {
      GNUNET_TRANSPORT_get_hello_cancel (ctx->d2->ghh);
      ctx->d2->ghh = NULL;
      GNUNET_TRANSPORT_disconnect (ctx->d2->th);
    }
    ctx->d2->th =
        GNUNET_TRANSPORT_connect (ctx->d2->cfg, &ctx->d2->id, NULL, NULL, NULL,
                                  NULL);
    GNUNET_assert (ctx->d2->th != NULL);
    ctx->d2->ghh =
        GNUNET_TRANSPORT_get_hello (ctx->d2->th, &process_hello, ctx->d2);
  }
  else
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "didn't have %s's HELLO\n",
                ctx->d2->shortname);
  }

  if ((NULL == ctx->d2->hello) && (ctx->d2->th == NULL))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "didn't have %s's HELLO, trying to get it now\n",
                ctx->d2->shortname);
    ctx->d2->th =
        GNUNET_TRANSPORT_connect (ctx->d2->cfg, &ctx->d2->id, NULL, NULL, NULL,
                                  NULL);
    if (NULL == ctx->d2->th)
    {
      GNUNET_CORE_disconnect (ctx->d1core);
      GNUNET_free (ctx);
      if (NULL != ctx->cb)
        ctx->cb (ctx->cb_cls, &ctx->d1->id, &ctx->d2->id, 0, ctx->d1->cfg,
                 ctx->d2->cfg, ctx->d1, ctx->d2,
                 _("Failed to connect to transport service!\n"));
      return;
    }
    ctx->d2->ghh =
        GNUNET_TRANSPORT_get_hello (ctx->d2->th, &process_hello, ctx->d2);
  }
  else
  {
    if (NULL == ctx->d2->hello)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "didn't have %s's HELLO but th wasn't NULL, not trying!!\n",
                  ctx->d2->shortname);
    }
  }

  if (ctx->send_hello == GNUNET_YES)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Sending %s's HELLO to %s\n",
                ctx->d1->shortname, ctx->d2->shortname);
    ctx->d1th =
        GNUNET_TRANSPORT_connect (ctx->d1->cfg, &ctx->d1->id, ctx->d1, NULL,
                                  NULL, NULL);
    if (ctx->d1th == NULL)
    {
      GNUNET_CORE_disconnect (ctx->d1core);
      GNUNET_free (ctx);
      if (NULL != ctx->cb)
        ctx->cb (ctx->cb_cls, &ctx->d1->id, &ctx->d2->id, 0, ctx->d1->cfg,
                 ctx->d2->cfg, ctx->d1, ctx->d2,
                 _("Failed to connect to transport service!\n"));
      return;
    }
    GNUNET_assert (GNUNET_SCHEDULER_NO_TASK == ctx->hello_send_task);
    ctx->hello_send_task = GNUNET_SCHEDULER_add_now (&send_hello, ctx);
  }
  else
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Trying to reconnect %s to %s\n",
                ctx->d1->shortname, ctx->d2->shortname);
    GNUNET_TRANSPORT_try_connect (ctx->d1th, &ctx->d2->id);
  }
  ctx->timeout_task =
      GNUNET_SCHEDULER_add_delayed (ctx->relative_timeout,
                                    &notify_connect_result, ctx);
}

/**
 * Iterator for currently known peers, to ensure
 * that we don't try to send duplicate connect
 * requests to core.
 *
 * @param cls our "struct GNUNET_TESTING_ConnectContext"
 * @param peer identity of the peer that has connected,
 *        NULL when iteration has finished
 * @param atsi performance information
 * @param atsi_count number of records in 'atsi'
 *
 */
static void
core_initial_iteration (void *cls, const struct GNUNET_PeerIdentity *peer,
                        const struct GNUNET_ATS_Information *atsi,
                        unsigned int atsi_count)
{
  struct GNUNET_TESTING_ConnectContext *ctx = cls;

  if ((peer != NULL) &&
      (0 == memcmp (&ctx->d2->id, peer, sizeof (struct GNUNET_PeerIdentity))))
  {
    ctx->connected = GNUNET_YES;
    ctx->distance = 0;          /* FIXME: distance */
    return;
  }
  if (peer != NULL)
    return;                     /* ignore other peers */
  /* peer == NULL: End of iteration over peers */

  GNUNET_assert (GNUNET_SCHEDULER_NO_TASK == ctx->timeout_task);
  if (ctx->connected == GNUNET_YES)
  {
    ctx->timeout_task = GNUNET_SCHEDULER_add_now (&notify_connect_result, ctx);
    return;
  }

  /* Peer not already connected, need to schedule connect request! */
  if (ctx->d1core == NULL)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Peers are NOT connected, connecting to core!\n");
    ctx->d1core =
        GNUNET_CORE_connect (ctx->d1->cfg, 1, ctx, &core_init_notify,
                             &connect_notify, NULL, NULL, GNUNET_NO, NULL,
                             GNUNET_NO, no_handlers);
  }

  if (ctx->d1core == NULL)
  {
    ctx->timeout_task = GNUNET_SCHEDULER_add_now (&notify_connect_result, ctx);
    return;
  }

  if ((NULL == ctx->d2->hello) && (ctx->d2->th == NULL))        /* Do not yet have the second peer's hello, set up a task to get it */
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Don't have d2's HELLO, trying to get it!\n");
    ctx->d2->th =
        GNUNET_TRANSPORT_connect (ctx->d2->cfg, &ctx->d2->id, NULL, NULL, NULL,
                                  NULL);
    if (ctx->d2->th == NULL)
    {
      GNUNET_CORE_disconnect (ctx->d1core);
      ctx->d1core = NULL;
      ctx->timeout_task =
          GNUNET_SCHEDULER_add_now (&notify_connect_result, ctx);
      return;
    }
    ctx->d2->ghh =
        GNUNET_TRANSPORT_get_hello (ctx->d2->th, &process_hello, ctx->d2);
  }

  if (ctx->send_hello == GNUNET_YES)
  {
    ctx->d1th =
        GNUNET_TRANSPORT_connect (ctx->d1->cfg, &ctx->d1->id, ctx->d1, NULL,
                                  NULL, NULL);
    if (ctx->d1th == NULL)
    {
      GNUNET_CORE_disconnect (ctx->d1core);
      ctx->d1core = NULL;
      ctx->timeout_task =
          GNUNET_SCHEDULER_add_now (&notify_connect_result, ctx);
      return;
    }
    GNUNET_assert (GNUNET_SCHEDULER_NO_TASK == ctx->hello_send_task);
    ctx->hello_send_task = GNUNET_SCHEDULER_add_now (&send_hello, ctx);
  }

  ctx->timeout_task =
      GNUNET_SCHEDULER_add_delayed (ctx->relative_timeout,
                                    &notify_connect_result, ctx);

}


/**
 * Establish a connection between two GNUnet daemons.  The daemons
 * must both be running and not be stopped until either the
 * 'cb' callback is called OR the connection request has been
 * explicitly cancelled.
 *
 * @param d1 handle for the first daemon
 * @param d2 handle for the second daemon
 * @param timeout how long is the connection attempt
 *        allowed to take?
 * @param max_connect_attempts how many times should we try to reconnect
 *        (within timeout)
 * @param send_hello GNUNET_YES to send the HELLO, GNUNET_NO to assume
 *                   the HELLO has already been exchanged
 * @param cb function to call at the end
 * @param cb_cls closure for cb
 * @return handle to cancel the request
 */
struct GNUNET_TESTING_ConnectContext *
GNUNET_TESTING_daemons_connect (struct GNUNET_TESTING_Daemon *d1,
                                struct GNUNET_TESTING_Daemon *d2,
                                struct GNUNET_TIME_Relative timeout,
                                unsigned int max_connect_attempts,
                                int send_hello,
                                GNUNET_TESTING_NotifyConnection cb,
                                void *cb_cls)
{
  struct GNUNET_TESTING_ConnectContext *ctx;

  if ((d1->running == GNUNET_NO) || (d2->running == GNUNET_NO))
  {
    if (NULL != cb)
      cb (cb_cls, &d1->id, &d2->id, 0, d1->cfg, d2->cfg, d1, d2,
          _("Peers are not fully running yet, can not connect!\n"));
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING, "Peers are not up!\n");
    return NULL;
  }

  ctx = GNUNET_malloc (sizeof (struct GNUNET_TESTING_ConnectContext));
  ctx->d1 = d1;
  ctx->d2 = d2;
  ctx->timeout_hello =
      GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MILLISECONDS, 500);
  ctx->relative_timeout =
      GNUNET_TIME_relative_divide (timeout, max_connect_attempts);
  ctx->cb = cb;
  ctx->cb_cls = cb_cls;
  ctx->connect_attempts = max_connect_attempts;
  ctx->connected = GNUNET_NO;
  ctx->send_hello = send_hello;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Asked to connect peer %s to peer %s\n",
              d1->shortname, d2->shortname);
  /* Core is up! Iterate over all _known_ peers first to check if we are already connected to the peer! */
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_CORE_is_peer_connected (ctx->d1->cfg, &ctx->d2->id,
                                                &core_initial_iteration, ctx));
  return ctx;
}


/**
 * Cancel an attempt to connect two daemons.
 *
 * @param cc connect context
 */
void
GNUNET_TESTING_daemons_connect_cancel (struct GNUNET_TESTING_ConnectContext *cc)
{
  if (GNUNET_SCHEDULER_NO_TASK != cc->timeout_task)
  {
    GNUNET_SCHEDULER_cancel (cc->timeout_task);
    cc->timeout_task = GNUNET_SCHEDULER_NO_TASK;
  }
  if (GNUNET_SCHEDULER_NO_TASK != cc->hello_send_task)
  {
    GNUNET_SCHEDULER_cancel (cc->hello_send_task);
    cc->hello_send_task = GNUNET_SCHEDULER_NO_TASK;
  }
  if (NULL != cc->d1core)
  {
    GNUNET_CORE_disconnect (cc->d1core);
    cc->d1core = NULL;
  }
  if (NULL != cc->d1th)
  {
    GNUNET_TRANSPORT_disconnect (cc->d1th);
    cc->d1th = NULL;
  }
  GNUNET_free (cc);
}


/* end of testing.c */

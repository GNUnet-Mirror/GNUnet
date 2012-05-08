/*
     This file is part of GNUnet.
     (C) 2010 Christian Grothoff

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
 * @file core/test_core_api_send_to_self.c
 * @brief
 * @author Philipp Toelke
 */
#include <platform.h>
#include <gnunet_common.h>
#include <gnunet_program_lib.h>
#include <gnunet_protocols.h>
#include <gnunet_core_service.h>
#include <gnunet_constants.h>

/**
 * Final status code.
 */
static int ret;

/**
 * Handle to the cleanup task.
 */
GNUNET_SCHEDULER_TaskIdentifier die_task;

static struct GNUNET_PeerIdentity myself;

/**
 * Configuration to load for the new peer.
 */
struct GNUNET_CONFIGURATION_Handle *core_cfg;

/**
 * The handle to core
 */
struct GNUNET_CORE_Handle *core;

/**
 * Handle to gnunet-service-arm.
 */
struct GNUNET_OS_Process *arm_proc;

/**
 * Function scheduled as very last function, cleans up after us
 */
static void
cleanup (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tskctx)
{
  die_task = GNUNET_SCHEDULER_NO_TASK;

  if (core != NULL)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Disconnecting core.\n");
    GNUNET_CORE_disconnect (core);
    core = NULL;
  }

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Stopping peer\n");
  if (0 != GNUNET_OS_process_kill (arm_proc, SIGTERM))
    GNUNET_log_strerror (GNUNET_ERROR_TYPE_WARNING, "kill");

  if (GNUNET_OS_process_wait (arm_proc) != GNUNET_OK)
    GNUNET_log_strerror (GNUNET_ERROR_TYPE_WARNING, "waitpid");

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "ARM process %u stopped\n",
              GNUNET_OS_process_get_pid (arm_proc));
  GNUNET_OS_process_destroy (arm_proc);
  arm_proc = NULL;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Ending test.\n");
}

static int
receive (void *cls, const struct GNUNET_PeerIdentity *other,
         const struct GNUNET_MessageHeader *message,
         const struct GNUNET_ATS_Information *atsi, unsigned int atsi_count)
{
  if (die_task != GNUNET_SCHEDULER_NO_TASK)
    GNUNET_SCHEDULER_cancel (die_task);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Received message from peer %s\n",
              GNUNET_i2s (other));
  GNUNET_SCHEDULER_add_now (&cleanup, NULL);
  ret = 0;
  return GNUNET_OK;
}

static size_t
send_message (void *cls, size_t size, void *buf)
{
  if (size == 0 || buf == NULL)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Could not send; got 0 buffer\n");
    return 0;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Sending!\n");
  struct GNUNET_MessageHeader *hdr = buf;

  hdr->size = htons (sizeof (struct GNUNET_MessageHeader));
  hdr->type = htons (GNUNET_MESSAGE_TYPE_DUMMY);
  return ntohs (hdr->size);
}

static void
init (void *cls, struct GNUNET_CORE_Handle *core,
      const struct GNUNET_PeerIdentity *my_identity)
{
  if (core == NULL)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Could NOT connect to CORE;\n");
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Correctly connected to CORE; we are the peer %s.\n",
              GNUNET_i2s (my_identity));
  memcpy (&myself, my_identity, sizeof (struct GNUNET_PeerIdentity));
}

static void
connect_cb (void *cls, const struct GNUNET_PeerIdentity *peer,
            const struct GNUNET_ATS_Information *atsi, unsigned int atsi_count)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Connected to peer %s.\n",
              GNUNET_i2s (peer));
  if (0 == memcmp (peer, &myself, sizeof (struct GNUNET_PeerIdentity)))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Connected to myself; sending message!\n");
    GNUNET_CORE_notify_transmit_ready (core, GNUNET_YES, 0,
                                       GNUNET_TIME_UNIT_FOREVER_REL, peer,
                                       sizeof (struct GNUNET_MessageHeader),
                                       send_message, NULL);
  }
}


/**
 * Main function that will be run by the scheduler.
 *
 * @param cls closure
 * @param args remaining command-line arguments
 * @param cfgfile name of the configuration file used (for saving, can be NULL!)
 * @param cfg configuration
 */
static void
run (void *cls, char *const *args, const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  const static struct GNUNET_CORE_MessageHandler handlers[] = {
    {&receive, GNUNET_MESSAGE_TYPE_DUMMY, 0},
    {NULL, 0, 0}
  };

  core_cfg = GNUNET_CONFIGURATION_create ();

  arm_proc =
    GNUNET_OS_start_process (GNUNET_YES, NULL, NULL, "gnunet-service-arm",
                               "gnunet-service-arm",
#if VERBOSE
                               "-L", "DEBUG",
#endif
                               "-c", "test_core_api_peer1.conf", NULL);

  GNUNET_assert (GNUNET_OK ==
                 GNUNET_CONFIGURATION_load (core_cfg,
                                            "test_core_api_peer1.conf"));

  core =
      GNUNET_CORE_connect (core_cfg, 42, NULL, &init, &connect_cb, NULL, NULL,
                           0, NULL, 0, handlers);

  die_task =
      GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_relative_multiply
                                    (GNUNET_TIME_UNIT_SECONDS, 300), &cleanup,
                                    cls);
}


static int
check ()
{
  char *const argv[] = { "test-core-api-send-to-self",
    "-c",
    "test_core_api_data.conf",
#if VERBOSE
    "-L", "DEBUG",
#endif
    NULL
  };

  static const struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_OPTION_END
  };

  ret = 1;

  return (GNUNET_OK ==
          GNUNET_PROGRAM_run ((sizeof (argv) / sizeof (char *)) - 1, argv,
                              "test_core_api_send_to_self",
                              gettext_noop ("help text"), options, &run,
                              NULL)) ? ret : 1;
}

/**
 * The main function to obtain template from gnunetd.
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return 0 ok, 1 on error
 */
int
main (int argc, char *argv[])
{
  GNUNET_log_setup ("test-core-api-send-to-self",
#if VERBOSE
                    "DEBUG",
#else
                    "WARNING",
#endif
                    NULL);
  ret = check ();
  GNUNET_DISK_directory_remove ("/tmp/test-gnunet-core-peer-1");
  return ret;
}

/* end of test_core_api_send_to_self.c */

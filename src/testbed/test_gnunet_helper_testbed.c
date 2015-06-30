/*
      This file is part of GNUnet
      Copyright (C) 2008--2013 Christian Grothoff (and other contributing authors)

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
      Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
      Boston, MA 02110-1301, USA.
 */

/**
 * @file testbed/test_gnunet_helper_testbed.c
 * @brief Testcase for testing gnunet-helper-testbed.c
 * @author Sree Harsha Totakura <sreeharsha@totakura.in>
 */

#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_testbed_service.h"
#include <zlib.h>

#include "testbed_api.h"
#include "testbed_helper.h"
#include "testbed_api_hosts.h"

/**
 * Generic logging shortcut
 */
#define LOG(kind,...)				\
  GNUNET_log (kind, __VA_ARGS__)


/**
 * Handle to the helper process
 */
static struct GNUNET_HELPER_Handle *helper;

/**
 * Message to helper
 */
static struct GNUNET_TESTBED_HelperInit *msg;

/**
 * Message send handle
 */
static struct GNUNET_HELPER_SendHandle *shandle;

/**
 * Abort task identifier
 */
static struct GNUNET_SCHEDULER_Task * abort_task;

/**
 * Shutdown task identifier
 */
static struct GNUNET_SCHEDULER_Task * shutdown_task;

/**
 * Configuratin handler
 */
static struct GNUNET_CONFIGURATION_Handle *cfg;

/**
 * Global testing status
 */
static int result;


/**
 * Shutdown nicely
 *
 * @param cls NULL
 * @param tc the task context
 */
static void
do_shutdown (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  if (NULL != abort_task)
    GNUNET_SCHEDULER_cancel (abort_task);
  if (NULL != helper)
    GNUNET_HELPER_stop (helper, GNUNET_NO);
  GNUNET_free_non_null (msg);
  if (NULL != cfg)
    GNUNET_CONFIGURATION_destroy (cfg);
}


/**
 * abort task to run on test timed out
 *
 * @param cls NULL
 * @param tc the task context
 */
static void
do_abort (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  abort_task = NULL;
  LOG (GNUNET_ERROR_TYPE_WARNING, "Test timedout -- Aborting\n");
  result = GNUNET_SYSERR;
  if (NULL != shandle)
    GNUNET_HELPER_send_cancel (shandle);
  if (NULL == shutdown_task)
    shutdown_task = GNUNET_SCHEDULER_add_now (&do_shutdown, NULL);
}


/**
 * Continuation function.
 *
 * @param cls closure
 * @param result GNUNET_OK on success,
 *               GNUNET_NO if helper process died
 *               GNUNET_SYSERR during GNUNET_HELPER_stop
 */
static void
cont_cb (void *cls, int result)
{
  shandle = NULL;
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Message sent\n");
  GNUNET_assert (GNUNET_OK == result);
}


/**
 * Functions with this signature are called whenever a
 * complete message is received by the tokenizer.
 *
 * Do not call GNUNET_SERVER_mst_destroy in callback
 *
 * @param cls closure
 * @param client identification of the client
 * @param message the actual message
 *
 * @return GNUNET_OK on success, GNUNET_SYSERR to stop further processing
 */
static int
mst_cb (void *cls, void *client, const struct GNUNET_MessageHeader *message)
{
  const struct GNUNET_TESTBED_HelperReply *msg;
  char *config;
  uLongf config_size;
  uLongf xconfig_size;

  msg = (const struct GNUNET_TESTBED_HelperReply *) message;
  config_size = 0;
  xconfig_size = 0;
  GNUNET_assert (sizeof (struct GNUNET_TESTBED_HelperReply) <
                 ntohs (msg->header.size));
  GNUNET_assert (GNUNET_MESSAGE_TYPE_TESTBED_HELPER_REPLY ==
                 ntohs (msg->header.type));
  config_size = (uLongf) ntohs (msg->config_size);
  xconfig_size =
      (uLongf) (ntohs (msg->header.size) -
                sizeof (struct GNUNET_TESTBED_HelperReply));
  config = GNUNET_malloc (config_size);
  GNUNET_assert (Z_OK ==
                 uncompress ((Bytef *) config, &config_size,
                             (const Bytef *) &msg[1], xconfig_size));
  GNUNET_free (config);
  if (NULL == shutdown_task)
    shutdown_task =
        GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_relative_multiply
                                      (GNUNET_TIME_UNIT_SECONDS, 1),
                                      &do_shutdown, NULL);
  return GNUNET_OK;
}


/**
 * Callback that will be called when the helper process dies. This is not called
 * when the helper process is stoped using GNUNET_HELPER_stop()
 *
 * @param cls the closure from GNUNET_HELPER_start()
 */
static void
exp_cb (void *cls)
{
  helper = NULL;
  result = GNUNET_SYSERR;
}


/**
 * Main function that will be run.
 *
 * @param cls closure
 * @param args remaining command-line arguments
 * @param cfgfile name of the configuration file used (for saving, can be NULL!)
 * @param cfg configuration
 */
static void
run (void *cls, char *const *args, const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *cfg2)
{
  static char *const binary_argv[] = {
    "gnunet-helper-testbed",
    NULL
  };
  const char *trusted_ip = "127.0.0.1";

  helper =
      GNUNET_HELPER_start (GNUNET_YES, "gnunet-helper-testbed", binary_argv,
                           &mst_cb, &exp_cb, NULL);
  GNUNET_assert (NULL != helper);
  cfg = GNUNET_CONFIGURATION_dup (cfg2);
  msg = GNUNET_TESTBED_create_helper_init_msg_ (trusted_ip, NULL, cfg);
  shandle =
      GNUNET_HELPER_send (helper, &msg->header, GNUNET_NO, &cont_cb, NULL);
  GNUNET_assert (NULL != shandle);
  abort_task =
      GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_relative_multiply
                                    (GNUNET_TIME_UNIT_MINUTES, 1), &do_abort,
                                    NULL);
}


/**
 * Main function
 *
 * @param argc the number of command line arguments
 * @param argv command line arg array
 * @return return code
 */
int
main (int argc, char **argv)
{
  struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_OPTION_END
  };

  result = GNUNET_OK;
  if (GNUNET_OK !=
      GNUNET_PROGRAM_run (argc, argv, "test_gnunet_helper_testbed",
                          "Testcase for testing gnunet-helper-testbed.c",
                          options, &run, NULL))
    return 1;
  return (GNUNET_OK == result) ? 0 : 1;
}

/* end of test_gnunet_helper_testbed.c */

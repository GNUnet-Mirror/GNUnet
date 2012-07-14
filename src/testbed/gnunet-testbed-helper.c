/*
      This file is part of GNUnet
      (C) 2012 Christian Grothoff (and other contributing authors)

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
 * @file testbed/gnunet-testbed-helper.c
 * @brief Helper binary that is started from a remote controller to start
 *          gnunet-service-testbed. This binary also receives configuration
 *          from the remove controller which is put in a temporary location
 *          with ports and paths fixed so that gnunet-service-testbed runs
 *          without any hurdels. This binary also kills the testbed service
 *          should the connection from the remote controller is dropped
 * @author Sree Harsha Totakura <sreeharsha@totakura.in> 
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_testing_lib-new.h"
#include "testbed_helper.h"


/**
 * Generic debug logging shortcut
 */
#define LOG_DEBUG(...)                                  \
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, __VA_ARGS__)


/**
 * Handle to the testing system
 */
static struct GNUNET_TESTING_System *test_system;

/**
 * Our message stream tokenizer
 */
struct GNUNET_SERVER_MessageStreamTokenizer *tokenizer;

/**
 * Disk handle from stdin
 */
static struct GNUNET_DISK_FileHandle *stdin_fd;

/**
 * Task identifier for the read task
 */
static GNUNET_SCHEDULER_TaskIdentifier read_task_id;

/**
 * Are we done reading messages from stdin?
 */
static int done_reading;


/**
 * Task to shutting down nicely
 *
 * @param cls NULL
 * @return tc the task context
 */
static void
shutdown_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  if (GNUNET_SCHEDULER_NO_TASK != read_task_id)
  {
    GNUNET_SCHEDULER_cancel (read_task_id);
    read_task_id = GNUNET_SCHEDULER_NO_TASK;
  }
  (void) GNUNET_DISK_file_close (stdin_fd);
  GNUNET_SERVER_mst_destroy (tokenizer);  
  tokenizer = NULL;
  if (NULL != test_system)
  {
    GNUNET_TESTING_system_destroy (test_system, GNUNET_YES);
    test_system = NULL;
  }
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
tokenizer_cb (void *cls, void *client,
              const struct GNUNET_MessageHeader *message)
{
  GNUNET_break (0);
  // FIXME: write config & start gnunet-service-testbed
  done_reading = GNUNET_YES;
  return GNUNET_OK;
}


/**
 * Task to read from stdin
 *
 * @param cls NULL
 * @return tc the task context
 */
static void
read_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  char buf[GNUNET_SERVER_MAX_MESSAGE_SIZE];
  ssize_t sread;

  read_task_id = GNUNET_SCHEDULER_NO_TASK;
  if (0 != (GNUNET_SCHEDULER_REASON_SHUTDOWN & tc->reason))
    return;  
  sread = GNUNET_DISK_file_read (stdin_fd, buf, sizeof (buf));
  if (GNUNET_SYSERR == sread)
  {
    GNUNET_break (0);           /* FIXME: stdin closed - kill child */
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  if (GNUNET_YES == done_reading)
  {
    /* didn't expect any more data! */
    GNUNET_break (0);
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  LOG_DEBUG ("Read %u bytes\n", sread);
  if (GNUNET_OK !=
      GNUNET_SERVER_mst_receive (tokenizer, NULL, buf, sread,
				 GNUNET_NO, GNUNET_NO))
  {
    GNUNET_break (0);
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  read_task_id =                /* No timeout while reading */
    GNUNET_SCHEDULER_add_read_file (GNUNET_TIME_UNIT_FOREVER_REL,
                                    stdin_fd, &read_task, NULL);
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
     const struct GNUNET_CONFIGURATION_Handle * cfg)
{
  LOG_DEBUG ("Starting testbed helper...\n");
  tokenizer = GNUNET_SERVER_mst_create (&tokenizer_cb, NULL);
  stdin_fd = GNUNET_DISK_get_handle_from_native (stdin);
  read_task_id =
    GNUNET_SCHEDULER_add_read_file (GNUNET_TIME_UNIT_FOREVER_REL,
                                    stdin_fd, &read_task, NULL);
  GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_FOREVER_REL,
				&shutdown_task, NULL);
}


/**
 * Main function
 *
 * @param argc the number of command line arguments
 * @param argv command line arg array
 * @return return code
 */
int main (int argc, char **argv)
{
  struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_OPTION_END
  };
  if (GNUNET_OK != 
      GNUNET_PROGRAM_run (argc, argv, "gnunet-testbed-helper",
			  "Helper for starting gnunet-service-testbed",
			  options, &run, NULL))
    return 1;
  return 0;
}

/* end of gnunet-testbed-helper.c */

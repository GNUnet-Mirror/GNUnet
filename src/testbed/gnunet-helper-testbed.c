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
 * @file testbed/gnunet-helper-testbed.c
 * @brief Helper binary that is started from a remote controller to start
 *          gnunet-service-testbed. This binary also receives configuration
 *          from the remove controller which is put in a temporary location
 *          with ports and paths fixed so that gnunet-service-testbed runs
 *          without any hurdles. This binary also kills the testbed service
 *          should the connection from the remote controller is dropped
 * @author Sree Harsha Totakura <sreeharsha@totakura.in>
 */


#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_testing_lib.h"
#include "gnunet_testbed_service.h"
#include "testbed_helper.h"
#include "testbed_api.h"
#include <zlib.h>

/**
 * Generic logging shortcut
 */
#define LOG(kind, ...)                                   \
  GNUNET_log (kind, __VA_ARGS__)

/**
 * Debug logging shorthand
 */
#define LOG_DEBUG(...)                          \
  LOG (GNUNET_ERROR_TYPE_DEBUG, __VA_ARGS__)


/**
 * We need pipe control only on WINDOWS
 */
#if WINDOWS
#define PIPE_CONTROL GNUNET_YES
#else
#define PIPE_CONTROL GNUNET_NO
#endif


/**
 * Context for a single write on a chunk of memory
 */
struct WriteContext
{
  /**
   * The data to write
   */
  void *data;

  /**
   * The length of the data
   */
  size_t length;

  /**
   * The current position from where the write operation should begin
   */
  size_t pos;
};


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
 * Disk handle for stdout
 */
static struct GNUNET_DISK_FileHandle *stdout_fd;

/**
 * The process handle to the testbed service
 */
static struct GNUNET_OS_Process *testbed;

/**
 * Task identifier for the read task
 */
static GNUNET_SCHEDULER_TaskIdentifier read_task_id;

/**
 * Task identifier for the write task
 */
static GNUNET_SCHEDULER_TaskIdentifier write_task_id;

/**
 * Are we done reading messages from stdin?
 */
static int done_reading;

/**
 * Result to return in case we fail
 */
static int status;


/**
 * Are we shutting down
 */
static int in_shutdown;


/**
 * Task to shutting down nicely
 *
 * @param cls NULL
 * @param tc the task context
 */
static void
shutdown_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  LOG_DEBUG ("Shutting down\n");
  in_shutdown = GNUNET_YES;
  if (GNUNET_SCHEDULER_NO_TASK != read_task_id)
  {
    GNUNET_SCHEDULER_cancel (read_task_id);
    read_task_id = GNUNET_SCHEDULER_NO_TASK;
  }
  if (GNUNET_SCHEDULER_NO_TASK != write_task_id)
  {
    GNUNET_SCHEDULER_cancel (write_task_id);
    write_task_id = GNUNET_SCHEDULER_NO_TASK;
  }
  if (NULL != stdin_fd)
    (void) GNUNET_DISK_file_close (stdin_fd);
  if (NULL != stdout_fd)
    (void) GNUNET_DISK_file_close (stdout_fd);
  GNUNET_SERVER_mst_destroy (tokenizer);
  tokenizer = NULL;
  if (NULL != testbed)
  {
    LOG_DEBUG ("Killing testbed\n");
    GNUNET_break (0 == GNUNET_OS_process_kill (testbed, SIGTERM));
    GNUNET_assert (GNUNET_OK == GNUNET_OS_process_wait (testbed));
    GNUNET_OS_process_destroy (testbed);
    testbed = NULL;
  }
  if (NULL != test_system)
  {
    GNUNET_TESTING_system_destroy (test_system, GNUNET_YES);
    test_system = NULL;
  }
}


/**
 * Task to write to the standard out
 *
 * @param cls the WriteContext
 * @param tc the TaskContext
 */
static void
write_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct WriteContext *wc = cls;
  ssize_t bytes_wrote;

  GNUNET_assert (NULL != wc);
  write_task_id = GNUNET_SCHEDULER_NO_TASK;
  if (0 != (GNUNET_SCHEDULER_REASON_SHUTDOWN & tc->reason))
  {
    GNUNET_free (wc->data);
    GNUNET_free (wc);
    return;
  }
  bytes_wrote =
      GNUNET_DISK_file_write (stdout_fd, wc->data + wc->pos,
                              wc->length - wc->pos);
  if (GNUNET_SYSERR == bytes_wrote)
  {
    LOG (GNUNET_ERROR_TYPE_WARNING, "Cannot reply back configuration\n");
    GNUNET_free (wc->data);
    GNUNET_free (wc);
    return;
  }
  wc->pos += bytes_wrote;
  if (wc->pos == wc->length)
  {
    GNUNET_free (wc->data);
    GNUNET_free (wc);
    return;
  }
  write_task_id =
      GNUNET_SCHEDULER_add_write_file (GNUNET_TIME_UNIT_FOREVER_REL, stdout_fd,
                                       &write_task, wc);
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
  const struct GNUNET_TESTBED_HelperInit *msg;
  struct GNUNET_TESTBED_HelperReply *reply;
  struct GNUNET_CONFIGURATION_Handle *cfg;
  struct WriteContext *wc;
  char *binary;
  char *trusted_ip;
  char *hostname;
  char *config;
  char *xconfig;
  size_t config_size;
  uLongf ul_config_size;
  size_t xconfig_size;
  uint16_t trusted_ip_size;
  uint16_t hostname_size;
  uint16_t msize;

  msize = ntohs (message->size);
  if ((sizeof (struct GNUNET_TESTBED_HelperInit) >= msize) ||
      (GNUNET_MESSAGE_TYPE_TESTBED_HELPER_INIT != ntohs (message->type)))
  {
    LOG (GNUNET_ERROR_TYPE_WARNING, "Received unexpected message -- exiting\n");
    goto error;
  }
  msg = (const struct GNUNET_TESTBED_HelperInit *) message;
  trusted_ip_size = ntohs (msg->trusted_ip_size);
  trusted_ip = (char *) &msg[1];
  if ('\0' != trusted_ip[trusted_ip_size])
  {
    LOG (GNUNET_ERROR_TYPE_WARNING, "Trusted IP cannot be empty -- exiting\n");
    goto error;
  }
  hostname_size = ntohs (msg->hostname_size);
  if ((sizeof (struct GNUNET_TESTBED_HelperInit) + trusted_ip_size + 1 +
       hostname_size) >= msize)
  {
    GNUNET_break (0);
    LOG (GNUNET_ERROR_TYPE_WARNING, "Received unexpected message -- exiting\n");
    goto error;
  }
  ul_config_size = (uLongf) ntohs (msg->config_size);
  config = GNUNET_malloc (ul_config_size);
  xconfig_size =
      ntohs (message->size) - (trusted_ip_size + 1 +
                               sizeof (struct GNUNET_TESTBED_HelperInit));
  if (Z_OK !=
      uncompress ((Bytef *) config, &ul_config_size,
                  (const Bytef *) (trusted_ip + trusted_ip_size + 1 +
                                   hostname_size), (uLongf) xconfig_size))
  {
    LOG (GNUNET_ERROR_TYPE_WARNING,
         "Error while uncompressing config -- exiting\n");
    GNUNET_free (config);
    goto error;
  }
  cfg = GNUNET_CONFIGURATION_create ();
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_deserialize (cfg, config, ul_config_size, GNUNET_NO))
  {
    LOG (GNUNET_ERROR_TYPE_WARNING,
         "Unable to deserialize config -- exiting\n");
    GNUNET_free (config);
    goto error;
  }
  GNUNET_free (config);
  hostname = NULL;
  if (0 != hostname_size)
  {
    hostname = GNUNET_malloc (hostname_size + 1);
    (void) strncpy (hostname, ((char *) &msg[1]) + trusted_ip_size + 1,
                    hostname_size);
    hostname[hostname_size] = '\0';
  }
  test_system =
      GNUNET_TESTING_system_create ("testbed-helper", trusted_ip, hostname);
  GNUNET_free_non_null (hostname);
  hostname = NULL;
  GNUNET_assert (NULL != test_system);
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_TESTING_configuration_create (test_system, cfg));
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_CONFIGURATION_get_value_string (cfg, "PATHS",
                                                        "DEFAULTCONFIG",
                                                        &config));
  if (GNUNET_OK != GNUNET_CONFIGURATION_write (cfg, config))
  {
    LOG (GNUNET_ERROR_TYPE_WARNING,
         "Unable to write config file: %s -- exiting\n", config);
    GNUNET_CONFIGURATION_destroy (cfg);
    GNUNET_free (config);
    goto error;
  }
  LOG_DEBUG ("Staring testbed with config: %s\n", config);
  binary = GNUNET_OS_get_libexec_binary_path ("gnunet-service-testbed");
  testbed =
      GNUNET_OS_start_process (PIPE_CONTROL,
                               GNUNET_OS_INHERIT_STD_ERR /*verbose? */ , NULL,
                               NULL, binary, "gnunet-service-testbed", "-c",
                               config, NULL);
  GNUNET_free (binary);
  GNUNET_free (config);
  if (NULL == testbed)
  {
    LOG (GNUNET_ERROR_TYPE_WARNING,
         "Error starting gnunet-service-testbed -- exiting\n");
    GNUNET_CONFIGURATION_destroy (cfg);
    goto error;
  }
  done_reading = GNUNET_YES;
  config = GNUNET_CONFIGURATION_serialize (cfg, &config_size);
  GNUNET_CONFIGURATION_destroy (cfg);
  cfg = NULL;
  xconfig_size =
      GNUNET_TESTBED_compress_config_ (config, config_size, &xconfig);
  GNUNET_free (config);
  wc = GNUNET_malloc (sizeof (struct WriteContext));
  wc->length = xconfig_size + sizeof (struct GNUNET_TESTBED_HelperReply);
  reply = GNUNET_realloc (xconfig, wc->length);
  memmove (&reply[1], reply, xconfig_size);
  reply->header.type = htons (GNUNET_MESSAGE_TYPE_TESTBED_HELPER_REPLY);
  reply->header.size = htons ((uint16_t) wc->length);
  reply->config_size = htons ((uint16_t) config_size);
  wc->data = reply;
  write_task_id =
      GNUNET_SCHEDULER_add_write_file (GNUNET_TIME_UNIT_FOREVER_REL, stdout_fd,
                                       &write_task, wc);
  return GNUNET_OK;

error:
  status = GNUNET_SYSERR;
  GNUNET_SCHEDULER_shutdown ();
  return GNUNET_SYSERR;
}


/**
 * Task to read from stdin
 *
 * @param cls NULL
 * @param tc the task context
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
  if ((GNUNET_SYSERR == sread) || (0 == sread))
  {
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  if (GNUNET_YES == done_reading)
  {
    /* didn't expect any more data! */
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  LOG_DEBUG ("Read %u bytes\n", sread);
  if (GNUNET_OK !=
      GNUNET_SERVER_mst_receive (tokenizer, NULL, buf, sread, GNUNET_NO,
                                 GNUNET_NO))
  {
    GNUNET_break (0);
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  read_task_id =                /* No timeout while reading */
      GNUNET_SCHEDULER_add_read_file (GNUNET_TIME_UNIT_FOREVER_REL, stdin_fd,
                                      &read_task, NULL);
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
     const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  LOG_DEBUG ("Starting testbed helper...\n");
  tokenizer = GNUNET_SERVER_mst_create (&tokenizer_cb, NULL);
  stdin_fd = GNUNET_DISK_get_handle_from_native (stdin);
  stdout_fd = GNUNET_DISK_get_handle_from_native (stdout);
  read_task_id =
      GNUNET_SCHEDULER_add_read_file (GNUNET_TIME_UNIT_FOREVER_REL, stdin_fd,
                                      &read_task, NULL);
  GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_FOREVER_REL, &shutdown_task,
                                NULL);
}


/**
 * Signal handler called for SIGCHLD.
 */
static void
sighandler_child_death ()
{
  if ((NULL != testbed) && (GNUNET_NO == in_shutdown))
  {
    LOG_DEBUG ("Child died\n");
    GNUNET_assert (GNUNET_OK == GNUNET_OS_process_wait (testbed));
    GNUNET_OS_process_destroy (testbed);
    testbed = NULL;
    GNUNET_SCHEDULER_shutdown ();       /* We are done too! */
  }
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
  struct GNUNET_SIGNAL_Context *shc_chld;

  struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_OPTION_END
  };
  int ret;

  status = GNUNET_OK;
  in_shutdown = GNUNET_NO;
  shc_chld =
      GNUNET_SIGNAL_handler_install (GNUNET_SIGCHLD, &sighandler_child_death);
  ret =
      GNUNET_PROGRAM_run (argc, argv, "gnunet-helper-testbed",
                          "Helper for starting gnunet-service-testbed", options,
                          &run, NULL);
  GNUNET_SIGNAL_handler_uninstall (shc_chld);
  shc_chld = NULL;
  if (GNUNET_OK != ret)
    return 1;
  return (GNUNET_OK == status) ? 0 : 1;
}

/* end of gnunet-helper-testbed.c */

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
 * @file testbed/gnunet-helper-testbed.c
 * @brief Helper binary that is started from a remote controller to start
 *          gnunet-service-testbed. This binary also receives configuration
 *          from the remove controller which is put in a temporary location
 *          with ports and paths fixed so that gnunet-service-testbed runs
 *          without any hurdles.
 *
 *          This helper monitors for three termination events.  They are: (1)The
 *          stdin of the helper is closed for reading; (2)the helper received
 *          SIGTERM/SIGINT; (3)the testbed crashed.  In case of events 1 and 2
 *          the helper kills the testbed service.  When testbed crashed (event
 *          3), the helper should send a SIGTERM to its own process group; this
 *          behaviour will help terminate any child processes (peers) testbed
 *          has started and prevents them from leaking and running forever.
 *
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
 * Pipe used to communicate shutdown via signal.
 */
static struct GNUNET_DISK_PipeHandle *sigpipe;

/**
 * Task identifier for the read task
 */
static struct GNUNET_SCHEDULER_Task * read_task_id;

/**
 * Task identifier for the write task
 */
static struct GNUNET_SCHEDULER_Task * write_task_id;

/**
 * Task to kill the child
 */
static struct GNUNET_SCHEDULER_Task * child_death_task_id;

/**
 * shutdown task id
 */
static struct GNUNET_SCHEDULER_Task * shutdown_task_id;

/**
 * Are we done reading messages from stdin?
 */
static int done_reading;

/**
 * Result to return in case we fail
 */
static int status;


/**
 * Task to shut down cleanly
 *
 * @param cls NULL
 * @param tc the task context
 */
static void
shutdown_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  LOG_DEBUG ("Shutting down\n");
  shutdown_task_id = NULL;
  if (NULL != testbed)
  {
    LOG_DEBUG ("Killing testbed\n");
    GNUNET_break (0 == GNUNET_OS_process_kill (testbed, GNUNET_TERM_SIG));
  }
  if (NULL != read_task_id)
  {
    GNUNET_SCHEDULER_cancel (read_task_id);
    read_task_id = NULL;
  }
  if (NULL != write_task_id)
  {
    GNUNET_SCHEDULER_cancel (write_task_id);
    write_task_id = NULL;
  }
  if (NULL != child_death_task_id)
  {
    GNUNET_SCHEDULER_cancel (child_death_task_id);
    child_death_task_id = NULL;
  }
  if (NULL != stdin_fd)
    (void) GNUNET_DISK_file_close (stdin_fd);
  if (NULL != stdout_fd)
    (void) GNUNET_DISK_file_close (stdout_fd);
  GNUNET_SERVER_mst_destroy (tokenizer);
  tokenizer = NULL;
  if (NULL != testbed)
  {
    GNUNET_break (GNUNET_OK == GNUNET_OS_process_wait (testbed));
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
 * Scheduler shutdown task to be run now.
 */
static void
shutdown_now (void)
{
  if (NULL != shutdown_task_id)
    GNUNET_SCHEDULER_cancel (shutdown_task_id);
  shutdown_task_id = GNUNET_SCHEDULER_add_now (&shutdown_task, NULL);
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
  write_task_id = NULL;
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
 * Task triggered whenever we receive a SIGCHLD (child
 * process died).
 *
 * @param cls closure, NULL if we need to self-restart
 * @param tc context
 */
static void
child_death_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  const struct GNUNET_DISK_FileHandle *pr;
  char c[16];
  enum GNUNET_OS_ProcessStatusType type;
  unsigned long code;
  int ret;

  pr = GNUNET_DISK_pipe_handle (sigpipe, GNUNET_DISK_PIPE_END_READ);
  child_death_task_id = NULL;
  if (0 == (tc->reason & GNUNET_SCHEDULER_REASON_READ_READY))
  {
    child_death_task_id =
	GNUNET_SCHEDULER_add_read_file (GNUNET_TIME_UNIT_FOREVER_REL,
					pr, &child_death_task, NULL);
    return;
  }
  /* consume the signal */
  GNUNET_break (0 < GNUNET_DISK_file_read (pr, &c, sizeof (c)));
  LOG_DEBUG ("Got SIGCHLD\n");
  if (NULL == testbed)
  {
    GNUNET_break (0);
    return;
  }
  GNUNET_break (GNUNET_SYSERR !=
                (ret = GNUNET_OS_process_status (testbed, &type, &code)));
  if (GNUNET_NO != ret)
  {
    GNUNET_OS_process_destroy (testbed);
    testbed = NULL;
    /* Send SIGTERM to our process group */
    if (0 != PLIBC_KILL (0, GNUNET_TERM_SIG))
    {
      GNUNET_log_strerror (GNUNET_ERROR_TYPE_ERROR, "signal");
      shutdown_now ();          /* Couldn't send the signal, we shutdown frowning */
    }
    return;
  }
  LOG_DEBUG ("Child hasn't died.  Resuming to monitor its status\n");
  child_death_task_id =
      GNUNET_SCHEDULER_add_read_file (GNUNET_TIME_UNIT_FOREVER_REL,
                                      pr, &child_death_task, NULL);
}


/**
 * Functions with this signature are called whenever a
 * complete message is received by the tokenizer.
 *
 * Do not call #GNUNET_SERVER_mst_destroy() in this callback
 *
 * @param cls closure
 * @param client identification of the client
 * @param message the actual message
 *
 * @return #GNUNET_OK on success, #GNUNET_SYSERR to stop further processing
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
  char *evstr;
  //char *str;
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
  /* unset GNUNET_TESTING_PREFIX if present as it is more relevant for testbed */
  evstr = getenv (GNUNET_TESTING_PREFIX);
  if (NULL != evstr)
  {
    /* unsetting the variable will invalidate the pointer! */
    evstr = GNUNET_strdup (evstr);
#ifdef WINDOWS
    GNUNET_break (0 != SetEnvironmentVariable (GNUNET_TESTING_PREFIX, NULL));
#else
    GNUNET_break (0 == unsetenv (GNUNET_TESTING_PREFIX));
#endif
  }
  test_system =
      GNUNET_TESTING_system_create ("testbed-helper", trusted_ip, hostname,
                                    NULL);
  if (NULL != evstr)
  {
#ifdef WINDOWS
    GNUNET_assert (0 != SetEnvironmentVariable (GNUNET_TESTING_PREFIX,
                                                evstr));
#else
    char *evar;

    GNUNET_asprintf (&evar,
                     GNUNET_TESTING_PREFIX "=%s",
                     evstr);
    putenv (evar); /* consumes 'evar',
                      see putenv(): becomes part of envrionment! */
#endif
    GNUNET_free (evstr);
    evstr = NULL;
  }
  GNUNET_free_non_null (hostname);
  hostname = NULL;
  GNUNET_assert (NULL != test_system);
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_TESTING_configuration_create (test_system, cfg));
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_CONFIGURATION_get_value_filename (cfg, "PATHS",
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
  {
    static char evar[2 * PATH_MAX];

    /* expose testbed configuration through env variable */
    GNUNET_assert (0 < GNUNET_snprintf (evar, sizeof (evar),
                                        "%s=%s", ENV_TESTBED_CONFIG, config));
    GNUNET_assert (0 == putenv (evar));
    evstr = NULL;
  }
  testbed =
      GNUNET_OS_start_process (PIPE_CONTROL,
                               GNUNET_OS_INHERIT_STD_ERR /*verbose? */ ,
                               NULL, NULL, NULL,
                               binary,
                               "gnunet-service-testbed",
                               "-c", config,
                               NULL);
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
  wc = GNUNET_new (struct WriteContext);
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
  child_death_task_id =
      GNUNET_SCHEDULER_add_read_file (GNUNET_TIME_UNIT_FOREVER_REL,
                                      GNUNET_DISK_pipe_handle (sigpipe,
                                                               GNUNET_DISK_PIPE_END_READ),
                                      &child_death_task, NULL);
  return GNUNET_OK;

error:
  status = GNUNET_SYSERR;
  shutdown_now ();
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

  read_task_id = NULL;
  if (0 != (GNUNET_SCHEDULER_REASON_SHUTDOWN & tc->reason))
    return;
  sread = GNUNET_DISK_file_read (stdin_fd, buf, sizeof (buf));
  if ((GNUNET_SYSERR == sread) || (0 == sread))
  {
    LOG_DEBUG ("STDIN closed\n");
    shutdown_now ();
    return;
  }
  if (GNUNET_YES == done_reading)
  {
    /* didn't expect any more data! */
    GNUNET_break_op (0);
    shutdown_now ();
    return;
  }
  LOG_DEBUG ("Read %u bytes\n", sread);
  if (GNUNET_OK !=
      GNUNET_SERVER_mst_receive (tokenizer, NULL, buf, sread, GNUNET_NO,
                                 GNUNET_NO))
  {
    GNUNET_break (0);
    shutdown_now ();
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
  shutdown_task_id =
      GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_FOREVER_REL, &shutdown_task,
                                    NULL);
}


/**
 * Signal handler called for SIGCHLD.
 */
static void
sighandler_child_death ()
{
  static char c;
  int old_errno;	/* back-up errno */

  old_errno = errno;
  GNUNET_break (1 ==
                GNUNET_DISK_file_write (GNUNET_DISK_pipe_handle
                                        (sigpipe, GNUNET_DISK_PIPE_END_WRITE),
                                        &c, sizeof (c)));
  errno = old_errno;
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
  if (NULL == (sigpipe = GNUNET_DISK_pipe (GNUNET_NO, GNUNET_NO,
                                           GNUNET_NO, GNUNET_NO)))
  {
    GNUNET_break (0);
    return 1;
  }
  shc_chld =
      GNUNET_SIGNAL_handler_install (GNUNET_SIGCHLD, &sighandler_child_death);
  ret =
      GNUNET_PROGRAM_run (argc, argv, "gnunet-helper-testbed",
                          "Helper for starting gnunet-service-testbed", options,
                          &run, NULL);
  GNUNET_SIGNAL_handler_uninstall (shc_chld);
  shc_chld = NULL;
  GNUNET_DISK_pipe_close (sigpipe);
  if (GNUNET_OK != ret)
    return 1;
  return (GNUNET_OK == status) ? 0 : 1;
}

/* end of gnunet-helper-testbed.c */

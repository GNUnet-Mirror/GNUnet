#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_testbed_service.h"


/**
 * Generic logging shorthand
 */
#define LOG(kind,...)                           \
  GNUNET_log (kind, __VA_ARGS__)

/**
 * Debug logging shorthand
 */
#define LOG_DEBUG(...)                          \
  LOG (GNUNET_ERROR_TYPE_DEBUG, __VA_ARGS__)

/**
 * Global result
 */
static int ret;

/**
 * The child process we spawn
 */
static struct GNUNET_OS_Process *child;

/**
 * The arguments including the binary to spawn
 */
static char **argv2;

/**
 * Pipe used to communicate shutdown via signal.
 */
static struct GNUNET_DISK_PipeHandle *sigpipe;

/**
 * Filename of the unique file
 */
static char *fn;

/**
 * Handle to the unique file
 */
static int fh;

/**
 * The return code of the binary
 */
static unsigned long child_exit_code;

/**
 * The process status of the child
 */
static enum GNUNET_OS_ProcessStatusType child_status;

/**
 * The shutdown task
 */
static struct GNUNET_SCHEDULER_Task * shutdown_task_id;

/**
 * Task to kill the child
 */
static struct GNUNET_SCHEDULER_Task * terminate_task_id;

/**
 * Task to kill the child
 */
static struct GNUNET_SCHEDULER_Task * child_death_task_id;

/**
 * The shutdown task
 */
static void
shutdown_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  shutdown_task_id = NULL;
  if (0 != child_exit_code)
  {
    LOG (GNUNET_ERROR_TYPE_WARNING, "Child exited with error code: %lu\n",
         child_exit_code);
    ret = 128 + (int) child_exit_code;
  }
  if (0 != fh)
  {
    close (fh);
  }
  if ((NULL != fn) && (0 != unlink (fn)))
  {
    GNUNET_log_strerror (GNUNET_ERROR_TYPE_ERROR, "open");
    ret = GNUNET_SYSERR;
  }
}


static void
terminate_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  static int hard_kill;

  GNUNET_assert (NULL != child);
  terminate_task_id =
      GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_FOREVER_REL,
                                    &terminate_task, NULL);
  if (0 != hard_kill)
  {
    switch (hard_kill)
    {
    case 1:
    case 2:
      LOG (GNUNET_ERROR_TYPE_WARNING,
           "%d more interrupts needed to send SIGKILL to the child\n",
           3 - hard_kill);
      hard_kill++;
      return;
    case 3:
      GNUNET_break (0 == GNUNET_OS_process_kill (child, SIGKILL));
      return;
    }
  }
  hard_kill++;
  GNUNET_break (0 == GNUNET_OS_process_kill (child, GNUNET_TERM_SIG));
  LOG (GNUNET_ERROR_TYPE_INFO, _("Waiting for child to exit.\n"));
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
  LOG_DEBUG ("Child died\n");
  GNUNET_SCHEDULER_cancel (terminate_task_id);
  terminate_task_id = NULL;
  GNUNET_assert (GNUNET_OK == GNUNET_OS_process_status (child, &child_status,
                                                        &child_exit_code));
  GNUNET_OS_process_destroy (child);
  child = NULL;
  shutdown_task_id = GNUNET_SCHEDULER_add_now (&shutdown_task, NULL);
}


static void
destroy_hosts(struct GNUNET_TESTBED_Host **hosts, unsigned int nhosts)
{
  unsigned int host;

  GNUNET_assert (NULL != hosts);
  for (host = 0; host < nhosts; host++)
    if (NULL != hosts[host])
      GNUNET_TESTBED_host_destroy (hosts[host]);
  GNUNET_free (hosts);
  hosts = NULL;
}


/**
 * The main scheduler run task
 *
 * @param cls NULL
 * @param tc scheduler task context
 */
static void
run (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_TESTBED_Host **hosts;
  const struct GNUNET_CONFIGURATION_Handle *null_cfg;
  char *tmpdir;
  char *hostname;
  size_t hostname_len;
  unsigned int nhosts;

  null_cfg = GNUNET_CONFIGURATION_create ();
  nhosts = GNUNET_TESTBED_hosts_load_from_loadleveler (null_cfg, &hosts);
  if (0 == nhosts)
  {
    GNUNET_break (0);
    ret = GNUNET_SYSERR;
    return;
  }
  hostname_len = GNUNET_OS_get_hostname_max_length ();
  hostname = GNUNET_malloc (hostname_len);
  if (0 != gethostname (hostname, hostname_len))
  {
    LOG (GNUNET_ERROR_TYPE_ERROR, "Cannot get hostname.  Exiting\n");
    GNUNET_free (hostname);
    destroy_hosts (hosts, nhosts);
    ret = GNUNET_SYSERR;
    return;
  }
  if (NULL == strstr (GNUNET_TESTBED_host_get_hostname (hosts[0]), hostname))
  {
    LOG_DEBUG ("Exiting as `%s' is not the lowest host\n", hostname);
    GNUNET_free (hostname);
    ret = GNUNET_OK;
    return;
  }
  LOG_DEBUG ("Will be executing `%s' on host `%s'\n", argv2[0], hostname);
  GNUNET_free (hostname);
  destroy_hosts (hosts, nhosts);
  tmpdir = getenv ("TMPDIR");
  if (NULL == tmpdir)
    tmpdir = getenv ("TMP");
  if (NULL == tmpdir)
    tmpdir = getenv ("TEMP");
  if (NULL == tmpdir)
    tmpdir = "/tmp";
  (void) GNUNET_asprintf (&fn, "%s/gnunet-testbed-spawn.lock", tmpdir);
  /* Open the unique file; we can create it then we can spawn the child process
     else we exit */
  fh = open (fn, O_CREAT | O_EXCL | O_CLOEXEC,
             S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
  if (-1 == fh)
  {
    if (EEXIST == errno)
    {
      LOG_DEBUG ("Lock file already created by other process.  Exiting\n");
      ret = GNUNET_OK;
      return;
    }
    GNUNET_log_strerror (GNUNET_ERROR_TYPE_ERROR, "open");
    ret = GNUNET_SYSERR;
    return;
  }
  /* Spawn the new process here */
  LOG (GNUNET_ERROR_TYPE_INFO, _("Spawning process `%s'\n"), argv2[0]);
  child = GNUNET_OS_start_process_vap (GNUNET_NO, GNUNET_OS_INHERIT_STD_ALL, NULL,
                                       NULL, NULL,
                                       argv2[0], argv2);
  if (NULL == child)
  {
    GNUNET_break (0);
    ret = GNUNET_SYSERR;
    shutdown_task_id = GNUNET_SCHEDULER_add_now (&shutdown_task, NULL);
    return;
  }
  ret = GNUNET_OK;
  terminate_task_id =
      GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_FOREVER_REL,
                                    &terminate_task, NULL);
  child_death_task_id =
    GNUNET_SCHEDULER_add_read_file (GNUNET_TIME_UNIT_FOREVER_REL,
				    GNUNET_DISK_pipe_handle (sigpipe,
							     GNUNET_DISK_PIPE_END_READ),
				    &child_death_task, NULL);
}


/**
 * Signal handler called for SIGCHLD.
 */
static void
sighandler_child_death ()
{
  static char c;
  int old_errno = errno;	/* back-up errno */

  GNUNET_break (1 ==
		GNUNET_DISK_file_write (GNUNET_DISK_pipe_handle
					(sigpipe, GNUNET_DISK_PIPE_END_WRITE),
					&c, sizeof (c)));
  errno = old_errno;		/* restore errno */
}


/**
 * Execution start point
 */
int
main (int argc, char *argv[])
{
  struct GNUNET_SIGNAL_Context *shc_chld;
  unsigned int cnt;

  ret = -1;
  if (argc < 2)
  {
    printf ("Need arguments: gnunet-testbed-mpi-spawn <cmd> <cmd_args>");
    return 1;
  }
  if (GNUNET_OK != GNUNET_log_setup ("gnunet-testbed-spawn", NULL, NULL))
  {
    GNUNET_break (0);
    return 1;
  }
  if (NULL == (sigpipe = GNUNET_DISK_pipe (GNUNET_NO, GNUNET_NO,
                                           GNUNET_NO, GNUNET_NO)))
  {
    GNUNET_break (0);
    ret = GNUNET_SYSERR;
    return 1;
  }
  shc_chld =
      GNUNET_SIGNAL_handler_install (GNUNET_SIGCHLD, &sighandler_child_death);
  if (NULL == shc_chld)
  {
    LOG (GNUNET_ERROR_TYPE_ERROR, "Cannot install a signal handler\n");
    return 1;
  }
  argv2 = GNUNET_malloc (sizeof (char *) * argc);
  for (cnt = 1; cnt < argc; cnt++)
    argv2[cnt - 1] = argv[cnt];
  GNUNET_SCHEDULER_run (run, NULL);
  GNUNET_free (argv2);
  GNUNET_SIGNAL_handler_uninstall (shc_chld);
  shc_chld = NULL;
  GNUNET_DISK_pipe_close (sigpipe);
  GNUNET_free_non_null (fn);
  if (GNUNET_OK != ret)
    return ret;
  return 0;
}

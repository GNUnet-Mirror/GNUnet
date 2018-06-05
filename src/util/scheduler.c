/*
      This file is part of GNUnet
      Copyright (C) 2009-2017 GNUnet e.V.

      GNUnet is free software: you can redistribute it and/or modify it
      under the terms of the GNU General Public License as published
      by the Free Software Foundation, either version 3 of the License,
      or (at your option) any later version.

      GNUnet is distributed in the hope that it will be useful, but
      WITHOUT ANY WARRANTY; without even the implied warranty of
      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
      Affero General Public License for more details.
 */
/**
 * @file util/scheduler.c
 * @brief schedule computations using continuation passing style
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "disk.h"
// DEBUG
#include <inttypes.h>

#define LOG(kind,...) GNUNET_log_from (kind, "util-scheduler", __VA_ARGS__)

#define LOG_STRERROR(kind,syscall) GNUNET_log_from_strerror (kind, "util-scheduler", syscall)


#if HAVE_EXECINFO_H
#include "execinfo.h"

/**
 * Use lsof to generate file descriptor reports on select error?
 * (turn off for stable releases).
 */
#define USE_LSOF GNUNET_NO

/**
 * Obtain trace information for all scheduler calls that schedule tasks.
 */
#define EXECINFO GNUNET_NO

/**
 * Check each file descriptor before adding
 */
#define DEBUG_FDS GNUNET_NO

/**
 * Depth of the traces collected via EXECINFO.
 */
#define MAX_TRACE_DEPTH 50
#endif

/**
 * Should we figure out which tasks are delayed for a while
 * before they are run? (Consider using in combination with EXECINFO).
 */
#define PROFILE_DELAYS GNUNET_NO

/**
 * Task that were in the queue for longer than this are reported if
 * PROFILE_DELAYS is active.
 */
#define DELAY_THRESHOLD GNUNET_TIME_UNIT_SECONDS


/**
 * Argument to be passed from the driver to
 * #GNUNET_SCHEDULER_do_work().  Contains the
 * scheduler's internal state.
 */
struct GNUNET_SCHEDULER_Handle
{
  /**
   * Passed here to avoid constantly allocating/deallocating
   * this element, but generally we want to get rid of this.
   * @deprecated
   */
  struct GNUNET_NETWORK_FDSet *rs;

  /**
   * Passed here to avoid constantly allocating/deallocating
   * this element, but generally we want to get rid of this.
   * @deprecated
   */
  struct GNUNET_NETWORK_FDSet *ws;

  /**
   * context of the SIGINT handler
   */
  struct GNUNET_SIGNAL_Context *shc_int;

  /**
   * context of the SIGTERM handler
   */
  struct GNUNET_SIGNAL_Context *shc_term;

#if (SIGTERM != GNUNET_TERM_SIG)
  /**
   * context of the TERM_SIG handler
   */
  struct GNUNET_SIGNAL_Context *shc_gterm;
#endif

#ifndef MINGW
  /**
   * context of the SIGQUIT handler
   */
  struct GNUNET_SIGNAL_Context *shc_quit;

  /**
   * context of the SIGHUP handler
   */
  struct GNUNET_SIGNAL_Context *shc_hup;

  /**
   * context of hte SIGPIPE handler
   */
  struct GNUNET_SIGNAL_Context *shc_pipe;
#endif
};


/**
 * Entry in list of pending tasks.
 */
struct GNUNET_SCHEDULER_Task
{
  /**
   * This is a linked list.
   */
  struct GNUNET_SCHEDULER_Task *next;

  /**
   * This is a linked list.
   */
  struct GNUNET_SCHEDULER_Task *prev;

  /**
   * Function to run when ready.
   */
  GNUNET_SCHEDULER_TaskCallback callback;

  /**
   * Closure for the @e callback.
   */
  void *callback_cls;

  /**
   * Information about which FDs are ready for this task (and why).
   */
  struct GNUNET_SCHEDULER_FdInfo *fds;

  /**
   * Storage location used for @e fds if we want to avoid
   * a separate malloc() call in the common case that this
   * task is only about a single FD.
   */
  struct GNUNET_SCHEDULER_FdInfo fdx;

  /**
   * Size of the @e fds array.
   */
  unsigned int fds_len;

  /**
   * Do we own the network and file handles referenced by the FdInfo
   * structs in the fds array. This will only be GNUNET_YES if the
   * task was created by the #GNUNET_SCHEDULER_add_select function.
   */
  int own_handles;

  /**
   * Absolute timeout value for the task, or
   * #GNUNET_TIME_UNIT_FOREVER_ABS for "no timeout".
   */
  struct GNUNET_TIME_Absolute timeout;

#if PROFILE_DELAYS
  /**
   * When was the task scheduled?
   */
  struct GNUNET_TIME_Absolute start_time;
#endif

  /**
   * Why is the task ready?  Set after task is added to ready queue.
   * Initially set to zero.  All reasons that have already been
   * satisfied (i.e.  read or write ready) will be set over time.
   */
  enum GNUNET_SCHEDULER_Reason reason;

  /**
   * Task priority.
   */
  enum GNUNET_SCHEDULER_Priority priority;

  /**
   * Set if we only wait for reading from a single FD, otherwise -1.
   */
  int read_fd;

  /**
   * Set if we only wait for writing to a single FD, otherwise -1.
   */
  int write_fd;

  /**
   * Should the existence of this task in the queue be counted as
   * reason to not shutdown the scheduler?
   */
  int lifeness;

  /**
   * Is this task run on shutdown?
   */
  int on_shutdown;

  /**
   * Is this task in the ready list?
   */
  int in_ready_list;

#if EXECINFO
  /**
   * Array of strings which make up a backtrace from the point when this
   * task was scheduled (essentially, who scheduled the task?)
   */
  char **backtrace_strings;

  /**
   * Size of the backtrace_strings array
   */
  int num_backtrace_strings;
#endif

};


/**
 * A struct representing an event the select driver is waiting for
 */
struct Scheduled
{
  struct Scheduled *prev;

  struct Scheduled *next;

  /**
   * the task, the event is related to
   */
  struct GNUNET_SCHEDULER_Task *task;

  /**
   * information about the network socket / file descriptor where
   * the event is expected to occur
   */
  struct GNUNET_SCHEDULER_FdInfo *fdi;

  /**
   * the event types (multiple event types can be ORed) the select
   * driver is expected to wait for
   */
  enum GNUNET_SCHEDULER_EventType et;
};


/**
 * Driver context used by GNUNET_SCHEDULER_run
 */
struct DriverContext
{
  /**
   * the head of a DLL containing information about the events the
   * select driver is waiting for
   */
  struct Scheduled *scheduled_head;

  /**
   * the tail of a DLL containing information about the events the
   * select driver is waiting for
   */
  struct Scheduled *scheduled_tail;

  /**
   * the time when the select driver will wake up again (after
   * calling select)
   */
  struct GNUNET_TIME_Absolute timeout;
};


/**
 * The driver used for the event loop. Will be handed over to
 * the scheduler in #GNUNET_SCHEDULER_do_work(), persisted
 * there in this variable for later use in functions like
 * #GNUNET_SCHEDULER_add_select(), #add_without_sets() and
 * #GNUNET_SCHEDULER_cancel().
 */
static const struct GNUNET_SCHEDULER_Driver *scheduler_driver;

/**
 * Head of list of tasks waiting for an event.
 */
static struct GNUNET_SCHEDULER_Task *pending_head;

/**
 * Tail of list of tasks waiting for an event.
 */
static struct GNUNET_SCHEDULER_Task *pending_tail;

/**
 * Head of list of tasks waiting for shutdown.
 */
static struct GNUNET_SCHEDULER_Task *shutdown_head;

/**
 * Tail of list of tasks waiting for shutdown.
 */
static struct GNUNET_SCHEDULER_Task *shutdown_tail;

/**
 * List of tasks waiting ONLY for a timeout event.
 * Sorted by timeout (earliest first).  Used so that
 * we do not traverse the list of these tasks when
 * building select sets (we just look at the head
 * to determine the respective timeout ONCE).
 */
static struct GNUNET_SCHEDULER_Task *pending_timeout_head;

/**
 * List of tasks waiting ONLY for a timeout event.
 * Sorted by timeout (earliest first).  Used so that
 * we do not traverse the list of these tasks when
 * building select sets (we just look at the head
 * to determine the respective timeout ONCE).
 */
static struct GNUNET_SCHEDULER_Task *pending_timeout_tail;

/**
 * Last inserted task waiting ONLY for a timeout event.
 * Used to (heuristically) speed up insertion.
 */
static struct GNUNET_SCHEDULER_Task *pending_timeout_last;

/**
 * ID of the task that is running right now.
 */
static struct GNUNET_SCHEDULER_Task *active_task;

/**
 * Head of list of tasks ready to run right now, grouped by importance.
 */
static struct GNUNET_SCHEDULER_Task *ready_head[GNUNET_SCHEDULER_PRIORITY_COUNT];

/**
 * Tail of list of tasks ready to run right now, grouped by importance.
 */
static struct GNUNET_SCHEDULER_Task *ready_tail[GNUNET_SCHEDULER_PRIORITY_COUNT];

/**
 * Task for installing parent control handlers (it might happen that the
 * scheduler is shutdown before this task is executed, so
 * GNUNET_SCHEDULER_shutdown must cancel it in that case)
 */
static struct GNUNET_SCHEDULER_Task *install_parent_control_task;

/**
 * Task for reading from a pipe that signal handlers will use to initiate
 * shutdown
 */
static struct GNUNET_SCHEDULER_Task *shutdown_pipe_task;

/**
 * Number of tasks on the ready list.
 */
static unsigned int ready_count;

/**
 * Priority of the task running right now.  Only
 * valid while a task is running.
 */
static enum GNUNET_SCHEDULER_Priority current_priority;

/**
 * Priority of the highest task added in the current select
 * iteration.
 */
static enum GNUNET_SCHEDULER_Priority max_priority_added;

/**
 * Value of the 'lifeness' flag for the current task.
 */
static int current_lifeness;

/**
 * Function to use as a select() in the scheduler.
 * If NULL, we use GNUNET_NETWORK_socket_select().
 */
static GNUNET_SCHEDULER_select scheduler_select;

/**
 * Task context of the current task.
 */
static struct GNUNET_SCHEDULER_TaskContext tc;

/**
 * Closure for #scheduler_select.
 */
static void *scheduler_select_cls;


/**
 * Sets the select function to use in the scheduler (scheduler_select).
 *
 * @param new_select new select function to use
 * @param new_select_cls closure for @a new_select
 * @return previously used select function, NULL for default
 */
void
GNUNET_SCHEDULER_set_select (GNUNET_SCHEDULER_select new_select,
                             void *new_select_cls)
{
  scheduler_select = new_select;
  scheduler_select_cls = new_select_cls;
}


/**
 * Check that the given priority is legal (and return it).
 *
 * @param p priority value to check
 * @return p on success, 0 on error
 */
static enum GNUNET_SCHEDULER_Priority
check_priority (enum GNUNET_SCHEDULER_Priority p)
{
  if ((p >= 0) && (p < GNUNET_SCHEDULER_PRIORITY_COUNT))
    return p;
  GNUNET_assert (0);
  return 0;                     /* make compiler happy */
}


/**
 * chooses the nearest timeout from all pending tasks, to be used
 * to tell the driver the next wakeup time (using its set_wakeup
 * callback)
 */
struct GNUNET_TIME_Absolute
get_timeout ()
{
  struct GNUNET_SCHEDULER_Task *pos;
  struct GNUNET_TIME_Absolute now;
  struct GNUNET_TIME_Absolute timeout;

  pos = pending_timeout_head;
  now = GNUNET_TIME_absolute_get ();
  timeout = GNUNET_TIME_UNIT_FOREVER_ABS;
  if (NULL != pos)
  {
    if (0 != pos->reason)
    {
      return now;
    }
    else
    {
      timeout = pos->timeout;
    }
  }
  for (pos = pending_head; NULL != pos; pos = pos->next)
  {
    if (0 != pos->reason)
    {
      return now;
    }
    else if ((pos->timeout.abs_value_us != GNUNET_TIME_UNIT_FOREVER_ABS.abs_value_us) &&
             (timeout.abs_value_us > pos->timeout.abs_value_us))
    {
      timeout = pos->timeout;
    }
  }
  return timeout;
}


/**
 * Put a task that is ready for execution into the ready queue.
 *
 * @param task task ready for execution
 */
static void
queue_ready_task (struct GNUNET_SCHEDULER_Task *task)
{
  enum GNUNET_SCHEDULER_Priority p = check_priority (task->priority);

  GNUNET_CONTAINER_DLL_insert (ready_head[p],
                               ready_tail[p],
                               task);
  task->in_ready_list = GNUNET_YES;
  ready_count++;
}


/**
 * Request the shutdown of a scheduler.  Marks all tasks
 * awaiting shutdown as ready. Note that tasks
 * scheduled with #GNUNET_SCHEDULER_add_shutdown() AFTER this call
 * will be delayed until the next shutdown signal.
 */
void
GNUNET_SCHEDULER_shutdown ()
{
  struct GNUNET_SCHEDULER_Task *pos;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "GNUNET_SCHEDULER_shutdown\n");
  if (NULL != install_parent_control_task)
  {
    GNUNET_SCHEDULER_cancel (install_parent_control_task);
    install_parent_control_task = NULL;
  }
  if (NULL != shutdown_pipe_task)
  {
    GNUNET_SCHEDULER_cancel (shutdown_pipe_task);
    shutdown_pipe_task = NULL;
  }
  while (NULL != (pos = shutdown_head))
  {
    GNUNET_CONTAINER_DLL_remove (shutdown_head,
                                 shutdown_tail,
                                 pos);
    pos->reason |= GNUNET_SCHEDULER_REASON_SHUTDOWN;
    queue_ready_task (pos);
  }
}


/**
 * Output stack trace of task @a t.
 *
 * @param t task to dump stack trace of
 */
static void
dump_backtrace (struct GNUNET_SCHEDULER_Task *t)
{
#if EXECINFO
  for (unsigned int i = 0; i < t->num_backtrace_strings; i++)
    LOG (GNUNET_ERROR_TYPE_WARNING,
	 "Task %p trace %u: %s\n",
	 t,
	 i,
	 t->backtrace_strings[i]);
#else
  (void) t;
#endif
}


/**
 * Destroy a task (release associated resources)
 *
 * @param t task to destroy
 */
static void
destroy_task (struct GNUNET_SCHEDULER_Task *t)
{
  unsigned int i;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "destroying task %p\n",
       t);

  if (GNUNET_YES == t->own_handles)
  {
    for (i = 0; i != t->fds_len; ++i)
    {
      const struct GNUNET_NETWORK_Handle *fd = t->fds[i].fd;
      const struct GNUNET_DISK_FileHandle *fh = t->fds[i].fh;
      if (fd)
      {
        GNUNET_NETWORK_socket_free_memory_only_ ((struct GNUNET_NETWORK_Handle *) fd);
      }
      if (fh)
      {
        // FIXME: on WIN32 this is not enough! A function
        // GNUNET_DISK_file_free_memory_only would be nice
        GNUNET_free ((void *) fh);
      }
    }
  }
  if (t->fds_len > 1)
  {
    GNUNET_array_grow (t->fds, t->fds_len, 0);
  }
#if EXECINFO
  GNUNET_free (t->backtrace_strings);
#endif
  GNUNET_free (t);
}


/**
 * Pipe used to communicate shutdown via signal.
 */
static struct GNUNET_DISK_PipeHandle *shutdown_pipe_handle;

/**
 * Process ID of this process at the time we installed the various
 * signal handlers.
 */
static pid_t my_pid;

/**
 * Signal handler called for SIGPIPE.
 */
#ifndef MINGW
static void
sighandler_pipe ()
{
  return;
}
#endif


///**
// * Wait for a short time.
// * Sleeps for @a ms ms (as that should be long enough for virtually all
// * modern systems to context switch and allow another process to do
// * some 'real' work).
// *
// * @param ms how many ms to wait
// */
//static void
//short_wait (unsigned int ms)
//{
//  struct GNUNET_TIME_Relative timeout;
//
//  timeout = GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MILLISECONDS, ms);
//  (void) GNUNET_NETWORK_socket_select (NULL, NULL, NULL, timeout);
//}


/**
 * Signal handler called for signals that should cause us to shutdown.
 */
static void
sighandler_shutdown ()
{
  static char c;
  int old_errno = errno;        /* backup errno */

  if (getpid () != my_pid)
    exit (1);                   /* we have fork'ed since the signal handler was created,
                                 * ignore the signal, see https://gnunet.org/vfork discussion */
  GNUNET_DISK_file_write (GNUNET_DISK_pipe_handle
                          (shutdown_pipe_handle, GNUNET_DISK_PIPE_END_WRITE),
                          &c, sizeof (c));
  errno = old_errno;
}


static void
shutdown_if_no_lifeness ()
{
  struct GNUNET_SCHEDULER_Task *t;

  if (ready_count > 0)
    return;
  for (t = pending_head; NULL != t; t = t->next)
    if (GNUNET_YES == t->lifeness)
      return;
  for (t = shutdown_head; NULL != t; t = t->next)
    if (GNUNET_YES == t->lifeness)
      return;
  for (t = pending_timeout_head; NULL != t; t = t->next)
    if (GNUNET_YES == t->lifeness)
      return;
  /* No lifeness! */
  GNUNET_SCHEDULER_shutdown ();
}


static int
select_loop (struct GNUNET_SCHEDULER_Handle *sh,
             struct DriverContext *context);


/**
 * Initialize and run scheduler.  This function will return when all
 * tasks have completed.  On systems with signals, receiving a SIGTERM
 * (and other similar signals) will cause #GNUNET_SCHEDULER_shutdown()
 * to be run after the active task is complete.  As a result, SIGTERM
 * causes all active tasks to be scheduled with reason
 * #GNUNET_SCHEDULER_REASON_SHUTDOWN.  (However, tasks added
 * afterwards will execute normally!). Note that any particular signal
 * will only shut down one scheduler; applications should always only
 * create a single scheduler.
 *
 * @param task task to run immediately
 * @param task_cls closure of @a task
 */
void
GNUNET_SCHEDULER_run (GNUNET_SCHEDULER_TaskCallback task,
                      void *task_cls)
{
  struct GNUNET_SCHEDULER_Handle *sh;
  struct GNUNET_SCHEDULER_Driver *driver;
  struct DriverContext context = {.scheduled_head = NULL,
                                  .scheduled_tail = NULL,
                                  .timeout = GNUNET_TIME_absolute_get ()};

  driver = GNUNET_SCHEDULER_driver_select ();
  driver->cls = &context;
  sh = GNUNET_SCHEDULER_driver_init (driver);
  GNUNET_SCHEDULER_add_with_reason_and_priority (task,
                                                 task_cls,
                                                 GNUNET_SCHEDULER_REASON_STARTUP,
                                                 GNUNET_SCHEDULER_PRIORITY_DEFAULT);
  select_loop (sh,
               &context);
  GNUNET_SCHEDULER_driver_done (sh);
  GNUNET_free (driver);
}


/**
 * Obtain the task context, giving the reason why the current task was
 * started.
 *
 * @return current tasks' scheduler context
 */
const struct GNUNET_SCHEDULER_TaskContext *
GNUNET_SCHEDULER_get_task_context ()
{
  GNUNET_assert (NULL != active_task);
  return &tc;
}


/**
 * Get information about the current load of this scheduler.  Use this
 * function to determine if an elective task should be added or simply
 * dropped (if the decision should be made based on the number of
 * tasks ready to run).
 *
 * @param p priority level to look at
 * @return number of tasks pending right now
 */
unsigned int
GNUNET_SCHEDULER_get_load (enum GNUNET_SCHEDULER_Priority p)
{
  struct GNUNET_SCHEDULER_Task *pos;
  unsigned int ret;

  GNUNET_assert (NULL != active_task);
  if (p == GNUNET_SCHEDULER_PRIORITY_COUNT)
    return ready_count;
  if (p == GNUNET_SCHEDULER_PRIORITY_KEEP)
    p = current_priority;
  ret = 0;
  for (pos = ready_head[check_priority (p)]; NULL != pos; pos = pos->next)
    ret++;
  return ret;
}


void
init_fd_info (struct GNUNET_SCHEDULER_Task *t,
              const struct GNUNET_NETWORK_Handle *const *read_nh,
              unsigned int read_nh_len,
              const struct GNUNET_NETWORK_Handle *const *write_nh,
              unsigned int write_nh_len,
              const struct GNUNET_DISK_FileHandle *const *read_fh,
              unsigned int read_fh_len,
              const struct GNUNET_DISK_FileHandle *const *write_fh,
              unsigned int write_fh_len)
{
  // FIXME: if we have exactly two network handles / exactly two file handles
  // and they are equal, we can make one FdInfo with both
  // GNUNET_SCHEDULER_ET_IN and GNUNET_SCHEDULER_ET_OUT set.
  struct GNUNET_SCHEDULER_FdInfo *fdi;

  t->fds_len = read_nh_len + write_nh_len + read_fh_len + write_fh_len;
  if (1 == t->fds_len)
  {
    fdi = &t->fdx;
    t->fds = fdi;
    if (1 == read_nh_len)
    {
      GNUNET_assert (NULL != read_nh);
      GNUNET_assert (NULL != *read_nh);
      fdi->fd = *read_nh;
      fdi->et = GNUNET_SCHEDULER_ET_IN;
      fdi->sock = GNUNET_NETWORK_get_fd (*read_nh);
      t->read_fd = fdi->sock;
      t->write_fd = -1;
    }
    else if (1 == write_nh_len)
    {
      GNUNET_assert (NULL != write_nh);
      GNUNET_assert (NULL != *write_nh);
      fdi->fd = *write_nh;
      fdi->et = GNUNET_SCHEDULER_ET_OUT;
      fdi->sock = GNUNET_NETWORK_get_fd (*write_nh);
      t->read_fd = -1;
      t->write_fd = fdi->sock;
    }
    else if (1 == read_fh_len)
    {
      GNUNET_assert (NULL != read_fh);
      GNUNET_assert (NULL != *read_fh);
      fdi->fh = *read_fh;
      fdi->et = GNUNET_SCHEDULER_ET_IN;
      fdi->sock = (*read_fh)->fd; // FIXME: does not work under WIN32
      t->read_fd = fdi->sock;
      t->write_fd = -1;
    }
    else
    {
      GNUNET_assert (NULL != write_fh);
      GNUNET_assert (NULL != *write_fh);
      fdi->fh = *write_fh;
      fdi->et = GNUNET_SCHEDULER_ET_OUT;
      fdi->sock = (*write_fh)->fd; // FIXME: does not work under WIN32
      t->read_fd = -1;
      t->write_fd = fdi->sock;
    }
  }
  else
  {
    fdi = GNUNET_new_array (t->fds_len, struct GNUNET_SCHEDULER_FdInfo);
    t->fds = fdi;
    t->read_fd = -1;
    t->write_fd = -1;
    unsigned int i;
    for (i = 0; i != read_nh_len; ++i)
    {
      fdi->fd = read_nh[i];
      GNUNET_assert (NULL != fdi->fd);
      fdi->et = GNUNET_SCHEDULER_ET_IN;
      fdi->sock = GNUNET_NETWORK_get_fd (read_nh[i]);
      ++fdi;
    }
    for (i = 0; i != write_nh_len; ++i)
    {
      fdi->fd = write_nh[i];
      GNUNET_assert (NULL != fdi->fd);
      fdi->et = GNUNET_SCHEDULER_ET_OUT;
      fdi->sock = GNUNET_NETWORK_get_fd (write_nh[i]);
      ++fdi;
    }
    for (i = 0; i != read_fh_len; ++i)
    {
      fdi->fh = read_fh[i];
      GNUNET_assert (NULL != fdi->fh);
      fdi->et = GNUNET_SCHEDULER_ET_IN;
      fdi->sock = (read_fh[i])->fd; // FIXME: does not work under WIN32
      ++fdi;
    }
    for (i = 0; i != write_fh_len; ++i)
    {
      fdi->fh = write_fh[i];
      GNUNET_assert (NULL != fdi->fh);
      fdi->et = GNUNET_SCHEDULER_ET_OUT;
      fdi->sock = (write_fh[i])->fd; // FIXME: does not work under WIN32
      ++fdi;
    }
  }
}


/**
 * calls the given function @a func on each FdInfo related to @a t.
 * Optionally updates the event type field in each FdInfo after calling
 * @a func.
 *
 * @param t the task
 * @param driver_func the function to call with each FdInfo contained in
 *                    in @a t
 * @param if_not_ready only call @a driver_func on FdInfos that are not
 *                     ready
 * @param et the event type to be set in each FdInfo after calling
 *           @a driver_func on it, or -1 if no updating not desired.
 */
static void
driver_add_multiple (struct GNUNET_SCHEDULER_Task *t)
{
  struct GNUNET_SCHEDULER_FdInfo *fdi;
  int success = GNUNET_YES;

  for (unsigned int i = 0; i != t->fds_len; ++i)
  {
    fdi = &t->fds[i];
    success = scheduler_driver->add (scheduler_driver->cls,
				     t,
				     fdi) && success;
    fdi->et = GNUNET_SCHEDULER_ET_NONE;
  }
  if (GNUNET_YES != success)
  {
    LOG (GNUNET_ERROR_TYPE_ERROR,
         "driver could not add task\n");
  }
}


static void
install_parent_control_handler (void *cls)
{
  install_parent_control_task = NULL;
  GNUNET_OS_install_parent_control_handler (NULL);
}


static void
shutdown_pipe_cb (void *cls)
{
  char c;
  const struct GNUNET_DISK_FileHandle *pr;

  shutdown_pipe_task = NULL;
  pr = GNUNET_DISK_pipe_handle (shutdown_pipe_handle,
                                GNUNET_DISK_PIPE_END_READ);
  GNUNET_assert (! GNUNET_DISK_handle_invalid (pr));
  /* consume the signal */
  GNUNET_DISK_file_read (pr, &c, sizeof (c));
  /* mark all active tasks as ready due to shutdown */
  GNUNET_SCHEDULER_shutdown ();
  shutdown_pipe_task =
    GNUNET_SCHEDULER_add_read_file (GNUNET_TIME_UNIT_FOREVER_REL,
                                    pr,
                                    &shutdown_pipe_cb,
                                    NULL);
}


/**
 * Cancel the task with the specified identifier.
 * The task must not yet have run. Only allowed to be called as long as the
 * scheduler is running, that is one of the following conditions is met:
 *
 * - #GNUNET_SCHEDULER_run has been called and has not returned yet
 * - #GNUNET_SCHEDULER_driver_init has been run and
 *   #GNUNET_SCHEDULER_driver_done has not been called yet
 *
 * @param task id of the task to cancel
 * @return original closure of the task
 */
void *
GNUNET_SCHEDULER_cancel (struct GNUNET_SCHEDULER_Task *task)
{
  enum GNUNET_SCHEDULER_Priority p;
  int is_fd_task;
  void *ret;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "canceling task %p\n",
       task);

  /* scheduler must be running */
  GNUNET_assert (NULL != scheduler_driver);
  GNUNET_assert ( (NULL != active_task) ||
      (GNUNET_NO == task->lifeness) );
  is_fd_task = (NULL != task->fds);
  if (is_fd_task)
  {
    int del_result = scheduler_driver->del (scheduler_driver->cls, task);
    if (GNUNET_OK != del_result)
    {
      LOG (GNUNET_ERROR_TYPE_ERROR,
           "driver could not delete task\n");
      GNUNET_assert (0);
    }
  }
  if (! task->in_ready_list)
  {
    if (is_fd_task)
    {
      GNUNET_CONTAINER_DLL_remove (pending_head,
                                   pending_tail,
                                   task);
    }
    else if (GNUNET_YES == task->on_shutdown)
    {
      GNUNET_CONTAINER_DLL_remove (shutdown_head,
                                   shutdown_tail,
                                   task);
    }
    else
    {
      GNUNET_CONTAINER_DLL_remove (pending_timeout_head,
                                   pending_timeout_tail,
                                   task);
      if (pending_timeout_last == task)
        pending_timeout_last = NULL;
    }
  }
  else
  {
    p = check_priority (task->priority);
    GNUNET_CONTAINER_DLL_remove (ready_head[p],
                                 ready_tail[p],
                                 task);
    ready_count--;
  }
  ret = task->callback_cls;
  destroy_task (task);
  return ret;
}


/**
 * Initialize backtrace data for task @a t
 *
 * @param t task to initialize
 */
static void
init_backtrace (struct GNUNET_SCHEDULER_Task *t)
{
#if EXECINFO
  void *backtrace_array[MAX_TRACE_DEPTH];

  t->num_backtrace_strings
    = backtrace (backtrace_array, MAX_TRACE_DEPTH);
  t->backtrace_strings =
      backtrace_symbols (backtrace_array,
       t->num_backtrace_strings);
  dump_backtrace (t);
#else
  (void) t;
#endif
}


/**
 * Continue the current execution with the given function.  This is
 * similar to the other "add" functions except that there is no delay
 * and the reason code can be specified.
 *
 * @param task main function of the task
 * @param task_cls closure for @a task
 * @param reason reason for task invocation
 * @param priority priority to use for the task
 */
void
GNUNET_SCHEDULER_add_with_reason_and_priority (GNUNET_SCHEDULER_TaskCallback task,
                                               void *task_cls,
                                               enum GNUNET_SCHEDULER_Reason reason,
                                               enum GNUNET_SCHEDULER_Priority priority)
{
  struct GNUNET_SCHEDULER_Task *t;

  GNUNET_assert (NULL != task);
  GNUNET_assert ((NULL != active_task) ||
                 (GNUNET_SCHEDULER_REASON_STARTUP == reason));
  t = GNUNET_new (struct GNUNET_SCHEDULER_Task);
  t->read_fd = -1;
  t->write_fd = -1;
  t->callback = task;
  t->callback_cls = task_cls;
#if PROFILE_DELAYS
  t->start_time = GNUNET_TIME_absolute_get ();
#endif
  t->reason = reason;
  t->priority = check_priority (priority);
  t->lifeness = current_lifeness;
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Adding continuation task %p\n",
       t);
  init_backtrace (t);
  queue_ready_task (t);
}


/**
 * Schedule a new task to be run at the specified time.  The task
 * will be scheduled for execution at time @a at.
 *
 * @param at time when the operation should run
 * @param priority priority to use for the task
 * @param task main function of the task
 * @param task_cls closure of @a task
 * @return unique task identifier for the job
 *         only valid until @a task is started!
 */
struct GNUNET_SCHEDULER_Task *
GNUNET_SCHEDULER_add_at_with_priority (struct GNUNET_TIME_Absolute at,
                                       enum GNUNET_SCHEDULER_Priority priority,
                                       GNUNET_SCHEDULER_TaskCallback task,
                                       void *task_cls)
{
  struct GNUNET_SCHEDULER_Task *t;
  struct GNUNET_SCHEDULER_Task *pos;
  struct GNUNET_SCHEDULER_Task *prev;

  GNUNET_assert (NULL != active_task);
  GNUNET_assert (NULL != task);
  t = GNUNET_new (struct GNUNET_SCHEDULER_Task);
  t->callback = task;
  t->callback_cls = task_cls;
  t->read_fd = -1;
  t->write_fd = -1;
#if PROFILE_DELAYS
  t->start_time = GNUNET_TIME_absolute_get ();
#endif
  t->timeout = at;
  t->priority = check_priority (priority);
  t->lifeness = current_lifeness;
  /* try tail first (optimization in case we are
   * appending to a long list of tasks with timeouts) */
  if ( (NULL == pending_timeout_head) ||
       (at.abs_value_us < pending_timeout_head->timeout.abs_value_us) )
  {
    GNUNET_CONTAINER_DLL_insert (pending_timeout_head,
                                 pending_timeout_tail,
                                 t);
  }
  else
  {
    /* first move from heuristic start backwards to before start time */
    prev = pending_timeout_last;
    while ( (NULL != prev) &&
            (prev->timeout.abs_value_us > t->timeout.abs_value_us) )
      prev = prev->prev;
    /* now, move from heuristic start (or head of list) forward to insertion point */
    if (NULL == prev)
      pos = pending_timeout_head;
    else
      pos = prev->next;
    while ((NULL != pos) && (pos->timeout.abs_value_us <= t->timeout.abs_value_us))
    {
      prev = pos;
      pos = pos->next;
    }
    GNUNET_CONTAINER_DLL_insert_after (pending_timeout_head,
                                       pending_timeout_tail,
                                       prev,
                                       t);
  }
  /* finally, update heuristic insertion point to last insertion... */
  pending_timeout_last = t;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Adding task %p\n",
       t);
  init_backtrace (t);
  return t;
}


/**
 * Schedule a new task to be run with a specified delay.  The task
 * will be scheduled for execution once the delay has expired.
 *
 * @param delay when should this operation time out?
 * @param priority priority to use for the task
 * @param task main function of the task
 * @param task_cls closure of @a task
 * @return unique task identifier for the job
 *         only valid until @a task is started!
 */
struct GNUNET_SCHEDULER_Task *
GNUNET_SCHEDULER_add_delayed_with_priority (struct GNUNET_TIME_Relative delay,
                                            enum GNUNET_SCHEDULER_Priority priority,
                                            GNUNET_SCHEDULER_TaskCallback task,
                                            void *task_cls)
{
  return GNUNET_SCHEDULER_add_at_with_priority (GNUNET_TIME_relative_to_absolute (delay),
                                                priority,
                                                task,
                                                task_cls);
}


/**
 * Schedule a new task to be run with a specified priority.
 *
 * @param prio how important is the new task?
 * @param task main function of the task
 * @param task_cls closure of @a task
 * @return unique task identifier for the job
 *         only valid until @a task is started!
 */
struct GNUNET_SCHEDULER_Task *
GNUNET_SCHEDULER_add_with_priority (enum GNUNET_SCHEDULER_Priority prio,
                                    GNUNET_SCHEDULER_TaskCallback task,
                                    void *task_cls)
{
  return GNUNET_SCHEDULER_add_delayed_with_priority (GNUNET_TIME_UNIT_ZERO,
                                                     prio,
                                                     task,
                                                     task_cls);
}


/**
 * Schedule a new task to be run at the specified time.  The task
 * will be scheduled for execution once specified time has been
 * reached. It will be run with the DEFAULT priority.
 *
 * @param at time at which this operation should run
 * @param task main function of the task
 * @param task_cls closure of @a task
 * @return unique task identifier for the job
 *         only valid until @a task is started!
 */
struct GNUNET_SCHEDULER_Task *
GNUNET_SCHEDULER_add_at (struct GNUNET_TIME_Absolute at,
                         GNUNET_SCHEDULER_TaskCallback task,
                         void *task_cls)
{
  return GNUNET_SCHEDULER_add_at_with_priority (at,
                                                GNUNET_SCHEDULER_PRIORITY_DEFAULT,
                                                task,
                                                task_cls);
}


/**
 * Schedule a new task to be run with a specified delay.  The task
 * will be scheduled for execution once the delay has expired. It
 * will be run with the DEFAULT priority.
 *
 * @param delay when should this operation time out?
 * @param task main function of the task
 * @param task_cls closure of @a task
 * @return unique task identifier for the job
 *         only valid until @a task is started!
 */
struct GNUNET_SCHEDULER_Task *
GNUNET_SCHEDULER_add_delayed (struct GNUNET_TIME_Relative delay,
                              GNUNET_SCHEDULER_TaskCallback task,
                              void *task_cls)
{
  return GNUNET_SCHEDULER_add_delayed_with_priority (delay,
                 GNUNET_SCHEDULER_PRIORITY_DEFAULT,
                 task,
                 task_cls);
}


/**
 * Schedule a new task to be run as soon as possible.  Note that this
 * does not guarantee that this will be the next task that is being
 * run, as other tasks with higher priority (or that are already ready
 * to run) might get to run first.  Just as with delays, clients must
 * not rely on any particular order of execution between tasks
 * scheduled concurrently.
 *
 * The task will be run with the DEFAULT priority.
 *
 * @param task main function of the task
 * @param task_cls closure of @a task
 * @return unique task identifier for the job
 *         only valid until @a task is started!
 */
struct GNUNET_SCHEDULER_Task *
GNUNET_SCHEDULER_add_now (GNUNET_SCHEDULER_TaskCallback task,
                          void *task_cls)
{
  return GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_ZERO,
                                       task,
                                       task_cls);
}


/**
 * Schedule a new task to be run on shutdown, that is when a CTRL-C
 * signal is received, or when #GNUNET_SCHEDULER_shutdown() is being
 * invoked.
 *
 * @param task main function of the task
 * @param task_cls closure of @a task
 * @return unique task identifier for the job
 *         only valid until @a task is started!
 */
struct GNUNET_SCHEDULER_Task *
GNUNET_SCHEDULER_add_shutdown (GNUNET_SCHEDULER_TaskCallback task,
                               void *task_cls)
{
  struct GNUNET_SCHEDULER_Task *t;

  GNUNET_assert (NULL != active_task);
  GNUNET_assert (NULL != task);
  t = GNUNET_new (struct GNUNET_SCHEDULER_Task);
  t->callback = task;
  t->callback_cls = task_cls;
  t->read_fd = -1;
  t->write_fd = -1;
#if PROFILE_DELAYS
  t->start_time = GNUNET_TIME_absolute_get ();
#endif
  t->timeout = GNUNET_TIME_UNIT_FOREVER_ABS;
  t->priority = GNUNET_SCHEDULER_PRIORITY_SHUTDOWN;
  t->on_shutdown = GNUNET_YES;
  t->lifeness = GNUNET_NO;
  GNUNET_CONTAINER_DLL_insert (shutdown_head,
                               shutdown_tail,
                               t);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Adding shutdown task %p\n",
       t);
  init_backtrace (t);
  return t;
}


/**
 * Schedule a new task to be run as soon as possible with the
 * (transitive) ignore-shutdown flag either explicitly set or
 * explicitly enabled.  This task (and all tasks created from it,
 * other than by another call to this function) will either count or
 * not count for the "lifeness" of the process.  This API is only
 * useful in a few special cases.
 *
 * @param lifeness #GNUNET_YES if the task counts for lifeness, #GNUNET_NO if not.
 * @param task main function of the task
 * @param task_cls closure of @a task
 * @return unique task identifier for the job
 *         only valid until @a task is started!
 */
struct GNUNET_SCHEDULER_Task *
GNUNET_SCHEDULER_add_now_with_lifeness (int lifeness,
                                        GNUNET_SCHEDULER_TaskCallback task,
                                        void *task_cls)
{
  struct GNUNET_SCHEDULER_Task *ret;

  ret = GNUNET_SCHEDULER_add_now (task, task_cls);
  ret->lifeness = lifeness;
  return ret;
}


#if DEBUG_FDS
/**
 * check a raw file descriptor and abort if it is bad (for debugging purposes)
 *
 * @param t the task related to the file descriptor
 * @param raw_fd the raw file descriptor to check
 */
void
check_fd (struct GNUNET_SCHEDULER_Task *t, int raw_fd)
{
  if (-1 != raw_fd)
  {
    int flags = fcntl (raw_fd, F_GETFD);

    if ((flags == -1) && (errno == EBADF))
    {
      LOG (GNUNET_ERROR_TYPE_ERROR,
           "Got invalid file descriptor %d!\n",
           raw_fd);
      init_backtrace (t);
      GNUNET_assert (0);
    }
  }
}
#endif


/**
 * Schedule a new task to be run with a specified delay or when any of
 * the specified file descriptor sets is ready.  The delay can be used
 * as a timeout on the socket(s) being ready.  The task will be
 * scheduled for execution once either the delay has expired or any of
 * the socket operations is ready.  This is the most general
 * function of the "add" family.  Note that the "prerequisite_task"
 * must be satisfied in addition to any of the other conditions.  In
 * other words, the task will be started when
 * <code>
 * (prerequisite-run)
 * && (delay-ready
 *     || any-rs-ready
 *     || any-ws-ready)
 * </code>
 *
 * @param delay how long should we wait?
 * @param priority priority to use
 * @param rfd file descriptor we want to read (can be -1)
 * @param wfd file descriptors we want to write (can be -1)
 * @param task main function of the task
 * @param task_cls closure of @a task
 * @return unique task identifier for the job
 *         only valid until @a task is started!
 */
#ifndef MINGW
static struct GNUNET_SCHEDULER_Task *
add_without_sets (struct GNUNET_TIME_Relative delay,
                  enum GNUNET_SCHEDULER_Priority priority,
                  const struct GNUNET_NETWORK_Handle *read_nh,
                  const struct GNUNET_NETWORK_Handle *write_nh,
                  const struct GNUNET_DISK_FileHandle *read_fh,
                  const struct GNUNET_DISK_FileHandle *write_fh,
                  GNUNET_SCHEDULER_TaskCallback task,
                  void *task_cls)
{
  struct GNUNET_SCHEDULER_Task *t;

  GNUNET_assert (NULL != active_task);
  GNUNET_assert (NULL != task);
  t = GNUNET_new (struct GNUNET_SCHEDULER_Task);
  init_fd_info (t,
                &read_nh,
                read_nh ? 1 : 0,
                &write_nh,
                write_nh ? 1 : 0,
                &read_fh,
                read_fh ? 1 : 0,
                &write_fh,
                write_fh ? 1 : 0);
  t->callback = task;
  t->callback_cls = task_cls;
#if DEBUG_FDS
  check_fd (t, NULL != read_nh ? GNUNET_NETWORK_get_fd (read_nh) : -1);
  check_fd (t, NULL != write_nh ? GNUNET_NETWORK_get_fd (write_nh) : -1);
  check_fd (t, NULL != read_fh ? read_fh->fd : -1);
  check_fd (t, NULL != write_fh ? write_fh->fd : -1);
#endif
#if PROFILE_DELAYS
  t->start_time = GNUNET_TIME_absolute_get ();
#endif
  t->timeout = GNUNET_TIME_relative_to_absolute (delay);
  t->priority = check_priority ((priority == GNUNET_SCHEDULER_PRIORITY_KEEP) ? current_priority : priority);
  t->lifeness = current_lifeness;
  GNUNET_CONTAINER_DLL_insert (pending_head,
                               pending_tail,
                               t);
  driver_add_multiple (t);
  max_priority_added = GNUNET_MAX (max_priority_added,
                                   t->priority);
  init_backtrace (t);
  return t;
}
#endif


/**
 * Schedule a new task to be run with a specified delay or when the
 * specified file descriptor is ready for reading.  The delay can be
 * used as a timeout on the socket being ready.  The task will be
 * scheduled for execution once either the delay has expired or the
 * socket operation is ready.  It will be run with the DEFAULT priority.
 * Only allowed to be called as long as the scheduler is running, that
 * is one of the following conditions is met:
 *
 * - #GNUNET_SCHEDULER_run has been called and has not returned yet
 * - #GNUNET_SCHEDULER_driver_init has been run and
 *   #GNUNET_SCHEDULER_driver_done has not been called yet
 *
 * @param delay when should this operation time out?
 * @param rfd read file-descriptor
 * @param task main function of the task
 * @param task_cls closure of @a task
 * @return unique task identifier for the job
 *         only valid until @a task is started!
 */
struct GNUNET_SCHEDULER_Task *
GNUNET_SCHEDULER_add_read_net (struct GNUNET_TIME_Relative delay,
                               struct GNUNET_NETWORK_Handle *rfd,
                               GNUNET_SCHEDULER_TaskCallback task,
                               void *task_cls)
{
  return GNUNET_SCHEDULER_add_read_net_with_priority (delay,
                  GNUNET_SCHEDULER_PRIORITY_DEFAULT,
                  rfd, task, task_cls);
}


/**
 * Schedule a new task to be run with a specified priority and to be
 * run after the specified delay or when the specified file descriptor
 * is ready for reading.  The delay can be used as a timeout on the
 * socket being ready.  The task will be scheduled for execution once
 * either the delay has expired or the socket operation is ready.  It
 * will be run with the DEFAULT priority.
 * Only allowed to be called as long as the scheduler is running, that
 * is one of the following conditions is met:
 *
 * - #GNUNET_SCHEDULER_run has been called and has not returned yet
 * - #GNUNET_SCHEDULER_driver_init has been run and
 *   #GNUNET_SCHEDULER_driver_done has not been called yet
 *
 * @param delay when should this operation time out?
 * @param priority priority to use for the task
 * @param rfd read file-descriptor
 * @param task main function of the task
 * @param task_cls closure of @a task
 * @return unique task identifier for the job
 *         only valid until @a task is started!
 */
struct GNUNET_SCHEDULER_Task *
GNUNET_SCHEDULER_add_read_net_with_priority (struct GNUNET_TIME_Relative delay,
               enum GNUNET_SCHEDULER_Priority priority,
               struct GNUNET_NETWORK_Handle *rfd,
               GNUNET_SCHEDULER_TaskCallback task,
                                             void *task_cls)
{
  return GNUNET_SCHEDULER_add_net_with_priority (delay, priority,
                                                 rfd,
                                                 GNUNET_YES,
                                                 GNUNET_NO,
                                                 task, task_cls);
}


/**
 * Schedule a new task to be run with a specified delay or when the
 * specified file descriptor is ready for writing.  The delay can be
 * used as a timeout on the socket being ready.  The task will be
 * scheduled for execution once either the delay has expired or the
 * socket operation is ready.  It will be run with the priority of
 * the calling task.
 * Only allowed to be called as long as the scheduler is running, that
 * is one of the following conditions is met:
 *
 * - #GNUNET_SCHEDULER_run has been called and has not returned yet
 * - #GNUNET_SCHEDULER_driver_init has been run and
 *   #GNUNET_SCHEDULER_driver_done has not been called yet
 *
 * @param delay when should this operation time out?
 * @param wfd write file-descriptor
 * @param task main function of the task
 * @param task_cls closure of @a task
 * @return unique task identifier for the job
 *         only valid until @a task is started!
 */
struct GNUNET_SCHEDULER_Task *
GNUNET_SCHEDULER_add_write_net (struct GNUNET_TIME_Relative delay,
                                struct GNUNET_NETWORK_Handle *wfd,
                                GNUNET_SCHEDULER_TaskCallback task,
                                void *task_cls)
{
  return GNUNET_SCHEDULER_add_net_with_priority (delay,
                                                 GNUNET_SCHEDULER_PRIORITY_DEFAULT,
                                                 wfd,
                                                 GNUNET_NO, GNUNET_YES,
                                                 task, task_cls);
}

/**
 * Schedule a new task to be run with a specified delay or when the
 * specified file descriptor is ready.  The delay can be
 * used as a timeout on the socket being ready.  The task will be
 * scheduled for execution once either the delay has expired or the
 * socket operation is ready.
 * Only allowed to be called as long as the scheduler is running, that
 * is one of the following conditions is met:
 *
 * - #GNUNET_SCHEDULER_run has been called and has not returned yet
 * - #GNUNET_SCHEDULER_driver_init has been run and
 *   #GNUNET_SCHEDULER_driver_done has not been called yet
 *
 * @param delay when should this operation time out?
 * @param priority priority of the task
 * @param fd file-descriptor
 * @param on_read whether to poll the file-descriptor for readability
 * @param on_write whether to poll the file-descriptor for writability
 * @param task main function of the task
 * @param task_cls closure of task
 * @return unique task identifier for the job
 *         only valid until "task" is started!
 */
struct GNUNET_SCHEDULER_Task *
GNUNET_SCHEDULER_add_net_with_priority  (struct GNUNET_TIME_Relative delay,
                                         enum GNUNET_SCHEDULER_Priority priority,
                                         struct GNUNET_NETWORK_Handle *fd,
                                         int on_read,
                                         int on_write,
                                         GNUNET_SCHEDULER_TaskCallback task,
                                         void *task_cls)
{
  /* scheduler must be running */
  GNUNET_assert (NULL != scheduler_driver);

#if MINGW
  struct GNUNET_NETWORK_FDSet *s;
  struct GNUNET_SCHEDULER_Task * ret;

  GNUNET_assert (NULL != fd);
  s = GNUNET_NETWORK_fdset_create ();
  GNUNET_NETWORK_fdset_set (s, fd);
  ret = GNUNET_SCHEDULER_add_select (
      priority, delay,
      on_read  ? s : NULL,
      on_write ? s : NULL,
      task, task_cls);
  GNUNET_NETWORK_fdset_destroy (s);
  return ret;
#else
  GNUNET_assert (on_read || on_write);
  GNUNET_assert (GNUNET_NETWORK_get_fd (fd) >= 0);
  return add_without_sets (delay, priority,
                           on_read  ? fd : NULL,
                           on_write ? fd : NULL,
                           NULL,
                           NULL,
                           task, task_cls);
#endif
}


/**
 * Schedule a new task to be run with a specified delay or when the
 * specified file descriptor is ready for reading.  The delay can be
 * used as a timeout on the socket being ready.  The task will be
 * scheduled for execution once either the delay has expired or the
 * socket operation is ready. It will be run with the DEFAULT priority.
 * Only allowed to be called as long as the scheduler is running, that
 * is one of the following conditions is met:
 *
 * - #GNUNET_SCHEDULER_run has been called and has not returned yet
 * - #GNUNET_SCHEDULER_driver_init has been run and
 *   #GNUNET_SCHEDULER_driver_done has not been called yet
 *
 * @param delay when should this operation time out?
 * @param rfd read file-descriptor
 * @param task main function of the task
 * @param task_cls closure of @a task
 * @return unique task identifier for the job
 *         only valid until @a task is started!
 */
struct GNUNET_SCHEDULER_Task *
GNUNET_SCHEDULER_add_read_file (struct GNUNET_TIME_Relative delay,
                                const struct GNUNET_DISK_FileHandle *rfd,
                                GNUNET_SCHEDULER_TaskCallback task, void *task_cls)
{
  return GNUNET_SCHEDULER_add_file_with_priority (
      delay, GNUNET_SCHEDULER_PRIORITY_DEFAULT,
      rfd, GNUNET_YES, GNUNET_NO,
      task, task_cls);
}


/**
 * Schedule a new task to be run with a specified delay or when the
 * specified file descriptor is ready for writing.  The delay can be
 * used as a timeout on the socket being ready.  The task will be
 * scheduled for execution once either the delay has expired or the
 * socket operation is ready. It will be run with the DEFAULT priority.
 * Only allowed to be called as long as the scheduler is running, that
 * is one of the following conditions is met:
 *
 * - #GNUNET_SCHEDULER_run has been called and has not returned yet
 * - #GNUNET_SCHEDULER_driver_init has been run and
 *   #GNUNET_SCHEDULER_driver_done has not been called yet
 *
 * @param delay when should this operation time out?
 * @param wfd write file-descriptor
 * @param task main function of the task
 * @param task_cls closure of @a task
 * @return unique task identifier for the job
 *         only valid until @a task is started!
 */
struct GNUNET_SCHEDULER_Task *
GNUNET_SCHEDULER_add_write_file (struct GNUNET_TIME_Relative delay,
                                 const struct GNUNET_DISK_FileHandle *wfd,
                                 GNUNET_SCHEDULER_TaskCallback task, void *task_cls)
{
  return GNUNET_SCHEDULER_add_file_with_priority (
      delay, GNUNET_SCHEDULER_PRIORITY_DEFAULT,
      wfd, GNUNET_NO, GNUNET_YES,
      task, task_cls);
}


/**
 * Schedule a new task to be run with a specified delay or when the
 * specified file descriptor is ready.  The delay can be
 * used as a timeout on the socket being ready.  The task will be
 * scheduled for execution once either the delay has expired or the
 * socket operation is ready.
 * Only allowed to be called as long as the scheduler is running, that
 * is one of the following conditions is met:
 *
 * - #GNUNET_SCHEDULER_run has been called and has not returned yet
 * - #GNUNET_SCHEDULER_driver_init has been run and
 *   #GNUNET_SCHEDULER_driver_done has not been called yet
 *
 * @param delay when should this operation time out?
 * @param priority priority of the task
 * @param fd file-descriptor
 * @param on_read whether to poll the file-descriptor for readability
 * @param on_write whether to poll the file-descriptor for writability
 * @param task main function of the task
 * @param task_cls closure of @a task
 * @return unique task identifier for the job
 *         only valid until @a task is started!
 */
struct GNUNET_SCHEDULER_Task *
GNUNET_SCHEDULER_add_file_with_priority (struct GNUNET_TIME_Relative delay,
                                         enum GNUNET_SCHEDULER_Priority priority,
                                         const struct GNUNET_DISK_FileHandle *fd,
                                         int on_read, int on_write,
                                         GNUNET_SCHEDULER_TaskCallback task, void *task_cls)
{
  /* scheduler must be running */
  GNUNET_assert (NULL != scheduler_driver);

#if MINGW
  struct GNUNET_NETWORK_FDSet *s;
  struct GNUNET_SCHEDULER_Task * ret;

  GNUNET_assert (NULL != fd);
  s = GNUNET_NETWORK_fdset_create ();
  GNUNET_NETWORK_fdset_handle_set (s, fd);
  ret = GNUNET_SCHEDULER_add_select (
      priority, delay,
      on_read  ? s : NULL,
      on_write ? s : NULL,
      task, task_cls);
  GNUNET_NETWORK_fdset_destroy (s);
  return ret;
#else
  GNUNET_assert (on_read || on_write);
  GNUNET_assert (fd->fd >= 0);
  return add_without_sets (delay, priority,
                           NULL,
                           NULL,
                           on_read ? fd : NULL,
                           on_write ? fd : NULL,
                           task, task_cls);
#endif
}


void
extract_handles (const struct GNUNET_NETWORK_FDSet *fdset,
                 const struct GNUNET_NETWORK_Handle ***ntarget,
                 unsigned int *extracted_nhandles,
                 const struct GNUNET_DISK_FileHandle ***ftarget,
                 unsigned int *extracted_fhandles)
{
  // FIXME: this implementation only works for unix, for WIN32 the file handles
  // in fdset must be handled separately
  const struct GNUNET_NETWORK_Handle **nhandles;
  const struct GNUNET_DISK_FileHandle **fhandles;
  unsigned int nhandles_len;
  unsigned int fhandles_len;

  nhandles = NULL;
  fhandles = NULL;
  nhandles_len = 0;
  fhandles_len = 0;
  for (int sock = 0; sock != fdset->nsds; ++sock)
  {
    if (GNUNET_YES == GNUNET_NETWORK_fdset_test_native (fdset, sock))
    {
      struct GNUNET_NETWORK_Handle *nhandle;
      struct GNUNET_DISK_FileHandle *fhandle;

      nhandle = GNUNET_NETWORK_socket_box_native (sock);
      if (NULL != nhandle)
      {
        GNUNET_array_append (nhandles, nhandles_len, nhandle);
      }
      else
      {
        fhandle = GNUNET_DISK_get_handle_from_int_fd (sock);
        if (NULL != fhandle)
        {
          GNUNET_array_append (fhandles, fhandles_len, fhandle);
        }
        else
        {
          GNUNET_assert (0);
        }
      }
    }
  }
  *ntarget = nhandles_len > 0 ? nhandles : NULL;
  *ftarget = fhandles_len > 0 ? fhandles : NULL;
  *extracted_nhandles = nhandles_len;
  *extracted_fhandles = fhandles_len;
}


/**
 * Schedule a new task to be run with a specified delay or when any of
 * the specified file descriptor sets is ready.  The delay can be used
 * as a timeout on the socket(s) being ready.  The task will be
 * scheduled for execution once either the delay has expired or any of
 * the socket operations is ready.  This is the most general
 * function of the "add" family.  Note that the "prerequisite_task"
 * must be satisfied in addition to any of the other conditions.  In
 * other words, the task will be started when
 * <code>
 * (prerequisite-run)
 * && (delay-ready
 *     || any-rs-ready
 *     || any-ws-ready) )
 * </code>
 * Only allowed to be called as long as the scheduler is running, that
 * is one of the following conditions is met:
 *
 * - #GNUNET_SCHEDULER_run has been called and has not returned yet
 * - #GNUNET_SCHEDULER_driver_init has been run and
 *   #GNUNET_SCHEDULER_driver_done has not been called yet
 *
 * @param prio how important is this task?
 * @param delay how long should we wait?
 * @param rs set of file descriptors we want to read (can be NULL)
 * @param ws set of file descriptors we want to write (can be NULL)
 * @param task main function of the task
 * @param task_cls closure of @a task
 * @return unique task identifier for the job
 *         only valid until @a task is started!
 */
struct GNUNET_SCHEDULER_Task *
GNUNET_SCHEDULER_add_select (enum GNUNET_SCHEDULER_Priority prio,
                             struct GNUNET_TIME_Relative delay,
                             const struct GNUNET_NETWORK_FDSet *rs,
                             const struct GNUNET_NETWORK_FDSet *ws,
                             GNUNET_SCHEDULER_TaskCallback task,
                             void *task_cls)
{
  struct GNUNET_SCHEDULER_Task *t;
  const struct GNUNET_NETWORK_Handle **read_nhandles = NULL;
  const struct GNUNET_NETWORK_Handle **write_nhandles = NULL;
  const struct GNUNET_DISK_FileHandle **read_fhandles = NULL;
  const struct GNUNET_DISK_FileHandle **write_fhandles = NULL;
  unsigned int read_nhandles_len = 0;
  unsigned int write_nhandles_len = 0;
  unsigned int read_fhandles_len = 0;
  unsigned int write_fhandles_len = 0;

  /* scheduler must be running */
  GNUNET_assert (NULL != scheduler_driver);
  GNUNET_assert (NULL != active_task);
  GNUNET_assert (NULL != task);
  int no_rs = (NULL == rs);
  int no_ws = (NULL == ws);
  int empty_rs = (NULL != rs) && (0 == rs->nsds);
  int empty_ws = (NULL != ws) && (0 == ws->nsds);
  int no_fds = (no_rs && no_ws) ||
               (empty_rs && empty_ws) ||
               (no_rs && empty_ws) ||
               (no_ws && empty_rs);
  if (! no_fds)
  {
    if (NULL != rs)
    {
      extract_handles (rs,
                       &read_nhandles,
                       &read_nhandles_len,
                       &read_fhandles,
                       &read_fhandles_len);
    }
    if (NULL != ws)
    {
      extract_handles (ws,
                       &write_nhandles,
                       &write_nhandles_len,
                       &write_fhandles,
                       &write_fhandles_len);
    }
  }
  /**
   * here we consider the case that a GNUNET_NETWORK_FDSet might be empty
   * although its maximum FD number (nsds) is greater than 0. We handle
   * this case gracefully because some libraries such as libmicrohttpd
   * only provide a hint what the maximum FD number in an FD set might be
   * and not the exact FD number (see e.g. gnunet-rest-service.c)
   */
  int no_fds_extracted = (0 == read_nhandles_len) &&
                         (0 == read_fhandles_len) &&
                         (0 == write_nhandles_len) &&
                         (0 == write_fhandles_len);
  if (no_fds || no_fds_extracted)
    return GNUNET_SCHEDULER_add_delayed_with_priority (delay,
                                                       prio,
                                                       task,
                                                       task_cls);
  t = GNUNET_new (struct GNUNET_SCHEDULER_Task);
  init_fd_info (t,
                read_nhandles,
                read_nhandles_len,
                write_nhandles,
                write_nhandles_len,
                read_fhandles,
                read_fhandles_len,
                write_fhandles,
                write_fhandles_len);
  t->callback = task;
  t->callback_cls = task_cls;
  t->own_handles = GNUNET_YES;
  /* free the arrays of pointers to network / file handles, the actual
   * handles will be freed in destroy_task */
  GNUNET_array_grow (read_nhandles, read_nhandles_len, 0);
  GNUNET_array_grow (write_nhandles, write_nhandles_len, 0);
  GNUNET_array_grow (read_fhandles, read_fhandles_len, 0);
  GNUNET_array_grow (write_fhandles, write_fhandles_len, 0);
#if PROFILE_DELAYS
  t->start_time = GNUNET_TIME_absolute_get ();
#endif
  t->timeout = GNUNET_TIME_relative_to_absolute (delay);
  t->priority =
      check_priority ((prio ==
                       GNUNET_SCHEDULER_PRIORITY_KEEP) ? current_priority :
                      prio);
  t->lifeness = current_lifeness;
  GNUNET_CONTAINER_DLL_insert (pending_head,
                               pending_tail,
                               t);
  driver_add_multiple (t);
  max_priority_added = GNUNET_MAX (max_priority_added,
           t->priority);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Adding task %p\n",
       t);
  init_backtrace (t);
  return t;
}


/**
 * Function used by event-loop implementations to signal the scheduler
 * that a particular @a task is ready due to an event specified in the
 * et field of @a fdi.
 *
 * This function will then queue the task to notify the application
 * that the task is ready (with the respective priority).
 *
 * @param task the task that is ready
 * @param fdi information about the related FD
 */
void
GNUNET_SCHEDULER_task_ready (struct GNUNET_SCHEDULER_Task *task,
                             struct GNUNET_SCHEDULER_FdInfo *fdi)
{
  enum GNUNET_SCHEDULER_Reason reason;

  reason = task->reason;
  if ( (0 == (reason & GNUNET_SCHEDULER_REASON_READ_READY)) &&
       (0 != (GNUNET_SCHEDULER_ET_IN & fdi->et)) )
    reason |= GNUNET_SCHEDULER_REASON_READ_READY;
  if ( (0 == (reason & GNUNET_SCHEDULER_REASON_WRITE_READY)) &&
       (0 != (GNUNET_SCHEDULER_ET_OUT & fdi->et)) )
    reason |= GNUNET_SCHEDULER_REASON_WRITE_READY;
  reason |= GNUNET_SCHEDULER_REASON_PREREQ_DONE;
  task->reason = reason;
  if (GNUNET_NO == task->in_ready_list)
  {
    GNUNET_CONTAINER_DLL_remove (pending_head,
                                 pending_tail,
                                 task);
    queue_ready_task (task);
  }
}


/**
 * Function called by external event loop implementations to tell the
 * scheduler to run some of the tasks that are ready. Must be called
 * only after #GNUNET_SCHEDULER_driver_init has been called and before
 * #GNUNET_SCHEDULER_driver_done is called.
 * This function may return even though there are tasks left to run
 * just to give other tasks a chance as well.  If we return #GNUNET_YES,
 * the event loop implementation should call this function again as
 * soon as possible, while if we return #GNUNET_NO it must block until
 * either the operating system has more work (the scheduler has no more
 * work to do right now) or the timeout set by the scheduler (using the
 * set_wakeup callback) is reached.
 *
 * @param sh scheduler handle that was returned by
 *        #GNUNET_SCHEDULER_driver_init
 * @return #GNUNET_YES if there are more tasks that are ready,
 *         and thus we would like to run more (yield to avoid
 *         blocking other activities for too long) #GNUNET_NO
 *         if we are done running tasks (yield to block)
 */
int
GNUNET_SCHEDULER_do_work (struct GNUNET_SCHEDULER_Handle *sh)
{
  enum GNUNET_SCHEDULER_Priority p;
  struct GNUNET_SCHEDULER_Task *pos;
  struct GNUNET_TIME_Absolute now;

  /* check for tasks that reached the timeout! */
  now = GNUNET_TIME_absolute_get ();
  pos = pending_timeout_head;
  while (NULL != pos)
  {
    struct GNUNET_SCHEDULER_Task *next = pos->next;
    if (now.abs_value_us >= pos->timeout.abs_value_us)
      pos->reason |= GNUNET_SCHEDULER_REASON_TIMEOUT;
    if (0 == pos->reason)
      break;
    GNUNET_CONTAINER_DLL_remove (pending_timeout_head,
                                 pending_timeout_tail,
                                 pos);
    if (pending_timeout_last == pos)
      pending_timeout_last = NULL;
    queue_ready_task (pos);
    pos = next;
  }
  pos = pending_head;
  while (NULL != pos)
  {
    struct GNUNET_SCHEDULER_Task *next = pos->next;
    if (now.abs_value_us >= pos->timeout.abs_value_us)
    {
      pos->reason |= GNUNET_SCHEDULER_REASON_TIMEOUT;
      GNUNET_CONTAINER_DLL_remove (pending_head,
                                   pending_tail,
                                   pos);
      queue_ready_task (pos);
    }
    pos = next;
  }

  if (0 == ready_count)
  {
    struct GNUNET_TIME_Absolute timeout = get_timeout ();

    if (timeout.abs_value_us > now.abs_value_us)
    {
      /**
       * The driver called this function before the current timeout was
       * reached (and no FD tasks are ready). This can happen in the
       * rare case when the system time is changed while the driver is
       * waiting for the timeout, so we handle this gracefully. It might
       * also be a programming error in the driver though.
       */
      LOG (GNUNET_ERROR_TYPE_DEBUG,
           "GNUNET_SCHEDULER_do_work did not find any ready "
           "tasks and timeout has not been reached yet.\n");
      return GNUNET_NO;
    }
    /**
     * the current timeout was reached but no ready tasks were found,
     * internal scheduler error!
     */
    GNUNET_assert (0);
  }

  /* find out which task priority level we are going to
     process this time */
  max_priority_added = GNUNET_SCHEDULER_PRIORITY_KEEP;
  GNUNET_assert (NULL == ready_head[GNUNET_SCHEDULER_PRIORITY_KEEP]);
  /* yes, p>0 is correct, 0 is "KEEP" which should
   * always be an empty queue (see assertion)! */
  for (p = GNUNET_SCHEDULER_PRIORITY_COUNT - 1; p > 0; p--)
  {
    pos = ready_head[p];
    if (NULL != pos)
      break;
  }
  GNUNET_assert (NULL != pos);        /* ready_count wrong? */

  /* process all tasks at this priority level, then yield */
  while (NULL != (pos = ready_head[p]))
  {
    GNUNET_CONTAINER_DLL_remove (ready_head[p],
         ready_tail[p],
         pos);
    ready_count--;
    current_priority = pos->priority;
    current_lifeness = pos->lifeness;
    active_task = pos;
#if PROFILE_DELAYS
    if (GNUNET_TIME_absolute_get_duration (pos->start_time).rel_value_us >
        DELAY_THRESHOLD.rel_value_us)
    {
      LOG (GNUNET_ERROR_TYPE_DEBUG,
           "Task %p took %s to be scheduled\n",
           pos,
           GNUNET_STRINGS_relative_time_to_string (GNUNET_TIME_absolute_get_duration (pos->start_time),
                                                   GNUNET_YES));
    }
#endif
    tc.reason = pos->reason;
    GNUNET_NETWORK_fdset_zero (sh->rs);
    GNUNET_NETWORK_fdset_zero (sh->ws);
    // FIXME: do we have to remove FdInfos from fds if they are not ready?
    tc.fds_len = pos->fds_len;
    tc.fds = pos->fds;
    for (unsigned int i = 0; i != pos->fds_len; ++i)
    {
      struct GNUNET_SCHEDULER_FdInfo *fdi = &pos->fds[i];
      if (0 != (GNUNET_SCHEDULER_ET_IN & fdi->et))
      {
        GNUNET_NETWORK_fdset_set_native (sh->rs,
                                         fdi->sock);
      }
      if (0 != (GNUNET_SCHEDULER_ET_OUT & fdi->et))
      {
        GNUNET_NETWORK_fdset_set_native (sh->ws,
                                         fdi->sock);
      }
    }
    tc.read_ready = sh->rs;
    tc.write_ready = sh->ws;
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Running task %p\n",
         pos);
    GNUNET_assert (NULL != pos->callback);
    pos->callback (pos->callback_cls);
    if (NULL != pos->fds)
    {
      int del_result = scheduler_driver->del (scheduler_driver->cls, pos);
      if (GNUNET_OK != del_result)
      {
        LOG (GNUNET_ERROR_TYPE_ERROR,
           "driver could not delete task %p\n", pos);
        GNUNET_assert (0);
      }
    }
    active_task = NULL;
    dump_backtrace (pos);
    destroy_task (pos);
  }
  shutdown_if_no_lifeness ();
  if (0 == ready_count)
  {
    scheduler_driver->set_wakeup (scheduler_driver->cls,
                                  get_timeout ());
    return GNUNET_NO;
  }
  scheduler_driver->set_wakeup (scheduler_driver->cls,
                                GNUNET_TIME_absolute_get ());
  return GNUNET_YES;
}


/**
 * Function called by external event loop implementations to initialize
 * the scheduler. An external implementation has to provide @a driver
 * which contains callbacks for the scheduler (see definition of struct
 * #GNUNET_SCHEDULER_Driver). The callbacks are used to instruct the
 * external implementation to watch for events. If it detects any of
 * those events it is expected to call #GNUNET_SCHEDULER_do_work to let
 * the scheduler handle it. If an event is related to a specific task
 * (e.g. the scheduler gave instructions to watch a file descriptor),
 * the external implementation is expected to mark that task ready
 * before by calling #GNUNET_SCHEDULER_task_ready.

 * This function has to be called before any tasks are scheduled and
 * before GNUNET_SCHEDULER_do_work is called for the first time. It
 * allocates resources that have to be freed again by calling
 * #GNUNET_SCHEDULER_driver_done.
 *
 * This function installs the same signal handlers as
 * #GNUNET_SCHEDULER_run. This means SIGTERM (and other similar signals)
 * will induce a call to #GNUNET_SCHEDULER_shutdown during the next
 * call to #GNUNET_SCHEDULER_do_work. As a result, SIGTERM causes all
 * active tasks to be scheduled with reason
 * #GNUNET_SCHEDULER_REASON_SHUTDOWN. (However, tasks added afterwards
 * will execute normally!). Note that any particular signal will only
 * shut down one scheduler; applications should always only create a
 * single scheduler.
 *
 * @param driver to use for the event loop
 * @return handle to be passed to #GNUNET_SCHEDULER_do_work and
 *         #GNUNET_SCHEDULER_driver_done
 */
struct GNUNET_SCHEDULER_Handle *
GNUNET_SCHEDULER_driver_init (const struct GNUNET_SCHEDULER_Driver *driver)
{
  struct GNUNET_SCHEDULER_Handle *sh;
  struct GNUNET_SCHEDULER_Task tsk;
  const struct GNUNET_DISK_FileHandle *pr;

  /* general set-up */
  GNUNET_assert (NULL == active_task);
  GNUNET_assert (NULL == shutdown_pipe_handle);
  sh = GNUNET_new (struct GNUNET_SCHEDULER_Handle);
  shutdown_pipe_handle = GNUNET_DISK_pipe (GNUNET_NO,
                                           GNUNET_NO,
                                           GNUNET_NO,
                                           GNUNET_NO);
  GNUNET_assert (NULL != shutdown_pipe_handle);
  pr = GNUNET_DISK_pipe_handle (shutdown_pipe_handle,
                                GNUNET_DISK_PIPE_END_READ);
  my_pid = getpid ();
  scheduler_driver = driver;

  /* install signal handlers */
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Registering signal handlers\n");
  sh->shc_int = GNUNET_SIGNAL_handler_install (SIGINT,
                                               &sighandler_shutdown);
  sh->shc_term = GNUNET_SIGNAL_handler_install (SIGTERM,
                                                &sighandler_shutdown);
#if (SIGTERM != GNUNET_TERM_SIG)
  sh->shc_gterm = GNUNET_SIGNAL_handler_install (GNUNET_TERM_SIG,
                                                 &sighandler_shutdown);
#endif
#ifndef MINGW
  sh->shc_pipe = GNUNET_SIGNAL_handler_install (SIGPIPE,
                                                &sighandler_pipe);
  sh->shc_quit = GNUNET_SIGNAL_handler_install (SIGQUIT,
                                                &sighandler_shutdown);
  sh->shc_hup = GNUNET_SIGNAL_handler_install (SIGHUP,
                                               &sighandler_shutdown);
#endif

  /* Setup initial tasks */
  current_priority = GNUNET_SCHEDULER_PRIORITY_DEFAULT;
  current_lifeness = GNUNET_NO;
  memset (&tsk,
          0,
          sizeof (tsk));
  active_task = &tsk;
  install_parent_control_task =
    GNUNET_SCHEDULER_add_now (&install_parent_control_handler,
                              NULL);
  shutdown_pipe_task =
    GNUNET_SCHEDULER_add_read_file (GNUNET_TIME_UNIT_FOREVER_REL,
                                    pr,
                                    &shutdown_pipe_cb,
                                    NULL);
  current_lifeness = GNUNET_YES;
  active_task = NULL;
  scheduler_driver->set_wakeup (scheduler_driver->cls,
                                get_timeout ());
  /* begin main event loop */
  sh->rs = GNUNET_NETWORK_fdset_create ();
  sh->ws = GNUNET_NETWORK_fdset_create ();
  GNUNET_NETWORK_fdset_handle_set (sh->rs, pr);
  return sh;
}


/**
 * Counter-part of #GNUNET_SCHEDULER_driver_init. Has to be called
 * by external event loop implementations after the scheduler has
 * shut down. This is the case if both of the following conditions
 * are met:
 *
 * - all tasks the scheduler has added through the driver's add
 *   callback have been removed again through the driver's del
 *   callback
 * - the timeout the scheduler has set through the driver's
 *   add_wakeup callback is FOREVER
 *
 * @param sh the handle returned by #GNUNET_SCHEDULER_driver_init
 */
void
GNUNET_SCHEDULER_driver_done (struct GNUNET_SCHEDULER_Handle *sh)
{
  GNUNET_assert (NULL == pending_head);
  GNUNET_assert (NULL == pending_timeout_head);
  GNUNET_assert (NULL == shutdown_head);
  for (int i = 0; i != GNUNET_SCHEDULER_PRIORITY_COUNT; ++i)
  {
    GNUNET_assert (NULL == ready_head[i]);
  }
  GNUNET_NETWORK_fdset_destroy (sh->rs);
  GNUNET_NETWORK_fdset_destroy (sh->ws);

  /* uninstall signal handlers */
  GNUNET_SIGNAL_handler_uninstall (sh->shc_int);
  GNUNET_SIGNAL_handler_uninstall (sh->shc_term);
#if (SIGTERM != GNUNET_TERM_SIG)
  GNUNET_SIGNAL_handler_uninstall (sh->shc_gterm);
#endif
#ifndef MINGW
  GNUNET_SIGNAL_handler_uninstall (sh->shc_pipe);
  GNUNET_SIGNAL_handler_uninstall (sh->shc_quit);
  GNUNET_SIGNAL_handler_uninstall (sh->shc_hup);
#endif
  GNUNET_DISK_pipe_close (shutdown_pipe_handle);
  shutdown_pipe_handle = NULL;
  scheduler_driver = NULL;
  GNUNET_free (sh);
}


static int
select_loop (struct GNUNET_SCHEDULER_Handle *sh,
             struct DriverContext *context)
{
  struct GNUNET_NETWORK_FDSet *rs;
  struct GNUNET_NETWORK_FDSet *ws;
  int select_result;

  GNUNET_assert (NULL != context);
  rs = GNUNET_NETWORK_fdset_create ();
  ws = GNUNET_NETWORK_fdset_create ();
  while ( (NULL != context->scheduled_head) ||
          (GNUNET_TIME_UNIT_FOREVER_ABS.abs_value_us != context->timeout.abs_value_us) )
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "select timeout = %s\n",
         GNUNET_STRINGS_absolute_time_to_string (context->timeout));

    GNUNET_NETWORK_fdset_zero (rs);
    GNUNET_NETWORK_fdset_zero (ws);

    for (struct Scheduled *pos = context->scheduled_head;
         NULL != pos;
         pos = pos->next)
    {
      if (0 != (GNUNET_SCHEDULER_ET_IN & pos->et))
      {
        GNUNET_NETWORK_fdset_set_native (rs, pos->fdi->sock);
      }
      if (0 != (GNUNET_SCHEDULER_ET_OUT & pos->et))
      {
        GNUNET_NETWORK_fdset_set_native (ws, pos->fdi->sock);
      }
    }
    struct GNUNET_TIME_Relative time_remaining =
      GNUNET_TIME_absolute_get_remaining (context->timeout);
    if (NULL == scheduler_select)
    {
      select_result = GNUNET_NETWORK_socket_select (rs,
                                                    ws,
                                                    NULL,
                                                    time_remaining);
    }
    else
    {
      select_result = scheduler_select (scheduler_select_cls,
                                        rs,
                                        ws,
                                        NULL,
                                        time_remaining);
    }
    if (select_result == GNUNET_SYSERR)
    {
      if (errno == EINTR)
        continue;

      LOG_STRERROR (GNUNET_ERROR_TYPE_ERROR,
                    "select");
#ifndef MINGW
#if USE_LSOF
      char lsof[512];

      snprintf (lsof,
                sizeof (lsof),
                "lsof -p %d",
                getpid ());
      (void) close (1);
      (void) dup2 (2, 1);
      if (0 != system (lsof))
        LOG_STRERROR (GNUNET_ERROR_TYPE_WARNING,
                      "system");
#endif
#endif
#if DEBUG_FDS
      for (struct Scheduled *s = context->scheduled_head;
           NULL != s;
           s = s->next)
      {
        int flags = fcntl (s->fdi->sock,
                           F_GETFD);

        if ( (flags == -1) &&
             (EBADF == errno) )
        {
          LOG (GNUNET_ERROR_TYPE_ERROR,
               "Got invalid file descriptor %d!\n",
               s->fdi->sock);
#if EXECINFO
          dump_backtrace (s->task);
#endif
        }
      }
#endif
      GNUNET_assert (0);
      GNUNET_NETWORK_fdset_destroy (rs);
      GNUNET_NETWORK_fdset_destroy (ws);
      return GNUNET_SYSERR;
    }
    if (select_result > 0)
    {
      for (struct Scheduled *pos = context->scheduled_head;
           NULL != pos;
           pos = pos->next)
      {
        int is_ready = GNUNET_NO;

        if (0 != (GNUNET_SCHEDULER_ET_IN & pos->et) &&
            GNUNET_YES ==
            GNUNET_NETWORK_fdset_test_native (rs,
                                              pos->fdi->sock))
        {
          pos->fdi->et |= GNUNET_SCHEDULER_ET_IN;
          is_ready = GNUNET_YES;
        }
        if (0 != (GNUNET_SCHEDULER_ET_OUT & pos->et) &&
            GNUNET_YES ==
            GNUNET_NETWORK_fdset_test_native (ws,
                                              pos->fdi->sock))
        {
          pos->fdi->et |= GNUNET_SCHEDULER_ET_OUT;
          is_ready = GNUNET_YES;
        }
        if (GNUNET_YES == is_ready)
        {
          GNUNET_SCHEDULER_task_ready (pos->task,
                                       pos->fdi);
        }
      }
    }
    if (GNUNET_YES == GNUNET_SCHEDULER_do_work (sh))
    {
      LOG (GNUNET_ERROR_TYPE_DEBUG,
           "scheduler has more tasks ready!\n");
    }
  }
  GNUNET_NETWORK_fdset_destroy (rs);
  GNUNET_NETWORK_fdset_destroy (ws);
  return GNUNET_OK;
}


static int
select_add (void *cls,
            struct GNUNET_SCHEDULER_Task *task,
            struct GNUNET_SCHEDULER_FdInfo *fdi)
{
  struct DriverContext *context = cls;
  GNUNET_assert (NULL != context);
  GNUNET_assert (NULL != task);
  GNUNET_assert (NULL != fdi);
  GNUNET_assert (0 != (GNUNET_SCHEDULER_ET_IN & fdi->et) ||
                 0 != (GNUNET_SCHEDULER_ET_OUT & fdi->et));

  if (!((NULL != fdi->fd) ^ (NULL != fdi->fh)) || (fdi->sock < 0))
  {
    /* exactly one out of {fd, hf} must be != NULL and the OS handle must be valid */
    return GNUNET_SYSERR;
  }

  struct Scheduled *scheduled = GNUNET_new (struct Scheduled);
  scheduled->task = task;
  scheduled->fdi = fdi;
  scheduled->et = fdi->et;

  GNUNET_CONTAINER_DLL_insert (context->scheduled_head,
                               context->scheduled_tail,
                               scheduled);
  return GNUNET_OK;
}


static int
select_del (void *cls,
            struct GNUNET_SCHEDULER_Task *task)
{
  struct DriverContext *context;
  struct Scheduled *pos;
  int ret;

  GNUNET_assert (NULL != cls);

  context = cls;
  ret = GNUNET_SYSERR;
  pos = context->scheduled_head;
  while (NULL != pos)
  {
    struct Scheduled *next = pos->next;
    if (pos->task == task)
    {
      GNUNET_CONTAINER_DLL_remove (context->scheduled_head,
                                   context->scheduled_tail,
                                   pos);
      GNUNET_free (pos);
      ret = GNUNET_OK;
    }
    pos = next;
  }
  return ret;
}


static void
select_set_wakeup (void *cls,
                   struct GNUNET_TIME_Absolute dt)
{
  struct DriverContext *context = cls;

  GNUNET_assert (NULL != context);
  context->timeout = dt;
}


/**
 * Obtain the driver for using select() as the event loop.
 *
 * @return NULL on error
 */
struct GNUNET_SCHEDULER_Driver *
GNUNET_SCHEDULER_driver_select ()
{
  struct GNUNET_SCHEDULER_Driver *select_driver;
  select_driver = GNUNET_new (struct GNUNET_SCHEDULER_Driver);

  select_driver->add = &select_add;
  select_driver->del = &select_del;
  select_driver->set_wakeup = &select_set_wakeup;

  return select_driver;
}


/* end of scheduler.c */

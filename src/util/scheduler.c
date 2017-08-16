/*
      This file is part of GNUnet
      Copyright (C) 2009-2017 GNUnet e.V.

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
 * @file util/scheduler.c
 * @brief schedule computations using continuation passing style
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "disk.h"

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
 * #GNUNET_SCHEDULER_run_from_driver().  Contains the
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

  ///**
  // * Set of file descriptors this task is waiting
  // * for for reading.  Once ready, this is updated
  // * to reflect the set of file descriptors ready
  // * for operation.
  // */
  //struct GNUNET_NETWORK_FDSet *read_set;

  ///**
  // * Set of file descriptors this task is waiting for for writing.
  // * Once ready, this is updated to reflect the set of file
  // * descriptors ready for operation.
  // */
  //struct GNUNET_NETWORK_FDSet *write_set;

  /**
   * Information about which FDs are ready for this task (and why).
   */
  const struct GNUNET_SCHEDULER_FdInfo *fds;

  /**
   * Storage location used for @e fds if we want to avoid
   * a separate malloc() call in the common case that this
   * task is only about a single FD.
   */
  struct GNUNET_SCHEDULER_FdInfo fdx;

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
   * Size of the @e fds array.
   */
  unsigned int fds_len;

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


struct Scheduled
{
  struct Scheduled *prev;

  struct Scheduled *next;

  struct GNUNET_SCHEDULER_Task *task;

  struct GNUNET_SCHEDULER_FdInfo *fdi;
};


/**
 * Driver context used by GNUNET_SCHEDULER_run
 */
struct DriverContext
{
  struct Scheduled *scheduled_in_head;

  struct Scheduled *scheduled_in_tail;

  struct Scheduled *scheduled_out_head;

  struct Scheduled *scheduled_out_tail;

  struct GNUNET_TIME_Relative timeout;
};


/**
 * The driver used for the event loop. Will be handed over to
 * the scheduler in #GNUNET_SCHEDULER_run_from_driver(), peristed
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
 * Number of tasks on the ready list.
 */
static unsigned int ready_count;

/**
 * How many tasks have we run so far?
 */
static unsigned long long tasks_run;

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
 * Scheduler handle used for the driver functions
 */
static struct GNUNET_SCHEDULER_Handle sh;


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
      timeout = now;
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
      timeout = now;
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
 * Destroy a task (release associated resources)
 *
 * @param t task to destroy
 */
static void
destroy_task (struct GNUNET_SCHEDULER_Task *t)
{
  // FIXME: destroy fds!
  if (t->fds_len > 1)
  {
    size_t i;
    for (i = 0; i != t->fds_len; ++i)
    {
      const struct GNUNET_SCHEDULER_FdInfo *fdi = t->fds + i;
      if (fdi->fd)
      {
        GNUNET_NETWORK_socket_free_memory_only_ ((struct GNUNET_NETWORK_Handle *) fdi->fd);
      }
      if (fdi->fh)
      {
        // FIXME: on WIN32 this is not enough! A function
        // GNUNET_DISK_file_free_memory_only would be nice
        GNUNET_free ((void *) fdi->fh);
      }
    }
    /* free the array */
    GNUNET_array_grow (t->fds, t->fds_len, 0);
  }
  //if (NULL != t->read_set)
  //  GNUNET_NETWORK_fdset_destroy (t->read_set);
  //if (NULL != t->write_set)
  //  GNUNET_NETWORK_fdset_destroy (t->write_set);
#if EXECINFO
  GNUNET_free (t->backtrace_strings);
#endif
  GNUNET_free (t);
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
  unsigned int i;

  for (i = 0; i < t->num_backtrace_strings; i++)
    LOG (GNUNET_ERROR_TYPE_WARNING,
   "Task %p trace %u: %s\n",
   t,
   i,
   t->backtrace_strings[i]);
#endif
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


/**
 * Wait for a short time.
 * Sleeps for @a ms ms (as that should be long enough for virtually all
 * modern systems to context switch and allow another process to do
 * some 'real' work).
 *
 * @param ms how many ms to wait
 */
static void
short_wait (unsigned int ms)
{
  struct GNUNET_TIME_Relative timeout;

  timeout = GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MILLISECONDS, ms);
  (void) GNUNET_NETWORK_socket_select (NULL, NULL, NULL, timeout);
}


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


/**
 * Check if the system has initiated shutdown. This means no tasks
 * that prevent shutdown were present and all tasks added with 
 * #GNUNET_SCHEDULER_add_shutdown were run already.
 *
 * Can be used by external event loop implementations to decide
 * whether to keep running or not.
 *
 * @return #GNUNET_YES if tasks which prevent shutdown exist
 *         #GNUNET_NO if the system has initiated shutdown
 */
// FIXME: make it an internal function again
int
GNUNET_SCHEDULER_check_lifeness ()
{
  struct GNUNET_SCHEDULER_Task *t;

  if (ready_count > 0)
    return GNUNET_YES;
  for (t = pending_head; NULL != t; t = t->next)
    if (t->lifeness == GNUNET_YES)
      return GNUNET_YES;
  for (t = shutdown_head; NULL != t; t = t->next)
    if (t->lifeness == GNUNET_YES)
      return GNUNET_YES;
  for (t = pending_timeout_head; NULL != t; t = t->next)
    if (t->lifeness == GNUNET_YES)
      return GNUNET_YES;
  if (NULL != shutdown_head)
  {
    GNUNET_SCHEDULER_shutdown ();
    LOG (GNUNET_ERROR_TYPE_WARNING,
         "shutting down\n");
    scheduler_driver->set_wakeup (scheduler_driver->cls,
                                  GNUNET_TIME_absolute_get ());
    return GNUNET_YES;
  }
  return GNUNET_NO;
}


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
  struct GNUNET_SCHEDULER_Driver *driver;
  struct DriverContext context = {.scheduled_in_head = NULL,
                                  .scheduled_in_tail = NULL,
                                  .scheduled_out_head = NULL,
                                  .scheduled_out_tail = NULL,
                                  .timeout = GNUNET_TIME_UNIT_FOREVER_REL};
  
  driver = GNUNET_SCHEDULER_driver_select ();
  driver->cls = &context;

  GNUNET_SCHEDULER_run_with_driver (driver, task, task_cls);
  
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
              size_t read_nh_len,
              const struct GNUNET_NETWORK_Handle *const *write_nh,
              size_t write_nh_len,
              const struct GNUNET_DISK_FileHandle *const *read_fh,
              size_t read_fh_len,
              const struct GNUNET_DISK_FileHandle *const *write_fh,
              size_t write_fh_len)
{
  struct GNUNET_SCHEDULER_FdInfo *fdi;

  t->fds_len = read_nh_len + write_nh_len + read_fh_len + write_fh_len;
  if (1 == t->fds_len)
  {
    fdi = &t->fdx;
    t->fds = fdi;
    if (1 == read_nh_len)
    {
      fdi->fd = GNUNET_NETWORK_socket_box_native (GNUNET_NETWORK_get_fd (*read_nh));
      GNUNET_assert (NULL != fdi->fd);
      fdi->et = GNUNET_SCHEDULER_ET_IN;
      fdi->sock = GNUNET_NETWORK_get_fd (*read_nh);
      t->read_fd = fdi->sock;
      t->write_fd = -1;
    }
    else if (1 == write_nh_len)
    {
      fdi->fd = GNUNET_NETWORK_socket_box_native (GNUNET_NETWORK_get_fd (*write_nh));
      GNUNET_assert (NULL != fdi->fd);
      fdi->et = GNUNET_SCHEDULER_ET_OUT;
      fdi->sock = GNUNET_NETWORK_get_fd (*write_nh);
      t->read_fd = -1;
      t->write_fd = fdi->sock;
    }
    else if (1 == read_fh_len)
    {
      fdi->fh = GNUNET_DISK_get_handle_from_int_fd ((*read_fh)->fd);
      GNUNET_assert (NULL != fdi->fh);
      fdi->et = GNUNET_SCHEDULER_ET_IN;
      fdi->sock = (*read_fh)->fd; // FIXME: does not work under WIN32
      t->read_fd = fdi->sock;
      t->write_fd = -1;
    }
    else
    {
      fdi->fh = GNUNET_DISK_get_handle_from_int_fd ((*write_fh)->fd);
      GNUNET_assert (NULL != fdi->fh);
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
    size_t i;
    for (i = 0; i != read_nh_len; ++i)
    {
      fdi->fd = GNUNET_NETWORK_socket_box_native (GNUNET_NETWORK_get_fd (read_nh[i]));
      GNUNET_assert (NULL != fdi->fd);
      fdi->et = GNUNET_SCHEDULER_ET_IN;
      fdi->sock = GNUNET_NETWORK_get_fd (read_nh[i]);
      ++fdi;
    }
    for (i = 0; i != write_nh_len; ++i)
    {
      fdi->fd = GNUNET_NETWORK_socket_box_native (GNUNET_NETWORK_get_fd (write_nh[i]));
      GNUNET_assert (NULL != fdi->fd);
      fdi->et = GNUNET_SCHEDULER_ET_OUT;
      fdi->sock = GNUNET_NETWORK_get_fd (write_nh[i]);
      ++fdi;
    }
    for (i = 0; i != read_fh_len; ++i)
    {
      fdi->fh = GNUNET_DISK_get_handle_from_int_fd (read_fh[i]->fd);
      GNUNET_assert (NULL != fdi->fh);
      fdi->et = GNUNET_SCHEDULER_ET_IN;
      fdi->sock = (read_fh[i])->fd; // FIXME: does not work under WIN32
      ++fdi;
    }
    for (i = 0; i != write_fh_len; ++i)
    {
      fdi->fh = GNUNET_DISK_get_handle_from_int_fd (write_fh[i]->fd);
      GNUNET_assert (NULL != fdi->fh);
      fdi->et = GNUNET_SCHEDULER_ET_OUT;
      fdi->sock = (write_fh[i])->fd; // FIXME: does not work under WIN32
      ++fdi;
    }
  }
}


void scheduler_multi_function_call(struct GNUNET_SCHEDULER_Task *t, int (*driver_func)())
{
  int success = GNUNET_YES;
  if (t->fds_len > 1)
  {
    for (int i = 0; i < t->fds_len;i++)
    {
      success = driver_func (scheduler_driver->cls, t , t->fds+i) && success;
    }
  }
  else
  {
    success = driver_func (scheduler_driver->cls, t , t->fds);
  }
  if (GNUNET_YES != success)
  {
    LOG (GNUNET_ERROR_TYPE_ERROR,
         "driver call not successful");
  }
}


void
shutdown_task (void *cls)
{
  char c;
  const struct GNUNET_DISK_FileHandle *pr;

  pr = GNUNET_DISK_pipe_handle (shutdown_pipe_handle,
                                GNUNET_DISK_PIPE_END_READ);
  GNUNET_assert (! GNUNET_DISK_handle_invalid (pr));
  /* consume the signal */
  GNUNET_DISK_file_read (pr, &c, sizeof (c));
  /* mark all active tasks as ready due to shutdown */
  GNUNET_SCHEDULER_shutdown ();
}


/**
 * Cancel the task with the specified identifier.
 * The task must not yet have run. Only allowed to be called as long as the
 * scheduler is running (#GNUNET_SCHEDULER_run or
 * #GNUNET_SCHEDULER_run_with_driver has been called and has not returned yet).
 *
 * @param task id of the task to cancel
 * @return original closure of the task
 */
void *
GNUNET_SCHEDULER_cancel (struct GNUNET_SCHEDULER_Task *task)
{
  enum GNUNET_SCHEDULER_Priority p;
  void *ret;

  /* scheduler must be running */
  GNUNET_assert (NULL != scheduler_driver);
  GNUNET_assert ( (NULL != active_task) ||
      (GNUNET_NO == task->lifeness) );
  if (! task->in_ready_list)
  {
    //if ( (-1 == task->read_fd) &&
    //     (-1 == task->write_fd) &&
    //     (NULL == task->read_set) &&
    //     (NULL == task->write_set) )
    if (NULL == task->fds)
    {
      if (GNUNET_YES == task->on_shutdown)
        GNUNET_CONTAINER_DLL_remove (shutdown_head,
                                     shutdown_tail,
                                     task);
      else
      {
        GNUNET_CONTAINER_DLL_remove (pending_timeout_head,
                                     pending_timeout_tail,
                                     task);
        if (pending_timeout_last == task)
          pending_timeout_last = NULL;
      }
      //TODO check if this is redundant
      if (task == pending_timeout_last)
        pending_timeout_last = NULL;
    }
    else
    {
      GNUNET_CONTAINER_DLL_remove (pending_head,
                                   pending_tail,
                                   task);
      scheduler_multi_function_call(task, scheduler_driver->del);
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
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Canceling task %p\n",
       task);
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
  t->priority = priority;
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
  t->priority = priority;
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
    while ( (NULL != pos) &&
            ( (pos->timeout.abs_value_us <= t->timeout.abs_value_us) ||
              (0 != pos->reason) ) )
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

  //int read_fds[2] = {GNUNET_NETWORK_get_fd (read_nh), read_fh->fd};
  //int write_fds[2] = {GNUNET_NETWORK_get_fd (write_nh), write_fh->fd};
  //init_fd_info (t, read_fds, 2, write_fds, 2);
  //init_fd_info (t, read_nh, write_nh, read_fh, write_fh);
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
  scheduler_multi_function_call (t, scheduler_driver->add);
  max_priority_added = GNUNET_MAX (max_priority_added,
                                   t->priority);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Adding task %p\n",
       t);
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
 * Only allowed to be called as long as the scheduler is running
 * (#GNUNET_SCHEDULER_run or #GNUNET_SCHEDULER_run_with_driver has been
 * called and has not returned yet).
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
 * Only allowed to be called as long as the scheduler is running
 * (#GNUNET_SCHEDULER_run or #GNUNET_SCHEDULER_run_with_driver has been
 * called and has not returned yet).
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
 * Only allowed to be called as long as the scheduler is running
 * (#GNUNET_SCHEDULER_run or #GNUNET_SCHEDULER_run_with_driver has been
 * called and has not returned yet).
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
 * Only allowed to be called as long as the scheduler is running
 * (#GNUNET_SCHEDULER_run or #GNUNET_SCHEDULER_run_with_driver has been
 * called and has not returned yet).
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
 * Only allowed to be called as long as the scheduler is running
 * (#GNUNET_SCHEDULER_run or #GNUNET_SCHEDULER_run_with_driver has been
 * called and has not returned yet).
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
 * Only allowed to be called as long as the scheduler is running
 * (#GNUNET_SCHEDULER_run or #GNUNET_SCHEDULER_run_with_driver has been
 * called and has not returned yet).
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
 * Only allowed to be called as long as the scheduler is running
 * (#GNUNET_SCHEDULER_run or #GNUNET_SCHEDULER_run_with_driver has been
 * called and has not returned yet).
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


int
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
  unsigned int nhandle_count, fhandle_count;
  int sock;
  int ret;

  nhandles = NULL;
  fhandles = NULL;
  nhandle_count = 0;
  fhandle_count = 0;
  ret = GNUNET_OK;
  for (sock = 0; sock != fdset->nsds; ++sock)
  {
    if (GNUNET_YES == GNUNET_NETWORK_fdset_test_native (fdset, sock))
    {
      const struct GNUNET_NETWORK_Handle *nhandle;
      const struct GNUNET_DISK_FileHandle *fhandle;

      nhandle = GNUNET_NETWORK_socket_box_native (sock);
      if (NULL != nhandle)
      {
        GNUNET_array_append (nhandles, nhandle_count, nhandle);
        ++nhandle_count;
      }
      else
      {
        fhandle = GNUNET_DISK_get_handle_from_int_fd (sock);
        if (NULL == fhandle)
        {
          ret = GNUNET_SYSERR;
          // DEBUG
          GNUNET_assert (0);
        }
        else
        {
          GNUNET_array_append (fhandles, fhandle_count, fhandle);
          ++fhandle_count;
        }
      }
    }
  }
  *ntarget = nhandles;
  *ftarget = fhandles;
  *extracted_nhandles = nhandle_count;
  *extracted_fhandles = fhandle_count;
  return ret;
}


void
destroy_network_handles (const struct GNUNET_NETWORK_Handle **handles,
                         unsigned int handles_len)
{
  size_t i;

  for (i = 0; i != handles_len; ++i)
  {
    GNUNET_free ((void *) handles[i]);
  }
  GNUNET_array_grow (handles, handles_len, 0);
}


void
destroy_file_handles (const struct GNUNET_DISK_FileHandle **handles,
                      unsigned int handles_len)
{
  size_t i;

  for (i = 0; i != handles_len; ++i)
  {
    GNUNET_free ((void *) handles[i]);
  }
  GNUNET_array_grow (handles, handles_len, 0);
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
 * Only allowed to be called as long as the scheduler is running
 * (#GNUNET_SCHEDULER_run or #GNUNET_SCHEDULER_run_with_driver has been
 * called and has not returned yet).
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
  const struct GNUNET_NETWORK_Handle **read_nhandles, **write_nhandles;
  const struct GNUNET_DISK_FileHandle **read_fhandles, **write_fhandles;
  unsigned int read_nhandles_len, write_nhandles_len,
               read_fhandles_len, write_fhandles_len;

  LOG (GNUNET_ERROR_TYPE_WARNING,
       "[%p] GNUNET_SCHDULER_add_select\n",
       sh);

  if ( (NULL == rs) &&
       (NULL == ws) )
    return GNUNET_SCHEDULER_add_delayed_with_priority (delay,
                                                       prio,
                                                       task,
                                                       task_cls);
  /* scheduler must be running */
  GNUNET_assert (NULL != scheduler_driver);
  GNUNET_assert (NULL != active_task);
  GNUNET_assert (NULL != task);
  t = GNUNET_new (struct GNUNET_SCHEDULER_Task);
  t->callback = task;
  t->callback_cls = task_cls;
  t->read_fd = -1;
  t->write_fd = -1;
  read_nhandles_len = 0;
  write_nhandles_len = 0;
  read_fhandles_len = 0;
  write_fhandles_len = 0;
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
  GNUNET_assert (read_nhandles_len + write_nhandles_len > 0);
  init_fd_info (t,
                read_nhandles,
                read_nhandles_len,
                write_nhandles,
                write_nhandles_len,
                read_fhandles,
                read_fhandles_len,
                write_fhandles,
                write_fhandles_len);
  destroy_network_handles (read_nhandles, read_nhandles_len);
  destroy_network_handles (write_nhandles, write_nhandles_len);
  destroy_file_handles (read_fhandles, read_fhandles_len);
  destroy_file_handles (write_fhandles, write_fhandles_len);
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
  scheduler_multi_function_call (t, scheduler_driver->add);
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
 * that a particular @a task is ready due to an event of type @a et.
 *
 * This function will then queue the task to notify the application
 * that the task is ready (with the respective priority).
 *
 * @param task the task that is ready, NULL for wake up calls
 * @param et information about why the task is ready
 */
void
GNUNET_SCHEDULER_task_ready (struct GNUNET_SCHEDULER_Task *task,
                             enum GNUNET_SCHEDULER_EventType et)
{
  enum GNUNET_SCHEDULER_Reason reason;
  struct GNUNET_TIME_Absolute now;

  now = GNUNET_TIME_absolute_get ();
  reason = task->reason;
  if (now.abs_value_us >= task->timeout.abs_value_us)
    reason |= GNUNET_SCHEDULER_REASON_TIMEOUT;
  if ( (0 == (reason & GNUNET_SCHEDULER_REASON_READ_READY)) &&
       (0 != (GNUNET_SCHEDULER_ET_IN & et)) )
    reason |= GNUNET_SCHEDULER_REASON_READ_READY;
  if ( (0 == (reason & GNUNET_SCHEDULER_REASON_WRITE_READY)) &&
       (0 != (GNUNET_SCHEDULER_ET_OUT & et)) )
    reason |= GNUNET_SCHEDULER_REASON_WRITE_READY;
  reason |= GNUNET_SCHEDULER_REASON_PREREQ_DONE;

   


  task->reason = reason;
  task->fds = &task->fdx; // FIXME: if task contains a list of fds, this is wrong!
  task->fdx.et = et;
  task->fds_len = 1;
  GNUNET_CONTAINER_DLL_remove (pending_head,
                               pending_tail,
                               task);
  queue_ready_task (task);
}


/**
 * Function called by the driver to tell the scheduler to run some of
 * the tasks that are ready.  This function may return even though
 * there are tasks left to run just to give other tasks a chance as
 * well.  If we return #GNUNET_YES, the driver should call this
 * function again as soon as possible, while if we return #GNUNET_NO
 * it must block until the operating system has more work as the
 * scheduler has no more work to do right now.
 *
 * @param sh scheduler handle that was given to the `loop`
 * @return #GNUNET_OK if there are more tasks that are ready,
 *          and thus we would like to run more (yield to avoid
 *          blocking other activities for too long)
 *         #GNUNET_NO if we are done running tasks (yield to block)
 *         #GNUNET_SYSERR on error
 */
int
GNUNET_SCHEDULER_run_from_driver (struct GNUNET_SCHEDULER_Handle *sh)
{
  // FIXME: call check_lifeness here!
  enum GNUNET_SCHEDULER_Priority p;
  struct GNUNET_SCHEDULER_Task *pos;
  struct GNUNET_TIME_Absolute now;

  /* check for tasks that reached the timeout! */
  now = GNUNET_TIME_absolute_get ();
  while (NULL != (pos = pending_timeout_head))
  {
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
  }

  if (0 == ready_count)
    return GNUNET_NO;

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
    tc.fds_len = pos->fds_len;
    tc.fds = pos->fds;
    //tc.read_ready = (NULL == pos->read_set) ? sh->rs : pos->read_set;
    tc.read_ready = sh->rs;
    if ( (-1 != pos->read_fd) &&
         (0 != (pos->reason & GNUNET_SCHEDULER_REASON_READ_READY)) )
      GNUNET_NETWORK_fdset_set_native (sh->rs,
                                       pos->read_fd);
    //tc.write_ready = (NULL == pos->write_set) ? sh->ws : pos->write_set;
    tc.write_ready = sh->ws;
    if ( (-1 != pos->write_fd) &&
         (0 != (pos->reason & GNUNET_SCHEDULER_REASON_WRITE_READY)) )
      GNUNET_NETWORK_fdset_set_native (sh->ws,
                                       pos->write_fd);
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Running task %p\n",
         pos);
    pos->callback (pos->callback_cls);
    active_task = NULL;
    dump_backtrace (pos);
    destroy_task (pos);
    tasks_run++;
  }
  if (0 == ready_count)
  {
    scheduler_driver->set_wakeup (scheduler_driver->cls,
                                  get_timeout ());
    return GNUNET_NO;
  }
  scheduler_driver->set_wakeup (scheduler_driver->cls,
                                GNUNET_TIME_absolute_get ()); 
  return GNUNET_OK;
}


/**
 * Initialize and run scheduler.  This function will return when all
 * tasks have completed.  On systems with signals, receiving a SIGTERM
 * (and other similar signals) will cause #GNUNET_SCHEDULER_shutdown
 * to be run after the active task is complete.  As a result, SIGTERM
 * causes all shutdown tasks to be scheduled with reason
 * #GNUNET_SCHEDULER_REASON_SHUTDOWN.  (However, tasks added
 * afterwards will execute normally!).  Note that any particular
 * signal will only shut down one scheduler; applications should
 * always only create a single scheduler.
 *
 * @param driver drive to use for the event loop
 * @param task task to run first (and immediately)
 * @param task_cls closure of @a task
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on failure
 */
int
GNUNET_SCHEDULER_run_with_driver (const struct GNUNET_SCHEDULER_Driver *driver,
                                  GNUNET_SCHEDULER_TaskCallback task,
                                  void *task_cls)
{
  int ret;
  struct GNUNET_SIGNAL_Context *shc_int;
  struct GNUNET_SIGNAL_Context *shc_term;
#if (SIGTERM != GNUNET_TERM_SIG)
  struct GNUNET_SIGNAL_Context *shc_gterm;
#endif
#ifndef MINGW
  struct GNUNET_SIGNAL_Context *shc_quit;
  struct GNUNET_SIGNAL_Context *shc_hup;
  struct GNUNET_SIGNAL_Context *shc_pipe;
#endif
  struct GNUNET_SCHEDULER_Task tsk;
  const struct GNUNET_DISK_FileHandle *pr;

  /* general set-up */
  GNUNET_assert (NULL == active_task);
  GNUNET_assert (NULL == shutdown_pipe_handle);
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
  shc_int = GNUNET_SIGNAL_handler_install (SIGINT,
             &sighandler_shutdown);
  shc_term = GNUNET_SIGNAL_handler_install (SIGTERM,
              &sighandler_shutdown);
#if (SIGTERM != GNUNET_TERM_SIG)
  shc_gterm = GNUNET_SIGNAL_handler_install (GNUNET_TERM_SIG,
               &sighandler_shutdown);
#endif
#ifndef MINGW
  shc_pipe = GNUNET_SIGNAL_handler_install (SIGPIPE,
              &sighandler_pipe);
  shc_quit = GNUNET_SIGNAL_handler_install (SIGQUIT,
              &sighandler_shutdown);
  shc_hup = GNUNET_SIGNAL_handler_install (SIGHUP,
             &sighandler_shutdown);
#endif

  /* Setup initial tasks */
  current_priority = GNUNET_SCHEDULER_PRIORITY_DEFAULT;
  current_lifeness = GNUNET_NO;
  memset (&tsk,
    0,
    sizeof (tsk));
  active_task = &tsk;
  GNUNET_SCHEDULER_add_now (&GNUNET_OS_install_parent_control_handler,
                            NULL);
  GNUNET_SCHEDULER_add_read_file (GNUNET_TIME_UNIT_FOREVER_REL,
                                  pr,
                                  &shutdown_task,
                                  NULL);
  current_lifeness = GNUNET_YES;
  GNUNET_SCHEDULER_add_with_reason_and_priority (task,
                                                 task_cls,
                                                 GNUNET_SCHEDULER_REASON_STARTUP,
                                                 GNUNET_SCHEDULER_PRIORITY_DEFAULT);
  active_task = NULL;
  scheduler_driver->set_wakeup (scheduler_driver->cls,
                                get_timeout ());
  /* begin main event loop */
  sh.rs = GNUNET_NETWORK_fdset_create ();
  sh.ws = GNUNET_NETWORK_fdset_create ();
  GNUNET_NETWORK_fdset_handle_set (sh.rs, pr);
  ret = driver->loop (driver->cls,
                      &sh);
  GNUNET_NETWORK_fdset_destroy (sh.rs);
  GNUNET_NETWORK_fdset_destroy (sh.ws);

  /* uninstall signal handlers */
  GNUNET_SIGNAL_handler_uninstall (shc_int);
  GNUNET_SIGNAL_handler_uninstall (shc_term);
#if (SIGTERM != GNUNET_TERM_SIG)
  GNUNET_SIGNAL_handler_uninstall (shc_gterm);
#endif
#ifndef MINGW
  GNUNET_SIGNAL_handler_uninstall (shc_pipe);
  GNUNET_SIGNAL_handler_uninstall (shc_quit);
  GNUNET_SIGNAL_handler_uninstall (shc_hup);
#endif
  GNUNET_DISK_pipe_close (shutdown_pipe_handle);
  shutdown_pipe_handle = NULL;
  scheduler_driver = NULL;
  return ret;
}


int
select_add (void *cls,
            struct GNUNET_SCHEDULER_Task *task,
            struct GNUNET_SCHEDULER_FdInfo *fdi)
{
  struct DriverContext *context = cls;
  GNUNET_assert (NULL != context);
  GNUNET_assert (NULL != task);
  GNUNET_assert (NULL != fdi);

  if (!((NULL != fdi->fd) ^ (NULL != fdi->fh)) || (0 > fdi->sock))
  {
    /* exactly one out of {fd, hf} must be != NULL and the OS handle must be valid */
    return GNUNET_SYSERR;
  }

  struct Scheduled *scheduled = GNUNET_new (struct Scheduled);
  scheduled->task = task;
  scheduled->fdi = fdi;

  switch (fdi->et)
  {
  case GNUNET_SCHEDULER_ET_IN:
  {
    GNUNET_CONTAINER_DLL_insert (context->scheduled_in_head,
                                 context->scheduled_in_tail,
                                 scheduled);
    break;
  }
  case GNUNET_SCHEDULER_ET_OUT:
  {
    GNUNET_CONTAINER_DLL_insert (context->scheduled_out_head,
                                 context->scheduled_out_tail,
                                 scheduled);
    break;
  }
  default:
  {
    // FIXME: other event types not implemented yet
    GNUNET_assert (0);
  }
  }
  return GNUNET_OK;
}


int
select_del (void *cls,
            struct GNUNET_SCHEDULER_Task *task,
            struct GNUNET_SCHEDULER_FdInfo *fdi)
{
  struct DriverContext *context = cls;
  GNUNET_assert (NULL != context);

  int ret = GNUNET_SYSERR;
  struct Scheduled *pos;
  // FIXME: are multiple ORed event types allowed?
  switch (fdi->et)
  {
  case GNUNET_SCHEDULER_ET_IN:
  {
    for (pos = context->scheduled_in_head; NULL != pos; pos = pos->next)
    {
      if (pos->task == task)
      {
        GNUNET_CONTAINER_DLL_remove (context->scheduled_in_head,
                                     context->scheduled_in_tail,
                                     pos);
        ret = GNUNET_OK;
      }
    }
    break; 
  }
  case GNUNET_SCHEDULER_ET_OUT:
  {
    for (pos = context->scheduled_out_head; NULL != pos; pos = pos->next)
    {
      if (pos->task == task)
      {
        GNUNET_CONTAINER_DLL_remove (context->scheduled_out_head,
                                     context->scheduled_out_tail,
                                     pos);
        ret = GNUNET_OK;
      }
    }
    break;
  }
  default:
  {
    // FIXME: other event types not implemented yet
    GNUNET_assert (0);
  }
  }
  return ret;
}


int
select_loop (void *cls,
             struct GNUNET_SCHEDULER_Handle *sh)
{
  struct GNUNET_NETWORK_FDSet *rs;
  struct GNUNET_NETWORK_FDSet *ws;
  struct DriverContext *context;
  int select_result;
  unsigned long long last_tr;
  unsigned int busy_wait_warning;
  
  context = cls;
  GNUNET_assert (NULL != context);
  rs = GNUNET_NETWORK_fdset_create ();
  ws = GNUNET_NETWORK_fdset_create ();
  last_tr = 0;
  busy_wait_warning = 0;
  // FIXME: remove check_lifeness, instead the condition should be:
  // pending_in_head != NULL || pending_out_head != NULL || tasks_ready
  while (GNUNET_YES == GNUNET_SCHEDULER_check_lifeness ())
  {
    LOG (GNUNET_ERROR_TYPE_WARNING,
         "[%p] timeout = %s\n",
         sh,
         GNUNET_STRINGS_relative_time_to_string (context->timeout, GNUNET_NO));

    GNUNET_NETWORK_fdset_zero (rs);
    GNUNET_NETWORK_fdset_zero (ws);
    struct Scheduled *pos;
    for (pos = context->scheduled_in_head; NULL != pos; pos = pos->next)
    {
      GNUNET_NETWORK_fdset_set_native (rs, pos->fdi->sock);
    }
    for (pos = context->scheduled_out_head; NULL != pos; pos = pos->next)
    {
      GNUNET_NETWORK_fdset_set_native (ws, pos->fdi->sock);
    }
    if (NULL == scheduler_select)
    {
      select_result = GNUNET_NETWORK_socket_select (rs,
                                                    ws,
                                                    NULL,
                                                    context->timeout);
    }
    else
    {
      select_result = scheduler_select (scheduler_select_cls,
                                        rs,
                                        ws,
                                        NULL,
                                        context->timeout);
    }
    if (select_result == GNUNET_SYSERR)
    {
      if (errno == EINTR)
        continue;

      LOG_STRERROR (GNUNET_ERROR_TYPE_ERROR, "select");
#ifndef MINGW
#if USE_LSOF
      char lsof[512];

      snprintf (lsof, sizeof (lsof), "lsof -p %d", getpid ());
      (void) close (1);
      (void) dup2 (2, 1);
      if (0 != system (lsof))
        LOG_STRERROR (GNUNET_ERROR_TYPE_WARNING,
                      "system");
#endif
#endif
#if DEBUG_FDS
      struct GNUNET_SCHEDULER_Task *t;
      // FIXME: pending_head is a scheduler-internal variable!
      for (t = pending_head; NULL != t; t = t->next)
      {
        if (-1 != t->read_fd)
        {
          int flags = fcntl (t->read_fd, F_GETFD);
          if ((flags == -1) && (errno == EBADF))
          {
            LOG (GNUNET_ERROR_TYPE_ERROR,
                 "Got invalid file descriptor %d!\n",
                 t->read_fd);
            dump_backtrace (t);
          }
        }
        if (-1 != t->write_fd)
        {
          int flags = fcntl (t->write_fd, F_GETFD);
          if ((flags == -1) && (errno == EBADF))
          {
            LOG (GNUNET_ERROR_TYPE_ERROR,
                 "Got invalid file descriptor %d!\n",
                 t->write_fd);
            dump_backtrace (t);
          }
        }
      }
#endif
      GNUNET_assert (0);
      return GNUNET_SYSERR;
    }
    if ( (0 == select_result) &&
         (0 == context->timeout.rel_value_us) &&
         (busy_wait_warning > 16) )
    {
      LOG (GNUNET_ERROR_TYPE_WARNING,
           "[%p] Looks like we're busy waiting...\n",
           sh);
      //GNUNET_assert (0);
      short_wait (100);                /* mitigate */
    }
    for (pos = context->scheduled_in_head; NULL != pos; pos = pos->next)
    {
      if (GNUNET_YES == GNUNET_NETWORK_fdset_test_native (rs, pos->fdi->sock))
      {
        GNUNET_CONTAINER_DLL_remove (context->scheduled_in_head,
                                     context->scheduled_in_tail,
                                     pos);
        GNUNET_SCHEDULER_task_ready (pos->task, GNUNET_SCHEDULER_ET_IN);
      }
    }
    for (pos = context->scheduled_out_head; NULL != pos; pos = pos->next)
    {
      if (GNUNET_YES == GNUNET_NETWORK_fdset_test_native (ws, pos->fdi->sock))
      {
        GNUNET_CONTAINER_DLL_remove (context->scheduled_out_head,
                                     context->scheduled_out_tail,
                                     pos);
        GNUNET_SCHEDULER_task_ready (pos->task, GNUNET_SCHEDULER_ET_OUT);
      }
    }
    int tasks_ready = GNUNET_SCHEDULER_run_from_driver (sh);
    LOG (GNUNET_ERROR_TYPE_WARNING,
         "[%p] tasks_ready: %d\n",
         sh,
         tasks_ready);
    // FIXME: tasks_run is a driver-internal variable! Instead we should increment
    // a local variable tasks_ready_count everytime we're calling GNUNET_SCHEDULER_task_ready. 
    if (last_tr == tasks_run)
    {
      LOG (GNUNET_ERROR_TYPE_WARNING,
           "[%p] no tasks run\n",
           sh);
      short_wait (1);
      busy_wait_warning++;
    }
    else
    {
      last_tr = tasks_run;
      busy_wait_warning = 0;
    }
  }
  return GNUNET_OK; 
}


void
select_set_wakeup(void *cls,
                  struct GNUNET_TIME_Absolute dt)
{
  struct DriverContext *context = cls;
  GNUNET_assert (NULL != context);
 
  context->timeout = GNUNET_TIME_absolute_get_remaining (dt);
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

  select_driver->loop = &select_loop;
  select_driver->add = &select_add;
  select_driver->del = &select_del;
  select_driver->set_wakeup = &select_set_wakeup;

  return select_driver;
}


/* end of scheduler.c */

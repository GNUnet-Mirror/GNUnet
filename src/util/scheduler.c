/*
      This file is part of GNUnet
      (C) 2009, 2011 Christian Grothoff (and other contributing authors)

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
 * @file util/scheduler.c
 * @brief schedule computations using continuation passing style
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_common.h"
#include "gnunet_os_lib.h"
#include "gnunet_scheduler_lib.h"
#include "gnunet_signal_lib.h"
#include "gnunet_time_lib.h"
#include "disk.h"

#define LOG(kind,...) GNUNET_log_from (kind, "util-scheduler", __VA_ARGS__)

#define LOG_STRERROR(kind,syscall) GNUNET_log_from_strerror (kind, "util-scheduler", syscall)


#ifdef LINUX
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
 * Linked list of pending tasks.
 */
struct Task
{
  /**
   * This is a linked list.
   */
  struct Task *next;

  /**
   * Function to run when ready.
   */
  GNUNET_SCHEDULER_Task callback;

  /**
   * Closure for the callback.
   */
  void *callback_cls;

  /**
   * Set of file descriptors this task is waiting
   * for for reading.  Once ready, this is updated
   * to reflect the set of file descriptors ready
   * for operation.
   */
  struct GNUNET_NETWORK_FDSet *read_set;

  /**
   * Set of file descriptors this task is waiting for for writing.
   * Once ready, this is updated to reflect the set of file
   * descriptors ready for operation.
   */
  struct GNUNET_NETWORK_FDSet *write_set;

  /**
   * Unique task identifier.
   */
  GNUNET_SCHEDULER_TaskIdentifier id;

  /**
   * Identifier of a prerequisite task.
   */
  GNUNET_SCHEDULER_TaskIdentifier prereq_id;

  /**
   * Absolute timeout value for the task, or
   * GNUNET_TIME_UNIT_FOREVER_ABS for "no timeout".
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
 * List of tasks waiting for an event.
 */
static struct Task *pending;

/**
 * List of tasks waiting ONLY for a timeout event.
 * Sorted by timeout (earliest first).  Used so that
 * we do not traverse the list of these tasks when
 * building select sets (we just look at the head
 * to determine the respective timeout ONCE).
 */
static struct Task *pending_timeout;

/**
 * Last inserted task waiting ONLY for a timeout event.
 * Used to (heuristically) speed up insertion.
 */
static struct Task *pending_timeout_last;

/**
 * ID of the task that is running right now.
 */
static struct Task *active_task;

/**
 * List of tasks ready to run right now,
 * grouped by importance.
 */
static struct Task *ready[GNUNET_SCHEDULER_PRIORITY_COUNT];

/**
 * Identity of the last task queued.  Incremented for each task to
 * generate a unique task ID (it is virtually impossible to start
 * more than 2^64 tasks during the lifetime of a process).
 */
static GNUNET_SCHEDULER_TaskIdentifier last_id;

/**
 * Highest number so that all tasks with smaller identifiers
 * have already completed.  Also the lowest number of a task
 * still waiting to be executed.
 */
static GNUNET_SCHEDULER_TaskIdentifier lowest_pending_id;

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
 * If NULL, we use GNUNET_NETWORK_socket_select ().
 */
static GNUNET_SCHEDULER_select scheduler_select;

/**
 * Closure for 'scheduler_select'.
 */
static void *scheduler_select_cls;

/**
 * Sets the select function to use in the scheduler (scheduler_select).
 *
 * @param new_select new select function to use
 * @param new_select_cls closure for 'new_select'
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
 * Is a task with this identifier still pending?  Also updates
 * "lowest_pending_id" as a side-effect (for faster checks in the
 * future), but only if the return value is "GNUNET_NO" (and
 * the "lowest_pending_id" check failed).
 *
 * @param id which task are we checking for
 * @return GNUNET_YES if so, GNUNET_NO if not
 */
static int
is_pending (GNUNET_SCHEDULER_TaskIdentifier id)
{
  struct Task *pos;
  enum GNUNET_SCHEDULER_Priority p;
  GNUNET_SCHEDULER_TaskIdentifier min;

  if (id < lowest_pending_id)
    return GNUNET_NO;
  min = -1;                     /* maximum value */
  pos = pending;
  while (pos != NULL)
  {
    if (pos->id == id)
      return GNUNET_YES;
    if (pos->id < min)
      min = pos->id;
    pos = pos->next;
  }
  pos = pending_timeout;
  while (pos != NULL)
  {
    if (pos->id == id)
      return GNUNET_YES;
    if (pos->id < min)
      min = pos->id;
    pos = pos->next;
  }
  for (p = 0; p < GNUNET_SCHEDULER_PRIORITY_COUNT; p++)
  {
    pos = ready[p];
    while (pos != NULL)
    {
      if (pos->id == id)
        return GNUNET_YES;
      if (pos->id < min)
        min = pos->id;
      pos = pos->next;
    }
  }
  lowest_pending_id = min;
  return GNUNET_NO;
}


/**
 * Update all sets and timeout for select.
 *
 * @param rs read-set, set to all FDs we would like to read (updated)
 * @param ws write-set, set to all FDs we would like to write (updated)
 * @param timeout next timeout (updated)
 */
static void
update_sets (struct GNUNET_NETWORK_FDSet *rs, struct GNUNET_NETWORK_FDSet *ws,
             struct GNUNET_TIME_Relative *timeout)
{
  struct Task *pos;
  struct GNUNET_TIME_Absolute now;
  struct GNUNET_TIME_Relative to;

  now = GNUNET_TIME_absolute_get ();
  pos = pending_timeout;
  if (pos != NULL)
  {
    to = GNUNET_TIME_absolute_get_difference (now, pos->timeout);
    if (timeout->rel_value > to.rel_value)
      *timeout = to;
    if (pos->reason != 0)
      *timeout = GNUNET_TIME_UNIT_ZERO;
  }
  pos = pending;
  while (pos != NULL)
  {
    if ((pos->prereq_id != GNUNET_SCHEDULER_NO_TASK) &&
        (GNUNET_YES == is_pending (pos->prereq_id)))
    {
      pos = pos->next;
      continue;
    }
    if (pos->timeout.abs_value != GNUNET_TIME_UNIT_FOREVER_ABS.abs_value)
    {
      to = GNUNET_TIME_absolute_get_difference (now, pos->timeout);
      if (timeout->rel_value > to.rel_value)
        *timeout = to;
    }
    if (pos->read_fd != -1)
      GNUNET_NETWORK_fdset_set_native (rs, pos->read_fd);
    if (pos->write_fd != -1)
      GNUNET_NETWORK_fdset_set_native (ws, pos->write_fd);
    if (pos->read_set != NULL)
      GNUNET_NETWORK_fdset_add (rs, pos->read_set);
    if (pos->write_set != NULL)
      GNUNET_NETWORK_fdset_add (ws, pos->write_set);
    if (pos->reason != 0)
      *timeout = GNUNET_TIME_UNIT_ZERO;
    pos = pos->next;
  }
}


/**
 * Check if the ready set overlaps with the set we want to have ready.
 * If so, update the want set (set all FDs that are ready).  If not,
 * return GNUNET_NO.
 *
 * @param ready set that is ready
 * @param want set that we want to be ready
 * @return GNUNET_YES if there was some overlap
 */
static int
set_overlaps (const struct GNUNET_NETWORK_FDSet *ready,
              struct GNUNET_NETWORK_FDSet *want)
{
  if ((NULL == want) || (NULL == ready))
    return GNUNET_NO;
  if (GNUNET_NETWORK_fdset_overlap (ready, want))
  {
    /* copy all over (yes, there maybe unrelated bits,
     * but this should not hurt well-written clients) */
    GNUNET_NETWORK_fdset_copy (want, ready);
    return GNUNET_YES;
  }
  return GNUNET_NO;
}


/**
 * Check if the given task is eligible to run now.
 * Also set the reason why it is eligible.
 *
 * @param task task to check if it is ready
 * @param now the current time
 * @param rs set of FDs ready for reading
 * @param ws set of FDs ready for writing
 * @return GNUNET_YES if we can run it, GNUNET_NO if not.
 */
static int
is_ready (struct Task *task, struct GNUNET_TIME_Absolute now,
          const struct GNUNET_NETWORK_FDSet *rs,
          const struct GNUNET_NETWORK_FDSet *ws)
{
  enum GNUNET_SCHEDULER_Reason reason;

  reason = task->reason;
  if (now.abs_value >= task->timeout.abs_value)
    reason |= GNUNET_SCHEDULER_REASON_TIMEOUT;
  if ((0 == (reason & GNUNET_SCHEDULER_REASON_READ_READY)) &&
      (((task->read_fd != -1) &&
        (GNUNET_YES == GNUNET_NETWORK_fdset_test_native (rs, task->read_fd))) ||
       (set_overlaps (rs, task->read_set))))
    reason |= GNUNET_SCHEDULER_REASON_READ_READY;
  if ((0 == (reason & GNUNET_SCHEDULER_REASON_WRITE_READY)) &&
      (((task->write_fd != -1) &&
        (GNUNET_YES == GNUNET_NETWORK_fdset_test_native (ws, task->write_fd)))
       || (set_overlaps (ws, task->write_set))))
    reason |= GNUNET_SCHEDULER_REASON_WRITE_READY;
  if (reason == 0)
    return GNUNET_NO;           /* not ready */
  if (task->prereq_id != GNUNET_SCHEDULER_NO_TASK)
  {
    if (GNUNET_YES == is_pending (task->prereq_id))
    {
      task->reason = reason;
      return GNUNET_NO;         /* prereq waiting */
    }
    reason |= GNUNET_SCHEDULER_REASON_PREREQ_DONE;
  }
  task->reason = reason;
  return GNUNET_YES;
}


/**
 * Put a task that is ready for execution into the ready queue.
 *
 * @param task task ready for execution
 */
static void
queue_ready_task (struct Task *task)
{
  enum GNUNET_SCHEDULER_Priority p = task->priority;

  if (0 != (task->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN))
    p = GNUNET_SCHEDULER_PRIORITY_SHUTDOWN;
  task->next = ready[check_priority (p)];
  ready[check_priority (p)] = task;
  ready_count++;
}


/**
 * Check which tasks are ready and move them
 * to the respective ready queue.
 *
 * @param rs FDs ready for reading
 * @param ws FDs ready for writing
 */
static void
check_ready (const struct GNUNET_NETWORK_FDSet *rs,
             const struct GNUNET_NETWORK_FDSet *ws)
{
  struct Task *pos;
  struct Task *prev;
  struct Task *next;
  struct GNUNET_TIME_Absolute now;

  now = GNUNET_TIME_absolute_get ();
  prev = NULL;
  pos = pending_timeout;
  while (pos != NULL)
  {
    next = pos->next;
    if (now.abs_value >= pos->timeout.abs_value)
      pos->reason |= GNUNET_SCHEDULER_REASON_TIMEOUT;
    if (0 == pos->reason)
      break;
    pending_timeout = next;
    if (pending_timeout_last == pos)
      pending_timeout_last = NULL;
    queue_ready_task (pos);
    pos = next;
  }
  pos = pending;
  while (pos != NULL)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, 
	 "Checking readiness of task: %llu / %p\n",
         pos->id, pos->callback_cls);
    next = pos->next;
    if (GNUNET_YES == is_ready (pos, now, rs, ws))
    {
      if (prev == NULL)
        pending = next;
      else
        prev->next = next;
      queue_ready_task (pos);
      pos = next;
      continue;
    }
    prev = pos;
    pos = next;
  }
}


/**
 * Request the shutdown of a scheduler.  Marks all currently
 * pending tasks as ready because of shutdown.  This will
 * cause all tasks to run (as soon as possible, respecting
 * priorities and prerequisite tasks).  Note that tasks
 * scheduled AFTER this call may still be delayed arbitrarily.
 */
void
GNUNET_SCHEDULER_shutdown ()
{
  struct Task *pos;
  int i;

  pos = pending_timeout;
  while (pos != NULL)
  {
    pos->reason |= GNUNET_SCHEDULER_REASON_SHUTDOWN;
    /* we don't move the task into the ready queue yet; check_ready
     * will do that later, possibly adding additional
     * readiness-factors */
    pos = pos->next;
  }
  pos = pending;
  while (pos != NULL)
  {
    pos->reason |= GNUNET_SCHEDULER_REASON_SHUTDOWN;
    /* we don't move the task into the ready queue yet; check_ready
     * will do that later, possibly adding additional
     * readiness-factors */
    pos = pos->next;
  }
  for (i = 0; i < GNUNET_SCHEDULER_PRIORITY_COUNT; i++)
  {
    pos = ready[i];
    while (pos != NULL)
    {
      pos->reason |= GNUNET_SCHEDULER_REASON_SHUTDOWN;
      /* we don't move the task into the ready queue yet; check_ready
       * will do that later, possibly adding additional
       * readiness-factors */
      pos = pos->next;
    }
  }
}


/**
 * Destroy a task (release associated resources)
 *
 * @param t task to destroy
 */
static void
destroy_task (struct Task *t)
{
  if (NULL != t->read_set)
    GNUNET_NETWORK_fdset_destroy (t->read_set);
  if (NULL != t->write_set)
    GNUNET_NETWORK_fdset_destroy (t->write_set);
#if EXECINFO
  GNUNET_free (t->backtrace_strings);
#endif
  GNUNET_free (t);
}


/**
 * Run at least one task in the highest-priority queue that is not
 * empty.  Keep running tasks until we are either no longer running
 * "URGENT" tasks or until we have at least one "pending" task (which
 * may become ready, hence we should select on it).  Naturally, if
 * there are no more ready tasks, we also return.
 *
 * @param rs FDs ready for reading
 * @param ws FDs ready for writing
 */
static void
run_ready (struct GNUNET_NETWORK_FDSet *rs, struct GNUNET_NETWORK_FDSet *ws)
{
  enum GNUNET_SCHEDULER_Priority p;
  struct Task *pos;
  struct GNUNET_SCHEDULER_TaskContext tc;

  max_priority_added = GNUNET_SCHEDULER_PRIORITY_KEEP;
  do
  {
    if (ready_count == 0)
      return;
    GNUNET_assert (ready[GNUNET_SCHEDULER_PRIORITY_KEEP] == NULL);
    /* yes, p>0 is correct, 0 is "KEEP" which should
     * always be an empty queue (see assertion)! */
    for (p = GNUNET_SCHEDULER_PRIORITY_COUNT - 1; p > 0; p--)
    {
      pos = ready[p];
      if (pos != NULL)
        break;
    }
    GNUNET_assert (pos != NULL);        /* ready_count wrong? */
    ready[p] = pos->next;
    ready_count--;
    if (current_priority != pos->priority)
    {
      current_priority = pos->priority;
      (void) GNUNET_OS_set_process_priority (GNUNET_OS_process_current (),
                                             pos->priority);
    }
    current_lifeness = pos->lifeness;
    active_task = pos;
#if PROFILE_DELAYS
    if (GNUNET_TIME_absolute_get_duration (pos->start_time).rel_value >
        DELAY_THRESHOLD.rel_value)
    {
      LOG (GNUNET_ERROR_TYPE_ERROR, "Task %llu took %llums to be scheduled\n",
           pos->id,
           (unsigned long long)
           GNUNET_TIME_absolute_get_duration (pos->start_time).rel_value);
    }
#endif
    tc.reason = pos->reason;
    tc.read_ready = (pos->read_set == NULL) ? rs : pos->read_set;
    if ((pos->read_fd != -1) &&
        (0 != (pos->reason & GNUNET_SCHEDULER_REASON_READ_READY)))
      GNUNET_NETWORK_fdset_set_native (rs, pos->read_fd);
    tc.write_ready = (pos->write_set == NULL) ? ws : pos->write_set;
    if ((pos->write_fd != -1) &&
        (0 != (pos->reason & GNUNET_SCHEDULER_REASON_WRITE_READY)))
      GNUNET_NETWORK_fdset_set_native (ws, pos->write_fd);
    if (((tc.reason & GNUNET_SCHEDULER_REASON_WRITE_READY) != 0) &&
        (pos->write_fd != -1) &&
        (!GNUNET_NETWORK_fdset_test_native (ws, pos->write_fd)))
      GNUNET_abort ();          // added to ready in previous select loop!
    LOG (GNUNET_ERROR_TYPE_DEBUG, 
	 "Running task: %llu / %p\n", pos->id,
         pos->callback_cls);
    pos->callback (pos->callback_cls, &tc);
#if EXECINFO
    int i;

    for (i = 0; i < pos->num_backtrace_strings; i++)
      LOG (GNUNET_ERROR_TYPE_ERROR, "Task %llu trace %d: %s\n", pos->id, i,
           pos->backtrace_strings[i]);
#endif
    active_task = NULL;
    destroy_task (pos);
    tasks_run++;
  }
  while ((pending == NULL) || (p >= max_priority_added));
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
 * Check if the system is still life. Trigger shutdown if we
 * have tasks, but none of them give us lifeness.
 *
 * @return GNUNET_OK to continue the main loop,
 *         GNUNET_NO to exit
 */
static int
check_lifeness ()
{
  struct Task *t;

  if (ready_count > 0)
    return GNUNET_OK;
  for (t = pending; NULL != t; t = t->next)
    if (t->lifeness == GNUNET_YES)
      return GNUNET_OK;
  for (t = pending_timeout; NULL != t; t = t->next)
    if (t->lifeness == GNUNET_YES)
      return GNUNET_OK;
  if ((NULL != pending) || (NULL != pending_timeout))
  {
    GNUNET_SCHEDULER_shutdown ();
    return GNUNET_OK;
  }
  return GNUNET_NO;
}


/**
 * Initialize and run scheduler.  This function will return when all
 * tasks have completed.  On systems with signals, receiving a SIGTERM
 * (and other similar signals) will cause "GNUNET_SCHEDULER_shutdown"
 * to be run after the active task is complete.  As a result, SIGTERM
 * causes all active tasks to be scheduled with reason
 * "GNUNET_SCHEDULER_REASON_SHUTDOWN".  (However, tasks added
 * afterwards will execute normally!). Note that any particular signal
 * will only shut down one scheduler; applications should always only
 * create a single scheduler.
 *
 * @param task task to run immediately
 * @param task_cls closure of task
 */
void
GNUNET_SCHEDULER_run (GNUNET_SCHEDULER_Task task, void *task_cls)
{
  struct GNUNET_NETWORK_FDSet *rs;
  struct GNUNET_NETWORK_FDSet *ws;
  struct GNUNET_TIME_Relative timeout;
  int ret;
  struct GNUNET_SIGNAL_Context *shc_int;
  struct GNUNET_SIGNAL_Context *shc_term;

#ifndef MINGW
  struct GNUNET_SIGNAL_Context *shc_quit;
  struct GNUNET_SIGNAL_Context *shc_hup;
  struct GNUNET_SIGNAL_Context *shc_pipe;
#endif
  unsigned long long last_tr;
  unsigned int busy_wait_warning;
  const struct GNUNET_DISK_FileHandle *pr;
  char c;

  GNUNET_assert (active_task == NULL);
  rs = GNUNET_NETWORK_fdset_create ();
  ws = GNUNET_NETWORK_fdset_create ();
  GNUNET_assert (shutdown_pipe_handle == NULL);
  shutdown_pipe_handle = GNUNET_DISK_pipe (GNUNET_NO, GNUNET_NO, GNUNET_NO, GNUNET_NO);
  GNUNET_assert (shutdown_pipe_handle != NULL);
  pr = GNUNET_DISK_pipe_handle (shutdown_pipe_handle,
                                GNUNET_DISK_PIPE_END_READ);
  GNUNET_assert (pr != NULL);
  my_pid = getpid ();
  shc_int = GNUNET_SIGNAL_handler_install (SIGINT, &sighandler_shutdown);
  shc_term = GNUNET_SIGNAL_handler_install (SIGTERM, &sighandler_shutdown);
#ifndef MINGW
  shc_pipe = GNUNET_SIGNAL_handler_install (SIGPIPE, &sighandler_pipe);
  shc_quit = GNUNET_SIGNAL_handler_install (SIGQUIT, &sighandler_shutdown);
  shc_hup = GNUNET_SIGNAL_handler_install (SIGHUP, &sighandler_shutdown);
#endif
  current_priority = GNUNET_SCHEDULER_PRIORITY_DEFAULT;
  current_lifeness = GNUNET_YES;
  GNUNET_SCHEDULER_add_continuation (task, task_cls,
                                     GNUNET_SCHEDULER_REASON_STARTUP);
  active_task = (void *) (long) -1;     /* force passing of sanity check */
  GNUNET_SCHEDULER_add_now_with_lifeness (GNUNET_NO,
                                          &GNUNET_OS_install_parent_control_handler,
                                          NULL);
  active_task = NULL;
  last_tr = 0;
  busy_wait_warning = 0;
  while (GNUNET_OK == check_lifeness ())
  {
    GNUNET_NETWORK_fdset_zero (rs);
    GNUNET_NETWORK_fdset_zero (ws);
    timeout = GNUNET_TIME_UNIT_FOREVER_REL;
    update_sets (rs, ws, &timeout);
    GNUNET_NETWORK_fdset_handle_set (rs, pr);
    if (ready_count > 0)
    {
      /* no blocking, more work already ready! */
      timeout = GNUNET_TIME_UNIT_ZERO;
    }
    if (NULL == scheduler_select)
      ret = GNUNET_NETWORK_socket_select (rs, ws, NULL, timeout);
    else
      ret = scheduler_select (scheduler_select_cls, rs, ws, NULL, timeout);
    if (ret == GNUNET_SYSERR)
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
        LOG_STRERROR (GNUNET_ERROR_TYPE_WARNING, "system");
#endif
#endif
      GNUNET_abort ();
      break;
    }
    if ((ret == 0) && (timeout.rel_value == 0) && (busy_wait_warning > 16))
    {
      LOG (GNUNET_ERROR_TYPE_WARNING, _("Looks like we're busy waiting...\n"));
      sleep (1);                /* mitigate */
    }
    check_ready (rs, ws);
    run_ready (rs, ws);
    if (GNUNET_NETWORK_fdset_handle_isset (rs, pr))
    {
      /* consume the signal */
      GNUNET_DISK_file_read (pr, &c, sizeof (c));
      /* mark all active tasks as ready due to shutdown */
      GNUNET_SCHEDULER_shutdown ();
    }
    if (last_tr == tasks_run)
    {
      busy_wait_warning++;
    }
    else
    {
      last_tr = tasks_run;
      busy_wait_warning = 0;
    }
  }
  GNUNET_SIGNAL_handler_uninstall (shc_int);
  GNUNET_SIGNAL_handler_uninstall (shc_term);
#ifndef MINGW
  GNUNET_SIGNAL_handler_uninstall (shc_pipe);
  GNUNET_SIGNAL_handler_uninstall (shc_quit);
  GNUNET_SIGNAL_handler_uninstall (shc_hup);
#endif
  GNUNET_DISK_pipe_close (shutdown_pipe_handle);
  shutdown_pipe_handle = NULL;
  GNUNET_NETWORK_fdset_destroy (rs);
  GNUNET_NETWORK_fdset_destroy (ws);
}


/**
 * Obtain the reason code for why the current task was
 * started.  Will return the same value as
 * the GNUNET_SCHEDULER_TaskContext's reason field.
 *
 * @return reason(s) why the current task is run
 */
enum GNUNET_SCHEDULER_Reason
GNUNET_SCHEDULER_get_reason ()
{
  GNUNET_assert (active_task != NULL);
  return active_task->reason;
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
  struct Task *pos;
  unsigned int ret;

  GNUNET_assert (active_task != NULL);
  if (p == GNUNET_SCHEDULER_PRIORITY_COUNT)
    return ready_count;
  if (p == GNUNET_SCHEDULER_PRIORITY_KEEP)
    p = current_priority;
  ret = 0;
  pos = ready[check_priority (p)];
  while (pos != NULL)
  {
    pos = pos->next;
    ret++;
  }
  return ret;
}


/**
 * Cancel the task with the specified identifier.
 * The task must not yet have run.
 *
 * @param task id of the task to cancel
 * @return original closure of the task
 */
void *
GNUNET_SCHEDULER_cancel (GNUNET_SCHEDULER_TaskIdentifier task)
{
  struct Task *t;
  struct Task *prev;
  enum GNUNET_SCHEDULER_Priority p;
  int to;
  void *ret;

  GNUNET_assert (active_task != NULL);
  to = 0;
  prev = NULL;
  t = pending;
  while (t != NULL)
  {
    if (t->id == task)
      break;
    prev = t;
    t = t->next;
  }
  if (t == NULL)
  {
    prev = NULL;
    to = 1;
    t = pending_timeout;
    while (t != NULL)
    {
      if (t->id == task)
        break;
      prev = t;
      t = t->next;
    }
    if (pending_timeout_last == t)
      pending_timeout_last = NULL;
  }
  p = 0;
  while (t == NULL)
  {
    p++;
    if (p >= GNUNET_SCHEDULER_PRIORITY_COUNT)
    {
      LOG (GNUNET_ERROR_TYPE_ERROR, _("Attempt to cancel dead task %llu!\n"),
           (unsigned long long) task);
      GNUNET_assert (0);
    }
    prev = NULL;
    t = ready[p];
    while (t != NULL)
    {
      if (t->id == task)
      {
        ready_count--;
        break;
      }
      prev = t;
      t = t->next;
    }
  }
  if (prev == NULL)
  {
    if (p == 0)
    {
      if (to == 0)
      {
        pending = t->next;
      }
      else
      {
        pending_timeout = t->next;
      }
    }
    else
    {
      ready[p] = t->next;
    }
  }
  else
  {
    prev->next = t->next;
  }
  ret = t->callback_cls;
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Canceling task: %llu / %p\n", task,
       t->callback_cls);
  destroy_task (t);
  return ret;
}


/**
 * Continue the current execution with the given function.  This is
 * similar to the other "add" functions except that there is no delay
 * and the reason code can be specified.
 *
 * @param task main function of the task
 * @param task_cls closure for 'main'
 * @param reason reason for task invocation
 * @param priority priority to use for the task
 */
void
GNUNET_SCHEDULER_add_continuation_with_priority (GNUNET_SCHEDULER_Task task, void *task_cls,
						 enum GNUNET_SCHEDULER_Reason reason,
						 enum GNUNET_SCHEDULER_Priority priority)
{
  struct Task *t;

#if EXECINFO
  void *backtrace_array[50];
#endif

  GNUNET_assert (NULL != task);
  GNUNET_assert ((active_task != NULL) ||
                 (reason == GNUNET_SCHEDULER_REASON_STARTUP));
  t = GNUNET_malloc (sizeof (struct Task));
#if EXECINFO
  t->num_backtrace_strings = backtrace (backtrace_array, 50);
  t->backtrace_strings =
      backtrace_symbols (backtrace_array, t->num_backtrace_strings);
#endif
  t->read_fd = -1;
  t->write_fd = -1;
  t->callback = task;
  t->callback_cls = task_cls;
  t->id = ++last_id;
#if PROFILE_DELAYS
  t->start_time = GNUNET_TIME_absolute_get ();
#endif
  t->reason = reason;
  t->priority = priority;
  t->lifeness = current_lifeness;
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Adding continuation task: %llu / %p\n", t->id,
       t->callback_cls);
  queue_ready_task (t);
}


/**
 * Continue the current execution with the given function.  This is
 * similar to the other "add" functions except that there is no delay
 * and the reason code can be specified.
 *
 * @param task main function of the task
 * @param task_cls closure for 'main'
 * @param reason reason for task invocation
 */
void
GNUNET_SCHEDULER_add_continuation (GNUNET_SCHEDULER_Task task, void *task_cls,
                                   enum GNUNET_SCHEDULER_Reason reason)
{
  GNUNET_SCHEDULER_add_continuation_with_priority (task, task_cls,
						   reason,
						   GNUNET_SCHEDULER_PRIORITY_DEFAULT);
}


/**
 * Schedule a new task to be run after the specified prerequisite task
 * has completed. It will be run with the DEFAULT priority.
 *
 * @param prerequisite_task run this task after the task with the given
 *        task identifier completes (and any of our other
 *        conditions, such as delay, read or write-readiness
 *        are satisfied).  Use  GNUNET_SCHEDULER_NO_TASK to not have any dependency
 *        on completion of other tasks (this will cause the task to run as
 *        soon as possible).
 * @param task main function of the task
 * @param task_cls closure of task
 * @return unique task identifier for the job
 *         only valid until "task" is started!
 */
GNUNET_SCHEDULER_TaskIdentifier
GNUNET_SCHEDULER_add_after (GNUNET_SCHEDULER_TaskIdentifier prerequisite_task,
                            GNUNET_SCHEDULER_Task task, void *task_cls)
{
  return GNUNET_SCHEDULER_add_select (GNUNET_SCHEDULER_PRIORITY_DEFAULT,
                                      prerequisite_task, GNUNET_TIME_UNIT_ZERO,
                                      NULL, NULL, task, task_cls);
}


/**
 * Schedule a new task to be run with a specified priority.
 *
 * @param prio how important is the new task?
 * @param task main function of the task
 * @param task_cls closure of task
 * @return unique task identifier for the job
 *         only valid until "task" is started!
 */
GNUNET_SCHEDULER_TaskIdentifier
GNUNET_SCHEDULER_add_with_priority (enum GNUNET_SCHEDULER_Priority prio,
                                    GNUNET_SCHEDULER_Task task, void *task_cls)
{
  return GNUNET_SCHEDULER_add_select (prio, GNUNET_SCHEDULER_NO_TASK,
                                      GNUNET_TIME_UNIT_ZERO, NULL, NULL, task,
                                      task_cls);
}



/**
 * Schedule a new task to be run with a specified delay.  The task
 * will be scheduled for execution once the delay has expired.
 *
 * @param delay when should this operation time out? Use
 *        GNUNET_TIME_UNIT_FOREVER_REL for "on shutdown"
 * @param priority priority to use for the task
 * @param task main function of the task
 * @param task_cls closure of task
 * @return unique task identifier for the job
 *         only valid until "task" is started!
 */
GNUNET_SCHEDULER_TaskIdentifier
GNUNET_SCHEDULER_add_delayed_with_priority (struct GNUNET_TIME_Relative delay,
					    enum GNUNET_SCHEDULER_Priority priority,
					    GNUNET_SCHEDULER_Task task, void *task_cls)
{
  struct Task *t;
  struct Task *pos;
  struct Task *prev;

#if EXECINFO
  void *backtrace_array[MAX_TRACE_DEPTH];
#endif

  GNUNET_assert (active_task != NULL);
  GNUNET_assert (NULL != task);
  t = GNUNET_malloc (sizeof (struct Task));
  t->callback = task;
  t->callback_cls = task_cls;
#if EXECINFO
  t->num_backtrace_strings = backtrace (backtrace_array, MAX_TRACE_DEPTH);
  t->backtrace_strings =
      backtrace_symbols (backtrace_array, t->num_backtrace_strings);
#endif
  t->read_fd = -1;
  t->write_fd = -1;
  t->id = ++last_id;
#if PROFILE_DELAYS
  t->start_time = GNUNET_TIME_absolute_get ();
#endif
  t->timeout = GNUNET_TIME_relative_to_absolute (delay);
  t->priority = priority;
  t->lifeness = current_lifeness;
  /* try tail first (optimization in case we are
   * appending to a long list of tasks with timeouts) */
  prev = pending_timeout_last;
  if (prev != NULL)
  {
    if (prev->timeout.abs_value > t->timeout.abs_value)
      prev = NULL;
    else
      pos = prev->next;         /* heuristic success! */
  }
  if (prev == NULL)
  {
    /* heuristic failed, do traversal of timeout list */
    pos = pending_timeout;
  }
  while ((pos != NULL) &&
         ((pos->timeout.abs_value <= t->timeout.abs_value) ||
          (pos->reason != 0)))
  {
    prev = pos;
    pos = pos->next;
  }
  if (prev == NULL)
    pending_timeout = t;
  else
    prev->next = t;
  t->next = pos;
  /* hyper-optimization... */
  pending_timeout_last = t;

  LOG (GNUNET_ERROR_TYPE_DEBUG, "Adding task: %llu / %p\n", t->id,
       t->callback_cls);
#if EXECINFO
  int i;

  for (i = 0; i < t->num_backtrace_strings; i++)
    LOG (GNUNET_ERROR_TYPE_DEBUG, "Task %llu trace %d: %s\n", t->id, i,
         t->backtrace_strings[i]);
#endif
  return t->id;
}


/**
 * Schedule a new task to be run with a specified delay.  The task
 * will be scheduled for execution once the delay has expired. It
 * will be run with the DEFAULT priority.
 *
 * @param delay when should this operation time out? Use
 *        GNUNET_TIME_UNIT_FOREVER_REL for "on shutdown"
 * @param task main function of the task
 * @param task_cls closure of task
 * @return unique task identifier for the job
 *         only valid until "task" is started!
 */
GNUNET_SCHEDULER_TaskIdentifier
GNUNET_SCHEDULER_add_delayed (struct GNUNET_TIME_Relative delay,
                              GNUNET_SCHEDULER_Task task, void *task_cls)
{
  return GNUNET_SCHEDULER_add_delayed_with_priority (delay,
						     GNUNET_SCHEDULER_PRIORITY_DEFAULT,
						     task, task_cls);
}


/**
 * Schedule a new task to be run as soon as possible. The task
 * will be run with the DEFAULT priority.
 *
 * @param task main function of the task
 * @param task_cls closure of task
 * @return unique task identifier for the job
 *         only valid until "task" is started!
 */
GNUNET_SCHEDULER_TaskIdentifier
GNUNET_SCHEDULER_add_now (GNUNET_SCHEDULER_Task task, void *task_cls)
{
  return GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_ZERO, task, task_cls);
}


/**
 * Schedule a new task to be run as soon as possible with the
 * (transitive) ignore-shutdown flag either explicitly set or
 * explicitly enabled.  This task (and all tasks created from it,
 * other than by another call to this function) will either count or
 * not count for the 'lifeness' of the process.  This API is only
 * useful in a few special cases.
 *
 * @param lifeness GNUNET_YES if the task counts for lifeness, GNUNET_NO if not.
 * @param task main function of the task
 * @param task_cls closure of task
 * @return unique task identifier for the job
 *         only valid until "task" is started!
 */
GNUNET_SCHEDULER_TaskIdentifier
GNUNET_SCHEDULER_add_now_with_lifeness (int lifeness,
                                        GNUNET_SCHEDULER_Task task,
                                        void *task_cls)
{
  GNUNET_SCHEDULER_TaskIdentifier ret;

  ret =
      GNUNET_SCHEDULER_add_select (GNUNET_SCHEDULER_PRIORITY_DEFAULT,
                                   GNUNET_SCHEDULER_NO_TASK,
                                   GNUNET_TIME_UNIT_ZERO, NULL, NULL, task,
                                   task_cls);
  GNUNET_assert (pending->id == ret);
  pending->lifeness = lifeness;
  return ret;
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
 *     || any-ws-ready
 *     || shutdown-active )
 * </code>
 *
 * @param delay how long should we wait? Use GNUNET_TIME_UNIT_FOREVER_REL for "forever",
 *        which means that the task will only be run after we receive SIGTERM
 * @param priority priority to use
 * @param rfd file descriptor we want to read (can be -1)
 * @param wfd file descriptors we want to write (can be -1)
 * @param task main function of the task
 * @param task_cls closure of task
 * @return unique task identifier for the job
 *         only valid until "task" is started!
 */
#ifndef MINGW
static GNUNET_SCHEDULER_TaskIdentifier
add_without_sets (struct GNUNET_TIME_Relative delay, 
		  enum GNUNET_SCHEDULER_Priority priority,
		  int rfd, int wfd,
                  GNUNET_SCHEDULER_Task task, void *task_cls)
{
  struct Task *t;

#if EXECINFO
  void *backtrace_array[MAX_TRACE_DEPTH];
#endif

  GNUNET_assert (active_task != NULL);
  GNUNET_assert (NULL != task);
  t = GNUNET_malloc (sizeof (struct Task));
  t->callback = task;
  t->callback_cls = task_cls;
#if EXECINFO
  t->num_backtrace_strings = backtrace (backtrace_array, MAX_TRACE_DEPTH);
  t->backtrace_strings =
      backtrace_symbols (backtrace_array, t->num_backtrace_strings);
#endif
#if DEBUG_FDS
  if (-1 != rfd)
  {
    int flags = fcntl (rfd, F_GETFD);

    if ((flags == -1) && (errno == EBADF))
    {
      LOG (GNUNET_ERROR_TYPE_ERROR, "Got invalid file descriptor %d!\n", rfd);
#if EXECINFO
      int i;

      for (i = 0; i < t->num_backtrace_strings; i++)
        LOG (GNUNET_ERROR_TYPE_DEBUG, "Trace: %s\n", t->backtrace_strings[i]);
#endif
      GNUNET_assert (0);
    }
  }
  if (-1 != wfd)
  {
    int flags = fcntl (wfd, F_GETFD);

    if (flags == -1 && errno == EBADF)
    {
      LOG (GNUNET_ERROR_TYPE_ERROR, "Got invalid file descriptor %d!\n", wfd);
#if EXECINFO
      int i;

      for (i = 0; i < t->num_backtrace_strings; i++)
        LOG (GNUNET_ERROR_TYPE_DEBUG, "Trace: %s\n", t->backtrace_strings[i]);
#endif
      GNUNET_assert (0);
    }
  }
#endif
  t->read_fd = rfd;
  GNUNET_assert (wfd >= -1);
  t->write_fd = wfd;
  t->id = ++last_id;
#if PROFILE_DELAYS
  t->start_time = GNUNET_TIME_absolute_get ();
#endif
  t->prereq_id = GNUNET_SCHEDULER_NO_TASK;
  t->timeout = GNUNET_TIME_relative_to_absolute (delay);
  t->priority = check_priority ((priority == GNUNET_SCHEDULER_PRIORITY_KEEP) ? current_priority : priority);
  t->lifeness = current_lifeness;
  t->next = pending;
  pending = t;
  max_priority_added = GNUNET_MAX (max_priority_added, t->priority);
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Adding task: %llu / %p\n", t->id,
       t->callback_cls);
#if EXECINFO
  int i;

  for (i = 0; i < t->num_backtrace_strings; i++)
    LOG (GNUNET_ERROR_TYPE_DEBUG, "Task %llu trace %d: %s\n", t->id, i,
         t->backtrace_strings[i]);
#endif
  return t->id;
}
#endif



/**
 * Schedule a new task to be run with a specified delay or when the
 * specified file descriptor is ready for reading.  The delay can be
 * used as a timeout on the socket being ready.  The task will be
 * scheduled for execution once either the delay has expired or the
 * socket operation is ready.  It will be run with the DEFAULT priority.
 *
 * @param delay when should this operation time out? Use
 *        GNUNET_TIME_UNIT_FOREVER_REL for "on shutdown"
 * @param rfd read file-descriptor
 * @param task main function of the task
 * @param task_cls closure of task
 * @return unique task identifier for the job
 *         only valid until "task" is started!
 */
GNUNET_SCHEDULER_TaskIdentifier
GNUNET_SCHEDULER_add_read_net (struct GNUNET_TIME_Relative delay,
                               struct GNUNET_NETWORK_Handle *rfd,
                               GNUNET_SCHEDULER_Task task, void *task_cls)
{
#if MINGW
  struct GNUNET_NETWORK_FDSet *rs;
  GNUNET_SCHEDULER_TaskIdentifier ret;

  GNUNET_assert (rfd != NULL);
  rs = GNUNET_NETWORK_fdset_create ();
  GNUNET_NETWORK_fdset_set (rs, rfd);
  ret =
    GNUNET_SCHEDULER_add_select (GNUNET_SCHEDULER_PRIORITY_DEFAULT,
				 GNUNET_SCHEDULER_NO_TASK, delay, rs, NULL,
				 task, task_cls);
  GNUNET_NETWORK_fdset_destroy (rs);
  return ret;
#else
  return add_without_sets (delay, 
			   GNUNET_SCHEDULER_PRIORITY_DEFAULT,
			   GNUNET_NETWORK_get_fd (rfd), -1, task,
                           task_cls);
#endif
}


/**
 * Schedule a new task to be run with a specified delay or when the
 * specified file descriptor is ready for writing.  The delay can be
 * used as a timeout on the socket being ready.  The task will be
 * scheduled for execution once either the delay has expired or the
 * socket operation is ready.  It will be run with the priority of
 * the calling task.
 *
 * @param delay when should this operation time out? Use
 *        GNUNET_TIME_UNIT_FOREVER_REL for "on shutdown"
 * @param wfd write file-descriptor
 * @param task main function of the task
 * @param task_cls closure of task
 * @return unique task identifier for the job
 *         only valid until "task" is started!
 */
GNUNET_SCHEDULER_TaskIdentifier
GNUNET_SCHEDULER_add_write_net (struct GNUNET_TIME_Relative delay,
                                struct GNUNET_NETWORK_Handle *wfd,
                                GNUNET_SCHEDULER_Task task, void *task_cls)
{
#if MINGW
  struct GNUNET_NETWORK_FDSet *ws;
  GNUNET_SCHEDULER_TaskIdentifier ret;

  GNUNET_assert (wfd != NULL);
  ws = GNUNET_NETWORK_fdset_create ();
  GNUNET_NETWORK_fdset_set (ws, wfd);
  ret =
    GNUNET_SCHEDULER_add_select (GNUNET_SCHEDULER_PRIORITY_DEFAULT,
				 GNUNET_SCHEDULER_NO_TASK, delay, NULL, ws,
                                   task, task_cls);
  GNUNET_NETWORK_fdset_destroy (ws);
  return ret;
#else
  GNUNET_assert (GNUNET_NETWORK_get_fd (wfd) >= 0);
  return add_without_sets (delay, 
			   GNUNET_SCHEDULER_PRIORITY_DEFAULT,
			   -1, GNUNET_NETWORK_get_fd (wfd), task,
                           task_cls);
#endif
}


/**
 * Schedule a new task to be run with a specified delay or when the
 * specified file descriptor is ready for reading.  The delay can be
 * used as a timeout on the socket being ready.  The task will be
 * scheduled for execution once either the delay has expired or the
 * socket operation is ready. It will be run with the DEFAULT priority.
 *
 * @param delay when should this operation time out? Use
 *        GNUNET_TIME_UNIT_FOREVER_REL for "on shutdown"
 * @param rfd read file-descriptor
 * @param task main function of the task
 * @param task_cls closure of task
 * @return unique task identifier for the job
 *         only valid until "task" is started!
 */
GNUNET_SCHEDULER_TaskIdentifier
GNUNET_SCHEDULER_add_read_file (struct GNUNET_TIME_Relative delay,
                                const struct GNUNET_DISK_FileHandle *rfd,
                                GNUNET_SCHEDULER_Task task, void *task_cls)
{
#if MINGW
  struct GNUNET_NETWORK_FDSet *rs;
  GNUNET_SCHEDULER_TaskIdentifier ret;

  GNUNET_assert (rfd != NULL);
  rs = GNUNET_NETWORK_fdset_create ();
  GNUNET_NETWORK_fdset_handle_set (rs, rfd);
  ret =
      GNUNET_SCHEDULER_add_select (GNUNET_SCHEDULER_PRIORITY_DEFAULT,
                                   GNUNET_SCHEDULER_NO_TASK, delay, rs, NULL,
                                   task, task_cls);
  GNUNET_NETWORK_fdset_destroy (rs);
  return ret;
#else
  int fd;

  GNUNET_DISK_internal_file_handle_ (rfd, &fd, sizeof (int));
  return add_without_sets (delay, 
			   GNUNET_SCHEDULER_PRIORITY_DEFAULT,
			   fd, -1, task, task_cls);

#endif
}


/**
 * Schedule a new task to be run with a specified delay or when the
 * specified file descriptor is ready for writing.  The delay can be
 * used as a timeout on the socket being ready.  The task will be
 * scheduled for execution once either the delay has expired or the
 * socket operation is ready. It will be run with the DEFAULT priority.
 *
 * @param delay when should this operation time out? Use
 *        GNUNET_TIME_UNIT_FOREVER_REL for "on shutdown"
 * @param wfd write file-descriptor
 * @param task main function of the task
 * @param task_cls closure of task
 * @return unique task identifier for the job
 *         only valid until "task" is started!
 */
GNUNET_SCHEDULER_TaskIdentifier
GNUNET_SCHEDULER_add_write_file (struct GNUNET_TIME_Relative delay,
                                 const struct GNUNET_DISK_FileHandle *wfd,
                                 GNUNET_SCHEDULER_Task task, void *task_cls)
{
#if MINGW
  struct GNUNET_NETWORK_FDSet *ws;
  GNUNET_SCHEDULER_TaskIdentifier ret;

  GNUNET_assert (wfd != NULL);
  ws = GNUNET_NETWORK_fdset_create ();
  GNUNET_NETWORK_fdset_handle_set (ws, wfd);
  ret =
      GNUNET_SCHEDULER_add_select (GNUNET_SCHEDULER_PRIORITY_DEFAULT,
                                   GNUNET_SCHEDULER_NO_TASK, delay, NULL, ws,
                                   task, task_cls);
  GNUNET_NETWORK_fdset_destroy (ws);
  return ret;
#else
  int fd;

  GNUNET_DISK_internal_file_handle_ (wfd, &fd, sizeof (int));
  GNUNET_assert (fd >= 0);
  return add_without_sets (delay, 
			   GNUNET_SCHEDULER_PRIORITY_DEFAULT,
			   -1, fd, task, task_cls);

#endif
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
 *     || any-ws-ready
 *     || (shutdown-active && run-on-shutdown) )
 * </code>
 *
 * @param prio how important is this task?
 * @param prerequisite_task run this task after the task with the given
 *        task identifier completes (and any of our other
 *        conditions, such as delay, read or write-readiness
 *        are satisfied).  Use GNUNET_SCHEDULER_NO_TASK to not have any dependency
 *        on completion of other tasks.
 * @param delay how long should we wait? Use GNUNET_TIME_UNIT_FOREVER_REL for "forever",
 *        which means that the task will only be run after we receive SIGTERM
 * @param rs set of file descriptors we want to read (can be NULL)
 * @param ws set of file descriptors we want to write (can be NULL)
 * @param task main function of the task
 * @param task_cls closure of task
 * @return unique task identifier for the job
 *         only valid until "task" is started!
 */
GNUNET_SCHEDULER_TaskIdentifier
GNUNET_SCHEDULER_add_select (enum GNUNET_SCHEDULER_Priority prio,
                             GNUNET_SCHEDULER_TaskIdentifier prerequisite_task,
                             struct GNUNET_TIME_Relative delay,
                             const struct GNUNET_NETWORK_FDSet *rs,
                             const struct GNUNET_NETWORK_FDSet *ws,
                             GNUNET_SCHEDULER_Task task, void *task_cls)
{
  struct Task *t;

#if EXECINFO
  void *backtrace_array[MAX_TRACE_DEPTH];
#endif

  GNUNET_assert (active_task != NULL);
  GNUNET_assert (NULL != task);
  t = GNUNET_malloc (sizeof (struct Task));
  t->callback = task;
  t->callback_cls = task_cls;
#if EXECINFO
  t->num_backtrace_strings = backtrace (backtrace_array, MAX_TRACE_DEPTH);
  t->backtrace_strings =
      backtrace_symbols (backtrace_array, t->num_backtrace_strings);
#endif
  t->read_fd = -1;
  t->write_fd = -1;
  if (rs != NULL)
  {
    t->read_set = GNUNET_NETWORK_fdset_create ();
    GNUNET_NETWORK_fdset_copy (t->read_set, rs);
  }
  if (ws != NULL)
  {
    t->write_set = GNUNET_NETWORK_fdset_create ();
    GNUNET_NETWORK_fdset_copy (t->write_set, ws);
  }
  t->id = ++last_id;
#if PROFILE_DELAYS
  t->start_time = GNUNET_TIME_absolute_get ();
#endif
  t->prereq_id = prerequisite_task;
  t->timeout = GNUNET_TIME_relative_to_absolute (delay);
  t->priority =
      check_priority ((prio ==
                       GNUNET_SCHEDULER_PRIORITY_KEEP) ? current_priority :
                      prio);
  t->lifeness = current_lifeness;
  t->next = pending;
  pending = t;
  max_priority_added = GNUNET_MAX (max_priority_added, t->priority);
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Adding task: %llu / %p\n", t->id,
       t->callback_cls);
#if EXECINFO
  int i;

  for (i = 0; i < t->num_backtrace_strings; i++)
    LOG (GNUNET_ERROR_TYPE_DEBUG, "Task %llu trace %d: %s\n", t->id, i,
         t->backtrace_strings[i]);
#endif
  return t->id;
}

/* end of scheduler.c */

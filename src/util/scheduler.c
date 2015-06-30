/*
      This file is part of GNUnet
      Copyright (C) 2009-2013 Christian Grothoff (and other contributing authors)

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
 * Head of list of tasks waiting for an event.
 */
static struct GNUNET_SCHEDULER_Task *pending_head;

/**
 * Tail of list of tasks waiting for an event.
 */
static struct GNUNET_SCHEDULER_Task *pending_tail;

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
 * Update all sets and timeout for select.
 *
 * @param rs read-set, set to all FDs we would like to read (updated)
 * @param ws write-set, set to all FDs we would like to write (updated)
 * @param timeout next timeout (updated)
 */
static void
update_sets (struct GNUNET_NETWORK_FDSet *rs,
             struct GNUNET_NETWORK_FDSet *ws,
             struct GNUNET_TIME_Relative *timeout)
{
  struct GNUNET_SCHEDULER_Task *pos;
  struct GNUNET_TIME_Absolute now;
  struct GNUNET_TIME_Relative to;

  now = GNUNET_TIME_absolute_get ();
  pos = pending_timeout_head;
  if (NULL != pos)
  {
    to = GNUNET_TIME_absolute_get_difference (now, pos->timeout);
    if (timeout->rel_value_us > to.rel_value_us)
      *timeout = to;
    if (0 != pos->reason)
      *timeout = GNUNET_TIME_UNIT_ZERO;
  }
  for (pos = pending_head; NULL != pos; pos = pos->next)
  {
    if (pos->timeout.abs_value_us != GNUNET_TIME_UNIT_FOREVER_ABS.abs_value_us)
    {
      to = GNUNET_TIME_absolute_get_difference (now, pos->timeout);
      if (timeout->rel_value_us > to.rel_value_us)
        *timeout = to;
    }
    if (-1 != pos->read_fd)
      GNUNET_NETWORK_fdset_set_native (rs, pos->read_fd);
    if (-1 != pos->write_fd)
      GNUNET_NETWORK_fdset_set_native (ws, pos->write_fd);
    if (NULL != pos->read_set)
      GNUNET_NETWORK_fdset_add (rs, pos->read_set);
    if (NULL != pos->write_set)
      GNUNET_NETWORK_fdset_add (ws, pos->write_set);
    if (0 != pos->reason)
      *timeout = GNUNET_TIME_UNIT_ZERO;
  }
}


/**
 * Check if the ready set overlaps with the set we want to have ready.
 * If so, update the want set (set all FDs that are ready).  If not,
 * return #GNUNET_NO.
 *
 * @param ready set that is ready
 * @param want set that we want to be ready
 * @return #GNUNET_YES if there was some overlap
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
 * @return #GNUNET_YES if we can run it, #GNUNET_NO if not.
 */
static int
is_ready (struct GNUNET_SCHEDULER_Task *task,
          struct GNUNET_TIME_Absolute now,
          const struct GNUNET_NETWORK_FDSet *rs,
          const struct GNUNET_NETWORK_FDSet *ws)
{
  enum GNUNET_SCHEDULER_Reason reason;

  reason = task->reason;
  if (now.abs_value_us >= task->timeout.abs_value_us)
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
  if (0 == reason)
    return GNUNET_NO;           /* not ready */
  reason |= GNUNET_SCHEDULER_REASON_PREREQ_DONE;
  task->reason = reason;
  return GNUNET_YES;
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

  if (0 != (task->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN))
    p = task->priority = GNUNET_SCHEDULER_PRIORITY_SHUTDOWN;
  GNUNET_CONTAINER_DLL_insert (ready_head[p],
                               ready_tail[p],
                               task);
  task->in_ready_list = GNUNET_YES;
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
  struct GNUNET_SCHEDULER_Task *pos;
  struct GNUNET_SCHEDULER_Task *next;
  struct GNUNET_TIME_Absolute now;

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
  pos = pending_head;
  while (NULL != pos)
  {
    next = pos->next;
    if (GNUNET_YES == is_ready (pos, now, rs, ws))
    {
      GNUNET_CONTAINER_DLL_remove (pending_head,
                                   pending_tail,
                                   pos);
      queue_ready_task (pos);
    }
    pos = next;
  }
}


/**
 * Request the shutdown of a scheduler.  Marks all currently
 * pending tasks as ready because of shutdown.  This will
 * cause all tasks to run (as soon as possible, respecting
 * priorities and prerequisite tasks).  Note that tasks
 * scheduled AFTER this call may still be delayed arbitrarily.
 *
 * Note that we don't move the tasks into the ready queue yet;
 * check_ready() will do that later, possibly adding additional
 * readiness-factors
 */
void
GNUNET_SCHEDULER_shutdown ()
{
  struct GNUNET_SCHEDULER_Task *pos;
  int i;

  for (pos = pending_timeout_head; NULL != pos; pos = pos->next)
    pos->reason |= GNUNET_SCHEDULER_REASON_SHUTDOWN;
  for (pos = pending_head; NULL != pos; pos = pos->next)
    pos->reason |= GNUNET_SCHEDULER_REASON_SHUTDOWN;
  for (i = 0; i < GNUNET_SCHEDULER_PRIORITY_COUNT; i++)
    for (pos = ready_head[i]; NULL != pos; pos = pos->next)
      pos->reason |= GNUNET_SCHEDULER_REASON_SHUTDOWN;
}


/**
 * Destroy a task (release associated resources)
 *
 * @param t task to destroy
 */
static void
destroy_task (struct GNUNET_SCHEDULER_Task *t)
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
run_ready (struct GNUNET_NETWORK_FDSet *rs,
           struct GNUNET_NETWORK_FDSet *ws)
{
  enum GNUNET_SCHEDULER_Priority p;
  struct GNUNET_SCHEDULER_Task *pos;
  struct GNUNET_SCHEDULER_TaskContext tc;

  max_priority_added = GNUNET_SCHEDULER_PRIORITY_KEEP;
  do
  {
    if (0 == ready_count)
      return;
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
    tc.read_ready = (NULL == pos->read_set) ? rs : pos->read_set;
    if ((-1 != pos->read_fd) &&
        (0 != (pos->reason & GNUNET_SCHEDULER_REASON_READ_READY)))
      GNUNET_NETWORK_fdset_set_native (rs, pos->read_fd);
    tc.write_ready = (NULL == pos->write_set) ? ws : pos->write_set;
    if ((-1 != pos->write_fd) &&
        (0 != (pos->reason & GNUNET_SCHEDULER_REASON_WRITE_READY)))
      GNUNET_NETWORK_fdset_set_native (ws, pos->write_fd);
    if ((0 != (tc.reason & GNUNET_SCHEDULER_REASON_WRITE_READY)) &&
        (-1 != pos->write_fd) &&
        (!GNUNET_NETWORK_fdset_test_native (ws, pos->write_fd)))
      GNUNET_assert (0);          // added to ready in previous select loop!
    LOG (GNUNET_ERROR_TYPE_DEBUG,
	 "Running task: %p\n",
         pos);
    pos->callback (pos->callback_cls, &tc);
#if EXECINFO
    unsigned int i;

    for (i = 0; i < pos->num_backtrace_strings; i++)
      LOG (GNUNET_ERROR_TYPE_DEBUG,
           "Task %p trace %u: %s\n",
           pos,
           i,
           pos->backtrace_strings[i]);
#endif
    active_task = NULL;
    destroy_task (pos);
    tasks_run++;
  }
  while ((NULL == pending_head) || (p >= max_priority_added));
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
 * Check if the system is still life. Trigger shutdown if we
 * have tasks, but none of them give us lifeness.
 *
 * @return #GNUNET_OK to continue the main loop,
 *         #GNUNET_NO to exit
 */
static int
check_lifeness ()
{
  struct GNUNET_SCHEDULER_Task *t;

  if (ready_count > 0)
    return GNUNET_OK;
  for (t = pending_head; NULL != t; t = t->next)
    if (t->lifeness == GNUNET_YES)
      return GNUNET_OK;
  for (t = pending_timeout_head; NULL != t; t = t->next)
    if (t->lifeness == GNUNET_YES)
      return GNUNET_OK;
  if ((NULL != pending_head) || (NULL != pending_timeout_head))
  {
    GNUNET_SCHEDULER_shutdown ();
    return GNUNET_OK;
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
  struct GNUNET_NETWORK_FDSet *rs;
  struct GNUNET_NETWORK_FDSet *ws;
  struct GNUNET_TIME_Relative timeout;
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
  unsigned long long last_tr;
  unsigned int busy_wait_warning;
  const struct GNUNET_DISK_FileHandle *pr;
  char c;

  GNUNET_assert (NULL == active_task);
  rs = GNUNET_NETWORK_fdset_create ();
  ws = GNUNET_NETWORK_fdset_create ();
  GNUNET_assert (NULL == shutdown_pipe_handle);
  shutdown_pipe_handle = GNUNET_DISK_pipe (GNUNET_NO,
                                           GNUNET_NO,
                                           GNUNET_NO,
                                           GNUNET_NO);
  GNUNET_assert (NULL != shutdown_pipe_handle);
  pr = GNUNET_DISK_pipe_handle (shutdown_pipe_handle,
                                GNUNET_DISK_PIPE_END_READ);
  GNUNET_assert (NULL != pr);
  my_pid = getpid ();
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Registering signal handlers\n");
  shc_int = GNUNET_SIGNAL_handler_install (SIGINT, &sighandler_shutdown);
  shc_term = GNUNET_SIGNAL_handler_install (SIGTERM, &sighandler_shutdown);
#if (SIGTERM != GNUNET_TERM_SIG)
  shc_gterm = GNUNET_SIGNAL_handler_install (GNUNET_TERM_SIG, &sighandler_shutdown);
#endif
#ifndef MINGW
  shc_pipe = GNUNET_SIGNAL_handler_install (SIGPIPE, &sighandler_pipe);
  shc_quit = GNUNET_SIGNAL_handler_install (SIGQUIT, &sighandler_shutdown);
  shc_hup = GNUNET_SIGNAL_handler_install (SIGHUP, &sighandler_shutdown);
#endif
  current_priority = GNUNET_SCHEDULER_PRIORITY_DEFAULT;
  current_lifeness = GNUNET_YES;
  GNUNET_SCHEDULER_add_continuation (task,
                                     task_cls,
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
      ret = GNUNET_NETWORK_socket_select (rs,
                                          ws,
                                          NULL,
                                          timeout);
    else
      ret = scheduler_select (scheduler_select_cls,
                              rs,
                              ws,
                              NULL,
                              timeout);
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
        LOG_STRERROR (GNUNET_ERROR_TYPE_WARNING,
                      "system");
#endif
#endif
#if DEBUG_FDS
      struct GNUNET_SCHEDULER_Task *t;

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
#if EXECINFO
              unsigned int i;

              for (i = 0; i < t->num_backtrace_strings; i++)
                LOG (GNUNET_ERROR_TYPE_ERROR,
                     "Trace: %s\n",
                     t->backtrace_strings[i]);
#endif
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
#if EXECINFO
                unsigned int i;

                for (i = 0; i < t->num_backtrace_strings; i++)
                  LOG (GNUNET_ERROR_TYPE_DEBUG,
                       "Trace: %s\n",
                       t->backtrace_strings[i]);
#endif
              }
          }
      }
#endif
      GNUNET_assert (0);
      break;
    }

    if ( (0 == ret) &&
         (0 == timeout.rel_value_us) &&
         (busy_wait_warning > 16) )
    {
      LOG (GNUNET_ERROR_TYPE_WARNING,
           "Looks like we're busy waiting...\n");
      short_wait (100);                /* mitigate */
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
      short_wait (1);
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
  GNUNET_NETWORK_fdset_destroy (rs);
  GNUNET_NETWORK_fdset_destroy (ws);
}


/**
 * Obtain the reason code for why the current task was
 * started.  Will return the same value as
 * the `struct GNUNET_SCHEDULER_TaskContext`'s reason field.
 *
 * @return reason(s) why the current task is run
 */
enum GNUNET_SCHEDULER_Reason
GNUNET_SCHEDULER_get_reason ()
{
  GNUNET_assert (NULL != active_task);
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


/**
 * Cancel the task with the specified identifier.
 * The task must not yet have run.
 *
 * @param task id of the task to cancel
 * @return original closure of the task
 */
void *
GNUNET_SCHEDULER_cancel (struct GNUNET_SCHEDULER_Task *task)
{
  enum GNUNET_SCHEDULER_Priority p;
  void *ret;

  GNUNET_assert (NULL != active_task);
  if (! task->in_ready_list)
  {
    if ( (-1 == task->read_fd) &&
         (-1 == task->write_fd) &&
         (NULL == task->read_set) &&
         (NULL == task->write_set) )
    {
      GNUNET_CONTAINER_DLL_remove (pending_timeout_head,
                                   pending_timeout_tail,
                                   task);
      if (task == pending_timeout_last)
        pending_timeout_last = NULL;
    }
    else
    {
      GNUNET_CONTAINER_DLL_remove (pending_head,
                                   pending_tail,
                                   task);
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
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Canceling task %p\n",
       task);
  destroy_task (task);
  return ret;
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
GNUNET_SCHEDULER_add_continuation_with_priority (GNUNET_SCHEDULER_TaskCallback task,
                                                 void *task_cls,
						 enum GNUNET_SCHEDULER_Reason reason,
						 enum GNUNET_SCHEDULER_Priority priority)
{
  struct GNUNET_SCHEDULER_Task *t;

#if EXECINFO
  void *backtrace_array[50];
#endif

  GNUNET_assert (NULL != task);
  GNUNET_assert ((NULL != active_task) ||
                 (GNUNET_SCHEDULER_REASON_STARTUP == reason));
  t = GNUNET_new (struct GNUNET_SCHEDULER_Task);
#if EXECINFO
  t->num_backtrace_strings = backtrace (backtrace_array, 50);
  t->backtrace_strings =
      backtrace_symbols (backtrace_array, t->num_backtrace_strings);
#endif
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
  queue_ready_task (t);
}


/**
 * Continue the current execution with the given function.  This is
 * similar to the other "add" functions except that there is no delay
 * and the reason code can be specified.
 *
 * @param task main function of the task
 * @param task_cls closure for @a task
 * @param reason reason for task invocation
 */
void
GNUNET_SCHEDULER_add_continuation (GNUNET_SCHEDULER_TaskCallback task, void *task_cls,
                                   enum GNUNET_SCHEDULER_Reason reason)
{
  GNUNET_SCHEDULER_add_continuation_with_priority (task, task_cls,
						   reason,
						   GNUNET_SCHEDULER_PRIORITY_DEFAULT);
}


/**
 * Schedule a new task to be run with a specified delay.  The task
 * will be scheduled for execution once the delay has expired.
 *
 * @param delay when should this operation time out? Use
 *        #GNUNET_TIME_UNIT_FOREVER_REL for "on shutdown"
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
  struct GNUNET_SCHEDULER_Task *t;
  struct GNUNET_SCHEDULER_Task *pos;
  struct GNUNET_SCHEDULER_Task *prev;

#if EXECINFO
  void *backtrace_array[MAX_TRACE_DEPTH];
#endif

  GNUNET_assert (NULL != active_task);
  GNUNET_assert (NULL != task);
  t = GNUNET_new (struct GNUNET_SCHEDULER_Task);
  t->callback = task;
  t->callback_cls = task_cls;
#if EXECINFO
  t->num_backtrace_strings = backtrace (backtrace_array, MAX_TRACE_DEPTH);
  t->backtrace_strings =
      backtrace_symbols (backtrace_array, t->num_backtrace_strings);
#endif
  t->read_fd = -1;
  t->write_fd = -1;
#if PROFILE_DELAYS
  t->start_time = GNUNET_TIME_absolute_get ();
#endif
  t->timeout = GNUNET_TIME_relative_to_absolute (delay);
  t->priority = priority;
  t->lifeness = current_lifeness;
  /* try tail first (optimization in case we are
   * appending to a long list of tasks with timeouts) */
  if (0 == delay.rel_value_us)
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
    /* finally, update heuristic insertion point to last insertion... */
    pending_timeout_last = t;
  }

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Adding task: %p\n",
       t);
#if EXECINFO
  unsigned int i;

  for (i = 0; i < t->num_backtrace_strings; i++)
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Task %p trace %d: %s\n",
         t,
         i,
         t->backtrace_strings[i]);
#endif
  return t;
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
struct GNUNET_SCHEDULER_Task *
GNUNET_SCHEDULER_add_delayed (struct GNUNET_TIME_Relative delay,
                              GNUNET_SCHEDULER_TaskCallback task, void *task_cls)
{
  return GNUNET_SCHEDULER_add_delayed_with_priority (delay,
						     GNUNET_SCHEDULER_PRIORITY_DEFAULT,
						     task, task_cls);
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
 *         only valid until "task" is started!
 */
struct GNUNET_SCHEDULER_Task *
GNUNET_SCHEDULER_add_now (GNUNET_SCHEDULER_TaskCallback task, void *task_cls)
{
  return GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_ZERO, task, task_cls);
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
 * @param delay how long should we wait? Use #GNUNET_TIME_UNIT_FOREVER_REL for "forever",
 *        which means that the task will only be run after we receive SIGTERM
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
		  int rfd,
                  int wfd,
                  GNUNET_SCHEDULER_TaskCallback task,
                  void *task_cls)
{
  struct GNUNET_SCHEDULER_Task *t;

#if EXECINFO
  void *backtrace_array[MAX_TRACE_DEPTH];
#endif

  GNUNET_assert (NULL != active_task);
  GNUNET_assert (NULL != task);
  t = GNUNET_new (struct GNUNET_SCHEDULER_Task);
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
      LOG (GNUNET_ERROR_TYPE_ERROR,
           "Got invalid file descriptor %d!\n",
           rfd);
#if EXECINFO
      unsigned int i;

      for (i = 0; i < t->num_backtrace_strings; i++)
        LOG (GNUNET_ERROR_TYPE_ERROR,
             "Trace: %s\n",
             t->backtrace_strings[i]);
#endif
      GNUNET_assert (0);
    }
  }
  if (-1 != wfd)
  {
    int flags = fcntl (wfd, F_GETFD);

    if (flags == -1 && errno == EBADF)
    {
      LOG (GNUNET_ERROR_TYPE_ERROR,
           "Got invalid file descriptor %d!\n",
           wfd);
#if EXECINFO
      unsigned int i;

      for (i = 0; i < t->num_backtrace_strings; i++)
        LOG (GNUNET_ERROR_TYPE_DEBUG,
             "Trace: %s\n",
             t->backtrace_strings[i]);
#endif
      GNUNET_assert (0);
    }
  }
#endif
  t->read_fd = rfd;
  GNUNET_assert (wfd >= -1);
  t->write_fd = wfd;
#if PROFILE_DELAYS
  t->start_time = GNUNET_TIME_absolute_get ();
#endif
  t->timeout = GNUNET_TIME_relative_to_absolute (delay);
  t->priority = check_priority ((priority == GNUNET_SCHEDULER_PRIORITY_KEEP) ? current_priority : priority);
  t->lifeness = current_lifeness;
  GNUNET_CONTAINER_DLL_insert (pending_head,
                               pending_tail,
                               t);
  max_priority_added = GNUNET_MAX (max_priority_added,
                                   t->priority);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Adding task %p\n",
       t);
#if EXECINFO
  unsigned int i;

  for (i = 0; i < t->num_backtrace_strings; i++)
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Task %p trace %d: %s\n",
         t,
         i,
         t->backtrace_strings[i]);
#endif
  return t;
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
 *        #GNUNET_TIME_UNIT_FOREVER_REL for "on shutdown"
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
 *
 * @param delay when should this operation time out? Use
 *        #GNUNET_TIME_UNIT_FOREVER_REL for "on shutdown"
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
 *
 * @param delay when should this operation time out? Use
 *        #GNUNET_TIME_UNIT_FOREVER_REL for "on shutdown"
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
 *
 * @param delay when should this operation time out? Use
 *        #GNUNET_TIME_UNIT_FOREVER_REL for "on shutdown"
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
  GNUNET_assert (GNUNET_NETWORK_get_fd (fd) >= 0);
  return add_without_sets (delay, priority,
                           on_read  ? GNUNET_NETWORK_get_fd (fd) : -1,
                           on_write ? GNUNET_NETWORK_get_fd (fd) : -1,
                           task, task_cls);
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
 *        #GNUNET_TIME_UNIT_FOREVER_REL for "on shutdown"
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
 *
 * @param delay when should this operation time out? Use
 *        #GNUNET_TIME_UNIT_FOREVER_REL for "on shutdown"
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
 *
 * @param delay when should this operation time out? Use
 *        #GNUNET_TIME_UNIT_FOREVER_REL for "on shutdown"
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
  int real_fd;

  GNUNET_DISK_internal_file_handle_ (fd, &real_fd, sizeof (int));
  GNUNET_assert (real_fd >= 0);
  return add_without_sets (
      delay, priority,
      on_read  ? real_fd : -1,
      on_write ? real_fd : -1,
      task, task_cls);
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
 * @param delay how long should we wait? Use #GNUNET_TIME_UNIT_FOREVER_REL for "forever",
 *        which means that the task will only be run after we receive SIGTERM
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
#if EXECINFO
  void *backtrace_array[MAX_TRACE_DEPTH];
#endif

  if ( (NULL == rs) &&
       (NULL == ws) )
    return GNUNET_SCHEDULER_add_delayed_with_priority (delay,
                                                       prio,
                                                       task,
                                                       task_cls);
  GNUNET_assert (NULL != active_task);
  GNUNET_assert (NULL != task);
  t = GNUNET_new (struct GNUNET_SCHEDULER_Task);
  t->callback = task;
  t->callback_cls = task_cls;
#if EXECINFO
  t->num_backtrace_strings = backtrace (backtrace_array, MAX_TRACE_DEPTH);
  t->backtrace_strings =
      backtrace_symbols (backtrace_array, t->num_backtrace_strings);
#endif
  t->read_fd = -1;
  t->write_fd = -1;
  if (NULL != rs)
  {
    t->read_set = GNUNET_NETWORK_fdset_create ();
    GNUNET_NETWORK_fdset_copy (t->read_set, rs);
  }
  if (NULL != ws)
  {
    t->write_set = GNUNET_NETWORK_fdset_create ();
    GNUNET_NETWORK_fdset_copy (t->write_set, ws);
  }
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
  max_priority_added = GNUNET_MAX (max_priority_added, t->priority);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Adding task %p\n",
       t);
#if EXECINFO
  int i;

  for (i = 0; i < t->num_backtrace_strings; i++)
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Task p trace %d: %s\n",
         t,
         i,
         t->backtrace_strings[i]);
#endif
  return t;
}

/* end of scheduler.c */

/*
      This file is part of GNUnet
      (C) 2009 Christian Grothoff (and other contributing authors)

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
#include "gnunet_scheduler_lib.h"
#include "gnunet_signal_lib.h"
#include "gnunet_time_lib.h"
#ifdef LINUX
#include "execinfo.h"
#define EXECINFO GNUNET_NO
#define MAX_TRACE_DEPTH 50
#endif

#define DEBUG_TASKS GNUNET_NO

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
 * Handle for the scheduling service.
 */
struct GNUNET_SCHEDULER_Handle
{

  /**
   * List of tasks waiting for an event.
   */
  struct Task *pending;

  /**
   * ID of the task that is running right now.
   */
  struct Task *active_task;

  /**
   * List of tasks ready to run right now,
   * grouped by importance.
   */
  struct Task *ready[GNUNET_SCHEDULER_PRIORITY_COUNT];

  /**
   * Identity of the last task queued.  Incremented for each task to
   * generate a unique task ID (it is virtually impossible to start
   * more than 2^64 tasks during the lifetime of a process).
   */
  GNUNET_SCHEDULER_TaskIdentifier last_id;

  /**
   * Highest number so that all tasks with smaller identifiers
   * have already completed.  Also the lowest number of a task
   * still waiting to be executed.
   */
  GNUNET_SCHEDULER_TaskIdentifier lowest_pending_id;

  /**
   * Number of tasks on the ready list.
   */
  unsigned int ready_count;

  /**
   * How many tasks have we run so far?
   */
  unsigned long long tasks_run;

  /**
   * Priority of the task running right now.  Only
   * valid while a task is running.
   */
  enum GNUNET_SCHEDULER_Priority current_priority;

};


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
 * @param sched the scheduler
 * @param id which task are we checking for
 * @return GNUNET_YES if so, GNUNET_NO if not
 */
static int
is_pending (struct GNUNET_SCHEDULER_Handle *sched,
            GNUNET_SCHEDULER_TaskIdentifier id)
{
  struct Task *pos;
  enum GNUNET_SCHEDULER_Priority p;
  GNUNET_SCHEDULER_TaskIdentifier min;

  if (id < sched->lowest_pending_id)
    return GNUNET_NO;
  min = -1;                     /* maximum value */
  pos = sched->pending;
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
      pos = sched->ready[p];
      while (pos != NULL)
        {
          if (pos->id == id)
            return GNUNET_YES;
          if (pos->id < min)
            min = pos->id;
          pos = pos->next;
        }
    }
  sched->lowest_pending_id = min;
  return GNUNET_NO;
}


/**
 * Update all sets and timeout for select.
 *
 * @param sched the scheduler
 * @param rs read-set, set to all FDs we would like to read (updated)
 * @param ws write-set, set to all FDs we would like to write (updated)
 * @param timeout next timeout (updated)
 */
static void
update_sets (struct GNUNET_SCHEDULER_Handle *sched,
             struct GNUNET_NETWORK_FDSet *rs,
             struct GNUNET_NETWORK_FDSet *ws,
             struct GNUNET_TIME_Relative *timeout)
{
  struct Task *pos;

  pos = sched->pending;
  while (pos != NULL)
    {
      if ((pos->prereq_id != GNUNET_SCHEDULER_NO_TASK) &&
          (GNUNET_YES == is_pending (sched, pos->prereq_id)))
        {
          pos = pos->next;
          continue;
        }

      if (pos->timeout.value != GNUNET_TIME_UNIT_FOREVER_ABS.value)
        {
          struct GNUNET_TIME_Relative to;

          to = GNUNET_TIME_absolute_get_remaining (pos->timeout);
          if (timeout->value > to.value)
            *timeout = to;
        }
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
  if (NULL == want)
    return GNUNET_NO;
  if (GNUNET_NETWORK_fdset_overlap (ready, want))
    {
      /* copy all over (yes, there maybe unrelated bits,
         but this should not hurt well-written clients) */
      GNUNET_NETWORK_fdset_copy (want, ready);
      return GNUNET_YES;
    }
  return GNUNET_NO;
}


/**
 * Check if the given task is eligible to run now.
 * Also set the reason why it is eligible.
 *
 * @param sched the scheduler
 * @param task task to check if it is ready
 * @param now the current time
 * @param rs set of FDs ready for reading
 * @param ws set of FDs ready for writing
 * @return GNUNET_YES if we can run it, GNUNET_NO if not.
 */
static int
is_ready (struct GNUNET_SCHEDULER_Handle *sched,
          struct Task *task,
          struct GNUNET_TIME_Absolute now,
          const struct GNUNET_NETWORK_FDSet *rs,
          const struct GNUNET_NETWORK_FDSet *ws)
{
  if (now.value >= task->timeout.value)
    task->reason |= GNUNET_SCHEDULER_REASON_TIMEOUT;
  if ((0 == (task->reason & GNUNET_SCHEDULER_REASON_READ_READY)) &&
      (rs != NULL) && (set_overlaps (rs, task->read_set)))
    task->reason |= GNUNET_SCHEDULER_REASON_READ_READY;
  if ((0 == (task->reason & GNUNET_SCHEDULER_REASON_WRITE_READY)) &&
      (ws != NULL) && (set_overlaps (ws, task->write_set)))
    task->reason |= GNUNET_SCHEDULER_REASON_WRITE_READY;
  if (task->reason == 0)
    return GNUNET_NO;           /* not ready */
  if (task->prereq_id != GNUNET_SCHEDULER_NO_TASK)
    {
      if (GNUNET_YES == is_pending (sched, task->prereq_id))
        return GNUNET_NO;       /* prereq waiting */
      task->reason |= GNUNET_SCHEDULER_REASON_PREREQ_DONE;
    }
  return GNUNET_YES;
}


/**
 * Put a task that is ready for execution into the ready queue.
 *
 * @param handle the scheduler
 * @param task task ready for execution
 */
static void
queue_ready_task (struct GNUNET_SCHEDULER_Handle *handle, struct Task *task)
{
  enum GNUNET_SCHEDULER_Priority p = task->priority;
  if (0 != (task->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN))
    p = GNUNET_SCHEDULER_PRIORITY_SHUTDOWN;
  task->next = handle->ready[check_priority (p)];
  handle->ready[check_priority (p)] = task;
  handle->ready_count++;
}


/**
 * Check which tasks are ready and move them
 * to the respective ready queue.
 *
 * @param handle the scheduler
 * @param rs FDs ready for reading
 * @param ws FDs ready for writing
 */
static void
check_ready (struct GNUNET_SCHEDULER_Handle *handle,
             const struct GNUNET_NETWORK_FDSet *rs,
             const struct GNUNET_NETWORK_FDSet *ws)
{
  struct Task *pos;
  struct Task *prev;
  struct Task *next;
  struct GNUNET_TIME_Absolute now;

  now = GNUNET_TIME_absolute_get ();
  prev = NULL;
  pos = handle->pending;
  while (pos != NULL)
    {
#if DEBUG_TASKS
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Checking readiness of task: %llu / %p\n",
                  pos->id, pos->callback_cls);
#endif
      next = pos->next;
      if (GNUNET_YES == is_ready (handle, pos, now, rs, ws))
        {
          if (prev == NULL)
            handle->pending = next;
          else
            prev->next = next;
          queue_ready_task (handle, pos);
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
 *
 * @param sched the scheduler
 */
void
GNUNET_SCHEDULER_shutdown (struct GNUNET_SCHEDULER_Handle *sched)
{
  struct Task *pos;
  int i;

  pos = sched->pending;
  while (pos != NULL)
    {
      pos->reason |= GNUNET_SCHEDULER_REASON_SHUTDOWN;
      /* we don't move the task into the ready queue yet; check_ready
         will do that later, possibly adding additional
         readiness-factors */
      pos = pos->next;
    }
  for (i=0;i<GNUNET_SCHEDULER_PRIORITY_COUNT;i++)
    {
      pos = sched->ready[i];
      while (pos != NULL)
	{
	  pos->reason |= GNUNET_SCHEDULER_REASON_SHUTDOWN;
	  /* we don't move the task into the ready queue yet; check_ready
	     will do that later, possibly adding additional
	     readiness-factors */
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
 * @param sched the scheduler
 */
static void
run_ready (struct GNUNET_SCHEDULER_Handle *sched)
{
  enum GNUNET_SCHEDULER_Priority p;
  struct Task *pos;
  struct GNUNET_SCHEDULER_TaskContext tc;

  do
    {
      if (sched->ready_count == 0)
        return;
      GNUNET_assert (sched->ready[GNUNET_SCHEDULER_PRIORITY_KEEP] == NULL);
      /* yes, p>0 is correct, 0 is "KEEP" which should
         always be an empty queue (see assertion)! */
      for (p = GNUNET_SCHEDULER_PRIORITY_COUNT - 1; p > 0; p--)
        {
          pos = sched->ready[p];
          if (pos != NULL)
            break;
        }
      GNUNET_assert (pos != NULL);      /* ready_count wrong? */
      sched->ready[p] = pos->next;
      sched->ready_count--;
      sched->current_priority = pos->priority;
      sched->active_task = pos;
      tc.sched = sched;
      tc.reason = pos->reason;
      tc.read_ready = pos->read_set;
      tc.write_ready = pos->write_set;
      pos->callback (pos->callback_cls, &tc);
#if DEBUG_TASKS
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Running task: %llu / %p\n", pos->id, pos->callback_cls);
#endif
      sched->active_task = NULL;
      destroy_task (pos);
      sched->tasks_run++;
    }
  while ((sched->pending == NULL) || (p == GNUNET_SCHEDULER_PRIORITY_URGENT));
}

/**
 * Pipe used to communicate shutdown via signal.
 */
static struct GNUNET_DISK_PipeHandle *sigpipe;


/**
 * Signal handler called for signals that should cause us to shutdown.
 */
static void
sighandler_shutdown ()
{
  static char c;

  GNUNET_DISK_file_write (GNUNET_DISK_pipe_handle
                          (sigpipe, GNUNET_DISK_PIPE_END_WRITE), &c,
                          sizeof (c));
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
  struct GNUNET_SCHEDULER_Handle sched;
  struct GNUNET_NETWORK_FDSet *rs;
  struct GNUNET_NETWORK_FDSet *ws;
  struct GNUNET_TIME_Relative timeout;
  int ret;
  struct GNUNET_SIGNAL_Context *shc_int;
  struct GNUNET_SIGNAL_Context *shc_term;
  struct GNUNET_SIGNAL_Context *shc_quit;
  struct GNUNET_SIGNAL_Context *shc_hup;
  unsigned long long last_tr;
  unsigned int busy_wait_warning;
  const struct GNUNET_DISK_FileHandle *pr;
  char c;

  rs = GNUNET_NETWORK_fdset_create ();
  ws = GNUNET_NETWORK_fdset_create ();
  GNUNET_assert (sigpipe == NULL);
  sigpipe = GNUNET_DISK_pipe (GNUNET_NO);
  GNUNET_assert (sigpipe != NULL);
  pr = GNUNET_DISK_pipe_handle (sigpipe, GNUNET_DISK_PIPE_END_READ);
  GNUNET_assert (pr != NULL);
  shc_int = GNUNET_SIGNAL_handler_install (SIGINT, &sighandler_shutdown);
  shc_term = GNUNET_SIGNAL_handler_install (SIGTERM, &sighandler_shutdown);
#ifndef MINGW
  shc_quit = GNUNET_SIGNAL_handler_install (SIGQUIT, &sighandler_shutdown);
  shc_hup = GNUNET_SIGNAL_handler_install (SIGHUP, &sighandler_shutdown);
#endif
  memset (&sched, 0, sizeof (sched));
  sched.current_priority = GNUNET_SCHEDULER_PRIORITY_DEFAULT;
  GNUNET_SCHEDULER_add_continuation (&sched,
                                     task,
                                     task_cls,
                                     GNUNET_SCHEDULER_REASON_STARTUP);
  last_tr = 0;
  busy_wait_warning = 0;
  while ((sched.pending != NULL) || (sched.ready_count > 0))
    {
      GNUNET_NETWORK_fdset_zero (rs);
      GNUNET_NETWORK_fdset_zero (ws);
      timeout = GNUNET_TIME_UNIT_FOREVER_REL;
      update_sets (&sched, rs, ws, &timeout);
      GNUNET_NETWORK_fdset_handle_set (rs, pr);
      if (sched.ready_count > 0)
        {
          /* no blocking, more work already ready! */
          timeout = GNUNET_TIME_UNIT_ZERO;
        }
      ret = GNUNET_NETWORK_socket_select (rs, ws, NULL, timeout);
      if (ret == GNUNET_SYSERR)
        {
          if (errno == EINTR)
            continue;
          GNUNET_log_strerror (GNUNET_ERROR_TYPE_ERROR, "select");
          break;
        }
      if (GNUNET_NETWORK_fdset_handle_isset (rs, pr))
        {
          /* consume the signal */
          GNUNET_DISK_file_read (pr, &c, sizeof (c));
          /* mark all active tasks as ready due to shutdown */
          GNUNET_SCHEDULER_shutdown (&sched);
        }
      if (last_tr == sched.tasks_run)
        {
          busy_wait_warning++;
        }
      else
        {
          last_tr = sched.tasks_run;
          busy_wait_warning = 0;
        }
      if ((ret == 0) && (timeout.value == 0) && (busy_wait_warning > 16))
        {
          GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                      _("Looks like we're busy waiting...\n"));
          sleep (1);            /* mitigate */
        }
      check_ready (&sched, rs, ws);
      run_ready (&sched);
    }
  GNUNET_SIGNAL_handler_uninstall (shc_int);
  GNUNET_SIGNAL_handler_uninstall (shc_term);
#ifndef MINGW
  GNUNET_SIGNAL_handler_uninstall (shc_quit);
  GNUNET_SIGNAL_handler_uninstall (shc_hup);
#endif
  GNUNET_DISK_pipe_close (sigpipe);
  sigpipe = NULL;
  GNUNET_NETWORK_fdset_destroy (rs);
  GNUNET_NETWORK_fdset_destroy (ws);
}


/**
 * Obtain the reason code for why the current task was
 * started.  Will return the same value as 
 * the GNUNET_SCHEDULER_TaskContext's reason field.
 *
 * @param sched scheduler to query
 * @return reason(s) why the current task is run
 */
enum GNUNET_SCHEDULER_Reason
GNUNET_SCHEDULER_get_reason (struct GNUNET_SCHEDULER_Handle *sched)
{
  return sched->active_task->reason;
}


/**
 * Get information about the current load of this scheduler.  Use this
 * function to determine if an elective task should be added or simply
 * dropped (if the decision should be made based on the number of
 * tasks ready to run).
 *
 * @param sched scheduler to query
 * @param p priority level to look at
 * @return number of tasks pending right now
 */
unsigned int
GNUNET_SCHEDULER_get_load (struct GNUNET_SCHEDULER_Handle *sched,
                           enum GNUNET_SCHEDULER_Priority p)
{
  struct Task *pos;
  unsigned int ret;

  if (p == GNUNET_SCHEDULER_PRIORITY_COUNT)
    return sched->ready_count;
  if (p == GNUNET_SCHEDULER_PRIORITY_KEEP)
    p = sched->current_priority;
  ret = 0;
  pos = sched->ready[p];
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
 * @param sched scheduler to use
 * @param task id of the task to cancel
 * @return original closure of the task
 */
void *
GNUNET_SCHEDULER_cancel (struct GNUNET_SCHEDULER_Handle *sched,
                         GNUNET_SCHEDULER_TaskIdentifier task)
{
  struct Task *t;
  struct Task *prev;
  enum GNUNET_SCHEDULER_Priority p;
  void *ret;

  prev = NULL;
  t = sched->pending;
  while (t != NULL)
    {
      if (t->id == task)
        break;
      prev = t;
      t = t->next;
    }
  p = 0;
  while (t == NULL)
    {
      p++;
      GNUNET_assert (p < GNUNET_SCHEDULER_PRIORITY_COUNT);
      prev = NULL;
      t = sched->ready[p];
      while (t != NULL)
        {
          if (t->id == task)
            {
              sched->ready_count--;
              break;
            }
          prev = t;
          t = t->next;
        }
    }
  if (prev == NULL)
    {
      if (p == 0)
        sched->pending = t->next;
      else
        sched->ready[p] = t->next;
    }
  else
    prev->next = t->next;
  ret = t->callback_cls;
#if DEBUG_TASKS
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Canceling task: %llu / %p\n", task, t->callback_cls);
#endif
  destroy_task (t);
  return ret;
}


/**
 * Continue the current execution with the given function.  This is
 * similar to the other "add" functions except that there is no delay
 * and the reason code can be specified.
 *
 * @param sched scheduler to use
 * @param task main function of the task
 * @param task_cls closure for 'main'
 * @param reason reason for task invocation
 */
void
GNUNET_SCHEDULER_add_continuation (struct GNUNET_SCHEDULER_Handle *sched,
                                   GNUNET_SCHEDULER_Task task,
                                   void *task_cls,
                                   enum GNUNET_SCHEDULER_Reason reason)
{
  struct Task *t;
#if EXECINFO
  void *backtrace_array[50];
#endif
  t = GNUNET_malloc (sizeof (struct Task));
#if EXECINFO
  t->num_backtrace_strings = backtrace(backtrace_array, 50);
  t->backtrace_strings = backtrace_symbols(backtrace_array, t->num_backtrace_strings);
#endif
  t->callback = task;
  t->callback_cls = task_cls;
  t->id = ++sched->last_id;
  t->reason = reason;
  t->priority = sched->current_priority;
#if DEBUG_TASKS
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Adding continuation task: %llu / %p\n",
              t->id, t->callback_cls);
#endif
  queue_ready_task (sched, t);
}



/**
 * Schedule a new task to be run after the specified prerequisite task
 * has completed. It will be run with the priority of the calling
 * task.
 *
 * @param sched scheduler to use
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
GNUNET_SCHEDULER_add_after (struct GNUNET_SCHEDULER_Handle *sched,
                            GNUNET_SCHEDULER_TaskIdentifier prerequisite_task,
                            GNUNET_SCHEDULER_Task task, void *task_cls)
{
  return GNUNET_SCHEDULER_add_select (sched,
                                      GNUNET_SCHEDULER_PRIORITY_KEEP,
                                      prerequisite_task,
                                      GNUNET_TIME_UNIT_ZERO,
                                      NULL, NULL, task, task_cls);
}


/**
 * Schedule a new task to be run with a specified priority.
 *
 * @param sched scheduler to use
 * @param prio how important is the new task?
 * @param task main function of the task
 * @param task_cls closure of task
 * @return unique task identifier for the job
 *         only valid until "task" is started!
 */
GNUNET_SCHEDULER_TaskIdentifier
GNUNET_SCHEDULER_add_with_priority (struct GNUNET_SCHEDULER_Handle * sched,
                                    enum GNUNET_SCHEDULER_Priority prio,
                                    GNUNET_SCHEDULER_Task task,
                                    void *task_cls)
{
  return GNUNET_SCHEDULER_add_select (sched,
                                      prio,
                                      GNUNET_SCHEDULER_NO_TASK,
                                      GNUNET_TIME_UNIT_ZERO,
                                      NULL, NULL, task, task_cls);
}



/**
 * Schedule a new task to be run with a specified delay.  The task
 * will be scheduled for execution once the delay has expired. It
 * will be run with the priority of the calling task.
 *
 * @param sched scheduler to use
 * @param delay when should this operation time out? Use 
 *        GNUNET_TIME_UNIT_FOREVER_REL for "on shutdown"
 * @param task main function of the task
 * @param task_cls closure of task
 * @return unique task identifier for the job
 *         only valid until "task" is started!
 */
GNUNET_SCHEDULER_TaskIdentifier
GNUNET_SCHEDULER_add_delayed (struct GNUNET_SCHEDULER_Handle * sched,
                              struct GNUNET_TIME_Relative delay,
                              GNUNET_SCHEDULER_Task task, void *task_cls)
{
  return GNUNET_SCHEDULER_add_select (sched,
                                      GNUNET_SCHEDULER_PRIORITY_KEEP,
                                      GNUNET_SCHEDULER_NO_TASK, delay,
                                      NULL, NULL, task, task_cls);
}



/**
 * Schedule a new task to be run as soon as possible. The task
 * will be run with the priority of the calling task.
 *
 * @param sched scheduler to use
 * @param task main function of the task
 * @param task_cls closure of task
 * @return unique task identifier for the job
 *         only valid until "task" is started!
 */
GNUNET_SCHEDULER_TaskIdentifier
GNUNET_SCHEDULER_add_now (struct GNUNET_SCHEDULER_Handle *sched,
			  GNUNET_SCHEDULER_Task task,
			  void *task_cls)
{
  return GNUNET_SCHEDULER_add_select (sched,
                                      GNUNET_SCHEDULER_PRIORITY_KEEP,
                                      GNUNET_SCHEDULER_NO_TASK,
				      GNUNET_TIME_UNIT_ZERO,
                                      NULL, NULL, task, task_cls);
}



/**
 * Schedule a new task to be run with a specified delay or when the
 * specified file descriptor is ready for reading.  The delay can be
 * used as a timeout on the socket being ready.  The task will be
 * scheduled for execution once either the delay has expired or the
 * socket operation is ready.  It will be run with the priority of
 * the calling task.
 *
 * @param sched scheduler to use
 * @param delay when should this operation time out? Use 
 *        GNUNET_TIME_UNIT_FOREVER_REL for "on shutdown"
 * @param rfd read file-descriptor
 * @param task main function of the task
 * @param task_cls closure of task
 * @return unique task identifier for the job
 *         only valid until "task" is started!
 */
GNUNET_SCHEDULER_TaskIdentifier
GNUNET_SCHEDULER_add_read_net (struct GNUNET_SCHEDULER_Handle * sched,
                               struct GNUNET_TIME_Relative delay,
                               struct GNUNET_NETWORK_Handle * rfd,
                               GNUNET_SCHEDULER_Task task, void *task_cls)
{
  struct GNUNET_NETWORK_FDSet *rs;
  GNUNET_SCHEDULER_TaskIdentifier ret;

  GNUNET_assert (rfd != NULL);
  rs = GNUNET_NETWORK_fdset_create ();
  GNUNET_NETWORK_fdset_set (rs, rfd);
  ret = GNUNET_SCHEDULER_add_select (sched,
                                     GNUNET_SCHEDULER_PRIORITY_KEEP,
                                     GNUNET_SCHEDULER_NO_TASK,
                                     delay, rs, NULL, task, task_cls);
  GNUNET_NETWORK_fdset_destroy (rs);
  return ret;
}


/**
 * Schedule a new task to be run with a specified delay or when the
 * specified file descriptor is ready for writing.  The delay can be
 * used as a timeout on the socket being ready.  The task will be
 * scheduled for execution once either the delay has expired or the
 * socket operation is ready.  It will be run with the priority of
 * the calling task.
 *
 * @param sched scheduler to use
 * @param delay when should this operation time out? Use 
 *        GNUNET_TIME_UNIT_FOREVER_REL for "on shutdown"
 * @param wfd write file-descriptor
 * @param task main function of the task
 * @param task_cls closure of task
 * @return unique task identifier for the job
 *         only valid until "task" is started!
 */
GNUNET_SCHEDULER_TaskIdentifier
GNUNET_SCHEDULER_add_write_net (struct GNUNET_SCHEDULER_Handle * sched,
                                struct GNUNET_TIME_Relative delay,
                                struct GNUNET_NETWORK_Handle * wfd,
                                GNUNET_SCHEDULER_Task task, void *task_cls)
{
  struct GNUNET_NETWORK_FDSet *ws;
  GNUNET_SCHEDULER_TaskIdentifier ret;

  GNUNET_assert (wfd != NULL);
  ws = GNUNET_NETWORK_fdset_create ();
  GNUNET_NETWORK_fdset_set (ws, wfd);
  ret = GNUNET_SCHEDULER_add_select (sched,
                                     GNUNET_SCHEDULER_PRIORITY_KEEP,
                                     GNUNET_SCHEDULER_NO_TASK, delay,
                                     NULL, ws, task, task_cls);
  GNUNET_NETWORK_fdset_destroy (ws);
  return ret;
}


/**
 * Schedule a new task to be run with a specified delay or when the
 * specified file descriptor is ready for reading.  The delay can be
 * used as a timeout on the socket being ready.  The task will be
 * scheduled for execution once either the delay has expired or the
 * socket operation is ready. It will be run with the priority of
 * the calling task.
 *
 * @param sched scheduler to use
 * @param delay when should this operation time out? Use 
 *        GNUNET_TIME_UNIT_FOREVER_REL for "on shutdown"
 * @param rfd read file-descriptor
 * @param task main function of the task
 * @param task_cls closure of task
 * @return unique task identifier for the job
 *         only valid until "task" is started!
 */
GNUNET_SCHEDULER_TaskIdentifier
GNUNET_SCHEDULER_add_read_file (struct GNUNET_SCHEDULER_Handle * sched,
                                struct GNUNET_TIME_Relative delay,
                                const struct GNUNET_DISK_FileHandle * rfd,
                                GNUNET_SCHEDULER_Task task, void *task_cls)
{
  struct GNUNET_NETWORK_FDSet *rs;
  GNUNET_SCHEDULER_TaskIdentifier ret;

  GNUNET_assert (rfd != NULL);
  rs = GNUNET_NETWORK_fdset_create ();
  GNUNET_NETWORK_fdset_handle_set (rs, rfd);
  ret = GNUNET_SCHEDULER_add_select (sched,
                                     GNUNET_SCHEDULER_PRIORITY_KEEP,
                                     GNUNET_SCHEDULER_NO_TASK, delay,
                                     rs, NULL, task, task_cls);
  GNUNET_NETWORK_fdset_destroy (rs);
  return ret;
}


/**
 * Schedule a new task to be run with a specified delay or when the
 * specified file descriptor is ready for writing.  The delay can be
 * used as a timeout on the socket being ready.  The task will be
 * scheduled for execution once either the delay has expired or the
 * socket operation is ready. It will be run with the priority of
 * the calling task.
 *
 * @param sched scheduler to use
 * @param delay when should this operation time out? Use 
 *        GNUNET_TIME_UNIT_FOREVER_REL for "on shutdown"
 * @param wfd write file-descriptor
 * @param task main function of the task
 * @param task_cls closure of task
 * @return unique task identifier for the job
 *         only valid until "task" is started!
 */
GNUNET_SCHEDULER_TaskIdentifier
GNUNET_SCHEDULER_add_write_file (struct GNUNET_SCHEDULER_Handle * sched,
                                 struct GNUNET_TIME_Relative delay,
                                 const struct GNUNET_DISK_FileHandle * wfd,
                                 GNUNET_SCHEDULER_Task task, void *task_cls)
{
  struct GNUNET_NETWORK_FDSet *ws;
  GNUNET_SCHEDULER_TaskIdentifier ret;

  GNUNET_assert (wfd != NULL);
  ws = GNUNET_NETWORK_fdset_create ();
  GNUNET_NETWORK_fdset_handle_set (ws, wfd);
  ret = GNUNET_SCHEDULER_add_select (sched,
                                     GNUNET_SCHEDULER_PRIORITY_KEEP,
                                     GNUNET_SCHEDULER_NO_TASK,
                                     delay, NULL, ws, task, task_cls);
  GNUNET_NETWORK_fdset_destroy (ws);
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
 *     || (shutdown-active && run-on-shutdown) )
 * </code>
 *
 * @param sched scheduler to use
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
GNUNET_SCHEDULER_add_select (struct GNUNET_SCHEDULER_Handle * sched,
                             enum GNUNET_SCHEDULER_Priority prio,
                             GNUNET_SCHEDULER_TaskIdentifier
                             prerequisite_task,
                             struct GNUNET_TIME_Relative delay,
                             const struct GNUNET_NETWORK_FDSet * rs,
                             const struct GNUNET_NETWORK_FDSet * ws,
                             GNUNET_SCHEDULER_Task task, void *task_cls)
{
  struct Task *t;
#if EXECINFO
  void *backtrace_array[MAX_TRACE_DEPTH];
#endif
  t = GNUNET_malloc (sizeof (struct Task));
  t->callback = task;
  t->callback_cls = task_cls;
#if EXECINFO
  t->num_backtrace_strings = backtrace(backtrace_array, MAX_TRACE_DEPTH);
  t->backtrace_strings = backtrace_symbols(backtrace_array, t->num_backtrace_strings);
#endif
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
  t->id = ++sched->last_id;
  t->prereq_id = prerequisite_task;
  t->timeout = GNUNET_TIME_relative_to_absolute (delay);
  t->priority =
    check_priority ((prio ==
                     GNUNET_SCHEDULER_PRIORITY_KEEP) ? sched->current_priority
                    : prio);
  t->next = sched->pending;
  sched->pending = t;
#if DEBUG_TASKS
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Adding task: %llu / %p\n", t->id, t->callback_cls);
#endif
  return t->id;
}

/* end of scheduler.c */

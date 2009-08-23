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
 * @file include/gnunet_scheduler_lib.h
 * @brief API to schedule computations using continuation passing style
 * @author Christian Grothoff
 */

#ifndef GNUNET_SCHEDULER_LIB_H
#define GNUNET_SCHEDULER_LIB_H

#ifdef __cplusplus
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif


#include "gnunet_time_lib.h"
#include "gnunet_network_lib.h"

/**
 * Opaque handle for the scheduling service.
 */
struct GNUNET_SCHEDULER_Handle;

/**
 * Opaque reference to a task.
 */
typedef unsigned long long GNUNET_SCHEDULER_TaskIdentifier;


/**
 * Constant used to indicate that the scheduled
 * task has no others as prerequisites.
 */
#define GNUNET_SCHEDULER_NO_TASK ((GNUNET_SCHEDULER_TaskIdentifier) 0)

/**
 * Reasons why the schedule may have triggered
 * the task now.
 */
enum GNUNET_SCHEDULER_Reason
{
  /**
   * This is the very first task run during startup.
   */
  GNUNET_SCHEDULER_REASON_STARTUP = 0,

  /**
   * We are shutting down and are running all shutdown-related tasks
   * (regardless of timeout, etc.).
   */
  GNUNET_SCHEDULER_REASON_SHUTDOWN = 1,

  /**
   * The specified timeout has expired.
   * (also set if the delay given was 0).
   */
  GNUNET_SCHEDULER_REASON_TIMEOUT = 2,

  /**
   * The reading socket is ready.
   */
  GNUNET_SCHEDULER_REASON_READ_READY = 4,

  /**
   * The writing socket is ready.
   */
  GNUNET_SCHEDULER_REASON_WRITE_READY = 8,

  /**
   * The prerequisite task is done.
   */
  GNUNET_SCHEDULER_REASON_PREREQ_DONE = 16
};


/**
 * Valid task priorities.  Use these, do not
 * pass random integers!
 */
enum GNUNET_SCHEDULER_Priority
{
  /**
   * Run with the same priority as the current job.
   */
  GNUNET_SCHEDULER_PRIORITY_KEEP = 0,

  /**
   * Run when otherwise idle.
   */
  GNUNET_SCHEDULER_PRIORITY_IDLE = 1,

  /**
   * Run as background job (higher than idle,
   * lower than default).
   */
  GNUNET_SCHEDULER_PRIORITY_BACKGROUND = 2,

  /**
   * Run with the default priority (normal
   * P2P operations).  Higher than BACKGROUND.
   */
  GNUNET_SCHEDULER_PRIORITY_DEFAULT = 3,

  /**
   * Run with high priority (important requests).
   * Higher than DEFAULT.
   */
  GNUNET_SCHEDULER_PRIORITY_HIGH = 4,

  /**
   * Run with priority for interactive tasks.
   * Higher than "HIGH".
   */
  GNUNET_SCHEDULER_PRIORITY_UI = 5,

  /**
   * Run with priority for urgent tasks.  Use
   * for things like aborts and shutdowns that
   * need to preempt "UI"-level tasks.
   * Higher than "UI".
   */
  GNUNET_SCHEDULER_PRIORITY_URGENT = 6,

  /**
   * Number of priorities (must be the last priority).
   * This priority must not be used by clients.
   */
  GNUNET_SCHEDULER_PRIORITY_COUNT = 7
};


/**
 * Context information passed to each scheduler task.
 */
struct GNUNET_SCHEDULER_TaskContext
{

  /**
   * Scheduler running the task
   */
  struct GNUNET_SCHEDULER_Handle *sched;

  /**
   * Reason why the task is run now
   */
  enum GNUNET_SCHEDULER_Reason reason;

  /**
   * Set of file descriptors ready for reading;
   * note that additional bits may be set
   * that were not in the original request
   */
  const struct GNUNET_NETWORK_FDSet *read_ready;

  /**
   * Set of file descriptors ready for writing;
   * note that additional bits may be set
   * that were not in the original request.
   */
  const struct GNUNET_NETWORK_FDSet *write_ready;

};


/**
 * Signature of the main function of a task.
 *
 * @param cls closure
 * @param tc context information (why was this task triggered now)
 */
typedef void (*GNUNET_SCHEDULER_Task) (void *cls,
                                       const struct
                                       GNUNET_SCHEDULER_TaskContext * tc);


/**
 * Initialize and run scheduler.  This function will return when
 * either a shutdown was initiated (via signal) and all tasks marked
 * to "run_on_shutdown" have been completed or when all tasks in
 * general have been completed.
 *
 * @param task task to run immediately
 * @param cls closure of task
 */
void GNUNET_SCHEDULER_run (GNUNET_SCHEDULER_Task task, void *cls);


/**
 * Request the shutdown of a scheduler.  This function can be used to
 * stop a scheduler, for example from within the signal
 * handler for signals causing shutdowns.
 */
void GNUNET_SCHEDULER_shutdown (struct GNUNET_SCHEDULER_Handle *sched);


/**
 * Get information about the current load of this scheduler.  Use this
 * function to determine if an elective task should be added or simply
 * dropped (if the decision should be made based on the number of
 * tasks ready to run).
 *
 * @param sched scheduler to query
 * @param p priority-level to query, use KEEP to query the level
 *          of the current task, use COUNT to get the sum over
 *          all priority levels
 * @return number of tasks pending right now
 */
unsigned int GNUNET_SCHEDULER_get_load (struct GNUNET_SCHEDULER_Handle *sched,
                                        enum GNUNET_SCHEDULER_Priority p);


/**
 * Cancel the task with the specified identifier.
 * The task must not yet have run.
 *
 * @param sched scheduler to use
 * @param task id of the task to cancel
 * @return the closure of the callback of the cancelled task
 */
void *GNUNET_SCHEDULER_cancel (struct GNUNET_SCHEDULER_Handle *sched,
                               GNUNET_SCHEDULER_TaskIdentifier task);


/**
 * Continue the current execution with the given function.  This is
 * similar to the other "add" functions except that there is no delay
 * and the reason code can be specified.
 *
 * @param sched scheduler to use
 * @param main main function of the task
 * @param cls closure of task
 * @param reason reason for task invocation
 */
void
GNUNET_SCHEDULER_add_continuation (struct GNUNET_SCHEDULER_Handle *sched,
                                   int run_on_shutdown,
                                   GNUNET_SCHEDULER_Task main,
                                   void *cls,
                                   enum GNUNET_SCHEDULER_Reason reason);


/**
 * Schedule a new task to be run after the specified
 * prerequisite task has completed.
 *
 * @param sched scheduler to use
 * @param run_on_shutdown run on shutdown?
 * @param prio how important is this task?
 * @param prerequisite_task run this task after the task with the given
 *        task identifier completes (and any of our other
 *        conditions, such as delay, read or write-readyness
 *        are satisfied).  Use  GNUNET_SCHEDULER_NO_TASK to not have any dependency
 *        on completion of other tasks.
 * @param main main function of the task
 * @param cls closure of task
 * @return unique task identifier for the job
 *         only valid until "main" is started!
 */
GNUNET_SCHEDULER_TaskIdentifier
GNUNET_SCHEDULER_add_after (struct GNUNET_SCHEDULER_Handle *sched,
                            int run_on_shutdown,
                            enum GNUNET_SCHEDULER_Priority prio,
                            GNUNET_SCHEDULER_TaskIdentifier prerequisite_task,
                            GNUNET_SCHEDULER_Task main, void *cls);


/**
 * Schedule a new task to be run with a specified delay.  The task
 * will be scheduled for execution once the delay has expired and the
 * prerequisite task has completed.
 *
 * @param sched scheduler to use
 * @param run_on_shutdown run on shutdown? You can use this
 *        argument to run a function only during shutdown
 *        by setting delay to -1.  Set this
 *        argument to GNUNET_NO to skip this task if
 *        the user requested process termination.
 * @param prio how important is this task?
 * @param prerequisite_task run this task after the task with the given
 *        task identifier completes (and any of our other
 *        conditions, such as delay, read or write-readyness
 *        are satisfied).  Use  GNUNET_SCHEDULER_NO_TASK to not have any dependency
 *        on completion of other tasks.
 * @param delay how long should we wait? Use  GNUNET_TIME_UNIT_FOREVER_REL for "forever"
 * @param main main function of the task
 * @param cls closure of task
 * @return unique task identifier for the job
 *         only valid until "main" is started!
 */
GNUNET_SCHEDULER_TaskIdentifier
GNUNET_SCHEDULER_add_delayed (struct GNUNET_SCHEDULER_Handle *sched,
                              int run_on_shutdown,
                              enum GNUNET_SCHEDULER_Priority prio,
                              GNUNET_SCHEDULER_TaskIdentifier
                              prerequisite_task,
                              struct GNUNET_TIME_Relative delay,
                              GNUNET_SCHEDULER_Task main, void *cls);


/**
 * Schedule a new task to be run with a specified delay or when the
 * specified file descriptor is ready for reading.  The delay can be
 * used as a timeout on the socket being ready.  The task will be
 * scheduled for execution once either the delay has expired or the
 * socket operation is ready.
 *
 * @param sched scheduler to use
 * @param run_on_shutdown run on shutdown? Set this
 *        argument to GNUNET_NO to skip this task if
 *        the user requested process termination.
 * @param prio how important is this task?
 * @param prerequisite_task run this task after the task with the given
 *        task identifier completes (and any of our other
 *        conditions, such as delay, read or write-readyness
 *        are satisfied).  Use  GNUNET_SCHEDULER_NO_TASK to not have any dependency
 *        on completion of other tasks.
 * @param delay how long should we wait? Use  GNUNET_TIME_UNIT_FOREVER_REL for "forever"
 * @param rfd read file-descriptor
 * @param main main function of the task
 * @param cls closure of task
 * @return unique task identifier for the job
 *         only valid until "main" is started!
 */
GNUNET_SCHEDULER_TaskIdentifier
GNUNET_SCHEDULER_add_read_net (struct GNUNET_SCHEDULER_Handle *sched,
                           int run_on_shutdown,
                           enum GNUNET_SCHEDULER_Priority prio,
                           GNUNET_SCHEDULER_TaskIdentifier prerequisite_task,
                           struct GNUNET_TIME_Relative delay,
                           struct GNUNET_NETWORK_Descriptor *rfd, GNUNET_SCHEDULER_Task main, void *cls);


/**
 * Schedule a new task to be run with a specified delay or when the
 * specified file descriptor is ready for writing.  The delay can be
 * used as a timeout on the socket being ready.  The task will be
 * scheduled for execution once either the delay has expired or the
 * socket operation is ready.
 *
 * @param sched scheduler to use
 * @param run_on_shutdown run on shutdown? Set this
 *        argument to GNUNET_NO to skip this task if
 *        the user requested process termination.
 * @param prio how important is this task?
 * @param prerequisite_task run this task after the task with the given
 *        task identifier completes (and any of our other
 *        conditions, such as delay, read or write-readyness
 *        are satisfied).  Use  GNUNET_SCHEDULER_NO_TASK to not have any dependency
 *        on completion of other tasks.
 * @param delay how long should we wait? Use  GNUNET_TIME_UNIT_FOREVER_REL for "forever"
 * @param wfd write file-descriptor
 * @param main main function of the task
 * @param cls closure of task
 * @return unique task identifier for the job
 *         only valid until "main" is started!
 */
GNUNET_SCHEDULER_TaskIdentifier
GNUNET_SCHEDULER_add_write_net (struct GNUNET_SCHEDULER_Handle *sched,
                            int run_on_shutdown,
                            enum GNUNET_SCHEDULER_Priority prio,
                            GNUNET_SCHEDULER_TaskIdentifier prerequisite_task,
                            struct GNUNET_TIME_Relative delay,
                            struct GNUNET_NETWORK_Descriptor *wfd, GNUNET_SCHEDULER_Task main, void *cls);


/**
 * Schedule a new task to be run with a specified delay or when the
 * specified file descriptor is ready for reading.  The delay can be
 * used as a timeout on the socket being ready.  The task will be
 * scheduled for execution once either the delay has expired or the
 * socket operation is ready.
 *
 * @param sched scheduler to use
 * @param run_on_shutdown run on shutdown? Set this
 *        argument to GNUNET_NO to skip this task if
 *        the user requested process termination.
 * @param prio how important is this task?
 * @param prerequisite_task run this task after the task with the given
 *        task identifier completes (and any of our other
 *        conditions, such as delay, read or write-readyness
 *        are satisfied).  Use  GNUNET_SCHEDULER_NO_TASK to not have any dependency
 *        on completion of other tasks.
 * @param delay how long should we wait? Use  GNUNET_TIME_UNIT_FOREVER_REL for "forever"
 * @param rfd read file-descriptor
 * @param main main function of the task
 * @param cls closure of task
 * @return unique task identifier for the job
 *         only valid until "main" is started!
 */
GNUNET_SCHEDULER_TaskIdentifier
GNUNET_SCHEDULER_add_read_file (struct GNUNET_SCHEDULER_Handle *sched,
                           int run_on_shutdown,
                           enum GNUNET_SCHEDULER_Priority prio,
                           GNUNET_SCHEDULER_TaskIdentifier prerequisite_task,
                           struct GNUNET_TIME_Relative delay,
                           struct GNUNET_DISK_FileHandle *rfd, GNUNET_SCHEDULER_Task main, void *cls);


/**
 * Schedule a new task to be run with a specified delay or when the
 * specified file descriptor is ready for writing.  The delay can be
 * used as a timeout on the socket being ready.  The task will be
 * scheduled for execution once either the delay has expired or the
 * socket operation is ready.
 *
 * @param sched scheduler to use
 * @param run_on_shutdown run on shutdown? Set this
 *        argument to GNUNET_NO to skip this task if
 *        the user requested process termination.
 * @param prio how important is this task?
 * @param prerequisite_task run this task after the task with the given
 *        task identifier completes (and any of our other
 *        conditions, such as delay, read or write-readyness
 *        are satisfied).  Use  GNUNET_SCHEDULER_NO_TASK to not have any dependency
 *        on completion of other tasks.
 * @param delay how long should we wait? Use  GNUNET_TIME_UNIT_FOREVER_REL for "forever"
 * @param wfd write file-descriptor
 * @param main main function of the task
 * @param cls closure of task
 * @return unique task identifier for the job
 *         only valid until "main" is started!
 */
GNUNET_SCHEDULER_TaskIdentifier
GNUNET_SCHEDULER_add_write_file (struct GNUNET_SCHEDULER_Handle *sched,
                            int run_on_shutdown,
                            enum GNUNET_SCHEDULER_Priority prio,
                            GNUNET_SCHEDULER_TaskIdentifier prerequisite_task,
                            struct GNUNET_TIME_Relative delay,
                            struct GNUNET_DISK_FileHandle *wfd, GNUNET_SCHEDULER_Task main, void *cls);


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
 * @param run_on_shutdown run on shutdown?  Set this
 *        argument to GNUNET_NO to skip this task if
 *        the user requested process termination.
 * @param prio how important is this task?
 * @param prerequisite_task run this task after the task with the given
 *        task identifier completes (and any of our other
 *        conditions, such as delay, read or write-readyness
 *        are satisfied).  Use GNUNET_SCHEDULER_NO_TASK to not have any dependency
 *        on completion of other tasks.
 * @param delay how long should we wait? Use GNUNET_TIME_UNIT_FOREVER_REL for "forever"
 * @param nfds highest-numbered file descriptor in any of the two sets plus one
 * @param rs set of file descriptors we want to read (can be NULL)
 * @param ws set of file descriptors we want to write (can be NULL)
 * @param main main function of the task
 * @param cls closure of task
 * @return unique task identifier for the job
 *         only valid until "main" is started!
 */
GNUNET_SCHEDULER_TaskIdentifier
GNUNET_SCHEDULER_add_select (struct GNUNET_SCHEDULER_Handle *sched,
                             int run_on_shutdown,
                             enum GNUNET_SCHEDULER_Priority prio,
                             GNUNET_SCHEDULER_TaskIdentifier
                             prerequisite_task,
                             struct GNUNET_TIME_Relative delay,
                             const struct GNUNET_NETWORK_FDSet * rs, const struct GNUNET_NETWORK_FDSet * ws,
                             GNUNET_SCHEDULER_Task main, void *cls);

#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

#endif

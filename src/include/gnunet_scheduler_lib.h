/*
      This file is part of GNUnet
      Copyright (C) 2009-2015 Christian Grothoff (and other contributing authors)

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
 * @file include/gnunet_scheduler_lib.h
 * @brief API to schedule computations using continuation passing style
 * @author Christian Grothoff
 * @defgroup scheduler Event loop (scheduler)
 * @{
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

/**
 * Opaque reference to a task.
 */
struct GNUNET_SCHEDULER_Task;

/**
 * Reasons why the schedule may have triggered
 * the task now.
 */
enum GNUNET_SCHEDULER_Reason
{
  /**
   * This task is not ready.
   */
  GNUNET_SCHEDULER_REASON_NONE = 0,

  /**
   * This is the very first task run during startup.
   */
  GNUNET_SCHEDULER_REASON_STARTUP = 1,

  /**
   * We are shutting down and are running all shutdown-related tasks
   * (regardless of timeout, etc.).
   */
  GNUNET_SCHEDULER_REASON_SHUTDOWN = 2,

  /**
   * The specified timeout has expired.
   * (also set if the delay given was 0).
   */
  GNUNET_SCHEDULER_REASON_TIMEOUT = 4,

  /**
   * The reading socket is ready.
   */
  GNUNET_SCHEDULER_REASON_READ_READY = 8,

  /**
   * The writing socket is ready.
   */
  GNUNET_SCHEDULER_REASON_WRITE_READY = 16,

  /**
   * The prerequisite task is done.
   */
  GNUNET_SCHEDULER_REASON_PREREQ_DONE = 32
};


#include "gnunet_time_lib.h"
#include "gnunet_network_lib.h"


/**
 * Context information passed to each scheduler task.
 */
struct GNUNET_SCHEDULER_TaskContext
{
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
typedef void
(*GNUNET_SCHEDULER_TaskCallback) (void *cls,
                                  const struct GNUNET_SCHEDULER_TaskContext *tc);


/**
 * Signature of the select function used by the scheduler.
 * #GNUNET_NETWORK_socket_select matches it.
 *
 * @param cls closure
 * @param rfds set of sockets to be checked for readability
 * @param wfds set of sockets to be checked for writability
 * @param efds set of sockets to be checked for exceptions
 * @param timeout relative value when to return
 * @return number of selected sockets, #GNUNET_SYSERR on error
 */
typedef int
(*GNUNET_SCHEDULER_select) (void *cls,
                            struct GNUNET_NETWORK_FDSet *rfds,
                            struct GNUNET_NETWORK_FDSet *wfds,
                            struct GNUNET_NETWORK_FDSet *efds,
                            struct GNUNET_TIME_Relative timeout);


/**
 * Initialize and run scheduler.  This function will return when all
 * tasks have completed.  On systems with signals, receiving a SIGTERM
 * (and other similar signals) will cause #GNUNET_SCHEDULER_shutdown
 * to be run after the active task is complete.  As a result, SIGTERM
 * causes all active tasks to be scheduled with reason
 * #GNUNET_SCHEDULER_REASON_SHUTDOWN.  (However, tasks added
 * afterwards will execute normally!).  Note that any particular
 * signal will only shut down one scheduler; applications should
 * always only create a single scheduler.
 *
 * @param task task to run first (and immediately)
 * @param task_cls closure of @a task
 */
void
GNUNET_SCHEDULER_run (GNUNET_SCHEDULER_TaskCallback task,
                      void *task_cls);


/**
 * Request the shutdown of the scheduler.  Marks all currently
 * pending tasks as ready because of shutdown.  This will
 * cause all tasks to run (as soon as possible, respecting
 * priorities and prerequisite tasks).  Note that tasks
 * scheduled AFTER this call may still be delayed arbitrarily.
 */
void
GNUNET_SCHEDULER_shutdown (void);


/**
 * Get information about the current load of this scheduler.  Use this
 * function to determine if an elective task should be added or simply
 * dropped (if the decision should be made based on the number of
 * tasks ready to run).
 *
 * @param p priority-level to query, use KEEP to query the level
 *          of the current task, use COUNT to get the sum over
 *          all priority levels
 * @return number of tasks pending right now
 */
unsigned int
GNUNET_SCHEDULER_get_load (enum GNUNET_SCHEDULER_Priority p);


/**
 * Obtain the reason code for why the current task was
 * started.  Will return the same value as
 * the GNUNET_SCHEDULER_TaskContext's reason field.
 *
 * @return reason(s) why the current task is run
 */
enum GNUNET_SCHEDULER_Reason
GNUNET_SCHEDULER_get_reason (void);


/**
 * Cancel the task with the specified identifier.
 * The task must not yet have run.
 *
 * @param task id of the task to cancel
 * @return the closure of the callback of the cancelled task
 */
void *
GNUNET_SCHEDULER_cancel (struct GNUNET_SCHEDULER_Task *task);


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
                                               enum GNUNET_SCHEDULER_Priority priority);


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
                                    void *task_cls);


/**
 * Schedule a new task to be run as soon as possible. Note that this
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
                          void *task_cls);


/**
 * Schedule a new task to be run as soon as possible with the
 * (transitive) ignore-shutdown flag either explicitly set or
 * explicitly enabled.  This task (and all tasks created from it,
 * other than by another call to this function) will either count or
 * not count for the 'lifeness' of the process.  This API is only
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
                                        void *task_cls);


/**
 * Schedule a new task to be run with a specified delay.  The task
 * will be scheduled for execution once the delay has expired. It
 * will be run with the DEFAULT priority.
 *
 * * @param delay when should this operation time out? Use
 *        #GNUNET_TIME_UNIT_FOREVER_REL for "on shutdown"
 * @param task main function of the task
 * @param task_cls closure of @a task
 * @return unique task identifier for the job
 *         only valid until @a task is started!
 */
struct GNUNET_SCHEDULER_Task *
GNUNET_SCHEDULER_add_delayed (struct GNUNET_TIME_Relative delay,
                              GNUNET_SCHEDULER_TaskCallback task,
                              void *task_cls);


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
                                            void *task_cls);


/**
 * Schedule a new task to be run with a specified delay or when the
 * specified file descriptor is ready for reading.  The delay can be
 * used as a timeout on the socket being ready.  The task will be
 * scheduled for execution once either the delay has expired or the
 * socket operation is ready.  It will be run with the DEFAULT priority.
 *
 * * @param delay when should this operation time out? Use
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
                               void *task_cls);


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
                                             void *task_cls);


/**
 * Schedule a new task to be run with a specified delay or when the
 * specified file descriptor is ready for writing.  The delay can be
 * used as a timeout on the socket being ready.  The task will be
 * scheduled for execution once either the delay has expired or the
 * socket operation is ready.  It will be run with the DEFAULT priority.
 *
 * * @param delay when should this operation time out? Use
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
                                void *task_cls);


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
 *         only valid until "task" is started!
 */
struct GNUNET_SCHEDULER_Task *
GNUNET_SCHEDULER_add_net_with_priority  (struct GNUNET_TIME_Relative delay,
                                         enum GNUNET_SCHEDULER_Priority priority,
                                         struct GNUNET_NETWORK_Handle *fd,
                                         int on_read,
                                         int on_write,
                                         GNUNET_SCHEDULER_TaskCallback task,
                                         void *task_cls);

/**
 * Schedule a new task to be run with a specified delay or when the
 * specified file descriptor is ready for reading.  The delay can be
 * used as a timeout on the socket being ready.  The task will be
 * scheduled for execution once either the delay has expired or the
 * socket operation is ready. It will be run with the DEFAULT priority.
 *
 * * @param delay when should this operation time out? Use
 *        #GNUNET_TIME_UNIT_FOREVER_REL for "on shutdown"
 * @param rfd read file-descriptor
 * @param task main function of the task
 * @param task_cls closure of @a task
 * @return unique task identifier for the job
 *         only valid until "task" is started!
 */
struct GNUNET_SCHEDULER_Task *
GNUNET_SCHEDULER_add_read_file (struct GNUNET_TIME_Relative delay,
                                const struct GNUNET_DISK_FileHandle *rfd,
                                GNUNET_SCHEDULER_TaskCallback task,
                                void *task_cls);


/**
 * Schedule a new task to be run with a specified delay or when the
 * specified file descriptor is ready for writing.  The delay can be
 * used as a timeout on the socket being ready.  The task will be
 * scheduled for execution once either the delay has expired or the
 * socket operation is ready. It will be run with the DEFAULT priority.
 *
 * * @param delay when should this operation time out? Use
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
                                 GNUNET_SCHEDULER_TaskCallback task,
                                 void *task_cls);


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
                                         GNUNET_SCHEDULER_TaskCallback task,
                                         void *task_cls);


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
 *     || shutdown-active)
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
 *         only valid until "task" is started!
 */
struct GNUNET_SCHEDULER_Task *
GNUNET_SCHEDULER_add_select (enum GNUNET_SCHEDULER_Priority prio,
                             struct GNUNET_TIME_Relative delay,
                             const struct GNUNET_NETWORK_FDSet *rs,
                             const struct GNUNET_NETWORK_FDSet *ws,
                             GNUNET_SCHEDULER_TaskCallback task,
                             void *task_cls);

/**
 * Sets the select function to use in the scheduler (scheduler_select).
 *
 * @param new_select new select function to use (NULL to reset to default)
 * @param new_select_cls closure for 'new_select'
 */
void
GNUNET_SCHEDULER_set_select (GNUNET_SCHEDULER_select new_select,
                             void *new_select_cls);


/** @} */ /* end of group scheduler */

#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

#endif

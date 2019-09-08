/*
     This file is part of GNUnet.
     Copyright (C) 2009 GNUnet e.V.

     GNUnet is free software: you can redistribute it and/or modify it
     under the terms of the GNU Affero General Public License as published
     by the Free Software Foundation, either version 3 of the License,
     or (at your option) any later version.

     GNUnet is distributed in the hope that it will be useful, but
     WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
     Affero General Public License for more details.

     You should have received a copy of the GNU Affero General Public License
     along with this program.  If not, see <http://www.gnu.org/licenses/>.

     SPDX-License-Identifier: AGPL3.0-or-later
 */
/**
 * @file util/test_scheduler.c
 * @brief tests for the scheduler
 */
#include "platform.h"
#include "gnunet_util_lib.h"


static struct GNUNET_DISK_PipeHandle *p;

static const struct GNUNET_DISK_FileHandle *fds[2];

static struct GNUNET_SCHEDULER_Task *never_run_task;


static void
task2(void *cls)
{
  int *ok = cls;

  /* t3 should be ready (albeit with lower priority) */
  GNUNET_assert(1 ==
                GNUNET_SCHEDULER_get_load(GNUNET_SCHEDULER_PRIORITY_COUNT));
  GNUNET_assert(2 == *ok);
  (*ok) = 3;
}


static void
task3(void *cls)
{
  int *ok = cls;

  GNUNET_assert(3 == *ok);
  (*ok) = 4;
}


static void
taskWrt(void *cls)
{
  static char c;
  int *ok = cls;
  const struct GNUNET_SCHEDULER_TaskContext *tc;

  tc = GNUNET_SCHEDULER_get_task_context();
  GNUNET_assert(6 == *ok);
  GNUNET_assert(GNUNET_NETWORK_fdset_handle_isset(tc->write_ready, fds[1]));
  (*ok) = 7;
  GNUNET_assert(1 == GNUNET_DISK_file_write(fds[1], &c, 1));
}


static void
taskNeverRun(void *cls)
{
  GNUNET_assert(0);
}


static void
taskLastRd(void *cls)
{
  int *ok = cls;

  GNUNET_assert(8 == *ok);
  (*ok) = 0;
}


static void
taskLastSig(void *cls)
{
  int *ok = cls;

  GNUNET_SCHEDULER_cancel(never_run_task);
  GNUNET_assert(9 == *ok);
  (*ok) = 0;
}


static void
taskLastShutdown(void *cls)
{
  int *ok = cls;

  GNUNET_assert(10 == *ok);
  (*ok) = 0;
}


static void
taskRd(void *cls)
{
  static char c;
  int *ok = cls;
  const struct GNUNET_SCHEDULER_TaskContext *tc;

  tc = GNUNET_SCHEDULER_get_task_context();
  GNUNET_assert(7 == *ok);
  GNUNET_assert(GNUNET_NETWORK_fdset_handle_isset(tc->read_ready, fds[0]));
  GNUNET_assert(1 == GNUNET_DISK_file_read(fds[0], &c, 1));
  (*ok) = 8;
  GNUNET_SCHEDULER_add_shutdown(&taskLastRd,
                                cls);
  GNUNET_SCHEDULER_shutdown();
}


static void
task4(void *cls)
{
  int *ok = cls;

  GNUNET_assert(4 == *ok);
  (*ok) = 6;
  p = GNUNET_DISK_pipe(GNUNET_NO, GNUNET_NO, GNUNET_NO, GNUNET_NO);
  GNUNET_assert(NULL != p);
  fds[0] = GNUNET_DISK_pipe_handle(p, GNUNET_DISK_PIPE_END_READ);
  fds[1] = GNUNET_DISK_pipe_handle(p, GNUNET_DISK_PIPE_END_WRITE);
  GNUNET_SCHEDULER_add_read_file(GNUNET_TIME_UNIT_FOREVER_REL,
                                 fds[0],
                                 &taskRd,
                                 cls);
  GNUNET_SCHEDULER_add_write_file(GNUNET_TIME_UNIT_FOREVER_REL,
                                  fds[1],
                                  &taskWrt,
                                  cls);
}


static void
task1(void *cls)
{
  int *ok = cls;

  GNUNET_assert(1 == *ok);
  (*ok) = 2;
  GNUNET_SCHEDULER_add_now(&task3, cls);
  GNUNET_SCHEDULER_add_with_priority(GNUNET_SCHEDULER_PRIORITY_UI,
                                     &task2,
                                     cls);
  GNUNET_SCHEDULER_add_delayed(GNUNET_TIME_UNIT_SECONDS,
                               &task4,
                               cls);
}


/**
 * Main method, starts scheduler with task1,
 * checks that "ok" is correct at the end.
 */
static int
check()
{
  int ok;

  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
             "[Check scheduling]\n");
  ok = 1;
  GNUNET_SCHEDULER_run(&task1, &ok);
  return ok;
}


static void
taskShutdown(void *cls)
{
  int *ok = cls;

  GNUNET_assert(1 == *ok);
  *ok = 10;
  GNUNET_SCHEDULER_add_shutdown(&taskLastShutdown, cls);
  GNUNET_SCHEDULER_shutdown();
}


/**
 * Main method, starts scheduler with task1,
 * checks that "ok" is correct at the end.
 */
static int
checkShutdown()
{
  int ok;

  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
             "[Check shutdown]\n");
  ok = 1;
  GNUNET_SCHEDULER_run(&taskShutdown, &ok);
  return ok;
}


#ifndef MINGW
static void
taskSig(void *cls)
{
  int *ok = cls;

  GNUNET_assert(1 == *ok);
  *ok = 9;
  GNUNET_SCHEDULER_add_shutdown(&taskLastSig, cls);
  never_run_task =
    GNUNET_SCHEDULER_add_delayed(GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_SECONDS, 5),
                                 &taskNeverRun,
                                 NULL);
  GNUNET_break(0 == kill(getpid(),
                         GNUNET_TERM_SIG));
}


/**
 * Main method, starts scheduler with task1,
 * checks that "ok" is correct at the end.
 */
static int
checkSignal()
{
  int ok;

  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
             "[Check signal handling]\n");
  ok = 1;
  GNUNET_SCHEDULER_run(&taskSig, &ok);
  return ok;
}
#endif


static void
taskCancel(void *cls)
{
  int *ok = cls;

  GNUNET_assert(1 == *ok);
  *ok = 0;
  GNUNET_SCHEDULER_cancel(GNUNET_SCHEDULER_add_now(&taskNeverRun, NULL));
}


/**
 * Main method, starts scheduler with task1,
 * checks that "ok" is correct at the end.
 */
static int
checkCancel()
{
  int ok;

  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
             "[Check task cancellation]\n");
  ok = 1;
  GNUNET_SCHEDULER_run(&taskCancel, &ok);
  return ok;
}


int
main(int argc, char *argv[])
{
  int ret = 0;

  GNUNET_log_setup("test_scheduler", "WARNING", NULL);
  ret += check();
  ret += checkCancel();
#ifndef MINGW
  ret += checkSignal();
#endif
  ret += checkShutdown();
  GNUNET_DISK_pipe_close(p);

  return ret;
}

/* end of test_scheduler.c */

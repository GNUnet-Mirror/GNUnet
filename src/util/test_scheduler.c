/*
     This file is part of GNUnet.
     (C) 2009 Christian Grothoff (and other contributing authors)

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
     Free Software Foundation, Inc., 59 Temple Place - Suite 330,
     Boston, MA 02111-1307, USA.
*/
/**
 * @file util/test_scheduler.c
 * @brief tests for the scheduler
 */
#include "platform.h"
#include "gnunet_util_lib.h"


struct GNUNET_DISK_PipeHandle *p;

static const struct GNUNET_DISK_FileHandle *fds[2];


static void
task2 (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  int *ok = cls;

  /* t3 should be ready (albeit with lower priority) */
  GNUNET_assert (1 ==
                 GNUNET_SCHEDULER_get_load (GNUNET_SCHEDULER_PRIORITY_COUNT));
  GNUNET_assert (2 == *ok);
  (*ok) = 3;
}


static void
task3 (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  int *ok = cls;

  GNUNET_assert (3 == *ok);
  (*ok) = 4;
}


static void
taskWrt (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  static char c;
  int *ok = cls;

  GNUNET_assert (6 == *ok);
  GNUNET_assert (GNUNET_NETWORK_fdset_handle_isset (tc->write_ready, fds[1]));
  (*ok) = 7;
  GNUNET_assert (1 == GNUNET_DISK_file_write (fds[1], &c, 1));
}


static void
taskNeverRun (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  GNUNET_assert (0);
}


static void
taskLast (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  int *ok = cls;

  /* t4 should be ready (albeit with lower priority) */
  GNUNET_assert (8 == *ok);
  (*ok) = 0;
}


static void
taskRd (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  static char c;
  int *ok = cls;

  GNUNET_assert (7 == *ok);
  GNUNET_assert (GNUNET_NETWORK_fdset_handle_isset (tc->read_ready, fds[0]));
  GNUNET_assert (1 == GNUNET_DISK_file_read (fds[0], &c, 1));
  (*ok) = 8;
  GNUNET_SCHEDULER_add_with_priority (GNUNET_SCHEDULER_PRIORITY_IDLE, &taskLast,
                                      cls);
  GNUNET_SCHEDULER_shutdown ();
}


static void
task4 (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  int *ok = cls;

  GNUNET_assert (4 == *ok);
  (*ok) = 6;
  p = GNUNET_DISK_pipe (GNUNET_NO, GNUNET_NO, GNUNET_NO, GNUNET_NO);
  GNUNET_assert (NULL != p);
  fds[0] = GNUNET_DISK_pipe_handle (p, GNUNET_DISK_PIPE_END_READ);
  fds[1] = GNUNET_DISK_pipe_handle (p, GNUNET_DISK_PIPE_END_WRITE);
  GNUNET_SCHEDULER_add_read_file (GNUNET_TIME_UNIT_FOREVER_REL, fds[0], &taskRd,
                                  cls);
  GNUNET_SCHEDULER_add_write_file (GNUNET_TIME_UNIT_FOREVER_REL, fds[1],
                                   &taskWrt, cls);
}


static void
task1 (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  int *ok = cls;

  GNUNET_assert (1 == *ok);
  (*ok) = 2;
  GNUNET_SCHEDULER_add_now (&task3, cls);
  GNUNET_SCHEDULER_add_with_priority (GNUNET_SCHEDULER_PRIORITY_UI, &task2,
                                      cls);
  GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_SECONDS, &task4, cls);
}


/**
 * Main method, starts scheduler with task1,
 * checks that "ok" is correct at the end.
 */
static int
check ()
{
  int ok;

  ok = 1;
  GNUNET_SCHEDULER_run (&task1, &ok);
  return ok;
}


static void
taskShutdown (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  int *ok = cls;

  GNUNET_assert (1 == *ok);
  *ok = 8;
  GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_FOREVER_REL, &taskLast, cls);
  GNUNET_SCHEDULER_shutdown ();
}


/**
 * Main method, starts scheduler with task1,
 * checks that "ok" is correct at the end.
 */
static int
checkShutdown ()
{
  int ok;

  ok = 1;
  GNUNET_SCHEDULER_run (&taskShutdown, &ok);
  return ok;
}


#ifndef MINGW
static void
taskSig (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  int *ok = cls;

  GNUNET_assert (1 == *ok);
  *ok = 8;
  GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_FOREVER_REL, &taskLast, cls);
  GNUNET_break (0 == PLIBC_KILL (getpid (), SIGTERM));
}


/**
 * Main method, starts scheduler with task1,
 * checks that "ok" is correct at the end.
 */
static int
checkSignal ()
{
  int ok;

  ok = 1;
  GNUNET_SCHEDULER_run (&taskSig, &ok);
  return ok;
}
#endif


static void
taskCancel (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  int *ok = cls;

  GNUNET_assert (1 == *ok);
  *ok = 0;
  GNUNET_SCHEDULER_cancel (GNUNET_SCHEDULER_add_now
                           (&taskNeverRun, NULL));
}


/**
 * Main method, starts scheduler with task1,
 * checks that "ok" is correct at the end.
 */
static int
checkCancel ()
{
  int ok;

  ok = 1;
  GNUNET_SCHEDULER_run (&taskCancel, &ok);
  return ok;
}


int
main (int argc, char *argv[])
{
  int ret = 0;

  GNUNET_log_setup ("test_scheduler", "WARNING", NULL);
  ret += check ();
#ifndef MINGW
  ret += checkSignal ();
#endif
  ret += checkShutdown ();
  ret += checkCancel ();
  GNUNET_DISK_pipe_close (p);

  return ret;
}

/* end of test_scheduler.c */

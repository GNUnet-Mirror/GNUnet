/*
     This file is part of GNUnet.
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
 * @file util/test_scheduler.c
 * @brief tests for the scheduler
 */
#include "platform.h"
#include "gnunet_common.h"
#include "gnunet_scheduler_lib.h"
#include "gnunet_time_lib.h"

#define VERBOSE GNUNET_NO

static void
task2 (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  int *ok = cls;
  GNUNET_assert (2 == *ok);
  (*ok) = 3;
}

static void
task3 (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  int *ok = cls;
  /* t4 should be ready (albeit with lower priority) */
  GNUNET_assert (1 == GNUNET_SCHEDULER_get_load (tc->sched,
                                                 GNUNET_SCHEDULER_PRIORITY_COUNT));
  GNUNET_assert (3 == *ok);
  (*ok) = 4;
}

static void
task4 (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  int *ok = cls;
  GNUNET_assert (4 == *ok);
  (*ok) = 5;
}

static int fds[2];


static void
taskWrt (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  static char c;
  int *ok = cls;
  GNUNET_assert (6 == *ok);
  GNUNET_assert (FD_ISSET (fds[1], tc->write_ready));
  (*ok) = 7;
  GNUNET_assert (1 == WRITE (fds[1], &c, 1));
  GNUNET_break (0 == CLOSE (fds[1]));
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
  GNUNET_assert (FD_ISSET (fds[0], tc->read_ready));
  GNUNET_assert (1 == READ (fds[0], &c, 1));
  GNUNET_break (0 == CLOSE (fds[0]));
  (*ok) = 8;
  GNUNET_SCHEDULER_add_after (tc->sched,
                              GNUNET_NO,
                              GNUNET_SCHEDULER_PRIORITY_UI,
                              0, &taskNeverRun, NULL);
  GNUNET_SCHEDULER_add_after (tc->sched,
                              GNUNET_YES,
                              GNUNET_SCHEDULER_PRIORITY_IDLE,
                              0, &taskLast, cls);
  GNUNET_SCHEDULER_shutdown (tc->sched);
}


static void
task5 (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  int *ok = cls;
  GNUNET_assert (5 == *ok);
  (*ok) = 6;
  GNUNET_assert (0 == PIPE (fds));
  GNUNET_SCHEDULER_add_read (tc->sched,
                             GNUNET_NO,
                             GNUNET_SCHEDULER_PRIORITY_DEFAULT,
                             GNUNET_SCHEDULER_NO_TASK,
                             GNUNET_TIME_UNIT_FOREVER_REL,
                             fds[0], &taskRd, cls);
  GNUNET_SCHEDULER_add_write (tc->sched,
                              GNUNET_NO,
                              GNUNET_SCHEDULER_PRIORITY_DEFAULT,
                              GNUNET_SCHEDULER_NO_TASK,
                              GNUNET_TIME_UNIT_FOREVER_REL,
                              fds[1], &taskWrt, cls);
}


static void
task1 (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  int *ok = cls;
  GNUNET_SCHEDULER_TaskIdentifier t2;
  GNUNET_SCHEDULER_TaskIdentifier t3;
  GNUNET_SCHEDULER_TaskIdentifier t4;

  GNUNET_assert (1 == *ok);
  (*ok) = 2;
  /* t2 will go first -- prereq for all */
  t2 = GNUNET_SCHEDULER_add_after (tc->sched,
                                   GNUNET_NO,
                                   GNUNET_SCHEDULER_PRIORITY_IDLE,
                                   GNUNET_SCHEDULER_NO_TASK,
                                   &task2, cls);
  /* t3 will go before t4: higher priority */
  t4 = GNUNET_SCHEDULER_add_after (tc->sched,
                                   GNUNET_NO,
                                   GNUNET_SCHEDULER_PRIORITY_IDLE,
                                   t2, &task4, cls);
  t3 = GNUNET_SCHEDULER_add_delayed (tc->sched,
                                     GNUNET_NO,
                                     GNUNET_SCHEDULER_PRIORITY_DEFAULT,
                                     t2,
                                     GNUNET_TIME_relative_get_zero (),
                                     &task3, cls);
  /* t4 will go first: lower prio, but prereq! */
  GNUNET_SCHEDULER_add_after (tc->sched,
                              GNUNET_NO,
                              GNUNET_SCHEDULER_PRIORITY_UI, t4, &task5, cls);
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
taskSig (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  int *ok = cls;
  GNUNET_assert (1 == *ok);
  *ok = 8;
  GNUNET_SCHEDULER_add_after (tc->sched,
                              GNUNET_NO,
                              GNUNET_SCHEDULER_PRIORITY_UI,
                              0, &taskNeverRun, NULL);
  GNUNET_SCHEDULER_add_after (tc->sched,
                              GNUNET_YES,
                              GNUNET_SCHEDULER_PRIORITY_UI,
                              0, &taskLast, cls);
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




static void
taskCancel (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  int *ok = cls;

  GNUNET_assert (1 == *ok);
  *ok = 0;
  GNUNET_SCHEDULER_cancel (tc->sched,
                           GNUNET_SCHEDULER_add_after (tc->sched,
                                                       GNUNET_NO,
                                                       GNUNET_SCHEDULER_PRIORITY_UI,
                                                       0,
                                                       &taskNeverRun, NULL));
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
  ret += checkSignal ();
  ret += checkCancel ();

  return ret;
}

/* end of test_scheduler.c */

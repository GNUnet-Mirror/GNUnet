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
 * @file util/test_os_start_process.c
 * @brief testcase for os start process code
 *
 * This testcase simply calls the os start process code
 * giving a file descriptor to write stdout to.  If the
 * correct data "HELLO" is read then all is well.
 */
#include "platform.h"
#include "gnunet_common.h"
#include "gnunet_getopt_lib.h"
#include "gnunet_os_lib.h"
#include "gnunet_program_lib.h"
#include "gnunet_scheduler_lib.h"
#include "disk.h"

#define VERBOSE GNUNET_NO

static char *test_phrase = "HELLO WORLD";
static int ok;

static struct GNUNET_OS_Process *proc;

/* Pipe to write to started processes stdin (on write end) */
static struct GNUNET_DISK_PipeHandle *hello_pipe_stdin;

/* Pipe to read from started processes stdout (on read end) */
static struct GNUNET_DISK_PipeHandle *hello_pipe_stdout;

static GNUNET_SCHEDULER_TaskIdentifier die_task;

static void
end_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  if (0 != GNUNET_OS_process_kill (proc, SIGTERM))
  {
    GNUNET_log_strerror (GNUNET_ERROR_TYPE_WARNING, "kill");
  }
  GNUNET_assert (GNUNET_OK == GNUNET_OS_process_wait (proc));
  GNUNET_OS_process_destroy (proc);
  proc = NULL;
  GNUNET_DISK_pipe_close (hello_pipe_stdout);
  GNUNET_DISK_pipe_close (hello_pipe_stdin);
}

static void
read_call (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_DISK_FileHandle *stdout_read_handle = cls;
  char buf[16];

  memset (&buf, 0, sizeof (buf));
  int bytes;

  bytes = GNUNET_DISK_file_read (stdout_read_handle, &buf, sizeof (buf));

#if VERBOSE
  FPRINTF (stderr, "bytes is %d\n", bytes);
#endif

  if (bytes < 1)
  {
    GNUNET_break (0);
    ok = 1;
    GNUNET_SCHEDULER_cancel (die_task);
    GNUNET_SCHEDULER_add_now (&end_task, NULL);
    return;
  }

  ok = strncmp (&buf[0], test_phrase, strlen (test_phrase));
#if VERBOSE
  FPRINTF (stderr, "read %s\n", &buf[0]);
#endif
  if (ok == 0)
  {
    GNUNET_SCHEDULER_cancel (die_task);
    GNUNET_SCHEDULER_add_now (&end_task, NULL);
    return;
  }

  GNUNET_SCHEDULER_add_read_file (GNUNET_TIME_UNIT_FOREVER_REL,
                                  stdout_read_handle, &read_call,
                                  stdout_read_handle);

}


static void
run_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  char *fn;
  const struct GNUNET_DISK_FileHandle *stdout_read_handle;
  const struct GNUNET_DISK_FileHandle *wh;

  GNUNET_asprintf (&fn, "cat");

  hello_pipe_stdin = GNUNET_DISK_pipe (GNUNET_YES, GNUNET_YES, GNUNET_YES, GNUNET_NO);
  hello_pipe_stdout = GNUNET_DISK_pipe (GNUNET_YES, GNUNET_YES, GNUNET_NO, GNUNET_YES);

  if ((hello_pipe_stdout == NULL) || (hello_pipe_stdin == NULL))
  {
    GNUNET_break (0);
    ok = 1;
    GNUNET_free (fn);
    return;
  }

  proc =
      GNUNET_OS_start_process (GNUNET_NO, hello_pipe_stdin, hello_pipe_stdout, fn,
                               "test_gnunet_echo_hello", "-", NULL);
  GNUNET_free (fn);

  /* Close the write end of the read pipe */
  GNUNET_DISK_pipe_close_end (hello_pipe_stdout, GNUNET_DISK_PIPE_END_WRITE);
  /* Close the read end of the write pipe */
  GNUNET_DISK_pipe_close_end (hello_pipe_stdin, GNUNET_DISK_PIPE_END_READ);

  wh = GNUNET_DISK_pipe_handle (hello_pipe_stdin, GNUNET_DISK_PIPE_END_WRITE);

  /* Write the test_phrase to the cat process */
  if (GNUNET_DISK_file_write (wh, test_phrase, strlen (test_phrase) + 1) !=
      strlen (test_phrase) + 1)
  {
    GNUNET_break (0);
    ok = 1;
    return;
  }

  /* Close the write end to end the cycle! */
  GNUNET_DISK_pipe_close_end (hello_pipe_stdin, GNUNET_DISK_PIPE_END_WRITE);

  stdout_read_handle =
      GNUNET_DISK_pipe_handle (hello_pipe_stdout, GNUNET_DISK_PIPE_END_READ);

  die_task =
      GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_relative_multiply
                                    (GNUNET_TIME_UNIT_MINUTES, 1), &end_task,
                                    NULL);

  GNUNET_SCHEDULER_add_read_file (GNUNET_TIME_UNIT_FOREVER_REL,
                                  stdout_read_handle, &read_call,
                                  (void *) stdout_read_handle);
}


/**
 * Main method, starts scheduler with task1,
 * checks that "ok" is correct at the end.
 */
static int
check_run ()
{
  ok = 1;
  GNUNET_SCHEDULER_run (&run_task, &ok);
  return ok;
}


/**
 * Test killing via pipe.
 */
static int
check_kill ()
{
  hello_pipe_stdin = GNUNET_DISK_pipe (GNUNET_YES, GNUNET_YES, GNUNET_YES, GNUNET_NO);
  hello_pipe_stdout = GNUNET_DISK_pipe (GNUNET_YES, GNUNET_YES, GNUNET_NO, GNUNET_YES);
  if ((hello_pipe_stdout == NULL) || (hello_pipe_stdin == NULL))
  {
    return 1;
  }
  proc =
    GNUNET_OS_start_process (GNUNET_YES, hello_pipe_stdin, hello_pipe_stdout, "cat",
			     "gnunet-service-resolver", "-", NULL); 
  sleep (1); /* give process time to start and open pipe */
  if (0 != GNUNET_OS_process_kill (proc, SIGTERM))
  {
    GNUNET_log_strerror (GNUNET_ERROR_TYPE_WARNING, "kill");
  }
  GNUNET_assert (GNUNET_OK == GNUNET_OS_process_wait (proc));
  GNUNET_OS_process_destroy (proc);
  proc = NULL;
  GNUNET_DISK_pipe_close (hello_pipe_stdout);
  GNUNET_DISK_pipe_close (hello_pipe_stdin);
  return 0;
}


/**
 * Test killing via pipe.
 */
static int
check_instant_kill ()
{
  hello_pipe_stdin = GNUNET_DISK_pipe (GNUNET_YES, GNUNET_YES, GNUNET_YES, GNUNET_NO);
  hello_pipe_stdout = GNUNET_DISK_pipe (GNUNET_YES, GNUNET_YES, GNUNET_NO, GNUNET_YES);
  if ((hello_pipe_stdout == NULL) || (hello_pipe_stdin == NULL))
  {
    return 1;
  }
  proc =
    GNUNET_OS_start_process (GNUNET_YES, hello_pipe_stdin, hello_pipe_stdout, "cat",
			     "gnunet-service-resolver", "-", NULL); 
  if (0 != GNUNET_OS_process_kill (proc, SIGTERM))
  {
    GNUNET_log_strerror (GNUNET_ERROR_TYPE_WARNING, "kill");
  }
  GNUNET_assert (GNUNET_OK == GNUNET_OS_process_wait (proc));
  GNUNET_OS_process_destroy (proc);
  proc = NULL;
  GNUNET_DISK_pipe_close (hello_pipe_stdout);
  GNUNET_DISK_pipe_close (hello_pipe_stdin);
  return 0;
}


int
main (int argc, char *argv[])
{
  int ret;

  GNUNET_log_setup ("test-os-start-process",
#if VERBOSE
                    "DEBUG",
#else
                    "WARNING",
#endif
                    NULL);
  ret = 0;
  ret |= check_run ();
  ret |= check_kill ();
  ret |= check_instant_kill ();

  return ret;
}

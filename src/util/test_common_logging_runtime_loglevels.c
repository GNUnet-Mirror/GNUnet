/*
     This file is part of GNUnet.
     (C) 2011 Christian Grothoff (and other contributing authors)

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
 * @file util/test_common_logging_runtime_loglevels.c
 * @brief testcase for the logging module  (runtime log level adjustment)
 * @author LRN
 */
#include "platform.h"
#include "gnunet_common.h"
#include "gnunet_scheduler_lib.h"
#include "gnunet_network_lib.h"
#include "gnunet_disk_lib.h"
#include "gnunet_os_lib.h"

#define VERBOSE GNUNET_NO

static int ok;
static int phase = 0;

static struct GNUNET_OS_Process *proc;

/* Pipe to read from started processes stdout (on read end) */
static struct GNUNET_DISK_PipeHandle *pipe_stdout;

static GNUNET_SCHEDULER_TaskIdentifier die_task;

static void
runone (void);

static void
end_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Ending phase %d, ok is %d\n", phase,
              ok);
  if (0 != GNUNET_OS_process_kill (proc, SIGTERM))
  {
    GNUNET_log_strerror (GNUNET_ERROR_TYPE_WARNING, "kill");
  }
  GNUNET_OS_process_wait (proc);
  GNUNET_OS_process_close (proc);
  proc = NULL;
  GNUNET_DISK_pipe_close (pipe_stdout);
  if (ok == 1)
  {
    if (phase < 9)
    {
      phase += 1;
      runone ();
    }
    else
      ok = 0;
  }
  else
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "failing\n");
}

static char *
read_output_line (int phase_from1, int phase_to1, int phase_from2,
                  int phase_to2, char c, char *expect_level,
                  long delay_morethan, long delay_lessthan, int phase, char *p,
                  int *len, long *delay, char level[8])
{
  char *r = p;
  char t[7];
  int i, j, stop = 0;

  j = 0;
  int stage = 0;

  if (!(phase >= phase_from1 && phase <= phase_to1) &&
      !(phase >= phase_from2 && phase <= phase_to2))
    return p;
#if 0
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Trying to match '%c%s \\d\\r\\n' on %s\n", c, expect_level, p);
#endif
  for (i = 0; i < *len && !stop; i++)
  {
    switch (stage)
    {
    case 0:                    /* read first char */
      if (r[i] != c)
      {
        GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Expected '%c', but got '%c'\n", c,
                    r[i]);
        GNUNET_break (0);
        return NULL;
      }
      stage += 1;
      break;
    case 1:                    /* read at most 7 char-long error level string, finished by ' ' */
      if (r[i] == ' ')
      {
        level[j] = '\0';
        stage += 1;
        j = 0;
      }
      else if (i == 8)
      {
        GNUNET_break (0);
        ok = 2;
        return NULL;
      }
      else
        level[j++] = r[i];
      break;
    case 2:                    /* read the delay, finished by '\n' */
      t[j++] = r[i];
#if WINDOWS
      if (r[i] == '\r' && r[i + 1] == '\n')
      {
        i += 1;
        t[j - 1] = '\0';
        *delay = strtol (t, NULL, 10);
        stop = 1;
      }
#else
      if (r[i] == '\n')
      {
        t[j - 1] = '\0';
        *delay = strtol (t, NULL, 10);
        stop = 1;
      }
#endif
      break;
    }
  }
  if (!stop || strcmp (expect_level, level) != 0 || *delay < 0 || *delay > 1000
      || (!((*delay < delay_lessthan) || !(*delay > delay_morethan)) && c != '1'
          && c != '2'))
    return NULL;
  *len = *len - i;
  return &r[i];
}

char buf[20 * 16];
char *buf_ptr;
int bytes;

static void
read_call (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_DISK_FileHandle *stdout_read_handle = cls;
  char level[8];
  long delay;
  long delays[8];
  int rd;

  rd = GNUNET_DISK_file_read (stdout_read_handle, buf_ptr,
                              sizeof (buf) - bytes);
  if (rd > 0)
  {
    buf_ptr += rd;
    bytes += rd;
#if VERBOSE
    FPRINTF (stderr, "got %d bytes, reading more\n", rd);
#endif
    GNUNET_SCHEDULER_add_read_file (GNUNET_TIME_UNIT_FOREVER_REL,
                                    stdout_read_handle, &read_call,
                                    (void *) stdout_read_handle);
    return;
  }

#if VERBOSE
  FPRINTF (stderr, "bytes is %d:%s\n", bytes, buf);
#endif

  /* +------CHILD OUTPUT--
   * |      SOFT     HARD
   * |    E W I D  E W I D
   * | 0E *        * *
   * | 1W * *      * *
   * P 2I * * *    * *
   * H 3D * * * *  * *
   * A
   * S 4E *        *
   * E 5W * *      * *
   * | 6I * * *    * * *
   * | 7D * * * *  * * * *
   * | 8  * *      * *
   * | 9  * *      * *
   */
  char *p = buf;

  if (bytes == 20 * 16 ||
      !(p =
        read_output_line (0, 3, 4, 9, 'L', "ERROR", -1, 1, phase, p, &bytes,
                          &delay, level)) ||
      !(p =
        read_output_line (0, 3, 4, 9, '1', "ERROR", 200, 400, phase, p, &bytes,
                          &delays[0], level)) ||
      !(p =
        read_output_line (1, 3, 5, 9, 'L', "WARNING", -1, 1, phase, p, &bytes,
                          &delay, level)) ||
      !(p =
        read_output_line (0, 3, 4, 9, '1', "WARNING", 200, 400, phase, p,
                          &bytes, &delays[1], level)) ||
      !(p =
        read_output_line (2, 3, 6, 7, 'L', "INFO", -1, 1, phase, p, &bytes,
                          &delay, level)) ||
      !(p =
        read_output_line (0, 3, 4, 9, '1', "INFO", 200, 400, phase, p, &bytes,
                          &delays[2], level)) ||
      !(p =
        read_output_line (3, 3, 7, 7, 'L', "DEBUG", -1, 1, phase, p, &bytes,
                          &delay, level)) ||
      !(p =
        read_output_line (0, 3, 4, 9, '1', "DEBUG", 200, 400, phase, p, &bytes,
                          &delays[3], level)) ||
      !(p =
        read_output_line (0, 3, 4, 9, 'L', "ERROR", -1, 1, phase, p, &bytes,
                          &delay, level)) ||
      !(p =
        read_output_line (0, 3, 4, 9, '2', "ERROR", 200, 400, phase, p, &bytes,
                          &delays[4], level)) ||
      !(p =
        read_output_line (0, 3, 5, 9, 'L', "WARNING", -1, 1, phase, p, &bytes,
                          &delay, level)) ||
      !(p =
        read_output_line (0, 3, 4, 9, '2', "WARNING", 200, 400, phase, p,
                          &bytes, &delays[5], level)) ||
      !(p =
        read_output_line (-1, -1, 6, 7, 'L', "INFO", -1, 1, phase, p, &bytes,
                          &delay, level)) ||
      !(p =
        read_output_line (0, 3, 4, 9, '2', "INFO", 200, 400, phase, p, &bytes,
                          &delays[6], level)) ||
      !(p =
        read_output_line (-1, -1, 7, 7, 'L', "DEBUG", -1, 1, phase, p, &bytes,
                          &delay, level)) ||
      !(p =
        read_output_line (0, 3, 4, 9, '2', "DEBUG", 200, 400, phase, p, &bytes,
                          &delays[7], level)))
  {
    if (bytes == 20 * 16)
      FPRINTF (stderr, "%s",  "Ran out of buffer space!\n");
    GNUNET_break (0);
    ok = 2;
    GNUNET_SCHEDULER_cancel (die_task);
    GNUNET_SCHEDULER_add_now (&end_task, NULL);
    return;
  }

  GNUNET_SCHEDULER_cancel (die_task);
  GNUNET_SCHEDULER_add_now (&end_task, NULL);
}

static void
runone ()
{
  const struct GNUNET_DISK_FileHandle *stdout_read_handle;

  pipe_stdout = GNUNET_DISK_pipe (GNUNET_YES, GNUNET_YES, GNUNET_NO, GNUNET_YES);

  if (pipe_stdout == NULL)
  {
    GNUNET_break (0);
    ok = 2;
    return;
  }

  putenv ("GNUNET_LOG=");
  putenv ("GNUNET_FORCE_LOG=");
  putenv ("GNUNET_FORCE_LOGFILE=");
  switch (phase)
  {
  case 0:
    putenv ("GNUNET_LOG=;;;;ERROR");
    break;
  case 1:
    putenv ("GNUNET_LOG=;;;;WARNING");
    break;
  case 2:
    putenv ("GNUNET_LOG=;;;;INFO");
    break;
  case 3:
    putenv ("GNUNET_LOG=;;;;DEBUG");
    break;
  case 4:
    putenv ("GNUNET_FORCE_LOG=;;;;ERROR");
    break;
  case 5:
    putenv ("GNUNET_FORCE_LOG=;;;;WARNING");
    break;
  case 6:
    putenv ("GNUNET_FORCE_LOG=;;;;INFO");
    break;
  case 7:
    putenv ("GNUNET_FORCE_LOG=;;;;DEBUG");
    break;
  case 8:
    putenv ("GNUNET_LOG=blah;;;;ERROR");
    break;
  case 9:
    putenv ("GNUNET_FORCE_LOG=blah;;;;ERROR");
    break;
  }

  proc = GNUNET_OS_start_process (GNUNET_NO, NULL, pipe_stdout,
#if MINGW
                                  "test_common_logging_dummy",
#else
                                  "./test_common_logging_dummy",
#endif
                                  "test_common_logging_dummy", NULL);
  putenv ("GNUNET_FORCE_LOG=");
  putenv ("GNUNET_LOG=");

  /* Close the write end of the read pipe */
  GNUNET_DISK_pipe_close_end (pipe_stdout, GNUNET_DISK_PIPE_END_WRITE);

  stdout_read_handle =
      GNUNET_DISK_pipe_handle (pipe_stdout, GNUNET_DISK_PIPE_END_READ);

  die_task =
      GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_relative_multiply
                                    (GNUNET_TIME_UNIT_SECONDS, 10), &end_task,
                                    NULL);

  bytes = 0;
  buf_ptr = buf;
  memset (&buf, 0, sizeof (buf));

  GNUNET_SCHEDULER_add_read_file (GNUNET_TIME_UNIT_FOREVER_REL,
                                  stdout_read_handle, &read_call,
                                  (void *) stdout_read_handle);
}

static void
task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  phase = 0;
  runone ();
}

/**
 * Main method, starts scheduler with task1,
 * checks that "ok" is correct at the end.
 */
static int
check ()
{
  ok = 1;
  GNUNET_SCHEDULER_run (&task, &ok);
  return ok;
}


int
main (int argc, char *argv[])
{
  int ret;

  GNUNET_log_setup ("test-common-logging-runtime-loglevels",
#if VERBOSE
                    "DEBUG",
#else
                    "WARNING",
#endif
                    NULL);
  ret = check ();

  return ret;
}

/* end of test_common_logging_runtime_loglevels.c */

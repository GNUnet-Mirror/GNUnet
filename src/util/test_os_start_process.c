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
 * @file util/test_os_start_process.c
 * @brief testcase for os start process code
 *
 * This testcase simply calls the os start process code
 * giving a file descriptor to write stdout to.  If the
 * correct data "HELLO" is read then all is well.
 *
 */
#include "platform.h"
#include "gnunet_common.h"
#include "gnunet_getopt_lib.h"
#include "gnunet_os_lib.h"
#include "gnunet_program_lib.h"
#include "gnunet_scheduler_lib.h"
#include "disk.h"

#define VERBOSE GNUNET_NO

static int
check ()
{
  char *fn;
  pid_t pid;
  char *buf;
  int fd_stdout;
  int fd_stdin;
  int ret;
  static char *test_phrase = "HELLO WORLD";
  /* Pipe to write to started processes stdin (on write end) */
  struct GNUNET_DISK_PipeHandle *hello_pipe_stdin;
  /* Pipe to read from started processes stdout (on read end) */
  struct GNUNET_DISK_PipeHandle *hello_pipe_stdout;

  buf = GNUNET_malloc(strlen(test_phrase) + 1);
  GNUNET_asprintf(&fn, "cat");

  hello_pipe_stdin = GNUNET_DISK_pipe(GNUNET_YES);
  hello_pipe_stdout = GNUNET_DISK_pipe(GNUNET_YES);

  if ((hello_pipe_stdout == NULL) || (hello_pipe_stdin == NULL))
    return GNUNET_SYSERR;

  pid = GNUNET_OS_start_process (hello_pipe_stdin, hello_pipe_stdout, fn,
                                 "test_gnunet_echo_hello", NULL);

  /* Close the write end of the read pipe */
  GNUNET_DISK_pipe_close_end(hello_pipe_stdout, GNUNET_DISK_PIPE_END_WRITE);
  /* Close the read end of the write pipe */
  GNUNET_DISK_pipe_close_end(hello_pipe_stdin, GNUNET_DISK_PIPE_END_READ);
  /* Get the FD to read from */
  GNUNET_DISK_internal_file_handle_ (GNUNET_DISK_pipe_handle(hello_pipe_stdout, GNUNET_DISK_PIPE_END_READ), &fd_stdout, sizeof (int));
  /* Get the FD to write to */
  GNUNET_DISK_internal_file_handle_ (GNUNET_DISK_pipe_handle(hello_pipe_stdin, GNUNET_DISK_PIPE_END_WRITE), &fd_stdin, sizeof (int));

  /* Write the test_phrase to the cat process */
  ret = write(fd_stdin, test_phrase, strlen(test_phrase) + 1);

  /* Close the write end to end the cycle! */
  GNUNET_DISK_pipe_close_end(hello_pipe_stdin, GNUNET_DISK_PIPE_END_WRITE);

  ret = 0;
  /* Read from the cat process, hopefully get the phrase we wrote to it! */
  while (read(fd_stdout, buf, strlen(test_phrase) + 1) > 0)
    {
      ret = strncmp(buf, test_phrase, strlen(test_phrase));
    }

  if (0 != PLIBC_KILL (pid, SIGTERM))
    {
      GNUNET_log_strerror (GNUNET_ERROR_TYPE_WARNING, "kill");
    }
  GNUNET_OS_process_wait (pid);
  GNUNET_DISK_pipe_close(hello_pipe_stdout);
  GNUNET_DISK_pipe_close(hello_pipe_stdin);

  return ret;
}

int
main (int argc, char *argv[])
{
  int ret;

  GNUNET_log_setup ("test-start-process",
#if VERBOSE
                    "DEBUG",
#else
                    "WARNING",
#endif
                    NULL);
  ret = check ();

  return ret;
}

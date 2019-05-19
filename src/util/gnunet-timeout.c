/*
     This file is part of GNUnet
     Copyright (C) 2010 GNUnet e.V.

     GNUnet is free software: you can redistribute it and/or modify it
     under the terms of the GNU Affero General Public License as published
     by the Free Software Foundation, either version 3 of the License, or
     (at your option) any later version.

     GNUnet is distributed in the hope that it will be useful, but
     WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
     Affero General Public License for more details.

     You should have received a copy of the GNU Affero General Public License
     along with this program.  If not, see <http://www.gnu.org/licenses/>.

     SPDX-License-Identifier: AGPL3.0-or-later
*/

/**
 * @file src/util/gnunet-timeout.c
 * @brief small tool starting a child process, waiting that it terminates or killing it after a given timeout period
 * @author Matthias Wachs
 */

#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

static pid_t child;


static void
sigchld_handler (int val)
{
  int status = 0;
  int ret = 0;

  (void) val;
  waitpid (child, &status, 0);
  if (WIFEXITED (status) != 0)
  {
    ret = WEXITSTATUS (status);
    fprintf (stderr, "Process exited with result %u\n", ret);
    _exit (ret); /* return same status code */
  }
  if (WIFSIGNALED (status) != 0)
  {
    ret = WTERMSIG (status);
    fprintf (stderr, "Process received signal %u\n", ret);
    kill (getpid (), ret); /* kill self with the same signal */
  }
  _exit (-1);
}


static void
sigint_handler (int val)
{
  kill (0, val);
  _exit (val);
}


int
main (int argc, char *argv[])
{
  int timeout = 0;
  pid_t gpid = 0;

  if (argc < 3)
  {
    fprintf (stderr,
             "arg 1: timeout in sec., arg 2: executable, arg<n> arguments\n");
    exit (-1);
  }

  timeout = atoi (argv[1]);

  if (timeout == 0)
    timeout = 600;

  /* with getpgid() it does not compile, but getpgrp is the BSD version and working */
  gpid = getpgrp ();

  signal (SIGCHLD, sigchld_handler);
  signal (SIGABRT, sigint_handler);
  signal (SIGFPE, sigint_handler);
  signal (SIGILL, sigint_handler);
  signal (SIGINT, sigint_handler);
  signal (SIGSEGV, sigint_handler);
  signal (SIGTERM, sigint_handler);

  child = fork ();
  if (child == 0)
  {
    /*  int setpgrp(pid_t pid, pid_t pgid); is not working on this machine */
    //setpgrp (0, pid_t gpid);
    if (-1 != gpid)
      setpgid (0, gpid);
    execvp (argv[2], &argv[2]);
    exit (-1);
  }
  if (child > 0)
  {
    sleep (timeout);
    printf ("Child processes were killed after timeout of %u seconds\n",
            timeout);
    kill (0, SIGTERM);
    exit (3);
  }
  exit (-1);
}

/* end of timeout_watchdog.c */

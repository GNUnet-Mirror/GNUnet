/*
     This file is part of GNUnet.
     Copyright (C) 2010, 2011, 2012 Christian Grothoff
     Copyright (C) 2019 GNUnet e.V.

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

#include "platform.h"

//
// FIXME: These functions are copied from dns/gnunet-helper-dns.c,
// move them into a common library. Or think about implementing a even
// more elaborate version.
//

/**
 * Open '/dev/null' and make the result the given
 * file descriptor.
 *
 * @param target_fd desired FD to point to /dev/null
 * @param flags open flags (O_RDONLY, O_WRONLY)
 */
static void
open_dev_null (int target_fd,
	       int flags)
{
  int fd;

  fd = open ("/dev/null", flags);
  if (-1 == fd)
    abort ();
  if (fd == target_fd)
    return;
  if (-1 == dup2 (fd, target_fd))
  {
    (void) close (fd);
    abort ();
  }
  (void) close (fd);
}

/**
 * Run the given command and wait for it to complete.
 *
 * @param file name of the binary to run
 * @param cmd command line arguments (as given to 'execv')
 * @return 0 on success, 1 on any error
 */
static int
fork_and_exec (const char *file,
	       char *const cmd[])
{
  int status;
  pid_t pid;
  pid_t ret;

  pid = fork ();
  if (-1 == pid)
  {
    fprintf (stderr,
	     "fork failed: %s\n",
	     strerror (errno));
    return 1;
  }
  if (0 == pid)
  {
    /* we are the child process */
    /* close stdin/stdout to not cause interference
       with the helper's main protocol! */
    (void) close (0);
    open_dev_null (0, O_RDONLY);
    (void) close (1);
    open_dev_null (1, O_WRONLY);
    (void) execv (file, cmd);
    /* can only get here on error */
    fprintf (stderr,
	     "exec `%s' failed: %s\n",
	     file,
	     strerror (errno));
    _exit (1);
  }
  /* keep running waitpid as long as the only error we get is 'EINTR' */
  while ( (-1 == (ret = waitpid (pid, &status, 0))) &&
	  (errno == EINTR) );
  if (-1 == ret)
  {
    fprintf (stderr,
	     "waitpid failed: %s\n",
	     strerror (errno));
    return 1;
  }
  if (! (WIFEXITED (status) && (0 == WEXITSTATUS (status))))
    return 1;
  /* child process completed and returned success, we're happy */
  return 0;
}


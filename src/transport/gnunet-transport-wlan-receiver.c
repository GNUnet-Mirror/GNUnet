/*
 This file is part of GNUnet
 Copyright (C) 2012 Christian Grothoff (and other contributing authors)

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
 * @file transport/gnunet-transport-wlan-receiver.c
 * @brief program to send via WLAN as much as possible (to test physical/theoretical throughput)
 * @author David Brodski
 */
#include "platform.h"
#include "gnunet_protocols.h"
#include "plugin_transport_wlan.h"

int
main (int argc, char *argv[])
{
  char msg_buf[65536];
  unsigned long long count;
  double bytes_per_s;
  time_t start;
  time_t akt;
  ssize_t ret;
  pid_t pid;
  int commpipe[2];              /* This holds the fd for the input & output of the pipe */

  if (2 != argc)
  {
    fprintf (stderr,
             "This program must be started with the interface name as argument.\n");
    fprintf (stderr,
             "Usage: %s interface-name\n"
             "e.g. %s mon0\n",
	     argv[0], argv[0]);
    return 1;
  }

  /* Setup communication pipeline first */
  if (pipe (commpipe))
  {
    fprintf (stderr,
	     "Failed to create pipe: %s\n",
	     STRERROR (errno));
    exit (1);
  }

  /* Attempt to fork and check for errors */
  if ((pid = fork ()) == -1)
  {
    fprintf (stderr, "Failed to fork: %s\n",
	     STRERROR (errno));
    exit (1);
  }

  if (pid)
  {
    /* A positive (non-negative) PID indicates the parent process */
    if (0 != close (commpipe[1]))        /* Close unused side of pipe (in side) */
      fprintf (stderr,
	       "Failed to close fd: %s\n",
	       strerror (errno));
    start = time (NULL);
    count = 0;
    while (1)
    {
      ret = read (commpipe[0], msg_buf, sizeof (msg_buf));
      if (0 > ret)
      {
	fprintf (stderr, "read failed: %s\n", strerror (errno));
	break;
      }
      count += ret;
      akt = time (NULL);
      if (akt - start > 30)
      {
	bytes_per_s = count / (akt - start);
	bytes_per_s /= 1024;
	printf ("recv %f kb/s\n", bytes_per_s);
	start = akt;
	count = 0;
      }
    }
  }
  else
  {
    /* A zero PID indicates that this is the child process */
    (void) close (1);
    if (-1 == dup2 (commpipe[1], 1))    /* Replace stdin with the in side of the pipe */
      fprintf (stderr, "dup2 failed: %s\n", strerror (errno));
    (void) close (commpipe[0]); /* Close unused side of pipe (in side) */
    /* Replace the child fork with a new process */
    if (execlp
        ("gnunet-helper-transport-wlan", "gnunet-helper-transport-wlan",
         argv[1], NULL) == -1)
    {
      fprintf (stderr, "Could not start gnunet-helper-transport-wlan!");
      _exit (1);
    }
  }
  return 0;
}

/*
   This file is part of GNUnet.
   (C) 2010 Christian Grothoff

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
 * @file vpn/gnunet-helper-hijack-dns.c
 * @brief
 * @author Philipp Tölke
 */
#include <platform.h>

#include "gnunet_common.h"

int
fork_and_exec (char *file, char *cmd[])
{
  pid_t pid = fork ();

  if (pid < 0)
  {
    fprintf (stderr, "could not fork: %s\n", strerror (errno));
    return GNUNET_SYSERR;
  }

  int st = 0;

  if (pid == 0)
  {
    execv (file, cmd);
  }
  else
  {
    waitpid (pid, &st, 0);
  }
  return WIFEXITED (st) && (WEXITSTATUS (st) == 0);
}

int
main (int argc, char **argv)
{
  int delete = 0;
  int port = 0;
  char *virt_dns;

  if (argc < 3)
    return GNUNET_SYSERR;

  if (strncmp (argv[1], "-d", 2) == 0)
  {
    if (argc < 3)
      return GNUNET_SYSERR;
    delete = 1;
    port = atoi (argv[2]);
    virt_dns = argv[3];
  }
  else
  {
    port = atoi (argv[1]);
    virt_dns = argv[2];
  }

  if (port == 0)
    return GNUNET_SYSERR;

  struct stat s;

  if (stat ("/sbin/iptables", &s) < 0)
  {
    fprintf (stderr, "stat on /sbin/iptables failed: %s\n", strerror (errno));
    return GNUNET_SYSERR;
  }
  if (stat ("/sbin/ip", &s) < 0)
  {
    fprintf (stderr, "stat on /sbin/ip failed: %s\n", strerror (errno));
    return GNUNET_SYSERR;
  }

  char localport[7];

  snprintf (localport, 7, "%d", port);

  int r;

  if (delete)
  {
e4:
    r = fork_and_exec ("/sbin/ip", (char *[])
                       {
                       "ip", "route", "del", "default", "via", virt_dns,
                       "table", "2", NULL});
e3:
    r = fork_and_exec ("/sbin/ip", (char *[])
                       {
                       "ip", "rule", "del", "fwmark", "3", "table", "2", NULL});
e2:
    r = fork_and_exec ("/sbin/iptables", (char *[])
                       {
                       "iptables", "-t", "mangle", "-D", "OUTPUT", "-p", "udp",
                       "--dport", "53", "-j", "MARK", "--set-mark", "3", NULL});
e1:
    r = fork_and_exec ("/sbin/iptables", (char *[])
                       {
                       "iptables", "-t", "mangle", "-D", "OUTPUT", "-p", "udp",
                       "--sport", localport, "--dport", "53", "-j", "ACCEPT",
                       NULL});
    if (!delete)
      r = 0;
  }
  else
  {
    r = fork_and_exec ("/sbin/iptables", (char *[])
                       {
                       "iptables", "-t", "mangle", "-I", "OUTPUT", "1", "-p",
                       "udp", "--sport", localport, "--dport", "53", "-j",
                       "ACCEPT", NULL});
    if (!r)
      goto e1;
    r = fork_and_exec ("/sbin/iptables", (char *[])
                       {
                       "iptables", "-t", "mangle", "-I", "OUTPUT", "2", "-p",
                       "udp", "--dport", "53", "-j", "MARK", "--set-mark", "3",
                       NULL});
    if (!r)
      goto e2;
    r = fork_and_exec ("/sbin/ip", (char *[])
                       {
                       "ip", "rule", "add", "fwmark", "3", "table", "2", NULL});
    if (!r)
      goto e3;
    r = fork_and_exec ("/sbin/ip", (char *[])
                       {
                       "ip", "route", "add", "default", "via", virt_dns,
                       "table", "2", NULL});
    if (!r)
      goto e4;
  }
  if (r)
    return GNUNET_YES;
  return GNUNET_SYSERR;
}

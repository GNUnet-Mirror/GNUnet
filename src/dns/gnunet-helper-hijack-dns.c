/*
   This file is part of GNUnet.
   (C) 2010, 2011, 2012 Christian Grothoff

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
 * @file dns/gnunet-helper-hijack-dns.c
 * @brief helper to install firewall rules to hijack all DNS traffic
 *        and send it to our virtual interface except for DNS traffic
 *        that originates on the specified port. 
 * @author Philipp Tölke
 * @author Christian Grothoff
 *
 * This program alters the Linux firewall rules so that DNS traffic
 * that ordinarily exits the system can be intercepted and managed by
 * a virtual interface.  In order to achieve this, DNS traffic is
 * marked with the DNS_MARK given in below and re-routed to a custom
 * table with the DNS_TABLE ID given below.  Systems and
 * administrators must take care to not cause conflicts with these
 * values (it was deemed safest to hardcode them as passing these
 * values as arguments might permit messing with arbitrary firewall
 * rules, which would be dangerous).
 *
 * Note that having this binary SUID is only partially safe: it will
 * allow redirecting (and intercepting / mangling) of all DNS traffic
 * originating from this system by any user who can create a virtual
 * interface (and this is again enabled by other GNUnet SUID
 * binaries).  Furthermore, even without the ability to create a
 * tunnel interface, this code will make it possible to DoS all DNS
 * traffic originating from the current system, simply by sending it
 * to nowhere.  
 *
 * Naturally, neither of these problems can be helped as this is the
 * fundamental purpose of the binary.  Certifying that this code is
 * "safe" thus only means that it doesn't allow anything else (such
 * as local priv. escalation, etc.). 
 *
 * The following list of people have reviewed this code and considered
 * it safe (within specifications) since the last modification (if you
 * reviewed it, please have your name added to the list):
 *
 * - Christian Grothoff 
 */
#include "platform.h"

/**
 * Name and full path of IPTABLES binary.
 */
#define SBIN_IPTABLES "/sbin/iptables"

/**
 * Name and full path of IPTABLES binary.
 */
#define SBIN_IP "/sbin/ip"

/**
 * Port for DNS traffic.
 */
#define DNS_PORT "53"

/**
 * Marker we set for our hijacked DNS traffic.  We use GNUnet's
 * port (2086) plus the DNS port (53) in HEX to make a 32-bit mark
 * (which is hopefully long enough to not collide); so
 * 0x08260035 = 136708149 (hopefully unique enough...).
 */
#define DNS_MARK "136708149"

/**
 * Table we use for our DNS rules.  0-255 is the range and
 * 0, 253, 254 and 255 are already reserved.  As this is about
 * DNS and as "53" is likely (fingers crossed!) high enough to
 * not usually conflict with a normal user's setup, we use 53
 * to give a hint that this has something to do with DNS.
 */
#define DNS_TABLE "53"


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


/**
 * Main function of "gnunet-helper-hijack-dns".  
 * Use "-d" as the first argument to remove the firewall rules.
 * The other arguments are the DNS source port to NOT affect
 * by the rules, followed by the name of the virtual interface
 * to redirect all of the remaining DNS traffic to.
 *
 * @param argc number of arguments
 * @param argv ["-d"] PORT VTUN
 * @return 0 on success, otherwise code indicating type of error:
 *         1 wrong number of arguments
 *         2 invalid port number
 *         3 iptables not executable
 *         4 ip not executable
 *         8 failed to change routing table, cleanup successfull
 *         16-31 failed to undo some changes to routing table
 *         31-47 failed to fully change routing table and then might have failed to undo everything
 */
int
main (int argc, char *const*argv)
{
  int delete;
  unsigned int port;
  char *virt_dns;
  char localport[6];
  int r;

  /* check command-line arguments */
  if (argc < 3)
  {
    fprintf (stderr, 
	     "Syntax: gnunet-helper-hijack-dns [-d] PORT INTERFACENAME\n");
    return 1;
  }
  if (0 == strcmp (argv[1], "-d"))
    delete = 1;
  else
    delete = 0;
  if (argc != 3 + delete)
  {
    fprintf (stderr, 
	     "Syntax: gnunet-helper-hijack-dns [-d] PORT INTERFACENAME\n");
    return 1;
  }  
  port = atoi (argv[1 + delete]);
  virt_dns = argv[2 + delete];
  if ( (port == 0) || (port >= 65536) )
  {
    fprintf (stderr, 
	     "Port `%u' is invalid\n",
	     port);
    return 2;
  }
  /* verify that the binaries were care about are executable */
  if (0 != access (SBIN_IPTABLES, X_OK))
  {
    fprintf (stderr, 
	     "`%s' is not executable: %s\n", 
	     SBIN_IPTABLES,
	     strerror (errno));
    return 3;
  }
  if (0 != access (SBIN_IP, X_OK))
  {
    fprintf (stderr, 
	     "`%s' is not executable: %s\n", 
	     SBIN_IP,
	     strerror (errno));
    return 4;
  }

  /* print port number to string for command-line use*/
  (void) snprintf (localport,
		   sizeof (localport), 
		   "%u", 
		   port);

  /* update routing tables -- this is why we are SUID! */
  if (! delete)
  {
    /* Forward everything from the given local port (with destination
       to port 53, and only for UDP) without hijacking */
    {
      char *const mangle_args[] = 
	{
	  "iptables", "-t", "mangle", "-I", "OUTPUT", "1", "-p",
	  "udp", "--sport", localport, "--dport", DNS_PORT, "-j",
	  "ACCEPT", NULL
	};
      if (0 != fork_and_exec (SBIN_IPTABLES, mangle_args))
	goto cleanup_mangle_1;
    }    
    /* Mark all of the other DNS traffic using our mark DNS_MARK */
    {
      char *const mark_args[] =
	{
	  "iptables", "-t", "mangle", "-I", "OUTPUT", DNS_TABLE, "-p",
	  "udp", "--dport", DNS_PORT, "-j", "MARK", "--set-mark", DNS_MARK,
	  NULL
	};
      if (0 != fork_and_exec (SBIN_IPTABLES, mark_args))
	goto cleanup_mark_2;
    }
    /* Forward all marked DNS traffic to our DNS_TABLE */
    {
      char *const forward_args[] =
	{
	  "ip", "rule", "add", "fwmark", DNS_MARK, "table", DNS_TABLE, NULL
	};
      if (0 != fork_and_exec (SBIN_IP, forward_args))
	goto cleanup_forward_3;
    }
    /* Finally, add rule in our forwarding table to pass to our virtual interface */
    {
      char *const route_args[] =
	{
	  "ip", "route", "add", "default", "via", virt_dns,
	  "table", DNS_TABLE, NULL
	};
      if (0 != fork_and_exec (SBIN_IP, route_args))
	goto cleanup_route_4;
    }
  }
  else
  {
    r = 0;
    /* delete or clean-up-on-error case */
cleanup_route_4:
    {
      char *const route_clean_args[] = 			 
	{
	  "ip", "route", "del", "default", "via", virt_dns,
	  "table", DNS_TABLE, NULL
	};
      if (0 != fork_and_exec (SBIN_IP, route_clean_args))
	r += 1;
    }
cleanup_forward_3:
    {
      char *const forward_clean_args[] =
	{
	  "ip", "rule", "del", "fwmark", DNS_MARK, "table", DNS_TABLE, NULL
	};
      if (0 != fork_and_exec (SBIN_IP, forward_clean_args))
	r += 2;	
    }
cleanup_mark_2:
    {
      char *const mark_clean_args[] =
	{
	  "iptables", "-t", "mangle", "-D", "OUTPUT", "-p", "udp",
	  "--dport", DNS_PORT, "-j", "MARK", "--set-mark", DNS_MARK, NULL
	};
      if (0 != fork_and_exec (SBIN_IPTABLES, mark_clean_args))
	r += 4;
    }	
cleanup_mangle_1:
    {
      char *const mangle_clean_args[] =
	{
	  "iptables", "-t", "mangle", "-D", "OUTPUT", "-p", "udp",
	  "--sport", localport, "--dport", DNS_PORT, "-j", "ACCEPT",
	  NULL
	};
      if (0 != fork_and_exec (SBIN_IPTABLES, mangle_clean_args))
	r += 8;
    }
    if (r != 0)
    {
      if (delete)
	return 16 + r; /* failed to delete */
      return 32 + r; /* first failed to install, then also failed to clean up! */
    }
    if (! delete)
    {
      /* got here via goto to clean up handler, failed to install, succeeded with clean up */
      return 8;
    }
  } 
  /* success ! */
  return 0;
}

/* end of gnunet-helper-hijack-dns.c */

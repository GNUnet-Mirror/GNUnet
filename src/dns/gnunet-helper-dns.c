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
 * @file dns/gnunet-helper-dns.c
 * @brief helper to install firewall rules to hijack all DNS traffic
 *        and send it to our virtual interface (except for DNS traffic
 *        that originates on the specified port).  We then
 *        allow interacting with our virtual interface via stdin/stdout. 
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
 * rules, which would be dangerous).  Traffic coming from the same
 * group ID as the effective group ID that this process is running
 * as is not intercepted.
 *
 * The code first sets up the virtual interface, then begins to
 * redirect the DNS traffic to it, and then on errors or SIGTERM shuts
 * down the virtual interface and removes the rules for the traffic
 * redirection.
 *
 *
 * Note that having this binary SUID is only partially safe: it will
 * allow redirecting (and intercepting / mangling) of all DNS traffic
 * originating from this system by any user who is able to run it.
 * Furthermore, this code will make it trivial to DoS all DNS traffic
 * originating from the current system, simply by sending it to
 * nowhere (redirect stdout to /dev/null).
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

#include <linux/if_tun.h>

/**
 * Need 'struct GNUNET_MessageHeader'.
 */
#include "gnunet_common.h"

/**
 * Need DNS message types.
 */
#include "gnunet_protocols.h"

/**
 * Maximum size of a GNUnet message (GNUNET_SERVER_MAX_MESSAGE_SIZE)
 */
#define MAX_SIZE 65536

#ifndef _LINUX_IN6_H
/**
 * This is in linux/include/net/ipv6.h, but not always exported...
 */
struct in6_ifreq
{
  struct in6_addr ifr6_addr;
  uint32_t ifr6_prefixlen;
  unsigned int ifr6_ifindex;
};
#endif

/**
 * Name and full path of IPTABLES binary.
 */
static const char *sbin_iptables;

/**
 * Name and full path of IPTABLES binary.
 */
static const char *sbin_ip;

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
 * Control pipe for shutdown via signal. [0] is the read end,
 * [1] is the write end.
 */
static int cpipe[2];


/**
 * Signal handler called to initiate "nice" shutdown.  Signals select
 * loop via non-bocking pipe 'cpipe'.
 *
 * @param signal signal number of the signal (not used)
 */
static void
signal_handler (int signal)
{
  /* ignore return value, as the signal handler could theoretically
     be called many times before the shutdown can actually happen */
  (void) write (cpipe[1], "K", 1);
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
    (void) close (1); 
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
 * Creates a tun-interface called dev;
 *
 * @param dev is asumed to point to a char[IFNAMSIZ]
 *        if *dev == '\\0', uses the name supplied by the kernel;
 * @return the fd to the tun or -1 on error
 */
static int
init_tun (char *dev)
{
  struct ifreq ifr;
  int fd;

  if (NULL == dev)
  {
    errno = EINVAL;
    return -1;
  }

  if (-1 == (fd = open ("/dev/net/tun", O_RDWR)))
  {
    fprintf (stderr, "Error opening `%s': %s\n", "/dev/net/tun",
             strerror (errno));
    return -1;
  }

  if (fd >= FD_SETSIZE)
  {
    fprintf (stderr, "File descriptor to large: %d", fd);
    (void) close (fd);
    return -1;
  }

  memset (&ifr, 0, sizeof (ifr));
  ifr.ifr_flags = IFF_TUN;

  if ('\0' != *dev)
    strncpy (ifr.ifr_name, dev, IFNAMSIZ);

  if (-1 == ioctl (fd, TUNSETIFF, (void *) &ifr))
  {
    fprintf (stderr, "Error with ioctl on `%s': %s\n", "/dev/net/tun",
             strerror (errno));
    (void) close (fd);
    return -1;
  }
  strcpy (dev, ifr.ifr_name);
  return fd;
}


/**
 * @brief Sets the IPv6-Address given in address on the interface dev
 *
 * @param dev the interface to configure
 * @param address the IPv6-Address
 * @param prefix_len the length of the network-prefix
 */
static void
set_address6 (const char *dev, const char *address, unsigned long prefix_len)
{
  struct ifreq ifr;
  struct in6_ifreq ifr6;
  struct sockaddr_in6 sa6;
  int fd;

  /*
   * parse the new address
   */
  memset (&sa6, 0, sizeof (struct sockaddr_in6));
  sa6.sin6_family = AF_INET6;
  if (1 != inet_pton (AF_INET6, address, sa6.sin6_addr.s6_addr))
  {
    fprintf (stderr, "Failed to parse address `%s': %s\n", address,
             strerror (errno));
    exit (1);
  }

  if (-1 == (fd = socket (PF_INET6, SOCK_DGRAM, 0)))
  {
    fprintf (stderr, "Error creating socket: %s\n", strerror (errno));
    exit (1);
  }

  memset (&ifr, 0, sizeof (struct ifreq));
  /*
   * Get the index of the if
   */
  strncpy (ifr.ifr_name, dev, IFNAMSIZ);
  if (-1 == ioctl (fd, SIOGIFINDEX, &ifr))
  {
    fprintf (stderr, "ioctl failed at %d: %s\n", __LINE__, strerror (errno));
    (void) close (fd);
    exit (1);
  }

  memset (&ifr6, 0, sizeof (struct in6_ifreq));
  ifr6.ifr6_addr = sa6.sin6_addr;
  ifr6.ifr6_ifindex = ifr.ifr_ifindex;
  ifr6.ifr6_prefixlen = prefix_len;

  /*
   * Set the address
   */
  if (-1 == ioctl (fd, SIOCSIFADDR, &ifr6))
  {
    fprintf (stderr, "ioctl failed at line %d: %s\n", __LINE__,
             strerror (errno));
    (void) close (fd);
    exit (1);
  }

  /*
   * Get the flags
   */
  if (-1 == ioctl (fd, SIOCGIFFLAGS, &ifr))
  {
    fprintf (stderr, "ioctl failed at line %d: %s\n", __LINE__,
             strerror (errno));
    (void) close (fd);
    exit (1);
  }

  /*
   * Add the UP and RUNNING flags
   */
  ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
  if (-1 == ioctl (fd, SIOCSIFFLAGS, &ifr))
  {
    fprintf (stderr, "ioctl failed at line %d: %s\n", __LINE__,
             strerror (errno));
    (void) close (fd);
    exit (1);
  }

  if (0 != close (fd))
  {
    fprintf (stderr, "close failed: %s\n", strerror (errno));
    exit (1);
  }
}


/**
 * @brief Sets the IPv4-Address given in address on the interface dev
 *
 * @param dev the interface to configure
 * @param address the IPv4-Address
 * @param mask the netmask
 */
static void
set_address4 (const char *dev, const char *address, const char *mask)
{
  int fd;
  struct sockaddr_in *addr;
  struct ifreq ifr;

  memset (&ifr, 0, sizeof (struct ifreq));
  addr = (struct sockaddr_in *) &(ifr.ifr_addr);
  addr->sin_family = AF_INET;

  /*
   * Parse the address
   */
  if (1 != inet_pton (AF_INET, address, &addr->sin_addr.s_addr))
  {
    fprintf (stderr, "Failed to parse address `%s': %s\n", address,
             strerror (errno));
    exit (1);
  }

  if (-1 == (fd = socket (PF_INET, SOCK_DGRAM, 0)))
  {
    fprintf (stderr, "Error creating socket: %s\n", strerror (errno));
    exit (1);
  }

  strncpy (ifr.ifr_name, dev, IFNAMSIZ);

  /*
   * Set the address
   */
  if (-1 == ioctl (fd, SIOCSIFADDR, &ifr))
  {
    fprintf (stderr, "ioctl failed at %d: %s\n", __LINE__, strerror (errno));
    (void) close (fd);
    exit (1);
  }

  /*
   * Parse the netmask
   */
  addr = (struct sockaddr_in *) &(ifr.ifr_netmask);
  if (1 != inet_pton (AF_INET, mask, &addr->sin_addr.s_addr))
  {
    fprintf (stderr, "Failed to parse address `%s': %s\n", mask,
             strerror (errno));
    (void) close (fd);
    exit (1);
  }

  /*
   * Set the netmask
   */
  if (-1 == ioctl (fd, SIOCSIFNETMASK, &ifr))
  {
    fprintf (stderr, "ioctl failed at line %d: %s\n", __LINE__,
             strerror (errno));
    (void) close (fd);
    exit (1);
  }

  /*
   * Get the flags
   */
  if (-1 == ioctl (fd, SIOCGIFFLAGS, &ifr))
  {
    fprintf (stderr, "ioctl failed at line %d: %s\n", __LINE__,
             strerror (errno));
    (void) close (fd);
    exit (1);
  }

  /*
   * Add the UP and RUNNING flags
   */
  ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
  if (-1 == ioctl (fd, SIOCSIFFLAGS, &ifr))
  {
    fprintf (stderr, "ioctl failed at line %d: %s\n", __LINE__,
             strerror (errno));
    (void) close (fd);
    exit (1);
  }

  if (0 != close (fd))
  {
    fprintf (stderr, "close failed: %s\n", strerror (errno));
    (void) close (fd);
    exit (1);
  }
}


/**
 * Start forwarding to and from the tunnel.  This function runs with
 * "reduced" priviledges (saved UID is still 0, but effective UID is
 * the real user ID).
 *
 * @param fd_tun tunnel FD
 */
static void
run (int fd_tun)
{
  /*
   * The buffer filled by reading from fd_tun
   */
  unsigned char buftun[MAX_SIZE];
  ssize_t buftun_size = 0;
  unsigned char *buftun_read = NULL;

  /*
   * The buffer filled by reading from stdin
   */
  unsigned char bufin[MAX_SIZE];
  ssize_t bufin_size = 0;
  size_t bufin_rpos = 0;
  unsigned char *bufin_read = NULL;
  fd_set fds_w;
  fd_set fds_r;
  int max;

  while (1)
  {
    FD_ZERO (&fds_w);
    FD_ZERO (&fds_r);

    /*
     * We are supposed to read and the buffer is empty
     * -> select on read from tun
     */
    if (0 == buftun_size)
      FD_SET (fd_tun, &fds_r);

    /*
     * We are supposed to read and the buffer is not empty
     * -> select on write to stdout
     */
    if (0 != buftun_size)
      FD_SET (1, &fds_w);

    /*
     * We are supposed to write and the buffer is empty
     * -> select on read from stdin
     */
    if (NULL == bufin_read)
      FD_SET (0, &fds_r);

    /*
     * We are supposed to write and the buffer is not empty
     * -> select on write to tun
     */
    if (NULL != bufin_read)
      FD_SET (fd_tun, &fds_w);

    FD_SET (cpipe[0], &fds_r);
    max = (fd_tun > cpipe[0]) ? fd_tun : cpipe[0];

    int r = select (max + 1, &fds_r, &fds_w, NULL, NULL);

    if (-1 == r)
    {
      if (EINTR == errno)
        continue;
      fprintf (stderr, "select failed: %s\n", strerror (errno));
      return;
    }

    if (r > 0)
    {
      if (FD_ISSET (cpipe[0], &fds_r))
	return; /* aborted by signal */

      if (FD_ISSET (fd_tun, &fds_r))
      {
        buftun_size =
            read (fd_tun, buftun + sizeof (struct GNUNET_MessageHeader),
                  MAX_SIZE - sizeof (struct GNUNET_MessageHeader));
        if (-1 == buftun_size)
        {
	  if ( (errno == EINTR) ||
	       (errno == EAGAIN) )
	    continue;
          fprintf (stderr, "read-error: %s\n", strerror (errno));
	  return;
        }
	if (0 == buftun_size)
        {
          fprintf (stderr, "EOF on tun\n");
	  return;
        }
	buftun_read = buftun;
	{
          struct GNUNET_MessageHeader *hdr =
              (struct GNUNET_MessageHeader *) buftun;
          buftun_size += sizeof (struct GNUNET_MessageHeader);
          hdr->type = htons (GNUNET_MESSAGE_TYPE_DNS_HELPER);
          hdr->size = htons (buftun_size);
        }
      }
      else if (FD_ISSET (1, &fds_w))
      {
        ssize_t written = write (1, buftun_read, buftun_size);

        if (-1 == written)
        {
	  if ( (errno == EINTR) ||
	       (errno == EAGAIN) )
	    continue;
          fprintf (stderr, "write-error to stdout: %s\n", strerror (errno));
          return;
        }
	if (0 == written)
        {
          fprintf (stderr, "write returned 0\n");
          return;
        }
	buftun_size -= written;
	buftun_read += written;        
      }

      if (FD_ISSET (0, &fds_r))
      {
        bufin_size = read (0, bufin + bufin_rpos, MAX_SIZE - bufin_rpos);
        if (-1 == bufin_size)
        {
	  bufin_read = NULL;
	  if ( (errno == EINTR) ||
	       (errno == EAGAIN) )
	    continue;
          fprintf (stderr, "read-error: %s\n", strerror (errno));
	  return;
        }
	if (0 == bufin_size)
        {
	  bufin_read = NULL;
          fprintf (stderr, "EOF on stdin\n");
	  return;
        }
        {
          struct GNUNET_MessageHeader *hdr;

PROCESS_BUFFER:
          bufin_rpos += bufin_size;
          if (bufin_rpos < sizeof (struct GNUNET_MessageHeader))
            continue;
          hdr = (struct GNUNET_MessageHeader *) bufin;
          if (ntohs (hdr->type) != GNUNET_MESSAGE_TYPE_DNS_HELPER)
          {
            fprintf (stderr, "protocol violation!\n");
            return;
          }
	  if (ntohs (hdr->size) > bufin_rpos)
            continue;
          bufin_read = bufin + sizeof (struct GNUNET_MessageHeader);
          bufin_size = ntohs (hdr->size) - sizeof (struct GNUNET_MessageHeader);
          bufin_rpos -= bufin_size + sizeof (struct GNUNET_MessageHeader);
        }
      }
      else if (FD_ISSET (fd_tun, &fds_w))
      {
        ssize_t written = write (fd_tun, bufin_read, bufin_size);

        if (-1 == written)
        {
	  if ( (errno == EINTR) ||
	       (errno == EAGAIN) )
	    continue;
          fprintf (stderr, "write-error to tun: %s\n", strerror (errno));
	  return;
        }
	if (0 == written)
        {
          fprintf (stderr, "write returned 0\n");
          return;
        }
        {
          bufin_size -= written;
          bufin_read += written;
          if (0 == bufin_size)
          {
            memmove (bufin, bufin_read, bufin_rpos);
            bufin_read = NULL;  /* start reading again */
            bufin_size = 0;
            goto PROCESS_BUFFER;
          }
        }
      }
    }
  }
}


/**
 * Main function of "gnunet-helper-dns", which opens a VPN tunnel interface,
 * redirects all outgoing DNS traffic (except from the specified port) to that
 * interface and then passes traffic from and to the interface via stdin/stdout.
 *
 * Once stdin/stdout close or have other errors, the tunnel is closed and the
 * DNS traffic redirection is stopped.
 *
 * @param argc number of arguments
 * @param argv 0: binary name (should be "gnunet-helper-vpn")
 *             1: tunnel interface name (typically "gnunet-dns")
 *             2: IPv6 address for the tunnel ("FE80::1")
 *             3: IPv6 netmask length in bits ("64")
 *             4: IPv4 address for the tunnel ("1.2.3.4")
 *             5: IPv4 netmask ("255.255.0.0")
 * @return 0 on success, otherwise code indicating type of error:
 *         1 wrong number of arguments
 *         2 invalid arguments (i.e. port number / prefix length wrong)
 *         3 iptables not executable
 *         4 ip not executable
 *         5 failed to initialize tunnel interface
 *         6 failed to initialize control pipe
 *         8 failed to change routing table, cleanup successful
 *         9-23 failed to change routing table and failed to undo some changes to routing table
 *         24 failed to drop privs
 *         25-39 failed to drop privs and then failed to undo some changes to routing table
 *         40 failed to regain privs
 *         41-55 failed to regain prisv and then failed to undo some changes to routing table
 *         255 failed to handle kill signal properly
 */
int
main (int argc, char *const*argv)
{
  int r;
  char dev[IFNAMSIZ];
  char mygid[32];
  int fd_tun;

  if (6 != argc)
  {
    fprintf (stderr, "Fatal: must supply 6 arguments!\n");
    return 1;
  }

  /* verify that the binaries were care about are executable */
  if (0 == access ("/sbin/iptables", X_OK))
    sbin_iptables = "/sbin/iptables";
  else if (0 == access ("/usr/sbin/iptables", X_OK))
    sbin_iptables = "/usr/sbin/iptables";
  else
  {
    fprintf (stderr, 
	     "Fatal: executable iptables not found in approved directories: %s\n",
	     strerror (errno));
    return 3;
  }
  if (0 == access ("/sbin/ip", X_OK))
    sbin_ip = "/sbin/ip";
  else if (0 == access ("/usr/sbin/ip", X_OK))
    sbin_ip = "/usr/sbin/ip";
  else
  {
    fprintf (stderr,
	     "Fatal: executable ip not found in approved directories: %s\n",
	     strerror (errno));
    return 4;
  }

  /* setup 'mygid' string */
  snprintf (mygid, sizeof (mygid), "%d", (int) getegid());

  /* do not die on SIGPIPE */
  if (SIG_ERR == signal (SIGPIPE, SIG_IGN))
  {
    fprintf (stderr, "Failed to protect against SIGPIPE: %s\n",
             strerror (errno));
    return 7;
  }

  /* setup pipe to shutdown nicely on SIGINT */
  if (0 != pipe (cpipe))
  {
    fprintf (stderr, 
	     "Fatal: could not setup control pipe: %s\n",
	     strerror (errno));
    return 6;
  }
  if (cpipe[0] >= FD_SETSIZE)
  {
    fprintf (stderr, "Pipe file descriptor to large: %d", cpipe[0]);
    (void) close (cpipe[0]);
    (void) close (cpipe[1]);
    return 6;
  }
  {
    /* make pipe non-blocking, as we theoretically could otherwise block
       in the signal handler */
    int flags = fcntl (cpipe[1], F_GETFL);
    if (-1 == flags)
    {
      fprintf (stderr, "Failed to read flags for pipe: %s", strerror (errno));
      (void) close (cpipe[0]);
      (void) close (cpipe[1]);
      return 6;
    }
    flags |= O_NONBLOCK;
    if (0 != fcntl (cpipe[1], F_SETFL, flags))
    {
      fprintf (stderr, "Failed to make pipe non-blocking: %s", strerror (errno));
      (void) close (cpipe[0]);
      (void) close (cpipe[1]);
      return 6;
    }
  }
  if ( (SIG_ERR == signal (SIGTERM, &signal_handler)) ||
       (SIG_ERR == signal (SIGINT, &signal_handler)) ||
       (SIG_ERR == signal (SIGHUP, &signal_handler)) )       
  { 
    fprintf (stderr, 
	     "Fatal: could not initialize signal handler: %s\n",
	     strerror (errno));
    (void) close (cpipe[0]);
    (void) close (cpipe[1]);
    return 7;   
  }


  /* get interface name */
  strncpy (dev, argv[1], IFNAMSIZ);
  dev[IFNAMSIZ - 1] = '\0';

  /* now open virtual interface (first part that requires root) */
  if (-1 == (fd_tun = init_tun (dev)))
  {
    fprintf (stderr, "Fatal: could not initialize tun-interface\n");
    (void) signal (SIGTERM, SIG_IGN);
    (void) signal (SIGINT, SIG_IGN);
    (void) signal (SIGHUP, SIG_IGN);
    (void) close (cpipe[0]);
    (void) close (cpipe[1]);
    return 5;
  }

  /* now set interface addresses */
  {
    const char *address = argv[2];
    long prefix_len = atol (argv[3]);

    if ((prefix_len < 1) || (prefix_len > 127))
    {
      fprintf (stderr, "Fatal: prefix_len out of range\n");
      (void) signal (SIGTERM, SIG_IGN);
      (void) signal (SIGINT, SIG_IGN);
      (void) signal (SIGHUP, SIG_IGN);
      (void) close (cpipe[0]);
      (void) close (cpipe[1]);
      return 2;
    }
    set_address6 (dev, address, prefix_len);
  }

  {
    const char *address = argv[4];
    const char *mask = argv[5];

    set_address4 (dev, address, mask);
  }
  
  /* update routing tables -- next part why we need SUID! */
  /* Forward everything from our EGID (which should only be held
     by the 'gnunet-service-dns') and with destination
     to port 53 on UDP, without hijacking */
  r = 8; /* failed to fully setup routing table */
  {
    char *const mangle_args[] = 
      {
	"iptables", "-m", "owner", "-t", "mangle", "-I", "OUTPUT", "1", "-p",
	"udp", "--gid-owner", mygid, "--dport", DNS_PORT, "-j",
	"ACCEPT", NULL
      };
    if (0 != fork_and_exec (sbin_iptables, mangle_args))
      goto cleanup_rest;
  }    
  /* Mark all of the other DNS traffic using our mark DNS_MARK */
  {
    char *const mark_args[] =
      {
	"iptables", "-t", "mangle", "-I", "OUTPUT", "2", "-p",
	"udp", "--dport", DNS_PORT, "-j", "MARK", "--set-mark", DNS_MARK,
	NULL
      };
    if (0 != fork_and_exec (sbin_iptables, mark_args))
      goto cleanup_mangle_1;
  }
  /* Forward all marked DNS traffic to our DNS_TABLE */
  {
    char *const forward_args[] =
      {
	"ip", "rule", "add", "fwmark", DNS_MARK, "table", DNS_TABLE, NULL
      };
    if (0 != fork_and_exec (sbin_ip, forward_args))
      goto cleanup_mark_2;
  }
  /* Finally, add rule in our forwarding table to pass to our virtual interface */
  {
    char *const route_args[] =
      {
	"ip", "route", "add", "default", "dev", dev,
	"table", DNS_TABLE, NULL
      };
    if (0 != fork_and_exec (sbin_ip, route_args))
      goto cleanup_forward_3;
  }

  /* drop privs *except* for the saved UID; this is not perfect, but better
     than doing nothing */
  uid_t uid = getuid ();
#ifdef HAVE_SETRESUID
  if (0 != setresuid (uid, uid, 0))
  {
    fprintf (stderr, "Failed to setresuid: %s\n", strerror (errno));
    r = 24;
    goto cleanup_route_4;
  }
#else
  /* Note: no 'setuid' here as we must keep our saved UID as root */
  if (0 != seteuid (uid)) 
  {
    fprintf (stderr, "Failed to seteuid: %s\n", strerror (errno));
    r = 24;
    goto cleanup_route_4;
  }
#endif

  r = 0; /* did fully setup routing table (if nothing else happens, we were successful!) */

  /* now forward until we hit a problem */
   run (fd_tun);
  
  /* now need to regain privs so we can remove the firewall rules we added! */
#ifdef HAVE_SETRESUID
  if (0 != setresuid (uid, 0, 0))
  {
    fprintf (stderr, "Failed to setresuid back to root: %s\n", strerror (errno));
    r = 40;
    goto cleanup_route_4;
  }
#else
  if (0 != seteuid (0)) 
  {
    fprintf (stderr, "Failed to seteuid back to root: %s\n", strerror (errno));
    r = 40;
    goto cleanup_route_4;
  }
#endif
 
  /* update routing tables again -- this is why we could not fully drop privs */
  /* now undo updating of routing tables; normal exit or clean-up-on-error case */
 cleanup_route_4:
  {
    char *const route_clean_args[] = 			 
      {
	"ip", "route", "del", "default", "dev", dev,
	"table", DNS_TABLE, NULL
      };
    if (0 != fork_and_exec (sbin_ip, route_clean_args))
      r += 1;
  }
 cleanup_forward_3:
  {
    char *const forward_clean_args[] =
      {
	"ip", "rule", "del", "fwmark", DNS_MARK, "table", DNS_TABLE, NULL
      };
    if (0 != fork_and_exec (sbin_ip, forward_clean_args))
      r += 2;	
  }
 cleanup_mark_2:
  {
    char *const mark_clean_args[] =
      {
	"iptables", "-t", "mangle", "-D", "OUTPUT", "-p", "udp",
	"--dport", DNS_PORT, "-j", "MARK", "--set-mark", DNS_MARK, NULL
      };
    if (0 != fork_and_exec (sbin_iptables, mark_clean_args))
      r += 4;
  }	
 cleanup_mangle_1:
  {
    char *const mangle_clean_args[] =
      {
	"iptables", "-m", "owner", "-t", "mangle", "-D", "OUTPUT", "-p", "udp",
	 "--gid-owner", mygid, "--dport", DNS_PORT, "-j", "ACCEPT",
	NULL
      };
    if (0 != fork_and_exec (sbin_iptables, mangle_clean_args))
      r += 8;
  }

 cleanup_rest:
  /* close virtual interface */
  (void) close (fd_tun);
  /* remove signal handler so we can close the pipes */
  (void) signal (SIGTERM, SIG_IGN);
  (void) signal (SIGINT, SIG_IGN);
  (void) signal (SIGHUP, SIG_IGN);
  (void) close (cpipe[0]);
  (void) close (cpipe[1]);
  return r;
}

/* end of gnunet-helper-dns.c */

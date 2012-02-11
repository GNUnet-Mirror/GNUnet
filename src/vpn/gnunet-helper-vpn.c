/*
     This file is part of GNUnet.
     (C) 2010, 2012 Christian Grothoff

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
 * @file vpn/gnunet-helper-vpn.c
 * @brief the helper for the VPN service. Opens a virtual network-interface,
 * sends data received on the if to stdout, sends data received on stdin to the
 * interface
 * @author Philipp Tölke
 * @author Christian Grothoff
 *
 * The following list of people have reviewed this code and considered
 * it safe since the last modification (if you reviewed it, please
 * have your name added to the list):
 *
 * - Philipp Tölke
 */
#include "platform.h"
#include <linux/if_tun.h>

/**
 * Need 'struct GNUNET_MessageHeader'.
 */
#include "gnunet_common.h"

/**
 * Need VPN message types.
 */
#include "gnunet_protocols.h"

/**
 * Should we print (interesting|debug) messages that can happen during
 * normal operation?
 */
#define DEBUG GNUNET_NO

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
 * Start forwarding to and from the tunnel.
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

  /* read refers to reading from fd_tun, writing to stdout */
  int read_open = 1;

  /* write refers to reading from stdin, writing to fd_tun */
  int write_open = 1;

  while ((1 == read_open) || (1 == write_open))
  {
    FD_ZERO (&fds_w);
    FD_ZERO (&fds_r);

    /*
     * We are supposed to read and the buffer is empty
     * -> select on read from tun
     */
    if (read_open && (0 == buftun_size))
      FD_SET (fd_tun, &fds_r);

    /*
     * We are supposed to read and the buffer is not empty
     * -> select on write to stdout
     */
    if (read_open && (0 != buftun_size))
      FD_SET (1, &fds_w);

    /*
     * We are supposed to write and the buffer is empty
     * -> select on read from stdin
     */
    if (write_open && (NULL == bufin_read))
      FD_SET (0, &fds_r);

    /*
     * We are supposed to write and the buffer is not empty
     * -> select on write to tun
     */
    if (write_open && (NULL != bufin_read))
      FD_SET (fd_tun, &fds_w);

    int r = select (fd_tun + 1, &fds_r, &fds_w, NULL, NULL);

    if (-1 == r)
    {
      if (EINTR == errno)
        continue;
      fprintf (stderr, "select failed: %s\n", strerror (errno));
      exit (1);
    }

    if (r > 0)
    {
      if (FD_ISSET (fd_tun, &fds_r))
      {
        buftun_size =
            read (fd_tun, buftun + sizeof (struct GNUNET_MessageHeader),
                  MAX_SIZE - sizeof (struct GNUNET_MessageHeader));
        if (-1 == buftun_size)
        {
          fprintf (stderr, "read-error: %s\n", strerror (errno));
          shutdown (fd_tun, SHUT_RD);
          shutdown (1, SHUT_WR);
          read_open = 0;
          buftun_size = 0;
        }
        else if (0 == buftun_size)
        {
          fprintf (stderr, "EOF on tun\n");
          shutdown (fd_tun, SHUT_RD);
          shutdown (1, SHUT_WR);
          read_open = 0;
          buftun_size = 0;
        }
        else
        {
          buftun_read = buftun;
          struct GNUNET_MessageHeader *hdr =
              (struct GNUNET_MessageHeader *) buftun;
          buftun_size += sizeof (struct GNUNET_MessageHeader);
          hdr->type = htons (GNUNET_MESSAGE_TYPE_VPN_HELPER);
          hdr->size = htons (buftun_size);
        }
      }
      else if (FD_ISSET (1, &fds_w))
      {
        ssize_t written = write (1, buftun_read, buftun_size);

        if (-1 == written)
        {
#if !DEBUG
	  if (errno != EPIPE)
#endif
	    fprintf (stderr, "write-error to stdout: %s\n", strerror (errno));
          shutdown (fd_tun, SHUT_RD);
          shutdown (1, SHUT_WR);
          read_open = 0;
          buftun_size = 0;
        }
        else if (0 == written)
        {
          fprintf (stderr, "write returned 0!?\n");
          exit (1);
        }
        else
        {
          buftun_size -= written;
          buftun_read += written;
        }
      }

      if (FD_ISSET (0, &fds_r))
      {
        bufin_size = read (0, bufin + bufin_rpos, MAX_SIZE - bufin_rpos);
        if (-1 == bufin_size)
        {
          fprintf (stderr, "read-error: %s\n", strerror (errno));
          shutdown (0, SHUT_RD);
          shutdown (fd_tun, SHUT_WR);
          write_open = 0;
          bufin_size = 0;
        }
        else if (0 == bufin_size)
        {
#if DEBUG
          fprintf (stderr, "EOF on stdin\n");
#endif
          shutdown (0, SHUT_RD);
          shutdown (fd_tun, SHUT_WR);
          write_open = 0;
          bufin_size = 0;
        }
        else
        {
          struct GNUNET_MessageHeader *hdr;

PROCESS_BUFFER:
          bufin_rpos += bufin_size;
          if (bufin_rpos < sizeof (struct GNUNET_MessageHeader))
            continue;
          hdr = (struct GNUNET_MessageHeader *) bufin;
          if (ntohs (hdr->type) != GNUNET_MESSAGE_TYPE_VPN_HELPER)
          {
            fprintf (stderr, "protocol violation!\n");
            exit (1);
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
          fprintf (stderr, "write-error to tun: %s\n", strerror (errno));
          shutdown (0, SHUT_RD);
          shutdown (fd_tun, SHUT_WR);
          write_open = 0;
          bufin_size = 0;
        }
        else if (0 == written)
        {
          fprintf (stderr, "write returned 0!?\n");
          exit (1);
        }
        else
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
 * Open VPN tunnel interface.
 *
 * @param argc must be 6
 * @param argv 0: binary name (gnunet-helper-vpn)
 *             1: tunnel interface name (gnunet-vpn)
 *             2: IPv6 address (::1), "-" to disable
 *             3: IPv6 netmask length in bits (64), ignored if #2 is "-"
 *             4: IPv4 address (1.2.3.4), "-" to disable
 *             5: IPv4 netmask (255.255.0.0), ignored if #4 is "-"
 */
int
main (int argc, char **argv)
{
  char dev[IFNAMSIZ];
  int fd_tun;
  int global_ret;

  if (6 != argc)
  {
    fprintf (stderr, "Fatal: must supply 5 arguments!\n");
    return 1;
  }

  strncpy (dev, argv[1], IFNAMSIZ);
  dev[IFNAMSIZ - 1] = '\0';

  if (-1 == (fd_tun = init_tun (dev)))
  {
    fprintf (stderr, "Fatal: could not initialize tun-interface `%s'  with IPv6 %s/%s and IPv4 %s/%s\n",
	     dev,
	     argv[2],
	     argv[3],
	     argv[4],
	     argv[5]);
    return 1;
  }

  if (0 != strcmp (argv[2], "-"))
  {
    const char *address = argv[2];
    long prefix_len = atol (argv[3]);

    if ((prefix_len < 1) || (prefix_len > 127))
    {
      fprintf (stderr, "Fatal: prefix_len out of range\n");
      return 1;
    }

    set_address6 (dev, address, prefix_len);
  }

  if (0 != strcmp (argv[4], "-"))
  {
    const char *address = argv[4];
    const char *mask = argv[5];

    set_address4 (dev, address, mask);
  }
  
  uid_t uid = getuid ();
#ifdef HAVE_SETRESUID
  if (0 != setresuid (uid, uid, uid))
  {
    fprintf (stderr, "Failed to setresuid: %s\n", strerror (errno));
    global_ret = 2;
    goto cleanup;
  }
#else
  if (0 != (setuid (uid) | seteuid (uid)))
  {
    fprintf (stderr, "Failed to setuid: %s\n", strerror (errno));
    global_ret = 2;
    goto cleanup;
  }
#endif

  if (SIG_ERR == signal (SIGPIPE, SIG_IGN))
  {
    fprintf (stderr, "Failed to protect against SIGPIPE: %s\n",
             strerror (errno));
    /* no exit, we might as well die with SIGPIPE should it ever happen */
  }
  run (fd_tun);
  global_ret = 0;
 cleanup:
  close (fd_tun);
  return global_ret;
}

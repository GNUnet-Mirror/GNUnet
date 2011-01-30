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
 * @file vpn/gnunet-daemon-vpn.c
 * @brief the helper for various vpn-daemons. Opens a virtual network-interface,
 * sends data received on the if to stdout, sends data received on stdin to the
 * interface
 * @author Philipp Tölke
 */
#include <platform.h>
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
 * @param dev is asumed to point to a char[IFNAMSIZ]
 *        if *dev == '\\0', uses the name supplied by the kernel
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
      fprintf (stderr,
	       "Error opening `%s': %s\n", "/dev/net/tun", strerror (errno));
      return -1;
    }

  if (fd >= FD_SETSIZE)
    {
      fprintf (stderr, "Filedescriptor to large: %d", fd);
      return -1;
    }

  memset (&ifr, 0, sizeof (ifr));
  ifr.ifr_flags = IFF_TUN;

  if ('\0' == *dev)
    strncpy (ifr.ifr_name, dev, IFNAMSIZ);

  if (-1 == ioctl (fd, TUNSETIFF, (void *) &ifr))
    {
      fprintf (stderr,
	       "Error with ioctl on `%s': %s\n",
	       "/dev/net/tun", strerror (errno));
      close (fd);
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

  if (-1 == (fd = socket (PF_INET6, SOCK_DGRAM, 0)))
    {
      fprintf (stderr, "Error creating socket: %s\n", strerror (errno));
      exit (1);
    }
  memset (&sa6, 0, sizeof (struct sockaddr_in6));
  sa6.sin6_family = AF_INET6;

  /*
   * parse the new address
   */
  if (1 != inet_pton (AF_INET6, address, sa6.sin6_addr.s6_addr))
    {
      fprintf (stderr,
	       "Failed to parse address `%s': %s\n",
	       address, strerror (errno));
      exit (1);
    }
  memcpy (&ifr6.ifr6_addr, &sa6.sin6_addr, sizeof (struct in6_addr));


  /*
   * Get the index of the if
   */
  strncpy (ifr.ifr_name, dev, IFNAMSIZ);
  if (-1 == ioctl (fd, SIOGIFINDEX, &ifr))
    {
      fprintf (stderr,
	       "ioctl failed at %d: %s\n", __LINE__, strerror (errno));
      exit (1);
    }
  ifr6.ifr6_ifindex = ifr.ifr_ifindex;

  ifr6.ifr6_prefixlen = prefix_len;

  /*
   * Set the address
   */
  if (-1 == ioctl (fd, SIOCSIFADDR, &ifr6))
    {
      fprintf (stderr,
	       "ioctl failed at line %d: %s\n", __LINE__, strerror (errno));
      exit (1);
    }

  /*
   * Get the flags
   */
  if (-1 == ioctl (fd, SIOCGIFFLAGS, &ifr))
    {
      fprintf (stderr,
	       "ioctl failed at line %d: %s\n", __LINE__, strerror (errno));
      exit (1);
    }

  /*
   * Add the UP and RUNNING flags
   */
  ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
  if (-1 == ioctl (fd, SIOCSIFFLAGS, &ifr))
    {
      fprintf (stderr,
	       "ioctl failed at line %d: %s\n", __LINE__, strerror (errno));
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
set_address4 (char *dev, char *address, char *mask)
{
  int fd = 0;
  struct sockaddr_in *addr;
  struct ifreq ifr;

  memset (&ifr, 0, sizeof (struct ifreq));
  addr = (struct sockaddr_in *) &(ifr.ifr_addr);
  memset (addr, 0, sizeof (struct sockaddr_in));
  addr->sin_family = AF_INET;
  addr->sin_addr.s_addr = inet_addr (address);

  /*
   * Parse the address
   */
  int r = inet_pton (AF_INET, address, &addr->sin_addr.s_addr);
  if (r < 0)
    {
      fprintf (stderr, "error at inet_pton: %m\n");
      exit (1);
    }

  fd = socket (PF_INET, SOCK_DGRAM, 0);
  if (fd < 0)
    {
      perror ("socket()");
      return;
    }

  strncpy (ifr.ifr_name, dev, IFNAMSIZ);

  /*
   * Set the address
   */
  if (ioctl (fd, SIOCSIFADDR, &ifr) != 0)
    {
      perror ("SIOCSIFADDR");
      close (fd);
      return;
    }

  /*
   * Parse the netmask
   */
  addr = (struct sockaddr_in *) &(ifr.ifr_netmask);
  r = inet_pton (AF_INET, mask, &addr->sin_addr.s_addr);
  if (r < 0)
    {
      fprintf (stderr, "error at inet_pton: %m\n");
      exit (1);
    }

  /*
   * Set the netmask
   */
  if (ioctl (fd, SIOCSIFNETMASK, &ifr) != 0)
    {
      perror ("SIOCSIFNETMASK");
      close (fd);
      return;
    }

  /*
   * Get the flags
   */
  if (-1 == ioctl (fd, SIOCGIFFLAGS, &ifr))
    {
      fprintf (stderr,
	       "ioctl failed at line %d: %s\n", __LINE__, strerror (errno));
      exit (1);
    }

  /*
   * Add the UP and RUNNING flags
   */
  ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
  if (-1 == ioctl (fd, SIOCSIFFLAGS, &ifr))
    {
      fprintf (stderr,
	       "ioctl failed at line %d: %s\n", __LINE__, strerror (errno));
      exit (1);
    }

  if (0 != close (fd))
    {
      fprintf (stderr, "close failed: %s\n", strerror (errno));
      exit (1);
    }
}


static void
run (int fd_tun)
{
  /*
   * The buffer filled by reading from fd_tun
   */
  unsigned char buftun[MAX_SIZE];
  ssize_t buftun_size = 0;
  unsigned char *buftun_read = 0;

  /*
   * The buffer filled by reading from stdin
   */
  unsigned char bufin[MAX_SIZE];
  ssize_t bufin_size = 0;
  unsigned char *bufin_write = 0;

  fd_set fds_w;
  fd_set fds_r;

  int rea = 1;
  int wri = 1;

  while ((1 == rea) || (1 == wri))
    {
      FD_ZERO (&fds_w);
      FD_ZERO (&fds_r);

      /*
       * We are supposed to read and the buffer is empty
       * -> select on read from tun
       */
      if (rea && (0 == buftun_size))
	{
	  FD_SET (fd_tun, &fds_r);
	}

      /*
       * We are supposed to read and the buffer is not empty
       * -> select on write to stdout
       */
      if (rea && (0 != buftun_size))
	{
	  FD_SET (1, &fds_w);
	}

      /*
       * We are supposed to write and the buffer is empty
       * -> select on read from stdin
       */
      if (wri && (0 == bufin_size))
	{
	  FD_SET (0, &fds_r);
	}

      /*
       * We are supposed to write and the buffer is not empty
       * -> select on write to tun
       */
      if (wri && (0 != bufin_size))
	{
	  FD_SET (fd_tun, &fds_w);
	}

      int r = select (fd_tun + 1, &fds_r, &fds_w, NULL, NULL);
      if (-1 == r)
	{
	  fprintf (stderr, "select failed: %s\n", strerror (errno));
	  exit (1);
	}

      if (r > 0)
	{
	  if (FD_ISSET (fd_tun, &fds_r))
	    {
	      buftun_size =
		read (fd_tun, buftun + sizeof (struct GNUNET_MessageHeader),
		      MAX_SIZE - sizeof (struct GNUNET_MessageHeader)) +
		sizeof (struct GNUNET_MessageHeader);
	      if (-1 == buftun_size)
		{
		  fprintf (stderr, "read-error: %s\n", strerror (errno));
		  shutdown (fd_tun, SHUT_RD);
		  shutdown (1, SHUT_WR);
		  rea = 0;
		  buftun_size = 0;
		}
	      else if (0 == buftun_size)
		{
		  fprintf (stderr, "eof on tun\n");
		  shutdown (fd_tun, SHUT_RD);
		  shutdown (1, SHUT_WR);
		  rea = 0;
		  buftun_size = 0;
		}
	      else
		{
		  buftun_read = buftun;
		  struct GNUNET_MessageHeader *hdr =
		    (struct GNUNET_MessageHeader *) buftun;
		  hdr->type = htons (GNUNET_MESSAGE_TYPE_VPN_HELPER);
		  hdr->size = htons (buftun_size);
		}
	    }
	  else if (FD_ISSET (1, &fds_w))
	    {
	      ssize_t written = write (1, buftun_read, buftun_size);
	      if (-1 == written)
		{
		  fprintf (stderr, "write-error to stdout: %s\n",
			   strerror (errno));
		  shutdown (fd_tun, SHUT_RD);
		  shutdown (1, SHUT_WR);
		  rea = 0;
		  buftun_size = 0;
		}
	      buftun_size -= written;
	      buftun_read += written;
	    }

	  if (FD_ISSET (0, &fds_r))
	    {
	      bufin_size = read (0, bufin, MAX_SIZE);
	      if (-1 == bufin_size)
		{
		  fprintf (stderr, "read-error: %s\n", strerror (errno));
		  shutdown (0, SHUT_RD);
		  shutdown (fd_tun, SHUT_WR);
		  wri = 0;
		  bufin_size = 0;
		}
	      else if (0 == bufin_size)
		{
		  fprintf (stderr, "eof on stdin\n");
		  shutdown (0, SHUT_RD);
		  shutdown (fd_tun, SHUT_WR);
		  wri = 0;
		  bufin_size = 0;
		}
	      else
		{
		  struct GNUNET_MessageHeader *hdr =
		    (struct GNUNET_MessageHeader *) bufin;
		  if ((bufin_size < sizeof (struct GNUNET_MessageHeader))
		      || (ntohs (hdr->type) != GNUNET_MESSAGE_TYPE_VPN_HELPER)
		      || (ntohs (hdr->size) != bufin_size))
		    {
		      fprintf (stderr, "protocol violation!\n");
		      exit (1);
		    }
		  bufin_write = bufin + sizeof (struct GNUNET_MessageHeader);
		  bufin_size -= sizeof (struct GNUNET_MessageHeader);
		}
	    }
	  else if (FD_ISSET (fd_tun, &fds_w))
	    {
	      ssize_t written = write (fd_tun, bufin_write, bufin_size);
	      if (-1 == written)
		{
		  fprintf (stderr, "write-error to tun: %s\n",
			   strerror (errno));
		  shutdown (0, SHUT_RD);
		  shutdown (fd_tun, SHUT_WR);
		  wri = 0;
		  bufin_size = 0;
		}
	      bufin_size -= written;
	      bufin_write += written;
	    }
	}
    }
}


int
main (int argc, char **argv)
{
  char dev[IFNAMSIZ];
  int fd_tun;

  memset (dev, 0, IFNAMSIZ);
  if (-1 == (fd_tun = init_tun (dev)))
    {
      fprintf (stderr, "Fatal: could not initialize tun-interface\n");
      return 1;
    }

  if (5 != argc)
    {
      fprintf(stderr, "Fatal: must supply 4 arguments!\n");
      return 1;
    }

  {
    char *address = argv[1];
    long prefix_len = atol(argv[2]);

    if (prefix_len < 1 || prefix_len > 127)
      {
	fprintf(stderr, "Fatal: prefix_len out of range\n");
	return 1;
      }

    set_address6 (dev, address, prefix_len);
  }

  {
    char *address = argv[3];
    char *mask = argv[4];

    set_address4 (dev, address, mask);
  }

  uid_t uid = getuid ();
  if (0 != setresuid (uid, uid, uid))
    fprintf (stderr, "Failed to setresuid: %s\n", strerror (errno));
  run (fd_tun);
  close (fd_tun);
  return 0;
}

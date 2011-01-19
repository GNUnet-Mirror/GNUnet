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


struct suid_packet 
{
  struct GNUNET_MessageHeader hdr;
  unsigned char data[1];
}


/**
 * Creates a tun-interface called dev;
 * @param dev is asumed to point to a char[IFNAMSIZ]
 *        if *dev == '\0', uses the name supplied by the kernel
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

  if (-1 == (fd = open("/dev/net/tun", O_RDWR))) 
    {
      fprintf (stderr, 
	       "Error opening `%s': %s\n", 
	       "/dev/net/tun",
	       strerror(errno));
      return -1;
    }

  memset(&ifr, 0, sizeof(ifr));
  ifr.ifr_flags = IFF_TUN;

  if ('\0' == *dev)
    strncpy(ifr.ifr_name, dev, IFNAMSIZ);

  if (-1 == ioctl(fd, TUNSETIFF, (void *) &ifr))
    {
      fprintf (stderr, 
	       "Error with ioctl on `%s': %s\n", 
	       "/dev/net/tun",
	       strerror(errno));
      close (fd);
      return -1;
    }
  strcpy(dev, ifr.ifr_name);
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
set_address6 (const char *dev, 
	      const char *address, 
	      unsigned long prefix_len)
{			    
  struct ifreq ifr;
  struct in6_ifreq ifr6;
  struct sockaddr_in6 sa6;
  int fd;

  if (-1 == (fd = socket (PF_INET6, SOCK_DGRAM, 0)))
    {
      fprintf (stderr, 
	       "Error creating socket: %s\n",
	       strerror (errno));
      exit (1);
    }
  memset (&sa6, 0, sizeof (struct sockaddr_in6));
  sa6.sin6_family = AF_INET6;

  if (1 != inet_pton (AF_INET6, address, sa6.sin6_addr.s6_addr))
    {
      fprintf (stderr, 
	       "Failed to parse address `%s': %s\n",
	       address,
	       strerror (errno));
      exit (1);
    }

  memcpy (&ifr6.ifr6_addr, 
	  &sa6.sin6_addr,
	  sizeof (struct in6_addr));
  strncpy (ifr.ifr_name, dev, IFNAMSIZ);
  if (-1 == ioctl (fd, SIOGIFINDEX, &ifr))
    {
      fprintf (stderr, 
	       "ioctl failed at %d: %s\n",
	       __LINE__,
	       strerror (errno));
      exit (1);
    }

  ifr6.ifr6_ifindex = ifr.ifr_ifindex;
  ifr6.ifr6_prefixlen = prefix_len;
  if (-1 == ioctl (fd, SIOCSIFADDR, &ifr6))
    {
      fprintf (stderr, 
	       "ioctl failed at line %d: %s\n",
	       __LINE__,
	       strerror (errno));
      exit (1);
    }

  if (-1 == ioctl (fd, SIOCGIFFLAGS, &ifr))
    {
      fprintf (stderr, 
	       "ioctl failed at line %d: %s\n",
	       __LINE__,
	       strerror (errno));
      exit (1);
    }
  ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
  if (-1 == ioctl (fd, SIOCSIFFLAGS, &ifr))
    {
      fprintf (stderr, 
	       "ioctl failed at line %d: %s\n",
	       __LINE__,
	       strerror (errno));
      exit (1);
    }

  if (0 != close (fd))
    {
      fprintf (stderr, 
	       "close failed: %s\n",
	       strerror (errno));
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

  if (ioctl (fd, SIOCSIFADDR, &ifr) != 0)
    {
      perror ("SIOCSIFADDR");
      close (fd);
      return;
    }

  addr = (struct sockaddr_in *) &(ifr.ifr_netmask);
  r = inet_pton (AF_INET, mask, &addr->sin_addr.s_addr);
  if (r < 0)
    {
      fprintf (stderr, "error at inet_pton: %m\n");
      exit (1);
    }

  if (ioctl (fd, SIOCSIFNETMASK, &ifr) != 0)
    {
      perror ("SIOCSIFNETMASK");
      close (fd);
      return;
    }

  (void) ioctl (fd, SIOCGIFFLAGS, &ifr);
  ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
  (void) ioctl (fd, SIOCSIFFLAGS, &ifr);
  close (fd);
}


static void
run (int fd_tun)
{
  unsigned char buf[MAX_SIZE];
  fd_set fds_w;
  fd_set fds_r;
  int rea = 1;
  int wri = 1;
  int write_fd_possible = 0;
  int write_stdout_possible = 0;
  ssize_t tin;
outer:
  while ((1 == rea) || (1 == wri))
    {
      FD_ZERO (&fds_w);
      FD_ZERO (&fds_r);

      if (rea)
	{
	  FD_SET (fd_tun, &fds_r);
	  if (!write_stdout_possible)
	    FD_SET (1, &fds_w);
	}

      if (wri)
	{
	  FD_SET (0, &fds_r);
	  if (!write_fd_possible)
	    FD_SET (fd_tun, &fds_w);
	}

      int r = select (fd_tun + 1, &fds_r, &fds_w, NULL, NULL);
      if (r > 0)
	{
	  if (FD_ISSET (fd_tun, &fds_w))
	    write_fd_possible = 1;
	  if (FD_ISSET (1, &fds_w))
	    write_stdout_possible = 1;

	  if (FD_ISSET (0, &fds_r) && write_fd_possible)
	    {
	      write_fd_possible = 0;
	      struct suid_packet *pkt = (struct suid_packet *) buf;
	      tin = read (0, buf, sizeof (struct GNUNET_MessageHeader));
	      if (tin <= 0)
		{
		  fprintf (stderr, "read-error: %s\n", strerror (errno));
		  shutdown (fd_tun, SHUT_WR);
		  shutdown (0, SHUT_RD);
		  wri = 0;
		  goto outer;
		}
	      if (pkt->hdr.type != ntohs (GNUNET_MESSAGE_TYPE_VPN_HELPER))
		abort ();
	      while (tin < ntohs (pkt->hdr.size))
		{
		  ssize_t t = read (0, buf + tin, ntohs (pkt->hdr.size) - tin);
		  if (t <= 0)
		    {
		      fprintf (stderr, "read-error: %s\n", strerror (errno));
		      shutdown (fd_tun, SHUT_WR);
		      shutdown (0, SHUT_RD);
		      wri = 0;
		      goto outer;
		    }
		  tin += t;
		}
	      tin = 0;
	      while (tin <
		     ntohs (pkt->hdr.size) -
		     sizeof (struct GNUNET_MessageHeader))
		{
		  ssize_t t = write (fd_tun, pkt->data,
				 ntohs (pkt->hdr.size) -
				 sizeof (struct GNUNET_MessageHeader) - tin);
		  if (t <= 0)
		    {
		      fprintf (stderr, "write-error 3: %s\n",
			       strerror (errno));
		      shutdown (fd_tun, SHUT_WR);
		      shutdown (0, SHUT_RD);
		      wri = 0;
		      goto outer;
		    }
		  tin += t;
		}
	    }
	  else if (write_stdout_possible && FD_ISSET (fd_tun, &fds_r))
	    {
	      write_stdout_possible = 0;
	      tin = read (fd_tun, buf, MAX_SIZE);
	      if (tin <= 0)
		{
		  fprintf (stderr, "read-error: %s\n", strerror (errno));
		  shutdown (fd_tun, SHUT_RD);
		  shutdown (1, SHUT_WR);
		  rea = 0;
		  goto outer;
		}
	      struct GNUNET_MessageHeader hdr = {.size =
		  htons (r + sizeof (struct GNUNET_MessageHeader)),.type =
		  htons (GNUNET_MESSAGE_TYPE_VPN_HELPER)
	      };
	      tin = 0;
	      while (tin < sizeof (struct GNUNET_MessageHeader))
		{
		  ssize_t t =
		    write (1, &hdr, sizeof (struct GNUNET_MessageHeader) - tin);
		  if (t < 0)
		    {
		      fprintf (stderr, "write-error 2: %s\n",
			       strerror (errno));
		      shutdown (fd_tun, SHUT_RD);
		      shutdown (1, SHUT_WR);
		      rea = 0;
		      goto outer;
		    }
		  tin += t;
		}
	      while (tin < ntohs (hdr.size))
		{
		  size_t t = write (1, buf, ntohs (hdr.size) - tin);
		  if (t < 0)
		    {
		      fprintf (stderr, "write-error 1: %s, written %d/%d\n",
			       strerror (errno), r, ntohs (hdr.size));
		      shutdown (fd_tun, SHUT_RD);
		      shutdown (1, SHUT_WR);
		      rea = 0;
		      goto outer;
		    }
		  tin += t;
		}
	    }
	}
    }
}



/**
 * @brief sets the socket to nonblocking
 *
 * @param fd the socket
 */
static void
setnonblocking (int fd)
{
  int opts;

  if (-1 == (opts = fcntl (fd, F_GETFL)))
    {
      fprintf (stderr, 
	       "Error in fcntl at line %d: %s\n",
	       __LINE__,
	       strerror (errno));
      exit (1);
    }
  opts |= O_NONBLOCK;
  if (-1 == fcntl (fd, F_SETFL, opts)) 
    {
      fprintf (stderr, 
	       "Error in fcntl at line %d: %s\n",
	       __LINE__,
	       strerror (errno));
      exit (1);
    }
}


int 
main (int argc, 
      char** argv) 
{
  char dev[IFNAMSIZ];
  int fd_tun;

  memset (dev, 0, IFNAMSIZ);
  if (-1 == (fd_tun = init_tun (dev)))
    {
      fprintf (stderr, 
	       "Fatal: could not initialize tun-interface\n");
      return 1;
    }

  {
    // TODO: get this out of argv
    char address[] = "1234::1";
    unsigned long prefix_len = 16;

    set_address6 (dev, address, prefix_len);
  }

  {
    char address[] = "10.10.10.1";
    char mask[] = "255.255.255.252";

    set_address4 (dev, address, mask);
  }

  uid_t uid = getuid ();
  if (0 != setresuid (uid, uid, uid))
    fprintf (stderr, 
	     "Failed to setresuid: %s\n", 
	     strerror (errno));
  run (fd_tun);
  close (fd_tun);
  return 0;
}

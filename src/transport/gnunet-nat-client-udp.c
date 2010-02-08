/*
     This file is part of GNUnet.
     (C) 2010 Christian Grothoff (and other contributing authors)

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
 * @file src/transport/client-test.c
 * @brief Test for NAT traversal using ICMP method.
 * @author Christian Grothoff
 */
#include <sys/types.h> 
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <stdint.h>
#include <netinet/in.h> 
#include <time.h>

/**
 * How often do we send our UDP messages to keep ports open (and to
 * try to connect, of course).  Use small value since we are the
 * initiator and should hence be rather aggressive.
 */
#define UDP_SEND_FREQUENCY_MS 5

/**
 * Port we always try to use.
 */
#define NAT_TRAV_PORT 22223

/**
 * Number of UDP ports to keep open at the same time (typically >= 256).
 * Should be less than FD_SETSIZE.
 */
#define NUM_UDP_PORTS 1000

/**
 * How often do we retry to open and bind a UDP socket before giving up?
 */
#define MAX_BIND_TRIES 10

/**
 * How often do we try at most?  We expect to need (for the worst kind
 * of NAT) on average 64512 / 512 = 126 attempts to have the right
 * destination port and we then need to also (in the worst case) have
 * the right source port (so 126 * 64512 = 8128512 packets on
 * average!).  That's obviously a bit much, so we give up earlier.  The
 * given value corresponds to about 1 minute of runtime (for a send
 * frequency of one packet per ms).
 *
 * NOW: if the *server* would listen for Linux-generated ICMP 
 * "Destination unreachables" we *might* increase our chances since
 * maybe the firewall has some older/other UDP rules (this was
 * the case during testing for me), but obviously that would mean
 * more SUID'ed code. Yuck.
 */
#define MAX_TRIES 62500

#define LOW_PORT 32768

/**
 * create a random port number that is not totally
 * unlikely to be chosen by the nat box.
 */
static uint16_t 
make_port ()
{
  return LOW_PORT + ( (unsigned int)rand ()) % (64 * 1024 - LOW_PORT);
}


/**
 * create a fresh udp socket bound to a random local port,
 * or, if the argument is zero, to the NAT_TRAV_PORT.
 *
 * @param i counter
 * @return -1 on error
 */
static int
make_udp_socket (int i)
{
  int ret;
  int tries;
  struct sockaddr_in src;

  for (tries=0;tries<MAX_BIND_TRIES;tries++)
    {
      ret = socket (AF_INET, SOCK_DGRAM, IPPROTO_UDP);
      if (-1 == ret)
        {
          fprintf (stderr,
                   "Error opening udp socket: %s\n",
                   strerror (errno));
          return -1;
        }
      if (ret >= FD_SETSIZE)
        {
          fprintf (stderr,
                   "Socket number too large (%d > %u)\n",
                   ret,
                   (unsigned int) FD_SETSIZE);
          close (ret);
          return -1;
        }
      memset (&src, 0, sizeof (src));
      src.sin_family = AF_INET;
      if (i == 0)
	src.sin_port = htons (NAT_TRAV_PORT);
      else
	src.sin_port = htons (make_port ());
      if (0 != bind (ret, (struct sockaddr*) &src, sizeof (src)))
        {
          close (ret);
          continue;
        }
      return ret;
    }
  fprintf (stderr,
           "Error binding udp socket: %s\n",
           strerror (errno));
  return -1;
}




int
main (int argc, char *const *argv)
{
  int udpsocks[NUM_UDP_PORTS];
  char command[512];
  struct in_addr external;
  struct in_addr target;
  int ret;
  unsigned int pos;
  int i;
  int max;
  struct sockaddr_in dst;
  struct sockaddr_in src;
  int first_round = 1;
  char dummybuf[65536];
  unsigned int tries;
  struct timeval tv;
  socklen_t slen;
  fd_set rs;
 
  if (argc != 3)
    {
      fprintf (stderr,
	       "This program must be started with our IP and the targets external IP as arguments.\n");
      return 1;
    }
  if ( (1 != inet_pton (AF_INET, argv[1], &external)) ||
       (1 != inet_pton (AF_INET, argv[2], &target)) )
    {
      fprintf (stderr,
	       "Error parsing IPv4 address: %s\n",
	       strerror (errno));
      return 1;
    }
  snprintf (command, 
	    sizeof (command),
	    "gnunet-nat-client %s %s",
	    argv[1],
	    argv[2]);
  if (0 != (ret = system (command)))
    {
      if (ret == -1)
	fprintf (stderr,
		 "Error running `%s': %s\n",
		 command,
		 strerror (errno));
      return 1;
    }
  fprintf (stderr,
	   "Trying to connect to `%s'\n",
	   argv[2]);
  srand (time(NULL));
  for (i=0;i<NUM_UDP_PORTS;i++)
    udpsocks[i] = make_udp_socket (i); 
  memset (&dst, 0, sizeof (dst));
  dst.sin_family = AF_INET;
  dst.sin_addr = target;
  pos = 0;
  tries = 0;
  while (MAX_TRIES > tries++)
    {
      FD_ZERO (&rs);
      for (i=0;i<NUM_UDP_PORTS;i++)
	{
	  if (udpsocks[i] != -1)
	    FD_SET (udpsocks[i], &rs);
	  if (udpsocks[i] > max)
	    max = udpsocks[i];
	}
      tv.tv_sec = 0;
      tv.tv_usec = UDP_SEND_FREQUENCY_MS * 1000;
      select (max + 1, &rs, NULL, NULL, &tv);
      for (i=0;i<NUM_UDP_PORTS;i++)
	{
	  if (udpsocks[i] == -1)
	    continue;
	  if (! FD_ISSET (udpsocks[i], &rs))
	    continue;
	  slen = sizeof (src);
	  recvfrom (udpsocks[i], 
		    dummybuf, sizeof (dummybuf), 0,
		    (struct sockaddr*) &src,
		    &slen);
	  if (slen != sizeof (src))
	    {
	      fprintf (stderr,
		       "Unexpected size of address.\n");
	      continue;
	    }
	  if (0 != memcmp (&src.sin_addr,
			   &target,
			   sizeof (external)))
	    {
	      fprintf (stderr,
		       "Unexpected sender IP\n");
	      continue;
	    }
	  /* discovered port! */
	  fprintf (stdout,
		   "%s:%u\n",
		   argv[2],
		   ntohs (src.sin_port));
	  dst.sin_port = src.sin_port;
	  if (-1 == sendto (udpsocks[i],
			    NULL, 0, 0,
			    (struct sockaddr*) &dst, sizeof (dst)))
	    {
	      fprintf (stderr,
		       "sendto failed: %s\n",
		       strerror (errno));	      
	      return 2; /* oops */
	    }	  
	  /* success! */
	  fprintf (stderr,
		   "Succeeded after %u packets.\n",
		   tries);
	  return 0;
        }
      if (udpsocks[pos] == -1)
	{
          udpsocks[pos] = make_udp_socket (pos);
	  continue;
	}
      if ( (0 == ((unsigned int)rand() % NUM_UDP_PORTS)) ||
	   (1 == first_round) )
	dst.sin_port = htons (NAT_TRAV_PORT);
      else
	dst.sin_port = htons (make_port ());
      fprintf (stderr,
	       "Sending UDP packet to `%s:%u'\n",
	       argv[2],
	       ntohs (dst.sin_port));
      first_round = 0;
      if (-1 == sendto (udpsocks[pos],
                        NULL, 0, 0,
                        (struct sockaddr*) &dst, sizeof (dst)))
        {
          fprintf (stderr,
                   "sendto failed: %s\n",
                   strerror (errno));
          close (udpsocks[pos]);
          udpsocks[pos] = make_udp_socket (pos);
        }
      pos = (pos+1) % NUM_UDP_PORTS;
    }
  fprintf (stderr,
	   "Giving up after %u tries.\n",
	   tries);
  return 3;
}

/* end of client-test.c */

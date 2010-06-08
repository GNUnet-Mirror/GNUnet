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
 * @file src/transport/gnunet-nat-server-udp.c
 * @brief  This program will send ONE UDP message every 500 ms
 *         to a DUMMY IP address and also listens for ICMP replies.
 *
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


#define DUMMY_IP "1.2.3.4"

/**
 * How often do we send our UDP message to keep ports open (and to
 * try to connect, of course).
 */
#define UDP_SEND_FREQUENCY_MS 500

/**
 * Port we always try to use.
 */
#define NAT_TRAV_PORT 22225

/**
 * Number of UDP ports to send to
 */
#define NUM_UDP_PORTS 1

/**
 * How often do we retry to open and bind a UDP socket before giving up?
 */
#define MAX_BIND_TRIES 10

#define LOW_PORT 32768

static struct in_addr dummy;

static int icmpsock;

struct icmp_packet
{
  uint8_t type;
  uint8_t code;
  uint16_t checksum;
  uint32_t reserved;

};

struct udp_packet
{
  uint16_t src_port;

  uint16_t dst_port;

  uint32_t length;
};

struct ip_packet
{
  uint8_t vers_ihl;
  uint8_t tos;
  uint16_t pkt_len;
  uint16_t id;
  uint16_t flags_frag_offset;
  uint8_t ttl;
  uint8_t proto;
  uint16_t checksum;
  uint32_t src_ip;
  uint32_t dst_ip;
};

#if DUMMY
static uint16_t
calc_checksum(const uint16_t *data,
              unsigned int bytes)
{
  uint32_t sum;
  unsigned int i;

  sum = 0;
  for (i=0;i<bytes/2;i++)
    sum += data[i];
  sum = (sum & 0xffff) + (sum >> 16);
  sum = htons(0xffff - sum);
  return sum;
}
#endif

/**
 * create a fresh udp socket bound to the NAT_TRAV_PORT.
 *
 * @return -1 on error
 */
static int
make_udp_socket ()
{
  int ret;
  int tries;
  struct sockaddr_in src;

  for (tries=0; tries<MAX_BIND_TRIES; tries++)
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
      src.sin_port = htons (NAT_TRAV_PORT);

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

#define LOW_PORT 32768

/**
 * create a random port number that is not totally
 * unlikely to be chosen by the nat box.
 */
static uint16_t
make_port ()
{
  return LOW_PORT + ( (unsigned int)rand ()) % (64 * 1024 - LOW_PORT - 2);
}

static int
make_icmp_socket ()
{
  int ret;

  ret = socket (AF_INET, SOCK_RAW, IPPROTO_ICMP);
  if (-1 == ret)
    {
      fprintf (stderr,
               "Error opening RAW socket: %s\n",
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
  return ret;
}

#if DUMMY
/**
 * Send a UDP message to the dummy IP.
 *
 * @param my_ip source address (our ip address)
 */
static void
send_dummy_udp (const struct in_addr *my_ip)
{
  struct sockaddr_in dst;
  size_t off;
  int err;
  struct ip_packet ip_pkt;
  struct ip_packet udp_pkt;
  char packet[sizeof (ip_pkt) + sizeof (udp_pkt)];


  // build inner IP header
  memset(&ip_pkt, 0, sizeof(ip_pkt));
  ip_pkt.vers_ihl = 0x45;
  ip_pkt.tos = 0;
  ip_pkt.pkt_len = htons(sizeof (ip_pkt) + sizeof(udp_pkt));
  ip_pkt.id = htons(0);
  ip_pkt.flags_frag_offset = 0;
  ip_pkt.ttl = 128;
  ip_pkt.proto = IPPROTO_UDP;
  ip_pkt.checksum = 0;
  ip_pkt.src_ip = my_ip->s_addr;
  ip_pkt.dst_ip = inet_addr(dummy.s_addr);
  ip_pkt.checksum = htons(calc_checksum((uint16_t*)&ip_pkt, sizeof (ip_pkt)));
  memcpy(&packet[off], &ip_pkt, sizeof(ip_pkt));
  off += sizeof(ip_pkt);

  // build UDP header
  udp_pkt.src_port = NAT_TRAV_PORT;
  udp_pkt.dst_port = htons(NAT_TRAV_PORT);

  uint32_t newval = inet_addr("1.2.3.4");
  memcpy(&udp_pkt.length, &newval, sizeof(uint32_t));

  off += sizeof(udp_pkt);

  err = sendto(rawsock,
               ip_pkt, off, 0,
               (struct sockaddr*)&dst,
               sizeof(dst));
  if (err < 0)
    {
#if VERBOSE
      fprintf(stderr,
              "sendto failed: %s\n", strerror(errno));
#endif
    }
  else if (err != off)
    {
      fprintf(stderr,
              "Error: partial send of UDP message\n");
    }
}
#endif

static void
process_icmp_response()
{
  char buf[65536];
  ssize_t have;
  struct in_addr sip;
  struct ip_packet ip_pkt;
  struct icmp_packet icmp_pkt;
  size_t off;
  int have_port;
  //uint32_t port;

  have = read (icmpsock, buf, sizeof (buf));
  if (have == -1)
    {
      fprintf (stderr,
               "Error reading raw socket: %s\n",
               strerror (errno));
      return;
    }

  off = 0;
  memcpy (&ip_pkt, &buf[off], sizeof (ip_pkt));
  off += sizeof (ip_pkt);
  memcpy (&icmp_pkt, &buf[off], sizeof (icmp_pkt));
  off += sizeof (icmp_pkt);
  if ( (ip_pkt.proto != IPPROTO_ICMP) ||
       (icmp_pkt.type != 11) ||
       (icmp_pkt.code != 0) )
    {
      /* maybe we got an actual reply back... */
      return;
    }

  memcpy(&sip,
         &ip_pkt.src_ip,
         sizeof (sip));

  fprintf (stderr,
           "Received ICMP message of size: %u bytes from %s\n",
           (unsigned int) have,
           inet_ntop (AF_INET,
                      &sip,
                      buf,
                      sizeof (buf)));

  have_port = 0;
  if (have == sizeof (struct ip_packet) *2 + sizeof (struct icmp_packet) * 2 + sizeof(uint32_t))
    {
      have_port = 1;
    }
  else if (have != sizeof (struct ip_packet) *2 + sizeof (struct icmp_packet) * 2)
    {
#if VERBOSE
      fprintf (stderr,
               "Received ICMP message of unexpected size: %u bytes\n",
               (unsigned int) have);
#endif
      return;
    }
}

int
main (int argc, char *const *argv)
{
  int udpsocks[NUM_UDP_PORTS];
  struct in_addr external;
  unsigned int pos;
  int i;
  struct sockaddr_in dst;
  int first_round = 1;
  unsigned int tries;
  struct timeval tv;
  fd_set rs;
  time_t stime;
 
  if (argc != 2)
    {
      fprintf (stderr,
	       "This program must be started with our (internal) IP as the single argument.\n");
      return 1;
    }
  if ( (1 != inet_pton (AF_INET, argv[1], &external)))
    {
      fprintf (stderr,
	       "Error parsing IPv4 address: %s\n",
	       strerror (errno));
      return 1;
    }

  if (1 != inet_pton (AF_INET, DUMMY_IP, &dummy)) abort ();

  fprintf (stderr,
	   "Trying to connect to %s\n",
	   DUMMY_IP);
  srand (stime = time(NULL));
  for (i=0;i<NUM_UDP_PORTS;i++)
    udpsocks[i] = make_udp_socket (i); 

  if (-1 == (icmpsock = make_icmp_socket()))
    return 1;

  memset (&dst, 0, sizeof (dst));
  dst.sin_family = AF_INET;
  dst.sin_addr = dummy;
  pos = 0;
  tries = 0;

  while (1)
    {
      tries++;

      FD_ZERO (&rs);
      FD_SET (icmpsock, &rs);
      tv.tv_sec = 0;
      tv.tv_usec = UDP_SEND_FREQUENCY_MS * 1000;
      select (icmpsock + 1, &rs, NULL, NULL, &tv);
      if (FD_ISSET (icmpsock, &rs))
        process_icmp_response ();

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
#if VERBOSE
      fprintf (stderr,
	       "Sending UDP packet to `%s:%u'\n",
	       DUMMY_IP,
	       ntohs (dst.sin_port));

#endif
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

/* end of gnunet-nat-server-udp.c */

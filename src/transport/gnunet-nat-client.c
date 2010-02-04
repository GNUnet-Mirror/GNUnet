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
 * @file src/transport/gnunet-nat-client.c
 * @brief Tool to help bypass NATs using ICMP method; must run as root (for now, later SUID will do)
 *        This code will work under GNU/Linux only (or maybe BSDs, but never W32)
 * @author Christian Grothoff
 */

#include <sys/types.h> 
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <stdint.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/in.h> 

/**
 * Number of UDP ports to keep open.
 */
#define NUM_UDP_PORTS 512

/**
 * How often do we send our UDP messages to keep ports open?
 */
#define UDP_SEND_FREQUENCY_MS 500

/**
 * Port we use for the dummy target.
 */
#define NAT_TRAV_PORT 2222

/**
 * How often do we retry to open and bind a UDP socket before giving up?
 */
#define MAX_TRIES 10


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

struct icmp_packet 
{
  uint8_t type;
  uint8_t code;
  uint16_t checksum;
  uint32_t reserved;
};

struct udp_packet
{
  uint16_t source_port;
  uint16_t dst_port;
  uint16_t mlen_aka_reply_port_magic;
  uint16_t checksum_aka_my_magic;
};


/**
 * Structure of the data we tack on to the fake ICMP reply
 * (last 4 bytes of the 64 bytes).
 */
struct extra_packet
{
  /**
   * if this is a reply to an icmp, what was the 'my_magic'
   * value from the original icmp?
   */
  uint16_t reply_port_magic;

  /**
   * magic value of the sender of this icmp message.
   */
  uint16_t my_magic;
};

static int udpsocks[NUM_UDP_PORTS];

static uint16_t udpports[NUM_UDP_PORTS];
 
static int icmpsock;

static int rawsock;

static struct in_addr dummy;
 
static struct in_addr target;


/**
 * create a random port number that is not totally
 * unlikely to be chosen by the nat box.
 */ 
static uint16_t make_port ()
{
  return 1024 + ( (unsigned int)rand ()) % (63 * 1024 - 2);
}


/**
 * create a fresh udp socket bound to a random local port.
 */
static int
make_udp_socket (uint16_t *port)
{
  int ret;
  int tries;
  struct sockaddr_in src;

  for (tries=0;tries<MAX_TRIES;tries++)
    {
      ret = socket (AF_INET, SOCK_DGRAM, 0);
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
      src.sin_port = htons (make_port ());
      if (0 != bind (ret, (struct sockaddr*) &src, sizeof (src)))
	{
	  close (ret);
	  continue;
	}
      *port = ntohs (src.sin_port);
      return ret;
    }
  fprintf (stderr,
	   "Error binding udp socket: %s\n",
	   strerror (errno));
  return -1;
}


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


/**
 * send an icmp message to the target.
 *
 * @param my_ip source address (our ip address)
 * @param other target address
 * @param target_port_number fake port number to put into icmp response 
 *                           as well as the icmpextradata as 'my_magic'
 * @param source_port_number magic_number that enables the other peer to
 *                           identify our port number ('reply in response to') to
 *                           put in the data portion; 0 if we are initiating;
 *                           goes into 'reply_port_magic' of the icmpextradata
 */
static void
send_icmp (const struct in_addr *my_ip,
	   const struct in_addr *other,
	   uint16_t target_port_number,
	   uint16_t source_port_number)
{
  struct ip_packet ip_pkt;
  struct icmp_packet icmp_pkt;
  struct udp_packet udp_pkt;
  struct sockaddr_in dst;
  char packet[sizeof (ip_pkt) + sizeof (icmp_pkt) + sizeof (udp_pkt)];
  size_t off;
  int err;

  /* ip header: send to (known) ip address */
  off = 0;
  memset(&ip_pkt, 0, sizeof(ip_pkt));
  ip_pkt.vers_ihl = 0x45;//|(pkt_len>>2);//5;//(ipversion << 4) | (iphdr_size >> 2);
  ip_pkt.tos = 0;
  ip_pkt.pkt_len = sizeof (packet); /* huh? */
  ip_pkt.id = 1; /* kernel will change anyway!? */
  ip_pkt.flags_frag_offset = 0;
  ip_pkt.ttl = IPDEFTTL;
  ip_pkt.proto = IPPROTO_ICMP;
  ip_pkt.checksum = 0; /* maybe the kernel helps us out..? */
  ip_pkt.src_ip = my_ip->s_addr;
  ip_pkt.dst_ip = other->s_addr;
  ip_pkt.checksum = htons(calc_checksum((uint16_t*)&ip_pkt, sizeof (ip_pkt)));
  memcpy (packet, &ip_pkt, sizeof (ip_pkt));
  off += sizeof (ip_pkt);

  /* icmp reply: time exceeded */
  memset(&icmp_pkt, 0, sizeof(icmp_pkt));
  icmp_pkt.type = ICMP_TIME_EXCEEDED;
  icmp_pkt.code = ICMP_NET_UNREACH;
  icmp_pkt.reserved = 0;
  icmp_pkt.checksum = 0;
  icmp_pkt.checksum = htons(calc_checksum((uint16_t*)&icmp_pkt, sizeof (icmp_pkt)));
  memcpy (&packet[off], &icmp_pkt, sizeof (icmp_pkt));
  off += sizeof (icmp_pkt);

  /* ip header of the presumably 'lost' udp packet */
  memset(&ip_pkt, 0, sizeof (ip_pkt));
  ip_pkt.vers_ihl = 0x45;
  ip_pkt.tos = 0;
  /* no idea why i need to shift the bits here, but not on ip_pkt->pkt_len... */
  ip_pkt.pkt_len = (sizeof (ip_pkt) + sizeof (icmp_pkt)) << 8;
  ip_pkt.id = 1; /* kernel sets proper value htons(ip_id_counter); */
  ip_pkt.flags_frag_offset = 0;
  ip_pkt.ttl = 1; /* real TTL would be 1 on a time exceeded packet */
  ip_pkt.proto = IPPROTO_UDP;
  ip_pkt.src_ip = other->s_addr;
  ip_pkt.dst_ip = dummy.s_addr;
  ip_pkt.checksum = 0;
  ip_pkt.checksum = htons(calc_checksum((uint16_t*)&ip_pkt, sizeof (ip_pkt)));
  memcpy (&packet[off], &ip_pkt, sizeof (ip_pkt));
  off += sizeof (ip_pkt);
  
  memset(&udp_pkt, 0, sizeof (udp_pkt));
  udp_pkt.source_port = htons (target_port_number);
  udp_pkt.dst_port = htons (NAT_TRAV_PORT);
  fprintf (stderr,
	   "** Generating ICMP with rpm %u\n",
	   target_port_number);
  udp_pkt.mlen_aka_reply_port_magic = htons (source_port_number);
  udp_pkt.checksum_aka_my_magic = htons (target_port_number);
  memcpy (&packet[off], &udp_pkt, sizeof (udp_pkt));
  off += sizeof (udp_pkt);
  
  memset (&dst, 0, sizeof (dst));
  dst.sin_family = AF_INET;
  dst.sin_addr = *other;
  err = sendto(rawsock, 
	       packet, 
	       off, 0, 
	       (struct sockaddr*)&dst, 
	       sizeof(dst)); /* or sizeof 'struct sockaddr'? */
  if (err < 0) {
    fprintf(stderr,
	    "sendto failed: %s\n", strerror(errno));
  } else if (err != off) 
    fprintf(stderr,
	    "Error: partial send of ICMP message\n");
}


/**
 * We discovered the IP address of the other peer.
 * Try to connect back to it.
 */
static void
try_connect (const struct in_addr *my_ip,
	     const struct in_addr *other,
	     uint16_t port_magic)
{
  unsigned int i;
  char sbuf [INET_ADDRSTRLEN];

  fprintf (stderr,
	   "Sending %u ICMPs to `%s' with reply magic %u\n",
	   NUM_UDP_PORTS,
	   inet_ntop (AF_INET,
		      other,
		      sbuf,
		      sizeof (sbuf)),
	   port_magic);
  for (i=0;i<NUM_UDP_PORTS;i++)
    send_icmp (my_ip, other, make_port(), port_magic);
}


static void
process_icmp_response (const struct in_addr *my_ip,
		       int s)
{
  char buf[65536];
  ssize_t have;
  struct in_addr sip;
  uint16_t my_magic;
  uint16_t reply_magic;
  struct ip_packet ip_pkt;
  struct icmp_packet icmp_pkt;
  struct udp_packet udp_pkt;  
  size_t off;
  
  have = read (s, buf, sizeof (buf));
  if (have == -1)
    {
      fprintf (stderr,
	       "Error reading raw socket: %s\n",
	       strerror (errno));
      /* What now? */
      return; 
    }
  if (have != sizeof (struct ip_packet) *2 + sizeof (struct icmp_packet) + 
      sizeof (struct udp_packet))
    {
      fprintf (stderr,
	       "Received ICMP message of unexpected size: %u bytes\n",
	       (unsigned int) have);
      return;
    }
  off = 0;
  memcpy (&ip_pkt, &buf[off], sizeof (ip_pkt));
  off += sizeof (ip_pkt);
  memcpy (&icmp_pkt, &buf[off], sizeof (icmp_pkt));
  off += sizeof (icmp_pkt);
  off += sizeof (ip_pkt);
  memcpy (&udp_pkt, &buf[off], sizeof (udp_pkt));
  off += sizeof (struct udp_packet);

  if ( (ip_pkt.proto == IPPROTO_ICMP) &&
       (icmp_pkt.type == ICMP_DEST_UNREACH) && 
       (icmp_pkt.code == ICMP_HOST_UNREACH) )
    {
      /* this is what is normal due to our UDP traffic */
      return;
    }
  if ( (ip_pkt.proto != IPPROTO_ICMP) ||
       (icmp_pkt.type != ICMP_TIME_EXCEEDED) || 
       (icmp_pkt.code != ICMP_NET_UNREACH) )
    {
      /* Note the expected client response and not the normal network response */
      fprintf (stderr,
	       "Received unexpected ICMP message contents (%u, %u, %u), ignoring\n",
	       ip_pkt.proto,
	       icmp_pkt.type,
	       icmp_pkt.code);
      return;
    }
  memcpy(&sip, &ip_pkt.src_ip, sizeof (sip));
  reply_magic = ntohs (udp_pkt.checksum_aka_my_magic);
  my_magic = ntohs (udp_pkt.mlen_aka_reply_port_magic);
  if  (my_magic == 0)
    {
#if 0
      /* we get these a lot during loopback testing... */
      fprintf (stderr,
	       "Received ICMP without hint as to which port worked, dropping\n");
#endif
      return;
    }
  fprintf (stderr,
	   "Received ICMP from `%s' with hints %u and %u\n",
	   inet_ntop (AF_INET,
		      &sip,
		      buf,
		      sizeof (buf)),
	   my_magic,
	   reply_magic);
  if (my_magic == 0)
    {
      try_connect (my_ip, &sip, reply_magic);
    }
  else
    {
      send_icmp (my_ip, &target, reply_magic, my_magic);
      printf ("%s:%u\n",
	      inet_ntop (AF_INET,
			 &sip,
			 buf,
			 sizeof(buf)),
	      my_magic);    
    }
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


static int
make_raw_socket ()
{
  const int one = 1;
  int ret;

  ret = socket (AF_INET, SOCK_RAW, IPPROTO_RAW);
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
  if (setsockopt(ret, SOL_SOCKET, SO_BROADCAST,
		 (char *)&one, sizeof(one)) == -1)
    fprintf(stderr,
	    "setsockopt failed: %s\n",
	    strerror (errno));
  if (setsockopt(ret, IPPROTO_IP, IP_HDRINCL,
		 (char *)&one, sizeof(one)) == -1)
    fprintf(stderr,
	    "setsockopt failed: %s\n",
	    strerror (errno));
  return ret;
}


int
main (int argc, char *const *argv)
{
  struct in_addr external;
  unsigned int i;  
  unsigned int pos;
  fd_set rs;
  struct timeval tv;
  struct sockaddr_in dst;  
  uint16_t p;
  
  if (argc != 4)
    {
      fprintf (stderr,
	       "This program must be started with our IP, the targets external IP and the dummy IP address as arguments.\n");
      return 1;
    }
  if ( (1 != inet_pton (AF_INET, argv[1], &external)) ||
       (1 != inet_pton (AF_INET, argv[2], &target)) ||
       (1 != inet_pton (AF_INET, argv[3], &dummy)) )
    {
      fprintf (stderr,
	       "Error parsing IPv4 address: %s\n",
	       strerror (errno));
      return 1;
    }
  memset (&dst, 0, sizeof (dst));
  dst.sin_family = AF_INET;
  dst.sin_port = htons (NAT_TRAV_PORT);
  dst.sin_addr = dummy;

  if (-1 == (icmpsock = make_icmp_socket()))
    return 1; 
  if (-1 == (rawsock = make_raw_socket()))
    {
      close (icmpsock);
      return 1; 
    }
  for (i=0;i<NUM_UDP_PORTS;i++)
    udpsocks[i] = make_udp_socket (&udpports[i]);
  pos = 0;
  while (1)
    {
      FD_ZERO (&rs);
      FD_SET (icmpsock, &rs);
      tv.tv_sec = 0;
      tv.tv_usec = UDP_SEND_FREQUENCY_MS * 1000; 
      select (icmpsock + 1, &rs, NULL, NULL, &tv);
      /* FIXME: do I need my external IP here? */
      if (FD_ISSET (icmpsock, &rs))
	{
	  process_icmp_response (&external, icmpsock);
	  continue;
	}
      fprintf (stderr,
	       "Sending UDP message to %s:%u\n",
	       argv[3],
	       NAT_TRAV_PORT);      
      if (-1 == sendto (udpsocks[pos],
			NULL, 0, 0,
			(struct sockaddr*) &dst, sizeof (dst)))
	{
	  fprintf (stderr, 
		   "sendto failed: %s\n",
		   strerror (errno));
	  close (udpsocks[pos]);
	  udpsocks[pos] = make_udp_socket (&udpports[pos]);
	}
      p = make_port ();
      fprintf (stderr,
	       "Sending fake ICMP message to %s with port %u\n",
	       argv[1],
	       p);      
      send_icmp (&external,
		 &target,
		 p,
		 0);
      pos = (pos+1) % NUM_UDP_PORTS;
    }  
  return 0;
}


/* end of gnunet-nat-client.c */

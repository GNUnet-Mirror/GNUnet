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
 * @file src/transport/gnunet-nat-server-windows.c
 * @brief Windows tool to help bypass NATs using ICMP method
 *        This code will work under W32 only
 * @author Christian Grothoff
 *
 * This program will send ONE ICMP message every 500 ms RAW sockets
 * to a DUMMY IP address and also listens for ICMP replies.  Since
 * it uses RAW sockets, it must be run as an administrative user.
 * In order to keep the security risk of the resulting binary
 * minimal, the program ONLY opens the two RAW sockets with administrative
 * privileges, then drops them and only then starts to process
 * command line arguments.  The code also does not link against
 * any shared libraries (except libc) and is strictly minimal
 * (except for checking for errors).  The following list of people
 * have reviewed this code and considered it safe since the last
 * modification (if you reviewed it, please have your name added
 * to the list):
 *
 * - Nathan Evans
 */
#define _GNU_SOURCE


#include <winsock2.h>
#include <ws2tcpip.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>

typedef unsigned int uid_t;
typedef SOCKET Socket;
typedef unsigned short ushort;
#define IPDEFTTL 64
#define ICMP_ECHO 8
#define ICMP_TIME_EXCEEDED      11      /* Time Exceeded

/**
 * Must match IP given in the client.
 */
#define DUMMY_IP "192.0.2.86"

#define VERBOSE 1

/**
 * How often do we send our ICMP messages to receive replies?
 */
#define ICMP_SEND_FREQUENCY_MS 500

struct ip_packet 
{
  /*uint8_t vers_ihl;
  uint8_t tos;
  uint16_t pkt_len;
  uint16_t id;
  uint16_t flags_frag_offset;
  uint8_t ttl;
  uint8_t proto;
  uint16_t checksum;
  uint32_t src_ip;
  uint32_t dst_ip;*/

  u_char vers_ihl;         // Version (4 bits) + Internet header length (4 bits)
  u_char tos;             // Type of service
  u_short pkt_len;           // Total length
  u_short id;             // Identification
  u_short flags_frag_offset;       // Flags (3 bits) + Fragment offset (13 bits)
  u_char  ttl;            // Time to live
  u_char  proto;          // Protocol
  u_short checksum;            // Header checksum
  u_long  src_ip;     // Source address
  u_long  dst_ip;     // Destination address
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
  uint16_t src_port;

  uint16_t dst_port;

  uint32_t length;
};

static Socket icmpsock;

static Socket rawsock;

static struct in_addr dummy;

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
 * @param af address family
 * @param cp the address to print
 * @param buf where to write the address result
 */
static int inet_pton (int af, char *cp, struct in_addr *buf)
{
  //ret = WSAStringToAddress (cp, af, NULL, (LPSOCKADDR)buf, &ssize);
  buf->s_addr = inet_addr(cp);
  if (buf->s_addr == INADDR_NONE)
    {
      fprintf(stderr, "Error %d handling address %s", WSAGetLastError(), cp);
      return 0;
    }
  else
    return 1;
}

static void
make_echo (const struct in_addr *src_ip,
	   struct icmp_packet *echo)
{
  memset(echo, 0, sizeof(struct icmp_packet));
  echo->type = ICMP_ECHO;
  echo->code = 0;
  echo->reserved = 0;
  echo->checksum = 0;
  echo->checksum = htons(calc_checksum((uint16_t*)echo, sizeof (struct icmp_packet)));
}


/**
 * Send an ICMP message to the dummy IP.
 *
 * @param my_ip source address (our ip address)
 */
static void
send_icmp_echo (const struct in_addr *my_ip)
{
  struct icmp_packet icmp_echo;
  struct sockaddr_in dst;
  size_t off;
  int err;
  struct ip_packet ip_pkt;
  struct icmp_packet icmp_pkt;
  char packet[sizeof (ip_pkt) + sizeof (icmp_pkt)];

  off = 0;
  memset(&ip_pkt, 0, sizeof(ip_pkt));
  ip_pkt.vers_ihl = 0x45;
  ip_pkt.tos = 0;
  ip_pkt.pkt_len = sizeof (packet);
  ip_pkt.id = htons (256);
  ip_pkt.flags_frag_offset = 0;
  ip_pkt.ttl = IPDEFTTL;
  ip_pkt.proto = IPPROTO_ICMP;
  ip_pkt.checksum = 0;
  ip_pkt.src_ip = my_ip->s_addr;
  ip_pkt.dst_ip = dummy.s_addr;
  ip_pkt.checksum = htons(calc_checksum((uint16_t*)&ip_pkt, sizeof (ip_pkt)));
  memcpy (packet, &ip_pkt, sizeof (ip_pkt));
  off += sizeof (ip_pkt);

  make_echo (my_ip, &icmp_echo);
  memcpy (&packet[off], &icmp_echo, sizeof (icmp_echo));
  off += sizeof (icmp_echo);
 
  memset (&dst, 0, sizeof (dst));
  dst.sin_family = AF_INET;
  dst.sin_addr = dummy;
  err = sendto(rawsock, 
               packet, off, 0,
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
	      "Error: partial send of ICMP message\n");
    }
}


static void
process_icmp_response ()
{
  char buf[65536];
  ssize_t have;
  struct in_addr sip;
  struct ip_packet ip_pkt;
  struct icmp_packet icmp_pkt;
  struct udp_packet udp_pkt;
  size_t off;
  int have_port;
  int have_udp;
  uint32_t port;
  have = read (icmpsock, buf, sizeof (buf));
  if (have == -1)
    {
      fprintf (stderr,
	       "Error reading raw socket: %s\n",
	       strerror (errno));
      return; 
    }
  have_port = 0;
#if VERBOSE
  fprintf (stderr,
           "Received message of %u bytes\n",
           (unsigned int) have);
#endif
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
  off = 0;
  memcpy (&ip_pkt, &buf[off], sizeof (ip_pkt));
  off += sizeof (ip_pkt);
  memcpy (&icmp_pkt, &buf[off], sizeof (icmp_pkt));
  off += sizeof (icmp_pkt);
  if ( ((ip_pkt.proto != IPPROTO_ICMP) && (ip_pkt.proto != IPPROTO_UDP)) ||
       (icmp_pkt.type != ICMP_TIME_EXCEEDED) || 
       (icmp_pkt.code != 0) )
    {
      /* maybe we got an actual reply back... */
      return;    
    }
  memcpy(&sip, 
	 &ip_pkt.src_ip, 
	 sizeof (sip));

  memcpy (&ip_pkt, &buf[off], sizeof (ip_pkt));
  off += sizeof (ip_pkt);

  have_udp = 0;
  if (ip_pkt.proto == IPPROTO_UDP)
    {
      have_udp = 1;
    }

  if (have_port)
    {
      memcpy(&port, &buf[sizeof (struct ip_packet) *2 + sizeof (struct icmp_packet) * 2], sizeof(uint32_t));
      port = ntohs(port);
      DWORD ssize = sizeof(buf);
      WSAAddressToString((LPSOCKADDR)&sip, sizeof(sip), NULL, buf, &ssize);
      fprintf (stdout, "%s:%d\n", buf, port);

    }
  else if (have_udp)
    {
      memcpy(&udp_pkt, &buf[off], sizeof(udp_pkt));
      DWORD ssize = sizeof(buf);
      WSAAddressToString((LPSOCKADDR)&sip, sizeof(sip), NULL, buf, &ssize);
      fprintf (stdout, "%s:%d\n", buf, ntohs((int)udp_pkt.length));
    }
  else
    {
      DWORD ssize = sizeof(buf);
      WSAAddressToString((LPSOCKADDR)&sip, sizeof(sip), NULL, buf, &ssize);
      fprintf (stdout, "%s\n", buf);
    }
  fflush (stdout);
}


static Socket
make_icmp_socket ()
{
  Socket ret;

  ret = socket (AF_INET, SOCK_RAW, IPPROTO_ICMP);
  if (-1 == ret)
    {
      fprintf (stderr,
	       "Error opening RAW socket: %s\n",
	       strerror (errno));
      return -1;
    }  
  if (ret == INVALID_SOCKET)
    {
      fprintf (stderr, "Invalid socket %d!\n", ret);
      closesocket (ret);
    }
  return ret;
}


static Socket
make_raw_socket ()
{
  DWORD bOptVal = TRUE;
  int bOptLen = sizeof(bOptVal);

  rawsock = socket (AF_INET, SOCK_RAW, IPPROTO_ICMP);
  if (-1 == rawsock)
    {
      fprintf (stderr,
	       "Error opening RAW socket: %s\n",
	       strerror (errno));
      return -1;
    }

  if (setsockopt(rawsock, SOL_SOCKET, SO_BROADCAST, (char*)&bOptVal, bOptLen) != 0)
    fprintf(stderr, "Error setting SO_BROADCAST: ON\n");

  if (setsockopt(rawsock, IPPROTO_IP, IP_HDRINCL, (char*)&bOptVal, bOptLen) != 0)
    fprintf(stderr, "Error setting IP_HDRINCL: ON\n");
  return rawsock;
}


int
main (int argc, char *const *argv)
{
  struct in_addr external;
  fd_set rs;
  struct timeval tv;

  // WSA startup
  WSADATA wsaData;
  if (WSAStartup (MAKEWORD (2, 1), &wsaData) != 0)
  {
      fprintf (stderr, "Failed to find Winsock 2.1 or better.\n");
      return 4;                       // ERROR
  }

  if (-1 == (icmpsock = make_icmp_socket()))
    return 1; 
  if (-1 == (make_raw_socket()))
    {
      close (icmpsock);
      return 1; 
    }

  if (argc != 2)
    {
      fprintf (stderr,
	       "This program must be started with our (internal NAT) IP as the only argument.\n");
      return 1;
    }

  if (1 != inet_pton (AF_INET, argv[1], &external))
    {
      fprintf (stderr,
	       "Error parsing IPv4 address: %s, error %s\n",
	       argv[1], strerror (errno));
      return 1;
    }

  if (1 != inet_pton (AF_INET, DUMMY_IP, &dummy)) abort ();
  while (1)
    {
      FD_ZERO (&rs);
      FD_SET (icmpsock, &rs);
      tv.tv_sec = 0;
      tv.tv_usec = ICMP_SEND_FREQUENCY_MS * 1000; 
      select (icmpsock + 1, &rs, NULL, NULL, &tv);
      if (FD_ISSET (icmpsock, &rs))
        process_icmp_response ();
      send_icmp_echo (&external);
    }  

  closesocket(icmpsock);
  closesocket(rawsock);
  WSACleanup ();
  return 0;
}


/* end of gnunet-nat-server-windows.c */

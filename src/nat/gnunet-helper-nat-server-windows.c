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
 * @file src/nat/gnunet-helper-nat-server-windows.c
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
 * - Christian Grothoff
 */
#define _GNU_SOURCE

#define FD_SETSIZE 1024
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

/**
 * Should we print some debug output?
 */
#define VERBOSE 0

/**
 * Must match IP given in the client.
 */
#define DUMMY_IP "192.0.2.86"

/**
 * Default Port
 */
#define NAT_TRAV_PORT 22225

/**
 * Must match packet ID used by gnunet-helper-nat-client.c
 */
#define PACKET_ID 256

/**
 * TTL to use for our outgoing messages.
 */
#define IPDEFTTL 64

#define ICMP_ECHO 8

#define ICMP_TIME_EXCEEDED 11

/**
 * How often do we send our ICMP messages to receive replies?
 */
#define ICMP_SEND_FREQUENCY_MS 500

/**
 * IPv4 header.
 */
struct ip_header
{

  /**
   * Version (4 bits) + Internet header length (4 bits)
   */
  uint8_t vers_ihl;

  /**
   * Type of service
   */
  uint8_t tos;

  /**
   * Total length
   */
  uint16_t pkt_len;

  /**
   * Identification
   */
  uint16_t id;

  /**
   * Flags (3 bits) + Fragment offset (13 bits)
   */
  uint16_t flags_frag_offset;

  /**
   * Time to live
   */
  uint8_t ttl;

  /**
   * Protocol
   */
  uint8_t proto;

  /**
   * Header checksum
   */
  uint16_t checksum;

  /**
   * Source address
   */
  uint32_t src_ip;

  /**
   * Destination address
   */
  uint32_t dst_ip;
};

/**
 * Format of ICMP packet.
 */
struct icmp_ttl_exceeded_header
{
  uint8_t type;

  uint8_t code;

  uint16_t checksum;

  uint32_t unused;

  /* followed by original payload */
};

struct icmp_echo_header
{
  uint8_t type;

  uint8_t code;

  uint16_t checksum;

  uint32_t reserved;
};

/**
 * Beginning of UDP packet.
 */
struct udp_header
{
  uint16_t src_port;

  uint16_t dst_port;

  uint16_t length;

  uint16_t crc;
};

/**
 * Socket we use to receive "fake" ICMP replies.
 */
static SOCKET icmpsock;

/**
 * Socket we use to send our ICMP requests.
 */
static SOCKET rawsock;

/**
 * Socket we use to send our UDP requests.
 */
static SOCKET udpsock;

/**
 * Target "dummy" address.
 */
static struct in_addr dummy;


/**
 * CRC-16 for IP/ICMP headers.
 *
 * @param data what to calculate the CRC over
 * @param bytes number of bytes in data (must be multiple of 2)
 * @return the CRC 16.
 */
static uint16_t
calc_checksum (const uint16_t * data, unsigned int bytes)
{
  uint32_t sum;
  unsigned int i;

  sum = 0;
  for (i = 0; i < bytes / 2; i++)
    sum += data[i];
  sum = (sum & 0xffff) + (sum >> 16);
  sum = htons (0xffff - sum);
  return sum;
}


/**
 * Convert IPv4 address from text to binary form.
 *
 * @param af address family
 * @param cp the address to print
 * @param buf where to write the address result
 * @return 1 on success
 */
static int
inet_pton (int af, const char *cp, struct in_addr *buf)
{
  buf->s_addr = inet_addr (cp);
  if (buf->s_addr == INADDR_NONE)
  {
    fprintf (stderr, "Error %d handling address %s", WSAGetLastError (), cp);
    return 0;
  }
  return 1;
}


/**
 * Send an ICMP message to the dummy IP.
 *
 * @param my_ip source address (our ip address)
 */
static void
send_icmp_echo (const struct in_addr *my_ip)
{
  char packet[sizeof (struct ip_header) + sizeof (struct icmp_echo_header)];
  struct icmp_echo_header icmp_echo;
  struct ip_header ip_pkt;
  struct sockaddr_in dst;
  size_t off;
  int err;

  off = 0;
  ip_pkt.vers_ihl = 0x45;
  ip_pkt.tos = 0;
  ip_pkt.pkt_len = htons (sizeof (packet));
  ip_pkt.id = htons (PACKET_ID);
  ip_pkt.flags_frag_offset = 0;
  ip_pkt.ttl = IPDEFTTL;
  ip_pkt.proto = IPPROTO_ICMP;
  ip_pkt.checksum = 0;
  ip_pkt.src_ip = my_ip->s_addr;
  ip_pkt.dst_ip = dummy.s_addr;
  ip_pkt.checksum =
      htons (calc_checksum ((uint16_t *) & ip_pkt, sizeof (struct ip_header)));
  memcpy (&packet[off], &ip_pkt, sizeof (struct ip_header));
  off += sizeof (struct ip_header);

  icmp_echo.type = ICMP_ECHO;
  icmp_echo.code = 0;
  icmp_echo.reserved = 0;
  icmp_echo.checksum = 0;
  icmp_echo.checksum =
      htons (calc_checksum
             ((uint16_t *) & icmp_echo, sizeof (struct icmp_echo_header)));
  memcpy (&packet[off], &icmp_echo, sizeof (struct icmp_echo_header));
  off += sizeof (struct icmp_echo_header);

  memset (&dst, 0, sizeof (dst));
  dst.sin_family = AF_INET;
  dst.sin_addr = dummy;
  err =
      sendto (rawsock, packet, off, 0, (struct sockaddr *) &dst, sizeof (dst));
  if (err < 0)
  {
#if VERBOSE
    fprintf (stderr, "sendto failed: %s\n", strerror (errno));
#endif
  }
  else if (err != off)
  {
    fprintf (stderr, "Error: partial send of ICMP message\n");
  }
}


/**
 * Send a UDP message to the dummy IP.
 */
static void
send_udp ()
{
  struct sockaddr_in dst;
  ssize_t err;

  memset (&dst, 0, sizeof (dst));
  dst.sin_family = AF_INET;
  dst.sin_addr = dummy;
  dst.sin_port = htons (NAT_TRAV_PORT);
  err = sendto (udpsock, NULL, 0, 0, (struct sockaddr *) &dst, sizeof (dst));
  if (err < 0)
  {
#if VERBOSE
    fprintf (stderr, "sendto failed: %s\n", strerror (errno));
#endif
  }
  else if (0 != err)
  {
    fprintf (stderr, "Error: partial send of ICMP message\n");
  }
}


/**
 * We've received an ICMP response.  Process it.
 */
static void
process_icmp_response ()
{
  char buf[65536];
  ssize_t have;
  struct in_addr source_ip;
  struct ip_header ip_pkt;
  struct icmp_ttl_exceeded_header icmp_ttl;
  struct icmp_echo_header icmp_echo;
  struct udp_header udp_pkt;
  size_t off;
  uint16_t port;
  DWORD ssize;

  have = read (icmpsock, buf, sizeof (buf));
  if (have == -1)
  {
    fprintf (stderr, "Error reading raw socket: %s\n", strerror (errno));
    return;
  }
#if VERBOSE
  fprintf (stderr, "Received message of %u bytes\n", (unsigned int) have);
#endif
  if (have <
      (ssize_t) (sizeof (struct ip_header) +
                 sizeof (struct icmp_ttl_exceeded_header) +
                 sizeof (struct ip_header)))
  {
    /* malformed */
    return;
  }
  off = 0;
  memcpy (&ip_pkt, &buf[off], sizeof (struct ip_header));
  off += sizeof (struct ip_header);
  memcpy (&source_ip, &ip_pkt.src_ip, sizeof (source_ip));
  memcpy (&icmp_ttl, &buf[off], sizeof (struct icmp_ttl_exceeded_header));
  off += sizeof (struct icmp_ttl_exceeded_header);
  if ((ICMP_TIME_EXCEEDED != icmp_ttl.type) || (0 != icmp_ttl.code))
  {
    /* different type than what we want */
    return;
  }
  /* skip 2nd IP header */
  memcpy (&ip_pkt, &buf[off], sizeof (struct ip_header));
  off += sizeof (struct ip_header);

  switch (ip_pkt.proto)
  {
  case IPPROTO_ICMP:
    if (have !=
        (sizeof (struct ip_header) * 2 +
         sizeof (struct icmp_ttl_exceeded_header) +
         sizeof (struct icmp_echo_header)))
    {
      /* malformed */
      return;
    }
    /* grab ICMP ECHO content */
    memcpy (&icmp_echo, &buf[off], sizeof (struct icmp_echo_header));
    port = (uint16_t) ntohl (icmp_echo.reserved);
    break;
  case IPPROTO_UDP:
    if (have !=
        (sizeof (struct ip_header) * 2 +
         sizeof (struct icmp_ttl_exceeded_header) + sizeof (struct udp_header)))
    {
      /* malformed */
      return;
    }
    /* grab UDP content */
    memcpy (&udp_pkt, &buf[off], sizeof (struct udp_header));
    port = ntohs (udp_pkt.length);
    break;
  default:
    /* different type than what we want */
    return;
  }

  ssize = sizeof (buf);
  WSAAddressToString ((LPSOCKADDR) & source_ip, sizeof (source_ip), NULL, buf,
                      &ssize);
  if (port == 0)
    fprintf (stdout, "%s\n", buf);
  else
    fprintf (stdout, "%s:%u\n", buf, (unsigned int) port);
  fflush (stdout);
}


/**
 * Create an ICMP raw socket for reading.
 *
 * @return INVALID_SOCKET on error
 */
static SOCKET
make_icmp_socket ()
{
  SOCKET ret;

  ret = socket (AF_INET, SOCK_RAW, IPPROTO_ICMP);
  if (INVALID_SOCKET == ret)
  {
    fprintf (stderr, "Error opening RAW socket: %s\n", strerror (errno));
    return INVALID_SOCKET;
  }
  return ret;
}


/**
 * Create an ICMP raw socket for writing.
 *
 * @return INVALID_SOCKET on error
 */
static SOCKET
make_raw_socket ()
{
  DWORD bOptVal = TRUE;
  int bOptLen = sizeof (bOptVal);

  rawsock = socket (AF_INET, SOCK_RAW, IPPROTO_ICMP);
  if (INVALID_SOCKET == rawsock)
  {
    fprintf (stderr, "Error opening RAW socket: %s\n", strerror (errno));
    return INVALID_SOCKET;
  }

  if (0 !=
      setsockopt (rawsock, SOL_SOCKET, SO_BROADCAST, (char *) &bOptVal,
                  bOptLen))
  {
    fprintf (stderr, "Error setting SO_BROADCAST to ON: %s\n",
             strerror (errno));
    closesocket (rawsock);
    return INVALID_SOCKET;
  }
  if (0 !=
      setsockopt (rawsock, IPPROTO_IP, IP_HDRINCL, (char *) &bOptVal, bOptLen))
  {
    fprintf (stderr, "Error setting IP_HDRINCL to ON: %s\n", strerror (errno));
    closesocket (rawsock);
    return INVALID_SOCKET;
  }
  return rawsock;
}


/**
 * Create a UDP socket for writing.
 *
 * @param my_ip source address (our ip address)
 * @return INVALID_SOCKET on error
 */
static SOCKET
make_udp_socket (const struct in_addr *my_ip)
{
  SOCKET ret;
  struct sockaddr_in addr;

  ret = socket (AF_INET, SOCK_DGRAM, 0);
  if (INVALID_SOCKET == ret)
  {
    fprintf (stderr, "Error opening UDP socket: %s\n", strerror (errno));
    return INVALID_SOCKET;
  }
  memset (&addr, 0, sizeof (addr));
  addr.sin_family = AF_INET;
  addr.sin_addr = *my_ip;
  addr.sin_port = htons (NAT_TRAV_PORT);
  if (0 != bind (ret, (struct sockaddr *) &addr, sizeof (addr)))
  {
    fprintf (stderr, "Error binding UDP socket to port %u: %s\n", NAT_TRAV_PORT,
             strerror (errno));
    /* likely problematic, but not certain, try to continue */
  }
  return ret;
}


int
main (int argc, char *const *argv)
{
  struct in_addr external;
  fd_set rs;
  struct timeval tv;
  WSADATA wsaData;
  unsigned int alt;

  alt = 0;
  if (2 != argc)
  {
    fprintf (stderr,
             "This program must be started with our (internal NAT) IP as the only argument.\n");
    return 1;
  }
  if (1 != inet_pton (AF_INET, argv[1], &external))
  {
    fprintf (stderr, "Error parsing IPv4 address: %s, error %s\n", argv[1],
             strerror (errno));
    return 1;
  }
  if (1 != inet_pton (AF_INET, DUMMY_IP, &dummy))
  {
    fprintf (stderr, "Internal error converting dummy IP to binary.\n");
    return 2;
  }
  if (WSAStartup (MAKEWORD (2, 1), &wsaData) != 0)
  {
    fprintf (stderr, "Failed to find Winsock 2.1 or better.\n");
    return 2;
  }
  if (INVALID_SOCKET == (icmpsock = make_icmp_socket ()))
  {
    return 3;
  }
  if (INVALID_SOCKET == (make_raw_socket ()))
  {
    closesocket (icmpsock);
    return 3;
  }
  if (INVALID_SOCKET == (udpsock = make_udp_socket (&external)))
  {
    closesocket (icmpsock);
    closesocket (rawsock);
    return 3;
  }
  while (1)
  {
    FD_ZERO (&rs);
    FD_SET (icmpsock, &rs);
    tv.tv_sec = 0;
    tv.tv_usec = ICMP_SEND_FREQUENCY_MS * 1000;
    if (-1 == select (icmpsock + 1, &rs, NULL, NULL, &tv))
    {
      if (errno == EINTR)
        continue;
      fprintf (stderr, "select failed: %s\n", strerror (errno));
      break;
    }
    if (FD_ISSET (icmpsock, &rs))
      process_icmp_response ();
    if (0 == (++alt % 2))
      send_icmp_echo (&external);
    else
      send_udp ();
  }
  /* select failed (internal error or OS out of resources) */
  closesocket (icmpsock);
  closesocket (rawsock);
  closesocket (udpsock);
  WSACleanup ();
  return 4;
}


/* end of gnunet-helper-nat-server-windows.c */

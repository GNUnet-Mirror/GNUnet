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
 * @file src/nat/gnunet-helper-nat-client.c
 * @brief Tool to help bypass NATs using ICMP method; must run as root (SUID will do)
 *        This code will work under GNU/Linux only.
 * @author Christian Grothoff
 *
 * This program will send ONE ICMP message using RAW sockets
 * to the IP address specified as the second argument.  Since
 * it uses RAW sockets, it must be installed SUID or run as 'root'.
 * In order to keep the security risk of the resulting SUID binary
 * minimal, the program ONLY opens the RAW socket with root
 * privileges, then drops them and only then starts to process
 * command line arguments.  The code also does not link against
 * any shared libraries (except libc) and is strictly minimal
 * (except for checking for errors).  The following list of people
 * have reviewed this code and considered it safe since the last
 * modification (if you reviewed it, please have your name added
 * to the list):
 *
 * - Christian Grothoff
 * - Nathan Evans
 * - Benjamin Kuperman (22 Aug 2010)
 */
#if HAVE_CONFIG_H
/* Just needed for HAVE_SOCKADDR_IN_SIN_LEN test macro! */
#include "gnunet_config.h"
#else
#define _GNU_SOURCE
#endif
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
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/in.h>

/**
 * Must match IP given in the server.
 */
#define DUMMY_IP "192.0.2.86"

#define NAT_TRAV_PORT 22225

/**
 * Must match packet ID used by gnunet-helper-nat-server.c
 */
#define PACKET_ID 256

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
 * Socket we use to send our fake ICMP replies.
 */
static int rawsock;

/**
 * Target "dummy" address of the packet we pretend to respond to.
 */
static struct in_addr dummy;

/**
 * Our "source" port.
 */
static uint16_t port;


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
 * Send an ICMP message to the target.
 *
 * @param my_ip source address
 * @param other target address
 */
static void
send_icmp_udp (const struct in_addr *my_ip, const struct in_addr *other)
{
  char packet[sizeof (struct ip_header) * 2 +
              sizeof (struct icmp_ttl_exceeded_header) +
              sizeof (struct udp_header)];
  struct ip_header ip_pkt;
  struct icmp_ttl_exceeded_header icmp_pkt;
  struct udp_header udp_pkt;
  struct sockaddr_in dst;
  size_t off;
  int err;

  /* ip header: send to (known) ip address */
  off = 0;
  ip_pkt.vers_ihl = 0x45;
  ip_pkt.tos = 0;
  ip_pkt.pkt_len = htons (sizeof (packet));
  ip_pkt.id = htons (PACKET_ID);
  ip_pkt.flags_frag_offset = 0;
  ip_pkt.ttl = 128;
  ip_pkt.proto = IPPROTO_ICMP;
  ip_pkt.checksum = 0;
  ip_pkt.src_ip = my_ip->s_addr;
  ip_pkt.dst_ip = other->s_addr;
  ip_pkt.checksum =
      htons (calc_checksum ((uint16_t *) & ip_pkt, sizeof (struct ip_header)));
  memcpy (&packet[off], &ip_pkt, sizeof (struct ip_header));
  off += sizeof (struct ip_header);

  icmp_pkt.type = ICMP_TIME_EXCEEDED;
  icmp_pkt.code = 0;
  icmp_pkt.checksum = 0;
  icmp_pkt.unused = 0;
  memcpy (&packet[off], &icmp_pkt, sizeof (struct icmp_ttl_exceeded_header));
  off += sizeof (struct icmp_ttl_exceeded_header);

  /* ip header of the presumably 'lost' udp packet */
  ip_pkt.vers_ihl = 0x45;
  ip_pkt.tos = 0;
  ip_pkt.pkt_len =
      htons (sizeof (struct ip_header) + sizeof (struct udp_header));
  ip_pkt.id = htons (0);
  ip_pkt.flags_frag_offset = 0;
  ip_pkt.ttl = 128;
  ip_pkt.proto = IPPROTO_UDP;
  ip_pkt.checksum = 0;
  ip_pkt.src_ip = other->s_addr;
  ip_pkt.dst_ip = dummy.s_addr;
  ip_pkt.checksum =
      htons (calc_checksum ((uint16_t *) & ip_pkt, sizeof (struct ip_header)));
  memcpy (&packet[off], &ip_pkt, sizeof (struct ip_header));
  off += sizeof (struct ip_header);

  /* build UDP header */
  udp_pkt.src_port = htons (NAT_TRAV_PORT);
  udp_pkt.dst_port = htons (NAT_TRAV_PORT);
  udp_pkt.length = htons (port);
  udp_pkt.crc = 0;
  memcpy (&packet[off], &udp_pkt, sizeof (struct udp_header));
  off += sizeof (struct udp_header);

  /* set ICMP checksum */
  icmp_pkt.checksum =
      htons (calc_checksum
             ((uint16_t *) & packet[sizeof (struct ip_header)],
              sizeof (struct icmp_ttl_exceeded_header) +
              sizeof (struct ip_header) + sizeof (struct udp_header)));
  memcpy (&packet[sizeof (struct ip_header)], &icmp_pkt,
          sizeof (struct icmp_ttl_exceeded_header));

  memset (&dst, 0, sizeof (dst));
  dst.sin_family = AF_INET;
#if HAVE_SOCKADDR_IN_SIN_LEN
  dst.sin_len = sizeof (struct sockaddr_in);
#endif
  dst.sin_addr = *other;
  err =
      sendto (rawsock, packet, sizeof (packet), 0, (struct sockaddr *) &dst,
              sizeof (dst));
  if (err < 0)
  {
    fprintf (stderr, "sendto failed: %s\n", strerror (errno));
  }
  else if (sizeof (packet) != (size_t) err)
  {
    fprintf (stderr, "Error: partial send of ICMP message\n");
  }
}


/**
 * Send an ICMP message to the target.
 *
 * @param my_ip source address
 * @param other target address
 */
static void
send_icmp (const struct in_addr *my_ip, const struct in_addr *other)
{
  struct ip_header ip_pkt;
  struct icmp_ttl_exceeded_header icmp_ttl;
  struct icmp_echo_header icmp_echo;
  struct sockaddr_in dst;
  char packet[sizeof (struct ip_header) * 2 +
              sizeof (struct icmp_ttl_exceeded_header) +
              sizeof (struct icmp_echo_header)];
  size_t off;
  int err;

  /* ip header: send to (known) ip address */
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
  ip_pkt.dst_ip = other->s_addr;
  ip_pkt.checksum =
      htons (calc_checksum ((uint16_t *) & ip_pkt, sizeof (struct ip_header)));
  memcpy (&packet[off], &ip_pkt, sizeof (struct ip_header));
  off = sizeof (ip_pkt);

  /* icmp reply: time exceeded */
  icmp_ttl.type = ICMP_TIME_EXCEEDED;
  icmp_ttl.code = 0;
  icmp_ttl.checksum = 0;
  icmp_ttl.unused = 0;
  memcpy (&packet[off], &icmp_ttl, sizeof (struct icmp_ttl_exceeded_header));
  off += sizeof (struct icmp_ttl_exceeded_header);

  /* ip header of the presumably 'lost' udp packet */
  ip_pkt.vers_ihl = 0x45;
  ip_pkt.tos = 0;
  ip_pkt.pkt_len =
      htons (sizeof (struct ip_header) + sizeof (struct icmp_echo_header));
  ip_pkt.id = htons (PACKET_ID);
  ip_pkt.flags_frag_offset = 0;
  ip_pkt.ttl = 1;               /* real TTL would be 1 on a time exceeded packet */
  ip_pkt.proto = IPPROTO_ICMP;
  ip_pkt.src_ip = other->s_addr;
  ip_pkt.dst_ip = dummy.s_addr;
  ip_pkt.checksum = 0;
  ip_pkt.checksum =
      htons (calc_checksum ((uint16_t *) & ip_pkt, sizeof (struct ip_header)));
  memcpy (&packet[off], &ip_pkt, sizeof (struct ip_header));
  off += sizeof (struct ip_header);

  icmp_echo.type = ICMP_ECHO;
  icmp_echo.code = 0;
  icmp_echo.reserved = htonl (port);
  icmp_echo.checksum = 0;
  icmp_echo.checksum =
      htons (calc_checksum
             ((uint16_t *) & icmp_echo, sizeof (struct icmp_echo_header)));
  memcpy (&packet[off], &icmp_echo, sizeof (struct icmp_echo_header));

  /* no go back to calculate ICMP packet checksum */
  off = sizeof (struct ip_header);
  icmp_ttl.checksum =
      htons (calc_checksum
             ((uint16_t *) & packet[off],
              sizeof (struct icmp_ttl_exceeded_header) +
              sizeof (struct ip_header) + sizeof (struct icmp_echo_header)));
  memcpy (&packet[off], &icmp_ttl, sizeof (struct icmp_ttl_exceeded_header));

  /* prepare for transmission */
  memset (&dst, 0, sizeof (dst));
  dst.sin_family = AF_INET;
#if HAVE_SOCKADDR_IN_SIN_LEN
  dst.sin_len = sizeof (struct sockaddr_in);
#endif
  dst.sin_addr = *other;
  err =
      sendto (rawsock, packet, sizeof (packet), 0, (struct sockaddr *) &dst,
              sizeof (dst));
  if (err < 0)
  {
    fprintf (stderr, "sendto failed: %s\n", strerror (errno));
  }
  else if (sizeof (packet) != (size_t) err)
  {
    fprintf (stderr, "Error: partial send of ICMP message\n");
  }
}


int
main (int argc, char *const *argv)
{
  const int one = 1;
  struct in_addr external;
  struct in_addr target;
  uid_t uid;
  unsigned int p;
  int raw_eno;
  int global_ret;

  /* Create an ICMP raw socket for writing (only operation that requires root) */
  rawsock = socket (AF_INET, SOCK_RAW, IPPROTO_RAW);
  raw_eno = errno; /* for later error checking */

  /* now drop root privileges */
  uid = getuid ();
#ifdef HAVE_SETRESUID
  if (0 != setresuid (uid, uid, uid))
  {
    fprintf (stderr, "Failed to setresuid: %s\n", strerror (errno));
    global_ret = 1;
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
  if (-1 == rawsock)
  {
    fprintf (stderr, "Error opening RAW socket: %s\n", strerror (raw_eno));
    global_ret = 3;
    goto cleanup;
  }
  if (0 !=
      setsockopt (rawsock, SOL_SOCKET, SO_BROADCAST, (char *) &one, sizeof (one)))
  {
    fprintf (stderr, "setsockopt failed: %s\n", strerror (errno));
    global_ret = 4;
    goto cleanup;
  }
  if (0 !=
      setsockopt (rawsock, IPPROTO_IP, IP_HDRINCL, (char *) &one, sizeof (one)))
  {
    fprintf (stderr, "setsockopt failed: %s\n", strerror (errno));
    global_ret = 5;
    goto cleanup;
  }

  if (4 != argc)
  {
    fprintf (stderr,
             "This program must be started with our IP, the targets external IP, and our port as arguments.\n");
    global_ret = 6;
    goto cleanup;
  }
  if ((1 != inet_pton (AF_INET, argv[1], &external)) ||
      (1 != inet_pton (AF_INET, argv[2], &target)))
  {
    fprintf (stderr, "Error parsing IPv4 address: %s\n", strerror (errno));
    global_ret = 7;
    goto cleanup;
  }
  if ((1 != sscanf (argv[3], "%u", &p)) || (0 == p) || (0xFFFF < p))
  {
    fprintf (stderr, "Error parsing port value `%s'\n", argv[3]);
    global_ret = 8;
    goto cleanup;
  }
  port = (uint16_t) p;
  if (1 != inet_pton (AF_INET, DUMMY_IP, &dummy))
  {
    fprintf (stderr, "Internal error converting dummy IP to binary.\n");
    global_ret = 9;
    goto cleanup;
  }
  send_icmp (&external, &target);
  send_icmp_udp (&external, &target);
  global_ret = 0;
 cleanup:
  if (-1 != rawsock)
    (void) close (rawsock);
  return global_ret;
}

/* end of gnunet-helper-nat-client.c */

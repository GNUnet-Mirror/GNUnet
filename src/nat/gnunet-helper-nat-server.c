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
 * @file src/nat/gnunet-helper-nat-server.c
 * @brief Tool to help bypass NATs using ICMP method; must run as root (SUID will do)
 *        This code will work under GNU/Linux only (or maybe BSDs, but never W32)
 * @author Christian Grothoff
 *
 * This program will send ONE ICMP message every 500 ms RAW sockets
 * to a DUMMY IP address and also listens for ICMP replies.  Since
 * it uses RAW sockets, it must be installed SUID or run as 'root'.
 * In order to keep the security risk of the resulting SUID binary
 * minimal, the program ONLY opens the two RAW sockets with root
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
 * - Jacob Appelbaum (19 Dec 2011)
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
#include <sys/select.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/in.h>

/**
 * Should we print some debug output?
 */
#define VERBOSE 0

/**
 * Must match packet ID used by gnunet-helper-nat-client.c
 */
#define PACKET_ID 256

/**
 * Must match IP given in the client.
 */
#define DUMMY_IP "192.0.2.86"

/**
 * Port for UDP
 */
#define NAT_TRAV_PORT 22225

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
static int icmpsock;

/**
 * Socket we use to send our ICMP requests.
 */
static int rawsock;

/**
 * Socket we use to send our UDP requests.
 */
static int udpsock;

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
  icmp_echo.checksum = 0;
  icmp_echo.reserved = 0;
  icmp_echo.checksum =
      htons (calc_checksum
             ((uint16_t *) & icmp_echo, sizeof (struct icmp_echo_header)));
  memcpy (&packet[off], &icmp_echo, sizeof (struct icmp_echo_header));
  off += sizeof (struct icmp_echo_header);

  memset (&dst, 0, sizeof (dst));
  dst.sin_family = AF_INET;
#if HAVE_SOCKADDR_IN_SIN_LEN
  dst.sin_len = sizeof (struct sockaddr_in);
#endif
  dst.sin_addr = dummy;
  err =
      sendto (rawsock, packet, off, 0, (struct sockaddr *) &dst, sizeof (dst));
  if (err < 0)
  {
#if VERBOSE
    fprintf (stderr, "sendto failed: %s\n", strerror (errno));
#endif
  }
  else if (sizeof (packet) != err)
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
#if HAVE_SOCKADDR_IN_SIN_LEN
  dst.sin_len = sizeof (struct sockaddr_in);
#endif
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

  have = read (icmpsock, buf, sizeof (buf));
  if (-1 == have)
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

  source_ip.s_addr = ip_pkt.src_ip;
  if (port == 0)
    fprintf (stdout, "%s\n",
             inet_ntop (AF_INET, &source_ip, buf, sizeof (buf)));
  else
    fprintf (stdout, "%s:%u\n",
             inet_ntop (AF_INET, &source_ip, buf, sizeof (buf)),
             (unsigned int) port);
  fflush (stdout);
}


/**
 * Fully initialize the raw socket.
 *
 * @return -1 on error, 0 on success
 */
static int
setup_raw_socket ()
{
  const int one = 1;

  if (-1 ==
      setsockopt (rawsock, SOL_SOCKET, SO_BROADCAST, (char *) &one, sizeof (one)))
  {
    fprintf (stderr, "setsockopt failed: %s\n", strerror (errno));
    return -1;
  }
  if (-1 ==
      setsockopt (rawsock, IPPROTO_IP, IP_HDRINCL, (char *) &one, sizeof (one)))
  {
    fprintf (stderr, "setsockopt failed: %s\n", strerror (errno));
    return -1;
  }
  return 0;
}


/**
 * Create a UDP socket for writing.
 *
 * @param my_ip source address (our ip address)
 * @return -1 on error
 */
static int
make_udp_socket (const struct in_addr *my_ip)
{
  int ret;
  struct sockaddr_in addr;

  ret = socket (AF_INET, SOCK_DGRAM, 0);
  if (-1 == ret)
  {
    fprintf (stderr, "Error opening UDP socket: %s\n", strerror (errno));
    return -1;
  }
  memset (&addr, 0, sizeof (addr));
  addr.sin_family = AF_INET;
#if HAVE_SOCKADDR_IN_SIN_LEN
  addr.sin_len = sizeof (struct sockaddr_in);
#endif
  addr.sin_addr = *my_ip;
  addr.sin_port = htons (NAT_TRAV_PORT);

  if (0 != bind (ret, &addr, sizeof (addr)))
  {
    fprintf (stderr, "Error binding UDP socket to port %u: %s\n", NAT_TRAV_PORT,
             strerror (errno));
    (void) close (ret);
    return -1;
  }
  return ret;
}


int
main (int argc, char *const *argv)
{
  struct in_addr external;
  fd_set rs;
  struct timeval tv;
  uid_t uid;
  unsigned int alt;
  int icmp_eno;
  int raw_eno;
  int global_ret;

  /* Create an ICMP raw socket for reading (we'll check errors later) */
  icmpsock = socket (AF_INET, SOCK_RAW, IPPROTO_ICMP);
  icmp_eno = errno;

  /* Create an (ICMP) raw socket for writing (we'll check errors later) */
  rawsock = socket (AF_INET, SOCK_RAW, IPPROTO_RAW);
  raw_eno = errno;
  udpsock = -1;

  /* drop root rights */
  uid = getuid ();
#ifdef HAVE_SETRESUID
  if (0 != setresuid (uid, uid, uid))
  {
    fprintf (stderr, "Failed to setresuid: %s\n", strerror (errno));
    global_ret = 1;
    goto error_exit;
  }
#else
  if (0 != (setuid (uid) | seteuid (uid)))
  {
    fprintf (stderr, "Failed to setuid: %s\n", strerror (errno));
    global_ret = 2;
    goto error_exit;
  }
#endif

  /* Now that we run without root rights, we can do error checking... */
  if (2 != argc)
  {
    fprintf (stderr,
             "This program must be started with our (internal NAT) IP as the only argument.\n");
    global_ret = 3;
    goto error_exit;
  }
  if (1 != inet_pton (AF_INET, argv[1], &external))
  {
    fprintf (stderr, "Error parsing IPv4 address: %s\n", strerror (errno));
    global_ret = 4;
    goto error_exit;
  }
  if (1 != inet_pton (AF_INET, DUMMY_IP, &dummy))
  {
    fprintf (stderr, "Internal error converting dummy IP to binary.\n");
    global_ret = 5;
    goto error_exit;
  }

  /* error checking icmpsock */
  if (-1 == icmpsock)
  {
    fprintf (stderr, "Error opening RAW socket: %s\n", strerror (icmp_eno));
    global_ret = 6;
    goto error_exit;
  }
  if (icmpsock >= FD_SETSIZE)
  {
    /* this could happen if we were started with a large number of already-open
       file descriptors... */
    fprintf (stderr, "Socket number too large (%d > %u)\n", icmpsock,
             (unsigned int) FD_SETSIZE);
    global_ret = 7;
    goto error_exit;
  }

  /* error checking rawsock */
  if (-1 == rawsock)
  {
    fprintf (stderr, "Error opening RAW socket: %s\n", strerror (raw_eno));
    global_ret = 8;
    goto error_exit;
  }
  /* no need to check 'rawsock' against FD_SETSIZE as it is never used
     with 'select' */

  if (0 != setup_raw_socket ())
  {
    global_ret = 9;
    goto error_exit;
  }

  if (-1 == (udpsock = make_udp_socket (&external)))
  {
    global_ret = 10;
    goto error_exit;
  }

  alt = 0;
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
    if (1 == getppid ())        /* Check the parent process id, if 1 the parent has died, so we should die too */
      break;
    if (FD_ISSET (icmpsock, &rs))
      process_icmp_response ();
    if (0 == (++alt % 2))
      send_icmp_echo (&external);
    else
      send_udp ();
  }

  /* select failed (internal error or OS out of resources) */
  global_ret = 11; 
error_exit:
  if (-1 != icmpsock)
    (void) close (icmpsock);
  if (-1 != rawsock)
    (void) close (rawsock);
  if (-1 != udpsock)
    (void) close (udpsock);
  return global_ret;
}


/* end of gnunet-helper-nat-server.c */

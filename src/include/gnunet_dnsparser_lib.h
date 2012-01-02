/*
      This file is part of GNUnet
      (C) 2010, 2011, 2012 Christian Grothoff (and other contributing authors)

      GNUnet is free software; you can redistribute it and/or modify
      it under the terms of the GNU General Public License as published
      by the Free Software Foundation; either version 2, or (at your
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
 * @file include/gnunet_dnsparse_lib.h
 * @brief API for helper library to parse DNS packets. 
 * @author Philipp Toelke
 */
#ifndef GNUNET_DNSPARSER_LIB_H
#define GNUNET_DNSPARSER_LIB_H

#include "platform.h"
#include "gnunet_common.h"

/**
 * A few common DNS types.
 */
#define GNUNET_DNS_TYPE_A 1
#define GNUNET_DNS_TYPE_NS 2
#define GNUNET_DNS_TYPE_CNAME 5
#define GNUNET_DNS_TYPE_SOA 6
#define GNUNET_DNS_TYPE_PTR 12
#define GNUNET_DNS_TYPE_MX 15
#define GNUNET_DNS_TYPE_TXT 16
#define GNUNET_DNS_TYPE_AAAA 28
#define GNUNET_DNS_TYPE_IXFR 251
#define GNUNET_DNS_TYPE_AXFR 252

/**
 * A few common DNS classes (ok, only one is common, but I list a
 * couple more to make it clear what we're talking about here).
 */
#define GNUNET_DNS_CLASS_INTERNET 1
#define GNUNET_DNS_CLASS_CHAOS 3
#define GNUNET_DNS_CLASS_HESIOD 4


// DNS-Stuff
GNUNET_NETWORK_STRUCT_BEGIN

struct dns_static
{
  uint16_t id GNUNET_PACKED;

  unsigned rd:1 GNUNET_PACKED;  // recursion desired (client -> server)
  unsigned tc:1 GNUNET_PACKED;  // message is truncated
  unsigned aa:1 GNUNET_PACKED;  // authoritative answer
  unsigned op:4 GNUNET_PACKED;  // query:0, inverse q.:1, status: 2
  unsigned qr:1 GNUNET_PACKED;  // query:0, response:1

  unsigned rcode:4 GNUNET_PACKED;       // 0 No error
  // 1 Format error
  // 2 Server failure
  // 3 Name Error
  // 4 Not Implemented
  // 5 Refused
  unsigned z:3 GNUNET_PACKED;   // reserved
  unsigned ra:1 GNUNET_PACKED;  // recursion available (server -> client)

  uint16_t qdcount GNUNET_PACKED;       // number of questions
  uint16_t ancount GNUNET_PACKED;       // number of answers
  uint16_t nscount GNUNET_PACKED;       // number of authority-records
  uint16_t arcount GNUNET_PACKED;       // number of additional records
};
GNUNET_NETWORK_STRUCT_END

struct dns_pkt
{
  struct dns_static s;
  unsigned char data[1];
};

struct dns_pkt_parsed
{
  struct dns_static s;
  struct dns_query **queries;
  struct dns_record **answers;
  struct dns_record **nameservers;
  struct dns_record **additional;
};

struct dns_query_line
{
  uint16_t type;
  uint16_t class;
};

struct dns_query
{
  char *name;
  unsigned char namelen;
  uint16_t qtype;
  uint16_t qclass;
};

struct dns_record_line
{
  uint16_t type;
  uint16_t class;
  uint32_t ttl;
  uint16_t data_len;
  unsigned char data;
};

struct dns_record
{
  char *name;
  unsigned char namelen;
  uint16_t type;
  uint16_t class;
  uint32_t ttl;
  uint16_t data_len;
  unsigned char *data;
};


struct dns_pkt_parsed *
parse_dns_packet (struct dns_pkt *pkt);

struct dns_pkt *
unparse_dns_packet (struct dns_pkt_parsed *pkt);

void
free_parsed_dns_packet (struct dns_pkt_parsed *ppkt);

#endif

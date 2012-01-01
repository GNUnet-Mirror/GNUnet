#ifndef _GNVPN_DNSP_H_
#define _GNVPN_DNSP_H_

#include "platform.h"
#include "gnunet_common.h"

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
  unsigned short type;
  unsigned short class;
};

struct dns_query
{
  char *name;
  unsigned char namelen;
  unsigned short qtype;
  unsigned short qclass;
};

struct dns_record_line
{
  unsigned short type;
  unsigned short class;
  unsigned int ttl;
  unsigned short data_len;
  unsigned char data;
};

struct dns_record
{
  char *name;
  unsigned char namelen;
  unsigned short type;
  unsigned short class;
  unsigned int ttl;
  unsigned short data_len;
  unsigned char *data;
};


struct dns_pkt_parsed *
parse_dns_packet (struct dns_pkt *pkt);

struct dns_pkt *
unparse_dns_packet (struct dns_pkt_parsed *pkt);

void
free_parsed_dns_packet (struct dns_pkt_parsed *ppkt);

#endif

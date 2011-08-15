#ifndef _GNTUN_PACKET_H_
#define _GNTUN_PACKET_H_

#include "platform.h"
#include "gnunet_common.h"

// Headers
struct pkt_tun
{
  unsigned flags:16 GNUNET_PACKED;
  unsigned type:16 GNUNET_PACKED;
};

struct ip6_hdr
{
  unsigned tclass_h:4 GNUNET_PACKED;
  unsigned version:4 GNUNET_PACKED;
  unsigned tclass_l:4 GNUNET_PACKED;
  unsigned flowlbl:20 GNUNET_PACKED;
  unsigned paylgth:16 GNUNET_PACKED;
  unsigned nxthdr:8 GNUNET_PACKED;
  unsigned hoplmt:8 GNUNET_PACKED;
  unsigned char sadr[16];
  unsigned char dadr[16];
};

struct ip_hdr
{
  unsigned hdr_lngth:4 GNUNET_PACKED;
  unsigned version:4 GNUNET_PACKED;

  unsigned diff_serv:8 GNUNET_PACKED;
  unsigned tot_lngth:16 GNUNET_PACKED;

  unsigned ident:16 GNUNET_PACKED;
  unsigned flags:3 GNUNET_PACKED;
  unsigned frag_off:13 GNUNET_PACKED;

  unsigned ttl:8 GNUNET_PACKED;
  unsigned proto:8 GNUNET_PACKED;
  unsigned chks:16 GNUNET_PACKED;

  unsigned sadr:32 GNUNET_PACKED;
  unsigned dadr:32 GNUNET_PACKED;
};

#define TCP_FLAG_SYN 2

struct tcp_pkt
{
  unsigned spt:16 GNUNET_PACKED;
  unsigned dpt:16 GNUNET_PACKED;
  unsigned seq:32 GNUNET_PACKED;
  unsigned ack:32 GNUNET_PACKED;
  unsigned off:4 GNUNET_PACKED;
  unsigned rsv:4 GNUNET_PACKED;
  unsigned flg:8 GNUNET_PACKED;
  unsigned wsz:16 GNUNET_PACKED;
  unsigned crc:16 GNUNET_PACKED;
  unsigned urg:16 GNUNET_PACKED;
};

struct udp_pkt
{
  unsigned spt:16 GNUNET_PACKED;
  unsigned dpt:16 GNUNET_PACKED;
  unsigned len:16 GNUNET_PACKED;
  unsigned crc:16 GNUNET_PACKED;
};

struct icmp_hdr
{
  unsigned type:8 GNUNET_PACKED;
  unsigned code:8 GNUNET_PACKED;
  unsigned chks:16 GNUNET_PACKED;
};

// DNS-Stuff
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

struct udp_dns
{
  struct udp_pkt udp_hdr;
  struct dns_pkt data;
};

// Complete Packets
struct tun_pkt
{
  struct GNUNET_MessageHeader shdr;
  struct pkt_tun tun;
};

struct ip6_pkt
{
  struct GNUNET_MessageHeader shdr;
  struct pkt_tun tun;
  struct ip6_hdr ip6_hdr;
  unsigned char data[1];
};

struct ip6_tcp
{
  struct GNUNET_MessageHeader shdr;
  struct pkt_tun tun;
  struct ip6_hdr ip6_hdr;
  struct tcp_pkt tcp_hdr;
  unsigned char data[1];
};

struct ip6_icmp
{
  struct GNUNET_MessageHeader shdr;
  struct pkt_tun tun;
  struct ip6_hdr ip6_hdr;
  struct icmp_hdr icmp_hdr;
};

struct ip6_udp
{
  struct GNUNET_MessageHeader shdr;
  struct pkt_tun tun;
  struct ip6_hdr ip6_hdr;
  struct udp_pkt udp_hdr;
  unsigned char data[1];
};

struct ip6_udp_dns
{
  struct GNUNET_MessageHeader shdr;
  struct pkt_tun tun;
  struct ip6_hdr ip6_hdr;
  struct udp_dns udp_dns;
};

struct ip_pkt
{
  struct GNUNET_MessageHeader shdr;
  struct pkt_tun tun;
  struct ip_hdr ip_hdr;
  unsigned char data[1];
};

struct ip_udp
{
  struct GNUNET_MessageHeader shdr;
  struct pkt_tun tun;
  struct ip_hdr ip_hdr;
  struct udp_pkt udp_hdr;
  unsigned char data[1];
};

struct ip_udp_dns
{
  struct GNUNET_MessageHeader shdr;
  struct pkt_tun tun;
  struct ip_hdr ip_hdr;
  struct udp_dns udp_dns;
};

struct ip_tcp
{
  struct GNUNET_MessageHeader shdr;
  struct pkt_tun tun;
  struct ip_hdr ip_hdr;
  struct tcp_pkt tcp_hdr;
  unsigned char data[1];
};

struct ip_icmp
{
  struct GNUNET_MessageHeader shdr;
  struct pkt_tun tun;
  struct ip_hdr ip_hdr;
  struct icmp_hdr icmp_hdr;
};

#endif

#ifndef _GNTUN_PACKET_H_
#define _GNTUN_PACKET_H_

#include "platform.h"
#include "gnunet_common.h"
#include "gnunet-dns-parser.h"

GNUNET_NETWORK_STRUCT_BEGIN

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

  uint32_t sadr GNUNET_PACKED;
  uint32_t dadr GNUNET_PACKED;
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
GNUNET_NETWORK_STRUCT_END


struct udp_dns
{
  struct udp_pkt udp_hdr;
  struct dns_pkt data;
};

GNUNET_NETWORK_STRUCT_BEGIN

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
GNUNET_NETWORK_STRUCT_END

#endif

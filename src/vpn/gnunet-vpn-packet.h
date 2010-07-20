#ifndef _GNTUN_PACKET_H_
#define _GNTUN_PACKET_H_

#include "gnunet-vpn-helper-p.h"
#include "gnunet_common.h"

// Headers
struct pkt_tun {
	unsigned flags:16;
	unsigned type:16;
};

struct ip6_hdr {
	unsigned version:4;
	unsigned tclass:8;
	unsigned flowlbl:20;
	unsigned paylgth:16;
	unsigned nxthdr:8;
	unsigned hoplmt:8;
	unsigned char sadr[16];
	unsigned char dadr[16];
};

struct tcp_pkt {
	unsigned spt:16;
	unsigned dpt:16;
	unsigned seq:32;
	unsigned ack:32;
	unsigned off:4;
	unsigned rsv:4;
	unsigned flg:8;
	unsigned wsz:16;
	unsigned crc:16;
	unsigned urg:16;
};

struct udp_pkt {
	unsigned spt:16;
	unsigned dpt:16;
	unsigned len:16;
	unsigned crc:16;
};

// DNS-Stuff
struct dns_pkt {
	unsigned short id;

	unsigned rd:1; // recursion desired (client -> server)
	unsigned tc:1; // message is truncated
	unsigned aa:1; // authoritative answer
	unsigned op:4; // query:0, inverse q.:1, status: 2
	unsigned qr:1; // query:0, response:1

	unsigned rcode:4; // 0 No error
	                  // 1 Format error
	                  // 2 Server failure
	                  // 3 Name Error
	                  // 4 Not Implemented
	                  // 5 Refused
	unsigned z:3;  // reserved
	unsigned ra:1; // recursion available (server -> client)

	unsigned short qdcount; // number of questions
	unsigned short ancount; // number of answers
	unsigned short nscount; // number of authority-records
	unsigned short arcount; // number of additional records
	unsigned char data[1];
};

struct dns_query {
	unsigned char* name;
	unsigned short qtype;
	unsigned short qclass;
};

struct dns_record {
	unsigned char* name;
	unsigned short type;
	unsigned short class;
	unsigned int ttl;
	unsigned short data_len;
	unsigned char* data;
};

// Complete Packets
struct ip6_pkt {
	struct GNUNET_MessageHeader shdr;
	struct pkt_tun tun;
	struct ip6_hdr ip6_hdr;
	unsigned char data[1];
};

struct ip6_tcp {
	struct GNUNET_MessageHeader shdr;
	struct pkt_tun tun;
	struct ip6_hdr ip6_hdr;
	struct tcp_pkt tcp_hdr;
	unsigned char data[1];
};

struct ip6_udp {
	struct GNUNET_MessageHeader shdr;
	struct pkt_tun tun;
	struct ip6_hdr ip6_hdr;
	struct udp_pkt udp_hdr;
	unsigned char data[1];
};

struct ip6_udp_dns {
	struct GNUNET_MessageHeader shdr;
	struct pkt_tun tun;
	struct ip6_hdr ip6_hdr;
	struct udp_pkt udp_hdr;
	struct dns_pkt data;
};

#endif

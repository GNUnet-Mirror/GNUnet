#ifndef _GNTUN_PACKET_H_
#define _GNTUN_PACKET_H_

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
	unsigned char data[1];
};

struct udp_pkt {
	unsigned spt:16;
	unsigned dpt:16;
	unsigned len:16;
	unsigned crc:16;
};

struct dns_pkt {
	unsigned id:16;
	unsigned qr:1; // query:0, response:1
	unsigned op:4; // query:0, inverse q.:1, status: 2
	unsigned aa:1; // authoritative answer
	unsigned tc:1; // message is truncated
	unsigned rd:1; // recursion desired (client -> server)
	unsigned ra:1; // recursion available (server -> client)
	unsigned z:2;  // reserved
	unsigned a:1;  // answer is signed by server
	unsigned rcode:4; // 0 No error
	                  // 1 Format error
	                  // 2 Server failure
	                  // 3 Name Error
	                  // 4 Not Implemented
	                  // 5 Refused
	unsigned qdcount:16; // number of questions
	unsigned ancount:16; // number of answers
	unsigned nscount:16; // number of authority-records
	unsigned arcount:16; // number of additional records
	unsigned char data[1];
};

struct ip6_pkt {
	struct pkt_tun tun;
	struct ip6_hdr hdr;
	unsigned char data[1];
};

struct ip6_tcp {
	struct pkt_tun tun;
	struct ip6_hdr hdr;
	struct tcp_pkt data;
};

struct ip6_udp {
	struct pkt_tun tun;
	struct ip6_hdr hdr;
	struct udp_pkt data;
};

void send_pkt(int fd, struct ip6_pkt* pkt);
int recv_ipv6pkt(int fd, struct pkt_tun** pkt);
int recv_pkt(int fd, struct pkt_tun** pkt);
struct ip6_pkt* parse_ip6(struct pkt_tun* pkt);

struct ip6_tcp* parse_ip6_tcp(struct ip6_pkt*);
struct ip6_udp* parse_ip6_udp(struct ip6_pkt*);

short payload(struct ip6_hdr* pkt);

#endif

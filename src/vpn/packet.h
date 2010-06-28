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

extern void send_pkt(int fd, struct ip6_pkt* pkt);
extern int recv_ipv6pkt(int fd, struct pkt_tun** pkt);
extern int recv_pkt(int fd, struct pkt_tun** pkt);
extern struct ip6_pkt* parse_ip6(struct pkt_tun* pkt);

extern struct ip6_tcp* parse_ip6_tcp(struct ip6_pkt*);

extern short payload(struct ip6_hdr* pkt);

#endif

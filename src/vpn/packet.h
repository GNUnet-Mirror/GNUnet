#ifndef _GNTUN_PACKET_H_
#define _GNTUN_PACKET_H_

struct pkt_tun {
	unsigned char flags[2];
	unsigned char type[2];

	unsigned char* data;
};

struct ip6_pkt {
	unsigned char tclass;
	unsigned char flowlbl[3];
	unsigned char paylgth[2];
	unsigned char nxthdr;
	unsigned char hoplmt;
	unsigned char sadr[16];
	unsigned char dadr[16];

	unsigned char* data;
};

extern void send_pkt(int fd, struct ip6_pkt* pkt);
extern int recv_ipv6pkt(int fd, struct pkt_tun** pkt, unsigned char*);
extern int recv_pkt(int fd, struct pkt_tun** pkt);
extern struct ip6_pkt* parse_ip6(struct pkt_tun* pkt);
extern void pkt_printf(struct ip6_pkt* pkt);

#endif

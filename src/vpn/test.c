#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <string.h>

#include <linux/if.h>

#include "packet.h"
#include "tun.h"
#include "debug.h"
#include "pretty-print.h"
#include "tcp.h"
#include "udp.h"
#include <arpa/inet.h>


int main(int c, char** v) {
	char dev[IFNAMSIZ];
	memset(dev, 0, IFNAMSIZ);
	int fd = init_tun(dev);

	debug(1, 0, "Initialized the interface %s.\n", dev);

	struct pkt_tun* pkt;

	for(;;) {
		printf("read %d bytes from socket, ", recv_pkt(fd, &pkt));
		switch (ntohs(pkt->type)) {
			case 0x86dd:
				printf("parsing ipv6:\n");
				struct ip6_pkt* pkt6 = parse_ip6(pkt);
				pkt_printf(pkt6);
				struct ip6_tcp* pkt6_tcp;
				struct ip6_udp* pkt6_udp;
				switch(pkt6->hdr.nxthdr) {
					case 0x06:
						pkt6_tcp = parse_ip6_tcp(pkt6);
						pkt_printf_ip6tcp(pkt6_tcp);
						handle_tcp(pkt6_tcp);
						break;
					case 0x11:
						pkt6_udp = parse_ip6_udp(pkt6);
						pkt_printf_ip6udp(pkt6_udp);
						handle_udp(pkt6_udp);
						break;
				}
				break;
			default:
				printf("unknown/unimplemented packet-type\n");
				break;
		}
	}
}

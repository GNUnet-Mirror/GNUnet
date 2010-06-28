#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>

#include <linux/if.h>

#include "packet.h"
#include "tun.h"
#include "debug.h"

int main(int c, char** v) {
	//char* dev = (char*) malloc(IFNAMSIZ);
	char dev[IFNAMSIZ];
	int fd = init_tun(dev);

	debug(1, 0, "Initialized the interface %s.\n", dev);

	struct pkt_tun* pkt;

	for(;;) {
		printf("read %d bytes from socket, ", recv_pkt(fd, &pkt));
		switch (pkt->type[0] << 8 | pkt->type[1]) {
			case 0x86dd:
				printf("parsing ipv6:\n");
				struct ip6_pkt* pkt6 = parse_ip6(pkt);
				pkt_printf(pkt6);
				break;
			default:
				printf("unknown/unimplemented packet-type\n");
				break;
		}
	}
}

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/uio.h>

#include <linux/if_tun.h>

#include "debug.h"
#include "packet.h"
#include "arpa/inet.h"

short payload(struct ip6_hdr* hdr) {{{
	return ntohs(hdr->paylgth);
}}}

void send_pkt(int fd, struct ip6_pkt* pkt) {{{
	int sz = payload(&(pkt->hdr));
	int w = 0;
	char* buf = (char*)pkt;

	w = 0;
	while ( w > 0) {
		int t = write(fd, buf+w, (sz + 40) - w);
		if (t < 0)
			debug(1, 0, "packet: write : %s\n", strerror(errno));
		else
			w+=t;
	}

	free(buf);
}}}

int recv_pkt(int fd, struct pkt_tun** pkt) {{{
	int size = 1504;
	unsigned char data[size];

	debug(1, 0, "beginning to read...\n");

	int r = read(fd, data, size);
	debug(1, 0, "read %d bytes\n", r);

	*pkt = (struct pkt_tun*)malloc(r);

	int r = r > size ? size : r;
	memcpy(*pkt, data, r);
	struct pkt_tun *_pkt = *pkt;

	debug(1, 0, "read the flags: %04x\n", ntohs(_pkt->flags));
	debug(1, 0, "read the type: %04x\n", ntohs(_pkt->type));

	switch(ntohs(_pkt->type)) {
		case 0x86dd:
			debug(1, 0, "reading an ipv6-packet\n");
			struct ip6_pkt * pkt6 = (struct ip6_pkt*) *pkt;
			size = payload(&(pkt6->hdr));
			debug(1, 0, "read the size: %d\n", size);
			return size;
			break;
		case 0x0800:
			debug(1, 0, "unknown pkt-type: IPv4\n");
			//IPv4 TODO
			break;
		default:
			debug(1, 0, "unknown pkt-type: 0x%02x\n", 0x800);
			//Whatever TODO
			break;
	}
	return -1;
}}}

struct ip6_pkt* parse_ip6(struct pkt_tun* pkt) {{{
	struct ip6_pkt* pkt6 = (struct ip6_pkt*)pkt;

	return pkt6;
}}}

struct ip6_tcp* parse_ip6_tcp(struct ip6_pkt* pkt) {{{
	struct ip6_tcp* res = (struct ip6_tcp*) pkt;

	return res;
}}}

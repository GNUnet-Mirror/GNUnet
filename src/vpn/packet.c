#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/uio.h>

#include <linux/if_tun.h>

#include "debug.h"
#include "packet.h"

long payload(struct ip6_hdr* hdr) {{{
	return (hdr->paylgth[0] << 8) + hdr->paylgth[1];
}}}

void send_pkt(int fd, struct ip6_pkt* pkt) {{{
	int sz = payload(&(pkt->hdr));
	int w = 0;
	char* buf = (char*)malloc(sz+40);

	buf[0] = (6 << 4) | (pkt->hdr.tclass >> 4);
	buf[1] = (pkt->hdr.tclass << 4) | (pkt->hdr.flowlbl[0] >> 4);
	buf[2] = pkt->hdr.flowlbl[1];
	buf[3] = pkt->hdr.flowlbl[2];
	buf[4] = pkt->hdr.paylgth[0];
	buf[5] = pkt->hdr.paylgth[1];
	buf[6] = pkt->hdr.nxthdr;
	buf[7] = pkt->hdr.hoplmt;

	for (w = 0; w < 16; w++) {
		buf[8+w] = pkt->hdr.sadr[w];
		buf[24+w] = pkt->hdr.dadr[w];
	}

	memcpy(buf+40, pkt->data, sz);

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

int recv_ipv6pkt(int fd, struct pkt_tun** pkt, unsigned char* data) {{{
	int size = (data[4] << 8) + data[5] + 40;

	debug(1, 0, "read the size: %d\n", size);

	(*pkt)->data = (unsigned char*)malloc(size);

	memcpy((*pkt)->data, data, size);

	return size;
}}}

int recv_pkt(int fd, struct pkt_tun** pkt) {{{
	struct pkt_tun* _pkt = (struct pkt_tun*)malloc(sizeof(struct pkt_tun));
	*pkt = _pkt;

	unsigned char data[1500];
	unsigned char buf[4];

	struct iovec vect[2];
	vect[0].iov_len = sizeof(struct tun_pi);
	vect[0].iov_base = &buf;
	vect[1].iov_len = 1500;
	vect[1].iov_base = data;

	int r = 0;

	debug(1, 0, "beginning to read...\n");

	r = readv(fd, vect, 2);

	_pkt->flags[0] = buf[0];
	_pkt->flags[1] = buf[1];
	_pkt->type[0] = buf[2];
	_pkt->type[1] = buf[3];

	debug(1, 0, "read the flags: %02x%02x\n", _pkt->flags[0], _pkt->flags[1]);
	debug(1, 0, "read the type: %02x%02x\n", _pkt->type[0], _pkt->type[1]);

	switch((_pkt->type[0] << 8) + _pkt->type[1]) {
		case 0x86dd:
			return recv_ipv6pkt(fd, pkt, data);
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
	struct ip6_pkt* pkt6 = (struct ip6_pkt*)malloc(sizeof(struct ip6_pkt));

	pkt6->hdr.tclass = pkt->data[0] << 4 | pkt->data[1] >> 4;
	pkt6->hdr.flowlbl[0] = pkt->data[1]>>4;
	pkt6->hdr.flowlbl[1] = pkt->data[2];
	pkt6->hdr.flowlbl[2] = pkt->data[3];

	pkt6->hdr.paylgth[0] = pkt->data[4];
	pkt6->hdr.paylgth[1] = pkt->data[5];

	pkt6->hdr.nxthdr = pkt->data[6];
	pkt6->hdr.hoplmt = pkt->data[7];

	for (int w = 0; w < 16; w++) {
		pkt6->hdr.sadr[w] = pkt->data[8+w];
		pkt6->hdr.dadr[w] = pkt->data[24+w];
	}

	pkt6->data = (unsigned char*)malloc(payload(&(pkt6->hdr)));
	memcpy(pkt6->data, pkt->data+40, payload(&(pkt6->hdr)));

	return pkt6;
}}}

struct ip6_tcp* parse_ip6_tcp(struct ip6_pkt* pkt) {{{
	struct ip6_tcp* res = (struct ip6_tcp*) malloc(sizeof(struct ip6_tcp));
	memcpy(&(res->hdr), &(pkt->hdr), sizeof(struct ip6_hdr));
	
	res->data.spt = (pkt->data[0] << 8) | pkt->data[1];
	res->data.dpt = (pkt->data[2] << 8) | pkt->data[3];

	res->data.seq = (pkt->data[4] << 24) | (pkt->data[5] << 16) | (pkt->data[6] << 8) | pkt->data[7];
	res->data.ack = (pkt->data[8] << 24) | (pkt->data[9] << 16) | (pkt->data[10] << 8) | pkt->data[11];

	res->data.off = pkt->data[12] >> 4;
	res->data.rsv = pkt->data[12] & 0xF;

	res->data.flg = pkt->data[13];

	res->data.wsz = (pkt->data[14] << 8) | pkt->data[15];

	res->data.crc = (pkt->data[16] << 8) | pkt->data[17];

	res->data.urg = (pkt->data[18] << 8) | pkt->data[19];

	res->data.opt = (unsigned char*) malloc((res->data.off - 5)*4);
	memcpy(res->data.opt, pkt->data+20, (res->data.off - 5)*4);

	res->data.data = (unsigned char*) malloc(payload(&(pkt->hdr)) - 4*(res->data.off));
	memcpy(res->data.data, pkt->data+4*(res->data.off), payload(&(pkt->hdr)) - 4*(res->data.off));

	return res;
}}}

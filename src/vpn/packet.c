#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/uio.h>

#include <linux/if_tun.h>

#include "debug.h"
#include "packet.h"

static long payload(struct ip6_pkt* pkt) {
	return (pkt->paylgth[0] << 8) + pkt->paylgth[1];
}

static char* pretty = /*{{{*/
/*     0       1         2         3         4        5          6
 0123456789012345678901234567890123456789012345678901234567890123456789 */
"IPv6-Paket from xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx    \n" //60
"             to xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx    \n" //120
"        flow    0xXXX (        )                           \n" //180
"        length  0xXX  (   )                                \n" //240
"        nexthdr 0xXX  (                                    \n" //300
"        hoplmt  0xXX  (   )                                \n" //360
"first 128 bytes of payload:                                \n" //420
/*     0       1         2         3         4        5          6
 0123456789012345678901234567890123456789012345678901234567890123456789 */
"XX XX XX XX XX XX XX XX  XX XX XX XX XX XX XX XX | ................  \n" //490
"XX XX XX XX XX XX XX XX  XX XX XX XX XX XX XX XX | ................  \n" //560
"XX XX XX XX XX XX XX XX  XX XX XX XX XX XX XX XX | ................  \n" //630
"XX XX XX XX XX XX XX XX  XX XX XX XX XX XX XX XX | ................  \n" //700
"XX XX XX XX XX XX XX XX  XX XX XX XX XX XX XX XX | ................  \n" //770
"XX XX XX XX XX XX XX XX  XX XX XX XX XX XX XX XX | ................  \n" //840
"XX XX XX XX XX XX XX XX  XX XX XX XX XX XX XX XX | ................  \n" //910
"XX XX XX XX XX XX XX XX  XX XX XX XX XX XX XX XX | ................  \n";//980
/*}}}*/

void send_pkt(int fd, struct ip6_pkt* pkt) {{{
	int sz = payload(pkt);
	int w = 0;
	char* buf = (char*)malloc(sz+40);

	buf[0] = (6 << 4) | (pkt->tclass >> 4);
	buf[1] = (pkt->tclass << 4) | (pkt->flowlbl[0] >> 4);
	buf[2] = pkt->flowlbl[1];
	buf[3] = pkt->flowlbl[2];
	buf[4] = pkt->paylgth[0];
	buf[5] = pkt->paylgth[1];
	buf[6] = pkt->nxthdr;
	buf[7] = pkt->hoplmt;

	for (w = 0; w < 16; w++) {
		buf[8+w] = pkt->sadr[w];
		buf[24+w] = pkt->dadr[w];
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

	pkt6->tclass = pkt->data[0] << 4 | pkt->data[1] >> 4;
	pkt6->flowlbl[0] = pkt->data[1]>>4;
	pkt6->flowlbl[1] = pkt->data[2];
	pkt6->flowlbl[2] = pkt->data[3];

	pkt6->paylgth[0] = pkt->data[4];
	pkt6->paylgth[1] = pkt->data[5];

	pkt6->nxthdr = pkt->data[6];
	pkt6->hoplmt = pkt->data[7];

	for (int w = 0; w < 16; w++) {
		pkt6->sadr[w] = pkt->data[8+w];
		pkt6->dadr[w] = pkt->data[24+w];
	}

	pkt6->data = (unsigned char*)malloc(payload(pkt6));
	memcpy(pkt6->data, pkt->data+40, payload(pkt6));

	return pkt6;
}}}

static void pp_ip6adr(unsigned char* adr, char* dest) {{{
	char tmp[3];

	sprintf(tmp, "%02X", adr[0]);
	memcpy(dest+0, tmp, 2);
	sprintf(tmp, "%02X", adr[1]);
	memcpy(dest+2, tmp, 2);

	sprintf(tmp, "%02X", adr[2]);
	memcpy(dest+5, tmp, 2);
	sprintf(tmp, "%02X", adr[3]);
	memcpy(dest+7, tmp, 2);

	sprintf(tmp, "%02X", adr[4]);
	memcpy(dest+10, tmp, 2);
	sprintf(tmp, "%02X", adr[5]);
	memcpy(dest+12, tmp, 2);

	sprintf(tmp, "%02X", adr[6]);
	memcpy(dest+15, tmp, 2);
	sprintf(tmp, "%02X", adr[7]);
	memcpy(dest+17, tmp, 2);

	sprintf(tmp, "%02X", adr[8]);
	memcpy(dest+20, tmp, 2);
	sprintf(tmp, "%02X", adr[9]);
	memcpy(dest+22, tmp, 2);

	sprintf(tmp, "%02X", adr[10]);
	memcpy(dest+25, tmp, 2);
	sprintf(tmp, "%02X", adr[11]);
	memcpy(dest+27, tmp, 2);

	sprintf(tmp, "%02X", adr[12]);
	memcpy(dest+30, tmp, 2);
	sprintf(tmp, "%02X", adr[13]);
	memcpy(dest+32, tmp, 2);

	sprintf(tmp, "%02X", adr[14]);
	memcpy(dest+35, tmp, 2);
	sprintf(tmp, "%02X", adr[15]);
	memcpy(dest+37, tmp, 2);
}}}

void pp_hexdump(unsigned char* data, char* dest, int max) {{{
	char tmp[3];
	char tmp2[2];
	int off = 0;
	int to = max > 16 ? 16 : max;
	for (int i = 0; i < to; i++) {
		if (i == 8) off = 1;
		sprintf(tmp, "%02x", data[i]);
		memcpy(dest+(3*i)+off, tmp, 2);
		if (isprint(data[i])) {
			sprintf(tmp2, "%c", data[i]);
			memcpy(dest+51+i, tmp2, 1);
		}
	}
}}}

void pp_write_header(char* dest, struct ip6_pkt* pkt) {
	switch (pkt->nxthdr) {
		case 0x3a:
			memcpy(dest, "ICMPv6)", 7);
			break;
		default:
			memcpy(dest, "unknown)", 8);
			break;
	}
}

void pkt_printf(struct ip6_pkt* pkt) {
	char* buf = (char*)malloc(strlen(pretty)+1);
	char tmp[9];

	memcpy(buf, pretty, strlen(pretty)+1);

	pp_ip6adr(pkt->sadr, buf+16);
	pp_ip6adr(pkt->dadr, buf+76);

	int flow = (pkt->flowlbl[0] << 16) + (pkt->flowlbl[1] << 8) + (pkt->flowlbl[2]);
	sprintf(tmp, "%03x", flow);
	memcpy(buf+138, tmp, 3);
	sprintf(tmp, "%-8d", flow);
	memcpy(buf+143, tmp, 8);

	int length = (pkt->paylgth[0] << 8) + (pkt->paylgth[1]);
	sprintf(tmp, "%02x", length);
	memcpy(buf+198, tmp, 2);
	sprintf(tmp, "%-3d", length);
	memcpy(buf+203, tmp, 3);

	sprintf(tmp, "%02x", pkt->nxthdr);
	memcpy(buf+258, tmp, 2);
	pp_write_header(buf+263, pkt);

	sprintf(tmp, "%02x", pkt->hoplmt);
	memcpy(buf+318, tmp, 2);
	sprintf(tmp, "%-3d", pkt->hoplmt);
	memcpy(buf+323, tmp, 3);

	int size = payload(pkt);
	for(int i = 0; i < 8; i++) {
		if (16*i > size) break;
		pp_hexdump(pkt->data + (16*i), buf + 420 + (i*70), size - 16*i);
	}

	printf(buf);
	free(buf);
}

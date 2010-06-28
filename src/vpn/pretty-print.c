#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <arpa/inet.h>

#include "packet.h"

static char* pretty = /*{{{*/
/*     0       1         2         3         4        5          6
 0123456789012345678901234567890123456789012345678901234567890123456789 */
"IPv6-Paket from xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx    \n" //60
"             to xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx    \n" //120
/*     0       1         2         3         4        5          6
 0123456789012345678901234567890123456789012345678901234567890123456789 */
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

void pp_write_header(char* dest, struct ip6_pkt* pkt) {{{
	switch (pkt->hdr.nxthdr) {
		case 0x3a:
			memcpy(dest, "ICMPv6)", 7);
			break;
		case 0x06:
			memcpy(dest, "TCP)", 4);
			break;
		case 0x11:
			memcpy(dest, "UDP)", 4);
			break;
		default:
			memcpy(dest, "unknown)", 8);
			break;
	}
}}}

void pkt_printf(struct ip6_pkt* pkt) {{{
	char* buf = (char*)malloc(strlen(pretty)+1);
	char tmp[9];

	memcpy(buf, pretty, strlen(pretty)+1);

	pp_ip6adr(pkt->hdr.sadr, buf+16);
	pp_ip6adr(pkt->hdr.dadr, buf+76);

	int flow = (ntohl(pkt->hdr.flowlbl));
	sprintf(tmp, "%03x", flow);
	memcpy(buf+138, tmp, 3);
	sprintf(tmp, "%-8d", flow);
	memcpy(buf+143, tmp, 8);

	int length = ntohs(pkt->hdr.paylgth);
	sprintf(tmp, "%02x", length);
	memcpy(buf+198, tmp, 2);
	sprintf(tmp, "%-3d", length);
	memcpy(buf+203, tmp, 3);

	sprintf(tmp, "%02x", pkt->hdr.nxthdr);
	memcpy(buf+258, tmp, 2);
	pp_write_header(buf+263, pkt);

	sprintf(tmp, "%02x", pkt->hdr.hoplmt);
	memcpy(buf+318, tmp, 2);
	sprintf(tmp, "%-3d", pkt->hdr.hoplmt);
	memcpy(buf+323, tmp, 3);

	int size = payload(&pkt->hdr);
	for(int i = 0; i < 8; i++) {
		if (16*i > size) break;
		pp_hexdump(pkt->data + (16*i), buf + 420 + (i*70), size - 16*i);
	}

	printf(buf);
	free(buf);
}}}

void pkt_printf_ip6tcp(struct ip6_tcp* pkt) {{{
	printf("spt: %u\n", ntohs(pkt->data.spt));
	printf("dpt: %u\n", ntohs(pkt->data.dpt));
	printf("seq: %u\n", ntohs(pkt->data.seq));
	printf("ack: %u\n", ntohs(pkt->data.ack));
	printf("off: %u\n", ntohs(pkt->data.off));
	printf("wsz: %u\n", ntohs(pkt->data.wsz));
	printf("crc: 0x%x\n", ntohs(pkt->data.crc));
	printf("urg: %u\n", ntohs(pkt->data.urg));
	printf("flags: %c%c%c%c%c%c%c%c\n",
			pkt->data.flg & 0x80 ? 'C' : '.',
			pkt->data.flg & 0x40 ? 'E' : '.',
			pkt->data.flg & 0x20 ? 'U' : '.',
			pkt->data.flg & 0x10 ? 'A' : '.',
			pkt->data.flg & 0x08 ? 'P' : '.',
			pkt->data.flg & 0x04 ? 'R' : '.',
			pkt->data.flg & 0x02 ? 'S' : '.',
			pkt->data.flg & 0x01 ? 'F' : '.'
			);
}}}

void pkt_printf_ip6udp(struct ip6_udp* pkt) {{{
	printf("spt: %u\n", ntohs(pkt->data.spt));
	printf("dpt: %u\n", ntohs(pkt->data.dpt));
	printf("len: %u\n", ntohs(pkt->data.len));
	printf("crc: 0x%x\n", ntohs(pkt->data.crc));
}}}

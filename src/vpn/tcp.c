#include "debug.h"
#include "packet.h"
#include "tcp.h"

#include <errno.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <signal.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

struct le {
	int spt, dpt;

	unsigned char sadr[16];
	unsigned char dadr[16];

	int socket;

	struct le* next;
};

static struct le* le_head = 0;

static int look_for_child(struct ip6_tcp* pkt) {
	struct le* cur;

	for(cur = le_head; cur != 0; cur = cur->next) {
		if (cur->spt == pkt->data.spt &&/*{{{*/
				cur->dpt == pkt->data.spt &&
				cur->sadr[0] == pkt->hdr.sadr[0] &&
				cur->sadr[1] == pkt->hdr.sadr[1] &&
				cur->sadr[2] == pkt->hdr.sadr[2] &&
				cur->sadr[3] == pkt->hdr.sadr[3] &&
				cur->sadr[4] == pkt->hdr.sadr[4] &&
				cur->sadr[5] == pkt->hdr.sadr[5] &&
				cur->sadr[6] == pkt->hdr.sadr[6] &&
				cur->sadr[7] == pkt->hdr.sadr[7] &&
				cur->sadr[8] == pkt->hdr.sadr[8] &&
				cur->sadr[9] == pkt->hdr.sadr[9] &&
				cur->sadr[10] == pkt->hdr.sadr[10] &&
				cur->sadr[11] == pkt->hdr.sadr[11] &&
				cur->sadr[12] == pkt->hdr.sadr[12] &&
				cur->sadr[13] == pkt->hdr.sadr[13] &&
				cur->sadr[14] == pkt->hdr.sadr[14] &&
				cur->sadr[15] == pkt->hdr.sadr[15] &&

				cur->dadr[0] == pkt->hdr.dadr[0] &&
				cur->dadr[1] == pkt->hdr.dadr[1] &&
				cur->dadr[2] == pkt->hdr.dadr[2] &&
				cur->dadr[3] == pkt->hdr.dadr[3] &&
				cur->dadr[4] == pkt->hdr.dadr[4] &&
				cur->dadr[5] == pkt->hdr.dadr[5] &&
				cur->dadr[6] == pkt->hdr.dadr[6] &&
				cur->dadr[7] == pkt->hdr.dadr[7] &&
				cur->dadr[8] == pkt->hdr.dadr[8] &&
				cur->dadr[9] == pkt->hdr.dadr[9] &&
				cur->dadr[10] == pkt->hdr.dadr[10] &&
				cur->dadr[11] == pkt->hdr.dadr[11] &&
				cur->dadr[12] == pkt->hdr.dadr[12] &&
				cur->dadr[13] == pkt->hdr.dadr[13] &&
				cur->dadr[14] == pkt->hdr.dadr[14] &&
				cur->dadr[15] == pkt->hdr.dadr[15])/*}}}*/
			return cur->socket;
	}
	return -1;
}

static struct le* new_le() {{{
	struct le* res = (struct le*) malloc(sizeof(struct le));

	struct le** cur;

	for(cur = &le_head; *cur != 0; cur = &((*cur)->next)) {}

	*cur = res;

	return res;
}}}

static int nat(struct ip6_tcp* pkt) {{{
	unsigned char adr1[] = { 0x12, 0x34, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02};
	unsigned char adr2[] = { 0x12, 0x34, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03};

	if (strncmp((char*)adr1, (char*)pkt->hdr.dadr, 16)) {
		int sock = socket(AF_INET, SOCK_STREAM, 0);
		struct sockaddr_in info;
		memset(&info, 0, sizeof(info));

		info.sin_family = AF_INET;
		info.sin_port = pkt->data.dpt;
		inet_pton(AF_INET, "94.142.241.111", &info.sin_addr.s_addr);

		connect(sock, (const struct sockaddr*)&info, sizeof(info));
		return sock;
	} else if (strncmp((char*)adr2, (char*)pkt->hdr.dadr, 16)) {
		int sock = socket(AF_INET6, SOCK_STREAM, 0);

		struct sockaddr_in6 info;
		memset(&info, 0, sizeof(info));

		info.sin6_family = AF_INET6;
		info.sin6_port = pkt->data.dpt;

		inet_pton(AF_INET6, "2a02:898:17:8000::42", info.sin6_addr.s6_addr);

		connect(sock, (const struct sockaddr*)&info, sizeof(info));

		return sock;
	}
	return -1;
}}}

void handle_tcp(struct ip6_tcp* pkt) {
	signal(SIGCHLD, SIG_IGN);

	int fd = look_for_child(pkt);

	if (fd == -1) {
		struct le* le = new_le();
		le->spt = pkt->data.spt;
		le->dpt = pkt->data.dpt;

		memcpy(le->sadr, pkt->hdr.sadr, 16);
		memcpy(le->dadr, pkt->hdr.dadr, 16);

		le->socket = nat(pkt);
		fd = le->socket;
	}

	int size = payload((&pkt->hdr)) - pkt->data.off;

	int w = 0;
	while (size > 0) {
		w = write(fd, pkt->data.data, size - w);
		if (w < 0) {
			debug(1, 0, "writing: %s\n", strerror(errno));
		} else {
			size -= w;
		}
	}
}

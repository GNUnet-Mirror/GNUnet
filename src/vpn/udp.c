#include "debug.h"
#include "packet.h"
#include "udp.h"

#include "pretty-print.h"

#include <errno.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

void handle_udp(struct ip6_udp* pkt) {
	if (ntohs(pkt->data.dpt) == 53) { //TODO check for dadr, too
		pkt_printf_ip6dns((struct ip6_udp_dns*)pkt);
		return;
	}
}

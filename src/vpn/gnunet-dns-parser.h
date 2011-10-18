#ifndef _GNVPN_DNSP_H_
#define _GNVPN_DNSP_H_

#include "platform.h"
#include "gnunet-vpn-packet.h"

struct dns_pkt_parsed *
parse_dns_packet (struct dns_pkt *pkt);

struct dns_pkt *
unparse_dns_packet (struct dns_pkt_parsed *pkt);

void
free_parsed_dns_packet (struct dns_pkt_parsed *ppkt);

#endif

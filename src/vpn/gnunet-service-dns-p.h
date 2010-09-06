#ifndef GN_DNS_SERVICE_P_H
#define GN_DNS_SERVICE_P_H

#include "gnunet_common.h"

struct query_packet {
	struct GNUNET_MessageHeader hdr;
	
	unsigned orig_to:32 GNUNET_PACKED; /* The IP-Address, this query was originally sent to */
	unsigned orig_from:32 GNUNET_PACKED;
	unsigned src_port:16 GNUNET_PACKED;

	unsigned char data[1]; /* The DNS-Packet */
	
};

#endif

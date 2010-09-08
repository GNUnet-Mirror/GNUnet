#ifndef GN_VPN_HELPER_P_H
#define GN_VPN_HELPER_P_H

#include "platform.h"
#include "gnunet_common.h"

struct suid_packet {
	struct GNUNET_MessageHeader hdr;
	unsigned char data[1];
};

#endif

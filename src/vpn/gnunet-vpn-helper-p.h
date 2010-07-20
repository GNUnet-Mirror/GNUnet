#ifndef GN_VPN_HELPER_P_H
#define GN_VPN_HELPER_P_H

struct suid_packet_header {
	uint32_t size;
};

struct suid_packet {
	struct suid_packet_header hdr;
	unsigned char data[1];
};

#endif

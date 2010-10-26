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

struct query_packet_list {
	struct query_packet_list* next GNUNET_PACKED;
	struct query_packet_list* prev GNUNET_PACKED;
	struct query_packet pkt;
};

enum GNUNET_DNS_ANSWER_Subtype {
    /**
     * Answers of this type contain a dns-packet that just has to be transmitted
     */
    GNUNET_DNS_ANSWER_TYPE_IP,

    /**
     * Answers of this type contain an struct GNUNET_DNS_Record
     */
    GNUNET_DNS_ANSWER_TYPE_SERVICE
};

struct answer_packet {
    struct GNUNET_MessageHeader hdr;
    enum GNUNET_DNS_ANSWER_Subtype subtype GNUNET_PACKED;

    unsigned from:32 GNUNET_PACKED;
    unsigned to:32 GNUNET_PACKED;
    unsigned dst_port:16 GNUNET_PACKED;

    unsigned short id GNUNET_PACKED;
    GNUNET_HashCode peer;
    GNUNET_HashCode service_descriptor;
    uint64_t ports;
    uint32_t service_type;

    unsigned addroffset:16 GNUNET_PACKED;

    unsigned char data[1];
};

struct answer_packet_list {
	struct answer_packet_list* next GNUNET_PACKED;
	struct answer_packet_list* prev GNUNET_PACKED;
	struct answer_packet pkt;
};

#endif

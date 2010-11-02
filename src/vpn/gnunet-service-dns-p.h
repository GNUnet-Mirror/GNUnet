#ifndef GN_DNS_SERVICE_P_H
#define GN_DNS_SERVICE_P_H

#include "gnunet_common.h"

struct query_packet {
	struct GNUNET_MessageHeader hdr;

	/**
	 * The IP-Address this query was originally sent to
	 */
	unsigned orig_to:32 GNUNET_PACKED;
	/**
	 * The IP-Address this query was originally sent from
	 */
	unsigned orig_from:32 GNUNET_PACKED;
	/**
	 * The UDP-Portthis query was originally sent from
	 */
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
     * Answers of this type contain an incomplete dns-packet. The IP-Address
     * is all 0s. The addroffset points to it.
     */
    GNUNET_DNS_ANSWER_TYPE_SERVICE
};

struct answer_packet {
    struct GNUNET_MessageHeader hdr;
    enum GNUNET_DNS_ANSWER_Subtype subtype GNUNET_PACKED;

    unsigned from:32 GNUNET_PACKED;
    unsigned to:32 GNUNET_PACKED;
    unsigned dst_port:16 GNUNET_PACKED;

    /* Only sensible when subtype == GNUNET_DNS_ANSWER_TYPE_SERVICE */
    GNUNET_HashCode peer;
    GNUNET_HashCode service_descriptor;
    uint64_t ports;
    uint32_t service_type;

    /* The offsett in octets from the beginning of the struct to the field
     * in data where the IP-Address has to go. */
    unsigned addroffset:16 GNUNET_PACKED;

    unsigned char data[1];
};

struct answer_packet_list {
	struct answer_packet_list* next GNUNET_PACKED;
	struct answer_packet_list* prev GNUNET_PACKED;
	struct answer_packet pkt;
};

#endif

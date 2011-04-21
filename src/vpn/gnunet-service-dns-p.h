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
    GNUNET_DNS_ANSWER_TYPE_SERVICE,

    /**
     * Answers of this type contain an incomplete dns-packet as answer to a
     * PTR-Query. The resolved name is not allocated. The addroffset points to it.
     */
    GNUNET_DNS_ANSWER_TYPE_REV,

    /**
     * Answers of this type contains an IP-Address but traffic to this IP should
     * be routed through the GNUNet.
     */
    GNUNET_DNS_ANSWER_TYPE_REMOTE
};

struct GNUNET_vpn_service_descriptor {
    GNUNET_HashCode peer GNUNET_PACKED;
    GNUNET_HashCode service_descriptor GNUNET_PACKED;
    uint64_t ports GNUNET_PACKED;
    uint32_t service_type GNUNET_PACKED;
};

struct answer_packet {
    /* General data */
    struct GNUNET_MessageHeader hdr;
    enum GNUNET_DNS_ANSWER_Subtype subtype GNUNET_PACKED;

    unsigned from:32 GNUNET_PACKED;
    unsigned to:32 GNUNET_PACKED;
    unsigned dst_port:16 GNUNET_PACKED;
    /* -- */

    /* Data for GNUNET_DNS_ANSWER_TYPE_SERVICE */
    struct GNUNET_vpn_service_descriptor service_descr;
    /* -- */

    /* Data for GNUNET_DNS_ANSWER_TYPE_REV */
    /* The offsett in octets from the beginning of the struct to the field
     * in data where the IP-Address has to go. */
    uint16_t addroffset GNUNET_PACKED;
    /* -- */

    /* Data for GNUNET_DNS_ANSWER_TYPE_REMOTE */
    /* either 4 or 16 */
    char addrsize;
    unsigned char addr[16];
    /* -- */

    unsigned char data[1];
};

struct answer_packet_list {
	struct answer_packet_list* next GNUNET_PACKED;
	struct answer_packet_list* prev GNUNET_PACKED;
	struct answer_packet pkt;
};

#endif

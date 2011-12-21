#ifndef GN_DNS_SERVICE_P_H
#define GN_DNS_SERVICE_P_H

#include "gnunet_common.h"

GNUNET_NETWORK_STRUCT_BEGIN

struct query_packet
{
  struct GNUNET_MessageHeader hdr;

        /**
	 * The IP-Address this query was originally sent to
	 */
  char orig_to[16];
        /**
	 * The IP-Address this query was originally sent from
	 */
  char orig_from[16];
        /**
	 * The UDP-Portthis query was originally sent from
	 */
  char addrlen;
  uint16_t src_port GNUNET_PACKED;

  unsigned char data[1];        /* The DNS-Packet */
};

struct query_packet_list
{
  struct query_packet_list *next GNUNET_PACKED;
  struct query_packet_list *prev GNUNET_PACKED;
  struct query_packet pkt;
};

enum GNUNET_DNS_ANSWER_Subtype
{
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
     * Answers of this type contains an IP6-Address but traffic to this IP should
     * be routed through the GNUNet.
     */
  GNUNET_DNS_ANSWER_TYPE_REMOTE_AAAA,

    /**
     * Answers of this type contains an IP4-Address but traffic to this IP should
     * be routed through the GNUNet.
     */
  GNUNET_DNS_ANSWER_TYPE_REMOTE_A
};

struct GNUNET_vpn_service_descriptor
{
  GNUNET_HashCode peer GNUNET_PACKED;
  GNUNET_HashCode service_descriptor GNUNET_PACKED;
  uint64_t ports GNUNET_PACKED;
  uint32_t service_type GNUNET_PACKED;
};

struct answer_packet
{
  /* General data */
  struct GNUNET_MessageHeader hdr;
  enum GNUNET_DNS_ANSWER_Subtype subtype GNUNET_PACKED;

  char from[16];
  char to[16];
  char addrlen;
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

struct answer_packet_list
{
  struct answer_packet_list *next GNUNET_PACKED;
  struct answer_packet_list *prev GNUNET_PACKED;
  struct GNUNET_SERVER_Client *client;
  struct answer_packet pkt;
};
GNUNET_NETWORK_STRUCT_END

#endif

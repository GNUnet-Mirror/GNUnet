#ifndef _GNVPN_BLOCKDNS_H_
#define _GNVPN_BLOCKDNS_H_

#include "gnunet_common.h"

/**
 * Bitmask describing what ip-services are supported by services
 * It is 2 bytes long
 */
struct GNUNET_ipservices {
  unsigned UDP:1 GNUNET_PACKED;
  unsigned TCP:1 GNUNET_PACKED;
  unsigned RESERVED:14 GNUNET_PACKED;
};

/**
 * This is the structure describing an dns-record such as www.gnunet.
 */
struct GNUNET_DNS_Record
{
  /**
   * The peer providing this service
   */
  struct GNUNET_PeerIdentity peer;

  /**
   * The descriptor for the service
   * (a peer may provide more than one service)
   */
  GNUNET_HashCode service_descriptor;

  /**
   * What connection-types (UDP, TCP, ...) are supported by the service
   */
  struct GNUNET_ipservices connectiontypes;

  /**
   * The length of the name of the service
   */
  unsigned char namelen;

  /**
   * The name of the service
   * This is namelen bytes
   */
  char name[1];
};

#endif

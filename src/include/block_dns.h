#ifndef _GNVPN_BLOCKDNS_H_
#define _GNVPN_BLOCKDNS_H_

#include "gnunet_common.h"
#include "gnunet_crypto_lib.h"

/**
 * Bitmask describing what IP-protocols are supported by the service
 */
enum GNUNET_DNS_ServiceTypes
{
  GNUNET_DNS_SERVICE_TYPE_UDP = 1,
  GNUNET_DNS_SERVICE_TYPE_TCP = 2
};

GNUNET_NETWORK_STRUCT_BEGIN

/**
 * This is the structure describing an dns-record such as www.gnunet.
 */
struct GNUNET_DNS_Record
{
  /**
   * Signature of the peer affirming that he is offering the service.
   */
  struct GNUNET_CRYPTO_RsaSignature signature;

  /**
   * Beginning of signed portion of the record, signs everything until
   * the end of the struct.
   */
  struct GNUNET_CRYPTO_RsaSignaturePurpose purpose;

  /**
   * The peer providing this service
   */
  struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded peer;

  /**
   * The descriptor for the service
   * (a peer may provide more than one service)
   */
  GNUNET_HashCode service_descriptor GNUNET_PACKED;

  /**
   * When does this record expire?
   */
  struct GNUNET_TIME_AbsoluteNBO expiration_time;

  /**
   * Four TCP and UDP-Ports that are used by this service, big endian format
   */
  uint64_t ports GNUNET_PACKED;

  /**
   * What connection-types (UDP, TCP, ...) are supported by the service.
   * Contains an 'enum GNUNET_DNS_ServiceTypes' in big endian format.
   */
  uint32_t service_type GNUNET_PACKED;
};
GNUNET_NETWORK_STRUCT_END

#endif

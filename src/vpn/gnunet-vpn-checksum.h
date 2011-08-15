#ifndef GNUNET_VPN_CHECKSUM_H

#define GNUNET_VPN_CHECKSUM_H

#include <platform.h>

uint32_t calculate_checksum_update (uint32_t sum, uint16_t * hdr, short len);

uint16_t calculate_checksum_end (uint32_t sum);

/**
 * Calculate the checksum of an IPv4-Header
 */
uint16_t calculate_ip_checksum (uint16_t * hdr, short len);

#endif /* end of include guard: GNUNET-VPN-CHECKSUM_H */

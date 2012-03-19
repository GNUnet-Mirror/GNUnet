/*
     This file is part of GNUnet.
     (C) 2009 Christian Grothoff (and other contributing authors)

     GNUnet is free software; you can redistribute it and/or modify
     it under the terms of the GNU General Public License as published
     by the Free Software Foundation; either version 3, or (at your
     option) any later version.

     GNUnet is distributed in the hope that it will be useful, but
     WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
     General Public License for more details.

     You should have received a copy of the GNU General Public License
     along with GNUnet; see the file COPYING.  If not, write to the
     Free Software Foundation, Inc., 59 Temple Place - Suite 330,
     Boston, MA 02111-1307, USA.
*/

/**
 * @file include/block_dns.h
 * @author Philipp Toelke
 */
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
  GNUNET_HashCode service_descriptor;

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

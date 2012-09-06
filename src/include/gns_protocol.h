/*
      This file is part of GNUnet
      (C) 2012 Christian Grothoff (and other contributing authors)

      GNUnet is free software; you can redistribute it and/or modify
      it under the terms of the GNU General Public License as published
      by the Free Software Foundation; either version 2, or (at your
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
 * @file include/gns_protocol.h
 * @brief Resource Record definitions
 * @author Martin Schanzenbach
 */
#ifndef GNS_RECORDS_H
#define GNS_RECORDS_H

GNUNET_NETWORK_STRUCT_BEGIN

/**
 * Payload of DNS SOA record (header).
 */
struct soa_data
{
  /**
   * The version number of the original copy of the zone.   (NBO)
   */
  uint32_t serial GNUNET_PACKED;
  
  /**
   * Time interval before the zone should be refreshed. (NBO)
   */
  uint32_t refresh GNUNET_PACKED;
  
  /**
   * Time interval that should elapse before a failed refresh should
   * be retried. (NBO)
   */
  uint32_t retry GNUNET_PACKED;
 
  /**
   * Time value that specifies the upper limit on the time interval
   * that can elapse before the zone is no longer authoritative. (NBO)
   */
  uint32_t expire GNUNET_PACKED;

  /**
   * The bit minimum TTL field that should be exported with any RR
   * from this zone. (NBO)
   */
  uint32_t minimum GNUNET_PACKED;
};


/**
 * Payload of DNS SRV record (header).
 */
struct srv_data
{

  /**
   * Preference for this entry (lower value is higher preference).  Clients
   * will contact hosts from the lowest-priority group first and fall back
   * to higher priorities if the low-priority entries are unavailable. (NBO)
   */
  uint16_t prio GNUNET_PACKED;

  /**
   * Relative weight for records with the same priority.  Clients will use
   * the hosts of the same (lowest) priority with a probability proportional
   * to the weight given. (NBO)
   */
  uint16_t weight GNUNET_PACKED;

  /**
   * TCP or UDP port of the service. (NBO)
   */
  uint16_t port GNUNET_PACKED;

  /* followed by 'target' name */
};


/**
 * Payload of DNSSEC TLSA record.
 * http://datatracker.ietf.org/doc/draft-ietf-dane-protocol/
 */
struct tlsa_data
{

  /**
   * Certificate usage
   * 0: CA cert
   * 1: Entity cert
   * 2: Trust anchor
   * 3: domain-issued cert
   */
  uint8_t usage;

  /**
   * Selector
   * What part will be matched against the cert
   * presented by server
   * 0: Full cert (in binary)
   * 1: Full cert (in DER)
   */
  uint8_t selector;

  /**
   * Matching type (of selected content)
   * 0: exact match
   * 1: SHA-256 hash
   * 2: SHA-512 hash
   */
  uint8_t matching_type;

  /**
   * followed by certificate association data
   * The "certificate association data" to be matched.
   * These bytes are either raw data (that is, the full certificate or
   * its SubjectPublicKeyInfo, depending on the selector) for matching
   * type 0, or the hash of the raw data for matching types 1 and 2.
   * The data refers to the certificate in the association, not to the
   * TLS ASN.1 Certificate object.
   *
   * The data is represented as a string of hex chars
   */
};

/**
 * Payload of GNS VPN record
 */
struct vpn_data
{
  /**
   * The peer to contact
   */
  struct GNUNET_HashCode peer;

  /**
   * The protocol to use
   */
  uint16_t proto;

  /* followed by the servicename */
};

GNUNET_NETWORK_STRUCT_END

#endif

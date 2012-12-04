/*
      This file is part of GNUnet
      (C) 2010, 2011, 2012 Christian Grothoff (and other contributing authors)

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
 * @file dns/dnsparser.h
 * @brief helper library to parse DNS packets. 
 * @author Philipp Toelke
 * @author Christian Grothoff
 * @author Martin Schanzenbach
 */
GNUNET_NETWORK_STRUCT_BEGIN

/* FIXME: replace this one with the one from tcpip_tun.h!? */
/**
 * Head of a any DNS message.
 */
struct GNUNET_TUN_DnsHeader
{
  /**
   * Request/response ID. (NBO)
   */
  uint16_t id GNUNET_PACKED;

  /**
   * Flags for the operation.
   */
  struct GNUNET_DNSPARSER_Flags flags; 

  /**
   * number of questions (NBO)
   */
  uint16_t query_count GNUNET_PACKED;

  /**
   * number of answers (NBO)
   */
  uint16_t answer_rcount GNUNET_PACKED;

  /**
   * number of authority-records (NBO)
   */
  uint16_t authority_rcount GNUNET_PACKED;

  /**
   * number of additional records (NBO)
   */
  uint16_t additional_rcount GNUNET_PACKED;
};


/**
 * DNS query prefix.
 */
struct query_line
{
  /**
   * Desired type (GNUNET_DNSPARSER_TYPE_XXX). (NBO)
   */
  uint16_t type GNUNET_PACKED;

  /**
   * Desired class (usually GNUNET_DNSPARSER_CLASS_INTERNET). (NBO)
   */
  uint16_t class GNUNET_PACKED;
};


/**
 * General DNS record prefix.
 */
struct record_line
{
  /**
   * Record type (GNUNET_DNSPARSER_TYPE_XXX). (NBO)
   */
  uint16_t type GNUNET_PACKED;

  /**
   * Record class (usually GNUNET_DNSPARSER_CLASS_INTERNET). (NBO)
   */
  uint16_t class GNUNET_PACKED;

  /**
   * Expiration for the record (in seconds). (NBO)
   */
  uint32_t ttl GNUNET_PACKED;

  /**
   * Number of bytes of data that follow. (NBO)
   */
  uint16_t data_len GNUNET_PACKED;
};


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
  uint16_t proto GNUNET_PACKED;


  /* followed by the servicename / identifier / password (0-terminated) */
};

GNUNET_NETWORK_STRUCT_END

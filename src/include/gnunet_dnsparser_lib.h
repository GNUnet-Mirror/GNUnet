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
 * @file include/gnunet_dnsparser_lib.h
 * @brief API for helper library to parse DNS packets. 
 * @author Philipp Toelke
 * @author Christian Grothoff
 */
#ifndef GNUNET_DNSPARSER_LIB_H
#define GNUNET_DNSPARSER_LIB_H

#include "platform.h"
#include "gnunet_common.h"

/**
 * A few common DNS types.
 */
#define GNUNET_DNSPARSER_TYPE_A 1
#define GNUNET_DNSPARSER_TYPE_NS 2
#define GNUNET_DNSPARSER_TYPE_CNAME 5
#define GNUNET_DNSPARSER_TYPE_SOA 6
#define GNUNET_DNSPARSER_TYPE_PTR 12
#define GNUNET_DNSPARSER_TYPE_MX 15
#define GNUNET_DNSPARSER_TYPE_TXT 16
#define GNUNET_DNSPARSER_TYPE_AAAA 28

/**
 * A few common DNS classes (ok, only one is common, but I list a
 * couple more to make it clear what we're talking about here).
 */
#define GNUNET_DNSPARSER_CLASS_INTERNET 1
#define GNUNET_DNSPARSER_CLASS_CHAOS 3
#define GNUNET_DNSPARSER_CLASS_HESIOD 4

#define GNUNET_DNSPARSER_OPCODE_QUERY 0
#define GNUNET_DNSPARSER_OPCODE_INVERSE_QUERY 1
#define GNUNET_DNSPARSER_OPCODE_STATUS 2

/**
 * RFC 1035 codes.
 */
#define GNUNET_DNSPARSER_RETURN_CODE_NO_ERROR 0
#define GNUNET_DNSPARSER_RETURN_CODE_FORMAT_ERROR 1
#define GNUNET_DNSPARSER_RETURN_CODE_SERVER_FAILURE 2
#define GNUNET_DNSPARSER_RETURN_CODE_NAME_ERROR 3
#define GNUNET_DNSPARSER_RETURN_CODE_NOT_IMPLEMENTED 4
#define GNUNET_DNSPARSER_RETURN_CODE_REFUSED 5

/**
 * RFC 2136 codes
 */
#define GNUNET_DNSPARSER_RETURN_CODE_YXDOMAIN 6
#define GNUNET_DNSPARSER_RETURN_CODE_YXRRSET 7
#define GNUNET_DNSPARSER_RETURN_CODE_NXRRSET 8
#define GNUNET_DNSPARSER_RETURN_CODE_NOT_AUTH 9
#define GNUNET_DNSPARSER_RETURN_CODE_NOT_ZONE 10

/**
 * DNS flags (largely RFC 1035 / RFC 2136).
 */
struct GNUNET_DNSPARSER_Flags
{
  /**
   * Set to 1 if recursion is desired (client -> server)
   */
  unsigned int recursion_desired    : 1 GNUNET_PACKED;  
  
  /**
   * Set to 1 if message is truncated
   */
  unsigned int message_truncated    : 1 GNUNET_PACKED; 
  
  /**
   * Set to 1 if this is an authoritative answer
   */
  unsigned int authoritative_answer : 1 GNUNET_PACKED;
  
  /**
   * See GNUNET_DNSPARSER_OPCODE_ defines.
   */
  unsigned int opcode               : 4 GNUNET_PACKED;  
  
  /**
   * query:0, response:1
   */
  unsigned int query_or_response    : 1 GNUNET_PACKED;  
  
  /**
   * See GNUNET_DNSPARSER_RETURN_CODE_ defines.
   */
  unsigned int return_code          : 4 GNUNET_PACKED; 
  
  /**
   * See RFC 4035.
   */
  unsigned int checking_disabled    : 1 GNUNET_PACKED; 
  
  /**
   * Response has been cryptographically verified, RFC 4035.
   */
  unsigned int authenticated_data   : 1 GNUNET_PACKED;
  
  /**
   * Always zero.
   */
  unsigned int zero                 : 1 GNUNET_PACKED;
  
  /**
   * Set to 1 if recursion is available (server -> client)
   */
  unsigned int recursion_available  : 1 GNUNET_PACKED; 
  
} GNUNET_GCC_STRUCT_LAYOUT;


/**
 * A DNS query.
 */
struct GNUNET_DNSPARSER_Query
{

  /**
   * Name of the record that the query is for (0-terminated).
   */
  char *name;

  /**
   * See GNUNET_DNSPARSER_TYPE_*.
   */
  uint16_t type;

  /**
   * See GNUNET_DNSPARSER_CLASS_*.
   */
  uint16_t class;

};


/**
 * Information from MX records (RFC 1035).
 */
struct GNUNET_DNSPARSER_MxRecord
{
  
  /**
   * Preference for this entry (lower value is higher preference).
   */
  uint16_t preference;

  /**
   * Name of the mail server.
   */
  char *mxhost;

};

  
/**
 * Information from SOA records (RFC 1035).
 */
struct GNUNET_DNSPARSER_SoaRecord
{
  
  /**
   *The domainname of the name server that was the
   * original or primary source of data for this zone.
   */
  char *mname;

  /**
   * A domainname which specifies the mailbox of the
   * person responsible for this zone.
   */
  char *rname;

  /**
   * The version number of the original copy of the zone.  
   */
  uint32_t serial;

  /**
   * Time interval before the zone should be refreshed.
   */
  uint32_t refresh;

  /**
   * Time interval that should elapse before a failed refresh should
   * be retried.
   */
  uint32_t retry;

  /**
   * Time value that specifies the upper limit on the time interval
   * that can elapse before the zone is no longer authoritative.
   */
  uint32_t expire;

  /**
   * The bit minimum TTL field that should be exported with any RR
   * from this zone.
   */
  uint32_t minimum_ttl;
  
};


/**
 * Binary record information (unparsed).
 */
struct GNUNET_DNSPARSER_RawRecord
{

  /**
   * Binary record data.
   */
  void *data;

  /**
   * Number of bytes in data.
   */
  size_t data_len;
};


/**
 * A DNS response record.
 */
struct GNUNET_DNSPARSER_Record
{

  /**
   * Name of the record that the query is for (0-terminated).
   */
  char *name;

  union 
  {

    /**
     * For NS, CNAME and PTR records, this is the uncompressed 0-terminated hostname.
     */
    char *hostname;
    
    /**
     * SOA data for SOA records.
     */
    struct GNUNET_DNSPARSER_SoaRecord *soa;
    
    /**
     * MX data for MX records.
     */
    struct GNUNET_DNSPARSER_MxRecord *mx;

    /**
     * Raw data for all other types.
     */
    struct GNUNET_DNSPARSER_RawRecord raw;

  } data;


  /**
   * When does the record expire?
   */
  struct GNUNET_TIME_Absolute expiration_time;

  /**
   * See GNUNET_DNSPARSER_TYPE_*.
   */
  uint16_t type;

  /**
   * See GNUNET_DNSPARSER_CLASS_*.
   */
  uint16_t class;

};


/**
 * Easy-to-process, parsed version of a DNS packet.
 */
struct GNUNET_DNSPARSER_Packet
{
  /**
   * Array of all queries in the packet, must contain "num_queries" entries.
   */
  struct GNUNET_DNSPARSER_Query *queries;

  /**
   * Array of all answers in the packet, must contain "num_answers" entries.
   */
  struct GNUNET_DNSPARSER_Record *answers;

  /**
   * Array of all authority records in the packet, must contain "num_authority_records" entries.
   */
  struct GNUNET_DNSPARSER_Record *authority_records;

  /**
   * Array of all additional answers in the packet, must contain "num_additional_records" entries.
   */
  struct GNUNET_DNSPARSER_Record *additional_records;

  /**
   * Number of queries in the packet.
   */
  unsigned int num_queries;

  /**
   * Number of answers in the packet, should be 0 for queries.
   */
  unsigned int num_answers;

  /**
   * Number of authoritative answers in the packet, should be 0 for queries.
   */
  unsigned int num_authority_records;

  /**
   * Number of additional records in the packet, should be 0 for queries.
   */
  unsigned int num_additional_records;

  /**
   * Bitfield of DNS flags.
   */ 
  struct GNUNET_DNSPARSER_Flags flags;

  /**
   * DNS ID (to match replies to requests).
   */
  uint16_t id;

};


/**
 * Parse a UDP payload of a DNS packet in to a nice struct for further
 * processing and manipulation.
 *
 * @param udp_payload wire-format of the DNS packet
 * @param udp_payload_length number of bytes in udp_payload 
 * @return NULL on error, otherwise the parsed packet
 */
struct GNUNET_DNSPARSER_Packet *
GNUNET_DNSPARSER_parse (const char *udp_payload,
			size_t udp_payload_length);


/**
 * Free memory taken by a packet.
 *
 * @param p packet to free
 */
void
GNUNET_DNSPARSER_free_packet (struct GNUNET_DNSPARSER_Packet *p);


/**
 * Given a DNS packet, generate the corresponding UDP payload.
 *
 * @param p packet to pack
 * @param max maximum allowed size for the resulting UDP payload
 * @param buf set to a buffer with the packed message
 * @param buf_length set to the length of buf
 * @return GNUNET_SYSERR if 'p' is invalid
 *         GNUNET_NO if 'p' was truncated (but there is still a result in 'buf')
 *         GNUNET_OK if 'p' was packed completely into '*buf'
 */
int
GNUNET_DNSPARSER_pack (const struct GNUNET_DNSPARSER_Packet *p,
		       uint16_t max,
		       char **buf,
		       size_t *buf_length);


#endif

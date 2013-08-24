/*
      This file is part of GNUnet
      (C) 2010-2013 Christian Grothoff (and other contributing authors)

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
 * @file include/gnunet_dnsparser_lib.h
 * @brief API for helper library to parse DNS packets. 
 * @author Philipp Toelke
 * @author Christian Grothoff
 */
#ifndef GNUNET_DNSPARSER_LIB_H
#define GNUNET_DNSPARSER_LIB_H

#include "gnunet_common.h"
#include "gnunet_tun_lib.h"

/**
 * Maximum length of a label in DNS.
 */
#define GNUNET_DNSPARSER_MAX_LABEL_LENGTH 63

/**
 * Maximum length of a name in DNS.
 */
#define GNUNET_DNSPARSER_MAX_NAME_LENGTH 253


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
#define GNUNET_DNSPARSER_TYPE_SRV 33
#define GNUNET_DNSPARSER_TYPE_TLSA 52


/**
 * A DNS query.
 */
struct GNUNET_DNSPARSER_Query
{

  /**
   * Name of the record that the query is for (0-terminated).
   * In UTF-8 format.  The library will convert from and to DNS-IDNA 
   * as necessary.  Use 'GNUNET_DNSPARSER_check_label' to test if an
   * individual label is well-formed.  If a given name is not well-formed,
   * creating the DNS packet will fail.
   */
  char *name;

  /**
   * See GNUNET_DNSPARSER_TYPE_*.
   */
  uint16_t type;

  /**
   * See GNUNET_TUN_DNS_CLASS_*.
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
   * In UTF-8 format.  The library will convert from and to DNS-IDNA 
   * as necessary.  Use 'GNUNET_DNSPARSER_check_label' to test if an
   * individual label is well-formed.  If a given name is not well-formed,
   * creating the DNS packet will fail.
   */
  char *mxhost;

};


/**
 * Information from SRV records (RFC 2782).  The 'service', 'proto'
 * and 'domain_name' fields together give the DNS-name which for SRV
 * records is of the form "_$SERVICE._$PROTO.$DOMAIN_NAME".  The DNS
 * parser provides the full name in 'struct DNSPARSER_Record' and the
 * individual components in the respective fields of this struct.
 * When serializing, you CAN set the 'name' field of 'struct
 * GNUNET_DNSPARSER_Record' to NULL, in which case the DNSPARSER code
 * will populate 'name' from the 'service', 'proto' and 'domain_name'
 * fields in this struct.
 */
struct GNUNET_DNSPARSER_SrvRecord
{
  
  /**
   * Service name without the underscore (!).  Note that RFC 6335 clarifies the
   * set of legal characters for service names.
   * In UTF-8 format.  The library will convert from and to DNS-IDNA 
   * as necessary.  Use 'GNUNET_DNSPARSER_check_label' to test if an
   * individual label is well-formed.  If a given name is not well-formed,
   * creating the DNS packet will fail.
   */
  char *service;

  /**
   * Transport protocol (typcially "tcp" or "udp", but others might be allowed).
   * Without the underscore (!).
   */
  char *proto;

  /**
   * Domain name for which the record is valid
   * In UTF-8 format.  The library will convert from and to DNS-IDNA 
   * as necessary.  Use 'GNUNET_DNSPARSER_check_label' to test if an
   * individual label is well-formed.  If a given name is not well-formed,
   * creating the DNS packet will fail.
   */
  char *domain_name;

  /**
   * Hostname offering the service.
   * In UTF-8 format.  The library will convert from and to DNS-IDNA 
   * as necessary.  Use 'GNUNET_DNSPARSER_check_label' to test if an
   * individual label is well-formed.  If a given name is not well-formed,
   * creating the DNS packet will fail.
   */
  char *target;

  /**
   * Preference for this entry (lower value is higher preference).  Clients
   * will contact hosts from the lowest-priority group first and fall back
   * to higher priorities if the low-priority entries are unavailable.
   */
  uint16_t priority;

  /**
   * Relative weight for records with the same priority.  Clients will use
   * the hosts of the same (lowest) priority with a probability proportional
   * to the weight given.
   */
  uint16_t weight;

  /**
   * TCP or UDP port of the service.
   */
  uint16_t port;

};

  
/**
 * Information from SOA records (RFC 1035).
 */
struct GNUNET_DNSPARSER_SoaRecord
{
  
  /**
   *The domainname of the name server that was the
   * original or primary source of data for this zone.
   * In UTF-8 format.  The library will convert from and to DNS-IDNA 
   * as necessary.  Use 'GNUNET_DNSPARSER_check_label' to test if an
   * individual label is well-formed.  If a given name is not well-formed,
   * creating the DNS packet will fail.
   */
  char *mname;

  /**
   * A domainname which specifies the mailbox of the
   * person responsible for this zone.
   * In UTF-8 format.  The library will convert from and to DNS-IDNA 
   * as necessary.  Use 'GNUNET_DNSPARSER_check_label' to test if an
   * individual label is well-formed.  If a given name is not well-formed,
   * creating the DNS packet will fail.
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
   * In UTF-8 format.  The library will convert from and to DNS-IDNA 
   * as necessary.  Use #GNUNET_DNSPARSER_check_label to test if an
   * individual label is well-formed.  If a given name is not well-formed,
   * creating the DNS packet will fail.
   */
  char *name;

  /**
   * Payload of the record (which one of these is valid depends on the 'type').
   */
  union 
  {

    /**
     * For NS, CNAME and PTR records, this is the uncompressed 0-terminated hostname.
   * In UTF-8 format.  The library will convert from and to DNS-IDNA 
   * as necessary.  Use #GNUNET_DNSPARSER_check_label to test if an
   * individual label is well-formed.  If a given name is not well-formed,
   * creating the DNS packet will fail.
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
     * SRV data for SRV records.
     */
    struct GNUNET_DNSPARSER_SrvRecord *srv;

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
   * See GNUNET_TUN_DNS_CLASS_*.
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
  struct GNUNET_TUN_DnsFlags flags;

  /**
   * DNS ID (to match replies to requests).
   */
  uint16_t id;

};


/**
 * Check if a label in UTF-8 format can be coded into valid IDNA.
 * This can fail if the ASCII-conversion becomes longer than 63 characters.
 *
 * @param label label to check (UTF-8 string)
 * @return GNUNET_OK if the label can be converted to IDNA,
 *         GNUNET_SYSERR if the label is not valid for DNS names
 */
int
GNUNET_DNSPARSER_check_label (const char *label);


/**
 * Check if a hostname in UTF-8 format can be coded into valid IDNA.
 * This can fail if a label becomes longer than 63 characters or if
 * the entire name exceeds 253 characters.
 *
 * @param name name to check (UTF-8 string)
 * @return GNUNET_OK if the label can be converted to IDNA,
 *         GNUNET_SYSERR if the label is not valid for DNS names
 */
int
GNUNET_DNSPARSER_check_name (const char *name);


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
 * Given a DNS packet @a p, generate the corresponding UDP payload.
 * Note that we do not attempt to pack the strings with pointers
 * as this would complicate the code and this is about being 
 * simple and secure, not fast, fancy and broken like bind.
 *
 * @param p packet to pack
 * @param max maximum allowed size for the resulting UDP payload
 * @param buf set to a buffer with the packed message
 * @param buf_length set to the length of @a buf
 * @return #GNUNET_SYSERR if @a p is invalid
 *         #GNUNET_NO if @a p was truncated (but there is still a result in @a buf)
 *         #GNUNET_OK if @a p was packed completely into @a buf
 */
int
GNUNET_DNSPARSER_pack (const struct GNUNET_DNSPARSER_Packet *p,
		       uint16_t max,
		       char **buf,
		       size_t *buf_length);

/* ***************** low-level packing API ******************** */

/**
 * Add a DNS name to the UDP packet at the given location, converting
 * the name to IDNA notation as necessary.
 *
 * @param dst where to write the name (UDP packet)
 * @param dst_len number of bytes in @a dst
 * @param off pointer to offset where to write the name (increment by bytes used)
 *            must not be changed if there is an error
 * @param name name to write
 * @return #GNUNET_SYSERR if @a name is invalid
 *         #GNUNET_NO if @a name did not fit
 *         #GNUNET_OK if @a name was added to @a dst
 */
int
GNUNET_DNSPARSER_builder_add_name (char *dst,
				   size_t dst_len,
				   size_t *off,
				   const char *name);


/**
 * Add a DNS query to the UDP packet at the given location.
 *
 * @param dst where to write the query
 * @param dst_len number of bytes in @a dst
 * @param off pointer to offset where to write the query (increment by bytes used)
 *            must not be changed if there is an error
 * @param query query to write
 * @return #GNUNET_SYSERR if @a query is invalid
 *         #GNUNET_NO if @a query did not fit
 *         #GNUNET_OK if @a query was added to @a dst
 */
int
GNUNET_DNSPARSER_builder_add_query (char *dst,
				    size_t dst_len,
				    size_t *off,
				    const struct GNUNET_DNSPARSER_Query *query);


/**
 * Add an MX record to the UDP packet at the given location.
 *
 * @param dst where to write the mx record
 * @param dst_len number of bytes in @a dst
 * @param off pointer to offset where to write the mx information (increment by bytes used);
 *            can also change if there was an error
 * @param mx mx information to write
 * @return #GNUNET_SYSERR if @a mx is invalid
 *         #GNUNET_NO if @a mx did not fit
 *         #GNUNET_OK if @a mx was added to @a dst
 */
int
GNUNET_DNSPARSER_builder_add_mx (char *dst,
				 size_t dst_len,
				 size_t *off,
				 const struct GNUNET_DNSPARSER_MxRecord *mx);


/**
 * Add an SOA record to the UDP packet at the given location.
 *
 * @param dst where to write the SOA record
 * @param dst_len number of bytes in @a dst
 * @param off pointer to offset where to write the SOA information (increment by bytes used)
 *            can also change if there was an error
 * @param soa SOA information to write
 * @return #GNUNET_SYSERR if @a soa is invalid
 *         #GNUNET_NO if @a soa did not fit
 *         #GNUNET_OK if @a soa was added to @a dst
 */
int
GNUNET_DNSPARSER_builder_add_soa (char *dst,
				  size_t dst_len,
				  size_t *off,
				  const struct GNUNET_DNSPARSER_SoaRecord *soa);


/**
 * Add an SRV record to the UDP packet at the given location.
 *
 * @param dst where to write the SRV record
 * @param dst_len number of bytes in @a dst
 * @param off pointer to offset where to write the SRV information (increment by bytes used)
 *            can also change if there was an error
 * @param srv SRV information to write
 * @return #GNUNET_SYSERR if @a srv is invalid
 *         #GNUNET_NO if @a srv did not fit
 *         #GNUNET_OK if @a srv was added to @a dst
 */
int
GNUNET_DNSPARSER_builder_add_srv (char *dst,
				  size_t dst_len,
				  size_t *off,
				  const struct GNUNET_DNSPARSER_SrvRecord *srv);

/* ***************** low-level parsing API ******************** */

/**
 * Parse a DNS record entry.
 *
 * @param udp_payload entire UDP payload
 * @param udp_payload_length length of @a udp_payload
 * @param off pointer to the offset of the record to parse in the udp_payload (to be
 *                    incremented by the size of the record)
 * @param r where to write the record information
 * @return #GNUNET_OK on success, #GNUNET_SYSERR if the record is malformed
 */
int
GNUNET_DNSPARSER_parse_record (const char *udp_payload,
			       size_t udp_payload_length,
			       size_t *off,
			       struct GNUNET_DNSPARSER_Record *r);


/**
 * Parse name inside of a DNS query or record.
 *
 * @param udp_payload entire UDP payload
 * @param udp_payload_length length of @a udp_payload
 * @param off pointer to the offset of the name to parse in the udp_payload (to be
 *                    incremented by the size of the name)
 * @return name as 0-terminated C string on success, NULL if the payload is malformed
 */
char *
GNUNET_DNSPARSER_parse_name (const char *udp_payload,
			     size_t udp_payload_length,
			     size_t *off);


/**
 * Parse a DNS query entry.
 *
 * @param udp_payload entire UDP payload
 * @param udp_payload_length length of @a udp_payload
 * @param off pointer to the offset of the query to parse in the udp_payload (to be
 *                    incremented by the size of the query)
 * @param q where to write the query information
 * @return #GNUNET_OK on success, #GNUNET_SYSERR if the query is malformed
 */
int
GNUNET_DNSPARSER_parse_query (const char *udp_payload,
			      size_t udp_payload_length,
			      size_t *off,
			      struct GNUNET_DNSPARSER_Query *q);

/**
 * Parse a DNS SOA record.
 *
 * @param udp_payload reference to UDP packet
 * @param udp_payload_length length of @a udp_payload
 * @param off pointer to the offset of the query to parse in the SOA record (to be
 *                    incremented by the size of the record), unchanged on error
 * @return the parsed SOA record, NULL on error
 */
struct GNUNET_DNSPARSER_SoaRecord *
GNUNET_DNSPARSER_parse_soa (const char *udp_payload,
			    size_t udp_payload_length,
			    size_t *off);


/**
 * Parse a DNS MX record.
 *
 * @param udp_payload reference to UDP packet
 * @param udp_payload_length length of @a udp_payload
 * @param off pointer to the offset of the query to parse in the MX record (to be
 *                    incremented by the size of the record), unchanged on error
 * @return the parsed MX record, NULL on error
 */
struct GNUNET_DNSPARSER_MxRecord *
GNUNET_DNSPARSER_parse_mx (const char *udp_payload,
			   size_t udp_payload_length,
			   size_t *off);


/**
 * Parse a DNS SRV record.
 *
 * @param r_name name of the SRV record
 * @param udp_payload reference to UDP packet
 * @param udp_payload_length length of @a udp_payload
 * @param off pointer to the offset of the query to parse in the SRV record (to be
 *                    incremented by the size of the record), unchanged on error
 * @return the parsed SRV record, NULL on error
 */
struct GNUNET_DNSPARSER_SrvRecord *
GNUNET_DNSPARSER_parse_srv (const char *r_name,
			    const char *udp_payload,
			    size_t udp_payload_length,
			    size_t *off);

/* ***************** low-level deallocation API ******************** */

/**
 * Free the given DNS record.
 * 
 * @param r record to free
 */
void
GNUNET_DNSPARSER_free_record (struct GNUNET_DNSPARSER_Record *r);


/**
 * Free MX information record.
 *
 * @param mx record to free
 */
void
GNUNET_DNSPARSER_free_mx (struct GNUNET_DNSPARSER_MxRecord *mx);


/**
 * Free SRV information record.
 *
 * @param srv record to free
 */
void
GNUNET_DNSPARSER_free_srv (struct GNUNET_DNSPARSER_SrvRecord *srv);


/**
 * Free SOA information record.
 *
 * @param soa record to free
 */
void
GNUNET_DNSPARSER_free_soa (struct GNUNET_DNSPARSER_SoaRecord *soa);


#endif

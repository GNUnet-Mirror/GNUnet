/*
      This file is part of GNUnet
      Copyright (C) 2010-2014 Christian Grothoff (and other contributing authors)

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
      Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
      Boston, MA 02110-1301, USA.
 */

/**
 * @file include/gnunet_dnsparser_lib.h
 * @brief API for helper library to parse DNS packets.
 * @author Philipp Toelke
 * @author Christian Grothoff
 */
#ifndef GNUNET_DNSPARSER_LIB_H
#define GNUNET_DNSPARSER_LIB_H

#include "gnunet_util_lib.h"
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
#define GNUNET_DNSPARSER_TYPE_CERT 37
#define GNUNET_DNSPARSER_TYPE_TLSA 52


/**
 * A DNS query.
 */
struct GNUNET_DNSPARSER_Query
{

  /**
   * Name of the record that the query is for (0-terminated).
   * In UTF-8 format.  The library will convert from and to DNS-IDNA
   * as necessary.  Use #GNUNET_DNSPARSER_check_label() to test if an
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
  uint16_t dns_traffic_class;

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
   * as necessary.  Use #GNUNET_DNSPARSER_check_label() to test if an
   * individual label is well-formed.  If a given name is not well-formed,
   * creating the DNS packet will fail.
   */
  char *mxhost;

};


/**
 * Information from SRV records (RFC 2782).
 */
struct GNUNET_DNSPARSER_SrvRecord
{

  /**
   * Hostname offering the service.
   * In UTF-8 format.  The library will convert from and to DNS-IDNA
   * as necessary.  Use #GNUNET_DNSPARSER_check_label() to test if an
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
 * DNS CERT types as defined in RFC 4398.
 */
enum GNUNET_DNSPARSER_CertType
{
  /**
   *  Reserved value
   */
  GNUNET_DNSPARSER_CERTTYPE_RESERVED = 0,

  /**
   * An x509 PKIX certificate
   */
  GNUNET_DNSPARSER_CERTTYPE_PKIX = 1,

  /**
   * A SKPI certificate
   */
  GNUNET_DNSPARSER_CERTTYPE_SKPI = 2,

  /**
   * A PGP certificate
   */
  GNUNET_DNSPARSER_CERTTYPE_PGP = 3,

  /**
   * An x509 PKIX cert URL
   */
  GNUNET_DNSPARSER_CERTTYPE_IPKIX = 4,

  /**
   * A SKPI cert URL
   */
  GNUNET_DNSPARSER_CERTTYPE_ISKPI = 5,

  /**
   * A PGP cert fingerprint and URL
   */
  GNUNET_DNSPARSER_CERTTYPE_IPGP = 6,

  /**
   * An attribute Certificate
   */
  GNUNET_DNSPARSER_CERTTYPE_ACPKIX = 7,

  /**
   * An attribute cert URL
   */
  GNUNET_DNSPARSER_CERTTYPE_IACKPIX = 8
};


/**
 * DNSCERT algorithms as defined in http://www.iana.org/assignments/
 *  dns-sec-alg-numbers/dns-sec-alg-numbers.xhtml, under dns-sec-alg-numbers-1
 */
enum GNUNET_DNSPARSER_CertAlgorithm
{
  /**
   * No defined
   */
  GNUNET_DNSPARSER_CERTALGO_UNDEFINED = 0,

  /**
   * RSA/MD5
   */
  GNUNET_DNSPARSER_CERTALGO_RSAMD5 = 1,

  /**
   * Diffie-Hellman
   */
  GNUNET_DNSPARSER_CERTALGO_DH = 2,

  /**
   * DSA/SHA1
   */
  GNUNET_DNSPARSER_CERTALGO_DSASHA = 3,

  /**
   * Reserved
   */
  GNUNET_DNSPARSER_CERTALGO_RSRVD4 = 4,

  /**
   * RSA/SHA1
   */
  GNUNET_DNSPARSER_CERTALGO_RSASHA = 5,

  /**
   * DSA/NSEC3/SHA
   */
  GNUNET_DNSPARSER_CERTALGO_DSANSEC3 = 6,

  /**
   * RSA/NSEC3/SHA
   */
  GNUNET_DNSPARSER_CERTALGO_RSANSEC3 = 7,

  /**
   * RSA/SHA256
   */
  GNUNET_DNSPARSER_CERTALGO_RSASHA256 = 8,

  /**
   * Reserved
   */
  GNUNET_DNSPARSER_CERTALGO_RSRVD9 = 9,

  /**
   * RSA/SHA512
   */
  GNUNET_DNSPARSER_CERTALGO_RSASHA512 = 10,

  /**
   * GOST R 34.10-2001
   */
  GNUNET_DNSPARSER_CERTALGO_GOST_R34 = 12,

  /**
   * ECDSA Curve P-256/SHA256
   */
  GNUNET_DNSPARSER_CERTALGO_ECDSA_P256SHA256 = 13,

  /**
   * ECDSA Curve P-384/SHA384
   */
  GNUNET_DNSPARSER_CERTALGO_ECDSA_P384SHA384 = 14

};


/**
 * Information from CERT records (RFC 4034).
 */
struct GNUNET_DNSPARSER_CertRecord
{

  /**
   * Certificate type
   */
  enum GNUNET_DNSPARSER_CertType cert_type;

  /**
   * Certificate KeyTag
   */
  uint16_t cert_tag;

  /**
   * Algorithm
   */
  enum GNUNET_DNSPARSER_CertAlgorithm algorithm;

  /**
   * Number of bytes in @e certificate_data
   */
  size_t certificate_size;

  /**
   * Data of the certificate.
   */
  char *certificate_data;

};


/**
 * Information from SOA records (RFC 1035).
 */
struct GNUNET_DNSPARSER_SoaRecord
{

  /**
   * The domainname of the name server that was the
   * original or primary source of data for this zone.
   * In UTF-8 format.  The library will convert from and to DNS-IDNA
   * as necessary.  Use #GNUNET_DNSPARSER_check_label() to test if an
   * individual label is well-formed.  If a given name is not well-formed,
   * creating the DNS packet will fail.
   */
  char *mname;

  /**
   * A domainname which specifies the mailbox of the
   * person responsible for this zone.
   * In UTF-8 format.  The library will convert from and to DNS-IDNA
   * as necessary.  Use #GNUNET_DNSPARSER_check_label() to test if an
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
   * as necessary.  Use #GNUNET_DNSPARSER_check_label() to test if an
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
   * as necessary.  Use #GNUNET_DNSPARSER_check_label() to test if an
   * individual label is well-formed.  If a given name is not well-formed,
   * creating the DNS packet will fail.
     */
    char *hostname;

    /**
     * SOA data for SOA records.
     */
    struct GNUNET_DNSPARSER_SoaRecord *soa;

    /**
     * CERT data for CERT records.
     */
    struct GNUNET_DNSPARSER_CertRecord *cert;

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
  uint16_t dns_traffic_class;

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
 * @return #GNUNET_OK if the label can be converted to IDNA,
 *         #GNUNET_SYSERR if the label is not valid for DNS names
 */
int
GNUNET_DNSPARSER_check_label (const char *label);


/**
 * Check if a hostname in UTF-8 format can be coded into valid IDNA.
 * This can fail if a label becomes longer than 63 characters or if
 * the entire name exceeds 253 characters.
 *
 * @param name name to check (UTF-8 string)
 * @return #GNUNET_OK if the label can be converted to IDNA,
 *         #GNUNET_SYSERR if the label is not valid for DNS names
 */
int
GNUNET_DNSPARSER_check_name (const char *name);


/**
 * Parse a UDP payload of a DNS packet in to a nice struct for further
 * processing and manipulation.
 *
 * @param udp_payload wire-format of the DNS packet
 * @param udp_payload_length number of bytes in @a udp_payload
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
 * Add CERT record to the UDP packet at the given location.
 *
 * @param dst where to write the CERT record
 * @param dst_len number of bytes in @a dst
 * @param off pointer to offset where to write the CERT information (increment by bytes used)
 *            can also change if there was an error
 * @param cert CERT information to write
 * @return #GNUNET_SYSERR if @a soa is invalid
 *         #GNUNET_NO if @a soa did not fit
 *         #GNUNET_OK if @a soa was added to @a dst
 */
int
GNUNET_DNSPARSER_builder_add_cert (char *dst,
                                   size_t dst_len,
                                   size_t *off,
                                   const struct GNUNET_DNSPARSER_CertRecord *cert);


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
 * Parse a DNS CERT record.
 *
 * @param udp_payload reference to UDP packet
 * @param udp_payload_length length of @a udp_payload
 * @param off pointer to the offset of the query to parse in the CERT record (to be
 *                    incremented by the size of the record), unchanged on error
 * @return the parsed CERT record, NULL on error
 */
struct GNUNET_DNSPARSER_CertRecord *
GNUNET_DNSPARSER_parse_cert (const char *udp_payload,
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
 * @param udp_payload reference to UDP packet
 * @param udp_payload_length length of @a udp_payload
 * @param off pointer to the offset of the query to parse in the SRV record (to be
 *                    incremented by the size of the record), unchanged on error
 * @return the parsed SRV record, NULL on error
 */
struct GNUNET_DNSPARSER_SrvRecord *
GNUNET_DNSPARSER_parse_srv (const char *udp_payload,
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


/**
 * Free CERT information record.
 *
 * @param cert record to free
 */
void
GNUNET_DNSPARSER_free_cert (struct GNUNET_DNSPARSER_CertRecord *cert);


/**
 * Convert a block of binary data to HEX.
 *
 * @param data binary data to convert
 * @param data_size number of bytes in @a data
 * @return HEX string (lower case)
 */
char *
GNUNET_DNSPARSER_bin_to_hex (const void *data,
                             size_t data_size);


/**
 * Convert a HEX string to block of binary data.
 *
 * @param hex HEX string to convert (may contain mixed case)
 * @param data where to write result, must be
 *             at least `strlen(hex)/2` bytes long
 * @return number of bytes written to data
 */
size_t
GNUNET_DNSPARSER_hex_to_bin (const char *hex,
                             void *data);


#endif

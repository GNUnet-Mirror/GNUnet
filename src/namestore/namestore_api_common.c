/*
     This file is part of GNUnet.
     (C) 2009-2013 Christian Grothoff (and other contributing authors)

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
 * @file namestore/namestore_api_common.c
 * @brief API to access the NAMESTORE service
 * @author Martin Schanzenbach
 * @author Matthias Wachs
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_constants.h"
#include "gnunet_signatures.h"
#include "gnunet_arm_service.h"
#include "gnunet_namestore_service.h"
#include "gnunet_dnsparser_lib.h"
#include "gns_protocol.h"
#include "namestore.h"


#define LOG(kind,...) GNUNET_log_from (kind, "gns-api",__VA_ARGS__)

GNUNET_NETWORK_STRUCT_BEGIN


/**
 * Internal format of a record in the serialized form.
 */
struct NetworkRecord
{

  /**
   * Expiration time for the DNS record; relative or absolute depends
   * on 'flags', network byte order.
   */
  uint64_t expiration_time GNUNET_PACKED;

  /**
   * Number of bytes in 'data', network byte order.
   */
  uint32_t data_size GNUNET_PACKED;

  /**
   * Type of the GNS/DNS record, network byte order.
   */
  uint32_t record_type GNUNET_PACKED;

  /**
   * Flags for the record, network byte order.
   */
  uint32_t flags GNUNET_PACKED;
  
};

GNUNET_NETWORK_STRUCT_END

/**
 * Convert a UTF-8 string to UTF-8 lowercase
 * @param src source string
 * @return converted result
 */
char *
GNUNET_NAMESTORE_normalize_string (const char *src)
{
  GNUNET_assert (NULL != src);
  char *res = strdup (src);
  /* normalize */
  GNUNET_STRINGS_utf8_tolower(src, &res);
  return res;
}


/**
 * Convert a zone key to a string (for printing debug messages).
 * This is one of the very few calls in the entire API that is
 * NOT reentrant!
 *
 * @param z the zone key
 * @return string form; will be overwritten by next call to #GNUNET_NAMESTORE_z2s
 */
const char *
GNUNET_NAMESTORE_z2s (const struct GNUNET_CRYPTO_EccPublicKey *z)
{
  static char buf[sizeof (struct GNUNET_CRYPTO_EccPublicKey) * 8];
  char *end;

  end = GNUNET_STRINGS_data_to_string ((const unsigned char *) z, 
				       sizeof (struct GNUNET_CRYPTO_EccPublicKey),
				       buf, sizeof (buf));
  if (NULL == end)
  {
    GNUNET_break (0);
    return NULL;
  }
  *end = '\0';
  return buf;
}


/**
 * Calculate how many bytes we will need to serialize the given
 * records.
 *
 * @param rd_count number of records in the rd array
 * @param rd array of #GNUNET_NAMESTORE_RecordData with @a rd_count elements
 * @return the required size to serialize
 */
size_t
GNUNET_NAMESTORE_records_get_size (unsigned int rd_count,
				   const struct GNUNET_NAMESTORE_RecordData *rd)
{
  unsigned int i;
  size_t ret;

  ret = sizeof (struct NetworkRecord) * rd_count;
  for (i=0;i<rd_count;i++)
  {
    GNUNET_assert ((ret + rd[i].data_size) >= ret);
    ret += rd[i].data_size;
  }
  return ret;  
}


/**
 * Serialize the given records to the given destination buffer.
 *
 * @param rd_count number of records in the rd array
 * @param rd array of #GNUNET_NAMESTORE_RecordData with @a rd_count elements
 * @param dest_size size of the destination array
 * @param dest where to write the result
 * @return the size of serialized records, -1 if records do not fit
 */
ssize_t
GNUNET_NAMESTORE_records_serialize (unsigned int rd_count,
				    const struct GNUNET_NAMESTORE_RecordData *rd,
				    size_t dest_size,
				    char *dest)
{
  struct NetworkRecord rec;
  unsigned int i;
  size_t off;
  
  off = 0;
  for (i=0;i<rd_count;i++)
  {
    rec.expiration_time = GNUNET_htonll (rd[i].expiration_time);
    rec.data_size = htonl ((uint32_t) rd[i].data_size);
    rec.record_type = htonl (rd[i].record_type);
    rec.flags = htonl (rd[i].flags);
    if (off + sizeof (rec) > dest_size)
      return -1;
    memcpy (&dest[off], &rec, sizeof (rec));
    off += sizeof (rec);
    if (off + rd[i].data_size > dest_size)
      return -1;
    memcpy (&dest[off], rd[i].data, rd[i].data_size);
    off += rd[i].data_size;
  }
  return off;
}


/**
 * Compares if two records are equal (ignoring flags such
 * as authority, private and pending, but not relative vs.
 * absolute expiration time).
 *
 * @param a record
 * @param b record
 * @return #GNUNET_YES if the records are equal or #GNUNET_NO if they are not
 */
int
GNUNET_NAMESTORE_records_cmp (const struct GNUNET_NAMESTORE_RecordData *a,
                              const struct GNUNET_NAMESTORE_RecordData *b)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
      "Comparing records\n");
  if (a->record_type != b->record_type)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
        "Record type %lu != %lu\n", a->record_type, b->record_type);
    return GNUNET_NO;
  }
  if ((a->expiration_time != b->expiration_time) &&
      ((a->expiration_time != 0) && (b->expiration_time != 0)))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
        "Expiration time %llu != %llu\n", a->expiration_time, b->expiration_time);
    return GNUNET_NO;
  }
  if ((a->flags & GNUNET_NAMESTORE_RF_RCMP_FLAGS) 
       != (b->flags & GNUNET_NAMESTORE_RF_RCMP_FLAGS))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
        "Flags %lu (%lu) != %lu (%lu)\n", a->flags,
        a->flags & GNUNET_NAMESTORE_RF_RCMP_FLAGS, b->flags,
        b->flags & GNUNET_NAMESTORE_RF_RCMP_FLAGS);
    return GNUNET_NO;
  }
  if (a->data_size != b->data_size)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
        "Data size %lu != %lu\n", a->data_size, b->data_size);
    return GNUNET_NO;
  }
  if (0 != memcmp (a->data, b->data, a->data_size))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
        "Data contents do not match\n");
    return GNUNET_NO;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
      "Records are equal\n");
  return GNUNET_YES;
}


/**
 * Deserialize the given records to the given destination.
 *
 * @param len size of the serialized record data
 * @param src the serialized record data
 * @param rd_count number of records in the rd array
 * @param dest where to put the data
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on error
 */
int
GNUNET_NAMESTORE_records_deserialize (size_t len,
				      const char *src,
				      unsigned int rd_count,
				      struct GNUNET_NAMESTORE_RecordData *dest)
{
  struct NetworkRecord rec;
  unsigned int i;
  size_t off;
  
  off = 0;
  for (i=0;i<rd_count;i++)
  {
    if (off + sizeof (rec) > len)
      return GNUNET_SYSERR;
    memcpy (&rec, &src[off], sizeof (rec));
    dest[i].expiration_time = GNUNET_ntohll (rec.expiration_time);
    dest[i].data_size = ntohl ((uint32_t) rec.data_size);
    dest[i].record_type = ntohl (rec.record_type);
    dest[i].flags = ntohl (rec.flags);
    off += sizeof (rec);

    if (off + dest[i].data_size > len)
      return GNUNET_SYSERR;
    dest[i].data = &src[off];
    off += dest[i].data_size;
  }
  return GNUNET_OK; 
}


/**
 * Returns the expiration time of the given block of records. The block
 * expiration time is the expiration time of the block with smallest
 * expiration time.
 *
 * @param rd_count number of records given in @a rd
 * @param rd array of records
 * @return absolute expiration time
 */
struct GNUNET_TIME_Absolute
GNUNET_NAMESTORE_record_get_expiration_time (unsigned int rd_count, 
					     const struct GNUNET_NAMESTORE_RecordData *rd)
{
  unsigned int c;
  struct GNUNET_TIME_Absolute expire;
  struct GNUNET_TIME_Absolute at;
  struct GNUNET_TIME_Relative rt;

  if (NULL == rd)
    return GNUNET_TIME_UNIT_ZERO_ABS;
  expire = GNUNET_TIME_UNIT_FOREVER_ABS;
  for (c = 0; c < rd_count; c++)  
  {
    if (0 != (rd[c].flags & GNUNET_NAMESTORE_RF_RELATIVE_EXPIRATION))
    {
      rt.rel_value_us = rd[c].expiration_time;
      at = GNUNET_TIME_relative_to_absolute (rt);
    }
    else
    {
      at.abs_value_us = rd[c].expiration_time;
    }
    expire = GNUNET_TIME_absolute_min (at, expire);  
  }
  return expire;
}


/**
 * Sign name and records
 *
 * @param key the private key
 * @param expire block expiration
 * @param label the name for the records
 * @param rd record data
 * @param rd_count number of records
 */
struct GNUNET_NAMESTORE_Block *
GNUNET_NAMESTORE_block_create (const struct GNUNET_CRYPTO_EccPrivateKey *key,
			       struct GNUNET_TIME_Absolute expire,
			       const char *label,
			       const struct GNUNET_NAMESTORE_RecordData *rd,
			       unsigned int rd_count)
{
  GNUNET_break (0);
  return NULL;
}


/**
 * Check if a signature is valid.  This API is used by the GNS Block
 * to validate signatures received from the network.
 *
 * @param block block to verify
 * @return #GNUNET_OK if the signature is valid
 */
int
GNUNET_NAMESTORE_block_verify (const struct GNUNET_NAMESTORE_Block *block)
{
  GNUNET_break (0);
  return GNUNET_SYSERR;
}


/**
 * Decrypt block.
 *
 * @param block block to decrypt
 * @param zone_key public key of the zone
 * @param label the name for the records
 * @param proc function to call with the result
 * @param proc_cls closure for proc
 * @return #GNUNET_OK on success, #GNUNET_SYSERR if the block was 
 *        not well-formed
 */
int
GNUNET_NAMESTORE_block_decrypt (const struct GNUNET_NAMESTORE_Block *block,
				const struct GNUNET_CRYPTO_EccPublicKey *zone_key,
				const char *label,
				GNUNET_NAMESTORE_RecordCallback proc,
				void *proc_cls)
{
  GNUNET_break (0);
  return GNUNET_SYSERR;
}


#if OLD
/**
 * Sign name and records
 *
 * @param key the private key
 * @param expire block expiration
 * @param name the name
 * @param rd record data
 * @param rd_count number of records
 * @param signature where to store the signature
 */
void
GNUNET_NAMESTORE_create_signature (const struct GNUNET_CRYPTO_EccPrivateKey *key,
				   struct GNUNET_TIME_Absolute expire,
				   const char *name,
				   const struct GNUNET_NAMESTORE_RecordData *rd,
				   unsigned int rd_count,
				   struct GNUNET_CRYPTO_EccSignature *signature)
				   
{
  struct GNUNET_CRYPTO_EccPrivateKey *dkey;
  struct GNUNET_CRYPTO_EccSignaturePurpose *sig_purpose;
  struct GNUNET_TIME_AbsoluteNBO expire_nbo;
  size_t rd_ser_len;
  size_t name_len;
  struct GNUNET_TIME_AbsoluteNBO *expire_tmp;
  char * name_tmp;
  char * rd_tmp;
  int res;
  uint32_t sig_len;

  dkey = GNUNET_CRYPTO_ecc_key_derive (key, name, "gns");
  name_len = strlen (name) + 1;
  expire_nbo = GNUNET_TIME_absolute_hton (expire);
  rd_ser_len = GNUNET_NAMESTORE_records_get_size (rd_count, rd);
  {
    char rd_ser[rd_ser_len];

    GNUNET_assert (rd_ser_len ==
		   GNUNET_NAMESTORE_records_serialize (rd_count, rd, rd_ser_len, rd_ser));
    sig_len = sizeof (struct GNUNET_CRYPTO_EccSignaturePurpose) + sizeof (struct GNUNET_TIME_AbsoluteNBO) + rd_ser_len + name_len;
    sig_purpose = GNUNET_malloc (sig_len);
    sig_purpose->size = htonl (sig_len);
    sig_purpose->purpose = htonl (GNUNET_SIGNATURE_PURPOSE_GNS_RECORD_SIGN);
    expire_tmp = (struct GNUNET_TIME_AbsoluteNBO *) &sig_purpose[1];
    memcpy (expire_tmp, &expire_nbo, sizeof (struct GNUNET_TIME_AbsoluteNBO));
    name_tmp = (char *) &expire_tmp[1];
    memcpy (name_tmp, name, name_len);
    rd_tmp = &name_tmp[name_len];
    memcpy (rd_tmp, rd_ser, rd_ser_len);
    GNUNET_assert (GNUNET_OK ==
		   GNUNET_CRYPTO_ecc_sign (dkey, sig_purpose, signature));
    GNUNET_free (sig_purpose);
  }
  GNUNET_CRYPTO_ecc_key_free (dkey);
}


/**
 * Check if a signature is valid.  This API is used by the GNS Block
 * to validate signatures received from the network.
 *
 * @param derived_key derived key of the zone and the label
 * @param freshness time set for block expiration
 * @param rd_count number of entries in 'rd' array
 * @param rd array of records with data to store
 * @param signature signature for all the records in the zone under the given name
 * @return GNUNET_OK if the signature is valid
 */
int
GNUNET_NAMESTORE_verify_signature (const struct GNUNET_CRYPTO_EccPublicKey *derived_key,
                                   const struct GNUNET_TIME_Absolute freshness,
                                   unsigned int rd_count,
                                   const struct GNUNET_NAMESTORE_RecordData *rd,
                                   const struct GNUNET_CRYPTO_EccSignature *signature)
{
  size_t rd_ser_len;
  size_t name_len;
  char *name_tmp;
  char *rd_ser;
  struct GNUNET_CRYPTO_EccSignaturePurpose *sig_purpose;
  struct GNUNET_TIME_AbsoluteNBO *expire_tmp;
  struct GNUNET_TIME_AbsoluteNBO expire_nbo = GNUNET_TIME_absolute_hton (freshness);
  uint32_t sig_len;

  GNUNET_assert (NULL != public_key);
  GNUNET_assert (NULL != name);
  GNUNET_assert (NULL != rd);
  GNUNET_assert (NULL != signature);
  name_len = strlen (name) + 1;
  if (name_len > MAX_NAME_LEN)
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  rd_ser_len = GNUNET_NAMESTORE_records_get_size (rd_count, rd);
  sig_len = sizeof (struct GNUNET_CRYPTO_EccSignaturePurpose) + sizeof (struct GNUNET_TIME_AbsoluteNBO) + rd_ser_len + name_len;
  {
    char sig_buf[sig_len] GNUNET_ALIGN;

    sig_purpose = (struct GNUNET_CRYPTO_EccSignaturePurpose *) sig_buf;
    sig_purpose->size = htonl (sig_len);
    sig_purpose->purpose = htonl (GNUNET_SIGNATURE_PURPOSE_GNS_RECORD_SIGN);
    expire_tmp = (struct GNUNET_TIME_AbsoluteNBO *) &sig_purpose[1];
    memcpy (expire_tmp, &expire_nbo, sizeof (struct GNUNET_TIME_AbsoluteNBO));
    name_tmp = (char *) &expire_tmp[1];
    memcpy (name_tmp, name, name_len);
    rd_ser = &name_tmp[name_len];
    GNUNET_assert (rd_ser_len ==
		   GNUNET_NAMESTORE_records_serialize (rd_count, rd, rd_ser_len, rd_ser));
    return GNUNET_CRYPTO_ecc_verify (GNUNET_SIGNATURE_PURPOSE_GNS_RECORD_SIGN, sig_purpose, signature, public_key);
  }
}
#endif


/**
 * Convert the 'value' of a record to a string.
 *
 * @param type type of the record
 * @param data value in binary encoding
 * @param data_size number of bytes in data
 * @return NULL on error, otherwise human-readable representation of the value
 */
char *
GNUNET_NAMESTORE_value_to_string (uint32_t type,
				  const void *data,
				  size_t data_size)
{
  uint16_t mx_pref;
  const struct soa_data *soa;
  const struct vpn_data *vpn;
  const struct srv_data *srv;
  const struct tlsa_data *tlsa;
  struct GNUNET_CRYPTO_HashAsciiEncoded s_peer;
  const char *cdata;
  char* vpn_str;
  char* srv_str;
  char* tlsa_str;
  char* result;
  const char* soa_rname;
  const char* soa_mname;
  char tmp[INET6_ADDRSTRLEN];

  switch (type)
  {
  case 0:
    return NULL;
  case GNUNET_DNSPARSER_TYPE_A:
    if (data_size != sizeof (struct in_addr))
      return NULL;
    if (NULL == inet_ntop (AF_INET, data, tmp, sizeof (tmp)))
      return NULL;
    return GNUNET_strdup (tmp);
  case GNUNET_DNSPARSER_TYPE_NS:
    return GNUNET_strndup (data, data_size);
  case GNUNET_DNSPARSER_TYPE_CNAME:
    return GNUNET_strndup (data, data_size);
  case GNUNET_DNSPARSER_TYPE_SOA:
    if (data_size <= sizeof (struct soa_data))
      return NULL;
    soa = data;
    soa_rname = (const char*) &soa[1];
    soa_mname = memchr (soa_rname, 0, data_size - sizeof (struct soa_data) - 1);
    if (NULL == soa_mname)
      return NULL;
    soa_mname++;
    if (NULL == memchr (soa_mname, 0, 
			data_size - (sizeof (struct soa_data) + strlen (soa_rname) + 1)))
      return NULL;
    GNUNET_asprintf (&result, 
		     "rname=%s mname=%s %lu,%lu,%lu,%lu,%lu",
		     soa_rname, soa_mname,
		     ntohl (soa->serial), 
		     ntohl (soa->refresh),
		     ntohl (soa->retry), 
		     ntohl (soa->expire),
		     ntohl (soa->minimum));
    return result;
  case GNUNET_DNSPARSER_TYPE_PTR:
    return GNUNET_strndup (data, data_size);
  case GNUNET_DNSPARSER_TYPE_MX:
    mx_pref = ntohs(*((uint16_t*)data));
    if (GNUNET_asprintf(&result, "%hu,%s", mx_pref, data+sizeof(uint16_t))
        != 0)
      return result;
    else
    {
      GNUNET_free (result);
      return NULL;
    }
  case GNUNET_DNSPARSER_TYPE_TXT:
    return GNUNET_strndup (data, data_size);
  case GNUNET_DNSPARSER_TYPE_AAAA:
    if (data_size != sizeof (struct in6_addr))
      return NULL;
    if (NULL == inet_ntop (AF_INET6, data, tmp, sizeof (tmp)))
      return NULL;
    return GNUNET_strdup (tmp);
  case GNUNET_NAMESTORE_TYPE_PKEY:
    if (data_size != sizeof (struct GNUNET_CRYPTO_EccPublicKey))
      return NULL;
    return GNUNET_CRYPTO_ecc_public_key_to_string (data);
  case GNUNET_NAMESTORE_TYPE_PSEU:
    return GNUNET_strndup (data, data_size);
  case GNUNET_NAMESTORE_TYPE_LEHO:
    return GNUNET_strndup (data, data_size);
  case GNUNET_NAMESTORE_TYPE_VPN:
    cdata = data;
    if ( (data_size <= sizeof (struct vpn_data)) ||
	 ('\0' != cdata[data_size - 1]) )
      return NULL; /* malformed */
    vpn = data;
    GNUNET_CRYPTO_hash_to_enc (&vpn->peer, &s_peer);
    if (0 == GNUNET_asprintf (&vpn_str, "%u %s %s",
			      (unsigned int) ntohs (vpn->proto),
			      (const char*) &s_peer,
			      (const char*) &vpn[1]))
    {
      GNUNET_free (vpn_str);
      return NULL;
    }
    return vpn_str;
  case GNUNET_DNSPARSER_TYPE_SRV:
    cdata = data;
    if ( (data_size <= sizeof (struct srv_data)) ||
	 ('\0' != cdata[data_size - 1]) )
      return NULL; /* malformed */
    srv = data;

    if (0 == GNUNET_asprintf (&srv_str, 
			      "%d %d %d %s",
			      ntohs (srv->prio),
			      ntohs (srv->weight),
			      ntohs (srv->port),
			      (const char *)&srv[1]))
    {
      GNUNET_free (srv_str);
      return NULL;
    }
    return srv_str;
  case GNUNET_DNSPARSER_TYPE_TLSA:
    cdata = data;
    if ( (data_size <= sizeof (struct tlsa_data)) ||
	 ('\0' != cdata[data_size - 1]) )
      return NULL; /* malformed */
    tlsa = data;
    if (0 == GNUNET_asprintf (&tlsa_str, 
			      "%c %c %c %s",
			      tlsa->usage,
			      tlsa->selector,
			      tlsa->matching_type,
			      (const char *) &tlsa[1]))
    {
      GNUNET_free (tlsa_str);
      return NULL;
    }
    return tlsa_str;
  default:
    GNUNET_break (0);
  }
  GNUNET_break (0); // not implemented
  return NULL;
}


/**
 * Convert human-readable version of a 'value' of a record to the binary
 * representation.
 *
 * @param type type of the record
 * @param s human-readable string
 * @param data set to value in binary encoding (will be allocated)
 * @param data_size set to number of bytes in data
 * @return GNUNET_OK on success
 */
int
GNUNET_NAMESTORE_string_to_value (uint32_t type,
				  const char *s,
				  void **data,
				  size_t *data_size)
{
  struct in_addr value_a;
  struct in6_addr value_aaaa;
  struct GNUNET_CRYPTO_EccPublicKey pkey;
  struct soa_data *soa;
  struct vpn_data *vpn;
  struct tlsa_data *tlsa;
  char result[253 + 1];
  char soa_rname[253 + 1];
  char soa_mname[253 + 1];
  char s_peer[103 + 1];
  char s_serv[253 + 1];
  unsigned int soa_serial;
  unsigned int soa_refresh;
  unsigned int soa_retry;
  unsigned int soa_expire;
  unsigned int soa_min;
  uint16_t mx_pref;
  uint16_t mx_pref_n;
  unsigned int proto;
  
  if (NULL == s)
    return GNUNET_SYSERR;
  switch (type)
  {
  case 0:
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		_("Unsupported record type %d\n"),
		(int) type);
    return GNUNET_SYSERR;
  case GNUNET_DNSPARSER_TYPE_A:
    if (1 != inet_pton (AF_INET, s, &value_a))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  _("Unable to parse IPv4 address `%s'\n"),
		  s);
      return GNUNET_SYSERR;
    }
    *data = GNUNET_malloc (sizeof (struct in_addr));
    memcpy (*data, &value_a, sizeof (value_a));
    *data_size = sizeof (value_a);
    return GNUNET_OK;
  case GNUNET_DNSPARSER_TYPE_NS:
    *data = GNUNET_strdup (s);
    *data_size = strlen (s) + 1;
    return GNUNET_OK;
  case GNUNET_DNSPARSER_TYPE_CNAME:
    *data = GNUNET_strdup (s);
    *data_size = strlen (s) + 1;
    return GNUNET_OK;
  case GNUNET_DNSPARSER_TYPE_SOA:
    if (7 != SSCANF (s, 
		     "rname=%253s mname=%253s %u,%u,%u,%u,%u",
		     soa_rname, soa_mname,
		     &soa_serial, &soa_refresh, &soa_retry, &soa_expire, &soa_min))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  _("Unable to parse SOA record `%s'\n"),
		  s);
      return GNUNET_SYSERR;
    }
    *data_size = sizeof (struct soa_data)+strlen(soa_rname)+strlen(soa_mname)+2;
    *data = GNUNET_malloc (*data_size);
    soa = (struct soa_data*)*data;
    soa->serial = htonl(soa_serial);
    soa->refresh = htonl(soa_refresh);
    soa->retry = htonl(soa_retry);
    soa->expire = htonl(soa_expire);
    soa->minimum = htonl(soa_min);
    strcpy((char*)&soa[1], soa_rname);
    strcpy((char*)&soa[1]+strlen(*data)+1, soa_mname);
    return GNUNET_OK;
  case GNUNET_DNSPARSER_TYPE_PTR:
    *data = GNUNET_strdup (s);
    *data_size = strlen (s);
    return GNUNET_OK;
  case GNUNET_DNSPARSER_TYPE_MX:
    if (2 != SSCANF(s, "%hu,%253s", &mx_pref, result))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  _("Unable to parse MX record `%s'\n"),
		  s);
      return GNUNET_SYSERR;
    }
    *data_size = sizeof (uint16_t)+strlen(result)+1;
    *data = GNUNET_malloc (*data_size);
    mx_pref_n = htons(mx_pref);
    memcpy(*data, &mx_pref_n, sizeof (uint16_t));
    strcpy((*data)+sizeof (uint16_t), result);
    return GNUNET_OK;
  case GNUNET_DNSPARSER_TYPE_TXT:
    *data = GNUNET_strdup (s);
    *data_size = strlen (s);
    return GNUNET_OK;
  case GNUNET_DNSPARSER_TYPE_AAAA:
    if (1 != inet_pton (AF_INET6, s, &value_aaaa))    
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  _("Unable to parse IPv6 address `%s'\n"),
		  s);
      return GNUNET_SYSERR;
    }
    *data = GNUNET_malloc (sizeof (struct in6_addr));
    *data_size = sizeof (struct in6_addr);
    memcpy (*data, &value_aaaa, sizeof (value_aaaa));
    return GNUNET_OK;
  case GNUNET_NAMESTORE_TYPE_PKEY:
    if (GNUNET_OK !=
	GNUNET_CRYPTO_ecc_public_key_from_string (s, strlen (s), &pkey))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  _("Unable to parse PKEY record `%s'\n"),
		  s);
      return GNUNET_SYSERR;
    }
    *data = GNUNET_new (struct GNUNET_CRYPTO_EccPublicKey);
    memcpy (*data, &pkey, sizeof (pkey));
    *data_size = sizeof (struct GNUNET_CRYPTO_EccPublicKey);
    return GNUNET_OK;
  case GNUNET_NAMESTORE_TYPE_PSEU:
    *data = GNUNET_strdup (s);
    *data_size = strlen (s);
    return GNUNET_OK;
  case GNUNET_NAMESTORE_TYPE_LEHO:
    *data = GNUNET_strdup (s);
    *data_size = strlen (s);
    return GNUNET_OK;
  case GNUNET_NAMESTORE_TYPE_VPN:
    if (3 != SSCANF (s,"%u %103s %253s",
		     &proto, s_peer, s_serv))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  _("Unable to parse VPN record string `%s'\n"),
		  s);
      return GNUNET_SYSERR;
    }
    *data_size = sizeof (struct vpn_data) + strlen (s_serv) + 1;
    *data = vpn = GNUNET_malloc (*data_size);
    if (GNUNET_OK != GNUNET_CRYPTO_hash_from_string ((char*)&s_peer,
						     &vpn->peer))
    {
      GNUNET_free (vpn);
      *data_size = 0;
      return GNUNET_SYSERR;
    }
    vpn->proto = htons ((uint16_t) proto);
    strcpy ((char*)&vpn[1], s_serv);
    return GNUNET_OK;
  case GNUNET_DNSPARSER_TYPE_TLSA:
    *data_size = sizeof (struct tlsa_data) + strlen (s) - 6;
    *data = tlsa = GNUNET_malloc (*data_size);
    if (4 != SSCANF (s, "%c %c %c %s",
		     &tlsa->usage,
		     &tlsa->selector,
		     &tlsa->matching_type,
		     (char*)&tlsa[1]))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  _("Unable to parse TLSA record string `%s'\n"), 
		  s);
      *data_size = 0;
      GNUNET_free (tlsa);
      return GNUNET_SYSERR;
    }
    return GNUNET_OK;
  default:
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		_("Unsupported record type %d\n"),
		(int) type);
    return GNUNET_SYSERR;
  }
}


/**
 * Mapping of record type numbers to human-readable
 * record type names.
 */
static struct { 
  const char *name; 
  uint32_t number; 
} name_map[] = {
  { "A", GNUNET_DNSPARSER_TYPE_A },
  { "NS", GNUNET_DNSPARSER_TYPE_NS },
  { "CNAME", GNUNET_DNSPARSER_TYPE_CNAME },
  { "SOA", GNUNET_DNSPARSER_TYPE_SOA },
  { "PTR", GNUNET_DNSPARSER_TYPE_PTR },
  { "MX", GNUNET_DNSPARSER_TYPE_MX },
  { "TXT", GNUNET_DNSPARSER_TYPE_TXT },
  { "AAAA", GNUNET_DNSPARSER_TYPE_AAAA },
  { "PKEY",  GNUNET_NAMESTORE_TYPE_PKEY },
  { "PSEU",  GNUNET_NAMESTORE_TYPE_PSEU },
  { "LEHO",  GNUNET_NAMESTORE_TYPE_LEHO },
  { "VPN", GNUNET_NAMESTORE_TYPE_VPN },
  { "TLSA", GNUNET_DNSPARSER_TYPE_TLSA },
  { NULL, UINT32_MAX }
};


/**
 * Convert a type name (i.e. "AAAA") to the corresponding number.
 *
 * @param typename name to convert
 * @return corresponding number, UINT32_MAX on error
 */
uint32_t
GNUNET_NAMESTORE_typename_to_number (const char *typename)
{
  unsigned int i;

  i=0;
  while ( (name_map[i].name != NULL) &&
	  (0 != strcasecmp (typename, name_map[i].name)) )
    i++;
  return name_map[i].number;  
}


/**
 * Convert a type number (i.e. 1) to the corresponding type string (i.e. "A")
 *
 * @param type number of a type to convert
 * @return corresponding typestring, NULL on error
 */
const char *
GNUNET_NAMESTORE_number_to_typename (uint32_t type)
{
  unsigned int i;

  i=0;
  while ( (name_map[i].name != NULL) &&
	  (type != name_map[i].number) )
    i++;
  return name_map[i].name;  
}


/**
 * Test if a given record is expired.
 * 
 * @return #GNUNET_YES if the record is expired,
 *         #GNUNET_NO if not
 */
int
GNUNET_NAMESTORE_is_expired (const struct GNUNET_NAMESTORE_RecordData *rd)
{
  struct GNUNET_TIME_Absolute at;

  if (0 != (rd->flags & GNUNET_NAMESTORE_RF_RELATIVE_EXPIRATION))
    return GNUNET_NO;
  at.abs_value_us = rd->expiration_time;
  return (0 == GNUNET_TIME_absolute_get_remaining (at).rel_value_us) ? GNUNET_YES : GNUNET_NO;
}


/**
 * Calculate the DHT query for a given @a label in a given @a zone.
 * 
 * @param zone private key of the zone
 * @param label label of the record
 * @param query hash to use for the query
 */
void
GNUNET_NAMESTORE_query_from_private_key (const struct GNUNET_CRYPTO_EccPrivateKey *zone,
					 const char *label,
					 struct GNUNET_HashCode *query)
{
  struct GNUNET_CRYPTO_EccPublicKey pub;

  GNUNET_CRYPTO_ecc_key_get_public (zone, &pub);
  GNUNET_NAMESTORE_query_from_public_key (&pub, label, query);
}


/**
 * Calculate the DHT query for a given @a label in a given @a zone.
 * 
 * @param pub public key of the zone
 * @param label label of the record
 * @param query hash to use for the query
 */
void
GNUNET_NAMESTORE_query_from_public_key (const struct GNUNET_CRYPTO_EccPublicKey *pub,
					const char *label,
					struct GNUNET_HashCode *query)
{
  struct GNUNET_CRYPTO_EccPublicKey pd;

  GNUNET_CRYPTO_ecc_public_key_derive (pub, label, "gns", &pd);
  GNUNET_CRYPTO_hash (&pd, sizeof (pd), query);
}


/* end of namestore_common.c */

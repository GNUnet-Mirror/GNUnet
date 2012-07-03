/*
     This file is part of GNUnet.
     (C) 2009, 2010, 2012 Christian Grothoff (and other contributing authors)

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
 * @file namestore/namestore_common.c
 * @brief API to access the NAMESTORE service
 * @author Martin Schanzenbach
 * @author Matthias Wachs
 */

#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_constants.h"
#include "gnunet_signatures.h"
#include "gnunet_arm_service.h"
#include "gnunet_namestore_service.h"
#include "gnunet_dnsparser_lib.h"
#include "../dns/dnsparser.h"
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
 * Convert a short hash to a string (for printing debug messages).
 * This is one of the very few calls in the entire API that is
 * NOT reentrant!
 *
 * @param hc the short hash code
 * @return string form; will be overwritten by next call to GNUNET_h2s.
 */
const char *
GNUNET_short_h2s (const struct GNUNET_CRYPTO_ShortHashCode * hc)
{
  static struct GNUNET_CRYPTO_ShortHashAsciiEncoded ret;

  GNUNET_CRYPTO_short_hash_to_enc (hc, &ret);
  return (const char *) &ret;
}


/**
 * Calculate how many bytes we will need to serialize the given
 * records.
 *
 * @param rd_count number of records in the rd array
 * @param rd array of GNUNET_NAMESTORE_RecordData with rd_count elements
 *
 * @return the required size to serialize
 *
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
 * @param rd array of GNUNET_NAMESTORE_RecordData with rd_count elements
 * @param dest_size size of the destination array
 * @param dest where to write the result
 *
 * @return the size of serialized records
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
 * @return GNUNET_YES if the records are equal or GNUNET_NO if they are not
 */
int
GNUNET_NAMESTORE_records_cmp (const struct GNUNET_NAMESTORE_RecordData *a,
                              const struct GNUNET_NAMESTORE_RecordData *b)
{
  if ((a->record_type == b->record_type) &&
      (a->expiration_time == b->expiration_time) &&
      ((a->flags & GNUNET_NAMESTORE_RF_RCMP_FLAGS) 
       == (b->flags & GNUNET_NAMESTORE_RF_RCMP_FLAGS) ) &&
      (a->data_size == b->data_size) &&
      (0 == memcmp (a->data, b->data, a->data_size)))
    return GNUNET_YES;
  return GNUNET_NO;
}


/**
 * Deserialize the given records to the given destination.
 *
 * @param len size of the serialized record data
 * @param src the serialized record data
 * @param rd_count number of records in the rd array
 * @param dest where to put the data
 *
 * @return GNUNET_OK on success, GNUNET_SYSERR on error
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
 * Sign name and records
 *
 * @param key the private key
 * @param expire block expiration
 * @param name the name
 * @param rd record data
 * @param rd_count number of records
 *
 * @return the signature
 */
struct GNUNET_CRYPTO_RsaSignature *
GNUNET_NAMESTORE_create_signature (const struct GNUNET_CRYPTO_RsaPrivateKey *key,
				   struct GNUNET_TIME_Absolute expire,
				   const char *name,
				   const struct GNUNET_NAMESTORE_RecordData *rd,
				   unsigned int rd_count)
{
  struct GNUNET_CRYPTO_RsaSignature *sig;
  struct GNUNET_CRYPTO_RsaSignaturePurpose *sig_purpose;
  struct GNUNET_TIME_AbsoluteNBO expire_nbo;
  size_t rd_ser_len;
  size_t name_len;
  struct GNUNET_TIME_AbsoluteNBO *expire_tmp;
  char * name_tmp;
  char * rd_tmp;
  int res;
  uint32_t sig_len;

  if (NULL == name)
  {
    GNUNET_break (0);
    return NULL;
  }
  sig = GNUNET_malloc (sizeof (struct GNUNET_CRYPTO_RsaSignature));
  name_len = strlen (name) + 1;
  expire_nbo = GNUNET_TIME_absolute_hton (expire);
  rd_ser_len = GNUNET_NAMESTORE_records_get_size (rd_count, rd);
  {
    char rd_ser[rd_ser_len];

    GNUNET_assert (rd_ser_len ==
		   GNUNET_NAMESTORE_records_serialize (rd_count, rd, rd_ser_len, rd_ser));
    sig_len = sizeof (struct GNUNET_CRYPTO_RsaSignaturePurpose) + sizeof (struct GNUNET_TIME_AbsoluteNBO) + rd_ser_len + name_len;
    sig_purpose = GNUNET_malloc (sig_len);
    sig_purpose->size = htonl (sig_len);
    sig_purpose->purpose = htonl (GNUNET_SIGNATURE_PURPOSE_GNS_RECORD_SIGN);
    expire_tmp = (struct GNUNET_TIME_AbsoluteNBO *) &sig_purpose[1];
    memcpy (expire_tmp, &expire_nbo, sizeof (struct GNUNET_TIME_AbsoluteNBO));
    name_tmp = (char *) &expire_tmp[1];
    memcpy (name_tmp, name, name_len);
    rd_tmp = &name_tmp[name_len];
    memcpy (rd_tmp, rd_ser, rd_ser_len);
    res = GNUNET_CRYPTO_rsa_sign (key, sig_purpose, sig);
    GNUNET_free (sig_purpose);
  }
  if (GNUNET_OK != res)
  {
    GNUNET_break (0);
    GNUNET_free (sig);
    return NULL;
  }
  return sig;
}

/**
 * Checks if a name is wellformed
 *
 * @param name the name to check
 * @return GNUNET_OK on success, GNUNET_SYSERR on error
 */
int
GNUNET_NAMESTORE_check_name (const char * name)
{
  if (name == NULL)
    return GNUNET_SYSERR;
  if (strlen (name) > 63)
    return GNUNET_SYSERR;
  return GNUNET_OK;
}


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
  char tmp[INET6_ADDRSTRLEN];
  struct GNUNET_CRYPTO_ShortHashAsciiEncoded enc;
  uint16_t mx_pref;
  char* result;
  char* soa_rname;
  char* soa_mname;
  struct soa_data *soa;

  struct vpn_data *vpn;
  char* vpn_str;
  char* srv_str;
  struct GNUNET_CRYPTO_HashAsciiEncoded s_peer;
  struct srv_data *srv;

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
    soa = (struct soa_data*)data;
    soa_rname = (char*)&soa[1];
    soa_mname = (char*)&soa[1]+strlen(soa_rname)+1;
    if (GNUNET_asprintf(&result, "rname=%s mname=%s %lu,%lu,%lu,%lu,%lu", 
                     soa_rname, soa_mname,
                     ntohl (soa->serial), ntohl (soa->refresh),
                     ntohl (soa->retry), ntohl (soa->expire), ntohl (soa->minimum)))
      return result;
    else
      return NULL;
  case GNUNET_DNSPARSER_TYPE_PTR:
    return GNUNET_strndup (data, data_size);
  case GNUNET_DNSPARSER_TYPE_MX:
    mx_pref = ntohs(*((uint16_t*)data));
    if (GNUNET_asprintf(&result, "%hu,%s", mx_pref, data+sizeof(uint16_t))
        != 0)
      return result;
    else
      return NULL;
  case GNUNET_DNSPARSER_TYPE_TXT:
    return GNUNET_strndup (data, data_size);
  case GNUNET_DNSPARSER_TYPE_AAAA:
    if (data_size != sizeof (struct in6_addr))
      return NULL;
    if (NULL == inet_ntop (AF_INET6, data, tmp, sizeof (tmp)))
      return NULL;
    return GNUNET_strdup (tmp);
  case GNUNET_NAMESTORE_TYPE_PKEY:
    if (data_size != sizeof (struct GNUNET_CRYPTO_ShortHashCode))
      return NULL;
    GNUNET_CRYPTO_short_hash_to_enc (data,
				     &enc);
    return GNUNET_strdup ((const char*) enc.short_encoding);
  case GNUNET_NAMESTORE_TYPE_PSEU:
    return GNUNET_strndup (data, data_size);
  case GNUNET_NAMESTORE_TYPE_LEHO:
    return GNUNET_strndup (data, data_size);
  case GNUNET_NAMESTORE_TYPE_VPN:
    vpn = (struct vpn_data*)data;

    GNUNET_CRYPTO_hash_to_enc (&vpn->peer, &s_peer);
    if (GNUNET_OK != GNUNET_asprintf (&vpn_str, "%hu %s %s",
                                      vpn->proto,
                                      (char*)&s_peer,
                                      (char*)&vpn[1]))
      return NULL;
    return vpn_str;
  case GNUNET_DNSPARSER_TYPE_SRV:
    srv = (struct srv_data*)data;

    if (GNUNET_OK != GNUNET_asprintf (&srv_str, "%d %d %d %s",
                                      ntohs (srv->prio),
                                      ntohs (srv->weight),
                                      ntohs (srv->port),
                                      (char*)&srv[1]))
      return NULL;
    return srv_str;
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
  struct GNUNET_CRYPTO_ShortHashCode pkey;
  uint16_t mx_pref;
  uint16_t mx_pref_n;
  struct soa_data *soa;
  char result[253];
  char soa_rname[63];
  char soa_mname[63];
  uint32_t soa_serial;
  uint32_t soa_refresh;
  uint32_t soa_retry;
  uint32_t soa_expire;
  uint32_t soa_min;
  char s_peer[104];
  char s_serv[253];
  struct vpn_data* vpn;
  uint16_t proto;
  int ret;
  
  switch (type)
  {
  case 0:
    return GNUNET_SYSERR;
  case GNUNET_DNSPARSER_TYPE_A:
    if (1 != inet_pton (AF_INET, s, &value_a))
      return GNUNET_SYSERR;
    *data = GNUNET_malloc (sizeof (struct in_addr));
    memcpy (*data, &value_a, sizeof (value_a));
    *data_size = sizeof (value_a);
    return GNUNET_OK;
  case GNUNET_DNSPARSER_TYPE_NS:
    *data = GNUNET_strdup (s);
    *data_size = strlen (s);
    return GNUNET_OK;
  case GNUNET_DNSPARSER_TYPE_CNAME:
    *data = GNUNET_strdup (s);
    *data_size = strlen (s);
    return GNUNET_OK;
  case GNUNET_DNSPARSER_TYPE_SOA:
    
    if (SSCANF(s, "rname=%s mname=%s %u,%u,%u,%u,%u",
               soa_rname, soa_mname,
               &soa_serial, &soa_refresh, &soa_retry, &soa_expire, &soa_min) 
        != 7)
      return GNUNET_SYSERR;
    
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
    if (SSCANF(s, "%hu,%s", &mx_pref, result) != 2)
      return GNUNET_SYSERR;
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
      return GNUNET_SYSERR;    
    *data = GNUNET_malloc (sizeof (struct in6_addr));
    *data_size = sizeof (struct in6_addr);
    memcpy (*data, &value_aaaa, sizeof (value_aaaa));
    return GNUNET_OK;
  case GNUNET_NAMESTORE_TYPE_PKEY:
    if (GNUNET_OK !=
	GNUNET_CRYPTO_short_hash_from_string (s, &pkey))
      return GNUNET_SYSERR;
    *data = GNUNET_malloc (sizeof (struct GNUNET_CRYPTO_ShortHashCode));
    memcpy (*data, &pkey, sizeof (pkey));
    *data_size = sizeof (struct GNUNET_CRYPTO_ShortHashCode);
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
    
    ret = SSCANF (s,"%hu %s %s",
                  &proto, s_peer, s_serv);
    if (3 != ret)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  "Unable to parse VPN record string %s %d\n", s, ret);
      return GNUNET_SYSERR;
    }
    *data_size = sizeof (struct vpn_data) + strlen (s_serv) + 1;
    
    *data = GNUNET_malloc (*data_size);

    vpn = (struct vpn_data*)*data;
    
    if (GNUNET_OK != GNUNET_CRYPTO_hash_from_string ((char*)&s_peer, &vpn->peer))
    {
      GNUNET_free (*data);
      return GNUNET_SYSERR;
    }

    vpn->proto = htons (proto);
    strcpy ((char*)&vpn[1], s_serv);
    return GNUNET_OK;
  default:
    GNUNET_break (0);
  }
  return GNUNET_SYSERR;
}


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
 * @return GNUNET_YES if the record is expired,
 *         GNUNET_NO if not
 */
int
GNUNET_NAMESTORE_is_expired (const struct GNUNET_NAMESTORE_RecordData *rd)
{
  struct GNUNET_TIME_Absolute at;

  if (0 != (rd->flags & GNUNET_NAMESTORE_RF_RELATIVE_EXPIRATION))
    return GNUNET_NO;
  at.abs_value = rd->expiration_time;
  return (0 == GNUNET_TIME_absolute_get_remaining (at).rel_value) ? GNUNET_YES : GNUNET_NO;
}


/* end of namestore_common.c */

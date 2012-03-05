/*
     This file is part of GNUnet.
     (C) 2009, 2010 Christian Grothoff (and other contributing authors)

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
#include "namestore.h"
#define DEBUG_GNS_API GNUNET_EXTRA_LOGGING

#define LOG(kind,...) GNUNET_log_from (kind, "gns-api",__VA_ARGS__)


/**
 * Internal format of a record in the serialized form.
 */
struct NetworkRecord
{

  /**
   * Expiration time for the DNS record.
   */
  struct GNUNET_TIME_AbsoluteNBO expiration;

  /**
   * Number of bytes in 'data', network byte order.
   */
  uint32_t data_size;

  /**
   * Type of the GNS/DNS record, network byte order.
   */
  uint32_t record_type;

  /**
   * Flags for the record, network byte order.
   */
  uint32_t flags;
  
};

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
    GNUNET_assert (ret + rd[i].data_size >= ret);
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
    rec.expiration = GNUNET_TIME_absolute_hton (rd[i].expiration);
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
 * Compares if two records are equal
 *
 * @param a record
 * @param b record
 *
 * @return GNUNET_YES or GNUNET_NO
 */
int
GNUNET_NAMESTORE_records_cmp (const struct GNUNET_NAMESTORE_RecordData *a,
                              const struct GNUNET_NAMESTORE_RecordData *b)
{
  if ((a->record_type == b->record_type) &&
      (a->expiration.abs_value == b->expiration.abs_value) &&
      (a->data_size == b->data_size) &&
      (0 == memcmp (a->data, b->data, a->data_size)))
    return GNUNET_YES;
  else
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
    dest[i].expiration = GNUNET_TIME_absolute_ntoh (rec.expiration);
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
 * @param name the name
 * @param rd record data
 * @param rd_count number of records
 *
 * @return the signature
 */
struct GNUNET_CRYPTO_RsaSignature *
GNUNET_NAMESTORE_create_signature (const struct GNUNET_CRYPTO_RsaPrivateKey *key,
    const char *name,
    struct GNUNET_NAMESTORE_RecordData *rd,
    unsigned int rd_count)
{
  struct GNUNET_CRYPTO_RsaSignature *sig = GNUNET_malloc(sizeof (struct GNUNET_CRYPTO_RsaSignature));
  struct GNUNET_CRYPTO_RsaSignaturePurpose *sig_purpose;
  size_t rd_ser_len;
  size_t name_len;
  char * name_tmp;
  char * rd_tmp;
  int res;

  if (name == NULL)
  {
    GNUNET_break (0);
    GNUNET_free (sig);
    return NULL;
  }
  name_len = strlen (name) + 1;

  rd_ser_len = GNUNET_NAMESTORE_records_get_size(rd_count, rd);
  char rd_ser[rd_ser_len];
  GNUNET_NAMESTORE_records_serialize(rd_count, rd, rd_ser_len, rd_ser);

  sig_purpose = GNUNET_malloc(sizeof (struct GNUNET_CRYPTO_RsaSignaturePurpose) + rd_ser_len + name_len);

  sig_purpose->size = htonl (sizeof (struct GNUNET_CRYPTO_RsaSignaturePurpose)+ rd_ser_len + name_len);
  sig_purpose->purpose = htonl (GNUNET_SIGNATURE_PURPOSE_GNS_RECORD_SIGN);
  name_tmp = (char *) &sig_purpose[1];
  rd_tmp = &name_tmp[name_len];
  memcpy (name_tmp, name, name_len);
  memcpy (rd_tmp, rd_ser, rd_ser_len);

  res = GNUNET_CRYPTO_rsa_sign (key, sig_purpose, sig);

  GNUNET_free (sig_purpose);

  if (GNUNET_OK != res)
  {
    GNUNET_break (0);
    GNUNET_free (sig);
    return NULL;
  }
  return sig;
}

/* end of namestore_api.c */

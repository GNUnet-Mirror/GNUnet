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
 * @param rd_count expected number of records in 'src'
 * @param dest array of 'rd_count' entries for storing record data;
 *         'data' values in 'dest' will point into 'src' and will thus
 *         become invalid if 'src' is modified
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

    if (off + sizeof (dest[i].data_size) > len)
      return GNUNET_SYSERR;
    dest[i].data = &src[off];
    off += dest[i].data_size;
  }
  return GNUNET_OK; 
}



#if 0

/**
 * Serialize an array of GNUNET_NAMESTORE_RecordData *rd to transmit over the
 * network
 *
 * @param dest where to write the serialized data
 * @param rd_count number of elements in array
 * @param rd array
 *
 * @return number of bytes written to destination dest
 */
size_t
GNUNET_NAMESTORE_records_serialize (char ** dest,
                             unsigned int rd_count,
                             const struct GNUNET_NAMESTORE_RecordData *rd)
{
  //size_t len = 0;
  struct GNUNET_NAMESTORE_NetworkRecord nr;
  char * d = (*dest);
  int c = 0;
  int offset;

  GNUNET_assert (rd != NULL);

  size_t total_len = rd_count * sizeof (struct GNUNET_NAMESTORE_NetworkRecord);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Struct size: %u\n", total_len);

  /* figure out total len required */
  for (c = 0; c < rd_count; c ++)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Data size record[%i] : %u\n", c, rd[c].data_size);
    total_len += rd[c].data_size;
  }

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Serializing %i records with total length of %llu\n", rd_count, total_len);

  (*dest) = GNUNET_malloc (total_len);
  d = (*dest);

  /* copy records */
  offset = 0;

  for (c = 0; c < rd_count; c ++)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Serialized record [%i]: data_size %i\n", c,rd[c].data_size);

    // nr = (struct GNUNET_NAMESTORE_NetworkRecord *) &d[offset];
    nr.data_size = htonl (rd[c].data_size);
    nr.flags = htonl (rd[c].flags);
    nr.record_type = htonl (rd[c].record_type);
    nr.expiration = GNUNET_TIME_absolute_hton(rd[c].expiration);
    memcpy (&d[offset], &nr, sizeof (nr));
    offset += sizeof (struct GNUNET_NAMESTORE_NetworkRecord);

    /*put data here */
    memcpy (&d[offset], rd[c].data, rd[c].data_size);
    offset += rd[c].data_size;
  }

  GNUNET_assert (offset == total_len);
  return total_len;
}

void
GNUNET_NAMESTORE_records_free (unsigned int rd_count, struct GNUNET_NAMESTORE_RecordData *rd)
{
  int c;
  if ((rd == NULL) || (rd_count == 0))
    return;

  for (c = 0; c < rd_count; c++)
    GNUNET_free_non_null ((void *) rd[c].data);
  GNUNET_free (rd);
}


/**
 * Deserialize an array of GNUNET_NAMESTORE_RecordData *rd after transmission
 * over the network
 *
 * @param source where to read the data to deserialize
 * @param rd_count number of elements in array
 * @param rd array
 *
 * @return number of elements deserialized
 */
int
GNUNET_NAMESTORE_records_deserialize ( struct GNUNET_NAMESTORE_RecordData **dest, char *src, size_t len)
{
  struct GNUNET_NAMESTORE_NetworkRecord * nr;
  struct GNUNET_NAMESTORE_RecordData *d = (*dest);
  int elements;
  size_t offset;
  uint32_t data_size;
  int c;

  if (len == 0)
  {
    (*dest) = NULL;
    return 0;
  }

  offset = 0;
  elements = 0;
  while (offset < len)
  {
    nr = (struct GNUNET_NAMESTORE_NetworkRecord *) &src[offset];
    offset += sizeof (struct GNUNET_NAMESTORE_NetworkRecord);

    data_size = ntohl (nr->data_size);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Datasize record[%i]: %u\n", elements, data_size);
    offset += data_size;
    elements ++;
  }

  if (elements == 0)
  {
    (*dest) = NULL;
    return 0;
  }


  GNUNET_assert (len == offset);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Deserializing %i records with total length of %u\n", elements, len);

  (*dest) = GNUNET_malloc (elements * sizeof (struct GNUNET_NAMESTORE_RecordData));
  d = (*dest);

  offset = 0;
  for (c = 0; c < elements; c++)
  {
    nr = (struct GNUNET_NAMESTORE_NetworkRecord *) &src[offset];
    d[c].expiration = GNUNET_TIME_absolute_ntoh(nr->expiration);
    d[c].record_type = ntohl (nr->record_type);
    d[c].flags = ntohl (nr->flags);
    d[c].data_size = ntohl (nr->data_size);
    if (d[c].data_size > 0)
      d[c].data = GNUNET_malloc (d[c].data_size);
    else
      d[c].data = NULL;

    offset += sizeof (struct GNUNET_NAMESTORE_NetworkRecord);
    memcpy((char *) d[c].data, &src[offset], d[c].data_size);

    offset += d[c].data_size;
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Deserialized record[%i] /w data_size %i\n", c, d[c].data_size);
  }
  GNUNET_assert(offset == len);

  return elements;
}

#endif

/* end of namestore_api.c */

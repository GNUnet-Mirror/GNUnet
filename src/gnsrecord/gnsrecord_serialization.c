/*
     This file is part of GNUnet.
     Copyright (C) 2009-2013 GNUnet e.V.

     GNUnet is free software: you can redistribute it and/or modify it
     under the terms of the GNU Affero General Public License as published
     by the Free Software Foundation, either version 3 of the License,
     or (at your option) any later version.

     GNUnet is distributed in the hope that it will be useful, but
     WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
     Affero General Public License for more details.
    
     You should have received a copy of the GNU Affero General Public License
     along with this program.  If not, see <http://www.gnu.org/licenses/>.

     SPDX-License-Identifier: AGPL3.0-or-later
*/

/**
 * @file gnsrecord/gnsrecord_serialization.c
 * @brief API to serialize and deserialize GNS records
 * @author Martin Schanzenbach
 * @author Matthias Wachs
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_constants.h"
#include "gnunet_signatures.h"
#include "gnunet_arm_service.h"
#include "gnunet_gnsrecord_lib.h"
#include "gnunet_dnsparser_lib.h"
#include "gnunet_tun_lib.h"


#define LOG(kind,...) GNUNET_log_from (kind, "gnsrecord",__VA_ARGS__)

/**
 * Set to 1 to check that all records are well-formed (can be converted
 * to string) during serialization/deserialization.
 */
#define DEBUG_GNSRECORDS 0

GNUNET_NETWORK_STRUCT_BEGIN


/**
 * Internal format of a record in the serialized form.
 */
struct NetworkRecord
{

  /**
   * Expiration time for the DNS record; relative or absolute depends
   * on @e flags, network byte order.
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
 * Calculate how many bytes we will need to serialize the given
 * records.
 *
 * @param rd_count number of records in the rd array
 * @param rd array of #GNUNET_GNSRECORD_Data with @a rd_count elements
 * @return the required size to serialize, -1 on error
 */
ssize_t
GNUNET_GNSRECORD_records_get_size (unsigned int rd_count,
				   const struct GNUNET_GNSRECORD_Data *rd)
{
  size_t ret;

  if (0 == rd_count)
    return 0;
  
  ret = sizeof (struct NetworkRecord) * rd_count;
  for (unsigned int i=0;i<rd_count;i++)
  {
    if ((ret + rd[i].data_size) < ret)
    {
      GNUNET_break (0);
      return -1;
    }
    ret += rd[i].data_size;
#if DEBUG_GNSRECORDS
    {
      char *str;

      str = GNUNET_GNSRECORD_value_to_string (rd[i].record_type,
                                              rd[i].data,
                                              rd[i].data_size);
      if (NULL == str)
      {
        GNUNET_break_op (0);
        return -1;
      }
      GNUNET_free (str);
    }
#endif
  }
  if (ret > SSIZE_MAX)
  {
    GNUNET_break (0);
    return -1;
  }
  //Do not pad PKEY
  if (GNUNET_GNSRECORD_TYPE_PKEY == rd->record_type)
    return ret;
  /**
   * Efficiently round up to the next
   * power of 2 for padding
   * https://graphics.stanford.edu/~seander/bithacks.html#RoundUpPowerOf2
   */
  ret--;
  ret |= ret >> 1;
  ret |= ret >> 2;
  ret |= ret >> 4;
  ret |= ret >> 8;
  ret |= ret >> 16;
  ret++;
  return (ssize_t) ret;
}


/**
 * Serialize the given records to the given destination buffer.
 *
 * @param rd_count number of records in the rd array
 * @param rd array of #GNUNET_GNSRECORD_Data with @a rd_count elements
 * @param dest_size size of the destination array
 * @param dest where to write the result
 * @return the size of serialized records, -1 if records do not fit
 */
ssize_t
GNUNET_GNSRECORD_records_serialize (unsigned int rd_count,
                                    const struct GNUNET_GNSRECORD_Data *rd,
                                    size_t dest_size,
                                    char *dest)
{
  struct NetworkRecord rec;
  size_t off;

  off = 0;
  for (unsigned int i=0;i<rd_count;i++)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Serializing record %u with flags %d and expiration time %llu\n",
         i,
         rd[i].flags,
         (unsigned long long) rd[i].expiration_time);
    rec.expiration_time = GNUNET_htonll (rd[i].expiration_time);
    rec.data_size = htonl ((uint32_t) rd[i].data_size);
    rec.record_type = htonl (rd[i].record_type);
    rec.flags = htonl (rd[i].flags);
    if ( (off + sizeof (rec) > dest_size) ||
         (off + sizeof (rec) < off) )
    {
      GNUNET_break (0);
      return -1;
    }
    GNUNET_memcpy (&dest[off],
                   &rec,
                   sizeof (rec));
    off += sizeof (rec);
    if ( (off + rd[i].data_size > dest_size) ||
         (off + rd[i].data_size < off) )
    {
      GNUNET_break (0);
      return -1;
    }
    GNUNET_memcpy (&dest[off],
                   rd[i].data,
                   rd[i].data_size);
    off += rd[i].data_size;
#if DEBUG_GNSRECORDS
    {
      char *str;

      str = GNUNET_GNSRECORD_value_to_string (rd[i].record_type,
                                              rd[i].data,
                                              rd[i].data_size);
      if (NULL == str)
      {
        GNUNET_break_op (0);
        return -1;
      }
      GNUNET_free (str);
    }
#endif
  }
  memset (&dest[off],
          0,
          dest_size-off);
  return dest_size;
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
GNUNET_GNSRECORD_records_deserialize (size_t len,
                                      const char *src,
                                      unsigned int rd_count,
                                      struct GNUNET_GNSRECORD_Data *dest)
{
  struct NetworkRecord rec;
  size_t off;

  off = 0;
  for (unsigned int i=0;i<rd_count;i++)
  {
    if ( (off + sizeof (rec) > len) ||
         (off + sizeof (rec) < off) )
    {
      GNUNET_break_op (0);
      return GNUNET_SYSERR;
    }
    GNUNET_memcpy (&rec,
                   &src[off],
                   sizeof (rec));
    dest[i].expiration_time = GNUNET_ntohll (rec.expiration_time);
    dest[i].data_size = ntohl ((uint32_t) rec.data_size);
    dest[i].record_type = ntohl (rec.record_type);
    dest[i].flags = ntohl (rec.flags);
    off += sizeof (rec);
    if ( (off + dest[i].data_size > len) ||
         (off + dest[i].data_size < off) )
    {
      GNUNET_break_op (0);
      return GNUNET_SYSERR;
    }
    dest[i].data = &src[off];
    off += dest[i].data_size;
#if GNUNET_EXTRA_LOGGING
    {
      char *str;

      str = GNUNET_GNSRECORD_value_to_string (dest[i].record_type,
                                              dest[i].data,
                                              dest[i].data_size);
      if (NULL == str)
      {
        GNUNET_break_op (0);
        return GNUNET_SYSERR;
      }
      GNUNET_free (str);
    }
#endif
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Deserialized record %u with flags %d and expiration time %llu\n",
         i,
         dest[i].flags,
         (unsigned long long) dest[i].expiration_time);
  }
  return GNUNET_OK;
}


/* end of gnsrecord_serialization.c */

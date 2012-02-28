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
  struct GNUNET_NAMESTORE_NetworkRecord * nr;
  char * d = (*dest);
  int c = 0;
  int offset;


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

    nr = (struct GNUNET_NAMESTORE_NetworkRecord *) &d[offset];
    nr->data_size = htonl (rd[c].data_size);
    nr->flags = htonl (rd[c].flags);
    nr->record_type = htonl (rd[c].record_type);
    nr->expiration = GNUNET_TIME_absolute_hton(rd[c].expiration);

    /*put data here */
    offset += sizeof (struct GNUNET_NAMESTORE_NetworkRecord);
    memcpy (&d[offset], rd[c].data, rd[c].data_size);
    offset += rd[c].data_size;
  }

  GNUNET_assert (offset == total_len);
  return total_len;
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
    d[c].data = GNUNET_malloc (d[c].data_size);
    GNUNET_assert (d[c].data != NULL);

    offset += sizeof (struct GNUNET_NAMESTORE_NetworkRecord);
    memcpy((char *) d[c].data, &src[offset], d[c].data_size);

    offset += d[c].data_size;
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Deserialized record[%i] /w data_size %i\n", c, d[c].data_size);
  }
  GNUNET_assert(offset == len);

  return elements;
}

/* end of namestore_api.c */

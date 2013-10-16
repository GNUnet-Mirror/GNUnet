/*
     This file is part of GNUnet
     (C) 2012, 2013 Christian Grothoff (and other contributing authors)

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
 * @file include/gnunet_gnsrecord_lib.h
 * @brief API that can be used to manipulate GNS record data
 * @author Christian Grothoff
 */
#ifndef GNUNET_GNSRECORD_LIB_H
#define GNUNET_GNSRECORD_LIB_H

#ifdef __cplusplus
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif


/**
 * Record type indicating any record/'*'
 */
#define GNUNET_GNSRECORD_TYPE_ANY 0

/**
 * Record type for GNS zone transfer ("PKEY").
 */
#define GNUNET_GNSRECORD_TYPE_PKEY 65536

/**
 * Record type for GNS zone transfer ("PSEU").
 */
#define GNUNET_GNSRECORD_TYPE_PSEU 65537

/**
 * Record type for GNS legacy hostnames ("LEHO").
 */
#define GNUNET_GNSRECORD_TYPE_LEHO 65538

/**
 * Record type for VPN resolution
 */
#define GNUNET_GNSRECORD_TYPE_VPN 65539

/**
 * Record type for delegation to DNS.
 */
#define GNUNET_GNSRECORD_TYPE_GNS2DNS 65540

/**
 * Record type for a social place.
 */
#define GNUNET_GNSRECORD_TYPE_PLACE 65541

/**
 * Record type for a phone (of CONVERSATION).
 */
#define GNUNET_GNSRECORD_TYPE_PHONE 65542



/**
 * Convert the binary value @a data of a record of
 * type @a type to a human-readable string.
 *
 * @param type type of the record
 * @param data value in binary encoding
 * @param data_size number of bytes in @a data
 * @return NULL on error, otherwise human-readable representation of the value
 */
char *
GNUNET_GNSRECORD_value_to_string (uint32_t type,
				  const void *data,
				  size_t data_size);


/**
 * Convert human-readable version of the value @a s of a record
 * of type @a type to the respective binary representation.
 *
 * @param type type of the record
 * @param s human-readable string
 * @param data set to value in binary encoding (will be allocated)
 * @param data_size set to number of bytes in @a data
 * @return #GNUNET_OK on success
 */
int
GNUNET_GNSRECORD_string_to_value (uint32_t type,
				  const char *s,
				  void **data,
				  size_t *data_size);


/**
 * Convert a type name (i.e. "AAAA") to the corresponding number.
 *
 * @param dns_typename name to convert
 * @return corresponding number, UINT32_MAX on error
 */
uint32_t
GNUNET_GNSRECORD_typename_to_number (const char *dns_typename);


/**
 * Convert a type number (i.e. 1) to the corresponding type string (i.e. "A")
 *
 * @param type number of a type to convert
 * @return corresponding typestring, NULL on error
 */
const char *
GNUNET_GNSRECORD_number_to_typename (uint32_t type);


#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

#endif

/*
     This file is part of GNUnet.
     Copyright (C) 2017 GNUnet e.V.

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
 * @author Martin Schanzenbach
 *
 * @file
 * Identity attribute definitions
 *
 * @defgroup identity-provider  Identity Provider service
 * @{
 */
#ifndef GNUNET_RECLAIM_ATTRIBUTE_LIB_H
#define GNUNET_RECLAIM_ATTRIBUTE_LIB_H

#ifdef __cplusplus
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif

#include "gnunet_util_lib.h"


/**
 * No value attribute.
 */
#define GNUNET_RECLAIM_ATTRIBUTE_TYPE_NONE 0

/**
 * String attribute.
 */
#define GNUNET_RECLAIM_ATTRIBUTE_TYPE_STRING 1



/**
 * An attribute.
 */
struct GNUNET_RECLAIM_ATTRIBUTE_Claim
{
  /**
   * The name of the attribute. Note "name" must never be individually
   * free'd
   */
  const char* name;

  /**
   * Type of Claim
   */
  uint32_t type;

  /**
   * Version
   */
  uint32_t version;

  /**
   * Number of bytes in @e data.
   */
  size_t data_size;

  /**
   * Binary value stored as attribute value.  Note: "data" must never
   * be individually 'malloc'ed, but instead always points into some
   * existing data area.
   */
  const void *data;

};

struct GNUNET_RECLAIM_ATTRIBUTE_ClaimList
{
  /**
   * List head
   */
  struct GNUNET_RECLAIM_ATTRIBUTE_ClaimListEntry *list_head;

  /**
   * List tail
   */
  struct GNUNET_RECLAIM_ATTRIBUTE_ClaimListEntry *list_tail;
};

struct GNUNET_RECLAIM_ATTRIBUTE_ClaimListEntry
{
  /**
   * DLL
   */
  struct GNUNET_RECLAIM_ATTRIBUTE_ClaimListEntry *prev;

  /**
   * DLL
   */
  struct GNUNET_RECLAIM_ATTRIBUTE_ClaimListEntry *next;

  /**
   * The attribute claim
   */
  struct GNUNET_RECLAIM_ATTRIBUTE_Claim *claim;
};

/**
 * Create a new attribute claim.
 *
 * @param attr_name the attribute name
 * @param type the attribute type
 * @param data the attribute value
 * @param data_size the attribute value size
 * @return the new attribute
 */
struct GNUNET_RECLAIM_ATTRIBUTE_Claim *
GNUNET_RECLAIM_ATTRIBUTE_claim_new (const char* attr_name,
                                     uint32_t type,
                                     const void* data,
                                     size_t data_size);


/**
 * Get required size for serialization buffer
 *
 * @param attrs the attribute list to serialize
 *
 * @return the required buffer size
 */
size_t
GNUNET_RECLAIM_ATTRIBUTE_list_serialize_get_size (const struct GNUNET_RECLAIM_ATTRIBUTE_ClaimList *attrs);

void
GNUNET_RECLAIM_ATTRIBUTE_list_destroy (struct GNUNET_RECLAIM_ATTRIBUTE_ClaimList *attrs);

void
GNUNET_RECLAIM_ATTRIBUTE_list_add (struct GNUNET_RECLAIM_ATTRIBUTE_ClaimList *attrs,
				    const char* attr_name,
				    uint32_t type,
				    const void* data,
				    size_t data_size);

/**
 * Serialize an attribute list
 *
 * @param attrs the attribute list to serialize
 * @param result the serialized attribute
 *
 * @return length of serialized data
 */
size_t
GNUNET_RECLAIM_ATTRIBUTE_list_serialize (const struct GNUNET_RECLAIM_ATTRIBUTE_ClaimList *attrs,
                     char *result);

/**
 * Deserialize an attribute list
 *
 * @param data the serialized attribute list
 * @param data_size the length of the serialized data
 *
 * @return a GNUNET_IDENTITY_PROVIDER_AttributeList, must be free'd by caller
 */
struct GNUNET_RECLAIM_ATTRIBUTE_ClaimList *
GNUNET_RECLAIM_ATTRIBUTE_list_deserialize (const char* data,
                            size_t data_size);


/**
 * Get required size for serialization buffer
 *
 * @param attr the attribute to serialize
 *
 * @return the required buffer size
 */
size_t
GNUNET_RECLAIM_ATTRIBUTE_serialize_get_size (const struct GNUNET_RECLAIM_ATTRIBUTE_Claim *attr);



/**
 * Serialize an attribute
 *
 * @param attr the attribute to serialize
 * @param result the serialized attribute
 *
 * @return length of serialized data
 */
size_t
GNUNET_RECLAIM_ATTRIBUTE_serialize (const struct GNUNET_RECLAIM_ATTRIBUTE_Claim *attr,
                     char *result);

/**
 * Deserialize an attribute
 *
 * @param data the serialized attribute
 * @param data_size the length of the serialized data
 *
 * @return a GNUNET_IDENTITY_PROVIDER_Attribute, must be free'd by caller
 */
struct GNUNET_RECLAIM_ATTRIBUTE_Claim *
GNUNET_RECLAIM_ATTRIBUTE_deserialize (const char* data,
                       size_t data_size);

struct GNUNET_RECLAIM_ATTRIBUTE_ClaimList*
GNUNET_RECLAIM_ATTRIBUTE_list_dup (const struct GNUNET_RECLAIM_ATTRIBUTE_ClaimList *attrs);

/**
 * Convert a type name to the corresponding number
 *
 * @param typename name to convert
 * @return corresponding number, UINT32_MAX on error
 */
uint32_t
GNUNET_RECLAIM_ATTRIBUTE_typename_to_number (const char *typename);

/**
 * Convert human-readable version of a 'claim' of an attribute to the binary
 * representation
 *
 * @param type type of the claim
 * @param s human-readable string
 * @param data set to value in binary encoding (will be allocated)
 * @param data_size set to number of bytes in @a data
 * @return #GNUNET_OK on success
 */
int
GNUNET_RECLAIM_ATTRIBUTE_string_to_value (uint32_t type,
                                           const char *s,
                                           void **data,
                                           size_t *data_size);

/**
 * Convert the 'claim' of an attribute to a string
 *
 * @param type the type of attribute
 * @param data claim in binary encoding
 * @param data_size number of bytes in @a data
 * @return NULL on error, otherwise human-readable representation of the claim
 */
char *
GNUNET_RECLAIM_ATTRIBUTE_value_to_string (uint32_t type,
                                           const void* data,
                                           size_t data_size);

/**
 * Convert a type number to the corresponding type string
 *
 * @param type number of a type
 * @return corresponding typestring, NULL on error
 */
const char*
GNUNET_RECLAIM_ATTRIBUTE_number_to_typename (uint32_t type);


#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif


/* ifndef GNUNET_RECLAIM_ATTRIBUTE_LIB_H */
#endif

/** @} */ /* end of group identity */

/* end of gnunet_reclaim_attribute_lib.h */

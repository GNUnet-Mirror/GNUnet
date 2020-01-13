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
 * @defgroup reclaim-attribute reclaim attributes
 * @{
 */
#ifndef GNUNET_RECLAIM_ATTRIBUTE_LIB_H
#define GNUNET_RECLAIM_ATTRIBUTE_LIB_H

#ifdef __cplusplus
extern "C" {
#if 0 /* keep Emacsens' auto-indent happy */
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
* No value attestation.
*/
#define GNUNET_RECLAIM_ATTESTATION_TYPE_NONE 10

/**
* A JSON Web Token attestation.
*/
#define GNUNET_RECLAIM_ATTESTATION_TYPE_JWT 11

/**
 * An attribute.
 */
struct GNUNET_RECLAIM_ATTRIBUTE_Claim
{
  /**
   * ID
   */
  uint64_t id;

  /**
   * Type of Claim
   */
  uint32_t type;

  /**
   * Flags
   */
  uint32_t flag;
  /**
   * The name of the attribute. Note "name" must never be individually
   * free'd
   */
  const char *name;

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

/**
 * An attestation.
 */
struct GNUNET_RECLAIM_ATTESTATION_Claim
{
  /**
   * ID
   */
  uint64_t id;

  /**
   * Type/Format of Claim
   */
  uint32_t type;

  /**
   * Version
   */
  uint32_t version;

  /**
   * The name of the attribute. Note "name" must never be individually
   * free'd
   */
  const char *name;

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

/**
 * A reference to an Attestatiom.
 */
struct GNUNET_RECLAIM_ATTESTATION_REFERENCE
{
  /**
   * ID
   */
  uint64_t id;

  /**
   * Referenced ID of Attestation
   */
  uint64_t id_attest;

  /**
   * The name of the attribute/attestation reference value. Note "name" must never be individually
   * free'd
   */
  const char *name;

  /**
   * The name of the attribute/attestation reference value. Note "name" must never be individually
   * free'd
   */
  const char *reference_value;
};

/**
 * A list of GNUNET_RECLAIM_ATTRIBUTE_Claim structures.
 */
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
GNUNET_RECLAIM_ATTRIBUTE_claim_new (const char *attr_name,
                                    uint32_t type,
                                    const void *data,
                                    size_t data_size);


/**
 * Get required size for serialization buffer
 *
 * @param attrs the attribute list to serialize
 * @return the required buffer size
 */
size_t
GNUNET_RECLAIM_ATTRIBUTE_list_serialize_get_size (
  const struct GNUNET_RECLAIM_ATTRIBUTE_ClaimList *attrs);


/**
 * Destroy claim list
 *
 * @param attrs list to destroy
 */
void
GNUNET_RECLAIM_ATTRIBUTE_list_destroy (
  struct GNUNET_RECLAIM_ATTRIBUTE_ClaimList *attrs);


/**
 * Add a new attribute to a claim list
 *
 * @param attr_name the name of the new attribute claim
 * @param type the type of the claim
 * @param data claim payload
 * @param data_size claim payload size
 */
void
GNUNET_RECLAIM_ATTRIBUTE_list_add (
  struct GNUNET_RECLAIM_ATTRIBUTE_ClaimList *attrs,
  const char *attr_name,
  uint32_t type,
  const void *data,
  size_t data_size);


/**
 * Serialize an attribute list
 *
 * @param attrs the attribute list to serialize
 * @param result the serialized attribute
 * @return length of serialized data
 */
size_t
GNUNET_RECLAIM_ATTRIBUTE_list_serialize (
  const struct GNUNET_RECLAIM_ATTRIBUTE_ClaimList *attrs,
  char *result);


/**
 * Deserialize an attribute list
 *
 * @param data the serialized attribute list
 * @param data_size the length of the serialized data
 * @return a GNUNET_IDENTITY_PROVIDER_AttributeList, must be free'd by caller
 */
struct GNUNET_RECLAIM_ATTRIBUTE_ClaimList *
GNUNET_RECLAIM_ATTRIBUTE_list_deserialize (const char *data, size_t data_size);


/**
 * Get required size for serialization buffer
 *
 * @param attr the attribute to serialize
 * @return the required buffer size
 */
size_t
GNUNET_RECLAIM_ATTRIBUTE_serialize_get_size (
  const struct GNUNET_RECLAIM_ATTRIBUTE_Claim *attr);


/**
 * Serialize an attribute
 *
 * @param attr the attribute to serialize
 * @param result the serialized attribute
 * @return length of serialized data
 */
size_t
GNUNET_RECLAIM_ATTRIBUTE_serialize (
  const struct GNUNET_RECLAIM_ATTRIBUTE_Claim *attr,
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
GNUNET_RECLAIM_ATTRIBUTE_deserialize (const char *data, size_t data_size);


/**
 * Make a (deep) copy of a claim list
 * @param attrs claim list to copy
 * @return copied claim list
 */
struct GNUNET_RECLAIM_ATTRIBUTE_ClaimList *
GNUNET_RECLAIM_ATTRIBUTE_list_dup (
  const struct GNUNET_RECLAIM_ATTRIBUTE_ClaimList *attrs);


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
                                          const void *data,
                                          size_t data_size);


/**
 * Convert a type number to the corresponding type string
 *
 * @param type number of a type
 * @return corresponding typestring, NULL on error
 */
const char *
GNUNET_RECLAIM_ATTRIBUTE_number_to_typename (uint32_t type);

/**
   * Get required size for serialization buffer
   * FIXME:
   * 1. The naming convention is violated here.
   * It should GNUNET_RECLAIM_ATTRIBUTE_<lowercase from here>.
   * It might make sense to refactor attestations into a separate folder.
   * 2. The struct should be called GNUNET_RECLAIM_ATTESTATION_Data or
   * GNUNET_RECLAIM_ATTRIBUTE_Attestation depending on location in source.
   *
   * @param attr the attestation to serialize
   * @return the required buffer size
   */
size_t
GNUNET_RECLAIM_ATTESTATION_serialize_get_size (
  const struct GNUNET_RECLAIM_ATTESTATION_Claim *attr);


/**
 * Serialize an attestation
 *
 * @param attr the attestation to serialize
 * @param result the serialized attestation
 * @return length of serialized data
 */
size_t
GNUNET_RECLAIM_ATTESTATION_serialize (
  const struct GNUNET_RECLAIM_ATTESTATION_Claim *attr,
  char *result);


/**
 * Deserialize an attestation
 *
 * @param data the serialized attestation
 * @param data_size the length of the serialized data
 *
 * @return a GNUNET_IDENTITY_PROVIDER_Attribute, must be free'd by caller
 */
struct GNUNET_RECLAIM_ATTESTATION_Claim *
GNUNET_RECLAIM_ATTESTATION_deserialize (const char *data, size_t data_size);


/**
   * Create a new attestation.
   *
   * @param attr_name the attestation name
   * @param type the attestation type
   * @param data the attestation value
   * @param data_size the attestation value size
   * @return the new attestation
   */
struct GNUNET_RECLAIM_ATTESTATION_Claim *
GNUNET_RECLAIM_ATTESTATION_claim_new (const char *attr_name,
                                      uint32_t type,
                                      const void *data,
                                      size_t data_size);

/**
 * Convert the 'claim' of an attestation to a string
 *
 * @param type the type of attestation
 * @param data claim in binary encoding
 * @param data_size number of bytes in @a data
 * @return NULL on error, otherwise human-readable representation of the claim
 */
char *
GNUNET_RECLAIM_ATTESTATION_value_to_string (uint32_t type,
                                            const void *data,
                                            size_t data_size);

/**
 * Convert human-readable version of a 'claim' of an attestation to the binary
 * representation
 *
 * @param type type of the claim
 * @param s human-readable string
 * @param data set to value in binary encoding (will be allocated)
 * @param data_size set to number of bytes in @a data
 * @return #GNUNET_OK on success
 */
int
GNUNET_RECLAIM_ATTESTATION_string_to_value (uint32_t type,
                                            const char *s,
                                            void **data,
                                            size_t *data_size);

/**
 * Convert an attestation type number to the corresponding attestation type string
 *
 * @param type number of a type
 * @return corresponding typestring, NULL on error
 */
const char *
GNUNET_RECLAIM_ATTESTATION_number_to_typename (uint32_t type);

/**
 * Convert an attestation type name to the corresponding number
 *
 * @param typename name to convert
 * @return corresponding number, UINT32_MAX on error
 */
uint32_t
GNUNET_RECLAIM_ATTESTATION_typename_to_number (const char *typename);

/**
 * Create a new attestation reference.
 *
 * @param attr_name the referenced claim name
 * @param ref_value the claim name in the attestation
 * @return the new reference
 */
struct GNUNET_RECLAIM_ATTESTATION_REFERENCE *
GNUNET_RECLAIM_ATTESTATION_reference_new (const char *attr_name,
                                          const char *ref_value);


/**
 * Get required size for serialization buffer
 *
 * @param attr the reference to serialize
 * @return the required buffer size
 */
size_t
GNUNET_RECLAIM_ATTESTATION_REF_serialize_get_size (
  const struct GNUNET_RECLAIM_ATTESTATION_REFERENCE *attr);

/**
 * Serialize a reference
 *
 * @param attr the reference to serialize
 * @param result the serialized reference
 * @return length of serialized data
 */
size_t
GNUNET_RECLAIM_ATTESTATION_REF_serialize (
  const struct GNUNET_RECLAIM_ATTESTATION_REFERENCE *attr,
  char *result);

/**
 * Deserialize a reference
 *
 * @param data the serialized reference
 * @param data_size the length of the serialized data
 *
 * @return a GNUNET_IDENTITY_PROVIDER_Attribute, must be free'd by caller
 */
struct GNUNET_RECLAIM_ATTESTATION_REFERENCE *
GNUNET_RECLAIM_ATTESTATION_REF_deserialize (const char *data, size_t data_size);

#if 0 /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif


/* ifndef GNUNET_RECLAIM_ATTRIBUTE_LIB_H */
#endif

/** @} */ /* end of group reclaim-attribute */

/* end of gnunet_reclaim_attribute_lib.h */

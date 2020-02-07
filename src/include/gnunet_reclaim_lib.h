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
 * We want an ID to be a 256-bit symmetric key
 */
#define GNUNET_RECLAIM_ID_LENGTH (256 / 8)

/**
 * A reclaim identifier
 * FIXME maybe put this in a different namespace
 */
struct GNUNET_RECLAIM_Identifier
{
  char id[GNUNET_RECLAIM_ID_LENGTH];
};

static const struct GNUNET_RECLAIM_Identifier GNUNET_RECLAIM_ID_ZERO;

#define GNUNET_RECLAIM_id_is_equal(a,b) ((0 == \
                                          memcmp (a, \
                                                  b, \
                                                  sizeof (GNUNET_RECLAIM_ID_ZERO))) \
  ? \
                                         GNUNET_YES : GNUNET_NO)


#define GNUNET_RECLAIM_id_is_zero(a) GNUNET_RECLAIM_id_is_equal (a, \
                                                                 & \
                                                                 GNUNET_RECLAIM_ID_ZERO)

#define GNUNET_RECLAIM_id_generate(id) \
  (GNUNET_CRYPTO_random_block (GNUNET_CRYPTO_QUALITY_STRONG, \
                               id, \
                               sizeof (GNUNET_RECLAIM_ID_ZERO)))

/**
 * An attribute.
 */
struct GNUNET_RECLAIM_Attribute
{
  /**
   * ID
   */
  struct GNUNET_RECLAIM_Identifier id;

  /**
   * Referenced ID of Attestation (may be 0 if self-attested)
   */
  struct GNUNET_RECLAIM_Identifier attestation;

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
struct GNUNET_RECLAIM_Attestation
{
  /**
   * ID
   */
  struct GNUNET_RECLAIM_Identifier id;

  /**
   * Type/Format of Claim
   */
  uint32_t type;

  /**
   * Flag
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
 * A list of GNUNET_RECLAIM_Attribute structures.
 */
struct GNUNET_RECLAIM_AttributeList
{
  /**
   * List head
   */
  struct GNUNET_RECLAIM_AttributeListEntry *list_head;

  /**
   * List tail
   */
  struct GNUNET_RECLAIM_AttributeListEntry *list_tail;
};


struct GNUNET_RECLAIM_AttributeListEntry
{
  /**
   * DLL
   */
  struct GNUNET_RECLAIM_AttributeListEntry *prev;

  /**
   * DLL
   */
  struct GNUNET_RECLAIM_AttributeListEntry *next;

  /**
   * The attribute claim
   */
  struct GNUNET_RECLAIM_Attribute *attribute;

};

/**
 * A list of GNUNET_RECLAIM_Attestation structures.
 */
struct GNUNET_RECLAIM_AttestationList
{
  /**
   * List head
   */
  struct GNUNET_RECLAIM_AttestationListEntry *list_head;

  /**
   * List tail
   */
  struct GNUNET_RECLAIM_AttestationListEntry *list_tail;
};


struct GNUNET_RECLAIM_AttestationListEntry
{
  /**
   * DLL
   */
  struct GNUNET_RECLAIM_AttestationListEntry *prev;

  /**
   * DLL
   */
  struct GNUNET_RECLAIM_AttestationListEntry *next;

  /**
   * The attestation
   */
  struct GNUNET_RECLAIM_Attestation *attestation;

};


/**
 * Create a new attribute claim.
 *
 * @param attr_name the attribute name
 * @param attestation ID of the attestation (may be NULL)
 * @param type the attribute type
 * @param data the attribute value. Must be the mapped name if attestation not NULL
 * @param data_size the attribute value size
 * @return the new attribute
 */
struct GNUNET_RECLAIM_Attribute *
GNUNET_RECLAIM_attribute_new (const char *attr_name,
                              const struct
                              GNUNET_RECLAIM_Identifier *attestation,
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
GNUNET_RECLAIM_attribute_list_serialize_get_size (
  const struct GNUNET_RECLAIM_AttributeList *attrs);


/**
 * Destroy claim list
 *
 * @param attrs list to destroy
 */
void
GNUNET_RECLAIM_attribute_list_destroy (
  struct GNUNET_RECLAIM_AttributeList *attrs);


/**
 * Add a new attribute to a claim list
 *
 * @param attrs the attribute list to add to
 * @param attr_name the name of the new attribute claim
 * @param attestation attestation ID (may be NULL)
 * @param type the type of the claim
 * @param data claim payload
 * @param data_size claim payload size
 */
void
GNUNET_RECLAIM_attribute_list_add (
  struct GNUNET_RECLAIM_AttributeList *attrs,
  const char *attr_name,
  const struct GNUNET_RECLAIM_Identifier *attestation,
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
GNUNET_RECLAIM_attribute_list_serialize (
  const struct GNUNET_RECLAIM_AttributeList *attrs,
  char *result);


/**
 * Deserialize an attribute list
 *
 * @param data the serialized attribute list
 * @param data_size the length of the serialized data
 * @return a GNUNET_IDENTITY_PROVIDER_AttributeList, must be free'd by caller
 */
struct GNUNET_RECLAIM_AttributeList *
GNUNET_RECLAIM_attribute_list_deserialize (const char *data, size_t data_size);

/**
 * Get required size for serialization buffer
 *
 * @param attr the attribute to serialize
 * @return the required buffer size
 */
size_t
GNUNET_RECLAIM_attribute_serialize_get_size (
  const struct GNUNET_RECLAIM_Attribute *attr);


/**
 * Serialize an attribute
 *
 * @param attr the attribute to serialize
 * @param result the serialized attribute
 * @return length of serialized data
 */
size_t
GNUNET_RECLAIM_attribute_serialize (const struct GNUNET_RECLAIM_Attribute *attr,
                                    char *result);


/**
 * Deserialize an attribute
 *
 * @param data the serialized attribute
 * @param data_size the length of the serialized data
 *
 * @return a GNUNET_IDENTITY_PROVIDER_Attribute, must be free'd by caller
 */
struct GNUNET_RECLAIM_Attribute *
GNUNET_RECLAIM_attribute_deserialize (const char *data, size_t data_size);


/**
 * Make a (deep) copy of a claim list
 * @param attrs claim list to copy
 * @return copied claim list
 */
struct GNUNET_RECLAIM_AttributeList *
GNUNET_RECLAIM_attribute_list_dup (
  const struct GNUNET_RECLAIM_AttributeList *attrs);


/**
 * Convert a type name to the corresponding number
 *
 * @param typename name to convert
 * @return corresponding number, UINT32_MAX on error
 */
uint32_t
GNUNET_RECLAIM_attribute_typename_to_number (const char *typename);

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
GNUNET_RECLAIM_attribute_string_to_value (uint32_t type,
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
GNUNET_RECLAIM_attribute_value_to_string (uint32_t type,
                                          const void *data,
                                          size_t data_size);

/**
 * Convert a type number to the corresponding type string
 *
 * @param type number of a type
 * @return corresponding typestring, NULL on error
 */
const char *
GNUNET_RECLAIM_attribute_number_to_typename (uint32_t type);


/**
 * Get required size for serialization buffer
 *
 * @param attrs the attribute list to serialize
 * @return the required buffer size
 */
size_t
GNUNET_RECLAIM_attestation_list_serialize_get_size (
  const struct GNUNET_RECLAIM_AttestationList *attestations);


/**
 * Destroy claim list
 *
 * @param attrs list to destroy
 */
void
GNUNET_RECLAIM_attestation_list_destroy (
  struct GNUNET_RECLAIM_AttestationList *attestations);


/**
 * Add a new attribute to a claim list
 *
 * @param attr_name the name of the new attribute claim
 * @param type the type of the claim
 * @param data claim payload
 * @param data_size claim payload size
 */
void
GNUNET_RECLAIM_attestation_list_add (
  struct GNUNET_RECLAIM_AttestationList *attrs,
  const char *att_name,
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
GNUNET_RECLAIM_attestation_list_serialize (
  const struct GNUNET_RECLAIM_AttestationList *attrs,
  char *result);


/**
 * Deserialize an attribute list
 *
 * @param data the serialized attribute list
 * @param data_size the length of the serialized data
 * @return a GNUNET_IDENTITY_PROVIDER_AttributeList, must be free'd by caller
 */
struct GNUNET_RECLAIM_AttestationList *
GNUNET_RECLAIM_attestation_list_deserialize (const char *data,
                                             size_t data_size);


/**
   * @param attestation the attestation to serialize
   * @return the required buffer size
   */
size_t
GNUNET_RECLAIM_attestation_serialize_get_size (
  const struct GNUNET_RECLAIM_Attestation *attestation);


/**
 * Serialize an attestation
 *
 * @param attestation the attestation to serialize
 * @param result the serialized attestation
 * @return length of serialized data
 */
size_t
GNUNET_RECLAIM_attestation_serialize (
  const struct GNUNET_RECLAIM_Attestation *attestation,
  char *result);


/**
 * Deserialize an attestation
 *
 * @param data the serialized attestation
 * @param data_size the length of the serialized data
 *
 * @return a GNUNET_IDENTITY_PROVIDER_Attribute, must be free'd by caller
 */
struct GNUNET_RECLAIM_Attestation *
GNUNET_RECLAIM_attestation_deserialize (const char *data, size_t data_size);


/**
 * Create a new attestation.
 *
 * @param name the attestation name
 * @param type the attestation type
 * @param data the attestation value
 * @param data_size the attestation value size
 * @return the new attestation
 */
struct GNUNET_RECLAIM_Attestation *
GNUNET_RECLAIM_attestation_new (const char *name,
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
GNUNET_RECLAIM_attestation_value_to_string (uint32_t type,
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
GNUNET_RECLAIM_attestation_string_to_value (uint32_t type,
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
GNUNET_RECLAIM_attestation_number_to_typename (uint32_t type);

/**
 * Convert an attestation type name to the corresponding number
 *
 * @param typename name to convert
 * @return corresponding number, UINT32_MAX on error
 */
uint32_t
GNUNET_RECLAIM_attestation_typename_to_number (const char *typename);

/**
 * Convert an attestation type name to the corresponding number
 *
 * @param typename name to convert
 * @return corresponding number, UINT32_MAX on error
 */
struct GNUNET_RECLAIM_AttributeList*
GNUNET_RECLAIM_attestation_get_attributes (const struct
                                           GNUNET_RECLAIM_Attestation *attest);

char*
GNUNET_RECLAIM_attestation_get_issuer (const struct
                                       GNUNET_RECLAIM_Attestation *attest);

int
GNUNET_RECLAIM_attestation_get_expiration (const struct
                                           GNUNET_RECLAIM_Attestation *attest,
                                           struct GNUNET_TIME_Absolute *exp);

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

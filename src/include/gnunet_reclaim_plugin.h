/*
     This file is part of GNUnet
     Copyright (C) 2012, 2013 GNUnet e.V.

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
 * Plugin API for reclaim attribute types
 *
 * @defgroup reclaim-attribute-plugin  reclaim plugin API for attributes/claims
 * @{
 */
#ifndef GNUNET_RECLAIM_AttributePLUGIN_H
#define GNUNET_RECLAIM_AttributePLUGIN_H

#include "gnunet_util_lib.h"
#include "gnunet_reclaim_lib.h"

#ifdef __cplusplus
extern "C" {
#if 0 /* keep Emacsens' auto-indent happy */
}
#endif
#endif


/**
 * Function called to convert the binary value @a data of an attribute of
 * type @a type to a human-readable string.
 *
 * @param cls closure
 * @param type type of the attribute
 * @param data value in binary encoding
 * @param data_size number of bytes in @a data
 * @return NULL on error, otherwise human-readable representation of the value
 */
typedef char *(*GNUNET_RECLAIM_AttributeValueToStringFunction) (
  void *cls,
  uint32_t type,
  const void *data,
  size_t data_size);


/**
 * Function called to convert human-readable version of the value @a s
 * of an attribute of type @a type to the respective binary
 * representation.
 *
 * @param cls closure
 * @param type type of the attribute
 * @param s human-readable string
 * @param data set to value in binary encoding (will be allocated)
 * @param data_size set to number of bytes in @a data
 * @return #GNUNET_OK on success
 */
typedef int (*GNUNET_RECLAIM_AttributeStringToValueFunction) (
  void *cls,
  uint32_t type,
  const char *s,
  void **data,
  size_t *data_size);


/**
 * Function called to convert a type name to the
 * corresponding number.
 *
 * @param cls closure
 * @param typename name to convert
 * @return corresponding number, UINT32_MAX on error
 */
typedef uint32_t (*GNUNET_RECLAIM_AttributeTypenameToNumberFunction) (
  void *cls,
  const char *typename);


/**
 * Function called to convert a type number (i.e. 1) to the
 * corresponding type string
 *
 * @param cls closure
 * @param type number of a type to convert
 * @return corresponding typestring, NULL on error
 */
typedef const char *(*GNUNET_RECLAIM_AttributeNumberToTypenameFunction) (
  void *cls,
  uint32_t type);

/**
 * Function called to convert the binary value @a data of an attribute of
 * type @a type to a human-readable string.
 *
 * @param cls closure
 * @param type type of the attribute
 * @param data value in binary encoding
 * @param data_size number of bytes in @a data
 * @return NULL on error, otherwise human-readable representation of the value
 */
typedef char *(*GNUNET_RECLAIM_AttestationValueToStringFunction) (
  void *cls,
  uint32_t type,
  const void *data,
  size_t data_size);


/**
 * Function called to convert human-readable version of the value @a s
 * of an attribute of type @a type to the respective binary
 * representation.
 *
 * @param cls closure
 * @param type type of the attribute
 * @param s human-readable string
 * @param data set to value in binary encoding (will be allocated)
 * @param data_size set to number of bytes in @a data
 * @return #GNUNET_OK on success
 */
typedef int (*GNUNET_RECLAIM_AttestationStringToValueFunction) (
  void *cls,
  uint32_t type,
  const char *s,
  void **data,
  size_t *data_size);


/**
 * Function called to convert a type name to the
 * corresponding number.
 *
 * @param cls closure
 * @param typename name to convert
 * @return corresponding number, UINT32_MAX on error
 */
typedef uint32_t (*GNUNET_RECLAIM_AttestationTypenameToNumberFunction) (
  void *cls,
  const char *typename);


/**
 * Function called to convert a type number (i.e. 1) to the
 * corresponding type string
 *
 * @param cls closure
 * @param type number of a type to convert
 * @return corresponding typestring, NULL on error
 */
typedef const char *(*GNUNET_RECLAIM_AttestationNumberToTypenameFunction) (
  void *cls,
  uint32_t type);

/**
 * Function called to extract attributes from an attestation
 *
 * @param cls closure
 * @param attest the attestation object
 * @return an attribute list
 */
typedef struct GNUNET_RECLAIM_AttributeList *(*GNUNET_RECLAIM_AttestationGetAttributesFunction) (
  void *cls,
  const struct GNUNET_RECLAIM_Attestation *attest);

/**
 * Function called to get the issuer of the attestation (as string)
 *
 * @param cls closure
 * @param attest the attestation object
 * @return corresponding issuer string
 */
typedef char *(*GNUNET_RECLAIM_AttestationGetIssuerFunction) (
  void *cls,
  const struct GNUNET_RECLAIM_Attestation *attest);

/**
 * Function called to get the expiration of the attestation
 *
 * @param cls closure
 * @param attest the attestation object
 * @param where to write the value
 * @return GNUNET_OK if successful
 */
typedef int (*GNUNET_RECLAIM_AttestationGetExpirationFunction) (
  void *cls,
  const struct GNUNET_RECLAIM_Attestation *attest,
  struct GNUNET_TIME_Absolute *expiration);



/**
 * Each plugin is required to return a pointer to a struct of this
 * type as the return value from its entry point.
 */
struct GNUNET_RECLAIM_AttributePluginFunctions
{
  /**
   * Closure for all of the callbacks.
   */
  void *cls;

  /**
   * Conversion to string.
   */
  GNUNET_RECLAIM_AttributeValueToStringFunction value_to_string;

  /**
   * Conversion to binary.
   */
  GNUNET_RECLAIM_AttributeStringToValueFunction string_to_value;

  /**
   * Typename to number.
   */
  GNUNET_RECLAIM_AttributeTypenameToNumberFunction typename_to_number;

  /**
   * Number to typename.
   */
  GNUNET_RECLAIM_AttributeNumberToTypenameFunction number_to_typename;

};

/**
 * Each plugin is required to return a pointer to a struct of this
 * type as the return value from its entry point.
 */
struct GNUNET_RECLAIM_AttestationPluginFunctions
{
  /**
   * Closure for all of the callbacks.
   */
  void *cls;

  /**
   * Conversion to string.
   */
  GNUNET_RECLAIM_AttestationValueToStringFunction value_to_string;

  /**
   * Conversion to binary.
   */
  GNUNET_RECLAIM_AttestationStringToValueFunction string_to_value;

  /**
   * Typename to number.
   */
  GNUNET_RECLAIM_AttestationTypenameToNumberFunction typename_to_number;

  /**
   * Number to typename.
   */
  GNUNET_RECLAIM_AttestationNumberToTypenameFunction number_to_typename;

  /**
   * Attesation attributes.
   */
  GNUNET_RECLAIM_AttestationGetAttributesFunction get_attributes;

  /**
   * Attesation issuer.
   */
  GNUNET_RECLAIM_AttestationGetIssuerFunction get_issuer;

  /**
   * Expiration.
   */
  GNUNET_RECLAIM_AttestationGetExpirationFunction get_expiration;
};



#if 0 /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

#endif

/** @} */ /* end of group */

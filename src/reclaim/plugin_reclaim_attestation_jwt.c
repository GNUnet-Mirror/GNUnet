/*
     This file is part of GNUnet
     Copyright (C) 2013, 2014, 2016 GNUnet e.V.

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
 * @file reclaim-attribute/plugin_reclaim_attestation_gnuid.c
 * @brief reclaim-attribute-plugin-gnuid attribute plugin to provide the API for
 *                                       fundamental
 *                                       attribute types.
 *
 * @author Martin Schanzenbach
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_reclaim_plugin.h"
#include <inttypes.h>
#include <jansson.h>

/**
   * Convert the 'value' of an attestation to a string.
   *
   * @param cls closure, unused
   * @param type type of the attestation
   * @param data value in binary encoding
   * @param data_size number of bytes in @a data
   * @return NULL on error, otherwise human-readable representation of the value
   */
static char *
jwt_value_to_string (void *cls,
                     uint32_t type,
                     const void *data,
                     size_t data_size)
{
  switch (type)
  {
  case GNUNET_RECLAIM_ATTESTATION_TYPE_JWT:
    return GNUNET_strndup (data, data_size);

  default:
    return NULL;
  }
}


/**
 * Convert human-readable version of a 'value' of an attestation to the binary
 * representation.
 *
 * @param cls closure, unused
 * @param type type of the attestation
 * @param s human-readable string
 * @param data set to value in binary encoding (will be allocated)
 * @param data_size set to number of bytes in @a data
 * @return #GNUNET_OK on success
 */
static int
jwt_string_to_value (void *cls,
                     uint32_t type,
                     const char *s,
                     void **data,
                     size_t *data_size)
{
  if (NULL == s)
    return GNUNET_SYSERR;
  switch (type)
  {
  case GNUNET_RECLAIM_ATTESTATION_TYPE_JWT:
    *data = GNUNET_strdup (s);
    *data_size = strlen (s);
    return GNUNET_OK;

  default:
    return GNUNET_SYSERR;
  }
}


/**
 * Mapping of attestation type numbers to human-readable
 * attestation type names.
 */
static struct
{
  const char *name;
  uint32_t number;
} jwt_attest_name_map[] = { { "JWT", GNUNET_RECLAIM_ATTESTATION_TYPE_JWT },
                            { NULL, UINT32_MAX } };

/**
   * Convert a type name to the corresponding number.
   *
   * @param cls closure, unused
   * @param jwt_typename name to convert
   * @return corresponding number, UINT32_MAX on error
   */
static uint32_t
jwt_typename_to_number (void *cls, const char *jwt_typename)
{
  unsigned int i;

  i = 0;
  while ((NULL != jwt_attest_name_map[i].name) &&
         (0 != strcasecmp (jwt_typename, jwt_attest_name_map[i].name)))
    i++;
  return jwt_attest_name_map[i].number;
}


/**
 * Convert a type number (i.e. 1) to the corresponding type string
 *
 * @param cls closure, unused
 * @param type number of a type to convert
 * @return corresponding typestring, NULL on error
 */
static const char *
jwt_number_to_typename (void *cls, uint32_t type)
{
  unsigned int i;

  i = 0;
  while ((NULL != jwt_attest_name_map[i].name) && (type !=
                                                   jwt_attest_name_map[i].
                                                   number))
    i++;
  return jwt_attest_name_map[i].name;
}


/**
 * Parse a JWT and return the respective claim value as Attribute
 *
 * @param cls the plugin
 * @param attest the jwt attestation
 * @return a GNUNET_RECLAIM_Attribute, containing the new value
 */
struct GNUNET_RECLAIM_AttributeList *
jwt_parse_attributes (void *cls,
                      const struct GNUNET_RECLAIM_Attestation *attest)
{
  char *jwt_string;
  struct GNUNET_RECLAIM_AttributeList *attrs;
  char delim[] = ".";
  char *val_str = NULL;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Parsing JWT attributes.\n");
  char *decoded_jwt;
  json_t *json_val;
  json_error_t *json_err = NULL;

  GNUNET_log (GNUNET_ERROR_TYPE_WARNING, "%s\n", attest->data);
  if (GNUNET_RECLAIM_ATTESTATION_TYPE_JWT != attest->type)
    return NULL;
  attrs = GNUNET_new (struct GNUNET_RECLAIM_AttributeList);

  jwt_string = GNUNET_strdup (attest->data);
  const char *jwt_body = strtok (jwt_string, delim);
  jwt_body = strtok (NULL, delim);
  GNUNET_STRINGS_base64url_decode (jwt_body, strlen (jwt_body),
                                   (void **) &decoded_jwt);
  GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "%s\n", decoded_jwt);
  GNUNET_assert (NULL != decoded_jwt);
  json_val = json_loads (decoded_jwt, JSON_DECODE_ANY, json_err);
  const char *key;
  json_t *value;
  json_object_foreach (json_val, key, value) {
    if (0 == strcmp ("iss", key))
      continue;
    if (0 == strcmp ("exp", key))
      continue;
    if (0 == strcmp ("iat", key))
      continue;
    if (0 == strcmp ("nbf", key))
      continue;
    if (0 == strcmp ("aud", key))
      continue;
    val_str = json_dumps (value, JSON_ENCODE_ANY);
    GNUNET_RECLAIM_attribute_list_add (attrs,
                                       key,
                                       NULL,
                                       GNUNET_RECLAIM_ATTRIBUTE_TYPE_STRING,// FIXME
                                       val_str,
                                       strlen (val_str));
    GNUNET_free (val_str);
  }
  GNUNET_free (jwt_string);
  return attrs;
}


/**
 * Parse a JWT and return the issuer
 *
 * @param cls the plugin
 * @param attest the jwt attestation
 * @return a string, containing the isser
 */
char *
jwt_get_issuer (void *cls,
                const struct GNUNET_RECLAIM_Attestation *attest)
{
  const char *jwt_body;
  char *jwt_string;
  char delim[] = ".";
  char *issuer = NULL;
  char *decoded_jwt;
  json_t *issuer_json;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Parsing JWT attributes.\n");
  json_t *json_val;
  json_error_t *json_err = NULL;

  if (GNUNET_RECLAIM_ATTESTATION_TYPE_JWT != attest->type)
    return NULL;
  jwt_string = GNUNET_strdup (attest->data);
  jwt_body = strtok (jwt_string, delim);
  jwt_body = strtok (NULL, delim);
  GNUNET_STRINGS_base64url_decode (jwt_body, strlen (jwt_body),
                                   (void **) &decoded_jwt);
  json_val = json_loads (decoded_jwt, JSON_DECODE_ANY, json_err);
  issuer_json = json_object_get (json_val, "iss");
  if ((NULL == issuer_json) || (! json_is_string (issuer_json)))
    return NULL;
  issuer = GNUNET_strdup (json_string_value (issuer_json));
  GNUNET_free (jwt_string);
  return issuer;
}


/**
 * Parse a JWT and return the expiration
 *
 * @param cls the plugin
 * @param attest the jwt attestation
 * @return a string, containing the isser
 */
int
jwt_get_expiration (void *cls,
                    const struct GNUNET_RECLAIM_Attestation *attest,
                    struct GNUNET_TIME_Absolute *exp)
{
  const char *jwt_body;
  char *jwt_string;
  char delim[] = ".";
  char *decoded_jwt;
  json_t *exp_json;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Parsing JWT attributes.\n");
  json_t *json_val;
  json_error_t *json_err = NULL;

  if (GNUNET_RECLAIM_ATTESTATION_TYPE_JWT != attest->type)
    return GNUNET_NO;
  jwt_string = GNUNET_strdup (attest->data);
  jwt_body = strtok (jwt_string, delim);
  jwt_body = strtok (NULL, delim);
  GNUNET_STRINGS_base64url_decode (jwt_body, strlen (jwt_body),
                                   (void **) &decoded_jwt);
  json_val = json_loads (decoded_jwt, JSON_DECODE_ANY, json_err);
  exp_json = json_object_get (json_val, "exp");
  if ((NULL == exp_json) || (! json_is_integer (exp_json)))
    return GNUNET_SYSERR;
  exp->abs_value_us = json_integer_value (exp_json) * 1000 * 1000;
  GNUNET_free (jwt_string);
  return GNUNET_OK;
}


/**
 * Entry point for the plugin.
 *
 * @param cls NULL
 * @return the exported block API
 */
void *
libgnunet_plugin_reclaim_attestation_jwt_init (void *cls)
{
  struct GNUNET_RECLAIM_AttestationPluginFunctions *api;

  api = GNUNET_new (struct GNUNET_RECLAIM_AttestationPluginFunctions);
  api->value_to_string = &jwt_value_to_string;
  api->string_to_value = &jwt_string_to_value;
  api->typename_to_number = &jwt_typename_to_number;
  api->number_to_typename = &jwt_number_to_typename;
  api->get_attributes = &jwt_parse_attributes;
  api->get_issuer = &jwt_get_issuer;
  api->get_expiration = &jwt_get_expiration;
  return api;
}


/**
 * Exit point from the plugin.
 *
 * @param cls the return value from #libgnunet_plugin_block_test_init()
 * @return NULL
 */
void *
libgnunet_plugin_reclaim_attestation_jwt_done (void *cls)
{
  struct GNUNET_RECLAIM_AttestationPluginFunctions *api = cls;

  GNUNET_free (api);
  return NULL;
}


/* end of plugin_reclaim_attestation_type_gnuid.c */

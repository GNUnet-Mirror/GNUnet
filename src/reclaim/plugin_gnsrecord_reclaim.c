/*
     This file is part of GNUnet
     Copyright (C) 2013, 2014 GNUnet e.V.

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
 * @file reclaim/plugin_gnsrecord_reclaim.c
 * @brief gnsrecord plugin to provide the API for identity records
 * @author Martin Schanzenbach
 */
#include "platform.h"

#include "gnunet_util_lib.h"

#include "gnunet_gnsrecord_lib.h"
#include "gnunet_gnsrecord_plugin.h"

/**
 * Convert the 'value' of a record to a string.
 *
 * @param cls closure, unused
 * @param type type of the record
 * @param data value in binary encoding
 * @param data_size number of bytes in @a data
 * @return NULL on error, otherwise human-readable representation of the value
 */
static char *
value_to_string (void *cls, uint32_t type, const void *data, size_t data_size)
{
  switch (type)
  {
  case GNUNET_GNSRECORD_TYPE_RECLAIM_ATTR:
    return GNUNET_STRINGS_data_to_string_alloc (data, data_size);

  case GNUNET_GNSRECORD_TYPE_RECLAIM_OIDC_REDIRECT:
  case GNUNET_GNSRECORD_TYPE_RECLAIM_OIDC_CLIENT:
    return GNUNET_strndup (data, data_size);

  case GNUNET_GNSRECORD_TYPE_RECLAIM_ATTR_REF:
  case GNUNET_GNSRECORD_TYPE_RECLAIM_TICKET:
  case GNUNET_GNSRECORD_TYPE_RECLAIM_MASTER:
  case GNUNET_GNSRECORD_TYPE_RECLAIM_ATTEST_ATTR:
  case GNUNET_GNSRECORD_TYPE_RECLAIM_ATTEST_REF:
    return GNUNET_STRINGS_data_to_string_alloc (data, data_size);

  default:
    return NULL;
  }
}


/**
 * Convert human-readable version of a 'value' of a record to the binary
 * representation.
 *
 * @param cls closure, unused
 * @param type type of the record
 * @param s human-readable string
 * @param data set to value in binary encoding (will be allocated)
 * @param data_size set to number of bytes in @a data
 * @return #GNUNET_OK on success
 */
static int
string_to_value (void *cls, uint32_t type, const char *s, void **data,
                 size_t *data_size)
{
  if (NULL == s)
    return GNUNET_SYSERR;
  switch (type)
  {
  case GNUNET_GNSRECORD_TYPE_RECLAIM_ATTR:
    return GNUNET_STRINGS_string_to_data (s, strlen (s), *data, *data_size);

  case GNUNET_GNSRECORD_TYPE_RECLAIM_OIDC_REDIRECT:
  case GNUNET_GNSRECORD_TYPE_RECLAIM_OIDC_CLIENT:
    *data = GNUNET_strdup (s);
    *data_size = strlen (s);
    return GNUNET_OK;

  case GNUNET_GNSRECORD_TYPE_RECLAIM_ATTR_REF:
  case GNUNET_GNSRECORD_TYPE_RECLAIM_MASTER:
  case GNUNET_GNSRECORD_TYPE_RECLAIM_TICKET:
  case GNUNET_GNSRECORD_TYPE_RECLAIM_ATTEST_ATTR:
  case GNUNET_GNSRECORD_TYPE_RECLAIM_ATTEST_REF:
    return GNUNET_STRINGS_string_to_data (s, strlen (s), *data, *data_size);

  default:
    return GNUNET_SYSERR;
  }
}


/**
 * Mapping of record type numbers to human-readable
 * record type names.
 */
static struct
{
  const char *name;
  uint32_t number;
} name_map[] = {
  { "RECLAIM_ATTR", GNUNET_GNSRECORD_TYPE_RECLAIM_ATTR },
  { "RECLAIM_ATTR_REF", GNUNET_GNSRECORD_TYPE_RECLAIM_ATTR_REF },
  { "RECLAIM_ATTEST", GNUNET_GNSRECORD_TYPE_RECLAIM_ATTEST_ATTR },
  { "RECLAIM_MASTER", GNUNET_GNSRECORD_TYPE_RECLAIM_MASTER },
  { "RECLAIM_OIDC_CLIENT", GNUNET_GNSRECORD_TYPE_RECLAIM_OIDC_CLIENT },
  { "RECLAIM_OIDC_REDIRECT", GNUNET_GNSRECORD_TYPE_RECLAIM_OIDC_REDIRECT },
  { "RECLAIM_TICKET", GNUNET_GNSRECORD_TYPE_RECLAIM_TICKET },
  { "RECLAIM_ATTEST_REF", GNUNET_GNSRECORD_TYPE_RECLAIM_ATTEST_REF },
  { NULL, UINT32_MAX }
};


/**
 * Convert a type name (i.e. "AAAA") to the corresponding number.
 *
 * @param cls closure, unused
 * @param dns_typename name to convert
 * @return corresponding number, UINT32_MAX on error
 */
static uint32_t
typename_to_number (void *cls, const char *dns_typename)
{
  unsigned int i;

  i = 0;
  while ((NULL != name_map[i].name) &&
         (0 != strcasecmp (dns_typename, name_map[i].name)))
    i++;
  return name_map[i].number;
}


/**
 * Convert a type number (i.e. 1) to the corresponding type string (i.e. "A")
 *
 * @param cls closure, unused
 * @param type number of a type to convert
 * @return corresponding typestring, NULL on error
 */
static const char *
number_to_typename (void *cls, uint32_t type)
{
  unsigned int i;

  i = 0;
  while ((NULL != name_map[i].name) && (type != name_map[i].number))
    i++;
  return name_map[i].name;
}


/**
 * Entry point for the plugin.
 *
 * @param cls NULL
 * @return the exported block API
 */
void *
libgnunet_plugin_gnsrecord_reclaim_init (void *cls)
{
  struct GNUNET_GNSRECORD_PluginFunctions *api;

  api = GNUNET_new (struct GNUNET_GNSRECORD_PluginFunctions);
  api->value_to_string = &value_to_string;
  api->string_to_value = &string_to_value;
  api->typename_to_number = &typename_to_number;
  api->number_to_typename = &number_to_typename;
  return api;
}


/**
 * Exit point from the plugin.
 *
 * @param cls the return value from #libgnunet_plugin_block_test_init
 * @return NULL
 */
void *
libgnunet_plugin_gnsrecord_reclaim_done (void *cls)
{
  struct GNUNET_GNSRECORD_PluginFunctions *api = cls;

  GNUNET_free (api);
  return NULL;
}


/* end of plugin_gnsrecord_dns.c */

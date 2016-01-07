/*
     This file is part of GNUnet
     Copyright (C) 2013, 2014 Christian Grothoff (and other contributing authors)

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
     Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
     Boston, MA 02110-1301, USA.
*/

/**
 * @file identity/plugin_gnsrecord_identity.c
 * @brief gnsrecord plugin to provide the API for identity records
 * @author Christian Grothoff
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
value_to_string (void *cls,
                 uint32_t type,
                 const void *data,
                 size_t data_size)
{
  const struct GNUNET_CRYPTO_EcdhePrivateKey *ecdhe_privkey;
  const struct GNUNET_CRYPTO_EcdsaPublicKey *audience_pubkey;
  const char *scopes;
  char *ecdhe_str;
  char *aud_str;
  char *result;

  switch (type)
  {
    case GNUNET_GNSRECORD_TYPE_ID_ATTR:
    case GNUNET_GNSRECORD_TYPE_ID_TOKEN:
      return GNUNET_strndup (data, data_size);
    case GNUNET_GNSRECORD_TYPE_ID_TOKEN_METADATA:
        ecdhe_privkey = data;
        audience_pubkey = data+sizeof (struct GNUNET_CRYPTO_EcdhePrivateKey);
        scopes =  (char*) audience_pubkey+(sizeof (struct GNUNET_CRYPTO_EcdsaPublicKey));
        ecdhe_str = GNUNET_STRINGS_data_to_string_alloc (ecdhe_privkey,
                                                        sizeof (struct GNUNET_CRYPTO_EcdhePrivateKey));
        aud_str = GNUNET_STRINGS_data_to_string_alloc (audience_pubkey,
                                                       sizeof (struct GNUNET_CRYPTO_EcdsaPublicKey));
        GNUNET_asprintf (&result,
                         "%s;%s;%s",
                         ecdhe_str, aud_str, scopes);
        return result;

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
string_to_value (void *cls,
                 uint32_t type,
                 const char *s,
                 void **data,
                 size_t *data_size)
{
  char* ecdhe_str;
  char* aud_keystr;
  char* write_ptr;
  char* tmp_tok;
  char* str;

  if (NULL == s)
    return GNUNET_SYSERR;
  switch (type)
  {
    case GNUNET_GNSRECORD_TYPE_ID_ATTR:
    case GNUNET_GNSRECORD_TYPE_ID_TOKEN:
      *data = GNUNET_strdup (s);
      *data_size = strlen (s);
      return GNUNET_OK;
    case GNUNET_GNSRECORD_TYPE_ID_TOKEN_METADATA:
            tmp_tok = GNUNET_strdup (s);
      ecdhe_str = strtok (tmp_tok, ";");
      if (NULL == ecdhe_str)
      {
        GNUNET_free (tmp_tok);
        return GNUNET_SYSERR;
      }
      aud_keystr = strtok (NULL, ";");
      if (NULL == aud_keystr)
      {
        GNUNET_free (tmp_tok);
        return GNUNET_SYSERR;
      }
      str = strtok (NULL, ";");
      if (NULL == str)
      {
        GNUNET_free (tmp_tok);
        return GNUNET_SYSERR;
      }
      *data_size = strlen (str) + 1
        +sizeof (struct GNUNET_CRYPTO_EcdhePrivateKey)
        +sizeof (struct GNUNET_CRYPTO_EcdsaPublicKey);
      *data = GNUNET_malloc (*data_size);

      write_ptr = *data;
      GNUNET_STRINGS_string_to_data (ecdhe_str,
                                     strlen (ecdhe_str),
                                     write_ptr,
                                     sizeof (struct GNUNET_CRYPTO_EcdhePrivateKey));
      write_ptr += sizeof (struct GNUNET_CRYPTO_EcdhePrivateKey);
      GNUNET_STRINGS_string_to_data (aud_keystr,
                                     strlen (aud_keystr),
                                     write_ptr,
                                     sizeof (struct GNUNET_CRYPTO_EcdsaPublicKey));
      write_ptr += sizeof (struct GNUNET_CRYPTO_EcdsaPublicKey);
      memcpy (write_ptr, str, strlen (str) + 1); //with 0-Terminator
      GNUNET_free (tmp_tok);
      return GNUNET_OK;

    default:
      return GNUNET_SYSERR;
  }
}


/**
 * Mapping of record type numbers to human-readable
 * record type names.
 */
        static struct {
          const char *name;
          uint32_t number;
        } name_map[] = {
          { "ID_ATTR", GNUNET_GNSRECORD_TYPE_ID_ATTR },
          { "ID_TOKEN", GNUNET_GNSRECORD_TYPE_ID_TOKEN },
          { "ID_TOKEN_METADATA", GNUNET_GNSRECORD_TYPE_ID_TOKEN_METADATA },
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
typename_to_number (void *cls,
                    const char *dns_typename)
{
  unsigned int i;

  i=0;
  while ( (NULL != name_map[i].name) &&
          (0 != strcasecmp (dns_typename, name_map[i].name)) )
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
number_to_typename (void *cls,
                    uint32_t type)
{
  unsigned int i;

  i=0;
  while ( (NULL != name_map[i].name) &&
          (type != name_map[i].number) )
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
libgnunet_plugin_gnsrecord_identity_init (void *cls)
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
libgnunet_plugin_gnsrecord_identity_done (void *cls)
{
  struct GNUNET_GNSRECORD_PluginFunctions *api = cls;

  GNUNET_free (api);
  return NULL;
}

/* end of plugin_gnsrecord_dns.c */

/*
     This file is part of GNUnet
     Copyright (C) 2013 GNUnet e.V.

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
 * @file credential/plugin_gnsrecord_credential.c
 * @brief gnsrecord plugin to provide the API for CREDENTIAL records
 * @author Martin Schanzenbach
 */
#include "platform.h"

#include "gnunet_util_lib.h"

#include "credential_misc.h"
#include "delegate_misc.h"
#include "credential_serialization.h"
#include "gnunet_credential_service.h"
#include "gnunet_gnsrecord_lib.h"
#include "gnunet_gnsrecord_plugin.h"
#include "gnunet_signatures.h"
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
credential_value_to_string (void *cls,
                            uint32_t type,
                            const void *data,
                            size_t data_size)
{
  const char *cdata;

  switch (type)
  {
  case GNUNET_GNSRECORD_TYPE_ATTRIBUTE:
  {
    struct GNUNET_CREDENTIAL_DelegationRecord sets;
    char *attr_str;
    char *subject_pkey;
    char *tmp_str;
    int i;
    if (data_size < sizeof (struct GNUNET_CREDENTIAL_DelegationRecord))
      return NULL; /* malformed */

    GNUNET_memcpy (&sets, data, sizeof (sets));
    cdata = data;

    struct GNUNET_CREDENTIAL_DelegationSet set[ntohl (sets.set_count)];
    if (GNUNET_OK !=
        GNUNET_CREDENTIAL_delegation_set_deserialize (GNUNET_ntohll (
                                                        sets.data_size),
                                                      &cdata[sizeof (sets)],
                                                      ntohl (sets.set_count),
                                                      set))
      return NULL;

    for (i = 0; i < ntohl (sets.set_count); i++)
    {
      subject_pkey =
        GNUNET_CRYPTO_ecdsa_public_key_to_string (&set[i].subject_key);
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "%d len attr\n",
                  set[i].subject_attribute_len);
      if (0 == set[i].subject_attribute_len)
      {
        if (0 == i)
        {
          GNUNET_asprintf (&attr_str, "%s", subject_pkey);
        }
        else
        {
          GNUNET_asprintf (&tmp_str, "%s,%s", attr_str, subject_pkey);
          GNUNET_free (attr_str);
          attr_str = tmp_str;
        }
      }
      else
      {
        if (0 == i)
        {
          GNUNET_asprintf (&attr_str,
                           "%s %s",
                           subject_pkey,
                           set[i].subject_attribute);
        }
        else
        {
          GNUNET_asprintf (&tmp_str,
                           "%s,%s %s",
                           attr_str,
                           subject_pkey,
                           set[i].subject_attribute);
          GNUNET_free (attr_str);
          attr_str = tmp_str;
        }
      }
      GNUNET_free (subject_pkey);
    }
    return attr_str;
  }
  case GNUNET_GNSRECORD_TYPE_CREDENTIAL:
  {
    struct GNUNET_CREDENTIAL_Credential *cred;
    char *cred_str;

    cred = GNUNET_CREDENTIAL_credential_deserialize (data, data_size);
    cred_str = GNUNET_CREDENTIAL_credential_to_string (cred);
    GNUNET_free (cred);
    return cred_str;
  }
  case GNUNET_GNSRECORD_TYPE_DELEGATE:
  {
    struct GNUNET_CREDENTIAL_Delegate *cred;
    char *cred_str;

    cred = GNUNET_CREDENTIAL_delegate_deserialize (data, data_size);
    cred_str = GNUNET_CREDENTIAL_delegate_to_string (cred);
    GNUNET_free (cred);
    return cred_str;
  }
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
credential_string_to_value (void *cls,
                            uint32_t type,
                            const char *s,
                            void **data,
                            size_t *data_size)
{
  if (NULL == s)
    return GNUNET_SYSERR;
  switch (type)
  {
  case GNUNET_GNSRECORD_TYPE_ATTRIBUTE:
  {
    struct GNUNET_CREDENTIAL_DelegationRecord *sets;
    char attr_str[253 + 1];
    char subject_pkey[52 + 1];
    char *token;
    char *tmp_str;
    int matches = 0;
    int entries;
    size_t tmp_data_size;
    int i;

    tmp_str = GNUNET_strdup (s);
    token = strtok (tmp_str, ",");
    entries = 0;
    tmp_data_size = 0;
    *data_size = sizeof (struct GNUNET_CREDENTIAL_DelegationRecord);
    while (NULL != token)
    {
      // also fills the variables subject_pley and attr_str if "regex"-like match
      matches = SSCANF (token, "%s %s", subject_pkey, attr_str);

      if (0 == matches)
      {
        GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                    _ ("Unable to parse ATTR record string `%s'\n"),
                    s);
        GNUNET_free (tmp_str);
        return GNUNET_SYSERR;
      }

      entries++;
      token = strtok (NULL, ",");
    }
    GNUNET_free (tmp_str);

    tmp_str = GNUNET_strdup (s);
    token = strtok (tmp_str, ",");
    if (NULL == token)
    {
      GNUNET_free (tmp_str);
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Malformed string %s\n", s);
      return GNUNET_SYSERR;
    }

    struct GNUNET_CREDENTIAL_DelegationSet set[entries];
    // sets memory to be 0, starting at *set for the size of struct * entries
    memset (set, 0, sizeof (struct GNUNET_CREDENTIAL_DelegationSet) * entries);
    for (i = 0; i < entries; i++)
    {
      matches = SSCANF (token, "%s %s", subject_pkey, attr_str);

      // sets the public key for the set entry
      GNUNET_CRYPTO_ecdsa_public_key_from_string (subject_pkey,
                                                  strlen (subject_pkey),
                                                  &set[i].subject_key);

      // If not just key, also set subject attribute (Not A.a <- B but A.a <- B.b)
      if (2 == matches)
      {
        set[i].subject_attribute_len = strlen (attr_str) + 1;
        set[i].subject_attribute = GNUNET_strdup (attr_str);
      }
      // If more entries, then token string can take the next entry (separated by ',') by calling strtok again
      token = strtok (NULL, ",");
    }
    tmp_data_size = GNUNET_CREDENTIAL_delegation_set_get_size (entries, set);

    if (-1 == tmp_data_size)
    {
      GNUNET_free (tmp_str);
      return GNUNET_SYSERR;
    }
    *data_size += tmp_data_size;
    *data = sets = GNUNET_malloc (*data_size);
    GNUNET_CREDENTIAL_delegation_set_serialize (entries,
                                                set,
                                                tmp_data_size,
                                                (char *) &sets[1]);
    for (i = 0; i < entries; i++)
    {
      if (0 != set[i].subject_attribute_len)
        GNUNET_free ((char *) set[i].subject_attribute);
    }
    sets->set_count = htonl (entries);
    sets->data_size = GNUNET_htonll (tmp_data_size);

    GNUNET_free (tmp_str);
    return GNUNET_OK;
  }
  case GNUNET_GNSRECORD_TYPE_CREDENTIAL:
  {
    struct GNUNET_CREDENTIAL_Credential *cred;
    cred = GNUNET_CREDENTIAL_credential_from_string (s);

    *data_size = GNUNET_CREDENTIAL_credential_serialize (cred, (char **) data);
    return GNUNET_OK;
  }
  case GNUNET_GNSRECORD_TYPE_DELEGATE:
  {
    struct GNUNET_CREDENTIAL_Delegate *cred;
    cred = GNUNET_CREDENTIAL_delegate_from_string (s);

    *data_size = GNUNET_CREDENTIAL_delegate_serialize (cred, (char **) data);

    return GNUNET_OK;
  }
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
} name_map[] = {{"CRED", GNUNET_GNSRECORD_TYPE_CREDENTIAL},
                {"ATTR", GNUNET_GNSRECORD_TYPE_ATTRIBUTE},
                {"DEL", GNUNET_GNSRECORD_TYPE_DELEGATE},
                {NULL, UINT32_MAX}};


/**
 * Convert a type name (i.e. "AAAA") to the corresponding number.
 *
 * @param cls closure, unused
 * @param gns_typename name to convert
 * @return corresponding number, UINT32_MAX on error
 */
static uint32_t
credential_typename_to_number (void *cls, const char *gns_typename)
{
  unsigned int i;

  i = 0;
  while ((name_map[i].name != NULL) &&
         (0 != strcasecmp (gns_typename, name_map[i].name)))
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
credential_number_to_typename (void *cls, uint32_t type)
{
  unsigned int i;

  i = 0;
  while ((name_map[i].name != NULL) && (type != name_map[i].number))
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
libgnunet_plugin_gnsrecord_credential_init (void *cls)
{
  struct GNUNET_GNSRECORD_PluginFunctions *api;

  api = GNUNET_new (struct GNUNET_GNSRECORD_PluginFunctions);
  api->value_to_string = &credential_value_to_string;
  api->string_to_value = &credential_string_to_value;
  api->typename_to_number = &credential_typename_to_number;
  api->number_to_typename = &credential_number_to_typename;
  return api;
}


/**
 * Exit point from the plugin.
 *
 * @param cls the return value from #libgnunet_plugin_block_test_init
 * @return NULL
 */
void *
libgnunet_plugin_gnsrecord_credential_done (void *cls)
{
  struct GNUNET_GNSRECORD_PluginFunctions *api = cls;

  GNUNET_free (api);
  return NULL;
}

/* end of plugin_gnsrecord_credential.c */

/*
   This file is part of GNUnet
   Copyright (C) 2010-2015 GNUnet e.V.

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
 * @file reclaim-attribute/reclaim_attestation.c
 * @brief helper library to manage identity attribute attestations
 * @author Martin Schanzenbach
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_reclaim_plugin.h"
#include "reclaim_attestation.h"


/**
 * Handle for a plugin
 */
struct Plugin
{
  /**
   * Name of the plugin
   */
  char *library_name;

  /**
   * Plugin API
   */
  struct GNUNET_RECLAIM_AttestationPluginFunctions *api;
};


/**
 * Plugins
 */
static struct Plugin **attest_plugins;


/**
 * Number of plugins
 */
static unsigned int num_plugins;


/**
 * Init canary
 */
static int initialized;


/**
 * Add a plugin
 *
 * @param cls closure
 * @param library_name name of the API library
 * @param lib_ret the plugin API pointer
 */
static void
add_plugin (void *cls, const char *library_name, void *lib_ret)
{
  struct GNUNET_RECLAIM_AttestationPluginFunctions *api = lib_ret;
  struct Plugin *plugin;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Loading attestation plugin `%s'\n",
              library_name);
  plugin = GNUNET_new (struct Plugin);
  plugin->api = api;
  plugin->library_name = GNUNET_strdup (library_name);
  GNUNET_array_append (attest_plugins, num_plugins, plugin);
}


/**
 * Load plugins
 */
static void
init ()
{
  if (GNUNET_YES == initialized)
    return;
  initialized = GNUNET_YES;
  GNUNET_PLUGIN_load_all ("libgnunet_plugin_reclaim_attestation_",
                          NULL,
                          &add_plugin,
                          NULL);
}


/**
 * Convert an attestation type name to the corresponding number
 *
 * @param typename name to convert
 * @return corresponding number, UINT32_MAX on error
 */
uint32_t
GNUNET_RECLAIM_attestation_typename_to_number (const char *typename)
{
  unsigned int i;
  struct Plugin *plugin;
  uint32_t ret;
  init ();
  for (i = 0; i < num_plugins; i++)
  {
    plugin = attest_plugins[i];
    if (UINT32_MAX !=
        (ret = plugin->api->typename_to_number (plugin->api->cls,
                                                typename)))
      return ret;
  }
  return UINT32_MAX;
}


/**
 * Convert an attestation type number to the corresponding attestation type string
 *
 * @param type number of a type
 * @return corresponding typestring, NULL on error
 */
const char *
GNUNET_RECLAIM_attestation_number_to_typename (uint32_t type)
{
  unsigned int i;
  struct Plugin *plugin;
  const char *ret;

  init ();
  for (i = 0; i < num_plugins; i++)
  {
    plugin = attest_plugins[i];
    if (NULL !=
        (ret = plugin->api->number_to_typename (plugin->api->cls, type)))
      return ret;
  }
  return NULL;
}


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
                                            size_t *data_size)
{
  unsigned int i;
  struct Plugin *plugin;

  init ();
  for (i = 0; i < num_plugins; i++)
  {
    plugin = attest_plugins[i];
    if (GNUNET_OK == plugin->api->string_to_value (plugin->api->cls,
                                                   type,
                                                   s,
                                                   data,
                                                   data_size))
      return GNUNET_OK;
  }
  return GNUNET_SYSERR;
}


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
                                            size_t data_size)
{
  unsigned int i;
  struct Plugin *plugin;
  char *ret;

  init ();
  for (i = 0; i < num_plugins; i++)
  {
    plugin = attest_plugins[i];
    if (NULL != (ret = plugin->api->value_to_string (plugin->api->cls,
                                                     type,
                                                     data,
                                                     data_size)))
      return ret;
  }
  return NULL;
}


/**
   * Create a new attestation.
   *
   * @param attr_name the attestation name
   * @param type the attestation type
   * @param data the attestation value
   * @param data_size the attestation value size
   * @return the new attestation
   */
struct GNUNET_RECLAIM_Attestation *
GNUNET_RECLAIM_attestation_new (const char *attr_name,
                                uint32_t type,
                                const void *data,
                                size_t data_size)
{
  struct GNUNET_RECLAIM_Attestation *attr;
  char *write_ptr;
  char *attr_name_tmp = GNUNET_strdup (attr_name);

  GNUNET_STRINGS_utf8_tolower (attr_name, attr_name_tmp);

  attr = GNUNET_malloc (sizeof(struct GNUNET_RECLAIM_Attestation)
                        + strlen (attr_name_tmp) + 1 + data_size);
  attr->type = type;
  attr->data_size = data_size;
  attr->flag = 0;
  write_ptr = (char *) &attr[1];
  GNUNET_memcpy (write_ptr, attr_name_tmp, strlen (attr_name_tmp) + 1);
  attr->name = write_ptr;
  write_ptr += strlen (attr->name) + 1;
  GNUNET_memcpy (write_ptr, data, data_size);
  attr->data = write_ptr;
  GNUNET_free (attr_name_tmp);
  return attr;
}


/**
 * Get required size for serialization buffer
 *
 * @param attrs the attribute list to serialize
 * @return the required buffer size
 */
size_t
GNUNET_RECLAIM_attestation_list_serialize_get_size (
  const struct GNUNET_RECLAIM_AttestationList *attestations)
{
  struct GNUNET_RECLAIM_AttestationListEntry *le;
  size_t len = 0;

  for (le = attestations->list_head; NULL != le; le = le->next)
  {
    GNUNET_assert (NULL != le->attestation);
    len += GNUNET_RECLAIM_attestation_serialize_get_size (le->attestation);
    len += sizeof(struct GNUNET_RECLAIM_AttestationListEntry);
  }
  return len;
}


/**
 * Serialize an attribute list
 *
 * @param attrs the attribute list to serialize
 * @param result the serialized attribute
 * @return length of serialized data
 */
size_t
GNUNET_RECLAIM_attestation_list_serialize (
  const struct GNUNET_RECLAIM_AttestationList *attestations,
  char *result)
{
  struct GNUNET_RECLAIM_AttestationListEntry *le;
  size_t len;
  size_t total_len;
  char *write_ptr;
  write_ptr = result;
  total_len = 0;
  for (le = attestations->list_head; NULL != le; le = le->next)
  {
    GNUNET_assert (NULL != le->attestation);
    len = GNUNET_RECLAIM_attestation_serialize (le->attestation, write_ptr);
    total_len += len;
    write_ptr += len;
  }
  return total_len;
}


/**
 * Deserialize an attestation list
 *
 * @param data the serialized attribute list
 * @param data_size the length of the serialized data
 * @return a GNUNET_IDENTITY_PROVIDER_AttributeList, must be free'd by caller
 */
struct GNUNET_RECLAIM_AttestationList *
GNUNET_RECLAIM_attestation_list_deserialize (const char *data, size_t data_size)
{
  struct GNUNET_RECLAIM_AttestationList *al;
  struct GNUNET_RECLAIM_AttestationListEntry *ale;
  size_t att_len;
  const char *read_ptr;

  al = GNUNET_new (struct GNUNET_RECLAIM_AttestationList);

  if ((data_size < sizeof(struct
                          Attestation)
       + sizeof(struct GNUNET_RECLAIM_AttestationListEntry)))
    return al;

  read_ptr = data;
  while (((data + data_size) - read_ptr) >= sizeof(struct Attestation))
  {
    ale = GNUNET_new (struct GNUNET_RECLAIM_AttestationListEntry);
    ale->attestation =
      GNUNET_RECLAIM_attestation_deserialize (read_ptr,
                                              data_size - (read_ptr - data));
    if (NULL == ale->attestation)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  "Failed to deserialize malformed attestation.\n");
      GNUNET_free (ale);
      return al;
    }
    GNUNET_CONTAINER_DLL_insert (al->list_head, al->list_tail, ale);
    att_len = GNUNET_RECLAIM_attestation_serialize_get_size (ale->attestation);
    read_ptr += att_len;
  }
  return al;
}


/**
 * Make a (deep) copy of the attestation list
 * @param attrs claim list to copy
 * @return copied claim list
 */
struct GNUNET_RECLAIM_AttestationList *
GNUNET_RECLAIM_attestation_list_dup (
  const struct GNUNET_RECLAIM_AttestationList *al)
{
  struct GNUNET_RECLAIM_AttestationListEntry *ale;
  struct GNUNET_RECLAIM_AttestationListEntry *result_ale;
  struct GNUNET_RECLAIM_AttestationList *result;

  result = GNUNET_new (struct GNUNET_RECLAIM_AttestationList);
  for (ale = al->list_head; NULL != ale; ale = ale->next)
  {
    result_ale = GNUNET_new (struct GNUNET_RECLAIM_AttestationListEntry);
    GNUNET_assert (NULL != ale->attestation);
    result_ale->attestation =
      GNUNET_RECLAIM_attestation_new (ale->attestation->name,
                                      ale->attestation->type,
                                      ale->attestation->data,
                                      ale->attestation->data_size);
    result_ale->attestation->id = ale->attestation->id;
    GNUNET_CONTAINER_DLL_insert (result->list_head,
                                 result->list_tail,
                                 result_ale);
  }
  return result;
}


/**
 * Destroy attestation list
 *
 * @param attrs list to destroy
 */
void
GNUNET_RECLAIM_attestation_list_destroy (
  struct GNUNET_RECLAIM_AttestationList *al)
{
  struct GNUNET_RECLAIM_AttestationListEntry *ale;
  struct GNUNET_RECLAIM_AttestationListEntry *tmp_ale;

  for (ale = al->list_head; NULL != ale;)
  {
    if (NULL != ale->attestation)
      GNUNET_free (ale->attestation);
    tmp_ale = ale;
    ale = ale->next;
    GNUNET_free (tmp_ale);
  }
  GNUNET_free (al);
}


/**
 * Get required size for serialization buffer
 *
 * @param attr the attestation to serialize
 * @return the required buffer size
 */
size_t
GNUNET_RECLAIM_attestation_serialize_get_size (
  const struct GNUNET_RECLAIM_Attestation *attestation)
{
  return sizeof(struct Attestation) + strlen (attestation->name)
         + attestation->data_size;
}


/**
 * Serialize an attestation
 *
 * @param attr the attestation to serialize
 * @param result the serialized attestation
 * @return length of serialized data
 */
size_t
GNUNET_RECLAIM_attestation_serialize (
  const struct GNUNET_RECLAIM_Attestation *attestation,
  char *result)
{
  size_t data_len_ser;
  size_t name_len;
  struct Attestation *atts;
  char *write_ptr;

  atts = (struct Attestation *) result;
  atts->attestation_type = htons (attestation->type);
  atts->attestation_flag = htonl (attestation->flag);
  atts->attestation_id = attestation->id;
  name_len = strlen (attestation->name);
  atts->name_len = htons (name_len);
  write_ptr = (char *) &atts[1];
  GNUNET_memcpy (write_ptr, attestation->name, name_len);
  write_ptr += name_len;
  // TODO plugin-ize
  // data_len_ser = plugin->serialize_attribute_value (attr,
  //                                                  &attr_ser[1]);
  data_len_ser = attestation->data_size;
  GNUNET_memcpy (write_ptr, attestation->data, attestation->data_size);
  atts->data_size = htons (data_len_ser);

  return sizeof(struct Attestation) + strlen (attestation->name)
         + attestation->data_size;
}


/**
 * Deserialize an attestation
 *
 * @param data the serialized attestation
 * @param data_size the length of the serialized data
 *
 * @return a GNUNET_IDENTITY_PROVIDER_Attribute, must be free'd by caller
 */
struct GNUNET_RECLAIM_Attestation *
GNUNET_RECLAIM_attestation_deserialize (const char *data, size_t data_size)
{
  struct GNUNET_RECLAIM_Attestation *attestation;
  struct Attestation *atts;
  size_t data_len;
  size_t name_len;
  char *write_ptr;

  if (data_size < sizeof(struct Attestation))
    return NULL;

  atts = (struct Attestation *) data;
  data_len = ntohs (atts->data_size);
  name_len = ntohs (atts->name_len);
  if (data_size < sizeof(struct Attestation) + data_len + name_len)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Buffer too small to deserialize\n");
    return NULL;
  }
  attestation = GNUNET_malloc (sizeof(struct GNUNET_RECLAIM_Attestation)
                               + data_len + name_len + 1);
  attestation->type = ntohs (atts->attestation_type);
  attestation->flag = ntohl (atts->attestation_flag);
  attestation->id = atts->attestation_id;
  attestation->data_size = data_len;

  write_ptr = (char *) &attestation[1];
  GNUNET_memcpy (write_ptr, &atts[1], name_len);
  write_ptr[name_len] = '\0';
  attestation->name = write_ptr;

  write_ptr += name_len + 1;
  GNUNET_memcpy (write_ptr, (char *) &atts[1] + name_len,
                 attestation->data_size);
  attestation->data = write_ptr;
  return attestation;
}


struct GNUNET_RECLAIM_AttributeList*
GNUNET_RECLAIM_attestation_get_attributes (const struct
                                           GNUNET_RECLAIM_Attestation *attest)
{
  unsigned int i;
  struct Plugin *plugin;
  struct GNUNET_RECLAIM_AttributeList *ret;
  init ();
  for (i = 0; i < num_plugins; i++)
  {
    plugin = attest_plugins[i];
    if (NULL !=
        (ret = plugin->api->get_attributes (plugin->api->cls,
                                            attest)))
      return ret;
  }
  return NULL;
}


char*
GNUNET_RECLAIM_attestation_get_issuer (const struct
                                       GNUNET_RECLAIM_Attestation *attest)
{
  unsigned int i;
  struct Plugin *plugin;
  char *ret;
  init ();
  for (i = 0; i < num_plugins; i++)
  {
    plugin = attest_plugins[i];
    if (NULL !=
        (ret = plugin->api->get_issuer (plugin->api->cls,
                                        attest)))
      return ret;
  }
  return NULL;
}


int
GNUNET_RECLAIM_attestation_get_expiration (const struct
                                           GNUNET_RECLAIM_Attestation *attest,
                                           struct GNUNET_TIME_Absolute* exp)
{
  unsigned int i;
  struct Plugin *plugin;
  init ();
  for (i = 0; i < num_plugins; i++)
  {
    plugin = attest_plugins[i];
    if (GNUNET_OK !=  plugin->api->get_expiration (plugin->api->cls,
                                                   attest,
                                                   exp))
      continue;
    return GNUNET_OK;
  }
  return GNUNET_SYSERR;
}

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
 * @file reclaim-attribute/reclaim_attribute.c
 * @brief helper library to manage identity attributes
 * @author Martin Schanzenbach
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_reclaim_attribute_plugin.h"
#include "reclaim_attribute.h"


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
  struct GNUNET_RECLAIM_ATTRIBUTE_PluginFunctions *api;
};


/**
 * Plugins
 */
static struct Plugin **attr_plugins;


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
  struct GNUNET_RECLAIM_ATTRIBUTE_PluginFunctions *api = lib_ret;
  struct Plugin *plugin;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Loading attribute plugin `%s'\n",
              library_name);
  plugin = GNUNET_new (struct Plugin);
  plugin->api = api;
  plugin->library_name = GNUNET_strdup (library_name);
  GNUNET_array_append (attr_plugins, num_plugins, plugin);
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
  GNUNET_PLUGIN_load_all ("libgnunet_plugin_reclaim_attribute_",
                          NULL,
                          &add_plugin,
                          NULL);
}


/**
 * Convert a type name to the corresponding number
 *
 * @param typename name to convert
 * @return corresponding number, UINT32_MAX on error
 */
uint32_t
GNUNET_RECLAIM_ATTRIBUTE_typename_to_number (const char *typename)
{
  unsigned int i;
  struct Plugin *plugin;
  uint32_t ret;

  init ();
  for (i = 0; i < num_plugins; i++)
  {
    plugin = attr_plugins[i];
    if (UINT32_MAX !=
        (ret = plugin->api->typename_to_number (plugin->api->cls, typename)))
      return ret;
  }
  return UINT32_MAX;
}


/**
 * Convert a type number to the corresponding type string
 *
 * @param type number of a type
 * @return corresponding typestring, NULL on error
 */
const char *
GNUNET_RECLAIM_ATTRIBUTE_number_to_typename (uint32_t type)
{
  unsigned int i;
  struct Plugin *plugin;
  const char *ret;

  init ();
  for (i = 0; i < num_plugins; i++)
  {
    plugin = attr_plugins[i];
    if (NULL !=
        (ret = plugin->api->number_to_typename (plugin->api->cls, type)))
      return ret;
  }
  return NULL;
}


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
                                          size_t *data_size)
{
  unsigned int i;
  struct Plugin *plugin;

  init ();
  for (i = 0; i < num_plugins; i++)
  {
    plugin = attr_plugins[i];
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
                                          size_t data_size)
{
  unsigned int i;
  struct Plugin *plugin;
  char *ret;

  init ();
  for (i = 0; i < num_plugins; i++)
  {
    plugin = attr_plugins[i];
    if (NULL != (ret = plugin->api->value_to_string (plugin->api->cls,
                                                     type,
                                                     data,
                                                     data_size)))
      return ret;
  }
  return NULL;
}


/**
 * Create a new attribute.
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
                                    size_t data_size)
{
  struct GNUNET_RECLAIM_ATTRIBUTE_Claim *attr;
  char *write_ptr;
  char *attr_name_tmp = GNUNET_strdup (attr_name);

  GNUNET_STRINGS_utf8_tolower (attr_name, attr_name_tmp);

  attr = GNUNET_malloc (sizeof (struct GNUNET_RECLAIM_ATTRIBUTE_Claim) +
                        strlen (attr_name_tmp) + 1 + data_size);
  attr->type = type;
  attr->data_size = data_size;
  attr->version = 0;
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
 * Add a new attribute to a claim list
 *
 * @param attr_name the name of the new attribute claim
 * @param type the type of the claim
 * @param data claim payload
 * @param data_size claim payload size
 */
void
GNUNET_RECLAIM_ATTRIBUTE_list_add (
  struct GNUNET_RECLAIM_ATTRIBUTE_ClaimList *claim_list,
  const char *attr_name,
  uint32_t type,
  const void *data,
  size_t data_size)
{
  struct GNUNET_RECLAIM_ATTRIBUTE_ClaimListEntry *le;
  le = GNUNET_new (struct GNUNET_RECLAIM_ATTRIBUTE_ClaimListEntry);
  le->claim =
    GNUNET_RECLAIM_ATTRIBUTE_claim_new (attr_name, type, data, data_size);
  GNUNET_CONTAINER_DLL_insert (claim_list->list_head,
                               claim_list->list_tail,
                               le);
}


/**
 * Get required size for serialization buffer
 *
 * @param attrs the attribute list to serialize
 * @return the required buffer size
 */
size_t
GNUNET_RECLAIM_ATTRIBUTE_list_serialize_get_size (
  const struct GNUNET_RECLAIM_ATTRIBUTE_ClaimList *attrs)
{
  struct GNUNET_RECLAIM_ATTRIBUTE_ClaimListEntry *le;
  size_t len = 0;
  for (le = attrs->list_head; NULL != le; le = le->next)
    len += GNUNET_RECLAIM_ATTRIBUTE_serialize_get_size (le->claim);
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
GNUNET_RECLAIM_ATTRIBUTE_list_serialize (
  const struct GNUNET_RECLAIM_ATTRIBUTE_ClaimList *attrs,
  char *result)
{
  struct GNUNET_RECLAIM_ATTRIBUTE_ClaimListEntry *le;
  size_t len;
  size_t total_len;
  char *write_ptr;

  write_ptr = result;
  total_len = 0;
  for (le = attrs->list_head; NULL != le; le = le->next)
  {
    len = GNUNET_RECLAIM_ATTRIBUTE_serialize (le->claim, write_ptr);
    total_len += len;
    write_ptr += len;
  }
  return total_len;
}


/**
 * Deserialize an attribute list
 *
 * @param data the serialized attribute list
 * @param data_size the length of the serialized data
 * @return a GNUNET_IDENTITY_PROVIDER_AttributeList, must be free'd by caller
 */
struct GNUNET_RECLAIM_ATTRIBUTE_ClaimList *
GNUNET_RECLAIM_ATTRIBUTE_list_deserialize (const char *data, size_t data_size)
{
  struct GNUNET_RECLAIM_ATTRIBUTE_ClaimList *attrs;
  struct GNUNET_RECLAIM_ATTRIBUTE_ClaimListEntry *le;
  size_t attr_len;
  const char *read_ptr;

  if (data_size < sizeof (struct Attribute))
    return NULL;

  attrs = GNUNET_new (struct GNUNET_RECLAIM_ATTRIBUTE_ClaimList);
  read_ptr = data;
  while (((data + data_size) - read_ptr) >= sizeof (struct Attribute))
  {

    le = GNUNET_new (struct GNUNET_RECLAIM_ATTRIBUTE_ClaimListEntry);
    le->claim =
      GNUNET_RECLAIM_ATTRIBUTE_deserialize (read_ptr,
                                            data_size - (read_ptr - data));
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Deserialized attribute %s\n",
                le->claim->name);
    GNUNET_CONTAINER_DLL_insert (attrs->list_head, attrs->list_tail, le);
    attr_len = GNUNET_RECLAIM_ATTRIBUTE_serialize_get_size (le->claim);
    read_ptr += attr_len;
  }
  return attrs;
}


/**
 * Make a (deep) copy of a claim list
 * @param attrs claim list to copy
 * @return copied claim list
 */
struct GNUNET_RECLAIM_ATTRIBUTE_ClaimList *
GNUNET_RECLAIM_ATTRIBUTE_list_dup (
  const struct GNUNET_RECLAIM_ATTRIBUTE_ClaimList *attrs)
{
  struct GNUNET_RECLAIM_ATTRIBUTE_ClaimListEntry *le;
  struct GNUNET_RECLAIM_ATTRIBUTE_ClaimListEntry *result_le;
  struct GNUNET_RECLAIM_ATTRIBUTE_ClaimList *result;

  result = GNUNET_new (struct GNUNET_RECLAIM_ATTRIBUTE_ClaimList);
  for (le = attrs->list_head; NULL != le; le = le->next)
  {
    result_le = GNUNET_new (struct GNUNET_RECLAIM_ATTRIBUTE_ClaimListEntry);
    result_le->claim =
      GNUNET_RECLAIM_ATTRIBUTE_claim_new (le->claim->name,
                                          le->claim->type,
                                          le->claim->data,
                                          le->claim->data_size);
    result_le->claim->version = le->claim->version;
    result_le->claim->id = le->claim->id;
    GNUNET_CONTAINER_DLL_insert (result->list_head,
                                 result->list_tail,
                                 result_le);
  }
  return result;
}


/**
 * Destroy claim list
 *
 * @param attrs list to destroy
 */
void
GNUNET_RECLAIM_ATTRIBUTE_list_destroy (
  struct GNUNET_RECLAIM_ATTRIBUTE_ClaimList *attrs)
{
  struct GNUNET_RECLAIM_ATTRIBUTE_ClaimListEntry *le;
  struct GNUNET_RECLAIM_ATTRIBUTE_ClaimListEntry *tmp_le;

  for (le = attrs->list_head; NULL != le;)
  {
    GNUNET_free (le->claim);
    tmp_le = le;
    le = le->next;
    GNUNET_free (tmp_le);
  }
  GNUNET_free (attrs);
}


/**
 * Get required size for serialization buffer
 *
 * @param attr the attribute to serialize
 * @return the required buffer size
 */
size_t
GNUNET_RECLAIM_ATTRIBUTE_serialize_get_size (
  const struct GNUNET_RECLAIM_ATTRIBUTE_Claim *attr)
{
  return sizeof (struct Attribute) + strlen (attr->name) + attr->data_size;
}


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
  char *result)
{
  size_t data_len_ser;
  size_t name_len;
  struct Attribute *attr_ser;
  char *write_ptr;

  attr_ser = (struct Attribute *) result;
  attr_ser->attribute_type = htons (attr->type);
  attr_ser->attribute_version = htonl (attr->version);
  attr_ser->attribute_id = GNUNET_htonll (attr->id);
  name_len = strlen (attr->name);
  attr_ser->name_len = htons (name_len);
  write_ptr = (char *) &attr_ser[1];
  GNUNET_memcpy (write_ptr, attr->name, name_len);
  write_ptr += name_len;
  // TODO plugin-ize
  // data_len_ser = plugin->serialize_attribute_value (attr,
  //                                                  &attr_ser[1]);
  data_len_ser = attr->data_size;
  GNUNET_memcpy (write_ptr, attr->data, attr->data_size);
  attr_ser->data_size = htons (data_len_ser);

  return sizeof (struct Attribute) + strlen (attr->name) + attr->data_size;
}


/**
 * Deserialize an attribute
 *
 * @param data the serialized attribute
 * @param data_size the length of the serialized data
 *
 * @return a GNUNET_IDENTITY_PROVIDER_Attribute, must be free'd by caller
 */
struct GNUNET_RECLAIM_ATTRIBUTE_Claim *
GNUNET_RECLAIM_ATTRIBUTE_deserialize (const char *data, size_t data_size)
{
  struct GNUNET_RECLAIM_ATTRIBUTE_Claim *attr;
  struct Attribute *attr_ser;
  size_t data_len;
  size_t name_len;
  char *write_ptr;

  if (data_size < sizeof (struct Attribute))
    return NULL;

  attr_ser = (struct Attribute *) data;
  data_len = ntohs (attr_ser->data_size);
  name_len = ntohs (attr_ser->name_len);
  attr = GNUNET_malloc (sizeof (struct GNUNET_RECLAIM_ATTRIBUTE_Claim) +
                        data_len + name_len + 1);
  attr->type = ntohs (attr_ser->attribute_type);
  attr->version = ntohl (attr_ser->attribute_version);
  attr->id = GNUNET_ntohll (attr_ser->attribute_id);
  attr->data_size = ntohs (attr_ser->data_size);

  write_ptr = (char *) &attr[1];
  GNUNET_memcpy (write_ptr, &attr_ser[1], name_len);
  write_ptr[name_len] = '\0';
  attr->name = write_ptr;

  write_ptr += name_len + 1;
  GNUNET_memcpy (write_ptr, (char *) &attr_ser[1] + name_len, attr->data_size);
  attr->data = write_ptr;
  return attr;
}

/* end of reclaim_attribute.c */

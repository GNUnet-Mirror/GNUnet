/*
      This file is part of GNUnet
      Copyright (C) 2010-2015 GNUnet e.V.

      GNUnet is free software: you can redistribute it and/or modify it
      under the terms of the GNU General Public License as published
      by the Free Software Foundation, either version 3 of the License,
      or (at your option) any later version.

      GNUnet is distributed in the hope that it will be useful, but
      WITHOUT ANY WARRANTY; without even the implied warranty of
      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
      Affero General Public License for more details.
 */

/**
 * @file identity-attribute/identity_attribute.c
 * @brief helper library to manage identity attributes
 * @author Martin Schanzenbach
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "identity_attribute.h"
#include "gnunet_identity_attribute_plugin.h"

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
  struct GNUNET_IDENTITY_ATTRIBUTE_PluginFunctions *api;
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
 */
static void
add_plugin (void* cls,
            const char *library_name,
            void *lib_ret)
{
  struct GNUNET_IDENTITY_ATTRIBUTE_PluginFunctions *api = lib_ret;
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
init()
{
  if (GNUNET_YES == initialized)
    return;
  initialized = GNUNET_YES;
  GNUNET_PLUGIN_load_all ("libgnunet_plugin_identity_attribute_", NULL,
                          &add_plugin, NULL);
}

/**
 * Convert a type name to the corresponding number
 *
 * @param typename name to convert
 * @return corresponding number, UINT32_MAX on error
 */
uint32_t
GNUNET_IDENTITY_ATTRIBUTE_typename_to_number (const char *typename)
{
  unsigned int i;
  struct Plugin *plugin;
  uint32_t ret;
  
  init ();
  for (i = 0; i < num_plugins; i++)
  {
    plugin = attr_plugins[i];
    if (UINT32_MAX != (ret = plugin->api->typename_to_number (plugin->api->cls,
                                                              typename)))
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
const char*
GNUNET_IDENTITY_ATTRIBUTE_number_to_typename (uint32_t type)
{
  unsigned int i;
  struct Plugin *plugin;
  const char *ret;

  init ();
  for (i = 0; i < num_plugins; i++)
  {
    plugin = attr_plugins[i];
    if (NULL != (ret = plugin->api->number_to_typename (plugin->api->cls,
                                                        type)))
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
GNUNET_IDENTITY_ATTRIBUTE_string_to_value (uint32_t type,
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
GNUNET_IDENTITY_ATTRIBUTE_value_to_string (uint32_t type,
                                           const void* data,
                                           size_t data_size)
{
  unsigned int i;
  struct Plugin *plugin;
  char *ret;

  init();
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
struct GNUNET_IDENTITY_ATTRIBUTE_Claim *
GNUNET_IDENTITY_ATTRIBUTE_claim_new (const char* attr_name,
               uint32_t type,
               const void* data,
               size_t data_size)
{
  struct GNUNET_IDENTITY_ATTRIBUTE_Claim *attr;
  char *write_ptr;

  attr = GNUNET_malloc (sizeof (struct GNUNET_IDENTITY_ATTRIBUTE_Claim) +
                        strlen (attr_name) + 1 +
                        data_size);
  attr->type = type;
  attr->data_size = data_size;
  attr->version = 0;
  write_ptr = (char*)&attr[1];
  GNUNET_memcpy (write_ptr,
                 attr_name,
                 strlen (attr_name) + 1);
  attr->name = write_ptr;
  write_ptr += strlen (attr->name) + 1;
  GNUNET_memcpy (write_ptr,
                 data,
                 data_size);
  attr->data = write_ptr;
  return attr;
}

/**
 * Add a new claim list entry.
 *
 * @param claim_list the attribute name
 * @param attr_name the attribute name
 * @param type the attribute type
 * @param data the attribute value
 * @param data_size the attribute value size
 * @return
 */
void
GNUNET_IDENTITY_ATTRIBUTE_list_add (struct GNUNET_IDENTITY_ATTRIBUTE_ClaimList *claim_list,
				    const char* attr_name,
				    uint32_t type,
				    const void* data,
				    size_t data_size)
{
  struct GNUNET_IDENTITY_ATTRIBUTE_ClaimListEntry *le;
  le = GNUNET_new (struct GNUNET_IDENTITY_ATTRIBUTE_ClaimListEntry);
  le->claim = GNUNET_IDENTITY_ATTRIBUTE_claim_new (attr_name,
					       type,
					       data,
					       data_size);
  GNUNET_CONTAINER_DLL_insert (claim_list->list_head,
			       claim_list->list_tail,
			       le);
}

size_t
GNUNET_IDENTITY_ATTRIBUTE_list_serialize_get_size (const struct GNUNET_IDENTITY_ATTRIBUTE_ClaimList *attrs)
{
  struct GNUNET_IDENTITY_ATTRIBUTE_ClaimListEntry *le;
  size_t len = 0;
  for (le = attrs->list_head; NULL != le; le = le->next)
    len += GNUNET_IDENTITY_ATTRIBUTE_serialize_get_size (le->claim);
  return len; 
}

size_t
GNUNET_IDENTITY_ATTRIBUTE_list_serialize (const struct GNUNET_IDENTITY_ATTRIBUTE_ClaimList *attrs,
                          char *result)
{
  struct GNUNET_IDENTITY_ATTRIBUTE_ClaimListEntry *le;
  size_t len;
  size_t total_len;
  char* write_ptr;

  write_ptr = result;
  total_len = 0;
  for (le = attrs->list_head; NULL != le; le = le->next)
  {
    len = GNUNET_IDENTITY_ATTRIBUTE_serialize (le->claim,
                               write_ptr);
    total_len += len;
    write_ptr += len;
  }
  return total_len;
}

struct GNUNET_IDENTITY_ATTRIBUTE_ClaimList *
GNUNET_IDENTITY_ATTRIBUTE_list_deserialize (const char* data,
                       size_t data_size)
{
  struct GNUNET_IDENTITY_ATTRIBUTE_ClaimList *attrs;
  struct GNUNET_IDENTITY_ATTRIBUTE_ClaimListEntry *le;
  size_t attr_len;
  const char* read_ptr;

  if (data_size < sizeof (struct Attribute))
    return NULL;
  
  attrs = GNUNET_new (struct GNUNET_IDENTITY_ATTRIBUTE_ClaimList);
  read_ptr = data;
  while (((data + data_size) - read_ptr) >= sizeof (struct Attribute))
  {

    le = GNUNET_new (struct GNUNET_IDENTITY_ATTRIBUTE_ClaimListEntry);
    le->claim = GNUNET_IDENTITY_ATTRIBUTE_deserialize (read_ptr,
                                           data_size - (read_ptr - data));
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Deserialized attribute %s\n", le->claim->name);
    GNUNET_CONTAINER_DLL_insert (attrs->list_head,
                                 attrs->list_tail,
                                 le);
    attr_len = GNUNET_IDENTITY_ATTRIBUTE_serialize_get_size (le->claim);
    read_ptr += attr_len;
  }
  return attrs;
}

struct GNUNET_IDENTITY_ATTRIBUTE_ClaimList*
GNUNET_IDENTITY_ATTRIBUTE_list_dup (const struct GNUNET_IDENTITY_ATTRIBUTE_ClaimList *attrs)
{
  struct GNUNET_IDENTITY_ATTRIBUTE_ClaimListEntry *le;
  struct GNUNET_IDENTITY_ATTRIBUTE_ClaimListEntry *result_le;
  struct GNUNET_IDENTITY_ATTRIBUTE_ClaimList *result;

  result = GNUNET_new (struct GNUNET_IDENTITY_ATTRIBUTE_ClaimList);
  for (le = attrs->list_head; NULL != le; le = le->next)
  {
    result_le = GNUNET_new (struct GNUNET_IDENTITY_ATTRIBUTE_ClaimListEntry);
    result_le->claim = GNUNET_IDENTITY_ATTRIBUTE_claim_new (le->claim->name,
                                                     le->claim->type,
                                                     le->claim->data,
                                                     le->claim->data_size);
    GNUNET_CONTAINER_DLL_insert (result->list_head,
                                 result->list_tail,
                                 result_le);
  }
  return result;
}


void
GNUNET_IDENTITY_ATTRIBUTE_list_destroy (struct GNUNET_IDENTITY_ATTRIBUTE_ClaimList *attrs)
{
  struct GNUNET_IDENTITY_ATTRIBUTE_ClaimListEntry *le;
  struct GNUNET_IDENTITY_ATTRIBUTE_ClaimListEntry *tmp_le;

  for (le = attrs->list_head; NULL != le;)
  {
    GNUNET_free (le->claim);
    tmp_le = le;
    le = le->next;
    GNUNET_free (tmp_le);
  }
  GNUNET_free (attrs);

}

size_t
GNUNET_IDENTITY_ATTRIBUTE_serialize_get_size (const struct GNUNET_IDENTITY_ATTRIBUTE_Claim *attr)
{
  return sizeof (struct Attribute) 
    + strlen (attr->name)
    + attr->data_size;
}

size_t
GNUNET_IDENTITY_ATTRIBUTE_serialize (const struct GNUNET_IDENTITY_ATTRIBUTE_Claim *attr,
                     char *result)
{
  size_t data_len_ser;
  size_t name_len;
  struct Attribute *attr_ser;
  char* write_ptr;

  attr_ser = (struct Attribute*)result;
  attr_ser->attribute_type = htons (attr->type);
  attr_ser->attribute_version = htonl (attr->version);
  name_len = strlen (attr->name);
  attr_ser->name_len = htons (name_len);
  write_ptr = (char*)&attr_ser[1];
  GNUNET_memcpy (write_ptr, attr->name, name_len);
  write_ptr += name_len;
  //TODO plugin-ize
  //data_len_ser = plugin->serialize_attribute_value (attr,
  //                                                  &attr_ser[1]);
  data_len_ser = attr->data_size;
  GNUNET_memcpy (write_ptr, attr->data, attr->data_size);
  attr_ser->data_size = htons (data_len_ser);

  return sizeof (struct Attribute) + strlen (attr->name) + attr->data_size;
}

struct GNUNET_IDENTITY_ATTRIBUTE_Claim *
GNUNET_IDENTITY_ATTRIBUTE_deserialize (const char* data,
                       size_t data_size)
{
  struct GNUNET_IDENTITY_ATTRIBUTE_Claim *attr;
  struct Attribute *attr_ser;
  size_t data_len;
  size_t name_len;
  char* write_ptr;

  if (data_size < sizeof (struct Attribute))
    return NULL;

  attr_ser = (struct Attribute*)data;
  data_len = ntohs (attr_ser->data_size);
  name_len = ntohs (attr_ser->name_len);
  attr = GNUNET_malloc (sizeof (struct GNUNET_IDENTITY_ATTRIBUTE_Claim)
                        + data_len + name_len + 1);
  attr->type = ntohs (attr_ser->attribute_type);
  attr->version = ntohl (attr_ser->attribute_version);
  attr->data_size = ntohs (attr_ser->data_size);

  write_ptr =  (char*)&attr[1];
  GNUNET_memcpy (write_ptr,
                 &attr_ser[1],
                 name_len);
  write_ptr[name_len] = '\0';
  attr->name = write_ptr;

  write_ptr += name_len + 1;
  GNUNET_memcpy (write_ptr,
                 (char*)&attr_ser[1] + name_len,
                 attr->data_size);
  attr->data = write_ptr;
  return attr;

}

/* end of identity_attribute.c */

/*
      This file is part of GNUnet
      Copyright (C) 2010-2015 GNUnet e.V.

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
 * @file identity-provider/identity_attribute.c
 * @brief helper library to manage identity attributes
 * @author Martin Schanzenbach
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "identity_attribute.h"

/**
 * Create a new attribute.
 *
 * @param name the attribute name
 * @param type the attribute type
 * @param data the attribute value
 * @param data_size the attribute value size
 * @return the new attribute
 */
struct GNUNET_IDENTITY_PROVIDER_Attribute *
attribute_new (const char* attr_name,
               uint32_t attr_type,
               const void* data,
               size_t data_size)
{
  struct GNUNET_IDENTITY_PROVIDER_Attribute *attr;
  char *write_ptr;

  attr = GNUNET_malloc (sizeof (struct GNUNET_IDENTITY_PROVIDER_Attribute) +
                        strlen (attr_name) + 1 +
                        data_size);
  attr->attribute_type = attr_type;
  attr->data_size = data_size;
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

size_t
attribute_list_serialize_get_size (const struct GNUNET_IDENTITY_PROVIDER_AttributeList *attrs)
{
  struct GNUNET_IDENTITY_PROVIDER_AttributeListEntry *le;
  size_t len = 0;
  for (le = attrs->list_head; NULL != le; le = le->next)
    len += attribute_serialize_get_size (le->attribute);
  return len; 
}

size_t
attribute_list_serialize (const struct GNUNET_IDENTITY_PROVIDER_AttributeList *attrs,
                          char *result)
{
  struct GNUNET_IDENTITY_PROVIDER_AttributeListEntry *le;
  size_t len;
  size_t total_len;
  char* write_ptr;

  write_ptr = result;
  total_len = 0;
  for (le = attrs->list_head; NULL != le; le = le->next)
  {
    len = attribute_serialize (le->attribute,
                               write_ptr);
    total_len += len;
    write_ptr += len;
  }
  return total_len;
}

struct GNUNET_IDENTITY_PROVIDER_AttributeList *
attribute_list_deserialize (const char* data,
                       size_t data_size)
{
  struct GNUNET_IDENTITY_PROVIDER_AttributeList *attrs;
  struct GNUNET_IDENTITY_PROVIDER_AttributeListEntry *le;
  size_t attr_len;
  const char* read_ptr;

  if (data_size < sizeof (struct Attribute))
    return NULL;
  
  attrs = GNUNET_new (struct GNUNET_IDENTITY_PROVIDER_AttributeList);
  read_ptr = data;
  while (((data + data_size) - read_ptr) >= sizeof (struct Attribute))
  {

    le = GNUNET_new (struct GNUNET_IDENTITY_PROVIDER_AttributeListEntry);
    le->attribute = attribute_deserialize (read_ptr,
                                           data_size - (read_ptr - data));
    GNUNET_log (GNUNET_ERROR_TYPE_MESSAGE,
                "Deserialized attribute %s\n", le->attribute->name);
    GNUNET_CONTAINER_DLL_insert (attrs->list_head,
                                 attrs->list_tail,
                                 le);
    attr_len = attribute_serialize_get_size (le->attribute);
    read_ptr += attr_len;
  }
  return attrs;
}



size_t
attribute_serialize_get_size (const struct GNUNET_IDENTITY_PROVIDER_Attribute *attr)
{
  return sizeof (struct Attribute) 
    + strlen (attr->name)
    + attr->data_size; //TODO get data_size from plugin
}

size_t
attribute_serialize (const struct GNUNET_IDENTITY_PROVIDER_Attribute *attr,
                     char *result)
{
  size_t data_len_ser;
  size_t name_len;
  struct Attribute *attr_ser;
  char* write_ptr;

  attr_ser = (struct Attribute*)result;
  attr_ser->attribute_type = htons (attr->attribute_type);
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

struct GNUNET_IDENTITY_PROVIDER_Attribute *
attribute_deserialize (const char* data,
                       size_t data_size)
{
  struct GNUNET_IDENTITY_PROVIDER_Attribute *attr;
  struct Attribute *attr_ser;
  size_t data_len;
  size_t name_len;
  char* write_ptr;

  if (data_size < sizeof (struct Attribute))
    return NULL;

  attr_ser = (struct Attribute*)data;
  //TODO use plugin. 
  data_len = ntohs (attr_ser->data_size);
  name_len = ntohs (attr_ser->name_len);
  attr = GNUNET_malloc (sizeof (struct GNUNET_IDENTITY_PROVIDER_Attribute)
                        + data_len + name_len + 1);
  attr->attribute_type = ntohs (attr_ser->attribute_type);
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

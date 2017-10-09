/*
   This file is part of GNUnet.
   Copyright (C) 2012-2015 GNUnet e.V.

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
 * @author Martin Schanzenbach
 * @file identity-provider/identity_attribute.h
 * @brief GNUnet Identity Provider library
 *
 */
#ifndef IDENTITY_ATTRIBUTE_H
#define IDENTITY_ATTRIBUTE_H

#include "gnunet_identity_provider_service.h"

struct Attribute
{
  /**
   * Attribute type
   */
  uint32_t attribute_type;

  /**
   * Name length
   */
  uint32_t name_len;
  
  /**
   * Data size
   */
  uint32_t data_size;

  //followed by data_size Attribute value data
};

/**
 * Get required size for serialization buffer
 *
 * @param attrs the attribute list to serialize
 *
 * @return the required buffer size
 */
size_t
attribute_list_serialize_get_size (const struct GNUNET_IDENTITY_PROVIDER_AttributeList *attrs);

void
attribute_list_destroy (struct GNUNET_IDENTITY_PROVIDER_AttributeList *attrs);


/**
 * Serialize an attribute list
 *
 * @param attrs the attribute list to serialize
 * @param result the serialized attribute
 *
 * @return length of serialized data
 */
size_t
attribute_list_serialize (const struct GNUNET_IDENTITY_PROVIDER_AttributeList *attrs,
                     char *result);

/**
 * Deserialize an attribute list
 *
 * @param data the serialized attribute list
 * @param data_size the length of the serialized data
 *
 * @return a GNUNET_IDENTITY_PROVIDER_AttributeList, must be free'd by caller
 */
struct GNUNET_IDENTITY_PROVIDER_AttributeList *
attribute_list_deserialize (const char* data,
                            size_t data_size);


/**
 * Get required size for serialization buffer
 *
 * @param attr the attribute to serialize
 *
 * @return the required buffer size
 */
size_t
attribute_serialize_get_size (const struct GNUNET_IDENTITY_PROVIDER_Attribute *attr);



/**
 * Serialize an attribute
 *
 * @param attr the attribute to serialize
 * @param result the serialized attribute
 *
 * @return length of serialized data
 */
size_t
attribute_serialize (const struct GNUNET_IDENTITY_PROVIDER_Attribute *attr,
                     char *result);

/**
 * Deserialize an attribute
 *
 * @param data the serialized attribute
 * @param data_size the length of the serialized data
 *
 * @return a GNUNET_IDENTITY_PROVIDER_Attribute, must be free'd by caller
 */
struct GNUNET_IDENTITY_PROVIDER_Attribute *
attribute_deserialize (const char* data,
                       size_t data_size);

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
               size_t data_size);

struct GNUNET_IDENTITY_PROVIDER_AttributeList*
attribute_list_dup (const struct GNUNET_IDENTITY_PROVIDER_AttributeList *attrs);

#endif

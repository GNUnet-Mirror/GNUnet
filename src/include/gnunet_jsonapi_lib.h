/*
  This file is part of GNUnet
  Copyright (C) 2014, 2015, 2016 GNUnet e.V.

  GNUnet is free software; you can redistribute it and/or modify it under the
  terms of the GNU General Public License as published by the Free Software
  Foundation; either version 3, or (at your option) any later version.

  GNUnet is distributed in the hope that it will be useful, but WITHOUT ANY
  WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
  A PARTICULAR PURPOSE.  See the GNU General Public License for more details.

  You should have received a copy of the GNU General Public License along with
  GNUnet; see the file COPYING.  If not, If not, see <http://www.gnu.org/licenses/>
*/
/**
 * @file gnunet_jsonapi_lib.h
 * @brief functions to parse jsonapi objects
 * @author Martin Schanzenbach
 */
#ifndef GNUNET_JSONAPI_LIB_H
#define GNUNET_JSONAPI_LIB_H

#include "gnunet_util_lib.h"
#include "gnunet_json_lib.h"


/* ****************** JSONAPI parsing ******************* */

struct GNUNET_JSONAPI_Resource;

struct GNUNET_JSONAPI_Object;

/**
 * Specification for parsing a jsonapi object.
 *
 * @param jsonapi_obj where to store the jsonapi object
 */
struct GNUNET_JSON_Specification
GNUNET_JSON_spec_jsonapi (struct GNUNET_JSONAPI_Object **jsonapi_obj);

/**
 * Create a JSON API resource
 *
 * @param type the JSON API resource type
 * @param id the JSON API resource id
 * @return a new JSON API resource or NULL on error.
 */
struct GNUNET_JSONAPI_Resource*
GNUNET_JSONAPI_resource_new (const char *type, const char *id);

/**
 * Delete a JSON API resource
 *
 * @param res the JSON resource
 * @param result Pointer where the resource should be stored
 */
void
GNUNET_JSONAPI_resource_delete (struct GNUNET_JSONAPI_Resource *resource);

/**
 * Add a JSON API attribute
 *
 * @param res the JSON resource
 * @param key the key for the attribute
 * @param json the json_t attribute to add
 * @return #GNUNET_OK if added successfully
 *         #GNUNET_SYSERR if not
 */
int
GNUNET_JSONAPI_resource_add_attr (const struct GNUNET_JSONAPI_Resource *resource,
                                       const char* key,
                                       json_t *json);
/**
 * Read a JSON API attribute
 *
 * @param res the JSON resource
 * @param key the key for the attribute
 * @return the json attr
 */
json_t*
GNUNET_JSONAPI_resource_read_attr (const struct GNUNET_JSONAPI_Resource *resource,
                                       const char* key);


/**
 * Check a JSON API resource id
 *
 * @param res the JSON resource
 * @param id the expected id
 * @return GNUNET_YES if id matches
 */
int
GNUNET_JSONAPI_resource_check_id (const struct GNUNET_JSONAPI_Resource *resource,
                                       const char* id);


/**
 * Check a JSON API resource type
 *
 * @param res the JSON resource
 * @param type the expected type
 * @return GNUNET_YES if id matches
 */
int
GNUNET_JSONAPI_resource_check_type (const struct GNUNET_JSONAPI_Resource *resource,
                                         const char* type);


/**
 * Create a JSON API primary data
 *
 * @param type the JSON API resource type
 * @param id the JSON API resource id
 * @return a new JSON API resource or NULL on error.
 */
struct GNUNET_JSONAPI_Object*
GNUNET_JSONAPI_object_new ();


/**
 * Create a JSON API primary data from a string
 *
 * @param data the string of the JSON API data
 * @param Pointer where to store new jsonapi Object.
 * @return GNUNET_OK on success
 */
int
GNUNET_JSONAPI_object_parse (const char* data,
                             struct GNUNET_JSONAPI_Object** obj);


/**
 * Delete a JSON API primary data
 *
 * @param type the JSON API resource type
 * @param id the JSON API resource id
 * @return a new JSON API resource or NULL on error.
 */
void
GNUNET_JSONAPI_object_delete (struct GNUNET_JSONAPI_Object *resp);

/**
 * Add a JSON API resource to primary data
 *
 * @param data The JSON API data to add to
 * @param res the JSON API resource to add
 * @return the new number of resources
 */
void
GNUNET_JSONAPI_object_resource_add (struct GNUNET_JSONAPI_Object *resp,
                                           struct GNUNET_JSONAPI_Resource *res);
/**
 * Get a JSON API object resource count
 *
 * @param resp the JSON API object
 * @return the number of resources
 */
int
GNUNET_JSONAPI_object_resource_count (struct GNUNET_JSONAPI_Object *resp);

/**
 * Get a JSON API object resource num
 *
 * @param resp the JSON API object
 * @param num the number of the resource
 * @return the resource
 */
struct GNUNET_JSONAPI_Resource*
GNUNET_JSONAPI_object_get_resource (struct GNUNET_JSONAPI_Object *resp, int num);


/**
 * Add a JSON API resource to primary data
 *
 * @param resp The JSON API data to add to
 * @param res the JSON API resource to add
 * @return the new number of resources
 */
void
GNUNET_JSONAPI_data_resource_remove (struct GNUNET_JSONAPI_Object *resp,
                                          struct GNUNET_JSONAPI_Resource *res);

/**
 * String serialze jsonapi primary data
 *
 * @param data the JSON API primary data
 * @param result where to store the result
 * @return GNUNET_SYSERR on error else GNUNET_OK
 */
int
GNUNET_JSONAPI_data_serialize (const struct GNUNET_JSONAPI_Object *resp,
                                    char **result);

/**
 * Check a JSON API resource id
 *
 * @param res the JSON resource
 * @return the resource id
 */
json_t*
GNUNET_JSONAPI_resource_get_id (const struct GNUNET_JSONAPI_Resource *resource);
/* end of gnunet_jsonapi_lib.h */
#endif

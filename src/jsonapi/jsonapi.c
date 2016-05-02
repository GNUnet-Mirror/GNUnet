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
 * @file json/jsonapi.c
 * @brief functions to generate specifciations for JSONAPI parsing
 * @author Martin Schanzenbach
 */
#include "platform.h"
#include "gnunet_json_lib.h"

#define GNUNET_JSONAPI_KEY_DATA "data"

#define GNUNET_JSONAPI_KEY_ID "id"

#define GNUNET_JSONAPI_KEY_TYPE "type"

struct GNUNET_JSONAPI_Resource
{
  /**
   * DLL
   */
  struct GNUNET_JSONAPI_Resource *next;

  /**
   * DLL
   */
  struct GNUNET_JSONAPI_Resource *prev;

  /**
   * Resource content
   */
  json_t *res_obj;
};


struct GNUNET_JSONAPI_Object
{
  /**
   * DLL Resource
   */
  struct GNUNET_JSONAPI_Resource *res_list_head;

  /**
   * DLL Resource
   */
  struct GNUNET_JSONAPI_Resource *res_list_tail;

  /**
   * num resources
   */
  int res_count;
};


/**
 * JSON API
 */


/**
 * Create a JSON API resource
 *
 * @param type the JSON API resource type
 * @param id the JSON API resource id
 * @return a new JSON API resource or NULL on error.
 */
struct GNUNET_JSONAPI_Resource*
GNUNET_JSONAPI_resource_new (const char *type, const char *id)
{
  struct GNUNET_JSONAPI_Resource *res;

  if ( (NULL == type) || (0 == strlen (type)) )
    return NULL;
  if ( (NULL == id) || (0 == strlen (id)) )
    return NULL;

  res = GNUNET_new (struct GNUNET_JSONAPI_Resource);
  res->prev = NULL;
  res->next = NULL;

  res->res_obj = json_object ();

  json_object_set_new (res->res_obj, GNUNET_JSONAPI_KEY_ID, json_string (id));
  json_object_set_new (res->res_obj, GNUNET_JSONAPI_KEY_TYPE, json_string (type));

  return res;
}



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
                                       json_t *json)
{
  if ( (NULL == resource) ||
       (NULL == key) ||
       (NULL == json) )
    return GNUNET_SYSERR;
  json_object_set (resource->res_obj, key, json);
  return GNUNET_OK;
}

/**
 * Read a JSON API attribute
 *
 * @param res the JSON resource
 * @param key the key for the attribute
 * @return the json_t object
 */
json_t*
GNUNET_JSONAPI_resource_read_attr (const struct GNUNET_JSONAPI_Resource *resource,
                                       const char* key)
{
  if ( (NULL == resource) ||
       (NULL == key))
    return NULL;
  return json_object_get (resource->res_obj, key);
}

int
check_resource_attr_str (const struct GNUNET_JSONAPI_Resource *resource,
                         const char* key,
                         const char* attr)
{
  json_t *value;
  if ( (NULL == resource) ||
       (NULL == key) ||
       (NULL == attr))
    return GNUNET_NO;
  value = json_object_get (resource->res_obj, key);
  if (NULL == value)
    return GNUNET_NO;
  if (!json_is_string (value) ||
      (0 != strcmp (attr, json_string_value(value))))
  {
    return GNUNET_NO;
  }
  return GNUNET_YES;
}

/**
 * Check a JSON API resource id
 *
 * @param res the JSON resource
 * @param id the expected id
 * @return GNUNET_YES if id matches
 */
int
GNUNET_JSONAPI_resource_check_id (const struct GNUNET_JSONAPI_Resource *resource,
                                       const char* id)
{
  return check_resource_attr_str (resource, GNUNET_JSONAPI_KEY_ID, id);
}

/**
 * Check a JSON API resource id
 *
 * @param res the JSON resource
 * @return the resource id
 */
json_t*
GNUNET_JSONAPI_resource_get_id (const struct GNUNET_JSONAPI_Resource *resource)
{
  return GNUNET_JSONAPI_resource_read_attr (resource, GNUNET_JSONAPI_KEY_ID);
}

/**
 * Check a JSON API resource type
 *
 * @param res the JSON resource
 * @param type the expected type
 * @return GNUNET_YES if id matches
 */
int
GNUNET_JSONAPI_resource_check_type (const struct GNUNET_JSONAPI_Resource *resource,
                                         const char* type)
{
  return check_resource_attr_str (resource, GNUNET_JSONAPI_KEY_TYPE, type);
}

/**
 * Get a JSON API object resource count
 *
 * @param resp the JSON API object
 * @return the number of resources
 */
int
GNUNET_JSONAPI_object_resource_count (struct GNUNET_JSONAPI_Object *resp)
{
  return resp->res_count;
}

/**
 * Get a JSON API object resource by index
 *
 * @param resp the JSON API object
 * @param num the number of the resource
 * @return the resource
 */
struct GNUNET_JSONAPI_Resource*
GNUNET_JSONAPI_object_get_resource (struct GNUNET_JSONAPI_Object *resp,
					 int num)
{
  struct GNUNET_JSONAPI_Resource *res;
  int i;

  if ((0 == resp->res_count) ||
      (num >= resp->res_count))
    return NULL;
  res = resp->res_list_head;
  for (i = 0; i < num; i++)
  {
    res = res->next;
  }
  return res;
}

/**
 * Delete a JSON API resource
 *
 * @param res the JSON resource
 * @param result Pointer where the resource should be stored
 */
void
GNUNET_JSONAPI_resource_delete (struct GNUNET_JSONAPI_Resource *resource)
{
  json_decref (resource->res_obj);
  GNUNET_free (resource);
  resource = NULL;
}

/**
 * Delete a JSON API primary data
 *
 * @param type the JSON API resource type
 * @param id the JSON API resource id
 * @return a new JSON API resource or NULL on error.
 */
void
GNUNET_JSONAPI_object_delete (struct GNUNET_JSONAPI_Object *resp)
{
  struct GNUNET_JSONAPI_Resource *res;
  struct GNUNET_JSONAPI_Resource *res_next;

  for (res = resp->res_list_head;
       res != NULL;)
  {
    res_next = res->next;
    GNUNET_CONTAINER_DLL_remove (resp->res_list_head,
                                 resp->res_list_tail,
                                 res);
    GNUNET_JSONAPI_resource_delete (res);
    res = res_next;
  }
  GNUNET_free (resp);
  resp = NULL;
}

/**
 * Create a JSON API primary data
 *
 * @return a new JSON API resource or NULL on error.
 */
struct GNUNET_JSONAPI_Object*
GNUNET_JSONAPI_object_new ()
{
  struct GNUNET_JSONAPI_Object *result;

  result = GNUNET_new (struct GNUNET_JSONAPI_Object);
  result->res_count = 0;
  return result;
}

/**
 * Add a JSON API object to primary data
 *
 * @param data The JSON API data to add to
 * @param res the JSON API resource to add
 * @return the new number of resources
 */
void
GNUNET_JSONAPI_object_resource_add (struct GNUNET_JSONAPI_Object *resp,
                                         struct GNUNET_JSONAPI_Resource *res)
{
  GNUNET_CONTAINER_DLL_insert (resp->res_list_head,
                               resp->res_list_tail,
                               res);

  resp->res_count++;
}

static void
add_json_resource (struct GNUNET_JSONAPI_Object *obj,
                   const json_t *res_json)
{
  struct GNUNET_JSONAPI_Resource *res;
  const char *type_json;

  struct GNUNET_JSON_Specification dspec[] = {
    GNUNET_JSON_spec_string (GNUNET_JSONAPI_KEY_TYPE, &type_json),
    GNUNET_JSON_spec_end()
  };

  GNUNET_assert (GNUNET_OK ==
                 GNUNET_JSON_parse (res_json, dspec,
                                    NULL, NULL));
  GNUNET_JSON_parse_free (dspec);
  res = GNUNET_new (struct GNUNET_JSONAPI_Resource);
  res->next = NULL;
  res->prev = NULL;
  res->res_obj = json_deep_copy (res_json);
  GNUNET_JSONAPI_object_resource_add (obj, res);
}

/**
 * Parse given JSON object to RSA public key.
 *
 * @param cls closure, NULL
 * @param root the json object representing data
 * @param[out] spec where to write the data
 * @return #GNUNET_OK upon successful parsing; #GNUNET_SYSERR upon error
 */
static int
parse_jsonapiobject (void *cls,
                     json_t *root,
                     struct GNUNET_JSON_Specification *spec)
{
  struct GNUNET_JSONAPI_Object *result;
  json_t *data_json;
  int res_count = 0;
  int i;

  struct GNUNET_JSON_Specification jsonapispec[] = {
    GNUNET_JSON_spec_json (GNUNET_JSONAPI_KEY_DATA, &data_json),
    GNUNET_JSON_spec_end()
  };
  if (GNUNET_OK !=
                 GNUNET_JSON_parse (root, jsonapispec,
                                    NULL, NULL) || (NULL == data_json))
  {
    return GNUNET_SYSERR;
  }

  result = GNUNET_new (struct GNUNET_JSONAPI_Object);
  result->res_count = 0;
  if (json_is_object (data_json))
    add_json_resource (result, data_json);
  else if (json_is_array (data_json))
  {
    res_count = json_array_size (data_json);
    for (i = 0; i < res_count; i++)
      add_json_resource (result, json_array_get (data_json, i));
  }
  if (0 == result->res_count)
  {
    GNUNET_free (result);
    GNUNET_JSON_parse_free (jsonapispec);
    return GNUNET_SYSERR;
  }
  *(struct GNUNET_JSONAPI_Object **) spec->ptr = result;
  GNUNET_JSON_parse_free (jsonapispec);
  return GNUNET_OK;
}


/**
 * Cleanup data left from parsing RSA public key.
 *
 * @param cls closure, NULL
 * @param[out] spec where to free the data
 */
static void
clean_jsonapiobject (void *cls,
                     struct GNUNET_JSON_Specification *spec)
{
  struct GNUNET_JSONAPI_Object **jsonapi_obj;
  jsonapi_obj = (struct GNUNET_JSONAPI_Object **) spec->ptr;
  if (NULL != *jsonapi_obj)
  {
    GNUNET_JSONAPI_object_delete (*jsonapi_obj);
    *jsonapi_obj = NULL;
  }
}

/**
 * Add a JSON API resource to primary data
 *
 * @param data The JSON API data to add to
 * @param res the JSON API resource to add
 * @return the new number of resources
 */
void
GNUNET_JSONAPI_data_resource_remove (struct GNUNET_JSONAPI_Object *resp,
                                          struct GNUNET_JSONAPI_Resource *res)
{
  GNUNET_CONTAINER_DLL_remove (resp->res_list_head,
                               resp->res_list_tail,
                              res);
  resp->res_count--;
}

/**
 * String serialze jsonapi primary data
 *
 * @param data the JSON API primary data
 * @param result where to store the result
 * @return GNUNET_SYSERR on error else GNUNET_OK
 */
int
GNUNET_JSONAPI_data_serialize (const struct GNUNET_JSONAPI_Object *resp,
                                    char **result)
{
  struct GNUNET_JSONAPI_Resource *res;
  json_t *root_json;
  json_t *res_arr;

  if ((NULL == resp))
    return GNUNET_SYSERR;

  root_json = json_object ();
  res_arr = json_array ();
  for (res = resp->res_list_head;
       res != NULL;
       res = res->next)
  {
    json_array_append (res_arr, res->res_obj);
  }
  json_object_set (root_json, GNUNET_JSONAPI_KEY_DATA, res_arr);
  *result = json_dumps (root_json, JSON_INDENT(2));
  json_decref (root_json);
  json_decref (res_arr);
  return GNUNET_OK;
}

/**
 * JSON object.
 *
 * @param name name of the JSON field
 * @param[out] jsonp where to store the JSON found under @a name
 */
struct GNUNET_JSON_Specification
GNUNET_JSON_spec_jsonapi (struct GNUNET_JSONAPI_Object **jsonapi_object)
{
  struct GNUNET_JSON_Specification ret = {
    .parser = &parse_jsonapiobject,
    .cleaner = &clean_jsonapiobject,
    .cls = NULL,
    .field = NULL,
    .ptr = jsonapi_object,
    .ptr_size = 0,
    .size_ptr = NULL
  };
  *jsonapi_object = NULL;
  return ret;
}

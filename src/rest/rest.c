/*
      This file is part of GNUnet
      Copyright (C) 2010-2015 Christian Grothoff (and other contributing authors)

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
      Free Software Foundation, Inc., 59 Temple Place - Suite 330,
      Boston, MA 02111-1307, USA.
 */

/**
 * @file rest/rest.c
 * @brief helper library to create JSON REST Objects and handle REST
 * responses/requests.
 * @author Martin Schanzenbach
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_rest_lib.h"
#include "microhttpd.h"
#include <jansson.h>


struct JsonApiResource
{
  /**
   * DLL
   */
  struct JsonApiResource *next;

  /**
   * DLL
   */
  struct JsonApiResource *prev;

  /**
   * Resource content
   */
  json_t *res_obj;
};


struct JsonApiResponse
{
  /**
   * DLL Resource
   */
  struct JsonApiResource *res_list_head;

  /**
   * DLL Resource
   */
  struct JsonApiResource *res_list_tail;

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
struct JsonApiResource*
GNUNET_REST_jsonapi_resource_new (const char *type, const char *id)
{
  struct JsonApiResource *res;

  if ( (NULL == type) || (0 == strlen (type)) )
    return NULL;
  if ( (NULL == id) || (0 == strlen (id)) )
    return NULL;

  res = GNUNET_new (struct JsonApiResource);
  
  res->res_obj = json_object ();

  json_object_set_new (res->res_obj, GNUNET_REST_JSONAPI_KEY_ID, json_string (id));
  json_object_set_new (res->res_obj, GNUNET_REST_JSONAPI_KEY_TYPE, json_string (type));

  return res;
}

/**
 * Delete a JSON API resource
 *
 * @param res the JSON resource
 * @param result Pointer where the resource should be stored
 */
void
GNUNET_REST_jsonapi_resource_delete (struct JsonApiResource *resource)
{
  json_decref (resource->res_obj);
  GNUNET_free (resource);
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
GNUNET_REST_jsonapi_resource_add_attr (const struct JsonApiResource *resource,
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
 * Create a JSON API primary data
 *
 * @param type the JSON API resource type
 * @param id the JSON API resource id
 * @return a new JSON API resource or NULL on error.
 */
struct JsonApiResponse*
GNUNET_REST_jsonapi_response_new ()
{
  struct JsonApiResponse *result;

  result = GNUNET_new (struct JsonApiResponse);
  result->res_count = 0;
  return result;
}

/**
 * Delete a JSON API primary data
 *
 * @param type the JSON API resource type
 * @param id the JSON API resource id
 * @return a new JSON API resource or NULL on error.
 */
void
GNUNET_REST_jsonapi_response_delete (struct JsonApiResponse *resp)
{
  struct JsonApiResource *res;
  
  for (res = resp->res_list_head; 
       res != NULL;
       res = res->next)
    GNUNET_REST_jsonapi_resource_delete (res);
  GNUNET_free (resp);
}

/**
 * Add a JSON API resource to primary data
 *
 * @param data The JSON API data to add to
 * @param res the JSON API resource to add
 * @return the new number of resources
 */
void
GNUNET_REST_jsonapi_response_resource_add (struct JsonApiResponse *resp,
                                           struct JsonApiResource *res)
{
  GNUNET_CONTAINER_DLL_insert (resp->res_list_head,
                            resp->res_list_tail,
                            res);
  
  resp->res_count++;
}

/**
 * Add a JSON API resource to primary data
 *
 * @param data The JSON API data to add to
 * @param res the JSON API resource to add
 * @return the new number of resources
 */
void
GNUNET_REST_jsonapi_data_resource_remove (struct JsonApiResponse *resp,
                                          struct JsonApiResource *res)
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
GNUNET_REST_jsonapi_data_serialize (const struct JsonApiResponse *resp,
                                    char **result)
{
  struct JsonApiResource *res;
  json_t *root_json;
  json_t *res_arr;
  
  if ( (NULL == resp) ||
       (0 == resp->res_count) )
    return GNUNET_SYSERR;

  root_json = json_object ();
  
  if (1 == resp->res_count)
  {
    json_object_set (root_json, GNUNET_REST_JSONAPI_KEY_DATA, resp->res_list_head->res_obj);
  }
  else
  {
    res_arr = json_array ();
    for (res = resp->res_list_head; 
         res != NULL;
         res = res->next)
    {
      json_array_append (res_arr, res->res_obj);
    }
    json_object_set (root_json, GNUNET_REST_JSONAPI_KEY_DATA, res_arr);
  }
  *result = json_dumps (root_json, JSON_COMPACT);
  return GNUNET_OK;
}

/**
 * REST Utilities
 */

/**
 * Check if namespace is in URL.
 *
 * @param url URL to check
 * @param namespace namespace to check against
 * @retun GNUNET_YES if namespace matches
 */
int
GNUNET_REST_namespace_match (const char *url, const char *namespace)
{
  if (0 != strncmp (namespace, url, strlen (namespace)))
    return GNUNET_NO;

  if ((strlen (namespace) < strlen (url)) &&
      (url[strlen (namespace)] != '/'))
    return GNUNET_NO;

  return GNUNET_YES;
}

/**
 * Create JSON API MHD response
 *
 * @param data JSON result
 * @retun MHD response
 */
 struct MHD_Response*
GNUNET_REST_create_json_response (const char *data)
{
  struct MHD_Response *resp;
  size_t len;

  if (NULL == data)
    len = 0;
  else
    len = strlen (data);
  resp = MHD_create_response_from_buffer (len,
                                          (void*)data,
                                          MHD_RESPMEM_MUST_COPY);
  MHD_add_response_header (resp,MHD_HTTP_HEADER_CONTENT_TYPE,"application/json");
  return resp;

}

int
GNUNET_REST_handle_request (struct RestConnectionDataHandle *conn,
                            const struct GNUNET_REST_RestConnectionHandler *handlers,
                            void *cls)
{
  int count;
  int i;
  char *url;

  count = 0;

  while (NULL != handlers[count].method)
    count++;

  GNUNET_asprintf (&url, "%s", conn->url);
  if (url[strlen (url)-1] == '/')
    url[strlen (url)-1] = '\0';

  for (i = 0; i < count; i++)
  {
    if (0 != strcasecmp (conn->method, handlers[count].method))
      break;
    if (strlen (url) < strlen (handlers[count].namespace))
      break;
    if (GNUNET_NO == GNUNET_REST_namespace_match (url, handlers[count].namespace))
      break;
    //Match
    handlers[count].proc (conn, (const char*)url, cls);
    GNUNET_free (url);
    return GNUNET_YES;
  }
  GNUNET_free (url);
  return GNUNET_NO;
}

/* end of rest.c */

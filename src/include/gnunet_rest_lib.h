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
 * @file include/gnunet_rest_lib.h
 * @brief API for helper library to parse/create REST
 * @author Martin Schanzenbach
 */
#ifndef GNUNET_REST_LIB_H
#define GNUNET_REST_LIB_H

#include "gnunet_util_lib.h"
#include "microhttpd.h"
#include <jansson.h>

#define GNUNET_REST_JSONAPI_KEY_DATA "data"

#define GNUNET_REST_JSONAPI_KEY_ID "id"

#define GNUNET_REST_JSONAPI_KEY_TYPE "type"

#define GNUNET_REST_HANDLER_END {NULL, NULL, NULL}

struct RestConnectionDataHandle
{
  struct GNUNET_CONTAINER_MultiHashMap *url_param_map;
  const char *method;
  const char *url;
  const char *data;
  size_t data_size;

};

struct GNUNET_REST_RestConnectionHandler
{
  /**
   * Http method to handle
   */
  const char *method;

  /**
   * Namespace to handle
   */
  const char *namespace;

  /**
   * callback handler
   */
  void (*proc) (struct RestConnectionDataHandle *handle,
                const char *url,
                void *cls);

};


/**
 * Iterator called on obtained result for a REST result.
 *
 * @param cls closure
 * @param resp the response
 * @param status status code (HTTP)
 */
typedef void (*GNUNET_REST_ResultProcessor) (void *cls,
                                             struct MHD_Response *resp,
                                             int status);


/**
 * Resource structs for JSON API
 */
struct JsonApiResource;

/**
 * Responses for JSON API
 */
struct JsonApiResponse;

/**
 * Create a JSON API resource
 *
 * @param type the JSON API resource type
 * @param id the JSON API resource id
 * @return a new JSON API resource or NULL on error.
 */
struct JsonApiResource*
GNUNET_REST_jsonapi_resource_new (const char *type, const char *id);

/**
 * Delete a JSON API resource
 *
 * @param res the JSON resource
 * @param result Pointer where the resource should be stored
 */
void
GNUNET_REST_jsonapi_resource_delete (struct JsonApiResource *resource);

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
                                       json_t *json);

/**
 * Create a JSON API primary data
 *
 * @param type the JSON API resource type
 * @param id the JSON API resource id
 * @return a new JSON API resource or NULL on error.
 */
struct JsonApiResponse*
GNUNET_REST_jsonapi_response_new ();

/**
 * Delete a JSON API primary data
 *
 * @param type the JSON API resource type
 * @param id the JSON API resource id
 * @return a new JSON API resource or NULL on error.
 */
void
GNUNET_REST_jsonapi_response_delete (struct JsonApiResponse *resp);

/**
 * Add a JSON API resource to primary data
 *
 * @param data The JSON API data to add to
 * @param res the JSON API resource to add
 * @return the new number of resources
 */
void
GNUNET_REST_jsonapi_response_resource_add (struct JsonApiResponse *resp,
                                           struct JsonApiResource *res);

/**
 * Add a JSON API resource to primary data
 *
 * @param resp The JSON API data to add to
 * @param res the JSON API resource to add
 * @return the new number of resources
 */
void
GNUNET_REST_jsonapi_data_resource_remove (struct JsonApiResponse *resp,
                                          struct JsonApiResource *res);

/**
 * String serialze jsonapi primary data
 *
 * @param data the JSON API primary data
 * @param result where to store the result
 * @return GNUNET_SYSERR on error else GNUNET_OK
 */
int
GNUNET_REST_jsonapi_data_serialize (const struct JsonApiResponse *resp,
                                    char **result);

/**
 * Check if namespace is in URL.
 *
 * @param url URL to check
 * @param namespace namespace to check against
 * @retun GNUNET_YES if namespace matches
 */
int
GNUNET_REST_namespace_match (const char *url, const char *namespace);

/**
 * Create JSON API MHD response
 *
 * @param data JSON result
 * @retun MHD response
 */
 struct MHD_Response*
GNUNET_REST_create_json_response (const char *data);


int
GNUNET_REST_handle_request (struct RestConnectionDataHandle *conn,
                            const struct GNUNET_REST_RestConnectionHandler *handlers,
                            void *cls);

#endif

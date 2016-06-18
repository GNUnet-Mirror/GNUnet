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

#define GNUNET_JSONAPI_KEY_DATA "data"

#define GNUNET_JSONAPI_KEY_ID "id"

#define GNUNET_JSONAPI_KEY_TYPE "type"

#define GNUNET_JSONAPI_KEY_META "meta"

#define GNUNET_JSONAPI_KEY_ATTRIBUTES "attributes"

#define GNUNET_JSONAPI_KEY_CODE "code"

#define GNUNET_JSONAPI_KEY_TITLE "title"

#define GNUNET_JSONAPI_KEY_DETAIL "detail"

#define GNUNET_JSONAPI_KEY_SOURCE "source"

#define GNUNET_JSONAPI_KEY_LINKS "links"

#define GNUNET_JSONAPI_KEY_STATUS "status"

#define GNUNET_JSONAPI_KEY_ERRORS "errors"

/* ****************** JSONAPI parsing ******************* */

struct GNUNET_JSONAPI_Relationship;

struct GNUNET_JSONAPI_Error;

struct GNUNET_JSONAPI_Resource;

struct GNUNET_JSONAPI_Document;

/**
 * Specification for parsing a jsonapi relationship.
 *
 * @param jsonapi_obj where to store the jsonapi relationship
 */
struct GNUNET_JSON_Specification
GNUNET_JSON_spec_jsonapi_relationship (struct GNUNET_JSONAPI_Relationship **jsonapi_obj);

/**
 * Specification for parsing a jsonapi error.
 *
 * @param jsonapi_obj where to store the jsonapi error
 */
struct GNUNET_JSON_Specification
GNUNET_JSON_spec_jsonapi_error (struct GNUNET_JSONAPI_Error **jsonapi_obj);

/**
 * Specification for parsing a jsonapi resource.
 *
 * @param jsonapi_obj where to store the jsonapi resource
 */
struct GNUNET_JSON_Specification
GNUNET_JSON_spec_jsonapi_resource (struct GNUNET_JSONAPI_Resource **jsonapi_obj);

/**
 * Specification for parsing a jsonapi object.
 *
 * @param jsonapi_obj where to store the jsonapi object
 */
struct GNUNET_JSON_Specification
GNUNET_JSON_spec_jsonapi_document (struct GNUNET_JSONAPI_Document **jsonapi_obj);

/**
 * Delete a JSON API relationship
 *
 * @param res the JSON resource
 * @param result Pointer where the resource should be stored
 */
void
GNUNET_JSONAPI_relationship_delete (struct GNUNET_JSONAPI_Relationship *rel);


/****************** jsonapi Error API ********************/

/**
 * Create a JSON API error
 *
 * @param res the JSON error
 */
struct GNUNET_JSONAPI_Error*
GNUNET_JSONAPI_error_new (const char *id,
                          const char *status,
                          const char *code,
                          const char *title,
                          const char *detail,
                          json_t *links,
                          json_t *source,
                          json_t *meta);

/**
 * Delete a JSON API error
 *
 * @param res the JSON error
 */
void
GNUNET_JSONAPI_error_delete (struct GNUNET_JSONAPI_Error *error);


/**
 * Add a JSON API error to document
 *
 * @param data The JSON API document to add to
 * @param res the JSON API error to add
 * @return the new number of resources
 */
void
GNUNET_JSONAPI_document_error_add (struct GNUNET_JSONAPI_Document *doc,
                                      struct GNUNET_JSONAPI_Error *err);

/**
 * String serialze jsonapi error to json
 *
 * @param data the JSON API error
 * @param result where to store the result
 * @return GNUNET_SYSERR on error else GNUNET_OK
 */
int
GNUNET_JSONAPI_error_to_json (const struct GNUNET_JSONAPI_Error *err,
                              json_t **result);

/**
 * Parse json to error object
 *
 * @param err_json JSON object
 * @param[out] err error object
 * @return GNUNET_OK on success
 */
int
GNUNET_JSONAPI_json_to_error (json_t *err_json,
                              struct GNUNET_JSONAPI_Error **err);

/****************** jsonapi Resource API ********************/

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
 * String serialze jsonapi to json
 *
 * @param data the JSON API resource
 * @param result where to store the result
 * @return GNUNET_SYSERR on error else GNUNET_OK
 */
int
GNUNET_JSONAPI_resource_to_json (const struct GNUNET_JSONAPI_Resource *res,
                                 json_t **result);


/**
 * Parse json to resource object
 *
 * @param res_json JSON object
 * @param[out] res resource object
 * @return GNUNET_OK on success
 */
int
GNUNET_JSONAPI_json_to_resource (json_t *res_json,
                                 struct GNUNET_JSONAPI_Resource **res);


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
GNUNET_JSONAPI_resource_add_attr (struct GNUNET_JSONAPI_Resource *resource,
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
 * Check a JSON API resource id
 *
 * @param res the JSON resource
 * @return the resource id
 */
char*
GNUNET_JSONAPI_resource_get_id (const struct GNUNET_JSONAPI_Resource *resource);


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

/****************** jsonapi Document API ********************/

/**
 * Create a JSON API primary data
 *
 * @param type the JSON API resource type
 * @param id the JSON API resource id
 * @return a new JSON API resource or NULL on error.
 */
struct GNUNET_JSONAPI_Document*
GNUNET_JSONAPI_document_new ();


/**
 * Delete a JSON API primary data
 *
 * @param type the JSON API resource type
 * @param id the JSON API resource id
 * @return a new JSON API resource or NULL on error.
 */
void
GNUNET_JSONAPI_document_delete (struct GNUNET_JSONAPI_Document *resp);

/**
 * String serialze jsonapi primary data
 *
 * @param data the JSON API primary data
 * @param result where to store the result
 * @return GNUNET_SYSERR on error else GNUNET_OK
 */
int
GNUNET_JSONAPI_document_to_json (const struct GNUNET_JSONAPI_Document *doc,
                                 json_t **root_json);

/**
 * Add a JSON API resource to primary data
 *
 * @param data The JSON API data to add to
 * @param res the JSON API resource to add
 * @return the new number of resources
 */
void
GNUNET_JSONAPI_document_resource_add (struct GNUNET_JSONAPI_Document *resp,
                                      struct GNUNET_JSONAPI_Resource *res);
/**
 * Get a JSON API object resource count
 *
 * @param resp the JSON API object
 * @return the number of resources
 */
int
GNUNET_JSONAPI_document_resource_count (struct GNUNET_JSONAPI_Document *resp);

/**
 * Get a JSON API object resource num
 *
 * @param resp the JSON API object
 * @param num the number of the resource
 * @return the resource
 */
struct GNUNET_JSONAPI_Resource*
GNUNET_JSONAPI_document_get_resource (struct GNUNET_JSONAPI_Document *resp, int num);


/**
 * Add a JSON API resource to primary data
 *
 * @param resp The JSON API data to add to
 * @param res the JSON API resource to add
 * @return the new number of resources
 */
void
GNUNET_JSONAPI_document_resource_remove (struct GNUNET_JSONAPI_Document *resp,
                                         struct GNUNET_JSONAPI_Resource *res);

/**
 * String serialze jsonapi primary data
 *
 * @param data the JSON API primary data
 * @param result where to store the result
 * @return GNUNET_SYSERR on error else GNUNET_OK
 */
int
GNUNET_JSONAPI_document_serialize (const struct GNUNET_JSONAPI_Document *resp,
                                   char **result);

/* end of gnunet_jsonapi_lib.h */
#endif

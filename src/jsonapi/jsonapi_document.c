
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_json_lib.h"
#include "jsonapi_objects.h"

/**
 * Get a JSON API object resource count
 *
 * @param resp the JSON API object
 * @return the number of resources
 */
int
GNUNET_JSONAPI_document_resource_count (struct GNUNET_JSONAPI_Document *doc)
{
  return doc->res_count;
}

/**
 * Get a JSON API object resource by index
 *
 * @param resp the JSON API object
 * @param idx index of the resource
 * @return the resource
 */
struct GNUNET_JSONAPI_Resource*
GNUNET_JSONAPI_document_get_resource (struct GNUNET_JSONAPI_Document *doc,
                                      int idx)
{
  struct GNUNET_JSONAPI_Resource *res;
  int i;

  if ((0 == doc->res_count) ||
      (idx >= doc->res_count))
    return NULL;
  res = doc->res_list_head;
  for (i = 0; i < idx; i++)
  {
    res = res->next;
  }
  return res;
}

/**
 * Delete a JSON API primary data
 *
 * @param type the JSON API resource type
 * @param id the JSON API resource id
 * @return a new JSON API resource or NULL on error.
 */
void
GNUNET_JSONAPI_document_delete (struct GNUNET_JSONAPI_Document *doc)
{
  struct GNUNET_JSONAPI_Resource *res;
  struct GNUNET_JSONAPI_Resource *res_next;
  

  for (res = doc->res_list_head;
       res != NULL;)
  {
    res_next = res->next;
    GNUNET_CONTAINER_DLL_remove (doc->res_list_head,
                                 doc->res_list_tail,
                                 res);
    GNUNET_JSONAPI_resource_delete (res);
    res = res_next;
  }
  GNUNET_free (doc);
  doc = NULL;
}

/**
 * Create a JSON API primary data
 *
 * @return a new JSON API resource or NULL on error.
 */
struct GNUNET_JSONAPI_Document*
GNUNET_JSONAPI_document_new ()
{
  struct GNUNET_JSONAPI_Document *result;

  result = GNUNET_new (struct GNUNET_JSONAPI_Document);
  result->res_count = 0;
  result->err_count = 0;
  result->meta = 0;
  return result;
}

/**
 * Add a JSON API error to document
 *
 * @param data The JSON API document to add to
 * @param res the JSON API error to add
 * @return the new number of resources
 */
void
GNUNET_JSONAPI_document_error_add (struct GNUNET_JSONAPI_Document *doc,
                                      struct GNUNET_JSONAPI_Error *err)
{
  GNUNET_CONTAINER_DLL_insert (doc->err_list_head,
                               doc->err_list_tail,
                               err);

  doc->err_count++;
}

/**
 * Add a JSON API resource to primary data
 *
 * @param data The JSON API data to add to
 * @param res the JSON API resource to add
 * @return the new number of resources
 */
void
GNUNET_JSONAPI_document_resource_add (struct GNUNET_JSONAPI_Document *doc,
                                         struct GNUNET_JSONAPI_Resource *res)
{
  GNUNET_CONTAINER_DLL_insert (doc->res_list_head,
                               doc->res_list_tail,
                               res);

  doc->res_count++;
}


/**
 * Parse given JSON object to jsonapi document.
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
  struct GNUNET_JSONAPI_Document *result;
  struct GNUNET_JSONAPI_Error *error;
  struct GNUNET_JSONAPI_Resource *resource;
  json_t *meta_json;
  json_t *resource_json;
  json_t *errors_json;
  json_t *value;
  size_t index;

  struct GNUNET_JSON_Specification jsonapispecerrors[] = {
    GNUNET_JSON_spec_json (GNUNET_JSONAPI_KEY_ERRORS, &errors_json),
    GNUNET_JSON_spec_end()
  };
  if (GNUNET_OK !=
      GNUNET_JSON_parse (root, jsonapispecerrors,
                         NULL, NULL))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_INFO, 
                "JSONAPI document does not contain error objects\n");
  } else if (!json_is_array (errors_json))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Error object is not array!\n");
    GNUNET_JSON_parse_free (jsonapispecerrors);
    return GNUNET_SYSERR;
  }
  struct GNUNET_JSON_Specification jsonapispecmeta[] = {
    GNUNET_JSON_spec_json (GNUNET_JSONAPI_KEY_META, &meta_json),
    GNUNET_JSON_spec_end()
  };
  if (GNUNET_OK !=
      GNUNET_JSON_parse (root, jsonapispecmeta,
                         NULL, NULL))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                "JSONAPI document does not contain error objects\n");
  }
  struct GNUNET_JSON_Specification jsonapispecresource[] = {
    GNUNET_JSON_spec_json (GNUNET_JSONAPI_KEY_DATA, &resource_json),
    GNUNET_JSON_spec_end()
  };
  if (GNUNET_OK !=
      GNUNET_JSON_parse (root, jsonapispecresource,
                         NULL, NULL))
  {
    if (NULL == errors_json)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  "JSONAPI document contains neither error nor data!\n");
      GNUNET_JSON_parse_free (jsonapispecerrors);
      GNUNET_JSON_parse_free (jsonapispecmeta);
      return GNUNET_SYSERR;
    }
  } else {
    if (NULL != errors_json)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  "JSONAPI document contains both error and data!\n");
      GNUNET_JSON_parse_free (jsonapispecerrors);
      GNUNET_JSON_parse_free (jsonapispecmeta);
      GNUNET_JSON_parse_free (jsonapispecresource);
      return GNUNET_SYSERR;
    }
  }

  result = GNUNET_new (struct GNUNET_JSONAPI_Document);
  result->res_count = 0;
  result->err_count = 0;
  if (NULL != meta_json)
    result->meta = json_deep_copy (meta_json);
  if (NULL != errors_json) {
    json_array_foreach(errors_json, index, value) {
      GNUNET_assert (GNUNET_OK == 
                     GNUNET_JSONAPI_json_to_error (value,
                                                   &error));
      GNUNET_JSONAPI_document_error_add (result, error);
    }
  }
  if (NULL != resource_json) {
    if (0 != json_is_array (resource_json))
    {
      json_array_foreach(resource_json, index, value) {
        GNUNET_assert (GNUNET_OK == 
                       GNUNET_JSONAPI_json_to_resource (value,
                                                        &resource));
        GNUNET_JSONAPI_document_resource_add (result, resource);
      }
    } else {
      GNUNET_assert (GNUNET_OK == 
                     GNUNET_JSONAPI_json_to_resource (resource_json,
                                                      &resource));
      GNUNET_JSONAPI_document_resource_add (result, resource);
    }
  }
  if (NULL != errors_json)
    GNUNET_JSON_parse_free (jsonapispecerrors);
  if (NULL != resource)
    GNUNET_JSON_parse_free (jsonapispecresource);
  if (NULL != meta_json)
    GNUNET_JSON_parse_free (jsonapispecmeta);
  *(struct GNUNET_JSONAPI_Document **) spec->ptr = result;
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
  struct GNUNET_JSONAPI_Document **jsonapi_obj;
  jsonapi_obj = (struct GNUNET_JSONAPI_Document **) spec->ptr;
  if (NULL != *jsonapi_obj)
  {
    GNUNET_JSONAPI_document_delete (*jsonapi_obj);
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
GNUNET_JSONAPI_document_resource_remove (struct GNUNET_JSONAPI_Document *resp,
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
GNUNET_JSONAPI_document_to_json (const struct GNUNET_JSONAPI_Document *doc,
                                 json_t **root_json)
{
  struct GNUNET_JSONAPI_Resource *res;
  struct GNUNET_JSONAPI_Error *error;
  json_t *res_json;
  json_t *res_json_tmp;

  if ((NULL == doc))
    return GNUNET_SYSERR;

  *root_json = json_object ();

  //Check for errors first 
  if (doc->err_count != 0)
  {
    res_json = json_array ();
    for (error = doc->err_list_head;
         error != NULL;
         error = error->next)
    {
      GNUNET_assert (GNUNET_OK ==
                     GNUNET_JSONAPI_error_to_json (error,
                                                   &res_json_tmp));
      json_array_append (res_json, res_json_tmp);
    }
    json_object_set_new (*root_json,
                         GNUNET_JSONAPI_KEY_ERRORS,
                         res_json);
  } else {
    switch (doc->res_count)
    {
      case 0:
        res_json = json_null();
        break;
      case 1:
        GNUNET_assert (GNUNET_OK ==
                       GNUNET_JSONAPI_resource_to_json (doc->res_list_head,
                                                        &res_json));
        break;
      default:
        res_json = json_array ();
        for (res = doc->res_list_head;
             res != NULL;
             res = res->next)
        {
          GNUNET_assert (GNUNET_OK ==
                         GNUNET_JSONAPI_resource_to_json (res,
                                                          &res_json_tmp));
          json_array_append (res_json, res_json_tmp);
        }
        break;
    }
    json_object_set_new (*root_json,
                         GNUNET_JSONAPI_KEY_DATA,
                         res_json);
  }
  json_object_set (*root_json,
                   GNUNET_JSONAPI_KEY_META,
                   doc->meta);
  return GNUNET_OK;
}

/**
 * String serialze jsonapi primary data
 *
 * @param data the JSON API primary data
 * @param result where to store the result
 * @return GNUNET_SYSERR on error else GNUNET_OK
 */
int
GNUNET_JSONAPI_document_serialize (const struct GNUNET_JSONAPI_Document *doc,
                                   char **result)
{
  json_t *json_doc;
  if (GNUNET_OK != GNUNET_JSONAPI_document_to_json (doc,
                                                    &json_doc))
    return GNUNET_SYSERR;

  *result = json_dumps (json_doc, JSON_INDENT(2));
  json_decref (json_doc);
  return GNUNET_OK;
}

/**
 * JSON object.
 *
 * @param name name of the JSON field
 * @param[out] jsonp where to store the JSON found under @a name
 */
struct GNUNET_JSON_Specification
GNUNET_JSON_spec_jsonapi_document (struct GNUNET_JSONAPI_Document **jsonapi_object)
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



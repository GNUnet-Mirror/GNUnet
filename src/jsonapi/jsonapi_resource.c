#include "platform.h"
#include "gnunet_jsonapi_lib.h"
#include "jsonapi_objects.h"

/**
 * String serialze jsonapi resources
 *
 * @param data the JSON API resource
 * @param result where to store the result
 * @return GNUNET_SYSERR on error else GNUNET_OK
 */
int
GNUNET_JSONAPI_resource_to_json (const struct GNUNET_JSONAPI_Resource *res,
                                 json_t **result)
{
  struct GNUNET_JSONAPI_Resource *rel_res;
  json_t *relationship;
  json_t *res_json_tmp;
  *result = json_object ();

  if (0 != json_object_set_new (*result,
                                GNUNET_JSONAPI_KEY_ID,
                                json_string (res->id)))
    return GNUNET_SYSERR;
  if (0 != json_object_set_new (*result,
                                GNUNET_JSONAPI_KEY_TYPE,
                                json_string (res->type)))
    return GNUNET_SYSERR;
  if ((NULL != res->attr_obj) &&
      (0 != json_object_set (*result,
                             GNUNET_JSONAPI_KEY_ATTRIBUTES,
                             res->attr_obj)))
    return GNUNET_SYSERR;

  //Relationships
  if (NULL != res->relationship)
  {
    relationship = json_object ();
    if (0 != res->relationship->res_count)
    {
      json_t *res_json;
      switch (res->relationship->res_count)
      {
        case 0:
          res_json = json_null();
          break;
        case 1:
          GNUNET_assert (GNUNET_OK ==
                         GNUNET_JSONAPI_resource_to_json (res->relationship->res_list_head,
                                                          &res_json));
          break;
        default:
          res_json = json_array ();
          rel_res = NULL;
          for (rel_res = rel_res->relationship->res_list_head;
               rel_res != NULL;
               rel_res = rel_res->next)
          {
            GNUNET_assert (GNUNET_OK ==
                           GNUNET_JSONAPI_resource_to_json (rel_res,
                                                            &res_json_tmp));
            json_array_append_new (res_json, res_json_tmp);
          }
          break;
      }
      json_object_set_new (relationship,
                           GNUNET_JSONAPI_KEY_DATA,
                           res_json);
    }
    if ((NULL != res->relationship->meta) &&
        (0 != json_object_set_new (relationship,
                                   GNUNET_JSONAPI_KEY_META,
                                   res->relationship->meta)))
      return GNUNET_SYSERR;
    //TODO link
  }


  return GNUNET_OK;
}


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
  res->attr_obj = NULL;
  res->relationship = NULL;
  res->id = GNUNET_strdup (id);
  res->type = GNUNET_strdup (type);
  return res;
}

/**
 * Add a jsonapi relationship
 * @param res the resource to add to
 * @param rel the relationship to add
 * @return #GNUNETOK if added successfully
 */
int
GNUNET_JSONAPI_resource_set_relationship (struct GNUNET_JSONAPI_Resource *res,
                                          struct GNUNET_JSONAPI_Relationship *rel)
{
  GNUNET_assert (NULL != res);
  GNUNET_assert (NULL != rel);
  if (NULL != res->relationship)
    return GNUNET_SYSERR;
  res->relationship = rel;
  return GNUNET_OK;
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
GNUNET_JSONAPI_resource_add_attr (struct GNUNET_JSONAPI_Resource *resource,
                                  const char* key,
                                  json_t *json)
{
  if ( (NULL == resource) ||
       (NULL == key) ||
       (NULL == json) )
    return GNUNET_SYSERR;
  if (NULL == resource->attr_obj)
    resource->attr_obj = json_object ();
  json_object_set_new (resource->attr_obj, key, json);
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
       (NULL == key) ||
       (NULL == resource->attr_obj))
    return NULL;
  return json_object_get (resource->attr_obj, key);
}

int
check_resource_attr_str (const struct GNUNET_JSONAPI_Resource *resource,
                         const char* key,
                         const char* attr)
{
  json_t *value;
  if ( (NULL == resource) ||
       (NULL == key) ||
       (NULL == attr) ||
       (NULL == resource->attr_obj))
    return GNUNET_NO;
  value = json_object_get (resource->attr_obj, key);
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
  return (0 == memcmp (type, resource->type,
                       strlen (resource->type))) ? GNUNET_YES : GNUNET_NO;
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
  GNUNET_free (resource->id);
  GNUNET_free (resource->type);
  if (NULL != resource->attr_obj)
    json_decref (resource->attr_obj);
  if (NULL != resource->relationship)
    GNUNET_JSONAPI_relationship_delete (resource->relationship);
  GNUNET_free (resource);
  resource = NULL;
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
  return (0 == memcmp (resource->id, id, strlen (id))) ? GNUNET_YES : GNUNET_NO;
}

/**
 * Check a JSON API resource id
 *
 * @param res the JSON resource
 * @return the resource id
 */
char*
GNUNET_JSONAPI_resource_get_id (const struct GNUNET_JSONAPI_Resource *resource)
{
  return resource->id;
}

/**
 * Parse json to resource object
 *
 * @param res_json JSON object
 * @param[out] res resource object
 * @return GNUNET_OK on success
 */
int
GNUNET_JSONAPI_json_to_resource (json_t *res_json,
                                 struct GNUNET_JSONAPI_Resource **res)
{
  struct GNUNET_JSON_Specification jsonapispecresource[] = {
    GNUNET_JSON_spec_jsonapi_resource (res),
    GNUNET_JSON_spec_end()
  };
  return GNUNET_JSON_parse (res_json, jsonapispecresource,
                            NULL, NULL);
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
parse_jsonapiresource (void *cls,
                       json_t *root,
                       struct GNUNET_JSON_Specification *spec)
{
  struct GNUNET_JSONAPI_Resource *res;
  const char *type;
  const char *id;
  json_t *attrs;

  struct GNUNET_JSON_Specification dspec[] = {
    GNUNET_JSON_spec_string (GNUNET_JSONAPI_KEY_TYPE, &type),
    GNUNET_JSON_spec_string (GNUNET_JSONAPI_KEY_ID, &id),
    GNUNET_JSON_spec_end()
  };

  if (GNUNET_OK !=
      GNUNET_JSON_parse (root, dspec,
                         NULL, NULL))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Unable to parse resource\n");
    return GNUNET_SYSERR;
  }
  res = GNUNET_JSONAPI_resource_new (type, id);
  GNUNET_JSON_parse_free (dspec);

  struct GNUNET_JSON_Specification attrspec[] = {
    GNUNET_JSON_spec_json (GNUNET_JSONAPI_KEY_ATTRIBUTES, &attrs),
    GNUNET_JSON_spec_end()
  };
  if (GNUNET_OK !=
      GNUNET_JSON_parse (root, attrspec,
                         NULL, NULL))
    GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Resource does not contain attributes\n");
  if (NULL != attrs)
    res->attr_obj = json_deep_copy (attrs);

  //TODO relationship
  GNUNET_JSON_parse_free (attrspec);
  *(struct GNUNET_JSONAPI_Resource **) spec->ptr = res;
  return GNUNET_OK;
}


/**
 * Cleanup data left from parsing resource.
 *
 * @param cls closure, NULL
 * @param[out] spec where to free the data
 */
static void
clean_jsonapiresource (void *cls,
                       struct GNUNET_JSON_Specification *spec)
{
  struct GNUNET_JSONAPI_Resource **jsonapi_obj;
  jsonapi_obj = (struct GNUNET_JSONAPI_Resource **) spec->ptr;
  if (NULL != *jsonapi_obj)
  {
    GNUNET_JSONAPI_resource_delete (*jsonapi_obj);
    *jsonapi_obj = NULL;
  }
}


/**
 * JSON object.
 *
 * @param name name of the JSON field
 * @param[out] jsonp where to store the JSON found under @a name
 */
struct GNUNET_JSON_Specification
GNUNET_JSON_spec_jsonapi_resource (struct GNUNET_JSONAPI_Resource **jsonapi_object)
{
  struct GNUNET_JSON_Specification ret = {
    .parser = &parse_jsonapiresource,
    .cleaner = &clean_jsonapiresource,
    .cls = NULL,
    .field = NULL,
    .ptr = jsonapi_object,
    .ptr_size = 0,
    .size_ptr = NULL
  };
  *jsonapi_object = NULL;
  return ret;
}



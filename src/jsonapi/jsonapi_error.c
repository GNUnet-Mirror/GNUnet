#include "platform.h"
#include "gnunet_jsonapi_lib.h"
#include "jsonapi_objects.h"

/**
 * Parse json to error object
 *
 * @param err_json JSON object
 * @param[out] err error object
 * @return GNUNET_OK on success
 */
int
GNUNET_JSONAPI_json_to_error (json_t *err_json,
                              struct GNUNET_JSONAPI_Error **err)
{
  struct GNUNET_JSON_Specification jsonapispecerror[] = {
    GNUNET_JSON_spec_jsonapi_error (err),
    GNUNET_JSON_spec_end()
  };
  return GNUNET_JSON_parse (err_json, jsonapispecerror,
                            NULL, NULL);
}

/**
 * Serialze jsonapi errors
 *
 * @param data the JSON API errors
 * @param result where to store the result
 * @return GNUNET_SYSERR on error else GNUNET_OK
 */
int
GNUNET_JSONAPI_error_to_json (const struct GNUNET_JSONAPI_Error *err,
                              json_t **result)
{
  *result = json_object ();

  if ((NULL != err->id) &&
      (0 != json_object_set_new (*result,
                                 GNUNET_JSONAPI_KEY_ID,
                                 json_string (err->id))))
    return GNUNET_SYSERR;
  if ((NULL != err->status) &&
      (0 != json_object_set_new (*result,
                                 GNUNET_JSONAPI_KEY_STATUS,
                                 json_string (err->status))))
    return GNUNET_SYSERR;
  if ((NULL != err->code) &&
      (0 != json_object_set_new (*result,
                                 GNUNET_JSONAPI_KEY_CODE,
                                 json_string (err->code))))
    return GNUNET_SYSERR;

  if ((NULL != err->title) &&
      (0 != json_object_set_new (*result,
                                 GNUNET_JSONAPI_KEY_TITLE,
                                 json_string (err->title))))
    return GNUNET_SYSERR;
  if ((NULL != err->detail) &&
      (0 != json_object_set_new (*result,
                                 GNUNET_JSONAPI_KEY_DETAIL,
                                 json_string (err->detail))))
    return GNUNET_SYSERR;
  if ((NULL != err->source) &&
      (0 != json_object_set_new (*result,
                                 GNUNET_JSONAPI_KEY_SOURCE,
                                 err->source)))
    return GNUNET_SYSERR;
  if ((NULL != err->links) &&
      (0 != json_object_set_new (*result,
                                 GNUNET_JSONAPI_KEY_LINKS,
                                 err->links)))
    return GNUNET_SYSERR;
  if ((NULL != err->meta) &&
      (0 != json_object_set_new (*result,
                                 GNUNET_JSONAPI_KEY_META,
                                 err->meta)))
    return GNUNET_SYSERR;
  return GNUNET_OK;
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
parse_jsonapierror (void *cls,
                     json_t *root,
                     struct GNUNET_JSON_Specification *spec)
{
  struct GNUNET_JSONAPI_Error *result;
  json_t *pos;
  
  GNUNET_assert (NULL != root);
  result = GNUNET_new (struct GNUNET_JSONAPI_Error);
  pos = json_object_get (root, GNUNET_JSONAPI_KEY_ID);
  if (json_is_string (pos))
    result->id = GNUNET_strdup (json_string_value (pos));
  
  pos = json_object_get (root, GNUNET_JSONAPI_KEY_LINKS);
  if (json_is_object (pos))
    result->links = json_deep_copy (pos);
  
  pos = json_object_get (root, GNUNET_JSONAPI_KEY_STATUS);
  if (json_is_string (pos))
    result->status = GNUNET_strdup (json_string_value (pos));

  pos = json_object_get (root, GNUNET_JSONAPI_KEY_CODE);
  if (json_is_string (pos))
    result->code = GNUNET_strdup (json_string_value (pos));

  pos = json_object_get (root, GNUNET_JSONAPI_KEY_TITLE);
  if (json_is_string (pos))
    result->title = GNUNET_strdup (json_string_value (pos));

  pos = json_object_get (root, GNUNET_JSONAPI_KEY_DETAIL);
  if (json_is_string (pos))
    result->detail = GNUNET_strdup (json_string_value (pos));

  pos = json_object_get (root, GNUNET_JSONAPI_KEY_SOURCE);
  if (json_is_object (pos))
    result->source = json_deep_copy (pos);
  pos = json_object_get (root, GNUNET_JSONAPI_KEY_META);
  if (json_is_object (pos))
    result->meta = json_deep_copy (pos);
  *(struct GNUNET_JSONAPI_Error **) spec->ptr = result;
  return GNUNET_OK;
}

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
                          json_t *meta)
{
  struct GNUNET_JSONAPI_Error *error;
  error = GNUNET_new (struct GNUNET_JSONAPI_Error);

  GNUNET_assert (NULL != id);
  error->id = GNUNET_strdup (id);
  GNUNET_assert (NULL != status);
  error->status = GNUNET_strdup (status);
  GNUNET_assert (NULL != code);
  error->code = GNUNET_strdup (code);
  GNUNET_assert (NULL != title);
  error->title = GNUNET_strdup (title);
  GNUNET_assert (NULL != detail);
  error->detail = GNUNET_strdup (detail);
  GNUNET_assert (NULL != links);
  error->links = json_deep_copy (links);
  GNUNET_assert (NULL != source);
  error->source = json_deep_copy (source);
  GNUNET_assert (NULL != meta);
  error->meta = json_deep_copy (meta);
  return error;
}
/**
 * Delete a JSON API error
 *
 * @param res the JSON error
 */
void
GNUNET_JSONAPI_error_delete (struct GNUNET_JSONAPI_Error *error)
{
  GNUNET_assert (NULL != error);

  if (NULL != error->id)
    GNUNET_free (error->id);
  if (NULL != error->status)
    GNUNET_free (error->status);
  if (NULL != error->code)
    GNUNET_free (error->code);
  if (NULL != error->title)
    GNUNET_free (error->title);
  if (NULL != error->detail)
    GNUNET_free (error->detail);
  if (NULL != error->links)
    json_decref (error->links);
  if (NULL != error->source)
    json_decref (error->source);
  if (NULL != error->meta)
    json_decref (error->meta);
  GNUNET_free (error);
}



/**
 * Cleanup data left from parsing RSA public key.
 *
 * @param cls closure, NULL
 * @param[out] spec where to free the data
 */
static void
clean_jsonapierror (void *cls,
                     struct GNUNET_JSON_Specification *spec)
{
  struct GNUNET_JSONAPI_Error **jsonapi_obj;
  jsonapi_obj = (struct GNUNET_JSONAPI_Error **) spec->ptr;
  if (NULL != *jsonapi_obj)
  {
    GNUNET_JSONAPI_error_delete (*jsonapi_obj);
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
GNUNET_JSON_spec_jsonapi_error (struct GNUNET_JSONAPI_Error **jsonapi_object)
{
  struct GNUNET_JSON_Specification ret = {
    .parser = &parse_jsonapierror,
    .cleaner = &clean_jsonapierror,
    .cls = NULL,
    .field = NULL,
    .ptr = jsonapi_object,
    .ptr_size = 0,
    .size_ptr = NULL
  };
  *jsonapi_object = NULL;
  return ret;
}



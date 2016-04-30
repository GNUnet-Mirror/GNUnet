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
 * @file identity/plugin_rest_identity.c
 * @brief GNUnet Namestore REST plugin
 *
 */

#include "platform.h"
#include "gnunet_rest_plugin.h"
#include "gnunet_identity_service.h"
#include "gnunet_rest_lib.h"
#include "microhttpd.h"
#include <jansson.h>
#include "gnunet_signatures.h"

/**
 * REST root namespace
 */
#define GNUNET_REST_API_NS_IDENTITY "/identity"

/**
 * State while collecting all egos
 */
#define ID_REST_STATE_INIT 0

/**
 * Done collecting egos
 */
#define ID_REST_STATE_POST_INIT 1

/**
 * Resource type
 */
#define GNUNET_REST_JSONAPI_IDENTITY_EGO "ego"

/**
 * Name attribute
 */
#define GNUNET_REST_JSONAPI_IDENTITY_NAME "name"

/**
 * Attribute to rename "name" TODO we changed id to the pubkey
 * so this can be unified with "name"
 */
#define GNUNET_REST_JSONAPI_IDENTITY_NEWNAME "newname"

/**
 * URL parameter to change the subsytem for ego
 */
#define GNUNET_REST_JSONAPI_IDENTITY_SUBSYSTEM "subsystem"


/**
 * Error messages
 */
#define GNUNET_REST_ERROR_RESOURCE_INVALID "Resource location invalid"
#define GNUNET_REST_ERROR_NO_DATA "No data"

/**
 * GNUid token lifetime
 */
#define GNUNET_GNUID_TOKEN_EXPIRATION_MICROSECONDS 300000000

/**
 * The configuration handle
 */
const struct GNUNET_CONFIGURATION_Handle *cfg;

/**
 * HTTP methods allows for this plugin
 */
static char* allow_methods;

/**
 * @brief struct returned by the initialization function of the plugin
 */
struct Plugin
{
  const struct GNUNET_CONFIGURATION_Handle *cfg;
};

/**
 * The ego list
 */
struct EgoEntry
{
  /**
   * DLL
   */
  struct EgoEntry *next;

  /**
   * DLL
   */
  struct EgoEntry *prev;

  /**
   * Ego Identifier
   */
  char *identifier;

  /**
   * Public key string
   */
  char *keystring;

  /**
   * The Ego
   */
  struct GNUNET_IDENTITY_Ego *ego;
};


struct RequestHandle
{
  /**
   * Ego list
   */
  struct EgoEntry *ego_head;

  /**
   * Ego list
   */
  struct EgoEntry *ego_tail;

  /**
   * Handle to the rest connection
   */
  struct RestConnectionDataHandle *conndata_handle;

  /**
   * The processing state
   */
  int state;

  /**
   * Handle to GNS service.
   */
  struct GNUNET_IDENTITY_Handle *identity_handle;

  /**
   * IDENTITY Operation
   */
  struct GNUNET_IDENTITY_Operation *op;

  /**
   * Desired timeout for the lookup (default is no timeout).
   */
  struct GNUNET_TIME_Relative timeout;

  /**
   * ID of a task associated with the resolution process.
   */
  struct GNUNET_SCHEDULER_Task * timeout_task;

  /**
   * The plugin result processor
   */
  GNUNET_REST_ResultProcessor proc;

  /**
   * The closure of the result processor
   */
  void *proc_cls;

  /**
   * The name to look up
   */
  char *name;

  /**
   * The subsystem set from REST
   */
  char *subsys;

  /**
   * The url
   */
  char *url;

  /**
   * The data from the REST request
   */
  const char* data;

  /**
   * the length of the REST data
   */
  size_t data_size;

  /**
   * HTTP method
   */
  const char* method;

  /**
   * Error response message
   */
  char *emsg;

};


/**
 * Cleanup lookup handle
 * @param handle Handle to clean up
 */
static void
cleanup_handle (struct RequestHandle *handle)
{
  struct EgoEntry *ego_entry;
  struct EgoEntry *ego_tmp;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Cleaning up\n");
  if (NULL != handle->name)
    GNUNET_free (handle->name);
  if (NULL != handle->timeout_task)
    GNUNET_SCHEDULER_cancel (handle->timeout_task);
  if (NULL != handle->identity_handle)
    GNUNET_IDENTITY_disconnect (handle->identity_handle);
  if (NULL != handle->subsys)
    GNUNET_free (handle->subsys);
  if (NULL != handle->url)
    GNUNET_free (handle->url);
  if (NULL != handle->emsg)
    GNUNET_free (handle->emsg);
  for (ego_entry = handle->ego_head;
       NULL != ego_entry;)
  {
    ego_tmp = ego_entry;
    ego_entry = ego_entry->next;
    GNUNET_free (ego_tmp->identifier);
    GNUNET_free (ego_tmp->keystring);
    GNUNET_free (ego_tmp);
  }
  GNUNET_free (handle);
}


/**
 * Task run on errors.  Reports an error and cleans up everything.
 *
 * @param cls the `struct RequestHandle`
 */
static void
do_error (void *cls)
{
  struct RequestHandle *handle = cls;
  struct MHD_Response *resp;
  char *json_error;

  GNUNET_asprintf (&json_error,
                   "{Error while processing request: %s}",
                   &handle->emsg);

  resp = GNUNET_REST_create_json_response (json_error);
  handle->proc (handle->proc_cls,
		resp,
		MHD_HTTP_BAD_REQUEST);
  cleanup_handle (handle);
  GNUNET_free (json_error);
}


/**
 * Callback for IDENTITY_get()
 *
 * @param cls the RequestHandle
 * @param ego the Ego found
 * @param ctx the context
 * @param name the id of the ego
 */
static void
get_ego_for_subsys (void *cls,
                    struct GNUNET_IDENTITY_Ego *ego,
                    void **ctx,
                    const char *name)
{
  struct RequestHandle *handle = cls;
  struct JsonApiObject *json_object;
  struct JsonApiResource *json_resource;
  struct EgoEntry *ego_entry;
  struct MHD_Response *resp;
  json_t *name_json;
  char *result_str;

  json_object = GNUNET_REST_jsonapi_object_new ();

  for (ego_entry = handle->ego_head;
       NULL != ego_entry;
       ego_entry = ego_entry->next)
  {
    if ( (NULL != name) && (0 != strcmp (name, ego_entry->identifier)) )
      continue;
    if (NULL == name)
      continue;
    json_resource = GNUNET_REST_jsonapi_resource_new
      (GNUNET_REST_JSONAPI_IDENTITY_EGO, ego_entry->keystring);
    name_json = json_string (ego_entry->identifier);
    GNUNET_REST_jsonapi_resource_add_attr (json_resource,
                                           GNUNET_REST_JSONAPI_IDENTITY_NAME,
                                           name_json);
    json_decref (name_json);
    GNUNET_REST_jsonapi_object_resource_add (json_object, json_resource);
    break;
  }
  if (0 == GNUNET_REST_jsonapi_object_resource_count (json_object))
  {
    GNUNET_REST_jsonapi_object_delete (json_object);
    handle->emsg = GNUNET_strdup("No identity matches results!");
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }
  GNUNET_REST_jsonapi_data_serialize (json_object, &result_str);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Result %s\n", result_str);
  resp = GNUNET_REST_create_json_response (result_str);
  GNUNET_REST_jsonapi_object_delete (json_object);
  handle->proc (handle->proc_cls, resp, MHD_HTTP_OK);
  GNUNET_free (result_str);
  cleanup_handle (handle);
}

/**
 * Create a response with requested ego(s)
 *
 * @param con the Rest handle
 * @param url the requested url
 * @param cls the request handle
 */
static void
ego_info_response (struct RestConnectionDataHandle *con,
                   const char *url,
                   void *cls)
{
  const char *egoname;
  char *result_str;
  char *subsys_val;
  char *keystring;
  struct RequestHandle *handle = cls;
  struct EgoEntry *ego_entry;
  struct GNUNET_HashCode key;
  struct MHD_Response *resp;
  struct JsonApiObject *json_object;
  struct JsonApiResource *json_resource;
  json_t *name_str;

  if (GNUNET_NO == GNUNET_REST_namespace_match (handle->url, GNUNET_REST_API_NS_IDENTITY))
  {
    resp = GNUNET_REST_create_json_response (NULL);
    handle->proc (handle->proc_cls, resp, MHD_HTTP_BAD_REQUEST);
    cleanup_handle (handle);
    return;
  }
  egoname = NULL;
  keystring = NULL;
  if (strlen (GNUNET_REST_API_NS_IDENTITY) < strlen (handle->url))
  {
    keystring = &handle->url[strlen (GNUNET_REST_API_NS_IDENTITY)+1];
    //Return all egos
    for (ego_entry = handle->ego_head;
         NULL != ego_entry;
         ego_entry = ego_entry->next)
    {
      if ( (NULL != keystring) && (0 != strcmp (keystring, ego_entry->keystring)) )
        continue;
      egoname = ego_entry->identifier;
    }
  }

  if ( NULL == egoname ) {
    GNUNET_CRYPTO_hash (GNUNET_REST_JSONAPI_IDENTITY_SUBSYSTEM,
                        strlen (GNUNET_REST_JSONAPI_IDENTITY_SUBSYSTEM),
                        &key);
    if ( GNUNET_YES ==
         GNUNET_CONTAINER_multihashmap_contains (handle->conndata_handle->url_param_map,
                                                 &key) )
    {
      subsys_val = GNUNET_CONTAINER_multihashmap_get (handle->conndata_handle->url_param_map,
                                                      &key);
      if (NULL != subsys_val)
      {
        GNUNET_asprintf (&handle->subsys, "%s", subsys_val);
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Looking for %s's ego\n", subsys_val);
        handle->op = GNUNET_IDENTITY_get (handle->identity_handle,
                                          handle->subsys,
                                          &get_ego_for_subsys,
                                          handle);
        return;
      }
    }
  }

  json_object = GNUNET_REST_jsonapi_object_new ();

  //Return all egos
  for (ego_entry = handle->ego_head;
       NULL != ego_entry;
       ego_entry = ego_entry->next)
  {
    if ( (NULL != egoname) && (0 != strcmp (egoname, ego_entry->identifier)) )
      continue;
    json_resource = GNUNET_REST_jsonapi_resource_new (GNUNET_REST_JSONAPI_IDENTITY_EGO,
                                                      ego_entry->keystring);
    name_str = json_string (ego_entry->identifier);
    GNUNET_REST_jsonapi_resource_add_attr (
                                           json_resource,
                                           GNUNET_REST_JSONAPI_IDENTITY_NAME,
                                           name_str);
    json_decref (name_str);
    GNUNET_REST_jsonapi_object_resource_add (json_object, json_resource);
  }
  if (0 == GNUNET_REST_jsonapi_object_resource_count (json_object))
  {
    GNUNET_REST_jsonapi_object_delete (json_object);
    handle->emsg = GNUNET_strdup ("No identities found!");
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }
  GNUNET_REST_jsonapi_data_serialize (json_object, &result_str);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Result %s\n", result_str);
  resp = GNUNET_REST_create_json_response (result_str);
  GNUNET_REST_jsonapi_object_delete (json_object);
  handle->proc (handle->proc_cls, resp, MHD_HTTP_OK);
  GNUNET_free (result_str);
  cleanup_handle (handle);
}

/**
 * Processing finished
 *
 * @param cls request handle
 * @param emsg error message
 */
static void
do_finished (void *cls, const char *emsg)
{
  struct RequestHandle *handle = cls;
  struct MHD_Response *resp;

  handle->op = NULL;
  if (NULL != emsg)
  {
    handle->emsg = GNUNET_strdup (emsg);
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }
  resp = GNUNET_REST_create_json_response (NULL);
  handle->proc (handle->proc_cls, resp, MHD_HTTP_NO_CONTENT);
  cleanup_handle (handle);
}

/**
 * Create a new ego
 *
 * @param con rest handle
 * @param url url
 * @param cls request handle
 */
static void
ego_create_cont (struct RestConnectionDataHandle *con,
                 const char *url,
                 void *cls)
{
  struct RequestHandle *handle = cls;
  struct EgoEntry *ego_entry;
  struct MHD_Response *resp;
  struct JsonApiObject *json_obj;
  struct JsonApiResource *json_res;
  json_t *egoname_json;
  const char* egoname;
  char term_data[handle->data_size+1];

  if (strlen (GNUNET_REST_API_NS_IDENTITY) != strlen (handle->url))
  {
    handle->emsg = GNUNET_strdup (GNUNET_REST_ERROR_RESOURCE_INVALID);
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }
  if (0 >= handle->data_size)
  {
    handle->emsg = GNUNET_strdup (GNUNET_REST_ERROR_NO_DATA);
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }
  term_data[handle->data_size] = '\0';
  memcpy (term_data, handle->data, handle->data_size);
  json_obj = GNUNET_REST_jsonapi_object_parse (term_data);
  if (NULL == json_obj)
  {
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }
  if (1 != GNUNET_REST_jsonapi_object_resource_count (json_obj))
  {
    GNUNET_REST_jsonapi_object_delete (json_obj);
    handle->emsg = GNUNET_strdup ("Provided resource count invalid");
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }
  json_res = GNUNET_REST_jsonapi_object_get_resource (json_obj, 0);
  if (GNUNET_NO == GNUNET_REST_jsonapi_resource_check_type (json_res, GNUNET_REST_JSONAPI_IDENTITY_EGO))
  {
    GNUNET_REST_jsonapi_object_delete (json_obj);
    resp = GNUNET_REST_create_json_response (NULL);
    handle->proc (handle->proc_cls, resp, MHD_HTTP_CONFLICT);
    cleanup_handle (handle);
    return;
  }
  egoname_json = GNUNET_REST_jsonapi_resource_read_attr (json_res, GNUNET_REST_JSONAPI_IDENTITY_NAME);
  if (!json_is_string (egoname_json))
  {
    GNUNET_REST_jsonapi_object_delete (json_obj);
    handle->emsg = GNUNET_strdup ("No name provided");
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }
  egoname = json_string_value (egoname_json);
  for (ego_entry = handle->ego_head;
       NULL != ego_entry;
       ego_entry = ego_entry->next)
  {
    if (0 == strcasecmp (egoname, ego_entry->identifier))
    {
      GNUNET_REST_jsonapi_object_delete (json_obj);
      resp = GNUNET_REST_create_json_response (NULL);
      handle->proc (handle->proc_cls, resp, MHD_HTTP_CONFLICT);
      cleanup_handle (handle);
      return;
    }
  }
  GNUNET_asprintf (&handle->name, "%s", egoname);
  GNUNET_REST_jsonapi_object_delete (json_obj);
  handle->op = GNUNET_IDENTITY_create (handle->identity_handle,
                                       handle->name,
                                       &do_finished,
                                       handle);
}


/**
 * Handle ego edit request
 *
 * @param con rest connection handle
 * @param url the url that is requested
 * @param cls the RequestHandle
 */
static void
ego_edit_cont (struct RestConnectionDataHandle *con,
               const char *url,
               void *cls)
{
  struct JsonApiObject *json_obj;
  struct JsonApiResource *json_res;
  struct RequestHandle *handle = cls;
  struct EgoEntry *ego_entry;
  struct MHD_Response *resp;
  json_t *subsys_json;
  json_t *name_json;
  const char *keystring;
  const char *subsys;
  const char *newname;
  char term_data[handle->data_size+1];
  int ego_exists = GNUNET_NO;

  if (strlen (GNUNET_REST_API_NS_IDENTITY) > strlen (handle->url))
  {
    handle->emsg = GNUNET_strdup (GNUNET_REST_ERROR_RESOURCE_INVALID);
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }

  keystring = &handle->url[strlen(GNUNET_REST_API_NS_IDENTITY)+1];

  for (ego_entry = handle->ego_head;
       NULL != ego_entry;
       ego_entry = ego_entry->next)
  {
    if (0 != strcasecmp (keystring, ego_entry->keystring))
      continue;
    ego_exists = GNUNET_YES;
    break;
  }

  if (GNUNET_NO == ego_exists)
  {
    resp = GNUNET_REST_create_json_response (NULL);
    handle->proc (handle->proc_cls, resp, MHD_HTTP_NOT_FOUND);
    cleanup_handle (handle);
    return;
  }

  if (0 >= handle->data_size)
  {
    handle->emsg = GNUNET_strdup (GNUNET_REST_ERROR_NO_DATA);
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }

  term_data[handle->data_size] = '\0';
  memcpy (term_data, handle->data, handle->data_size);
  json_obj = GNUNET_REST_jsonapi_object_parse (term_data);

  if (NULL == json_obj)
  {
    handle->emsg = GNUNET_strdup ("Data invalid");
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }

  if (1 != GNUNET_REST_jsonapi_object_resource_count (json_obj))
  {
    GNUNET_REST_jsonapi_object_delete (json_obj);
    handle->emsg = GNUNET_strdup ("Resource amount invalid");
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }
  json_res = GNUNET_REST_jsonapi_object_get_resource (json_obj, 0);

  if (GNUNET_NO == GNUNET_REST_jsonapi_resource_check_type (json_res, GNUNET_REST_JSONAPI_IDENTITY_EGO))
  {
    GNUNET_REST_jsonapi_object_delete (json_obj);
    handle->emsg = GNUNET_strdup ("Resource type invalid");
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }

  //This is a rename
  name_json = GNUNET_REST_jsonapi_resource_read_attr (json_res,
                                                      GNUNET_REST_JSONAPI_IDENTITY_NEWNAME);
  if ((NULL != name_json) && json_is_string (name_json))
  {
    newname = json_string_value (name_json);
    for (ego_entry = handle->ego_head;
         NULL != ego_entry;
         ego_entry = ego_entry->next)
    {
      if (0 == strcasecmp (newname, ego_entry->identifier) &&
          0 != strcasecmp (keystring, ego_entry->keystring))
      {
        //Ego with same name not allowed
        GNUNET_REST_jsonapi_object_delete (json_obj);
        resp = GNUNET_REST_create_json_response (NULL);
        handle->proc (handle->proc_cls, resp, MHD_HTTP_CONFLICT);
        cleanup_handle (handle);
        return;
      }
    }
    handle->op = GNUNET_IDENTITY_rename (handle->identity_handle,
                                         ego_entry->identifier,
                                         newname,
                                         &do_finished,
                                         handle);
    GNUNET_REST_jsonapi_object_delete (json_obj);
    return;
  }

  //Set subsystem
  subsys_json = GNUNET_REST_jsonapi_resource_read_attr (json_res, GNUNET_REST_JSONAPI_IDENTITY_SUBSYSTEM);
  if ( (NULL != subsys_json) && json_is_string (subsys_json))
  {
    subsys = json_string_value (subsys_json);
    GNUNET_asprintf (&handle->subsys, "%s", subsys);
    GNUNET_REST_jsonapi_object_delete (json_obj);
    handle->op = GNUNET_IDENTITY_set (handle->identity_handle,
                                      handle->subsys,
                                      ego_entry->ego,
                                      &do_finished,
                                      handle);
    return;
  }
  GNUNET_REST_jsonapi_object_delete (json_obj);
  handle->emsg = GNUNET_strdup ("Subsystem not provided");
  GNUNET_SCHEDULER_add_now (&do_error, handle);
}

void
ego_delete_cont (struct RestConnectionDataHandle *con_handle,
                 const char* url,
                 void *cls)
{
  const char *keystring;
  struct EgoEntry *ego_entry;
  struct MHD_Response *resp;
  struct RequestHandle *handle = cls;
  int ego_exists = GNUNET_NO;

  if (strlen (GNUNET_REST_API_NS_IDENTITY) >= strlen (handle->url))
  {
    handle->emsg = GNUNET_strdup (GNUNET_REST_ERROR_RESOURCE_INVALID);
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }

  keystring = &handle->url[strlen(GNUNET_REST_API_NS_IDENTITY)+1];
  for (ego_entry = handle->ego_head;
       NULL != ego_entry;
       ego_entry = ego_entry->next)
  {
    if (0 != strcasecmp (keystring, ego_entry->keystring))
      continue;
    ego_exists = GNUNET_YES;
    break;
  }
  if (GNUNET_NO == ego_exists)
  {
    resp = GNUNET_REST_create_json_response (NULL);
    handle->proc (handle->proc_cls, resp, MHD_HTTP_NOT_FOUND);
    cleanup_handle (handle);
    return;
  }
  handle->op = GNUNET_IDENTITY_delete (handle->identity_handle,
                                       ego_entry->identifier,
                                       &do_finished,
                                       handle);

}


/**
 * Respond to OPTIONS request
 *
 * @param con_handle the connection handle
 * @param url the url
 * @param cls the RequestHandle
 */
static void
options_cont (struct RestConnectionDataHandle *con_handle,
              const char* url,
              void *cls)
{
  struct MHD_Response *resp;
  struct RequestHandle *handle = cls;

  //For now, independent of path return all options
  resp = GNUNET_REST_create_json_response (NULL);
  MHD_add_response_header (resp,
                           "Access-Control-Allow-Methods",
                           allow_methods);
  handle->proc (handle->proc_cls, resp, MHD_HTTP_OK);
  cleanup_handle (handle);
  return;
}

/**
 * Handle rest request
 *
 * @param handle the request handle
 */
static void
init_cont (struct RequestHandle *handle)
{
  static const struct GNUNET_REST_RestConnectionHandler handlers[] = {
    {MHD_HTTP_METHOD_GET, GNUNET_REST_API_NS_IDENTITY, &ego_info_response},
    {MHD_HTTP_METHOD_POST, GNUNET_REST_API_NS_IDENTITY, &ego_create_cont},
    {MHD_HTTP_METHOD_PUT, GNUNET_REST_API_NS_IDENTITY, &ego_edit_cont},
    {MHD_HTTP_METHOD_DELETE, GNUNET_REST_API_NS_IDENTITY, &ego_delete_cont},
    {MHD_HTTP_METHOD_OPTIONS, GNUNET_REST_API_NS_IDENTITY, &options_cont},
    GNUNET_REST_HANDLER_END
  };

  if (GNUNET_NO == GNUNET_REST_handle_request (handle->conndata_handle, handlers, handle))
  {
    handle->emsg = GNUNET_strdup ("Request unsupported");
    GNUNET_SCHEDULER_add_now (&do_error, handle);
  }
}

/**
 * If listing is enabled, prints information about the egos.
 *
 * This function is initially called for all egos and then again
 * whenever a ego's identifier changes or if it is deleted.  At the
 * end of the initial pass over all egos, the function is once called
 * with 'NULL' for 'ego'. That does NOT mean that the callback won't
 * be invoked in the future or that there was an error.
 *
 * When used with 'GNUNET_IDENTITY_create' or 'GNUNET_IDENTITY_get',
 * this function is only called ONCE, and 'NULL' being passed in
 * 'ego' does indicate an error (i.e. name is taken or no default
 * value is known).  If 'ego' is non-NULL and if '*ctx'
 * is set in those callbacks, the value WILL be passed to a subsequent
 * call to the identity callback of 'GNUNET_IDENTITY_connect' (if
 * that one was not NULL).
 *
 * When an identity is renamed, this function is called with the
 * (known) ego but the NEW identifier.
 *
 * When an identity is deleted, this function is called with the
 * (known) ego and "NULL" for the 'identifier'.  In this case,
 * the 'ego' is henceforth invalid (and the 'ctx' should also be
 * cleaned up).
 *
 * @param cls closure
 * @param ego ego handle
 * @param ctx context for application to store data for this ego
 *                 (during the lifetime of this process, initially NULL)
 * @param identifier identifier assigned by the user for this ego,
 *                   NULL if the user just deleted the ego and it
 *                   must thus no longer be used
 */
static void
list_ego (void *cls,
          struct GNUNET_IDENTITY_Ego *ego,
          void **ctx,
          const char *identifier)
{
  struct RequestHandle *handle = cls;
  struct EgoEntry *ego_entry;
  struct GNUNET_CRYPTO_EcdsaPublicKey pk;

  if ((NULL == ego) && (ID_REST_STATE_INIT == handle->state))
  {
    handle->state = ID_REST_STATE_POST_INIT;
    init_cont (handle);
    return;
  }
  if (ID_REST_STATE_INIT == handle->state) {
    ego_entry = GNUNET_new (struct EgoEntry);
    GNUNET_IDENTITY_ego_get_public_key (ego, &pk);
    ego_entry->keystring =
      GNUNET_CRYPTO_ecdsa_public_key_to_string (&pk);
    ego_entry->ego = ego;
    GNUNET_asprintf (&ego_entry->identifier, "%s", identifier);
    GNUNET_CONTAINER_DLL_insert_tail(handle->ego_head,handle->ego_tail, ego_entry);
  }

}

/**
 * Function processing the REST call
 *
 * @param method HTTP method
 * @param url URL of the HTTP request
 * @param data body of the HTTP request (optional)
 * @param data_size length of the body
 * @param proc callback function for the result
 * @param proc_cls closure for callback function
 * @return GNUNET_OK if request accepted
 */
static void
rest_identity_process_request(struct RestConnectionDataHandle *conndata_handle,
                              GNUNET_REST_ResultProcessor proc,
                              void *proc_cls)
{
  struct RequestHandle *handle = GNUNET_new (struct RequestHandle);



  handle->timeout = GNUNET_TIME_UNIT_FOREVER_REL;

  handle->proc_cls = proc_cls;
  handle->proc = proc;
  handle->state = ID_REST_STATE_INIT;
  handle->conndata_handle = conndata_handle;
  handle->data = conndata_handle->data;
  handle->data_size = conndata_handle->data_size;
  handle->method = conndata_handle->method;
  GNUNET_asprintf (&handle->url, "%s", conndata_handle->url);
  if (handle->url[strlen (handle->url)-1] == '/')
    handle->url[strlen (handle->url)-1] = '\0';
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Connecting...\n");
  handle->identity_handle = GNUNET_IDENTITY_connect (cfg,
                                                     &list_ego,
                                                     handle);
  handle->timeout_task =
    GNUNET_SCHEDULER_add_delayed (handle->timeout,
                                  &do_error,
                                  handle);


  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Connected\n");
}

/**
 * Entry point for the plugin.
 *
 * @param cls Config info
 * @return NULL on error, otherwise the plugin context
 */
void *
libgnunet_plugin_rest_identity_init (void *cls)
{
  static struct Plugin plugin;
  struct GNUNET_REST_Plugin *api;

  cfg = cls;
  if (NULL != plugin.cfg)
    return NULL;                /* can only initialize once! */
  memset (&plugin, 0, sizeof (struct Plugin));
  plugin.cfg = cfg;
  api = GNUNET_new (struct GNUNET_REST_Plugin);
  api->cls = &plugin;
  api->name = GNUNET_REST_API_NS_IDENTITY;
  api->process_request = &rest_identity_process_request;
  GNUNET_asprintf (&allow_methods,
                   "%s, %s, %s, %s, %s",
                   MHD_HTTP_METHOD_GET,
                   MHD_HTTP_METHOD_POST,
                   MHD_HTTP_METHOD_PUT,
                   MHD_HTTP_METHOD_DELETE,
                   MHD_HTTP_METHOD_OPTIONS);

  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              _("Identity REST API initialized\n"));
  return api;
}


/**
 * Exit point from the plugin.
 *
 * @param cls the plugin context (as returned by "init")
 * @return always NULL
 */
void *
libgnunet_plugin_rest_identity_done (void *cls)
{
  struct GNUNET_REST_Plugin *api = cls;
  struct Plugin *plugin = api->cls;

  plugin->cfg = NULL;
  GNUNET_free_non_null (allow_methods);
  GNUNET_free (api);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Identity REST plugin is finished\n");
  return NULL;
}

/* end of plugin_rest_gns.c */

/*
   This file is part of GNUnet.
   Copyright (C) 2012-2015 Christian Grothoff (and other contributing authors)

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
 * @author Martin Schanzenbach
 * @file identity/plugin_rest_identity.c
 * @brief GNUnet Namestore REST plugin
 *
 */

#include "platform.h"
#include "gnunet_rest_plugin.h"
#include "gnunet_identity_service.h"
#include "microhttpd.h"
#include <jansson.h>

#define API_NAMESPACE "/identity"

#define EGO_NAMESPACE "/identity/egos"

#define ID_REST_STATE_INIT 0

#define ID_REST_STATE_POST_INIT 1

#define URL_PARAM_SUBSYS "service"

#define JSON_API_TYPE_EGO "ego"

#define JSON_API_TYPE_DATA "data"

/**
 * @brief struct returned by the initialization function of the plugin
 */
struct Plugin
{
  const struct GNUNET_CONFIGURATION_Handle *cfg;
};

const struct GNUNET_CONFIGURATION_Handle *cfg;

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
   * Ego Pkey
   */
  struct GNUNET_CRYPTO_EcdsaPublicKey pk;

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
   * The root of the received JSON or NULL
   */
  json_t *json_root;

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

};

/**
 * Cleanup lookup handle
 * @praram handle Handle to clean up
 */
void
cleanup_handle (struct RequestHandle *handle)
{
  struct EgoEntry *ego_entry;
  struct EgoEntry *ego_tmp;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Cleaning up\n");
  if (NULL != handle->json_root)
    json_decref (handle->json_root);
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
  for (ego_entry = handle->ego_head;
       NULL != ego_entry;)
  {
    ego_tmp = ego_entry;
    ego_entry = ego_entry->next;
    GNUNET_free (ego_tmp->identifier);
    GNUNET_free (ego_tmp);
  }
  GNUNET_free (handle);
}


/**
 * Task run on shutdown.  Cleans up everything.
 *
 * @param cls unused
 * @param tc scheduler context
 */
static void
do_error (void *cls,
          const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct RequestHandle *handle = cls;
  handle->proc (handle->proc_cls, NULL, 0, GNUNET_SYSERR);
  cleanup_handle (handle);
}

void
get_ego_for_subsys (void *cls,
                    struct GNUNET_IDENTITY_Ego *ego,
                    void **ctx,
                    const char *name)
{
  struct RequestHandle *handle = cls;
  struct EgoEntry *ego_entry;
  char *result_str;
  char *keystring;
  json_t *ego_json;
  json_t *root_json;

  root_json = json_object ();

  //Return all egos
  for (ego_entry = handle->ego_head;
       NULL != ego_entry;
       ego_entry = ego_entry->next)
  {
    if ( (NULL != name) && (0 != strcmp (name, ego_entry->identifier)) )
      continue;
    if (NULL == name)
      continue;
    ego_json = json_object ();
    keystring = GNUNET_CRYPTO_ecdsa_public_key_to_string (&ego_entry->pk);
    json_object_set_new (ego_json, "id", json_string (ego_entry->identifier));
    json_object_set_new (ego_json, "type", json_string (JSON_API_TYPE_EGO));
    json_object_set_new (ego_json, "key", json_string (keystring));
    GNUNET_free (keystring);
    break;
  }
  if (NULL == ego_json)
  {
    json_decref (root_json);
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }
  json_object_set (root_json, JSON_API_TYPE_DATA, ego_json);
  result_str = json_dumps (root_json, JSON_COMPACT);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Result %s\n", result_str);
  json_decref (ego_json);
  json_decref (root_json);
  handle->proc (handle->proc_cls, result_str, strlen (result_str), GNUNET_OK);
  GNUNET_free (result_str);
  cleanup_handle (handle);
}

int
check_namespace (const char *url, const char *ns)
{
  if (0 != strncmp (EGO_NAMESPACE, url, strlen (EGO_NAMESPACE)))
  {
    return GNUNET_NO;
  }

  if ((strlen (EGO_NAMESPACE) < strlen (url)) &&
       (url[strlen (EGO_NAMESPACE)] != '/'))
  {
    return GNUNET_NO;
  }
  return GNUNET_YES;


}

void
ego_info_response (struct RequestHandle *handle)
{
  const char *egoname;
  char *keystring;
  char *result_str;
  char *subsys_val;
  struct EgoEntry *ego_entry;
  struct GNUNET_HashCode key;
  json_t *ego_arr;
  json_t *ego_json;
  json_t *root_json;

  if (GNUNET_NO == check_namespace (handle->url, EGO_NAMESPACE))
  {
    handle->proc (handle->proc_cls, NULL, 0, GNUNET_SYSERR);
    cleanup_handle (handle);
    GNUNET_break (0);
    return;
  }
  if ( (strlen (EGO_NAMESPACE) == strlen (handle->url) )) {
    GNUNET_CRYPTO_hash (URL_PARAM_SUBSYS, strlen (URL_PARAM_SUBSYS), &key);
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
  ego_arr = json_array ();
  root_json = json_object ();
  egoname = &handle->url[strlen (EGO_NAMESPACE)+1];

  if (strlen (EGO_NAMESPACE) == strlen (handle->url))
  {
    egoname = NULL;
  }

  //Return all egos
  for (ego_entry = handle->ego_head;
       NULL != ego_entry;
       ego_entry = ego_entry->next)
  {
    if ( (NULL != egoname) && (0 != strcmp (egoname, ego_entry->identifier)) )
      continue;
    ego_json = json_object ();
    keystring = GNUNET_CRYPTO_ecdsa_public_key_to_string (&ego_entry->pk);
    json_object_set_new (ego_json, "id", json_string (ego_entry->identifier));
    json_object_set_new (ego_json, "key", json_string (keystring));
    json_object_set_new (ego_json, "type", json_string (JSON_API_TYPE_EGO));
    GNUNET_free (keystring);
    if (NULL == egoname)
    {
      GNUNET_break (0);
      json_array_append (ego_arr, ego_json);
      json_decref (ego_json);
    }
    else
      break;
  }
  GNUNET_break (0);
  if (NULL == egoname)
    json_object_set (root_json, JSON_API_TYPE_DATA, ego_arr);
  else
    json_object_set (root_json, JSON_API_TYPE_DATA, ego_json);

  result_str = json_dumps (root_json, JSON_COMPACT);
  json_decref (ego_arr);
  if (NULL != egoname)
    json_decref (ego_json);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Result %s\n", result_str);
  handle->proc (handle->proc_cls, result_str, strlen (result_str), GNUNET_OK);
  GNUNET_free (result_str);
  cleanup_handle (handle);

}

static void
do_finished (void *cls, const char *emsg)
{
  struct RequestHandle *handle = cls;

  handle->op = NULL;
  if (NULL != emsg)
  {
    GNUNET_SCHEDULER_add_now (&do_error, handle);
  }
  handle->proc (handle->proc_cls, NULL, 0, GNUNET_OK);
  cleanup_handle (handle);
}

static void
ego_create_cont (struct RequestHandle *handle)
{
  const char* egoname;
  char term_data[handle->data_size+1];
  json_t *egoname_json;
  json_t *root_json;
  json_error_t error;
  struct EgoEntry *ego_entry;

  if (strlen (API_NAMESPACE) != strlen (handle->url))
  {
    GNUNET_break(0);
    handle->proc (handle->proc_cls, NULL, 0, GNUNET_SYSERR);
    cleanup_handle (handle);
    return;
  }
  if (0 >= handle->data_size)
  {
    GNUNET_break(0);
    handle->proc (handle->proc_cls, NULL, 0, GNUNET_SYSERR);
    cleanup_handle (handle);
    return;
  }

  term_data[handle->data_size] = '\0';
  memcpy (term_data, handle->data, handle->data_size);
  root_json = json_loads (term_data, 0, &error);

  if ((NULL == root_json) || !json_is_object (root_json))
  {
    GNUNET_break(0);
    handle->proc (handle->proc_cls, NULL, 0, GNUNET_SYSERR);
    cleanup_handle (handle);
    return;
  }
  egoname_json = json_object_get (root_json, "ego");
  if (!json_is_string (egoname_json))
  {
    GNUNET_break(0);
    handle->proc (handle->proc_cls, NULL, 0, GNUNET_SYSERR);
    cleanup_handle (handle);
    return;
  }
  egoname = json_string_value (egoname_json);
  for (ego_entry = handle->ego_head;
       NULL != ego_entry;
       ego_entry = ego_entry->next)
  {
    if (0 == strcasecmp (egoname, ego_entry->identifier))
    {
      json_decref (egoname_json);
      json_decref (root_json);
      handle->proc (handle->proc_cls, NULL, 0, GNUNET_SYSERR);
      cleanup_handle (handle);
      return;
    }
  }
  GNUNET_asprintf (&handle->name, "%s", egoname);
  json_decref (egoname_json);
  json_decref (root_json);
  handle->op = GNUNET_IDENTITY_create (handle->identity_handle,
                                       handle->name,
                                       &do_finished,
                                       handle);
}

void 
subsys_set_cont (struct RequestHandle *handle)
{
  const char *egoname;
  const char *subsys;
  char term_data[handle->data_size+1];
  struct EgoEntry *ego_entry;
  int ego_exists = GNUNET_NO;
  json_t *root_json;
  json_t *subsys_json;
  json_error_t error;

  if (strlen (API_NAMESPACE) >= strlen (handle->url))
  {
    GNUNET_break(0);
    handle->proc (handle->proc_cls, NULL, 0, GNUNET_SYSERR);
    cleanup_handle (handle);
    return;
  }

  egoname = &handle->url[strlen(API_NAMESPACE)+1];
  for (ego_entry = handle->ego_head;
       NULL != ego_entry;
       ego_entry = ego_entry->next)
  {
    if (0 == strcasecmp (egoname, ego_entry->identifier))
    {
      ego_exists = GNUNET_YES;
      break;
    }
  }
  if (GNUNET_NO == ego_exists)
  {
    GNUNET_break(0);
    handle->proc (handle->proc_cls, NULL, 0, GNUNET_SYSERR);
    cleanup_handle (handle);
    return;
  }

  if (0 >= handle->data_size)
  {
    GNUNET_break(0);
    handle->proc (handle->proc_cls, NULL, 0, GNUNET_SYSERR);
    cleanup_handle (handle);
    return;
  }

  term_data[handle->data_size] = '\0';
  memcpy (term_data, handle->data, handle->data_size);
  root_json = json_loads (term_data, 0, &error);

  if ((NULL == root_json) || !json_is_object (root_json))
  {
    GNUNET_break(0);
    handle->proc (handle->proc_cls, NULL, 0, GNUNET_SYSERR);
    cleanup_handle (handle);
    return;
  }
  subsys_json = json_object_get (root_json, "subsystem");
  if (!json_is_string (subsys_json))
  {
    GNUNET_break(0);
    handle->proc (handle->proc_cls, NULL, 0, GNUNET_SYSERR);
    cleanup_handle (handle);
    return;
  }
  subsys = json_string_value (subsys_json);
  GNUNET_asprintf (&handle->subsys, "%s", subsys);
  json_decref (subsys_json);
  json_decref (root_json);
  handle->op = GNUNET_IDENTITY_set (handle->identity_handle,
                                    handle->subsys,
                                    ego_entry->ego,
                                    &do_finished,
                                    handle);
}

void 
ego_delete_cont (struct RequestHandle *handle)
{
  const char *egoname;
  struct EgoEntry *ego_entry;
  int ego_exists = GNUNET_NO;

  if (strlen (API_NAMESPACE) >= strlen (handle->url))
  {
    GNUNET_break(0);
    handle->proc (handle->proc_cls, NULL, 0, GNUNET_SYSERR);
    cleanup_handle (handle);
    return;
  }

  egoname = &handle->url[strlen(API_NAMESPACE)+1];
  for (ego_entry = handle->ego_head;
       NULL != ego_entry;
       ego_entry = ego_entry->next)
  {
    if (0 == strcasecmp (egoname, ego_entry->identifier))
    {
      ego_exists = GNUNET_YES;
      break;
    }
  }
  if (GNUNET_NO == ego_exists)
  {
    GNUNET_break(0);
    handle->proc (handle->proc_cls, NULL, 0, GNUNET_SYSERR);
    cleanup_handle (handle);
    return;
  }
  handle->op = GNUNET_IDENTITY_delete (handle->identity_handle,
                                       egoname,
                                       &do_finished,
                                       handle);

}

void
init_cont (struct RequestHandle *handle)
{
  if (0 == strcasecmp (handle->method, MHD_HTTP_METHOD_GET))
    ego_info_response (handle);
  else if (0 == strcasecmp (handle->method, MHD_HTTP_METHOD_POST))
    ego_create_cont (handle);
  else if (0 == strcasecmp (handle->method, MHD_HTTP_METHOD_PUT))
    subsys_set_cont (handle);
  else if (0 == strcasecmp (handle->method, MHD_HTTP_METHOD_DELETE))
    ego_delete_cont (handle);
  else
    GNUNET_SCHEDULER_add_now (&do_error, handle);
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

  if ((NULL == ego) && (ID_REST_STATE_INIT == handle->state))
  {
    handle->state = ID_REST_STATE_POST_INIT;
    init_cont (handle);
    return;
  }
  if (ID_REST_STATE_INIT == handle->state) {
    ego_entry = GNUNET_new (struct EgoEntry);
    GNUNET_IDENTITY_ego_get_public_key (ego, &(ego_entry->pk));
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
void
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
  cfg = cls;
  struct GNUNET_REST_Plugin *api;

  if (NULL != plugin.cfg)
    return NULL;                /* can only initialize once! */
  memset (&plugin, 0, sizeof (struct Plugin));
  plugin.cfg = cfg;
  api = GNUNET_new (struct GNUNET_REST_Plugin);
  api->cls = &plugin;
  api->name = API_NAMESPACE;
  api->process_request = &rest_identity_process_request;
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
  GNUNET_free (api);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Identity REST plugin is finished\n");
  return NULL;
}

/* end of plugin_rest_gns.c */

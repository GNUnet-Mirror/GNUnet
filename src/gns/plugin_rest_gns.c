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
 * @author Philippe Buschmann
 * @file gns/plugin_rest_gns.c
 * @brief GNUnet GNS REST plugin
 *
 */

#include "platform.h"
#include "gnunet_rest_plugin.h"
#include <gnunet_dnsparser_lib.h>
#include <gnunet_identity_service.h>
#include <gnunet_gnsrecord_lib.h>
#include <gnunet_namestore_service.h>
#include <gnunet_gns_service.h>
#include <gnunet_rest_lib.h>
#include <gnunet_jsonapi_lib.h>
#include <gnunet_jsonapi_util.h>
#include <jansson.h>

#define GNUNET_REST_API_NS_GNS "/gns"

#define GNUNET_REST_JSONAPI_GNS_RECORD_TYPE "record_type"

#define GNUNET_REST_PARAMETER_GNS_NAME "name"

#define GNUNET_REST_JSONAPI_GNS_TYPEINFO "gns_name"

#define GNUNET_REST_JSONAPI_GNS_RECORD "records"

#define GNUNET_REST_JSONAPI_GNS_EGO "ego"

#define GNUNET_REST_JSONAPI_GNS_PKEY "pkey"

#define GNUNET_REST_JSONAPI_GNS_OPTIONS "options"

/**
 * @brief struct returned by the initialization function of the plugin
 */
struct Plugin
{
  const struct GNUNET_CONFIGURATION_Handle *cfg;
};

const struct GNUNET_CONFIGURATION_Handle *cfg;

struct LookupHandle
{
  /**
   * Handle to GNS service.
   */
  struct GNUNET_GNS_Handle *gns;

  /**
   * Desired timeout for the lookup (default is no timeout).
   */
  struct GNUNET_TIME_Relative timeout;

  /**
   * Handle to lookup request
   */
  struct GNUNET_GNS_LookupRequest *lookup_request;

  /**
   * Handle to rest request
   */
  struct GNUNET_REST_RequestHandle *rest_handle;

  /**
   * Lookup an ego with the identity service.
   */
  struct GNUNET_IDENTITY_EgoLookup *el;

  /**
   * Handle for identity service.
   */
  struct GNUNET_IDENTITY_Handle *identity;

  /**
   * Active operation on identity service.
   */
  struct GNUNET_IDENTITY_Operation *id_op;

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
   * The ego to use
   * In string representation from JSON
   */
  const char *ego_str;

  /**
   * The Pkey to use
   * In string representation from JSON
   */
  const char *pkey_str;

  /**
   * The record type
   */
  int type;

  /**
   * The public key of to use for lookup
   */
  struct GNUNET_CRYPTO_EcdsaPublicKey pkey;

  /**
   * The public key to use for lookup
   */
  struct GNUNET_CRYPTO_EcdsaPublicKey pkeym;

  /**
   * The resolver options
   */
  enum GNUNET_GNS_LocalOptions options;

  /**
   * the shorten key
   */
  struct GNUNET_CRYPTO_EcdsaPrivateKey shorten_key;

  /**
   * HTTP response code
   */
  int response_code;

  /**
   * HTTP response code
   */
  char* emsg;

};


/**
 * Cleanup lookup handle.
 *
 * @param handle Handle to clean up
 */
static void
cleanup_handle (struct LookupHandle *handle)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Cleaning up\n");
  if (NULL != handle->json_root)
    json_decref (handle->json_root);

  if (NULL != handle->name)
    GNUNET_free (handle->name);
  if (NULL != handle->emsg)
      GNUNET_free (handle->emsg);
  if (NULL != handle->el)
  {
    GNUNET_IDENTITY_ego_lookup_cancel (handle->el);
    handle->el = NULL;
  }
  if (NULL != handle->id_op)
  {
    GNUNET_IDENTITY_cancel (handle->id_op);
    handle->id_op = NULL;
  }
  if (NULL != handle->lookup_request)
  {
    GNUNET_GNS_lookup_cancel (handle->lookup_request);
    handle->lookup_request = NULL;
  }
  if (NULL != handle->identity)
  {
    GNUNET_IDENTITY_disconnect (handle->identity);
    handle->identity = NULL;
  }
  if (NULL != handle->gns)
  {
    GNUNET_GNS_disconnect (handle->gns);
    handle->gns = NULL;
  }

  if (NULL != handle->timeout_task)
  {
    GNUNET_SCHEDULER_cancel (handle->timeout_task);
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
do_error (void *cls)
{
  struct LookupHandle *handle = cls;
  struct MHD_Response *resp;
  char *json_error;

  if (NULL == handle->emsg)
    handle->emsg = GNUNET_strdup("Unknown Error");

  GNUNET_asprintf (&json_error, "{\"error\": \"%s\"}", handle->emsg);
  handle->response_code = MHD_HTTP_OK;

  resp = GNUNET_REST_create_response (json_error);
  handle->proc (handle->proc_cls, resp, handle->response_code);
  cleanup_handle (handle);
  GNUNET_free(json_error);
}


/**
 * Create json representation of a GNSRECORD
 *
 * @param rd the GNSRECORD_Data
 */
static json_t *
gnsrecord_to_json (const struct GNUNET_GNSRECORD_Data *rd)
{
  const char *typename;
  char *string_val;
  const char *exp_str;
  json_t *record_obj;

  typename = GNUNET_GNSRECORD_number_to_typename (rd->record_type);
  string_val = GNUNET_GNSRECORD_value_to_string (rd->record_type,
                                                 rd->data,
                                                 rd->data_size);

  if (NULL == string_val)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Record of type %d malformed, skipping\n",
                (int) rd->record_type);
    return NULL;
  }
  record_obj = json_object ();
  json_object_set_new (record_obj, "type", json_string (typename));
  json_object_set_new (record_obj, "value", json_string (string_val));
  GNUNET_free (string_val);

  if (GNUNET_GNSRECORD_RF_RELATIVE_EXPIRATION & rd->flags)
  {
    struct GNUNET_TIME_Relative time_rel;
    time_rel.rel_value_us = rd->expiration_time;
    exp_str = GNUNET_STRINGS_relative_time_to_string (time_rel, 1);
  }
  else
  {
    struct GNUNET_TIME_Absolute time_abs;
    time_abs.abs_value_us = rd->expiration_time;
    exp_str = GNUNET_STRINGS_absolute_time_to_string (time_abs);
  }
  json_object_set_new (record_obj, "expiration_time", json_string (exp_str));

  json_object_set_new (record_obj, "expired",
                       json_boolean (GNUNET_YES == GNUNET_GNSRECORD_is_expired (rd)));
  return record_obj;
}

/**
 * Function called with the result of a GNS lookup.
 *
 * @param cls the 'const char *' name that was resolved
 * @param rd_count number of records returned
 * @param rd array of @a rd_count records with the results
 */
static void
process_lookup_result (void *cls, uint32_t rd_count,
                       const struct GNUNET_GNSRECORD_Data *rd)
{
  struct LookupHandle *handle = cls;
  struct MHD_Response *resp;
  uint32_t i;
  char *result;
  json_t *result_array;
  json_t *record_obj;

  result_array = json_array();
  handle->lookup_request = NULL;
  for (i=0; i<rd_count; i++)
  {
    if ( (rd[i].record_type != handle->type) &&
         (GNUNET_GNSRECORD_TYPE_ANY != handle->type) )
      continue;
    record_obj = gnsrecord_to_json (&(rd[i]));
    json_array_append (result_array, record_obj);
    json_decref (record_obj);
  }
  result = json_dumps(result_array, 0);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Result %s\n", result);
  resp = GNUNET_REST_create_response (result);
  handle->proc (handle->proc_cls, resp, MHD_HTTP_OK);
  GNUNET_free (result);
  json_decref (result_array);
  cleanup_handle (handle);
}


/**
 * Perform the actual resolution, starting with the zone
 * identified by the given public key and the shorten zone.
 *
 * @param pkey public key to use for the zone, can be NULL
 */
static void
lookup_with_public_key (struct LookupHandle *handle)
{
  if (UINT32_MAX == handle->type)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _("Invalid typename specified, assuming `ANY'\n"));
    handle->type = GNUNET_GNSRECORD_TYPE_ANY;
  }
  if (NULL != handle->name)
  {
    handle->lookup_request = GNUNET_GNS_lookup (handle->gns,
                                                handle->name,
                                                &handle->pkey,
                                                handle->type,
                                                handle->options,
                                                &process_lookup_result,
                                                handle);
  }
  else
  {
    handle->emsg = GNUNET_strdup("Parameter name is missing");
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }
}


/**
 * Method called to with the ego we are to use for the lookup,
 * when the ego is determined by a name.
 *
 * @param cls closure (NULL, unused)
 * @param ego ego handle, NULL if not found
 */
static void
identity_zone_cb (void *cls,
                  const struct GNUNET_IDENTITY_Ego *ego)
{
  struct LookupHandle *handle = cls;

  handle->el = NULL;
  if (NULL == ego)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _("Ego for not found, cannot perform lookup.\n"));
    handle->emsg = GNUNET_strdup ("Ego for not found, cannot perform lookup.");
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }
  else
  {
    GNUNET_IDENTITY_ego_get_public_key (ego, &handle->pkey);
    lookup_with_public_key (handle);
  }
  json_decref(handle->json_root);
}


/**
 * Method called to with the ego we are to use for the lookup,
 * when the ego is the one for the default master zone.
 *
 * @param cls closure (NULL, unused)
 * @param ego ego handle, NULL if not found
 * @param ctx context for application to store data for this ego
 *                 (during the lifetime of this process, initially NULL)
 * @param name name assigned by the user for this ego,
 *                   NULL if the user just deleted the ego and it
 *                   must thus no longer be used
 */
static void
identity_master_cb (void *cls,
                    struct GNUNET_IDENTITY_Ego *ego,
                    void **ctx,
                    const char *name)
{
  const char *dot;
  struct LookupHandle *handle = cls;

  handle->id_op = NULL;
  if (NULL == ego)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _("Ego for `gns-master' not found, cannot perform lookup.  Did you run gnunet-gns-import.sh?\n"));
    handle->emsg = GNUNET_strdup("Ego for `gns-master' not found, cannot perform lookup.  Did you run gnunet-gns-import.sh?");
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }
  GNUNET_IDENTITY_ego_get_public_key (ego,
                                      &handle->pkey);
  /* main name is our own master zone, do no look for that in the DHT */
  handle->options = GNUNET_GNS_LO_LOCAL_MASTER;
  /* if the name is of the form 'label.gnu', never go to the DHT */
  dot = NULL;
  if (NULL != handle->name)
    dot = strchr (handle->name, '.');
  if ( (NULL != dot) &&
       (0 == strcasecmp (dot, ".gnu")) )
    handle->options = GNUNET_GNS_LO_NO_DHT;
  lookup_with_public_key (handle);
}

/**
 * Handle get request
 *
 * @param handle the lookup handle
 */
static void
get_gns_cont (struct GNUNET_REST_RequestHandle *conndata_handle,
              const char* url,
              void *cls)
{
  struct LookupHandle *handle = cls;
  struct GNUNET_HashCode key;
  long int enum_test;
  char *temp_val;

  //check for /gns otherwise 404
  if (strlen (GNUNET_REST_API_NS_GNS) > strlen (url))
  {
    handle->emsg = GNUNET_strdup("Wrong URL");
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }

  //connect to gns
  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "Connecting...\n");
  handle->gns = GNUNET_GNS_connect (cfg);
  handle->identity = GNUNET_IDENTITY_connect (cfg, NULL, NULL);
  handle->timeout_task = GNUNET_SCHEDULER_add_delayed (handle->timeout,
						       &do_error, handle);
  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "Connected\n");
  if (NULL == handle->gns)
  {
    GNUNET_log(GNUNET_ERROR_TYPE_ERROR, "Connecting to GNS failed\n");
    handle->emsg = GNUNET_strdup("Connecting to GNS failed");
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }

  //check parameter name -> BAD_REQUEST
  GNUNET_CRYPTO_hash (GNUNET_REST_PARAMETER_GNS_NAME,
		      strlen (GNUNET_REST_PARAMETER_GNS_NAME),
		      &key);
  if ( GNUNET_NO
      == GNUNET_CONTAINER_multihashmap_contains (conndata_handle->url_param_map,
						 &key))
  {
    handle->emsg = GNUNET_strdup("Parameter name is missing");
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }
  handle->name = GNUNET_strdup(GNUNET_CONTAINER_multihashmap_get (conndata_handle->url_param_map,
						    &key));

  //check parameter record_type, optional
  GNUNET_CRYPTO_hash (GNUNET_REST_JSONAPI_GNS_RECORD_TYPE,
                      strlen (GNUNET_REST_JSONAPI_GNS_RECORD_TYPE),
                      &key);
  if ( GNUNET_YES ==
       GNUNET_CONTAINER_multihashmap_contains (conndata_handle->url_param_map,
                                               &key) )
  {
    handle->type = GNUNET_GNSRECORD_typename_to_number(
	GNUNET_CONTAINER_multihashmap_get (conndata_handle->url_param_map,
                                          &key));
  }
  else
  {
    handle->type = GNUNET_GNSRECORD_TYPE_ANY;
  }

  //check parameter options, optional
  GNUNET_CRYPTO_hash (GNUNET_REST_JSONAPI_GNS_OPTIONS,
		      strlen (GNUNET_REST_JSONAPI_GNS_OPTIONS),
		      &key);
  handle->options = GNUNET_GNS_LO_DEFAULT;
  if ( GNUNET_YES
      == GNUNET_CONTAINER_multihashmap_contains (conndata_handle->url_param_map,
						 &key))
  {
    temp_val = GNUNET_CONTAINER_multihashmap_get (conndata_handle->url_param_map, &key);
    if (1 < strlen(temp_val))
    {
      handle->options = GNUNET_GNS_LO_DEFAULT;
    }
    else
    {
      //atoi because no valid conversion is default local option
      enum_test = atoi(temp_val);
      if (2 < enum_test)
	handle->options = GNUNET_GNS_LO_DEFAULT;
      else
	handle->options = enum_test;
    }
  }
  else
    handle->options = GNUNET_GNS_LO_DEFAULT;

  //check parameter pkey, shortcut to lookup
  GNUNET_CRYPTO_hash (GNUNET_REST_JSONAPI_GNS_PKEY,
		      strlen (GNUNET_REST_JSONAPI_GNS_PKEY),
		      &key);
  if ( GNUNET_YES
      == GNUNET_CONTAINER_multihashmap_contains (conndata_handle->url_param_map,
						 &key))
  {
    handle->pkey_str = GNUNET_CONTAINER_multihashmap_get (conndata_handle->url_param_map,
							  &key);
    GNUNET_assert(NULL != handle->pkey_str);
    if (GNUNET_OK
	!= GNUNET_CRYPTO_ecdsa_public_key_from_string (
	    handle->pkey_str, strlen (handle->pkey_str), &(handle->pkey)))
    {
      handle->emsg = GNUNET_strdup("Parameter pkey has a wrong format");
      GNUNET_SCHEDULER_add_now (&do_error, handle);
      return;
    }
    lookup_with_public_key (handle);
    return;
  }

  //check parameter ego, lookup public key of ego
  GNUNET_CRYPTO_hash (GNUNET_REST_JSONAPI_GNS_EGO,
                      strlen (GNUNET_REST_JSONAPI_GNS_EGO),
                      &key);
  if ( GNUNET_YES ==
       GNUNET_CONTAINER_multihashmap_contains (conndata_handle->url_param_map,
                                               &key) )
  {
    handle->ego_str = GNUNET_CONTAINER_multihashmap_get (conndata_handle->url_param_map,
                                                         &key);
    handle->el = GNUNET_IDENTITY_ego_lookup (cfg,
                                             handle->ego_str,
                                             &identity_zone_cb,
                                             handle);
    return;
  }

  //if name ends with .zkey then get public key
  if ( (NULL != handle->name) &&
       (strlen (handle->name) > 4) &&
       (0 == strcmp (".zkey",
                     &handle->name[strlen (handle->name) - 4])) )
  {
    GNUNET_CRYPTO_ecdsa_key_get_public( GNUNET_CRYPTO_ecdsa_key_get_anonymous (),
					&(handle->pkey));
    lookup_with_public_key (handle);
  }
  else //else use gns-master identity
  {
    handle->id_op = GNUNET_IDENTITY_get (handle->identity,
                                         "gns-master",
                                         &identity_master_cb,
                                         handle);
  }
}

/**
 * Handle rest request
 *
 * @param handle the lookup handle
 */
static void
options_cont (struct GNUNET_REST_RequestHandle *con_handle,
              const char* url,
              void *cls)
{
  struct MHD_Response *resp;
  struct LookupHandle *handle = cls;

  //For GNS, independent of path return all options
  resp = GNUNET_REST_create_response (NULL);
  MHD_add_response_header (resp,
                           "Access-Control-Allow-Methods",
                           MHD_HTTP_METHOD_GET);
  handle->proc (handle->proc_cls,
		resp,
		MHD_HTTP_OK);
  cleanup_handle (handle);
}


/**
 * Function processing the REST call
 *
 * @param method HTTP method
 * @param url URL of the HTTP request
 * @param data body of the HTTP request (optional)
 * @param data_size length of the body
 * @param proc callback function for the result
 * @param proc_cls closure for @a proc
 * @return #GNUNET_OK if request accepted
 */
static void
rest_gns_process_request (struct GNUNET_REST_RequestHandle *conndata_handle,
                          GNUNET_REST_ResultProcessor proc,
                          void *proc_cls)
{
  static const struct GNUNET_REST_RequestHandler handlers[] = {
    {MHD_HTTP_METHOD_GET, GNUNET_REST_API_NS_GNS, &get_gns_cont},
    {MHD_HTTP_METHOD_OPTIONS, GNUNET_REST_API_NS_GNS, &options_cont},
    GNUNET_REST_HANDLER_END
  };
  struct LookupHandle *handle = GNUNET_new (struct LookupHandle);
  struct GNUNET_REST_RequestHandlerError err;

  handle->timeout = GNUNET_TIME_UNIT_FOREVER_REL;
  handle->proc_cls = proc_cls;
  handle->proc = proc;
  handle->rest_handle = conndata_handle;

  if (GNUNET_NO == GNUNET_REST_handle_request (conndata_handle,
                                               handlers,
                                               &err,
                                               handle))
  {
    handle->response_code = err.error_code;
    GNUNET_SCHEDULER_add_now (&do_error, handle);
  }
}


/**
 * Entry point for the plugin.
 *
 * @param cls the "struct GNUNET_NAMESTORE_PluginEnvironment*"
 * @return NULL on error, otherwise the plugin context
 */
void *
libgnunet_plugin_rest_gns_init (void *cls)
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
  api->name = GNUNET_REST_API_NS_GNS;
  api->process_request = &rest_gns_process_request;
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              _("GNS REST API initialized\n"));
  return api;
}


/**
 * Exit point from the plugin.
 *
 * @param cls the plugin context (as returned by "init")
 * @return always NULL
 */
void *
libgnunet_plugin_rest_gns_done (void *cls)
{
  struct GNUNET_REST_Plugin *api = cls;
  struct Plugin *plugin = api->cls;

  plugin->cfg = NULL;
  GNUNET_free (api);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "GNS REST plugin is finished\n");
  return NULL;
}

/* end of plugin_rest_gns.c */

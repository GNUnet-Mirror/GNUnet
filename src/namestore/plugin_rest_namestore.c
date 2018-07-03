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
 * @file namestore/plugin_rest_namestore.c
 * @brief GNUnet Namestore REST plugin
 */

#include "platform.h"
#include "gnunet_rest_plugin.h"
#include "gnunet_gns_service.h"
#include "gnunet_namestore_service.h"
#include "gnunet_identity_service.h"
#include "gnunet_rest_lib.h"
#include "gnunet_json_lib.h"
#include "microhttpd.h"
#include <jansson.h>

#define GNUNET_REST_API_NS_NAMESTORE "/namestore"

#define GNUNET_REST_SUBSYSTEM_NAMESTORE "namestore"

#define GNUNET_REST_JSON_NAMESTORE_RECORD_TYPE "record_type"
#define GNUNET_REST_JSON_NAMESTORE_VALUE "value"
#define GNUNET_REST_JSON_NAMESTORE_EXPIRATION "expiration"
#define GNUNET_REST_JSON_NAMESTORE_EXPIRED "expired"

#define GNUNET_REST_NAMESTORE_RD_COUNT 1

//TODO define other variables

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

//TODO add specific structs

/**
 * The default namestore ego
 */
struct EgoEntry
{
  /**
   * Ego Identifier
   */
  const char *identifier;

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
  //TODO add specific entries

  /**
   * Records to store
   */
  struct GNUNET_GNSRECORD_Data *rd;

  /**
   * NAMESTORE Operation
   */
  struct GNUNET_NAMESTORE_QueueEntry *add_qe;

  /**
   * JSON data parser
   */
  struct GNUNET_REST_JSON_Data *json_data;

  /**
   * Response object
   */
  json_t *resp_object;

  /**
   * Handle to NAMESTORE
   */
  struct GNUNET_NAMESTORE_Handle *ns_handle;

  /**
   * Handle to NAMESTORE it
   */
  struct GNUNET_NAMESTORE_ZoneIterator *list_it;

  /**
   * Private key for the zone
   */
  struct GNUNET_CRYPTO_EcdsaPrivateKey zone_pkey;

  /**
   * IDENTITY Operation
   */
  struct EgoEntry *ego_entry;

  /**
   * IDENTITY Operation
   */
  struct GNUNET_IDENTITY_Operation *op;

  /**
   * Handle to Identity service.
   */
  struct GNUNET_IDENTITY_Handle *identity_handle;

  /**
   * Rest connection
   */
  struct GNUNET_REST_RequestHandle *rest_handle;
  
  /**
   * Desired timeout for the lookup (default is no timeout).
   */
  struct GNUNET_TIME_Relative timeout;

  /**
   * ID of a task associated with the resolution process.
   */
  struct GNUNET_SCHEDULER_Task *timeout_task;

  /**
   * The plugin result processor
   */
  GNUNET_REST_ResultProcessor proc;

  /**
   * The closure of the result processor
   */
  void *proc_cls;

  /**
   * The url
   */
  char *url;

  /**
   * Error response message
   */
  char *emsg;

  /**
   * Reponse code
   */
  int response_code;

};


//TODO add specific cleanup
/**
 * Cleanup lookup handle
 * @param handle Handle to clean up
 */
static void
cleanup_handle (struct RequestHandle *handle)
{
  size_t index;
  json_t *json_ego;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Cleaning up\n");
  if (NULL != handle->timeout_task)
  {
    GNUNET_SCHEDULER_cancel (handle->timeout_task);
    handle->timeout_task = NULL;
  }
  if (NULL != handle->url)
    GNUNET_free(handle->url);
  if (NULL != handle->emsg)
    GNUNET_free(handle->emsg);
  if (NULL != handle->rd)
  {
    if (NULL != handle->rd->data)
      GNUNET_free((void*)handle->rd->data);
    GNUNET_free(handle->rd);
  }
  if (NULL != handle->timeout_task)
    GNUNET_SCHEDULER_cancel(handle->timeout_task);
  if (NULL != handle->list_it)
    GNUNET_NAMESTORE_zone_iteration_stop(handle->list_it);
  if (NULL != handle->add_qe)
    GNUNET_NAMESTORE_cancel(handle->add_qe);
  if (NULL != handle->identity_handle)
    GNUNET_IDENTITY_disconnect(handle->identity_handle);
  if (NULL != handle->ns_handle)
  {
    GNUNET_NAMESTORE_disconnect(handle->ns_handle);
  }

  if (NULL != handle->ego_entry)
  {
    if (NULL != handle->ego_entry->keystring)
      GNUNET_free(handle->ego_entry->keystring);

    GNUNET_free(handle->ego_entry);
  }

  if(NULL != handle->resp_object)
  {
    json_array_foreach(handle->resp_object, index, json_ego )
    {
      json_decref (json_ego);
    }
    json_decref(handle->resp_object);
  }
  
  if (NULL != handle->json_data)
    GNUNET_REST_JSON_free(handle->json_data);

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

  if (NULL == handle->emsg)
    handle->emsg = GNUNET_strdup("Unknown Error");

  GNUNET_asprintf (&json_error, "{\"error\": \"%s\"}", handle->emsg);
  
  if (0 == handle->response_code)
    handle->response_code = MHD_HTTP_OK;

  resp = GNUNET_REST_create_response (json_error);
  handle->proc (handle->proc_cls, resp, handle->response_code);
  cleanup_handle (handle);
  GNUNET_free(json_error);
}

/**
 * Does internal server error when iteration failed.
 */
static void
namestore_iteration_error (void *cls)
{
  struct RequestHandle *handle = cls;
  struct MHD_Response *resp = GNUNET_REST_create_response (NULL);
  handle->response_code = MHD_HTTP_INTERNAL_SERVER_ERROR;
  handle->proc (handle->proc_cls, resp, handle->response_code);
  cleanup_handle (handle);
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
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Record of type %d malformed, skipping\n",
                (int) rd->record_type);
    return NULL;
  }
  record_obj = json_object();
  json_object_set_new (record_obj,
                       GNUNET_REST_JSON_NAMESTORE_RECORD_TYPE,
                       json_string (typename));
  json_object_set_new (record_obj,
                       GNUNET_REST_JSON_NAMESTORE_VALUE,
                       json_string (string_val));
  //GNUNET_free (string_val);

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
  json_object_set_new (record_obj,
		       GNUNET_REST_JSON_NAMESTORE_EXPIRATION,
		       json_string (exp_str));
  json_object_set_new (record_obj, "expired",
                       json_boolean (GNUNET_YES == GNUNET_GNSRECORD_is_expired (rd)));
  return record_obj;
}


static void
create_finished (void *cls, int32_t success, const char *emsg)
{
  struct RequestHandle *handle = cls;
  struct MHD_Response *resp;

  handle->add_qe = NULL;
  if (GNUNET_YES != success)
  {
    handle->emsg = GNUNET_strdup("Error storing records");
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }
  resp = GNUNET_REST_create_response (NULL);
  handle->proc (handle->proc_cls, resp, MHD_HTTP_NO_CONTENT);
  cleanup_handle(handle);
}

/**
 * Iteration over all results finished, build final
 * response.
 *
 * @param cls the `struct RequestHandle`
 */
static void
namestore_list_finished (void *cls)
{
  struct RequestHandle *handle = cls;
  char *result_str;
  struct MHD_Response *resp;

  handle->list_it = NULL;

  GNUNET_log(GNUNET_ERROR_TYPE_ERROR, "HEY\n");
  if (NULL == handle->resp_object)
  {
    GNUNET_log(GNUNET_ERROR_TYPE_ERROR, "OH\n");
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }

  result_str = json_dumps (handle->resp_object, 0);
  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "Result %s\n", result_str);
  resp = GNUNET_REST_create_response (result_str);
  handle->proc (handle->proc_cls, resp, MHD_HTTP_OK);
  GNUNET_free_non_null (result_str);
  cleanup_handle(handle);
}



/**
 * Create a response with requested records
 *
 * @param handle the RequestHandle
 */
static void
namestore_list_iteration (void *cls,
                         const struct GNUNET_CRYPTO_EcdsaPrivateKey *zone_key,
                         const char *rname,
                         unsigned int rd_len,
                         const struct GNUNET_GNSRECORD_Data *rd)
{
  struct RequestHandle *handle = cls;
  json_t *record_obj;

  if (NULL == handle->resp_object)
    handle->resp_object = json_array();

  char *result_str = json_dumps (handle->resp_object, 0);
  GNUNET_log(GNUNET_ERROR_TYPE_ERROR, "%s\n", result_str);
  GNUNET_free(result_str);
  /*if ( (NULL != handle->ego_entry->identifier) &&
       (0 != strcmp (handle->ego_entry->identifier,
		     rname)) )
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "%s does not match %s\n", rname,
	       handle->ego_entry->identifier);
    GNUNET_NAMESTORE_zone_iterator_next (handle->list_it, 1);
    return;
  }*/

  for (unsigned int i = 0; i < rd_len; i++)
  {
    if ( (GNUNET_GNSRECORD_TYPE_NICK == rd[i].record_type) &&
         (0 != strcmp (rname, GNUNET_GNS_EMPTY_LABEL_AT)) )
      continue;

    record_obj = gnsrecord_to_json (&rd[i]);

    if(NULL == record_obj)
      continue;

    json_array_append (handle->resp_object,
		       record_obj);
    json_decref (record_obj);
  }

  GNUNET_NAMESTORE_zone_iterator_next (handle->list_it, 1);
}


/**
 * Handle namestore GET request
 *
 * @param con_handle the connection handle
 * @param url the url
 * @param cls the RequestHandle
 */
void
namestore_get (struct GNUNET_REST_RequestHandle *con_handle,
                 const char* url,
                 void *cls)
{
  struct RequestHandle *handle = cls;
  if (strlen (GNUNET_REST_API_NS_NAMESTORE) != strlen (handle->url))
  {
    handle->emsg = GNUNET_strdup("Wrong URL");
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }
  handle->list_it = GNUNET_NAMESTORE_zone_iteration_start (handle->ns_handle,
                                                           &handle->zone_pkey,
                                                           &namestore_iteration_error,
                                                           handle,
                                                           &namestore_list_iteration,
                                                           handle,
                                                           &namestore_list_finished,
                                                           handle);
}

int
check_needed_data(struct RequestHandle *handle){
  if(NULL == handle->json_data->name)
  {
    handle->emsg = GNUNET_strdup("Missing JSON parameter: name");
    return GNUNET_SYSERR;
  }

  if(NULL == handle->json_data->type)
  {
    handle->emsg = GNUNET_strdup("Missing JSON parameter: type");
    return GNUNET_SYSERR;
  }

  if(NULL == handle->json_data->value)
  {
    handle->emsg = GNUNET_strdup("Missing JSON parameter: value");
    return GNUNET_SYSERR;
  }

  if(NULL == handle->json_data->expiration_time)
  {
    handle->emsg = GNUNET_strdup("Missing JSON parameter: expiration time");
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}

//TODO filter input
static int
json_to_gnsrecord (struct RequestHandle *handle)
{
  struct GNUNET_TIME_Relative etime_rel;
  struct GNUNET_TIME_Absolute etime_abs;
  void *rdata;
  size_t rdata_size;

  handle->rd = GNUNET_new_array(GNUNET_REST_NAMESTORE_RD_COUNT,
				 struct GNUNET_GNSRECORD_Data);
  memset (handle->rd, 0, sizeof(struct GNUNET_GNSRECORD_Data));
  handle->rd->record_type = GNUNET_GNSRECORD_typename_to_number (
      handle->json_data->type);
  if (UINT32_MAX == (*handle->rd).record_type)
  {
    handle->emsg = GNUNET_strdup("Unsupported type");
    return GNUNET_SYSERR;
  }
  if (GNUNET_OK
      != GNUNET_GNSRECORD_string_to_value ((*handle->rd).record_type,
					   handle->json_data->value, &rdata,
					   &rdata_size))
  {
    handle->emsg = GNUNET_strdup("Value invalid for record type");
    return GNUNET_SYSERR;
  }
  (*handle->rd).data = rdata;
  (*handle->rd).data_size = rdata_size;
  //TODO other flags
  if (0 == handle->json_data->is_public)
  {
    handle->rd->flags |= GNUNET_GNSRECORD_RF_PRIVATE;
  }
  /**TODO
   * if (1 == handle->is_shadow)
   rde->flags |= GNUNET_GNSRECORD_RF_SHADOW_RECORD;
   if (1 != handle->is_public)
   rde->flags |= GNUNET_GNSRECORD_RF_PRIVATE;
   */
  if (0 == strcmp (handle->json_data->expiration_time, "never"))
  {
    (*handle->rd).expiration_time = GNUNET_TIME_UNIT_FOREVER_ABS.abs_value_us;
  }
  else if (GNUNET_OK
      == GNUNET_STRINGS_fancy_time_to_relative (
	  handle->json_data->expiration_time, &etime_rel))
  {
    (*handle->rd).expiration_time = etime_rel.rel_value_us;
    (*handle->rd).flags |= GNUNET_GNSRECORD_RF_RELATIVE_EXPIRATION;
  }
  else if (GNUNET_OK
      == GNUNET_STRINGS_fancy_time_to_absolute (
	  handle->json_data->expiration_time, &etime_abs))
  {
    (*handle->rd).expiration_time = etime_abs.abs_value_us;
  }
  else
  {
    handle->emsg = GNUNET_strdup("Value invalid for record type");
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * We're storing a new record; this requires
 * that no record already exists
 *
 * @param cls closure, unused
 * @param zone_key private key of the zone
 * @param rec_name name that is being mapped (at most 255 characters long)
 * @param rd_count number of entries in @a rd array
 * @param rd array of records with data to store
 */
static void
create_new_record_cont (void *cls,
                        const struct GNUNET_CRYPTO_EcdsaPrivateKey *zone_key,
                        const char *rec_name,
                        unsigned int rd_count,
                        const struct GNUNET_GNSRECORD_Data *rd)
{
  struct RequestHandle *handle = cls;

  handle->add_qe = NULL;
  if (0 != strcmp (rec_name, handle->json_data->name))
  {
    GNUNET_break (0);
    do_error (handle);
    return;
  }

  if (0 != rd_count)
  {
    handle->proc (handle->proc_cls,
                  GNUNET_REST_create_response (NULL),
                  MHD_HTTP_CONFLICT);
    cleanup_handle(handle);
    return;
  }
  handle->add_qe = GNUNET_NAMESTORE_records_store (handle->ns_handle,
                                                   &handle->zone_pkey,
                                                   handle->json_data->name,
                                                   GNUNET_REST_NAMESTORE_RD_COUNT,
                                                   handle->rd,
                                                   &create_finished,
                                                   handle);
}


/**
 * Handle namestore POST request
 *
 * @param con_handle the connection handle
 * @param url the url
 * @param cls the RequestHandle
 */
void
namestore_add (struct GNUNET_REST_RequestHandle *con_handle,
               const char* url,
	       void *cls)
{
  struct RequestHandle *handle = cls;
  json_t *data_js;
  json_error_t err;
  char term_data[handle->rest_handle->data_size + 1];

  if (strlen (GNUNET_REST_API_NS_NAMESTORE) != strlen (handle->url))
  {
    handle->emsg = GNUNET_strdup("Wrong URL");
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }
  if (0 >= handle->rest_handle->data_size)
  {
    handle->emsg = GNUNET_strdup("No data");
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }
  term_data[handle->rest_handle->data_size] = '\0';
  GNUNET_memcpy(term_data, handle->rest_handle->data,
		handle->rest_handle->data_size);
  data_js = json_loads (term_data, JSON_DECODE_ANY, &err);
  GNUNET_REST_JSON_parse(&handle->json_data, data_js);
  if(NULL == handle->json_data)
  {
    handle->emsg = GNUNET_strdup("Wrong data");
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }
  if(GNUNET_SYSERR == check_needed_data(handle))
  {
    json_decref (data_js);
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }
  json_decref (data_js);
  json_to_gnsrecord (handle);
  handle->add_qe = GNUNET_NAMESTORE_records_lookup (handle->ns_handle,
						    &handle->zone_pkey,
						    handle->json_data->name,
						    &do_error,
						    handle,
						    &create_new_record_cont,
						    handle);
}


/**
 * Handle namestore DELETE request
 *
 * @param con_handle the connection handle
 * @param url the url
 * @param cls the RequestHandle
 */
void
namestore_delete (struct GNUNET_REST_RequestHandle *con_handle,
                 const char* url,
                 void *cls)
{
  struct RequestHandle *handle = cls;
  
  //TODO add behaviour and response
  
  handle->emsg = GNUNET_strdup ("Not implemented yet");
  GNUNET_SCHEDULER_add_now (&do_error, handle);
  return;
}



/**
 * Respond to OPTIONS request
 *
 * @param con_handle the connection handle
 * @param url the url
 * @param cls the RequestHandle
 */
static void
options_cont (struct GNUNET_REST_RequestHandle *con_handle,
              const char* url,
              void *cls)
{
  struct MHD_Response *resp;
  struct RequestHandle *handle = cls;

  //independent of path return all options
  resp = GNUNET_REST_create_response (NULL);
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
  //TODO specify parameter of init_cont if necessary
  struct GNUNET_REST_RequestHandlerError err;
  static const struct GNUNET_REST_RequestHandler handlers[] = {
    {MHD_HTTP_METHOD_GET, GNUNET_REST_API_NS_NAMESTORE, &namestore_get},
    {MHD_HTTP_METHOD_POST, GNUNET_REST_API_NS_NAMESTORE, &namestore_add},
    {MHD_HTTP_METHOD_DELETE, GNUNET_REST_API_NS_NAMESTORE, &namestore_delete},
    {MHD_HTTP_METHOD_OPTIONS, GNUNET_REST_API_NS_NAMESTORE, &options_cont},
    GNUNET_REST_HANDLER_END
  };

  if (GNUNET_NO == GNUNET_REST_handle_request (handle->rest_handle,
                                               handlers,
                                               &err,
                                               handle))
  {
    handle->response_code = err.error_code;
    GNUNET_SCHEDULER_add_now (&do_error, handle);
  }
}

/**
 *
 */
static void
default_ego_cb (void *cls,
                struct GNUNET_IDENTITY_Ego *ego,
                void **ctx,
                const char *name)
{
  struct RequestHandle *handle = cls;
  struct EgoEntry *ego_entry;
  struct GNUNET_CRYPTO_EcdsaPublicKey pk;

  handle->op = NULL;

  if (NULL == ego)
  {
    handle->emsg = GNUNET_strdup ("No default ego configured in identity service");
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }
  ego_entry = GNUNET_new(struct EgoEntry);
  GNUNET_IDENTITY_ego_get_public_key (ego, &pk);
  ego_entry->keystring = GNUNET_CRYPTO_ecdsa_public_key_to_string (&pk);
  ego_entry->identifier = name;
  ego_entry->ego = ego;
  handle->ego_entry = ego_entry;
  handle->zone_pkey = *GNUNET_IDENTITY_ego_get_private_key (ego);
  init_cont (handle);
}


/**
 * Connect to identity callback
 */
static void
id_connect_cb (void *cls,
               struct GNUNET_IDENTITY_Ego *ego,
               void **ctx,
               const char *name)
{
  struct RequestHandle *handle = cls;
  if (NULL == ego)
  {
    handle->op = GNUNET_IDENTITY_get (handle->identity_handle,
				      GNUNET_REST_SUBSYSTEM_NAMESTORE,
				      &default_ego_cb,
				      handle);
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
rest_process_request(struct GNUNET_REST_RequestHandle *rest_handle,
                              GNUNET_REST_ResultProcessor proc,
                              void *proc_cls)
{
  struct RequestHandle *handle = GNUNET_new (struct RequestHandle);
  
  handle->response_code = 0;
  handle->timeout = GNUNET_TIME_UNIT_FOREVER_REL;
  handle->proc_cls = proc_cls;
  handle->proc = proc;
  handle->rest_handle = rest_handle;
  
  handle->url = GNUNET_strdup (rest_handle->url);
  if (handle->url[strlen (handle->url)-1] == '/')
    handle->url[strlen (handle->url)-1] = '\0';
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Connecting...\n");

  handle->identity_handle = GNUNET_IDENTITY_connect (cfg, &id_connect_cb, handle);
  handle->ns_handle = GNUNET_NAMESTORE_connect (cfg);
  handle->timeout_task =
    GNUNET_SCHEDULER_add_delayed (handle->timeout,
                                  &do_error,
                                  handle);
  
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Connected\n");
}


/**
 * Entry point for the plugin.
 *
 * @param cls Config info
 * @return NULL on error, otherwise the plugin context
 */
void *
libgnunet_plugin_rest_namestore_init (void *cls)
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
  api->name = GNUNET_REST_API_NS_NAMESTORE;
  api->process_request = &rest_process_request;
  GNUNET_asprintf (&allow_methods,
                   "%s, %s, %s, %s, %s",
                   MHD_HTTP_METHOD_GET,
                   MHD_HTTP_METHOD_POST,
                   MHD_HTTP_METHOD_PUT,
                   MHD_HTTP_METHOD_DELETE,
                   MHD_HTTP_METHOD_OPTIONS);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              _("Namestore REST API initialized\n"));
  return api;
}


/**
 * Exit point from the plugin.
 *
 * @param cls the plugin context (as returned by "init")
 * @return always NULL
 */
void *
libgnunet_plugin_rest_namestore_done (void *cls)
{
  struct GNUNET_REST_Plugin *api = cls;
  struct Plugin *plugin = api->cls;
  plugin->cfg = NULL;

  GNUNET_free_non_null (allow_methods);
  GNUNET_free (api);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Namestore REST plugin is finished\n");
  return NULL;
}

/* end of plugin_rest_namestore.c */


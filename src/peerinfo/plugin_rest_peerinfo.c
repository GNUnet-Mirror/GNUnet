/*
   This file is part of GNUnet.
   Copyright (C) 2012-2015 GNUnet e.V.

   GNUnet is free software: you can redistribute it and/or modify it
   under the terms of the GNU Affero General Public License as published
   by the Free Software Foundation, either version 3 of the License,
   or (at your option) any later version.

   GNUnet is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Affero General Public License for more details.

   You should have received a copy of the GNU Affero General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
   */
/**
 * @author Martin Schanzenbach
 * @author Philippe Buschmann
 * @file peerinfo/plugin_rest_peerinfo.c
 * @brief GNUnet Peerinfo REST plugin
 */

#include "platform.h"
#include "gnunet_rest_plugin.h"
#include "gnunet_peerinfo_service.h"
#include "gnunet_transport_service.h"
#include "gnunet_rest_lib.h"
#include "gnunet_json_lib.h"
#include "microhttpd.h"
#include <jansson.h>

#define GNUNET_REST_API_NS_PEERINFO "/peerinfo"
#define GNUNET_REST_API_PEERINFO_PEER "peer"
#define GNUNET_REST_API_PEERINFO_FRIEND "friend"

//TODO define other variables
#define GNUNET_REST_ERROR_UNKNOWN "Unkown Error"

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



struct RequestHandle
{
  //TODO add specific entries
  json_t *temp_array;
  char *expiration_str;
  const char *address;

  /**
   * Iteration peer public key
   */
  char *pubkey;

  /**
   * JSON array response
   */
  json_t *response;

  /**
   * Handle to PEERINFO it
   */
  struct GNUNET_PEERINFO_IteratorContext *list_it;

  /**
   * Handle to PEERINFO
   */
  struct GNUNET_PEERINFO_Handle *peerinfo_handle;

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


/**
 * Cleanup lookup handle
 * @param handle Handle to clean up
 */
static void
cleanup_handle (void *cls)
{
  struct RequestHandle *handle = cls;

  GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Test: %i\n", NULL == handle);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Cleaning up\n");
  if (NULL != handle->timeout_task)
  {
    GNUNET_SCHEDULER_cancel (handle->timeout_task);
    handle->timeout_task = NULL;
  }
  if (NULL != handle->url)
    GNUNET_free (handle->url);
  if (NULL != handle->emsg)
    GNUNET_free (handle->emsg);

  if (NULL != handle->response)
  {
    json_decref(handle->response);
    handle->response = NULL;
  }

  if (NULL != handle->list_it)
  {
    GNUNET_PEERINFO_iterate_cancel(handle->list_it);
    handle->list_it = NULL;
  }

  if (NULL != handle->peerinfo_handle)
  {
    GNUNET_PEERINFO_disconnect(handle->peerinfo_handle);
    handle->peerinfo_handle = NULL;
  }

  //TODO add specific cleanup
  
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
  json_t *json_error = json_object();
  char *response;

  if (NULL == handle->emsg)
    handle->emsg = GNUNET_strdup(GNUNET_REST_ERROR_UNKNOWN);

  json_object_set_new(json_error,"error", json_string(handle->emsg));

  if (0 == handle->response_code)
    handle->response_code = MHD_HTTP_OK;
  response = json_dumps (json_error, 0);
  resp = GNUNET_REST_create_response (response);
  handle->proc (handle->proc_cls, resp, handle->response_code);
  json_decref(json_error);
  GNUNET_free(response);
  GNUNET_SCHEDULER_add_now (&cleanup_handle, handle);
}


/**
 * Function that assembles our response.
 */
static void
peerinfo_list_finished (void *cls)
{
  GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "6\n");
  struct RequestHandle *handle = cls;
  char *result_str;
  struct MHD_Response *resp;

  if (NULL == handle->response)
  {
    handle->emsg = GNUNET_strdup ("No peers found");
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }

  result_str = json_dumps (handle->response, 0);
  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "Result %s\n", result_str);
  resp = GNUNET_REST_create_response (result_str);
  handle->proc (handle->proc_cls, resp, MHD_HTTP_OK);
  GNUNET_free_non_null (result_str);
  GNUNET_SCHEDULER_add_now (&cleanup_handle, handle);
}


/**
 * Set @a cls to #GNUNET_YES (we have an address!).
 *
 * @param cls closure, an `int *`
 * @param address the address (ignored)
 * @param expiration expiration time (call is ignored if this is in the past)
 * @return  #GNUNET_SYSERR to stop iterating (unless expiration has occured)
 */
static int
check_has_addr (void *cls,
                const struct GNUNET_HELLO_Address *address,
                struct GNUNET_TIME_Absolute expiration)
{
  int *arg = cls;
  if (0 == GNUNET_TIME_absolute_get_remaining (expiration).rel_value_us)
  {
    return GNUNET_YES;          /* ignore this address */
  }
  *arg = GNUNET_YES;
  return GNUNET_SYSERR;
}

static void
create_array(void *cls)
{
  struct RequestHandle *handle = cls;
//  json_t *object;
//  object = json_object();
//
//  json_object_set(object,"address",json_string(handle->address));
//  json_object_set(object,"expires",json_string(handle->expiration_str));
//
//  if(NULL == handle->temp_array)
//  {
//    handle->temp_array = json_array();
//  }
//
//  json_array_append(handle->temp_array,object);
//
//  json_decref(object);
  GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "5\n");
  json_object_set(handle->response, handle->pubkey, handle->temp_array);
  json_decref (handle->temp_array);
}

static void
create_tmp_array (void *cls)
{
  struct RequestHandle *handle = cls;
  GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "4\n");
  json_t *object;
  json_t *address_json = json_string (handle->address);
  json_t *expires_json = json_string (handle->expiration_str);
  object = json_object ();

  json_object_set (object, "address", address_json);
  json_decref(address_json);
  json_object_set (object, "expires", expires_json);
  json_decref(expires_json);
  GNUNET_free(handle->expiration_str);

  if (NULL == handle->temp_array)
  {
    handle->temp_array = json_array ();
  }

  json_array_append (handle->temp_array, object);

  json_decref (object);
}

static void
addr_to_str_cb (void *cls,
		const char *address,
		int res)
{
  struct RequestHandle *handle = cls;
  if (NULL == address)
  {
    return;
  }
  if (GNUNET_OK != res)
  {
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "3\n");
  handle->address = GNUNET_strdup(address);
  GNUNET_assert(false);
}

/**
 * Set @a cls to #GNUNET_YES (we have an address!).
 *
 * @param cls closure
 * @param address the address (ignored)
 * @param expiration expiration time (call is ignored if this is in the past)
 * @return  #GNUNET_SYSERR to stop iterating (unless expiration has occured)
 */
static int
address_iteration (void *cls,
		   const struct GNUNET_HELLO_Address *address,
		   struct GNUNET_TIME_Absolute expiration)
{
  struct RequestHandle *handle = cls;
  char *expiration_tmp;

  if (0 == GNUNET_TIME_absolute_get_remaining (expiration).rel_value_us)
  {
    return GNUNET_YES;          /* ignore this address */
  }
  expiration_tmp = GNUNET_STRINGS_absolute_time_to_string(expiration);
  handle->expiration_str = GNUNET_strdup(expiration_tmp);
  GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "2\n");
  GNUNET_TRANSPORT_address_to_string(cfg,
				     address,
                                     GNUNET_NO,
                                     GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 10),
                                     &addr_to_str_cb,
				     handle);

  GNUNET_SCHEDULER_add_now(&create_tmp_array,handle);

//  GNUNET_SCHEDULER_add_delayed (
//      GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 11),
//      &create_array,
//      handle);
  return GNUNET_YES;
}


/**
 * Callback that processes each of the known HELLOs for the
 * iteration response construction.
 *
 * @param cls closure, NULL
 * @param peer id of the peer, NULL for last call
 * @param hello hello message for the peer (can be NULL)
 * @param err_msg message
 */
void
peerinfo_list_iteration(void *cls,
	                const struct GNUNET_PeerIdentity *peer,
	                const struct GNUNET_HELLO_Message *hello,
	                const char *err_msg)
{
  struct RequestHandle *handle = cls;
  int has_addr;

  if (NULL == handle->response)
  {
    handle->response = json_object();
  }

  if (NULL != err_msg)
  {
    GNUNET_assert (NULL == peer);
    handle->list_it = NULL;
    handle->emsg = GNUNET_strdup ("Error in communication with peerinfo");
    handle->response_code = MHD_HTTP_INTERNAL_SERVER_ERROR;
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }
  if (NULL == peer)
  {
    handle->list_it = NULL;
    GNUNET_SCHEDULER_add_now (&peerinfo_list_finished, handle);
    return;
  }
  if (NULL == hello)
    return;
  has_addr = GNUNET_NO;
  GNUNET_HELLO_iterate_addresses (hello,
                                  GNUNET_NO,
                                  &check_has_addr,
                                  &has_addr);
  if (GNUNET_NO == has_addr)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "HELLO for peer `%4s' has no address, not suitable for hostlist!\n",
                GNUNET_i2s (peer));
    return;
  }

  if (NULL != handle->pubkey)
    GNUNET_free (handle->pubkey);
  handle->pubkey = GNUNET_CRYPTO_eddsa_public_key_to_string(&peer->public_key);
  GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "1\n");
  GNUNET_HELLO_iterate_addresses (hello,
                                  GNUNET_NO,
                                  &address_iteration,
                                  handle);
  GNUNET_SCHEDULER_add_now(&create_array,handle);
}

/**
 * Handle peerinfo GET request
 *
 * @param con_handle the connection handle
 * @param url the url
 * @param cls the RequestHandle
 */
void
peerinfo_get (struct GNUNET_REST_RequestHandle *con_handle,
                 const char* url,
                 void *cls)
{
  struct RequestHandle *handle = cls;
  struct GNUNET_HashCode key;
  const struct GNUNET_PeerIdentity *specific_peer;
  GNUNET_PEER_Id peer_id;
  int include_friend_only;

  include_friend_only = GNUNET_NO;
  GNUNET_CRYPTO_hash (GNUNET_REST_API_PEERINFO_FRIEND,
		      strlen (GNUNET_REST_API_PEERINFO_FRIEND),
		      &key);
  if ( GNUNET_YES
      == GNUNET_CONTAINER_multihashmap_contains (con_handle->url_param_map,
						 &key))
  {
    include_friend_only = *(int*)GNUNET_CONTAINER_multihashmap_get (
	      con_handle->url_param_map, &key);
  }
  if(GNUNET_YES != include_friend_only)
  {
    include_friend_only = GNUNET_NO;
  }

  specific_peer = NULL;
  GNUNET_CRYPTO_hash (GNUNET_REST_API_PEERINFO_PEER,
		      strlen (GNUNET_REST_API_PEERINFO_PEER),
		      &key);
  if ( GNUNET_YES
      == GNUNET_CONTAINER_multihashmap_contains (con_handle->url_param_map,
						 &key))
  {
    peer_id = *(unsigned int*)GNUNET_CONTAINER_multihashmap_get (con_handle->url_param_map, &key);
    specific_peer = GNUNET_PEER_resolve2(peer_id);
  }


  //TODO friend_only and special peer

  //TODO add behaviour and response
  //TODO maybe notify better than iteration

  handle->list_it = GNUNET_PEERINFO_iterate(handle->peerinfo_handle,
					    include_friend_only,
					    specific_peer,
					    &peerinfo_list_iteration,
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
  GNUNET_SCHEDULER_add_now (&cleanup_handle, handle);
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
    {MHD_HTTP_METHOD_GET, GNUNET_REST_API_NS_PEERINFO, &peerinfo_get},
    {MHD_HTTP_METHOD_OPTIONS, GNUNET_REST_API_NS_PEERINFO, &options_cont},
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
  //TODO connect to specific service
  //connect ( cfg, [..., &callback_function, handle]);
  handle->peerinfo_handle = GNUNET_PEERINFO_connect(cfg);
  init_cont(handle);
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
libgnunet_plugin_rest_peerinfo_init (void *cls)
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
  api->name = GNUNET_REST_API_NS_PEERINFO;
  api->process_request = &rest_process_request;
  GNUNET_asprintf (&allow_methods,
                   "%s, %s, %s, %s, %s",
                   MHD_HTTP_METHOD_GET,
                   MHD_HTTP_METHOD_POST,
                   MHD_HTTP_METHOD_PUT,
                   MHD_HTTP_METHOD_DELETE,
                   MHD_HTTP_METHOD_OPTIONS);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              _("Peerinfo REST API initialized\n"));
  return api;
}


/**
 * Exit point from the plugin.
 *
 * @param cls the plugin context (as returned by "init")
 * @return always NULL
 */
void *
libgnunet_plugin_rest_peerinfo_done (void *cls)
{
  struct GNUNET_REST_Plugin *api = cls;
  struct Plugin *plugin = api->cls;
  plugin->cfg = NULL;

  GNUNET_free_non_null (allow_methods);
  GNUNET_free (api);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Peerinfo REST plugin is finished\n");
  return NULL;
}

/* end of plugin_rest_peerinfo.c */


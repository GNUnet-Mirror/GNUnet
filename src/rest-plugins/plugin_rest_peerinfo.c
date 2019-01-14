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

     SPDX-License-Identifier: AGPL3.0-or-later
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

/**
 * Peerinfo Namespace
 */
#define GNUNET_REST_API_NS_PEERINFO "/peerinfo"

/**
 * Peerinfo parameter peer
 */
#define GNUNET_REST_PEERINFO_PEER "peer"

/**
 * Peerinfo parameter friend
 */
#define GNUNET_REST_PEERINFO_FRIEND "friend"

/**
 * Peerinfo parameter array
 */
#define GNUNET_REST_PEERINFO_ARRAY "array"

/**
 * Error message Unknown Error
 */
#define GNUNET_REST_PEERINFO_ERROR_UNKNOWN "Unknown Error"

/**
 * How long until we time out during address lookup?
 */
#define TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 5)
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
 * Record we keep for each printable address.
 */
struct AddressRecord
{
  /**
   * Current address-to-string context (if active, otherwise NULL).
   */
  struct GNUNET_TRANSPORT_AddressToStringContext *atsc;

  /**
   * Address expiration time
   */
  struct GNUNET_TIME_Absolute expiration;

  /**
   * Printable address.
   */
  char *result;

  /**
   * Print context this address record belongs to.
   */
  struct PrintContext *pc;
};


/**
 * Structure we use to collect printable address information.
 */
struct PrintContext
{
  /**
   * Kept in DLL.
   */
  struct PrintContext *next;

  /**
   * Kept in DLL.
   */
  struct PrintContext *prev;

  /**
   * Identity of the peer.
   */
  struct GNUNET_PeerIdentity peer;

  /**
   * List of printable addresses.
   */
  struct AddressRecord *address_list;

  /**
   * Number of completed addresses in @e address_list.
   */
  unsigned int num_addresses;

  /**
   * Number of addresses allocated in @e address_list.
   */
  unsigned int address_list_size;

  /**
   * Current offset in @e address_list (counted down).
   */
  unsigned int off;

  /**
   * Hello was friend only, #GNUNET_YES or #GNUNET_NO
   */
  int friend_only;

  /**
   * RequestHandle
   */
  struct RequestHandle *handle;

};

/**
 * Head of list of print contexts.
 */
static struct PrintContext *pc_head;

/**
 * Tail of list of print contexts.
 */
static struct PrintContext *pc_tail;

/**
 * The request handle
 */
struct RequestHandle
{
  /**
   * JSON temporary array
   */
  json_t *temp_array;

  /**
   * Expiration time string
   */
  char *expiration_str;

  /**
   * Address string
   */
  const char *address;

  /**
   * Iteration peer public key
   */
  char *pubkey;

  /**
   * JSON response
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
  if (NULL != handle->address)
    GNUNET_free ((char*)handle->address);
  if (NULL != handle->expiration_str)
    GNUNET_free (handle->expiration_str);
  if (NULL != handle->pubkey)
    GNUNET_free (handle->pubkey);

  if (NULL != handle->temp_array)
  {
    json_decref(handle->temp_array);
    handle->temp_array = NULL;
  }
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
    handle->emsg = GNUNET_strdup(GNUNET_REST_PEERINFO_ERROR_UNKNOWN);

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
 * Function that assembles the response.
 *
 * @param cls the `struct RequestHandle`
 */
static void
peerinfo_list_finished (void *cls)
{
  struct RequestHandle *handle = cls;
  char *result_str;
  struct MHD_Response *resp;

  if (NULL == handle->response)
  {
    handle->response_code = MHD_HTTP_NOT_FOUND;
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
 * Iterator callback to go over all addresses and count them.
 *
 * @param cls `struct PrintContext *` with `off` to increment
 * @param address the address
 * @param expiration expiration time
 * @return #GNUNET_OK to keep the address and continue
 */
static int
count_address (void *cls,
               const struct GNUNET_HELLO_Address *address,
               struct GNUNET_TIME_Absolute expiration)
{
  struct PrintContext *pc = cls;

  if (0 == GNUNET_TIME_absolute_get_remaining (expiration).rel_value_us)
  {
    return GNUNET_OK;          /* ignore expired address */
  }

  pc->off++;
  return GNUNET_OK;
}


/**
 * Print the collected address information to the console and free @a pc.
 *
 * @param pc printing context
 */
static void
dump_pc (struct PrintContext *pc)
{
  struct RequestHandle *handle;
  unsigned int i;
  json_t *response_entry;
  json_t *temp_array;
  json_t *object;
  json_t *address;
  json_t *expires;
  json_t *friend_and_peer_json;
  char *friend_and_peer;

  temp_array = json_array();
  response_entry = json_object();

  for (i = 0; i < pc->num_addresses; i++)
  {
    if (NULL != pc->address_list[i].result)
    {
      object = json_object ();
      address = json_string(pc->address_list[i].result);
      expires = json_string(
	  GNUNET_STRINGS_absolute_time_to_string (pc->address_list[i].expiration));
      json_object_set (object, "address", address);
      json_object_set (object, "expires", expires);

      json_decref(address);
      json_decref(expires);

      json_array_append(temp_array, object);
      json_decref(object);
      GNUNET_free (pc->address_list[i].result);
    }
  }

  if (0 < json_array_size(temp_array))
  {
    GNUNET_asprintf(&friend_and_peer,
		    "%s%s",
		    (GNUNET_YES == pc->friend_only) ? "F2F:" : "",
		    GNUNET_i2s_full (&pc->peer));
    friend_and_peer_json = json_string(friend_and_peer);
    json_object_set(response_entry,
		    GNUNET_REST_PEERINFO_PEER,
		    friend_and_peer_json);
    json_object_set(response_entry,
		    GNUNET_REST_PEERINFO_ARRAY,
		    temp_array);
    json_array_append(pc->handle->response, response_entry);
    json_decref(friend_and_peer_json);
    GNUNET_free(friend_and_peer);
  }

  json_decref (temp_array);
  json_decref(response_entry);

  GNUNET_free_non_null (pc->address_list);
  GNUNET_CONTAINER_DLL_remove (pc_head,
			       pc_tail,
			       pc);
  handle = pc->handle;
  GNUNET_free (pc);

  if ( (NULL == pc_head) &&
       (NULL == handle->list_it) )
  {
    GNUNET_SCHEDULER_add_now (&peerinfo_list_finished, handle);
  }

}


/**
 * Function to call with a human-readable format of an address
 *
 * @param cls closure
 * @param address NULL on error, otherwise 0-terminated printable UTF-8 string
 * @param res result of the address to string conversion:
 *        if #GNUNET_OK: address was valid (conversion to
 *                       string might still have failed)
 *        if #GNUNET_SYSERR: address is invalid
 */
static void
process_resolved_address (void *cls,
                          const char *address,
                          int res)
{
  struct AddressRecord *ar = cls;
  struct PrintContext *pc = ar->pc;

  if (NULL != address)
  {
    if (0 != strlen (address))
    {
      if (NULL != ar->result)
        GNUNET_free (ar->result);
      ar->result = GNUNET_strdup (address);
    }
    return;
  }
  ar->atsc = NULL;
  if (GNUNET_SYSERR == res)
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                _("Failure: Cannot convert address to string for peer `%s'\n"),
                GNUNET_i2s (&ar->pc->peer));
  pc->num_addresses++;
  if (pc->num_addresses == pc->address_list_size)
    dump_pc (ar->pc);
}


/**
 * Iterator callback to go over all addresses.
 *
 * @param cls closure
 * @param address the address
 * @param expiration expiration time
 * @return #GNUNET_OK to keep the address and continue
 */
static int
print_address (void *cls,
               const struct GNUNET_HELLO_Address *address,
               struct GNUNET_TIME_Absolute expiration)
{
  struct PrintContext *pc = cls;
  struct AddressRecord *ar;

  if (0 == GNUNET_TIME_absolute_get_remaining (expiration).rel_value_us)
  {
    return GNUNET_OK;          /* ignore expired address */
  }

  GNUNET_assert (0 < pc->off);
  ar = &pc->address_list[--pc->off];
  ar->pc = pc;
  ar->expiration = expiration;
  GNUNET_asprintf (&ar->result,
                   "%s:%u:%u",
                   address->transport_name,
                   address->address_length,
                   address->local_info);
  ar->atsc = GNUNET_TRANSPORT_address_to_string (cfg,
                                                 address,
						 GNUNET_NO,
						 TIMEOUT,
						 &process_resolved_address,
						 ar);
  return GNUNET_OK;
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
  struct PrintContext *pc;
  int friend_only;

  if (NULL == handle->response)
  {
    handle->response = json_array();
  }

  if (NULL == peer)
  {
    handle->list_it = NULL;
    handle->emsg = GNUNET_strdup ("Error in communication with peerinfo");
    if (NULL != err_msg)
    {
      GNUNET_free(handle->emsg);
      handle->emsg = GNUNET_strdup (err_msg);
      handle->response_code = MHD_HTTP_INTERNAL_SERVER_ERROR;
    }
    if (NULL == pc_head)
      GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }
  if (NULL == hello)
    return;

  friend_only = GNUNET_NO;
  if (NULL != hello)
    friend_only = GNUNET_HELLO_is_friend_only (hello);

  pc = GNUNET_new(struct PrintContext);
  GNUNET_CONTAINER_DLL_insert (pc_head,
			       pc_tail,
			       pc);
  pc->peer = *peer;
  pc->friend_only = friend_only;
  pc->handle = handle;
  GNUNET_HELLO_iterate_addresses (hello,
				  GNUNET_NO,
				  &count_address,
				  pc);
  if (0 == pc->off)
  {
    dump_pc (pc);
    return;
  }
  pc->address_list_size = pc->off;
  pc->address_list = GNUNET_malloc(
      sizeof(struct AddressRecord) * pc->off);
  GNUNET_HELLO_iterate_addresses (hello,
				  GNUNET_NO,
				  &print_address,
				  pc);
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
  //GNUNET_PEER_Id peer_id;
  int include_friend_only;
  char* include_friend_only_str;

  include_friend_only = GNUNET_NO;
  GNUNET_CRYPTO_hash (GNUNET_REST_PEERINFO_FRIEND,
		      strlen (GNUNET_REST_PEERINFO_FRIEND),
		      &key);
  if ( GNUNET_YES
      == GNUNET_CONTAINER_multihashmap_contains (con_handle->url_param_map,
						 &key))
  {
    include_friend_only_str = GNUNET_CONTAINER_multihashmap_get (
	      con_handle->url_param_map, &key);
    if (0 == strcmp(include_friend_only_str, "yes"))
    {
      include_friend_only = GNUNET_YES;
    }
  }

  specific_peer = NULL;
  GNUNET_CRYPTO_hash (GNUNET_REST_PEERINFO_PEER,
		      strlen (GNUNET_REST_PEERINFO_PEER),
		      &key);
  if ( GNUNET_YES
      == GNUNET_CONTAINER_multihashmap_contains (con_handle->url_param_map,
						 &key))
  {
    //peer_id = *(unsigned int*)GNUNET_CONTAINER_multihashmap_get (con_handle->url_param_map, &key);
    //specific_peer = GNUNET_PEER_resolve2(peer_id);
  }

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
  handle->timeout = GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 60);
  handle->proc_cls = proc_cls;
  handle->proc = proc;
  handle->rest_handle = rest_handle;
  
  handle->url = GNUNET_strdup (rest_handle->url);
  if (handle->url[strlen (handle->url)-1] == '/')
    handle->url[strlen (handle->url)-1] = '\0';
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Connecting...\n");
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


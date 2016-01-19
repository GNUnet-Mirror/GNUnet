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
#include "gnunet_gns_service.h"
#include "gnunet_gnsrecord_lib.h"
#include "gnunet_namestore_service.h"
#include "gnunet_rest_lib.h"
#include "microhttpd.h"
#include <jansson.h>
#include "gnunet_signatures.h"
#include "gnunet_identity_provider_service.h"

/**
 * REST root namespace
 */
#define GNUNET_REST_API_NS_IDENTITY_PROVIDER "/idp"

/**
 * Issue namespace
 */
#define GNUNET_REST_API_NS_IDENTITY_TOKEN_ISSUE "/idp/issue"

/**
 * Check namespace TODO
 */
#define GNUNET_REST_API_NS_IDENTITY_TOKEN_CHECK "/idp/check"

/**
 * Token namespace
 */
#define GNUNET_REST_API_NS_IDENTITY_OAUTH2_TOKEN "/idp/token"

/**
 * The parameter name in which the ticket must be provided
 */
#define GNUNET_REST_JSONAPI_IDENTITY_PROVIDER_TICKET "ticket"

/**
 * The parameter name in which the ticket must be provided
 */
#define GNUNET_REST_JSONAPI_IDENTITY_PROVIDER_TOKEN "token"

/**
 * The URL parameter name in which the nonce must be provided
 */
#define GNUNET_IDENTITY_TOKEN_REQUEST_NONCE "nonce"

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
#define GNUNET_REST_JSONAPI_IDENTITY_TOKEN "token"

/**
 * URL parameter to create a GNUid token for a specific audience
 */
#define GNUNET_REST_JSONAPI_IDENTITY_AUD_REQUEST "audience"

/**
 * URL parameter to create a GNUid token for a specific issuer (EGO)
 */
#define GNUNET_REST_JSONAPI_IDENTITY_ISS_REQUEST "issuer"

/**
 * Attributes passed to issue request
 */
#define GNUNET_IDENTITY_TOKEN_ATTR_LIST "requested_attrs"

/**
 * Token expiration string
 */
#define GNUNET_IDENTITY_TOKEN_EXP_STRING "expiration"

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
   * Selected ego
   */
  struct EgoEntry *ego_entry;
  
  /**
   * Ptr to current ego private key
   */
  const struct GNUNET_CRYPTO_EcdsaPrivateKey *priv_key;

  /**
   * Handle to the rest connection
   */
  struct RestConnectionDataHandle *conndata_handle;
  
  /**
   * The processing state
   */
  int state;

  /**
   * Handle to Identity service.
   */
  struct GNUNET_IDENTITY_Handle *identity_handle;

  /**
   * IDENTITY Operation
   */
  struct GNUNET_IDENTITY_Operation *op;

  /**
   * Identity Provider
   */
  struct GNUNET_IDENTITY_PROVIDER_Handle *idp;

  /**
   * Idp Operation
   */
  struct GNUNET_IDENTITY_PROVIDER_Operation *idp_op;

  /**
   * Handle to NS service
   */
  struct GNUNET_NAMESTORE_Handle *ns_handle;

  /**
   * NS iterator
   */
  struct GNUNET_NAMESTORE_ZoneIterator *ns_it;

  /**
   * NS Handle
   */
  struct GNUNET_NAMESTORE_QueueEntry *ns_qe;

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
   * The url
   */
  char *url;

  /**
   * Error response message
   */
  char *emsg;

  /**
   * Response object
   */
  struct JsonApiObject *resp_object;

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
  if (NULL != handle->resp_object) 
    GNUNET_REST_jsonapi_object_delete (handle->resp_object);
  if (NULL != handle->timeout_task)
    GNUNET_SCHEDULER_cancel (handle->timeout_task);
  if (NULL != handle->identity_handle)
    GNUNET_IDENTITY_disconnect (handle->identity_handle);
  if (NULL != handle->idp)
    GNUNET_IDENTITY_PROVIDER_disconnect (handle->idp);
  if (NULL != handle->ns_it)
    GNUNET_NAMESTORE_zone_iteration_stop (handle->ns_it);
  if (NULL != handle->ns_qe)
    GNUNET_NAMESTORE_cancel (handle->ns_qe);
  if (NULL != handle->ns_handle)
    GNUNET_NAMESTORE_disconnect (handle->ns_handle);
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
  struct MHD_Response *resp;
  char *json_error;

  GNUNET_asprintf (&json_error,
                   "{Error while processing request: %s}",
                   handle->emsg);
  resp = GNUNET_REST_create_json_response (json_error);
  handle->proc (handle->proc_cls, resp, MHD_HTTP_BAD_REQUEST);
  cleanup_handle (handle);
  GNUNET_free (json_error);
}

/**
 * Task run on shutdown.  Cleans up everything.
 *
 * @param cls unused
 * @param tc scheduler context
 */
static void
do_cleanup_handle_delayed (void *cls,
          const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct RequestHandle *handle = cls;
  cleanup_handle(handle);
}


/**
 * Get a ticket for identity
 * @param cls the handle
 * @param ticket the ticket returned from the idp
 */
static void
token_creat_cont (void *cls,
                  const char *label,
                  const struct GNUNET_IDENTITY_PROVIDER_Ticket *ticket,
                  const struct GNUNET_IDENTITY_PROVIDER_Token *token)
{
  struct JsonApiResource *json_resource;
  struct RequestHandle *handle = cls;
  struct MHD_Response *resp;
  json_t *ticket_json;
  json_t *token_json;
  char *ticket_str;
  char *token_str;
  char *result_str;
  
  if (NULL == ticket)
  {
    handle->emsg = GNUNET_strdup ("Error in token issue");
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }

  handle->resp_object = GNUNET_REST_jsonapi_object_new ();
  json_resource = GNUNET_REST_jsonapi_resource_new (GNUNET_REST_JSONAPI_IDENTITY_PROVIDER_TICKET,
                                                    label);
  ticket_str = GNUNET_IDENTITY_PROVIDER_ticket_to_string (ticket);
  token_str = GNUNET_IDENTITY_PROVIDER_token_to_string (token);
  ticket_json = json_string (ticket_str);
  token_json = json_string (token_str);
  GNUNET_REST_jsonapi_resource_add_attr (json_resource,
                                         GNUNET_REST_JSONAPI_IDENTITY_PROVIDER_TICKET,
                                         ticket_json);
  GNUNET_REST_jsonapi_resource_add_attr (json_resource,
                                         GNUNET_REST_JSONAPI_IDENTITY_PROVIDER_TOKEN,
                                         token_json);
  GNUNET_free (ticket_str);
  GNUNET_free (token_str);
  json_decref (ticket_json);
  json_decref (token_json);
  GNUNET_REST_jsonapi_object_resource_add (handle->resp_object, json_resource);

  GNUNET_REST_jsonapi_data_serialize (handle->resp_object, &result_str);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Result %s\n", result_str);
  resp = GNUNET_REST_create_json_response (result_str);
  handle->proc (handle->proc_cls, resp, MHD_HTTP_OK);
  GNUNET_free (result_str);
  GNUNET_SCHEDULER_add_now (&do_cleanup_handle_delayed, handle);


}

/**
 * Continueationf for token issue request
 *
 * @param con the Rest handle
 * @param url the requested url
 * @param cls the request handle
 */
static void
issue_token_cont (struct RestConnectionDataHandle *con,
                  const char *url,
                  void *cls)
{
  const struct GNUNET_CRYPTO_EcdsaPrivateKey *priv_key;
  const char *egoname;

  struct RequestHandle *handle = cls;
  struct EgoEntry *ego_entry;
  struct GNUNET_HashCode key;
  struct MHD_Response *resp;
  struct GNUNET_CRYPTO_EcdsaPublicKey pub_key;
  struct GNUNET_CRYPTO_EcdsaPublicKey aud_key;
  struct GNUNET_TIME_Relative etime_rel;
  struct GNUNET_TIME_Absolute exp_time;
  char *ego_val;
  char *audience;
  char *exp_str;
  char *nonce_str;
  char *scopes;
  uint64_t time;
  uint64_t nonce;

  if (GNUNET_NO == GNUNET_REST_namespace_match (handle->url,
                                                GNUNET_REST_API_NS_IDENTITY_TOKEN_ISSUE))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "URL invalid: %s\n", handle->url);
    resp = GNUNET_REST_create_json_response (NULL);
    handle->proc (handle->proc_cls, resp, MHD_HTTP_BAD_REQUEST);
    cleanup_handle (handle);
    return;
  }
  egoname = NULL;
  ego_entry = NULL;
  GNUNET_CRYPTO_hash (GNUNET_REST_JSONAPI_IDENTITY_ISS_REQUEST,
                      strlen (GNUNET_REST_JSONAPI_IDENTITY_ISS_REQUEST),
                      &key);
  if ( GNUNET_YES !=
       GNUNET_CONTAINER_multihashmap_contains (handle->conndata_handle->url_param_map,
                                               &key) )
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Issuer not found\n");
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }
  ego_val = GNUNET_CONTAINER_multihashmap_get (handle->conndata_handle->url_param_map,
                                               &key);
  if (NULL == ego_val)
  {
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Ego invalid: %s\n", ego_val);
    return;
  }
  for (ego_entry = handle->ego_head;
       NULL != ego_entry;
       ego_entry = ego_entry->next)
  {
    if (0 != strcmp (ego_val, ego_entry->identifier))
      continue;
    egoname = ego_entry->identifier;
    break;
  }
  if (NULL == egoname || NULL == ego_entry)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Ego not found: %s\n", ego_val);
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Ego to issue token for: %s\n", egoname);


  //Meta info
  GNUNET_CRYPTO_hash (GNUNET_IDENTITY_TOKEN_ATTR_LIST,
                      strlen (GNUNET_IDENTITY_TOKEN_ATTR_LIST),
                      &key);

  scopes = NULL;
  if ( GNUNET_YES !=
       GNUNET_CONTAINER_multihashmap_contains (handle->conndata_handle->url_param_map,
                                               &key) )
  {
    handle->emsg = GNUNET_strdup ("Scopes missing!\n");
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }
  scopes = GNUNET_CONTAINER_multihashmap_get (handle->conndata_handle->url_param_map,
                                              &key);


  //Token audience
  GNUNET_CRYPTO_hash (GNUNET_REST_JSONAPI_IDENTITY_AUD_REQUEST,
                      strlen (GNUNET_REST_JSONAPI_IDENTITY_AUD_REQUEST),
                      &key);
  audience = NULL;
  if ( GNUNET_YES !=
       GNUNET_CONTAINER_multihashmap_contains (handle->conndata_handle->url_param_map,
                                               &key) )
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Audience missing!\n");
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }
  audience = GNUNET_CONTAINER_multihashmap_get (handle->conndata_handle->url_param_map,
                                                &key);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Audience to issue token for: %s\n", audience);

  priv_key = GNUNET_IDENTITY_ego_get_private_key (ego_entry->ego);
  GNUNET_IDENTITY_ego_get_public_key (ego_entry->ego,
                                      &pub_key);
  GNUNET_STRINGS_string_to_data (audience,
                                 strlen (audience),
                                 &aud_key,
                                 sizeof (struct GNUNET_CRYPTO_EcdsaPublicKey));

  //Remote nonce 
  nonce_str = NULL;
  GNUNET_CRYPTO_hash (GNUNET_IDENTITY_TOKEN_REQUEST_NONCE,
                      strlen (GNUNET_IDENTITY_TOKEN_REQUEST_NONCE),
                      &key);
  if ( GNUNET_YES !=
       GNUNET_CONTAINER_multihashmap_contains (handle->conndata_handle->url_param_map,
                                               &key) )
  {
    handle->emsg = GNUNET_strdup ("Request nonce missing!\n");
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }
  nonce_str = GNUNET_CONTAINER_multihashmap_get (handle->conndata_handle->url_param_map,
                                                 &key);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Request nonce: %s\n", nonce_str);
  sscanf (nonce_str, "%lu", &nonce);

  //Get expiration for token from URL parameter
  GNUNET_CRYPTO_hash (GNUNET_IDENTITY_TOKEN_EXP_STRING,
                      strlen (GNUNET_IDENTITY_TOKEN_EXP_STRING),
                      &key);

  exp_str = NULL;
  if (GNUNET_YES == GNUNET_CONTAINER_multihashmap_contains (handle->conndata_handle->url_param_map,
                                                            &key))
  {
    exp_str = GNUNET_CONTAINER_multihashmap_get (handle->conndata_handle->url_param_map,
                                                 &key);
  }
  if (NULL == exp_str) {
    handle->emsg = GNUNET_strdup ("No expiration given!\n");
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }

  if (GNUNET_OK !=
      GNUNET_STRINGS_fancy_time_to_relative (exp_str,
                                             &etime_rel))
  {
    handle->emsg = GNUNET_strdup ("Expiration invalid!\n");
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }
  time = GNUNET_TIME_absolute_get().abs_value_us;
  exp_time.abs_value_us = time + etime_rel.rel_value_us;

  handle->idp = GNUNET_IDENTITY_PROVIDER_connect (cfg);
  handle->idp_op = GNUNET_IDENTITY_PROVIDER_issue_token (handle->idp,
                                                         priv_key,
                                                         &aud_key,
                                                         scopes,
                                                         exp_time,
                                                         nonce,
                                                         &token_creat_cont,
                                                         handle);

}


/**
 * Build a GNUid token for identity
 *
 * @param cls the request handle
 * @param tc task context
 */
static void
return_token_list (void *cls,
                   const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  char* result_str;
  struct RequestHandle *handle = cls;
  struct MHD_Response *resp;

  GNUNET_REST_jsonapi_data_serialize (handle->resp_object, &result_str);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Result %s\n", result_str);
  resp = GNUNET_REST_create_json_response (result_str);
  handle->proc (handle->proc_cls, resp, MHD_HTTP_OK);
  GNUNET_free (result_str);
  cleanup_handle (handle);
}

/**
 * Collect all tokens for an ego
 *
 * TODO move this into the identity-provider service
 *
 */
static void
token_collect (void *cls,
               const struct GNUNET_CRYPTO_EcdsaPrivateKey *zone,
               const char *label,
               unsigned int rd_count,
               const struct GNUNET_GNSRECORD_Data *rd)
{
  int i;
  char* data;
  struct RequestHandle *handle = cls;
  struct EgoEntry *ego_tmp;
  struct JsonApiResource *json_resource;
  const struct GNUNET_CRYPTO_EcdsaPrivateKey *priv_key;
  json_t *issuer;
  json_t *token;

  if (NULL == label)
  {
    ego_tmp = handle->ego_head;
    GNUNET_CONTAINER_DLL_remove (handle->ego_head,
                                 handle->ego_tail,
                                 ego_tmp);
    GNUNET_free (ego_tmp->identifier);
    GNUNET_free (ego_tmp->keystring);
    GNUNET_free (ego_tmp);

    if (NULL == handle->ego_head)
    {
      //Done
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Adding token END\n");
      handle->ns_it = NULL;
      GNUNET_SCHEDULER_add_now (&return_token_list, handle);
      return;
    }

    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Next ego: %s\n", handle->ego_head->identifier);
    priv_key = GNUNET_IDENTITY_ego_get_private_key (handle->ego_head->ego);
    handle->ns_it = GNUNET_NAMESTORE_zone_iteration_start (handle->ns_handle,
                                                           priv_key,
                                                           &token_collect,
                                                           handle);
    return;
  }

  for (i = 0; i < rd_count; i++)
  {
    if (rd[i].record_type == GNUNET_GNSRECORD_TYPE_ID_TOKEN)
    {
      data = GNUNET_GNSRECORD_value_to_string (rd[i].record_type,
                                               rd[i].data,
                                               rd[i].data_size);
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Adding token: %s\n", data);
      json_resource = GNUNET_REST_jsonapi_resource_new (GNUNET_REST_JSONAPI_IDENTITY_TOKEN,
                                                        label);
      issuer = json_string (handle->ego_head->identifier);
      GNUNET_REST_jsonapi_resource_add_attr (json_resource,
                                             GNUNET_REST_JSONAPI_IDENTITY_ISS_REQUEST,
                                             issuer);
      json_decref (issuer);
      token = json_string (data);
      GNUNET_REST_jsonapi_resource_add_attr (json_resource,
                                             GNUNET_REST_JSONAPI_IDENTITY_TOKEN,
                                             token);
      json_decref (token);

      GNUNET_REST_jsonapi_object_resource_add (handle->resp_object, json_resource);
      GNUNET_free (data);
    }
  }

  GNUNET_NAMESTORE_zone_iterator_next (handle->ns_it);
}



/**
 * Respond to OPTIONS request
 *
 * @param con_handle the connection handle
 * @param url the url
 * @param cls the RequestHandle
 */
static void
list_token_cont (struct RestConnectionDataHandle *con_handle,
                 const char* url,
                 void *cls)
{
  char* ego_val;
  struct GNUNET_HashCode key;
  const struct GNUNET_CRYPTO_EcdsaPrivateKey *priv_key;
  struct RequestHandle *handle = cls;
  struct EgoEntry *ego_entry;
  struct EgoEntry *ego_tmp;

  GNUNET_CRYPTO_hash (GNUNET_REST_JSONAPI_IDENTITY_ISS_REQUEST,
                      strlen (GNUNET_REST_JSONAPI_IDENTITY_ISS_REQUEST),
                      &key);

  if ( GNUNET_YES !=
       GNUNET_CONTAINER_multihashmap_contains (handle->conndata_handle->url_param_map,
                                               &key) )
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "No issuer given.\n");
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }
  ego_val = GNUNET_CONTAINER_multihashmap_get (handle->conndata_handle->url_param_map,
                                               &key);
  //Remove non-matching egos
  for (ego_entry = handle->ego_head;
       NULL != ego_entry;)
  {
    ego_tmp = ego_entry;
    ego_entry = ego_entry->next;
    if (0 != strcmp (ego_val, ego_tmp->identifier))
    {
      GNUNET_CONTAINER_DLL_remove (handle->ego_head,
                                   handle->ego_tail,
                                   ego_tmp);
      GNUNET_free (ego_tmp->identifier);
      GNUNET_free (ego_tmp->keystring);
      GNUNET_free (ego_tmp);
    }
  }
  handle->resp_object = GNUNET_REST_jsonapi_object_new ();
  if (NULL == handle->ego_head)
  {
    //Done
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "No results.\n");
    GNUNET_SCHEDULER_add_now (&return_token_list, handle);
    return;
  }
  priv_key = GNUNET_IDENTITY_ego_get_private_key (handle->ego_head->ego);
  handle->ns_handle = GNUNET_NAMESTORE_connect (cfg);
  handle->ns_it = GNUNET_NAMESTORE_zone_iteration_start (handle->ns_handle,
                                                         priv_key,
                                                         &token_collect,
                                                         handle);

}

/**
 * Return token to requestor
 *
 * @param cls request handle
 * @param token the token
 */
static void
exchange_cont (void *cls,
               const struct GNUNET_IDENTITY_PROVIDER_Token *token)
{
  json_t *root;
  struct RequestHandle *handle = cls;
  struct MHD_Response *resp;
  char* result;
  char* token_str;

  root = json_object ();
  token_str = GNUNET_IDENTITY_PROVIDER_token_to_string (token);
  json_object_set_new (root, "token", json_string (token_str));
  json_object_set_new (root, "token_type", json_string ("jwt"));
  GNUNET_free (token_str);

  result = json_dumps (root, JSON_INDENT(1));
  resp = GNUNET_REST_create_json_response (result);
  GNUNET_free (result);
  handle->proc (handle->proc_cls, resp, MHD_HTTP_OK);
  cleanup_handle (handle);
  json_decref (root); 
}


/**
 *
 * Callback called when identity for token exchange has been found
 *
 * @param cls request handle
 * @param ego the identity to use as issuer
 * @param ctx user context
 * @param name identity name
 *
 */
static void
exchange_token_ticket_cb (void *cls,
                          struct GNUNET_IDENTITY_Ego *ego,
                          void **ctx,
                          const char *name)
{
  struct RequestHandle *handle = cls;
  struct GNUNET_HashCode key;
  struct GNUNET_IDENTITY_PROVIDER_Ticket *ticket;
  char* ticket_str;

  handle->op = NULL;

  if (NULL == ego)
  {
    handle->emsg = GNUNET_strdup ("No identity found.");
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }

  GNUNET_CRYPTO_hash (GNUNET_REST_JSONAPI_IDENTITY_PROVIDER_TICKET,
                      strlen (GNUNET_REST_JSONAPI_IDENTITY_PROVIDER_TICKET),
                      &key);

  if ( GNUNET_NO ==
       GNUNET_CONTAINER_multihashmap_contains (handle->conndata_handle->url_param_map,
                                               &key) )
  {
    handle->emsg = GNUNET_strdup ("No ticket given.");
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }
  ticket_str = GNUNET_CONTAINER_multihashmap_get (handle->conndata_handle->url_param_map,
                                                  &key);

  handle->priv_key = GNUNET_IDENTITY_ego_get_private_key (ego);
  GNUNET_IDENTITY_PROVIDER_string_to_ticket (ticket_str,
                                             &ticket);

  handle->idp = GNUNET_IDENTITY_PROVIDER_connect (cfg);
  handle->idp_op = GNUNET_IDENTITY_PROVIDER_exchange_ticket (handle->idp,
                                                             ticket,
                                                             handle->priv_key,
                                                             &exchange_cont,
                                                             handle);
  GNUNET_IDENTITY_PROVIDER_ticket_destroy (ticket);

}



/**
 * Respond to issue request
 *
 * @param con_handle the connection handle
 * @param url the url
 * @param cls the RequestHandle
 */
static void
exchange_token_ticket_cont (struct RestConnectionDataHandle *con_handle,
                            const char* url,
                            void *cls)
{
  struct RequestHandle *handle = cls;

  //Get token from GNS
  handle->op = GNUNET_IDENTITY_get (handle->identity_handle,
                                    "gns-master",
                                    &exchange_token_ticket_cb,
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
    {MHD_HTTP_METHOD_GET, GNUNET_REST_API_NS_IDENTITY_TOKEN_ISSUE, &issue_token_cont},
    //{MHD_HTTP_METHOD_POST, GNUNET_REST_API_NS_IDENTITY_TOKEN_CHECK, &check_token_cont},
    {MHD_HTTP_METHOD_GET, GNUNET_REST_API_NS_IDENTITY_PROVIDER, &list_token_cont},
    {MHD_HTTP_METHOD_OPTIONS, GNUNET_REST_API_NS_IDENTITY_PROVIDER, &options_cont},
    {MHD_HTTP_METHOD_POST, GNUNET_REST_API_NS_IDENTITY_OAUTH2_TOKEN, &exchange_token_ticket_cont},
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
libgnunet_plugin_rest_identity_provider_init (void *cls)
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
  api->name = GNUNET_REST_API_NS_IDENTITY_PROVIDER;
  api->process_request = &rest_identity_process_request;
  GNUNET_asprintf (&allow_methods,
                   "%s, %s, %s, %s, %s",
                   MHD_HTTP_METHOD_GET,
                   MHD_HTTP_METHOD_POST,
                   MHD_HTTP_METHOD_PUT,
                   MHD_HTTP_METHOD_DELETE,
                   MHD_HTTP_METHOD_OPTIONS);

  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              _("Identity Token REST API initialized\n"));
  return api;
}


/**
 * Exit point from the plugin.
 *
 * @param cls the plugin context (as returned by "init")
 * @return always NULL
 */
void *
libgnunet_plugin_rest_identity_provider_done (void *cls)
{
  struct GNUNET_REST_Plugin *api = cls;
  struct Plugin *plugin = api->cls;

  plugin->cfg = NULL;
  GNUNET_free_non_null (allow_methods);
  GNUNET_free (api);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Identity Token REST plugin is finished\n");
  return NULL;
}

/* end of plugin_rest_gns.c */

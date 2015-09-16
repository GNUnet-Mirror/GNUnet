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
#include "gnunet_gnsrecord_lib.h"
#include "gnunet_namestore_service.h"
#include "gnunet_rest_lib.h"
#include "microhttpd.h"
#include <jansson.h>
#include "gnunet_signatures.h"

/**
 * REST root namespace
 */
#define GNUNET_REST_API_NS_IDENTITY_TOKEN "/token"

/**
 * Issue namespace
 */
#define GNUNET_REST_API_NS_IDENTITY_TOKEN_ISSUE "/token/issue"

/**
 * Check namespace
 */
#define GNUNET_REST_API_NS_IDENTITY_TOKEN_CHECK "/token/check"


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
   * The name to look up
   */
  char *name;

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

  /**
   * JSON header
   */
  json_t *header;

  /**
   * JSON payload
   */
  json_t *payload;

  /**
   * Response object
   */
  struct JsonApiObject *resp_object;

  /**
   * ID Attribute list given
   */
  struct GNUNET_CONTAINER_MultiHashMap *attr_map;


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
  if (NULL != handle->name)
    GNUNET_free (handle->name);
  if (NULL != handle->timeout_task)
    GNUNET_SCHEDULER_cancel (handle->timeout_task);
  if (NULL != handle->identity_handle)
    GNUNET_IDENTITY_disconnect (handle->identity_handle);
  if (NULL != handle->ns_it)
    GNUNET_NAMESTORE_zone_iteration_stop (handle->ns_it);
  if (NULL != handle->ns_qe)
    GNUNET_NAMESTORE_cancel (handle->ns_qe);
  if (NULL != handle->ns_handle)
    GNUNET_NAMESTORE_disconnect (handle->ns_handle);
  if (NULL != handle->attr_map)
    GNUNET_CONTAINER_multihashmap_destroy (handle->attr_map);

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
                   &handle->emsg);

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

void
store_token_cont (void *cls,
                  int32_t success,
                  const char *emsg)
{
  char *result_str;
  struct MHD_Response *resp;
  struct RequestHandle *handle = cls;
  
  handle->ns_qe = NULL;
  if (GNUNET_SYSERR == success)
  {
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }
  GNUNET_REST_jsonapi_data_serialize (handle->resp_object, &result_str);
  GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Result %s\n", result_str);
  resp = GNUNET_REST_create_json_response (result_str);
  handle->proc (handle->proc_cls, resp, MHD_HTTP_OK);
  GNUNET_free (result_str);
  GNUNET_SCHEDULER_add_now (&do_cleanup_handle_delayed, handle);
}


/**
 * Build a GNUid token for identity
 * @param handle the handle
 * @param ego_entry the ego to build the token for
 * @param name name of the ego
 * @param token_aud token audience
 * @param token the resulting gnuid token
 * @return identifier string of token (label)
 */
static void
sign_and_return_token (void *cls,
                       const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  char *header_str;
  char *payload_str;
  char *header_base64;
  char *payload_base64;
  char *sig_str;
  char *lbl_str;
  char *token;
  uint64_t time;
  uint64_t lbl;
  json_t *token_str;
  json_t *name_str;
  const struct GNUNET_CRYPTO_EcdsaPrivateKey *priv_key;
  struct GNUNET_CRYPTO_EcdsaSignature sig;
  struct GNUNET_CRYPTO_EccSignaturePurpose *purpose;
  struct JsonApiResource *json_resource;
  struct RequestHandle *handle = cls;
  struct GNUNET_GNSRECORD_Data token_record;

  time = GNUNET_TIME_absolute_get().abs_value_us;
  lbl = GNUNET_CRYPTO_random_u64 (GNUNET_CRYPTO_QUALITY_STRONG, UINT64_MAX);
  GNUNET_STRINGS_base64_encode ((char*)&lbl, sizeof (uint64_t), &lbl_str);

  json_object_set_new (handle->payload, "lbl", json_string (lbl_str));
  json_object_set_new (handle->payload, "sub", json_string (handle->ego_entry->identifier));
  json_object_set_new (handle->payload, "nbf", json_integer (time));
  json_object_set_new (handle->payload, "iat", json_integer (time));
  json_object_set_new (handle->payload, "exp", json_integer (time+GNUNET_GNUID_TOKEN_EXPIRATION_MICROSECONDS));

  header_str = json_dumps (handle->header, JSON_COMPACT);
  GNUNET_STRINGS_base64_encode (header_str,
                                strlen (header_str),
                                &header_base64);
  char* padding = strtok(header_base64, "=");
  while (NULL != padding)
    padding = strtok(NULL, "=");

  payload_str = json_dumps (handle->payload, JSON_COMPACT);
  GNUNET_STRINGS_base64_encode (payload_str,
                                strlen (payload_str),
                                &payload_base64);
  padding = strtok(payload_base64, "=");
  while (NULL != padding)
    padding = strtok(NULL, "=");

  GNUNET_asprintf (&token, "%s,%s", header_base64, payload_base64);
  priv_key = GNUNET_IDENTITY_ego_get_private_key (handle->ego_entry->ego);
  purpose = 
    GNUNET_malloc (sizeof (struct GNUNET_CRYPTO_EccSignaturePurpose) + 
                   strlen (token));
  purpose->size = 
    htonl (strlen (token) + sizeof (struct GNUNET_CRYPTO_EccSignaturePurpose));
  purpose->purpose = htonl(GNUNET_SIGNATURE_PURPOSE_GNUID_TOKEN);
  memcpy (&purpose[1], token, strlen (token));
  if (GNUNET_OK != GNUNET_CRYPTO_ecdsa_sign (priv_key,
                                             purpose,
                                             &sig))
    GNUNET_break(0);
  GNUNET_free (token);
  sig_str = GNUNET_STRINGS_data_to_string_alloc (&sig,
                                                 sizeof (struct GNUNET_CRYPTO_EcdsaSignature));
  GNUNET_asprintf (&token, "%s.%s.%s",
                   header_base64, payload_base64, sig_str);
  GNUNET_free (sig_str);
  GNUNET_free (header_str);
  GNUNET_free (header_base64);
  GNUNET_free (payload_str);
  GNUNET_free (payload_base64);
  GNUNET_free (purpose);
  json_decref (handle->header);
  json_decref (handle->payload);

  handle->resp_object = GNUNET_REST_jsonapi_object_new ();

  json_resource = GNUNET_REST_jsonapi_resource_new (GNUNET_REST_JSONAPI_IDENTITY_TOKEN,
                                                    lbl_str);
  name_str = json_string (handle->ego_entry->identifier);
  GNUNET_REST_jsonapi_resource_add_attr (json_resource,
                                         GNUNET_REST_JSONAPI_IDENTITY_ISS_REQUEST,
                                         name_str);
  json_decref (name_str);



  token_str = json_string (token);
  GNUNET_REST_jsonapi_resource_add_attr (json_resource,
                                         GNUNET_REST_JSONAPI_IDENTITY_TOKEN,
                                         token_str);
  GNUNET_REST_jsonapi_object_resource_add (handle->resp_object, json_resource);
  token_record.data = token;
  token_record.data_size = strlen (token);
  token_record.expiration_time = time+GNUNET_GNUID_TOKEN_EXPIRATION_MICROSECONDS;
  token_record.record_type = GNUNET_GNSRECORD_TYPE_ID_TOKEN;
  token_record.flags = GNUNET_GNSRECORD_RF_NONE;
  //Persist token
  handle->ns_qe = GNUNET_NAMESTORE_records_store (handle->ns_handle,
                                                  priv_key,
                                                  lbl_str,
                                                  1,
                                                  &token_record,
                                                  &store_token_cont,
                                                  handle);
  GNUNET_free (lbl_str);
  GNUNET_free (token);
  json_decref (token_str);
}





static void
attr_collect (void *cls,
              const struct GNUNET_CRYPTO_EcdsaPrivateKey *zone,
              const char *label,
              unsigned int rd_count,
              const struct GNUNET_GNSRECORD_Data *rd)
{
  int i;
  char* data;
  json_t *attr_arr;
  struct RequestHandle *handle = cls;
  struct GNUNET_HashCode key;

  if (NULL == label)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Adding attribute END: \n");
    handle->ns_it = NULL;
    GNUNET_SCHEDULER_add_now (&sign_and_return_token, handle);
    return;
  }

  GNUNET_CRYPTO_hash (label,
                      strlen (label),
                      &key);

  if (0 == rd_count ||
      ( (NULL != handle->attr_map) &&
        (GNUNET_YES != GNUNET_CONTAINER_multihashmap_contains (handle->attr_map,
                                                               &key))
      )
     )
  {
    GNUNET_NAMESTORE_zone_iterator_next (handle->ns_it);
    return;
  }

  GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Adding attribute: %s\n", label);

  if (1 == rd_count)
  {
    if (rd->record_type == GNUNET_GNSRECORD_TYPE_ID_ATTR)
    {
      data = GNUNET_GNSRECORD_value_to_string (rd->record_type,
                                               rd->data,
                                               rd->data_size);
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Adding value: %s\n", data);
      json_object_set_new (handle->payload, label, json_string (data));
      GNUNET_free (data);
    }
    GNUNET_NAMESTORE_zone_iterator_next (handle->ns_it);
    return;
  }

  i = 0;
  attr_arr = json_array();
  for (; i < rd_count; i++)
  {
    if (rd->record_type == GNUNET_GNSRECORD_TYPE_ID_ATTR)
    {
      data = GNUNET_GNSRECORD_value_to_string (rd[i].record_type,
                                               rd[i].data,
                                               rd[i].data_size);
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Adding value: %s\n", data);
      json_array_append_new (attr_arr, json_string (data));
      GNUNET_free (data);
    }
  }

  if (0 < json_array_size (attr_arr))
  {
    json_object_set (handle->payload, label, attr_arr);
  }
  json_decref (attr_arr);
  GNUNET_NAMESTORE_zone_iterator_next (handle->ns_it);
}


/**
 * Create a response with requested ego(s)
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
  const char *egoname;
  char *ego_val;
  char *audience;
  struct RequestHandle *handle = cls;
  struct EgoEntry *ego_entry;
  struct GNUNET_HashCode key;
  struct MHD_Response *resp;
  const struct GNUNET_CRYPTO_EcdsaPrivateKey *priv_key;

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
  if ( GNUNET_YES ==
       GNUNET_CONTAINER_multihashmap_contains (handle->conndata_handle->url_param_map,
                                               &key) )
  {
    ego_val = GNUNET_CONTAINER_multihashmap_get (handle->conndata_handle->url_param_map,
                                                 &key);
    if (NULL == ego_val)
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Ego invalid: %s\n", ego_val);
    if (NULL != ego_val)
    {
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
        resp = GNUNET_REST_create_json_response (NULL);
        handle->proc (handle->proc_cls, resp, MHD_HTTP_BAD_REQUEST);
        cleanup_handle (handle);
        return;
      }
    }
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Ego to issue token for: %s\n", egoname);
  GNUNET_CRYPTO_hash (GNUNET_REST_JSONAPI_IDENTITY_AUD_REQUEST,
                      strlen (GNUNET_REST_JSONAPI_IDENTITY_AUD_REQUEST),
                      &key);

  //Token audience
  audience = NULL;
  if ( GNUNET_YES !=
       GNUNET_CONTAINER_multihashmap_contains (handle->conndata_handle->url_param_map,
                                               &key) )
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Audience missing!\n");
    resp = GNUNET_REST_create_json_response (NULL);
    handle->proc (handle->proc_cls, resp, MHD_HTTP_BAD_REQUEST);
    cleanup_handle (handle);
    return;
  }
  audience = GNUNET_CONTAINER_multihashmap_get (handle->conndata_handle->url_param_map,
                                                &key);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Audience to issue token for: %s\n", audience);
  handle->header = json_object ();
  json_object_set_new (handle->header, "alg", json_string ("ED512"));
  json_object_set_new (handle->header, "typ", json_string ("JWT"));

  handle->payload = json_object ();
  json_object_set_new (handle->payload, "iss", json_string (ego_entry->keystring));
  json_object_set_new (handle->payload, "aud", json_string (audience));


  //Get identity attributes
  handle->ns_handle = GNUNET_NAMESTORE_connect (cfg);
  priv_key = GNUNET_IDENTITY_ego_get_private_key (ego_entry->ego);
  handle->ego_entry = ego_entry;
  handle->ns_it = GNUNET_NAMESTORE_zone_iteration_start (handle->ns_handle,
                                                         priv_key,
                                                         &attr_collect,
                                                         handle);
}


/**
 * Build a GNUid token for identity
 * @param handle the handle
 * @param ego_entry the ego to build the token for
 * @param name name of the ego
 * @param token_aud token audience
 * @param token the resulting gnuid token
 * @return identifier string of token (label)
 */
static void
return_token_list (void *cls,
                   const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  char* result_str;
  struct RequestHandle *handle = cls;
  struct MHD_Response *resp;

  GNUNET_REST_jsonapi_data_serialize (handle->resp_object, &result_str);
  GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Result %s\n", result_str);
  resp = GNUNET_REST_create_json_response (result_str);
  handle->proc (handle->proc_cls, resp, MHD_HTTP_OK);
  GNUNET_free (result_str);
  cleanup_handle (handle);
}

/**
 * Collect all tokens for ego
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
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Adding token END\n");
      handle->ns_it = NULL;
      GNUNET_SCHEDULER_add_now (&return_token_list, handle);
      return;
    }

    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Next ego: %s\n", handle->ego_head->identifier);
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
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Adding token: %s\n", data);
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

  if ( GNUNET_YES ==
       GNUNET_CONTAINER_multihashmap_contains (handle->conndata_handle->url_param_map,
                                               &key) )
  {
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
    {MHD_HTTP_METHOD_GET, GNUNET_REST_API_NS_IDENTITY_TOKEN, &list_token_cont},
    {MHD_HTTP_METHOD_OPTIONS, GNUNET_REST_API_NS_IDENTITY_TOKEN, &options_cont},
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
  struct GNUNET_HashCode key;
  char* attr_list;
  char* attr_list_tmp;
  char* attr;

  GNUNET_CRYPTO_hash (GNUNET_IDENTITY_TOKEN_ATTR_LIST,
                      strlen (GNUNET_IDENTITY_TOKEN_ATTR_LIST),
                      &key);

  handle->timeout = GNUNET_TIME_UNIT_FOREVER_REL;

  handle->proc_cls = proc_cls;
  handle->proc = proc;
  handle->state = ID_REST_STATE_INIT;
  handle->conndata_handle = conndata_handle;
  handle->data = conndata_handle->data;
  handle->data_size = conndata_handle->data_size;
  handle->method = conndata_handle->method;
  if (GNUNET_YES == GNUNET_CONTAINER_multihashmap_contains (handle->conndata_handle->url_param_map,
                                                            &key))
  {
    handle->attr_map = GNUNET_CONTAINER_multihashmap_create (5,
                                                             GNUNET_NO);
    attr_list = GNUNET_CONTAINER_multihashmap_get (handle->conndata_handle->url_param_map,
                                                   &key);
    if (NULL != attr_list)
    {
      attr_list_tmp = GNUNET_strdup (attr_list);
      attr = strtok(attr_list_tmp, ",");
      for (; NULL != attr; attr = strtok (NULL, ","))
      {
        GNUNET_CRYPTO_hash (attr,
                            strlen (attr),
                            &key);
        GNUNET_CONTAINER_multihashmap_put (handle->attr_map,
                                           &key,
                                           attr,
                                           GNUNET_CONTAINER_MULTIHASHMAPOPTION_REPLACE);
      }
      GNUNET_free (attr_list_tmp);
    }
  }


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
libgnunet_plugin_rest_identity_token_init (void *cls)
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
  api->name = GNUNET_REST_API_NS_IDENTITY_TOKEN;
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
libgnunet_plugin_rest_identity_token_done (void *cls)
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

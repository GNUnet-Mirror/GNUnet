/*
   This file is part of GNUnet.
   Copyright (C) 2012-2016 GNUnet e.V.

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
 * @file gns/plugin_rest_credential.c
 * @brief GNUnet CREDENTIAL REST plugin
 *
 */

#include "platform.h"
#include "gnunet_rest_plugin.h"
#include <gnunet_identity_service.h>
#include <gnunet_gnsrecord_lib.h>
#include <gnunet_namestore_service.h>
#include <gnunet_credential_service.h>
#include <gnunet_rest_lib.h>
#include <gnunet_jsonapi_lib.h>
#include <gnunet_jsonapi_util.h>
#include <jansson.h>

#define GNUNET_REST_API_NS_CREDENTIAL "/credential"

#define GNUNET_REST_JSONAPI_CREDENTIAL "credential"

#define GNUNET_REST_JSONAPI_CREDENTIAL_TYPEINFO "credential"

#define GNUNET_REST_JSONAPI_CREDENTIAL_CHAIN "chain"

#define GNUNET_REST_JSONAPI_CREDENTIAL_ISSUER_ATTR "attribute"

#define GNUNET_REST_JSONAPI_CREDENTIAL_SUBJECT_ATTR "credential"

/**
 * @brief struct returned by the initialization function of the plugin
 */
struct Plugin
{
  const struct GNUNET_CONFIGURATION_Handle *cfg;
};

const struct GNUNET_CONFIGURATION_Handle *cfg;

struct VerifyHandle
{
  /**
   * Handle to Credential service.
   */
  struct GNUNET_CREDENTIAL_Handle *credential;

  /**
   * Handle to lookup request
   */
  struct GNUNET_CREDENTIAL_Request *verify_request;

  /**
   * Handle to rest request
   */
  struct GNUNET_REST_RequestHandle *rest_handle;

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
   * The issuer attribute to verify
   */
  char *issuer_attr;

  /**
   * The subject attribute
   */
  char *subject_attr;

  /**
   * The public key of the issuer
   */
  struct GNUNET_CRYPTO_EcdsaPublicKey issuer_key;

  /**
   * The public key of the subject
   */
  struct GNUNET_CRYPTO_EcdsaPublicKey subject_key;

  /**
   * HTTP response code
   */
  int response_code;

  /**
   * Timeout
   */
  struct GNUNET_TIME_Relative timeout;

};


/**
 * Cleanup lookup handle.
 *
 * @param handle Handle to clean up
 */
static void
cleanup_handle (struct VerifyHandle *handle)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Cleaning up\n");
  if (NULL != handle->json_root)
    json_decref (handle->json_root);

  if (NULL != handle->issuer_attr)
    GNUNET_free (handle->issuer_attr);
  if (NULL != handle->subject_attr)
    GNUNET_free (handle->subject_attr);
  if (NULL != handle->verify_request)
  {
    GNUNET_CREDENTIAL_verify_cancel (handle->verify_request);
    handle->verify_request = NULL;
  }
  if (NULL != handle->credential)
  {
    GNUNET_CREDENTIAL_disconnect (handle->credential);
    handle->credential = NULL;
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
  struct VerifyHandle *handle = cls;
  struct MHD_Response *resp;

  resp = GNUNET_REST_create_response (NULL);
  handle->proc (handle->proc_cls, resp, handle->response_code);
  cleanup_handle (handle);
}

/**
 * Attribute delegation to JSON
 * @param attr the attribute
 * @return JSON, NULL if failed
 */
static json_t*
attribute_delegation_to_json (struct GNUNET_CREDENTIAL_Delegation *delegation_chain_entry)
{
  char *subject;
  char *issuer;
  json_t *attr_obj;

  issuer = GNUNET_CRYPTO_ecdsa_public_key_to_string (&delegation_chain_entry->issuer_key);
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Issuer in delegation malformed\n");
    return NULL;
  }
  subject = GNUNET_CRYPTO_ecdsa_public_key_to_string (&delegation_chain_entry->subject_key);
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Subject in credential malformed\n");
    GNUNET_free (issuer);
    return NULL;
  }
  attr_obj = json_object ();

  json_object_set_new (attr_obj, "subject", json_string (subject));
  json_object_set_new (attr_obj, "issuer", json_string (issuer));
  json_object_set_new (attr_obj, "issuer_attribute",
                       json_string (delegation_chain_entry->issuer_attribute));

  if (0 < delegation_chain_entry->subject_attribute_len)
  {
    json_object_set_new (attr_obj, "subject_attribute",
                         json_string (delegation_chain_entry->subject_attribute));
  }
  GNUNET_free (subject);
  return attr_obj;
}

/**
 * Credential to JSON
 * @param cred the credential
 * @return the resulting json, NULL if failed
 */
static json_t*
credential_to_json (struct GNUNET_CREDENTIAL_Credential *cred)
{
  char *issuer;
  char *subject;
  char attribute[cred->issuer_attribute_len + 1];
  json_t *cred_obj;

  issuer = GNUNET_CRYPTO_ecdsa_public_key_to_string (&cred->issuer_key);
  if (NULL == issuer)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Issuer in credential malformed\n");
    return NULL;
  }  
  subject = GNUNET_CRYPTO_ecdsa_public_key_to_string (&cred->subject_key);
  if (NULL == subject)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Subject in credential malformed\n");
    GNUNET_free (issuer);
    return NULL;
  }
  memcpy (attribute,
          cred->issuer_attribute,
          cred->issuer_attribute_len);
  attribute[cred->issuer_attribute_len] = '\0';
  cred_obj = json_object ();
  json_object_set_new (cred_obj, "issuer", json_string (issuer));
  json_object_set_new (cred_obj, "subject", json_string (subject));
  json_object_set_new (cred_obj, "attribute", json_string (attribute));
  GNUNET_free (issuer);
  GNUNET_free (subject);
  return cred_obj;
}

/**
 * Function called with the result of a Credential lookup.
 *
 * @param cls the 'const char *' name that was resolved
 * @param cd_count number of records returned
 * @param cd array of @a cd_count records with the results
 */
static void
handle_verify_response (void *cls,
                        unsigned int d_count,
                        struct GNUNET_CREDENTIAL_Delegation *delegation_chain,
                        struct GNUNET_CREDENTIAL_Credential *cred)
{

  struct VerifyHandle *handle = cls;
  struct MHD_Response *resp;
  struct GNUNET_JSONAPI_Document *json_document;
  struct GNUNET_JSONAPI_Resource *json_resource;
  json_t *cred_obj;
  json_t *attr_obj;
  json_t *result_array;
  char *result;
  uint32_t i;

  handle->verify_request = NULL;
  if (NULL == cred) {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Verify failed.\n");
    handle->response_code = MHD_HTTP_NOT_FOUND;
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }
  json_document = GNUNET_JSONAPI_document_new ();
  json_resource = GNUNET_JSONAPI_resource_new (GNUNET_REST_JSONAPI_CREDENTIAL_TYPEINFO,
                                               handle->issuer_attr);
  cred_obj = credential_to_json (cred);
  result_array = json_array ();
  for (i = 0; i < d_count; i++)
  {
    attr_obj = attribute_delegation_to_json (&delegation_chain[i]);
    json_array_append (result_array, attr_obj);
    json_decref (attr_obj);
  }
  GNUNET_JSONAPI_resource_add_attr (json_resource,
                                    GNUNET_REST_JSONAPI_CREDENTIAL,
                                    cred_obj);
  GNUNET_JSONAPI_resource_add_attr (json_resource,
                                    GNUNET_REST_JSONAPI_CREDENTIAL_CHAIN,
                                    result_array);
  GNUNET_JSONAPI_document_resource_add (json_document, json_resource);
  GNUNET_JSONAPI_document_serialize (json_document, &result);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Result %s\n",
              result);
  json_decref (result_array);
  GNUNET_JSONAPI_document_delete (json_document);
  resp = GNUNET_REST_create_response (result);
  handle->proc (handle->proc_cls, resp, MHD_HTTP_OK);
  GNUNET_free (result);
  cleanup_handle (handle);
}


static void
verify_cred_cont (struct GNUNET_REST_RequestHandle *conndata_handle,
                  const char* url,
                  void *cls)
{
  struct VerifyHandle *handle = cls;
  struct GNUNET_HashCode key;
  char *tmp;
  char *entity_attr;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Connecting...\n");
  handle->credential = GNUNET_CREDENTIAL_connect (cfg);
  handle->timeout_task = GNUNET_SCHEDULER_add_delayed (handle->timeout,
                                                       &do_error, handle);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Connected\n");
  if (NULL == handle->credential)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Connecting to CREDENTIAL failed\n");
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }
  GNUNET_CRYPTO_hash (GNUNET_REST_JSONAPI_CREDENTIAL_ISSUER_ATTR,
                      strlen (GNUNET_REST_JSONAPI_CREDENTIAL_ISSUER_ATTR),
                      &key);
  if ( GNUNET_NO ==
       GNUNET_CONTAINER_multihashmap_contains (conndata_handle->url_param_map,
                                               &key) )
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Missing issuer attribute\n");
    GNUNET_SCHEDULER_add_now (&do_error, handle); 
    return;
  }
  tmp = GNUNET_CONTAINER_multihashmap_get (conndata_handle->url_param_map,
                                           &key);
  entity_attr = GNUNET_strdup (tmp);
  tmp = strtok(entity_attr, ".");
  if (NULL == tmp)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Malformed issuer or attribute\n");
    GNUNET_free (entity_attr);
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }
  if (GNUNET_OK != 
      GNUNET_CRYPTO_ecdsa_public_key_from_string (tmp,
                                                  strlen (tmp),
                                                  &handle->issuer_key))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Malformed issuer key\n");
    GNUNET_free (entity_attr);
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }
  tmp = strtok (NULL, "."); //Issuer attribute
  if (NULL == tmp)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Malformed attribute\n");
    GNUNET_free (entity_attr);
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }
  handle->issuer_attr = GNUNET_strdup (tmp);
  GNUNET_free (entity_attr);

  GNUNET_CRYPTO_hash (GNUNET_REST_JSONAPI_CREDENTIAL_SUBJECT_ATTR,
                      strlen (GNUNET_REST_JSONAPI_CREDENTIAL_SUBJECT_ATTR),
                      &key);
  if ( GNUNET_NO ==
       GNUNET_CONTAINER_multihashmap_contains (conndata_handle->url_param_map,
                                               &key) )
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Missing subject or attribute\n");
    GNUNET_free (entity_attr);
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }
  tmp = GNUNET_CONTAINER_multihashmap_get (conndata_handle->url_param_map,
                                           &key);
  entity_attr = GNUNET_strdup (tmp);
  tmp = strtok(entity_attr, ".");
  if (NULL == tmp)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Malformed subject\n");
    GNUNET_free (entity_attr);
    GNUNET_SCHEDULER_add_now (&do_error, handle); 
    return;
  }
  if (GNUNET_OK !=
      GNUNET_CRYPTO_ecdsa_public_key_from_string (tmp,
                                                  strlen (tmp),
                                                  &handle->subject_key)) {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Malformed subject key\n");
    GNUNET_free (entity_attr);
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }
  tmp = strtok (NULL, ".");
  if (NULL == tmp)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Malformed subject attribute\n");
    GNUNET_free (entity_attr);
    GNUNET_SCHEDULER_add_now (&do_error, handle); 
    return;
  }
  handle->subject_attr = GNUNET_strdup (tmp);
  GNUNET_free (entity_attr);

  handle->verify_request = GNUNET_CREDENTIAL_verify (handle->credential,
                                                     &handle->issuer_key,
                                                     handle->issuer_attr,
                                                     &handle->subject_key,
                                                     handle->subject_attr,
                                                     &handle_verify_response,
                                                     handle);

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
  struct VerifyHandle *handle = cls;

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
 * @param proc_cls closure for callback function
 * @return GNUNET_OK if request accepted
 */
static void
rest_credential_process_request(struct GNUNET_REST_RequestHandle *conndata_handle,
                                GNUNET_REST_ResultProcessor proc,
                                void *proc_cls)
{
  struct VerifyHandle *handle = GNUNET_new (struct VerifyHandle);
  struct GNUNET_REST_RequestHandlerError err;

  handle->timeout = GNUNET_TIME_UNIT_FOREVER_REL;
  handle->proc_cls = proc_cls;
  handle->proc = proc;
  handle->rest_handle = conndata_handle;

  static const struct GNUNET_REST_RequestHandler handlers[] = {
    {MHD_HTTP_METHOD_GET, GNUNET_REST_API_NS_CREDENTIAL, &verify_cred_cont},
    {MHD_HTTP_METHOD_OPTIONS, GNUNET_REST_API_NS_CREDENTIAL, &options_cont},
    GNUNET_REST_HANDLER_END
  };

  if (GNUNET_NO == GNUNET_JSONAPI_handle_request (conndata_handle,
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
libgnunet_plugin_rest_credential_init (void *cls)
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
  api->name = GNUNET_REST_API_NS_CREDENTIAL;
  api->process_request = &rest_credential_process_request;
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
libgnunet_plugin_rest_credential_done (void *cls)
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

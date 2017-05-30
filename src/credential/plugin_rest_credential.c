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

#define GNUNET_REST_API_NS_CREDENTIAL_ISSUE "/credential/issue"

#define GNUNET_REST_API_NS_CREDENTIAL_VERIFY "/credential/verify"

#define GNUNET_REST_API_NS_CREDENTIAL_COLLECT "/credential/collect"

#define GNUNET_REST_JSONAPI_CREDENTIAL_EXPIRATION "expiration"

#define GNUNET_REST_JSONAPI_CREDENTIAL_SUBJECT_KEY "subject_key"

#define GNUNET_REST_JSONAPI_CREDENTIAL_SUBJECT_EGO "subject"

#define GNUNET_REST_JSONAPI_CREDENTIAL "credential"

#define GNUNET_REST_JSONAPI_CREDENTIAL_TYPEINFO "credential"

#define GNUNET_REST_JSONAPI_DELEGATIONS "delegations"

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

struct RequestHandle
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
   * Handle to issue request
   */
  struct GNUNET_CREDENTIAL_Request *issue_request;

  /**
   * Handle to identity
   */
  struct GNUNET_IDENTITY_Handle *identity;

  /**
   * Handle to identity operation
   */
  struct GNUNET_IDENTITY_Operation *id_op;

  /**
   * Handle to ego lookup
   */
  struct GNUNET_IDENTITY_EgoLookup *ego_lookup;

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
cleanup_handle (struct RequestHandle *handle)
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
    GNUNET_CREDENTIAL_request_cancel (handle->verify_request);
  if (NULL != handle->credential)
    GNUNET_CREDENTIAL_disconnect (handle->credential);
  if (NULL != handle->id_op)
    GNUNET_IDENTITY_cancel (handle->id_op);
  if (NULL != handle->ego_lookup)
    GNUNET_IDENTITY_ego_lookup_cancel (handle->ego_lookup);
  if (NULL != handle->identity)
    GNUNET_IDENTITY_disconnect (handle->identity);
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
  struct RequestHandle *handle = cls;
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
  if (NULL == issuer)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Issuer in delegation malformed\n");
    return NULL;
  }
  subject = GNUNET_CRYPTO_ecdsa_public_key_to_string (&delegation_chain_entry->subject_key);
  if (NULL == subject)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Subject in credential malformed\n");
    GNUNET_free (issuer);
    return NULL;
  }
  attr_obj = json_object ();

    json_object_set_new (attr_obj, "issuer", json_string (issuer));
  json_object_set_new (attr_obj, "issuer_attribute",
                       json_string (delegation_chain_entry->issuer_attribute));

  json_object_set_new (attr_obj, "subject", json_string (subject));
  if (0 < delegation_chain_entry->subject_attribute_len)
  {
    json_object_set_new (attr_obj, "subject_attribute",
                         json_string (delegation_chain_entry->subject_attribute));
  }
  GNUNET_free (issuer);
  GNUNET_free (subject);
  return attr_obj;
}

/**
 * JSONAPI resource to Credential
 * @param res the JSONAPI resource
 * @return the resulting credential, NULL if failed
 */
static struct GNUNET_CREDENTIAL_Credential*
json_to_credential (json_t *res)
{
  struct GNUNET_CREDENTIAL_Credential *cred;
  json_t *tmp;
  const char *attribute;
  const char *signature;
  char *sig;

  tmp = json_object_get (res, "attribute");
  if (0 == json_is_string (tmp))
  {
    return NULL;
  }
  attribute = json_string_value (tmp);
  cred = GNUNET_malloc (sizeof (struct GNUNET_CREDENTIAL_Credential)
                        + strlen (attribute));
  cred->issuer_attribute = attribute;
  cred->issuer_attribute_len = strlen (attribute);
  tmp = json_object_get (res, "issuer");
  if (0 == json_is_string (tmp))
  {
    GNUNET_free (cred);
    return NULL;
  }

  GNUNET_CRYPTO_ecdsa_public_key_from_string (json_string_value(tmp),
                                              strlen (json_string_value(tmp)),
                                              &cred->issuer_key);
  tmp = json_object_get (res, "subject");
  if (0 == json_is_string (tmp))
  {
    GNUNET_free (cred);
    return NULL;
  }
  GNUNET_CRYPTO_ecdsa_public_key_from_string (json_string_value(tmp),
                                              strlen (json_string_value(tmp)),
                                              &cred->subject_key);

  tmp = json_object_get (res, "signature");
  if (0 == json_is_string (tmp))
  {
    GNUNET_free (cred);
    return NULL;
  }
  signature = json_string_value (tmp);
  GNUNET_STRINGS_base64_decode (signature,
                                strlen (signature),
                                (char**)&sig);
  GNUNET_memcpy (&cred->signature,
                 sig,
                 sizeof (struct GNUNET_CRYPTO_EcdsaSignature));
  GNUNET_free (sig);
 
  tmp = json_object_get (res, "expiration");
  if (0 == json_is_integer (tmp))
  {
    GNUNET_free (cred);
    return NULL;
  }
  cred->expiration.abs_value_us = json_integer_value (tmp); 
  return cred;
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
  char *signature;
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
  GNUNET_STRINGS_base64_encode ((char*)&cred->signature,
                                sizeof (struct GNUNET_CRYPTO_EcdsaSignature),
                                &signature);
  memcpy (attribute,
          cred->issuer_attribute,
          cred->issuer_attribute_len);
  attribute[cred->issuer_attribute_len] = '\0';
  cred_obj = json_object ();
  json_object_set_new (cred_obj, "issuer", json_string (issuer));
  json_object_set_new (cred_obj, "subject", json_string (subject));
  json_object_set_new (cred_obj, "attribute", json_string (attribute));
  json_object_set_new (cred_obj, "signature", json_string (signature));
  json_object_set_new (cred_obj, "expiration", json_integer (cred->expiration.abs_value_us));
  GNUNET_free (issuer);
  GNUNET_free (subject);
  GNUNET_free (signature);
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
handle_collect_response (void *cls,
                        unsigned int d_count,
                        struct GNUNET_CREDENTIAL_Delegation *delegation_chain,
                        unsigned int c_count,
                        struct GNUNET_CREDENTIAL_Credential *cred)
{
  struct RequestHandle *handle = cls;
  struct MHD_Response *resp;
  struct GNUNET_JSONAPI_Document *json_document;
  struct GNUNET_JSONAPI_Resource *json_resource;
  json_t *cred_obj;
  json_t *cred_array;
  char *result;
  char *issuer;
  char *id;
  uint32_t i;

  handle->verify_request = NULL;
  if (NULL == cred) {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Verify failed.\n");
    handle->response_code = MHD_HTTP_NOT_FOUND;
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }
  issuer = GNUNET_CRYPTO_ecdsa_public_key_to_string (&handle->issuer_key);
  if (NULL == issuer)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Issuer in delegation malformed\n");
    return;
  }
  GNUNET_asprintf (&id,
                   "%s.%s",
                   issuer,
                   handle->issuer_attr);
  GNUNET_free (issuer);
  json_document = GNUNET_JSONAPI_document_new ();
  json_resource = GNUNET_JSONAPI_resource_new (GNUNET_REST_JSONAPI_CREDENTIAL_TYPEINFO,
                                               id);
  GNUNET_free (id);
  cred_array = json_array ();
  for (i=0;i<c_count;i++)
  {
    cred_obj = credential_to_json (&cred[i]);
    json_array_append_new (cred_array, cred_obj);
  }
  GNUNET_JSONAPI_resource_add_attr (json_resource,
                                    GNUNET_REST_JSONAPI_CREDENTIAL,
                                    cred_array);
  GNUNET_JSONAPI_document_resource_add (json_document, json_resource);
  GNUNET_JSONAPI_document_serialize (json_document, &result);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Result %s\n",
              result);
  json_decref (cred_array);
  GNUNET_JSONAPI_document_delete (json_document);
  resp = GNUNET_REST_create_response (result);
  GNUNET_free(result);
  handle->proc (handle->proc_cls, resp, MHD_HTTP_OK);
  cleanup_handle (handle);
}

static void
subject_ego_lookup (void *cls,
                    const struct GNUNET_IDENTITY_Ego *ego)
{
  struct RequestHandle *handle = cls;
  const struct GNUNET_CRYPTO_EcdsaPrivateKey *sub_key;
  handle->ego_lookup = NULL;

  if (NULL == ego)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Subject not found\n");
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }
  sub_key = GNUNET_IDENTITY_ego_get_private_key (ego);
  handle->verify_request = GNUNET_CREDENTIAL_collect (handle->credential,
                                                      &handle->issuer_key,
                                                      handle->issuer_attr,
                                                      sub_key,
                                                      &handle_collect_response,
                                                      handle);
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
                        unsigned int c_count,
                        struct GNUNET_CREDENTIAL_Credential *cred)
{

  struct RequestHandle *handle = cls;
  struct MHD_Response *resp;
  struct GNUNET_JSONAPI_Document *json_document;
  struct GNUNET_JSONAPI_Resource *json_resource;
  json_t *cred_obj;
  json_t *attr_obj;
  json_t *cred_array;
  json_t *attr_array;
  char *result;
  char *issuer;
  char *id;
  uint32_t i;

  handle->verify_request = NULL;
  if (NULL == cred) {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Verify failed.\n");
    handle->response_code = MHD_HTTP_NOT_FOUND;
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }
  issuer = GNUNET_CRYPTO_ecdsa_public_key_to_string (&handle->issuer_key);
  if (NULL == issuer)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Issuer in delegation malformed\n");
    return;
  }
  GNUNET_asprintf (&id,
                   "%s.%s",
                   issuer,
                   handle->issuer_attr);
  GNUNET_free (issuer);
  json_document = GNUNET_JSONAPI_document_new ();
  json_resource = GNUNET_JSONAPI_resource_new (GNUNET_REST_JSONAPI_CREDENTIAL_TYPEINFO,
                                               id);
  GNUNET_free (id);
  attr_array = json_array ();
  for (i = 0; i < d_count; i++)
  {
    attr_obj = attribute_delegation_to_json (&delegation_chain[i]);
    json_array_append_new (attr_array, attr_obj);
  }
  cred_array = json_array ();
  for (i=0;i<c_count;i++)
  {
    cred_obj = credential_to_json (&cred[i]);
    json_array_append_new (cred_array, cred_obj);
  }
  GNUNET_JSONAPI_resource_add_attr (json_resource,
                                    GNUNET_REST_JSONAPI_CREDENTIAL,
                                    cred_array);
  GNUNET_JSONAPI_resource_add_attr (json_resource,
                                    GNUNET_REST_JSONAPI_DELEGATIONS,
                                    attr_array);
  GNUNET_JSONAPI_document_resource_add (json_document, json_resource);
  GNUNET_JSONAPI_document_serialize (json_document, &result);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Result %s\n",
              result);
  json_decref (attr_array);
  json_decref (cred_array);
  GNUNET_JSONAPI_document_delete (json_document);
  resp = GNUNET_REST_create_response (result);
  handle->proc (handle->proc_cls, resp, MHD_HTTP_OK);
  GNUNET_free (result);
  cleanup_handle (handle);
}

static void
collect_cred_cont (struct GNUNET_REST_RequestHandle *conndata_handle,
                   const char* url,
                   void *cls)
{
  struct RequestHandle *handle = cls;
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

  GNUNET_CRYPTO_hash (GNUNET_REST_JSONAPI_CREDENTIAL_SUBJECT_EGO,
                      strlen (GNUNET_REST_JSONAPI_CREDENTIAL_SUBJECT_EGO),
                      &key);
  if ( GNUNET_NO ==
       GNUNET_CONTAINER_multihashmap_contains (conndata_handle->url_param_map,
                                               &key) )
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Missing subject\n");
    GNUNET_free (entity_attr);
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }
  tmp = GNUNET_CONTAINER_multihashmap_get (conndata_handle->url_param_map,
                                           &key);
  if (NULL == tmp)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Malformed subject\n");
    GNUNET_free (entity_attr);
    GNUNET_SCHEDULER_add_now (&do_error, handle); 
    return;
  }
  handle->ego_lookup = GNUNET_IDENTITY_ego_lookup (cfg,
                                                   tmp,
                                                   &subject_ego_lookup,
                                                   handle);
}



static void
verify_cred_cont (struct GNUNET_REST_RequestHandle *conndata_handle,
                  const char* url,
                  void *cls)
{
  struct RequestHandle *handle = cls;
  struct GNUNET_HashCode key;
  struct GNUNET_JSONAPI_Document *json_obj;
  struct GNUNET_JSONAPI_Resource *res;
  struct GNUNET_CREDENTIAL_Credential *cred;
  char *tmp;
  char *entity_attr;
  int i;
  uint32_t credential_count;
  uint32_t resource_count;
  json_t *cred_json;
  json_t *data_js;
  json_error_t err;

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

  GNUNET_CRYPTO_hash (GNUNET_REST_JSONAPI_CREDENTIAL_SUBJECT_KEY,
                      strlen (GNUNET_REST_JSONAPI_CREDENTIAL_SUBJECT_KEY),
                      &key);
  if ( GNUNET_NO ==
       GNUNET_CONTAINER_multihashmap_contains (conndata_handle->url_param_map,
                                               &key) )
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Missing subject key\n");
    GNUNET_free (entity_attr);
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }
  tmp = GNUNET_CONTAINER_multihashmap_get (conndata_handle->url_param_map,
                                           &key);
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

  if (0 >= handle->rest_handle->data_size)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Missing credentials\n");
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }

  struct GNUNET_JSON_Specification docspec[] = {
    GNUNET_JSON_spec_jsonapi_document (&json_obj),
    GNUNET_JSON_spec_end()
  };
  char term_data[handle->rest_handle->data_size+1];
  term_data[handle->rest_handle->data_size] = '\0';
  credential_count = 0;
  GNUNET_memcpy (term_data,
                 handle->rest_handle->data,
                 handle->rest_handle->data_size);
  data_js = json_loads (term_data,
                        JSON_DECODE_ANY,
                        &err);
  GNUNET_assert (GNUNET_OK == GNUNET_JSON_parse (data_js, docspec,
                                                 NULL, NULL));
  json_decref (data_js);
  if (NULL == json_obj)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Unable to parse JSONAPI Object from %s\n",
                term_data);
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }

  resource_count = GNUNET_JSONAPI_document_resource_count(json_obj);
  GNUNET_assert (1 == resource_count);
  res = (GNUNET_JSONAPI_document_get_resource(json_obj, 0));
  if (GNUNET_NO == GNUNET_JSONAPI_resource_check_type(res,
                                                      GNUNET_REST_JSONAPI_CREDENTIAL_TYPEINFO))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Resource not a credential!\n");
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Unable to parse JSONAPI Object from %s\n",
                term_data);
    GNUNET_JSONAPI_document_delete (json_obj);
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }
  cred_json = GNUNET_JSONAPI_resource_read_attr (res,
                                                 GNUNET_REST_JSONAPI_CREDENTIAL);

  GNUNET_assert (json_is_array (cred_json));

  credential_count = json_array_size(cred_json);

  struct GNUNET_CREDENTIAL_Credential credentials[credential_count];
  for (i=0;i<credential_count;i++)
  {
    cred = json_to_credential (json_array_get (cred_json, i));
    if (NULL == cred)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  "Unable to parse credential!\n");
      continue;
    }
    GNUNET_memcpy (&credentials[i],
                   cred,
                   sizeof (struct GNUNET_CREDENTIAL_Credential));
    credentials[i].issuer_attribute = GNUNET_strdup (cred->issuer_attribute);
    GNUNET_free (cred);
  }
  GNUNET_JSONAPI_document_delete(json_obj);
  handle->verify_request = GNUNET_CREDENTIAL_verify (handle->credential,
                                                     &handle->issuer_key,
                                                     handle->issuer_attr,
                                                     &handle->subject_key,
                                                     credential_count,
                                                     credentials,
                                                     &handle_verify_response,
                                                     handle);
  for (i=0;i<credential_count;i++)
    GNUNET_free ((char*)credentials[i].issuer_attribute);

}

void
send_cred_response (struct RequestHandle *handle,
                    struct GNUNET_CREDENTIAL_Credential *cred)
{
  struct MHD_Response *resp;
  struct GNUNET_JSONAPI_Document *json_document;
  struct GNUNET_JSONAPI_Resource *json_resource;
  json_t *cred_obj;
  char *result;
  char *issuer;
  char *subject;
  char *signature;
  char *id;

  GNUNET_assert (NULL != cred);
  issuer = GNUNET_CRYPTO_ecdsa_public_key_to_string (&cred->issuer_key);
  if (NULL == issuer)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Subject malformed\n");
    return;
  }
  GNUNET_asprintf (&id,
                   "%s.%s",
                   issuer,
                   (char*)&cred[1]);
  subject = GNUNET_CRYPTO_ecdsa_public_key_to_string (&cred->subject_key);
  if (NULL == subject)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Subject malformed\n");
    return;
  }
  GNUNET_STRINGS_base64_encode ((char*)&cred->signature,
                                sizeof (struct GNUNET_CRYPTO_EcdsaSignature),
                                &signature);
  json_document = GNUNET_JSONAPI_document_new ();
  json_resource = GNUNET_JSONAPI_resource_new (GNUNET_REST_JSONAPI_CREDENTIAL_TYPEINFO,
                                               id);
  GNUNET_free (id);
  cred_obj = json_object();
  json_object_set_new (cred_obj, "issuer", json_string (issuer));
  json_object_set_new (cred_obj, "subject", json_string (subject));
  json_object_set_new (cred_obj, "expiration", json_integer( cred->expiration.abs_value_us));
  json_object_set_new (cred_obj, "signature", json_string (signature));
  GNUNET_JSONAPI_resource_add_attr (json_resource,
                                    GNUNET_REST_JSONAPI_CREDENTIAL,
                                    cred_obj);
  GNUNET_JSONAPI_document_resource_add (json_document, json_resource);
  GNUNET_JSONAPI_document_serialize (json_document, &result);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Result %s\n",
              result);
  json_decref (cred_obj);
  GNUNET_JSONAPI_document_delete (json_document);
  resp = GNUNET_REST_create_response (result);
  handle->proc (handle->proc_cls, resp, MHD_HTTP_OK);
  GNUNET_free (result);
  GNUNET_free (signature);
  GNUNET_free (issuer);
  GNUNET_free (subject);
  cleanup_handle (handle);
}

void
get_cred_issuer_cb (void *cls,
                    struct GNUNET_IDENTITY_Ego *ego,
                    void **ctx,
                    const char *name)
{
  struct RequestHandle *handle = cls;
  struct GNUNET_TIME_Absolute etime_abs;
  struct GNUNET_TIME_Relative etime_rel;
  const struct GNUNET_CRYPTO_EcdsaPrivateKey *issuer_key;
  struct GNUNET_HashCode key;
  struct GNUNET_CREDENTIAL_Credential *cred;
  char* expiration_str;
  char* tmp;

  handle->id_op = NULL;

  if (NULL == name)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Issuer not configured!\n");
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Connecting to credential service...\n");
  handle->credential = GNUNET_CREDENTIAL_connect (cfg);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Connected\n");
  if (NULL == handle->credential)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Connecting to CREDENTIAL failed\n");
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }
  GNUNET_CRYPTO_hash (GNUNET_REST_JSONAPI_CREDENTIAL_EXPIRATION,
                      strlen (GNUNET_REST_JSONAPI_CREDENTIAL_EXPIRATION),
                      &key);
  if ( GNUNET_NO ==
       GNUNET_CONTAINER_multihashmap_contains (handle->rest_handle->url_param_map,
                                               &key) )
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Missing expiration\n");
    GNUNET_SCHEDULER_add_now (&do_error, handle); 
    return;
  }
  expiration_str = GNUNET_CONTAINER_multihashmap_get (handle->rest_handle->url_param_map,
                                                      &key);
  if (GNUNET_OK == GNUNET_STRINGS_fancy_time_to_relative (expiration_str,
                                                          &etime_rel))
  {
    etime_abs = GNUNET_TIME_relative_to_absolute (etime_rel);
  } else if (GNUNET_OK != GNUNET_STRINGS_fancy_time_to_absolute (expiration_str,
                                                                 &etime_abs))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Malformed expiration: %s\n", expiration_str);
    GNUNET_SCHEDULER_add_now (&do_error, handle); 
    return;
  }
  GNUNET_CRYPTO_hash (GNUNET_REST_JSONAPI_CREDENTIAL_ISSUER_ATTR,
                      strlen (GNUNET_REST_JSONAPI_CREDENTIAL_ISSUER_ATTR),
                      &key);
  if ( GNUNET_NO ==
       GNUNET_CONTAINER_multihashmap_contains (handle->rest_handle->url_param_map,
                                               &key) )
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Missing issuer attribute\n");
    GNUNET_SCHEDULER_add_now (&do_error, handle); 
    return;
  }
  handle->issuer_attr = GNUNET_strdup(GNUNET_CONTAINER_multihashmap_get 
                                      (handle->rest_handle->url_param_map,
                                       &key));
  GNUNET_CRYPTO_hash (GNUNET_REST_JSONAPI_CREDENTIAL_SUBJECT_KEY,
                      strlen (GNUNET_REST_JSONAPI_CREDENTIAL_SUBJECT_KEY),
                      &key);
  if ( GNUNET_NO ==
       GNUNET_CONTAINER_multihashmap_contains (handle->rest_handle->url_param_map,
                                               &key) )
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Missing subject\n");
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }
  tmp = GNUNET_CONTAINER_multihashmap_get (handle->rest_handle->url_param_map,
                                           &key);
  if (NULL == tmp)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Malformed subject\n");
    GNUNET_SCHEDULER_add_now (&do_error, handle); 
    return;
  }
  if (GNUNET_OK !=
      GNUNET_CRYPTO_ecdsa_public_key_from_string (tmp,
                                                  strlen (tmp),
                                                  &handle->subject_key)) {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Malformed subject key\n");
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }
  issuer_key = GNUNET_IDENTITY_ego_get_private_key (ego);
  cred = GNUNET_CREDENTIAL_credential_issue (issuer_key,
                                             &handle->subject_key,
                                             handle->issuer_attr,
                                             &etime_abs);
  if (NULL == cred)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Failed to create credential\n");
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }
  send_cred_response (handle, cred);
}


static void
issue_cred_cont (struct GNUNET_REST_RequestHandle *conndata_handle,
                 const char* url,
                 void *cls)
{
  struct RequestHandle *handle = cls;

  handle->identity = GNUNET_IDENTITY_connect (cfg,
                                              NULL,
                                              NULL);
  handle->id_op = GNUNET_IDENTITY_get(handle->identity,
                                      "credential-issuer",
                                      &get_cred_issuer_cb,
                                      handle);
  handle->timeout_task = GNUNET_SCHEDULER_add_delayed (handle->timeout,
                                                       &do_error,
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
  struct RequestHandle *handle = cls;

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
  struct RequestHandle *handle = GNUNET_new (struct RequestHandle);
  struct GNUNET_REST_RequestHandlerError err;

  handle->timeout = GNUNET_TIME_UNIT_FOREVER_REL;
  handle->proc_cls = proc_cls;
  handle->proc = proc;
  handle->rest_handle = conndata_handle;

  static const struct GNUNET_REST_RequestHandler handlers[] = {
    {MHD_HTTP_METHOD_POST, GNUNET_REST_API_NS_CREDENTIAL_VERIFY, &verify_cred_cont},
    {MHD_HTTP_METHOD_GET, GNUNET_REST_API_NS_CREDENTIAL_COLLECT, &collect_cred_cont},
    {MHD_HTTP_METHOD_GET, GNUNET_REST_API_NS_CREDENTIAL_ISSUE, &issue_cred_cont},
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

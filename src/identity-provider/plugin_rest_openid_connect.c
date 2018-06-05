/*
   This file is part of GNUnet.
   Copyright (C) 2012-2015 GNUnet e.V.

   GNUnet is free software: you can redistribute it and/or modify it
   under the terms of the GNU General Public License as published
   by the Free Software Foundation, either version 3 of the License,
   or (at your option) any later version.

   GNUnet is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Affero General Public License for more details.
   */
/**
 * @author Martin Schanzenbach
 * @author Philippe Buschmann
 * @file identity/plugin_rest_openid_connect.c
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
#include "gnunet_jsonapi_lib.h"
#include "gnunet_jsonapi_util.h"
#include "microhttpd.h"
#include <jansson.h>
#include <inttypes.h>
#include "gnunet_signatures.h"
#include "gnunet_identity_attribute_lib.h"
#include "gnunet_identity_provider_service.h"
#include "jwt.h"

/**
 * REST root namespace
 */
#define GNUNET_REST_API_NS_OIDC "/openid"

/**
 * Authorize endpoint
 */
#define GNUNET_REST_API_NS_AUTHORIZE "/openid/authorize"

/**
 * Token endpoint
 */
#define GNUNET_REST_API_NS_TOKEN "/openid/token"

/**
 * UserInfo endpoint
 */
#define GNUNET_REST_API_NS_USERINFO "/openid/userinfo"

/**
 * Login namespace
 */
#define GNUNET_REST_API_NS_LOGIN "/openid/login"

/**
 * Attribute key
 */
#define GNUNET_REST_JSONAPI_IDENTITY_ATTRIBUTE "attribute"

/**
 * Ticket key
 */
#define GNUNET_REST_JSONAPI_IDENTITY_TICKET "ticket"


/**
 * Value key
 */
#define GNUNET_REST_JSONAPI_IDENTITY_ATTRIBUTE_VALUE "value"

/**
 * State while collecting all egos
 */
#define ID_REST_STATE_INIT 0

/**
 * Done collecting egos
 */
#define ID_REST_STATE_POST_INIT 1

/**
 * OIDC grant_type key
 */
#define OIDC_GRANT_TYPE_KEY "grant_type"

/**
 * OIDC grant_type key
 */
#define OIDC_GRANT_TYPE_VALUE "authorization_code"

/**
 * OIDC code key
 */
#define OIDC_CODE_KEY "code"

/**
 * OIDC response_type key
 */
#define OIDC_RESPONSE_TYPE_KEY "response_type"

/**
 * OIDC client_id key
 */
#define OIDC_CLIENT_ID_KEY "client_id"

/**
 * OIDC scope key
 */
#define OIDC_SCOPE_KEY "scope"

/**
 * OIDC redirect_uri key
 */
#define OIDC_REDIRECT_URI_KEY "redirect_uri"

/**
 * OIDC state key
 */
#define OIDC_STATE_KEY "state"

/**
 * OIDC nonce key
 */
#define OIDC_NONCE_KEY "nonce"

/**
 * OIDC cookie header key
 */
#define OIDC_COOKIE_HEADER_KEY "cookie"

/**
 * OIDC cookie header information key
 */
#define OIDC_AUTHORIZATION_HEADER_KEY "authorization"

/**
 * OIDC cookie header information key
 */
#define OIDC_COOKIE_HEADER_INFORMATION_KEY "Identity="

/**
 * OIDC expected response_type while authorizing
 */
#define OIDC_EXPECTED_AUTHORIZATION_RESPONSE_TYPE "code"

/**
 * OIDC expected scope part while authorizing
 */
#define OIDC_EXPECTED_AUTHORIZATION_SCOPE "openid"

/**
 * OIDC ignored parameter array
 */
static char* OIDC_ignored_parameter_array [] =
{
  "display",
  "prompt",
  "max_age",
  "ui_locales", 
  "response_mode",
  "id_token_hint",
  "login_hint", 
  "acr_values"
};

/**
 * OIDC authorized identities and times hashmap
 */
struct GNUNET_CONTAINER_MultiHashMap *OIDC_identity_login_time;

/**
 * OIDC authorized identities and times hashmap
 */
struct GNUNET_CONTAINER_MultiHashMap *OIDC_identity_grants;

/**
 * OIDC ticket/code use only once
 */
struct GNUNET_CONTAINER_MultiHashMap *OIDC_ticket_once;

/**
 * OIDC access_token to ticket and ego
 */
struct GNUNET_CONTAINER_MultiHashMap *OIDC_interpret_access_token;

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
 * OIDC needed variables
 */
struct OIDC_Variables
{
  /**
   * The RP client public key
   */
  struct GNUNET_CRYPTO_EcdsaPublicKey client_pkey;

  /**
   * The OIDC client id of the RP
   */
  char *client_id;

  /**
   * GNUNET_YES if there is a delegation to 
   * this RP or if it is a local identity
   */
  int is_client_trusted;

  /**
   * The OIDC redirect uri
   */
  char *redirect_uri;

  /**
   * The list of oidc scopes
   */
  char *scope;

  /**
   * The OIDC state
   */
  char *state;

  /**
   * The OIDC nonce
   */
  char *nonce;

  /**
   * The OIDC response type
   */
  char *response_type;

  /**
   * The identity chosen by the user to login
   */
  char *login_identity;

  /**
   * The response JSON
   */
  json_t *response;

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
   * Pointer to ego private key
   */
  struct GNUNET_CRYPTO_EcdsaPrivateKey priv_key;

  /**
   * OIDC variables
   */
  struct OIDC_Variables *oidc;

  /**
   * The processing state
   */
  int state;

  /**
   * Handle to Identity service.
   */
  struct GNUNET_IDENTITY_Handle *identity_handle;

  /**
   * Rest connection
   */
  struct GNUNET_REST_RequestHandle *rest_handle;

  /**
   * Handle to NAMESTORE
   */
  struct GNUNET_NAMESTORE_Handle *namestore_handle;

  /**
   * Iterator for NAMESTORE
   */
  struct GNUNET_NAMESTORE_ZoneIterator *namestore_handle_it;

  /**
   * Attribute claim list
   */
  struct GNUNET_IDENTITY_ATTRIBUTE_ClaimList *attr_list;

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
   * Attribute iterator
   */
  struct GNUNET_IDENTITY_PROVIDER_AttributeIterator *attr_it;

  /**
   * Ticket iterator
   */
  struct GNUNET_IDENTITY_PROVIDER_TicketIterator *ticket_it;

  /**
   * A ticket
   */
  struct GNUNET_IDENTITY_PROVIDER_Ticket ticket;

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
   * The tld for redirect
   */
  char *tld;

  /**
   * Error response message
   */
  char *emsg;

  /**
   * Error response description
   */
  char *edesc;

  /**
   * Reponse code
   */
  int response_code;

  /**
   * Response object
   */
  struct GNUNET_JSONAPI_Document *resp_object;

};

/**
 * Cleanup lookup handle
 * @param handle Handle to clean up
 */
static void
cleanup_handle (struct RequestHandle *handle)
{
  struct GNUNET_IDENTITY_ATTRIBUTE_ClaimListEntry *claim_entry;
  struct GNUNET_IDENTITY_ATTRIBUTE_ClaimListEntry *claim_tmp;
  struct EgoEntry *ego_entry;
  struct EgoEntry *ego_tmp;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Cleaning up\n");
  if (NULL != handle->resp_object)
    GNUNET_JSONAPI_document_delete (handle->resp_object);
  if (NULL != handle->timeout_task)
    GNUNET_SCHEDULER_cancel (handle->timeout_task);
  if (NULL != handle->identity_handle)
    GNUNET_IDENTITY_disconnect (handle->identity_handle);
  if (NULL != handle->attr_it)
    GNUNET_IDENTITY_PROVIDER_get_attributes_stop (handle->attr_it);
  if (NULL != handle->ticket_it)
    GNUNET_IDENTITY_PROVIDER_ticket_iteration_stop (handle->ticket_it);
  if (NULL != handle->idp)
    GNUNET_IDENTITY_PROVIDER_disconnect (handle->idp);
  if (NULL != handle->url)
    GNUNET_free (handle->url);
  if (NULL != handle->tld)
    GNUNET_free (handle->tld);
  if (NULL != handle->emsg)
    GNUNET_free (handle->emsg);
  if (NULL != handle->edesc)
    GNUNET_free (handle->edesc);
  if (NULL != handle->namestore_handle)
    GNUNET_NAMESTORE_disconnect (handle->namestore_handle);
  if (NULL != handle->oidc)
  {
    if (NULL != handle->oidc->client_id)
      GNUNET_free(handle->oidc->client_id);
    if (NULL != handle->oidc->login_identity)
      GNUNET_free(handle->oidc->login_identity);
    if (NULL != handle->oidc->nonce)
      GNUNET_free(handle->oidc->nonce);
    if (NULL != handle->oidc->redirect_uri)
      GNUNET_free(handle->oidc->redirect_uri);
    if (NULL != handle->oidc->response_type)
      GNUNET_free(handle->oidc->response_type);
    if (NULL != handle->oidc->scope)
      GNUNET_free(handle->oidc->scope);
    if (NULL != handle->oidc->state)
      GNUNET_free(handle->oidc->state);
    if (NULL != handle->oidc->response)
      json_decref(handle->oidc->response);
    GNUNET_free(handle->oidc);
  }
  if ( NULL != handle->attr_list )
  {
    for (claim_entry = handle->attr_list->list_head;
         NULL != claim_entry;)
    {
      claim_tmp = claim_entry;
      claim_entry = claim_entry->next;
      GNUNET_free(claim_tmp->claim);
      GNUNET_free(claim_tmp);
    }
    GNUNET_free (handle->attr_list);
  }
  for (ego_entry = handle->ego_head;
       NULL != ego_entry;)
  {
    ego_tmp = ego_entry;
    ego_entry = ego_entry->next;
    GNUNET_free (ego_tmp->identifier);
    GNUNET_free (ego_tmp->keystring);
    GNUNET_free (ego_tmp);
  }
  if (NULL != handle->attr_it)
  {
    GNUNET_free(handle->attr_it);
  }
  GNUNET_free (handle);
}

static void
cleanup_handle_delayed (void *cls)
{
  cleanup_handle (cls);
}


/**
 * Task run on error, sends error message.  Cleans up everything.
 *
 * @param cls the `struct RequestHandle`
 */
static void
do_error (void *cls)
{
  struct RequestHandle *handle = cls;
  struct MHD_Response *resp;
  char *json_error;

  GNUNET_asprintf (&json_error, "{ \"error\" : \"%s\", \"error_description\" : \"%s\"%s%s%s}",
                   handle->emsg,
                   (NULL != handle->edesc) ? handle->edesc : "",
                   (NULL != handle->oidc->state) ? ", \"state\":\"" : "",
                   (NULL != handle->oidc->state) ? handle->oidc->state : "",
                   (NULL != handle->oidc->state) ? "\"" : "");
  if ( 0 == handle->response_code )
  {
    handle->response_code = MHD_HTTP_BAD_REQUEST;
  }
  resp = GNUNET_REST_create_response (json_error);
  if (MHD_HTTP_UNAUTHORIZED == handle->response_code)
  {
    MHD_add_response_header(resp, "WWW-Authenticate", "Basic");
  }
  MHD_add_response_header (resp, "Content-Type", "application/json");
  handle->proc (handle->proc_cls, resp, handle->response_code);
  GNUNET_SCHEDULER_add_now (&cleanup_handle_delayed, handle);
  GNUNET_free (json_error);
}


/**
 * Task run on error in userinfo endpoint, sends error header. Cleans up
 * everything
 *
 * @param cls the `struct RequestHandle`
 */
static void
do_userinfo_error (void *cls)
{
  struct RequestHandle *handle = cls;
  struct MHD_Response *resp;
  char *error;

  GNUNET_asprintf (&error, "error=\"%s\", error_description=\"%s\"",
                   handle->emsg,
                   (NULL != handle->edesc) ? handle->edesc : "");
  resp = GNUNET_REST_create_response ("");
  MHD_add_response_header(resp, "WWW-Authenticate", error);
  handle->proc (handle->proc_cls, resp, handle->response_code);
  GNUNET_SCHEDULER_add_now (&cleanup_handle_delayed, handle);
  GNUNET_free (error);
}


/**
 * Task run on error, sends error message and redirects. Cleans up everything.
 *
 * @param cls the `struct RequestHandle`
 */
static void
do_redirect_error (void *cls)
{
  struct RequestHandle *handle = cls;
  struct MHD_Response *resp;
  char* redirect;
  GNUNET_asprintf (&redirect,
                   "%s?error=%s&error_description=%s%s%s",
                   handle->oidc->redirect_uri, handle->emsg, handle->edesc,
                   (NULL != handle->oidc->state) ? "&state=" : "",
                   (NULL != handle->oidc->state) ? handle->oidc->state : "");
  resp = GNUNET_REST_create_response ("");
  MHD_add_response_header (resp, "Location", redirect);
  handle->proc (handle->proc_cls, resp, MHD_HTTP_FOUND);
  GNUNET_SCHEDULER_add_now (&cleanup_handle_delayed, handle);
  GNUNET_free (redirect);
}

/**
 * Task run on timeout, sends error message.  Cleans up everything.
 *
 * @param cls the `struct RequestHandle`
 */
static void
do_timeout (void *cls)
{
  struct RequestHandle *handle = cls;

  handle->timeout_task = NULL;
  do_error (handle);
}

/**
 * Return attributes for claim
 *
 * @param cls the request handle
 */
static void
return_userinfo_response (void *cls)
{
  char* result_str;
  struct RequestHandle *handle = cls;
  struct MHD_Response *resp;

  result_str = json_dumps (handle->oidc->response, 0);

  resp = GNUNET_REST_create_response (result_str);
  handle->proc (handle->proc_cls, resp, MHD_HTTP_OK);
  GNUNET_free (result_str);
  cleanup_handle (handle);
}

/**
 * Returns base64 encoded string without padding
 *
 * @param string the string to encode
 * @return base64 encoded string
 */
static char*
base_64_encode(const char *s)
{
  char *enc;
  char *tmp;

  GNUNET_STRINGS_base64_encode(s, strlen(s), &enc);
  tmp = strrchr (enc, '=');
  *tmp = '\0';
  return enc;
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

  //For now, independent of path return all options
  resp = GNUNET_REST_create_response (NULL);
  MHD_add_response_header (resp,
                           "Access-Control-Allow-Methods",
                           allow_methods);
  handle->proc (handle->proc_cls, resp, MHD_HTTP_OK);
  cleanup_handle (handle);
  return;
}

/**
 * Interprets cookie header and pass its identity keystring to handle
 */
static void
cookie_identity_interpretation (struct RequestHandle *handle)
{
  struct GNUNET_HashCode cache_key;
  char *cookies;
  struct GNUNET_TIME_Absolute current_time, *relog_time;
  char delimiter[] = "; ";

  //gets identity of login try with cookie
  GNUNET_CRYPTO_hash (OIDC_COOKIE_HEADER_KEY, strlen (OIDC_COOKIE_HEADER_KEY),
                      &cache_key);
  if ( GNUNET_YES == GNUNET_CONTAINER_multihashmap_contains (handle->rest_handle->header_param_map,
                                                             &cache_key) )
  {
    //splits cookies and find 'Identity' cookie
    cookies = GNUNET_CONTAINER_multihashmap_get ( handle->rest_handle->header_param_map, &cache_key);
    handle->oidc->login_identity = strtok(cookies, delimiter);

    while ( NULL != handle->oidc->login_identity )
    {
      if ( NULL != strstr (handle->oidc->login_identity, OIDC_COOKIE_HEADER_INFORMATION_KEY) )
      {
        break;
      }
      handle->oidc->login_identity = strtok (NULL, delimiter);
    }
    GNUNET_CRYPTO_hash (handle->oidc->login_identity, strlen (handle->oidc->login_identity),
                        &cache_key);
    if ( GNUNET_YES == GNUNET_CONTAINER_multihashmap_contains (OIDC_identity_login_time, &cache_key) )
    {
      relog_time = GNUNET_CONTAINER_multihashmap_get (OIDC_identity_login_time,
                                                      &cache_key);
      current_time = GNUNET_TIME_absolute_get ();
      // 30 min after old login -> redirect to login
      if ( current_time.abs_value_us <= relog_time->abs_value_us )
      {
        handle->oidc->login_identity = strtok(handle->oidc->login_identity, OIDC_COOKIE_HEADER_INFORMATION_KEY);
        handle->oidc->login_identity = GNUNET_strdup(handle->oidc->login_identity);
      }
    }
    else
    {
      handle->oidc->login_identity = NULL;
    }
  }
}

/**
 * Redirects to login page stored in configuration file
 */
static void
login_redirection(void *cls)
{
  char *login_base_url;
  char *new_redirect;
  struct MHD_Response *resp;
  struct RequestHandle *handle = cls;

  if ( GNUNET_OK
       == GNUNET_CONFIGURATION_get_value_string (cfg, "identity-rest-plugin",
                                                 "address", &login_base_url) )
  {
    GNUNET_asprintf (&new_redirect, "%s?%s=%s&%s=%s&%s=%s&%s=%s&%s=%s&%s=%s",
                     login_base_url,
                     OIDC_RESPONSE_TYPE_KEY,
                     handle->oidc->response_type,
                     OIDC_CLIENT_ID_KEY,
                     handle->oidc->client_id,
                     OIDC_REDIRECT_URI_KEY,
                     handle->oidc->redirect_uri,
                     OIDC_SCOPE_KEY,
                     handle->oidc->scope,
                     OIDC_STATE_KEY,
                     (NULL != handle->oidc->state) ? handle->oidc->state : "",
                     OIDC_NONCE_KEY,
                     (NULL != handle->oidc->nonce) ? handle->oidc->nonce : "");
    resp = GNUNET_REST_create_response ("");
    MHD_add_response_header (resp, "Location", new_redirect);
    GNUNET_free(login_base_url);
  }
  else
  {
    handle->emsg = GNUNET_strdup("server_error");
    handle->edesc = GNUNET_strdup ("gnunet configuration failed");
    handle->response_code = MHD_HTTP_INTERNAL_SERVER_ERROR;
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }
  handle->proc (handle->proc_cls, resp, MHD_HTTP_FOUND);
  GNUNET_free(new_redirect);
  GNUNET_SCHEDULER_add_now (&cleanup_handle_delayed, handle);
}

/**
 * Does internal server error when iteration failed.
 */
static void
oidc_iteration_error (void *cls)
{
  struct RequestHandle *handle = cls;
  handle->emsg = GNUNET_strdup("INTERNAL_SERVER_ERROR");
  handle->response_code = MHD_HTTP_INTERNAL_SERVER_ERROR;
  GNUNET_SCHEDULER_add_now (&do_error, handle);
}

static void get_client_name_result (void *cls,
                                    const struct GNUNET_CRYPTO_EcdsaPrivateKey *zone,
                                    const char *label,
                                    unsigned int rd_count,
                                    const struct GNUNET_GNSRECORD_Data *rd)
{
  struct RequestHandle *handle = cls;
  struct MHD_Response *resp;
  char *ticket_str;
  char *redirect_uri;
  char *code_json_string;
  char *code_base64_final_string;
  char *redirect_path;
  char *tmp;
  char *tmp_prefix;
  char *prefix;
  ticket_str = GNUNET_STRINGS_data_to_string_alloc (&handle->ticket,
                                                    sizeof (struct GNUNET_IDENTITY_PROVIDER_Ticket));
  //TODO change if more attributes are needed (see max_age)
  GNUNET_asprintf (&code_json_string, "{\"ticket\":\"%s\"%s%s%s}",
                   ticket_str,
                   (NULL != handle->oidc->nonce) ? ", \"nonce\":\"" : "",
                   (NULL != handle->oidc->nonce) ? handle->oidc->nonce : "",
                   (NULL != handle->oidc->nonce) ? "\"" : "");
  code_base64_final_string = base_64_encode(code_json_string);
  tmp = GNUNET_strdup (handle->oidc->redirect_uri);
  redirect_path = strtok (tmp, "/");
  redirect_path = strtok (NULL, "/");
  redirect_path = strtok (NULL, "/");
  tmp_prefix = GNUNET_strdup (handle->oidc->redirect_uri);
  prefix = strrchr (tmp_prefix,
                    (unsigned char) '.');
  *prefix = '\0';
  GNUNET_asprintf (&redirect_uri, "%s.%s/%s?%s=%s&state=%s",
                   tmp_prefix,
                   handle->tld,
                   redirect_path,
                   handle->oidc->response_type,
                   code_base64_final_string, handle->oidc->state);
  resp = GNUNET_REST_create_response ("");
  MHD_add_response_header (resp, "Location", redirect_uri);
  handle->proc (handle->proc_cls, resp, MHD_HTTP_FOUND);
  GNUNET_SCHEDULER_add_now (&cleanup_handle_delayed, handle);
  GNUNET_free (tmp);
  GNUNET_free (tmp_prefix);
  GNUNET_free (redirect_uri);
  GNUNET_free (ticket_str);
  GNUNET_free (code_json_string);
  GNUNET_free (code_base64_final_string);
  return;
}

static void
get_client_name_error (void *cls)
{
  struct RequestHandle *handle = cls;

  handle->emsg = GNUNET_strdup("server_error");
  handle->edesc = GNUNET_strdup("Server cannot generate ticket, no name found for client.");
  GNUNET_SCHEDULER_add_now (&do_redirect_error, handle);
}

/**
 * Issues ticket and redirects to relying party with the authorization code as
 * parameter. Otherwise redirects with error
 */
static void
oidc_ticket_issue_cb (void* cls,
                      const struct GNUNET_IDENTITY_PROVIDER_Ticket *ticket)
{
  struct RequestHandle *handle = cls;
  handle->idp_op = NULL;
  handle->ticket = *ticket;
  if (NULL != ticket) {
    GNUNET_NAMESTORE_zone_to_name (handle->namestore_handle,
                                   &handle->priv_key,
                                   &handle->oidc->client_pkey,
                                   &get_client_name_error,
                                   handle,
                                   &get_client_name_result,
                                   handle);
    return;
  }
  handle->emsg = GNUNET_strdup("server_error");
  handle->edesc = GNUNET_strdup("Server cannot generate ticket.");
  GNUNET_SCHEDULER_add_now (&do_redirect_error, handle);
}

static void
oidc_collect_finished_cb (void *cls)
{
  struct RequestHandle *handle = cls;
  handle->attr_it = NULL;
  handle->ticket_it = NULL;
  if (NULL == handle->attr_list->list_head)
  {
    handle->emsg = GNUNET_strdup("invalid_scope");
    handle->edesc = GNUNET_strdup("The requested scope is not available.");
    GNUNET_SCHEDULER_add_now (&do_redirect_error, handle);
    return;
  }
  handle->idp_op = GNUNET_IDENTITY_PROVIDER_ticket_issue (handle->idp,
                                                          &handle->priv_key,
                                                          &handle->oidc->client_pkey,
                                                          handle->attr_list,
                                                          &oidc_ticket_issue_cb,
                                                          handle);
}


/**
 * Collects all attributes for an ego if in scope parameter
 */
static void
oidc_attr_collect (void *cls,
                   const struct GNUNET_CRYPTO_EcdsaPublicKey *identity,
                   const struct GNUNET_IDENTITY_ATTRIBUTE_Claim *attr)
{
  struct RequestHandle *handle = cls;
  struct GNUNET_IDENTITY_ATTRIBUTE_ClaimListEntry *le;
  char* scope_variables;
  char* scope_variable;
  char delimiter[]=" ";

  if ( (NULL == attr->name) || (NULL == attr->data) )
  {
    GNUNET_IDENTITY_PROVIDER_get_attributes_next (handle->attr_it);
    return;
  }

  scope_variables = GNUNET_strdup(handle->oidc->scope);
  scope_variable = strtok (scope_variables, delimiter);
  while (NULL != scope_variable)
  {
    if ( 0 == strcmp (attr->name, scope_variable) )
    {
      break;
    }
    scope_variable = strtok (NULL, delimiter);
  }
  if ( NULL == scope_variable )
  {
    GNUNET_IDENTITY_PROVIDER_get_attributes_next (handle->attr_it);
    GNUNET_free(scope_variables);
    return;
  }
  GNUNET_free(scope_variables);

  le = GNUNET_new(struct GNUNET_IDENTITY_ATTRIBUTE_ClaimListEntry);
  le->claim = GNUNET_IDENTITY_ATTRIBUTE_claim_new (attr->name, attr->type,
                                                   attr->data, attr->data_size);
  GNUNET_CONTAINER_DLL_insert(handle->attr_list->list_head,
                              handle->attr_list->list_tail, le);
  GNUNET_IDENTITY_PROVIDER_get_attributes_next (handle->attr_it);
}


/**
 * Checks time and cookie and redirects accordingly
 */
static void
login_check (void *cls)
{
  struct RequestHandle *handle = cls;
  struct GNUNET_TIME_Absolute current_time, *relog_time;
  struct GNUNET_CRYPTO_EcdsaPublicKey pubkey, ego_pkey;
  struct GNUNET_HashCode cache_key;
  char *identity_cookie;

  GNUNET_asprintf (&identity_cookie, "Identity=%s", handle->oidc->login_identity);
  GNUNET_CRYPTO_hash (identity_cookie, strlen (identity_cookie), &cache_key);
  GNUNET_free(identity_cookie);
  //No login time for identity -> redirect to login
  if ( GNUNET_YES
       == GNUNET_CONTAINER_multihashmap_contains (OIDC_identity_login_time,
                                                  &cache_key) )
  {
    relog_time = GNUNET_CONTAINER_multihashmap_get (OIDC_identity_login_time,
                                                    &cache_key);
    current_time = GNUNET_TIME_absolute_get ();
    // 30 min after old login -> redirect to login
    if ( current_time.abs_value_us <= relog_time->abs_value_us )
    {
      if ( GNUNET_OK
           != GNUNET_CRYPTO_ecdsa_public_key_from_string (
                                                          handle->oidc->login_identity,
                                                          strlen (handle->oidc->login_identity), &pubkey) )
      {
        handle->emsg = GNUNET_strdup("invalid_cookie");
        handle->edesc = GNUNET_strdup(
                                      "The cookie of a login identity is not valid");
        GNUNET_SCHEDULER_add_now (&do_redirect_error, handle);
        return;
      }
      // iterate over egos and compare their public key
      for (handle->ego_entry = handle->ego_head;
           NULL != handle->ego_entry; handle->ego_entry = handle->ego_entry->next)
      {
        GNUNET_IDENTITY_ego_get_public_key (handle->ego_entry->ego, &ego_pkey);
        if ( 0
             == memcmp (&ego_pkey, &pubkey,
                        sizeof(struct GNUNET_CRYPTO_EcdsaPublicKey)) )
        {
          handle->priv_key = *GNUNET_IDENTITY_ego_get_private_key (
                                                                   handle->ego_entry->ego);
          handle->resp_object = GNUNET_JSONAPI_document_new ();
          handle->idp = GNUNET_IDENTITY_PROVIDER_connect (cfg);
          handle->attr_list = GNUNET_new(
                                         struct GNUNET_IDENTITY_ATTRIBUTE_ClaimList);
          handle->attr_it = GNUNET_IDENTITY_PROVIDER_get_attributes_start (
                                                                           handle->idp, &handle->priv_key, &oidc_iteration_error, handle,
                                                                           &oidc_attr_collect, handle, &oidc_collect_finished_cb, handle);
          return;
        }
      }
      handle->emsg = GNUNET_strdup("invalid_cookie");
      handle->edesc = GNUNET_strdup(
                                    "The cookie of the login identity is not valid");
      GNUNET_SCHEDULER_add_now (&do_redirect_error, handle);
      return;
    }
  }
}

/**
 * Searches for client_id in namestore. If found trust status stored in handle
 * Else continues to search
 *
 * @param handle the RequestHandle
 */
static void
namestore_iteration_callback (
                              void *cls, const struct GNUNET_CRYPTO_EcdsaPrivateKey *zone_key,
                              const char *rname, unsigned int rd_len,
                              const struct GNUNET_GNSRECORD_Data *rd)
{
  struct RequestHandle *handle = cls;
  struct GNUNET_CRYPTO_EcdsaPublicKey login_identity_pkey;
  struct GNUNET_CRYPTO_EcdsaPublicKey current_zone_pkey;
  int i;

  for (i = 0; i < rd_len; i++)
  {
    if ( GNUNET_GNSRECORD_TYPE_PKEY != rd[i].record_type )
      continue;

    if ( NULL != handle->oidc->login_identity )
    {
      GNUNET_CRYPTO_ecdsa_public_key_from_string (
                                                  handle->oidc->login_identity,
                                                  strlen (handle->oidc->login_identity),
                                                  &login_identity_pkey);
      GNUNET_IDENTITY_ego_get_public_key (handle->ego_entry->ego,
                                          &current_zone_pkey);

      if ( 0 == memcmp (rd[i].data, &handle->oidc->client_pkey,
                        sizeof(struct GNUNET_CRYPTO_EcdsaPublicKey)) )
      {
        if ( 0 == memcmp (&login_identity_pkey, &current_zone_pkey,
                          sizeof(struct GNUNET_CRYPTO_EcdsaPublicKey)) )
        {
          handle->oidc->is_client_trusted = GNUNET_YES;
        }
      }
    }
    else
    {
      if ( 0 == memcmp (rd[i].data, &handle->oidc->client_pkey,
                        sizeof(struct GNUNET_CRYPTO_EcdsaPublicKey)) )
      {
        handle->oidc->is_client_trusted = GNUNET_YES;
      }
    }
  }

  GNUNET_NAMESTORE_zone_iterator_next (handle->namestore_handle_it,
				       1);
}


/**
 * Iteration over all results finished, build final
 * response.
 *
 * @param cls the `struct RequestHandle`
 */
static void
namestore_iteration_finished (void *cls)
{
  struct RequestHandle *handle = cls;
  struct GNUNET_HashCode cache_key;

  char *expected_scope;
  char delimiter[]=" ";
  int number_of_ignored_parameter, iterator;


  handle->ego_entry = handle->ego_entry->next;

  if(NULL != handle->ego_entry)
  {
    handle->priv_key = *GNUNET_IDENTITY_ego_get_private_key (handle->ego_entry->ego);
    handle->namestore_handle_it = GNUNET_NAMESTORE_zone_iteration_start (handle->namestore_handle, &handle->priv_key,
                                                                         &oidc_iteration_error, handle, &namestore_iteration_callback, handle,
                                                                         &namestore_iteration_finished, handle);
    return;
  }
  if (GNUNET_NO == handle->oidc->is_client_trusted)
  {
    handle->emsg = GNUNET_strdup("unauthorized_client");
    handle->edesc = GNUNET_strdup("The client is not authorized to request an "
                                  "authorization code using this method.");
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }

  // REQUIRED value: redirect_uri
  GNUNET_CRYPTO_hash (OIDC_REDIRECT_URI_KEY, strlen (OIDC_REDIRECT_URI_KEY),
                      &cache_key);
  if (GNUNET_NO == GNUNET_CONTAINER_multihashmap_contains (handle->rest_handle->url_param_map,
                                                           &cache_key))
  {
    handle->emsg=GNUNET_strdup("invalid_request");
    handle->edesc=GNUNET_strdup("missing parameter redirect_uri");
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }
  handle->oidc->redirect_uri = GNUNET_strdup (GNUNET_CONTAINER_multihashmap_get(handle->rest_handle->url_param_map,
                                                                                &cache_key));

  // REQUIRED value: response_type
  GNUNET_CRYPTO_hash (OIDC_RESPONSE_TYPE_KEY, strlen (OIDC_RESPONSE_TYPE_KEY),
                      &cache_key);
  if (GNUNET_NO == GNUNET_CONTAINER_multihashmap_contains (handle->rest_handle->url_param_map,
                                                           &cache_key))
  {
    handle->emsg=GNUNET_strdup("invalid_request");
    handle->edesc=GNUNET_strdup("missing parameter response_type");
    GNUNET_SCHEDULER_add_now (&do_redirect_error, handle);
    return;
  }
  handle->oidc->response_type = GNUNET_CONTAINER_multihashmap_get(handle->rest_handle->url_param_map,
                                                                  &cache_key);
  handle->oidc->response_type = GNUNET_strdup (handle->oidc->response_type);

  // REQUIRED value: scope
  GNUNET_CRYPTO_hash (OIDC_SCOPE_KEY, strlen (OIDC_SCOPE_KEY), &cache_key);
  if (GNUNET_NO == GNUNET_CONTAINER_multihashmap_contains (handle->rest_handle->url_param_map,
                                                           &cache_key))
  {
    handle->emsg=GNUNET_strdup("invalid_request");
    handle->edesc=GNUNET_strdup("missing parameter scope");
    GNUNET_SCHEDULER_add_now (&do_redirect_error, handle);
    return;
  }
  handle->oidc->scope = GNUNET_CONTAINER_multihashmap_get(handle->rest_handle->url_param_map,
                                                          &cache_key);
  handle->oidc->scope = GNUNET_strdup(handle->oidc->scope);

  //OPTIONAL value: nonce
  GNUNET_CRYPTO_hash (OIDC_NONCE_KEY, strlen (OIDC_NONCE_KEY), &cache_key);
  if (GNUNET_YES == GNUNET_CONTAINER_multihashmap_contains (handle->rest_handle->url_param_map,
                                                            &cache_key))
  {
    handle->oidc->nonce = GNUNET_CONTAINER_multihashmap_get(handle->rest_handle->url_param_map,
                                                            &cache_key);
    handle->oidc->nonce = GNUNET_strdup (handle->oidc->nonce);
  }

  //TODO check other values if needed
  number_of_ignored_parameter = sizeof(OIDC_ignored_parameter_array) / sizeof(char *);
  for( iterator = 0; iterator < number_of_ignored_parameter; iterator++ )
  {
    GNUNET_CRYPTO_hash (OIDC_ignored_parameter_array[iterator],
                        strlen(OIDC_ignored_parameter_array[iterator]),
                        &cache_key);
    if(GNUNET_YES == GNUNET_CONTAINER_multihashmap_contains(handle->rest_handle->url_param_map,
                                                            &cache_key))
    {
      handle->emsg=GNUNET_strdup("access_denied");
      GNUNET_asprintf (&handle->edesc, "Server will not handle parameter: %s",
                       OIDC_ignored_parameter_array[iterator]);
      GNUNET_SCHEDULER_add_now (&do_redirect_error, handle);
      return;
    }
  }

  // Checks if response_type is 'code'
  if( 0 != strcmp( handle->oidc->response_type, OIDC_EXPECTED_AUTHORIZATION_RESPONSE_TYPE ) )
  {
    handle->emsg=GNUNET_strdup("unsupported_response_type");
    handle->edesc=GNUNET_strdup("The authorization server does not support "
                                "obtaining this authorization code.");
    GNUNET_SCHEDULER_add_now (&do_redirect_error, handle);
    return;
  }

  // Checks if scope contains 'openid'
  expected_scope = GNUNET_strdup(handle->oidc->scope);
  char* test;
  test = strtok (expected_scope, delimiter);
  while (NULL != test)
  {
    if ( 0 == strcmp (OIDC_EXPECTED_AUTHORIZATION_SCOPE, expected_scope) )
    {
      break;
    }
    test = strtok (NULL, delimiter);
  }
  if (NULL == test)
  {
    handle->emsg = GNUNET_strdup("invalid_scope");
    handle->edesc=GNUNET_strdup("The requested scope is invalid, unknown, or "
                                "malformed.");
    GNUNET_SCHEDULER_add_now (&do_redirect_error, handle);
    GNUNET_free(expected_scope);
    return;
  }

  GNUNET_free(expected_scope);

  if( NULL != handle->oidc->login_identity )
  {
    GNUNET_SCHEDULER_add_now(&login_check,handle);
    return;
  }

  GNUNET_SCHEDULER_add_now(&login_redirection,handle);
}

/**
 * Responds to authorization GET and url-encoded POST request
 *
 * @param con_handle the connection handle
 * @param url the url
 * @param cls the RequestHandle
 */
static void
authorize_endpoint (struct GNUNET_REST_RequestHandle *con_handle,
                    const char* url,
                    void *cls)
{
  struct RequestHandle *handle = cls;
  struct GNUNET_HashCode cache_key;
  struct EgoEntry *tmp_ego;
  struct GNUNET_CRYPTO_EcdsaPublicKey pkey;
  const struct GNUNET_CRYPTO_EcdsaPrivateKey *priv_key;

  cookie_identity_interpretation(handle);

  //RECOMMENDED value: state - REQUIRED for answers
  GNUNET_CRYPTO_hash (OIDC_STATE_KEY, strlen (OIDC_STATE_KEY), &cache_key);
  if (GNUNET_YES == GNUNET_CONTAINER_multihashmap_contains (handle->rest_handle->url_param_map,
                                                            &cache_key))
  {
    handle->oidc->state = GNUNET_CONTAINER_multihashmap_get(handle->rest_handle->url_param_map,
                                                            &cache_key);
    handle->oidc->state = GNUNET_strdup (handle->oidc->state);
  }

  // REQUIRED value: client_id
  GNUNET_CRYPTO_hash (OIDC_CLIENT_ID_KEY, strlen (OIDC_CLIENT_ID_KEY),
                      &cache_key);
  if (GNUNET_NO == GNUNET_CONTAINER_multihashmap_contains (handle->rest_handle->url_param_map,
                                                           &cache_key))
  {
    handle->emsg=GNUNET_strdup("invalid_request");
    handle->edesc=GNUNET_strdup("missing parameter client_id");
    handle->response_code = MHD_HTTP_INTERNAL_SERVER_ERROR;
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }
  handle->oidc->client_id = GNUNET_strdup (GNUNET_CONTAINER_multihashmap_get(handle->rest_handle->url_param_map,
                                                                             &cache_key));

  if ( GNUNET_OK
       != GNUNET_CRYPTO_ecdsa_public_key_from_string (handle->oidc->client_id,
                                                      strlen (handle->oidc->client_id),
                                                      &handle->oidc->client_pkey) )
  {
    handle->emsg = GNUNET_strdup("unauthorized_client");
    handle->edesc = GNUNET_strdup("The client is not authorized to request an "
                                  "authorization code using this method.");
    handle->response_code = MHD_HTTP_INTERNAL_SERVER_ERROR;
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }


  if ( NULL == handle->ego_head )
  {
    handle->emsg = GNUNET_strdup("server_error");
    handle->edesc = GNUNET_strdup ("Egos are missing");
    handle->response_code = MHD_HTTP_INTERNAL_SERVER_ERROR;
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }

  handle->ego_entry = handle->ego_head;
  handle->priv_key = *GNUNET_IDENTITY_ego_get_private_key (handle->ego_head->ego);
  handle->oidc->is_client_trusted = GNUNET_NO;

  //First check if client_id is one of our egos; TODO: handle other TLD cases: Delegation, from config
  for (tmp_ego = handle->ego_head; NULL != tmp_ego; tmp_ego = tmp_ego->next)
  {
    priv_key = GNUNET_IDENTITY_ego_get_private_key (tmp_ego->ego);
    GNUNET_CRYPTO_ecdsa_key_get_public (priv_key,
                                        &pkey);
    if ( 0 == memcmp (&pkey, &handle->oidc->client_pkey,
                      sizeof(struct GNUNET_CRYPTO_EcdsaPublicKey)) )
    {
      handle->tld = GNUNET_strdup (tmp_ego->identifier);
      handle->oidc->is_client_trusted = GNUNET_YES;
      handle->ego_entry = handle->ego_tail;
    }
  }


  // Checks if client_id is valid:
  handle->namestore_handle_it = GNUNET_NAMESTORE_zone_iteration_start (
                                                                       handle->namestore_handle, &handle->priv_key, &oidc_iteration_error,
                                                                       handle, &namestore_iteration_callback, handle,
                                                                       &namestore_iteration_finished, handle);
}

/**
 * Combines an identity with a login time and responds OK to login request
 *
 * @param con_handle the connection handle
 * @param url the url
 * @param cls the RequestHandle
 */
static void
login_cont (struct GNUNET_REST_RequestHandle *con_handle,
            const char* url,
            void *cls)
{
  struct MHD_Response *resp = GNUNET_REST_create_response ("");
  struct RequestHandle *handle = cls;
  struct GNUNET_HashCode cache_key;
  struct GNUNET_TIME_Absolute *current_time;
  struct GNUNET_TIME_Absolute *last_time;
  char* cookie;
  json_t *root;
  json_error_t error;
  json_t *identity;
  char term_data[handle->rest_handle->data_size+1];
  term_data[handle->rest_handle->data_size] = '\0';
  GNUNET_memcpy (term_data, handle->rest_handle->data, handle->rest_handle->data_size);
  root = json_loads (term_data, JSON_DECODE_ANY, &error);
  identity = json_object_get (root, "identity");
  if ( json_is_string(identity) )
  {
    GNUNET_asprintf (&cookie, "Identity=%s", json_string_value (identity));
    MHD_add_response_header (resp, "Set-Cookie", cookie);
    MHD_add_response_header (resp, "Access-Control-Allow-Methods", "POST");
    GNUNET_CRYPTO_hash (cookie, strlen (cookie), &cache_key);

    current_time = GNUNET_new(struct GNUNET_TIME_Absolute);
    *current_time = GNUNET_TIME_relative_to_absolute (
                                                      GNUNET_TIME_relative_multiply (GNUNET_TIME_relative_get_minute_ (),
                                                                                     30));
    last_time = GNUNET_CONTAINER_multihashmap_get(OIDC_identity_login_time, &cache_key);
    if (NULL != last_time)
    {
      GNUNET_free(last_time);
    }
    GNUNET_CONTAINER_multihashmap_put (
                                       OIDC_identity_login_time, &cache_key, current_time,
                                       GNUNET_CONTAINER_MULTIHASHMAPOPTION_REPLACE);

    handle->proc (handle->proc_cls, resp, MHD_HTTP_OK);
    GNUNET_free(cookie);
  }
  else
  {
    handle->proc (handle->proc_cls, resp, MHD_HTTP_BAD_REQUEST);
  }
  json_decref (root);
  GNUNET_SCHEDULER_add_now (&cleanup_handle_delayed, handle);
  return;
}

/**
 * Responds to token url-encoded POST request
 *
 * @param con_handle the connection handle
 * @param url the url
 * @param cls the RequestHandle
 */
static void
token_endpoint (struct GNUNET_REST_RequestHandle *con_handle,
                const char* url,
                void *cls)
{
  //TODO static strings
  struct RequestHandle *handle = cls;
  struct GNUNET_HashCode cache_key;
  char *authorization, *credentials;
  char delimiter[]=" ";
  char delimiter_user_psw[]=":";
  char *grant_type, *code;
  char *user_psw = NULL, *client_id, *psw;
  char *expected_psw;
  int client_exists = GNUNET_NO;
  struct MHD_Response *resp;
  char* code_output;
  json_t *root, *ticket_string, *nonce, *max_age;
  json_error_t error;
  char *json_response;

  /*
   * Check Authorization
   */
  GNUNET_CRYPTO_hash (OIDC_AUTHORIZATION_HEADER_KEY,
                      strlen (OIDC_AUTHORIZATION_HEADER_KEY),
                      &cache_key);
  if ( GNUNET_NO == GNUNET_CONTAINER_multihashmap_contains (handle->rest_handle->header_param_map,
                                                            &cache_key) )
  {
    handle->emsg=GNUNET_strdup("invalid_client");
    handle->edesc=GNUNET_strdup("missing authorization");
    handle->response_code = MHD_HTTP_UNAUTHORIZED;
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }
  authorization = GNUNET_CONTAINER_multihashmap_get ( handle->rest_handle->header_param_map, &cache_key);

  //split header in "Basic" and [content]
  credentials = strtok (authorization, delimiter);
  if (0 != strcmp ("Basic",credentials))
  {
    handle->emsg=GNUNET_strdup("invalid_client");
    handle->response_code = MHD_HTTP_UNAUTHORIZED;
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }
  credentials = strtok(NULL, delimiter);
  if (NULL == credentials)
  {
    handle->emsg=GNUNET_strdup("invalid_client");
    handle->response_code = MHD_HTTP_UNAUTHORIZED;
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }
  GNUNET_STRINGS_base64_decode (credentials, strlen (credentials), &user_psw);

  if ( NULL == user_psw )
  {
    handle->emsg=GNUNET_strdup("invalid_client");
    handle->response_code = MHD_HTTP_UNAUTHORIZED;
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }
  client_id = strtok (user_psw, delimiter_user_psw);
  if ( NULL == client_id )
  {
    GNUNET_free_non_null(user_psw);
    handle->emsg=GNUNET_strdup("invalid_client");
    handle->response_code = MHD_HTTP_UNAUTHORIZED;
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }
  psw = strtok (NULL, delimiter_user_psw);
  if (NULL == psw)
  {
    GNUNET_free_non_null(user_psw);
    handle->emsg=GNUNET_strdup("invalid_client");
    handle->response_code = MHD_HTTP_UNAUTHORIZED;
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }

  //check client password
  if ( GNUNET_OK
       == GNUNET_CONFIGURATION_get_value_string (cfg, "identity-rest-plugin",
                                                 "psw", &expected_psw) )
  {
    if (0 != strcmp (expected_psw, psw))
    {
      GNUNET_free_non_null(user_psw);
      GNUNET_free(expected_psw);
      handle->emsg=GNUNET_strdup("invalid_client");
      handle->response_code = MHD_HTTP_UNAUTHORIZED;
      GNUNET_SCHEDULER_add_now (&do_error, handle);
      return;
    }
    GNUNET_free(expected_psw);
  }
  else
  {
    GNUNET_free_non_null(user_psw);
    handle->emsg = GNUNET_strdup("server_error");
    handle->edesc = GNUNET_strdup ("gnunet configuration failed");
    handle->response_code = MHD_HTTP_INTERNAL_SERVER_ERROR;
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }

  //check client_id
  for (handle->ego_entry = handle->ego_head; NULL != handle->ego_entry->next; )
  {
    if ( 0 == strcmp(handle->ego_entry->keystring, client_id))
    {
      client_exists = GNUNET_YES;
      break;
    }
    handle->ego_entry = handle->ego_entry->next;
  }
  if (GNUNET_NO == client_exists)
  {
    GNUNET_free_non_null(user_psw);
    handle->emsg=GNUNET_strdup("invalid_client");
    handle->response_code = MHD_HTTP_UNAUTHORIZED;
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }

  /*
   * Check parameter
   */

  //TODO Do not allow multiple equal parameter names
  //REQUIRED grant_type
  GNUNET_CRYPTO_hash (OIDC_GRANT_TYPE_KEY, strlen (OIDC_GRANT_TYPE_KEY), &cache_key);
  if ( GNUNET_NO
       == GNUNET_CONTAINER_multihashmap_contains (
                                                  handle->rest_handle->url_param_map, &cache_key) )
  {
    GNUNET_free_non_null(user_psw);
    handle->emsg = GNUNET_strdup("invalid_request");
    handle->edesc = GNUNET_strdup("missing parameter grant_type");
    handle->response_code = MHD_HTTP_BAD_REQUEST;
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }
  grant_type = GNUNET_CONTAINER_multihashmap_get (
                                                  handle->rest_handle->url_param_map, &cache_key);

  //REQUIRED code
  GNUNET_CRYPTO_hash (OIDC_CODE_KEY, strlen (OIDC_CODE_KEY), &cache_key);
  if ( GNUNET_NO
       == GNUNET_CONTAINER_multihashmap_contains (
                                                  handle->rest_handle->url_param_map, &cache_key) )
  {
    GNUNET_free_non_null(user_psw);
    handle->emsg = GNUNET_strdup("invalid_request");
    handle->edesc = GNUNET_strdup("missing parameter code");
    handle->response_code = MHD_HTTP_BAD_REQUEST;
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }
  code = GNUNET_CONTAINER_multihashmap_get (handle->rest_handle->url_param_map,
                                            &cache_key);

  //REQUIRED redirect_uri
  GNUNET_CRYPTO_hash (OIDC_REDIRECT_URI_KEY, strlen (OIDC_REDIRECT_URI_KEY),
                      &cache_key);
  if ( GNUNET_NO
       == GNUNET_CONTAINER_multihashmap_contains (
                                                  handle->rest_handle->url_param_map, &cache_key) )
  {
    GNUNET_free_non_null(user_psw);
    handle->emsg = GNUNET_strdup("invalid_request");
    handle->edesc = GNUNET_strdup("missing parameter redirect_uri");
    handle->response_code = MHD_HTTP_BAD_REQUEST;
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }

  //Check parameter grant_type == "authorization_code"
  if (0 != strcmp(OIDC_GRANT_TYPE_VALUE, grant_type))
  {
    GNUNET_free_non_null(user_psw);
    handle->emsg=GNUNET_strdup("unsupported_grant_type");
    handle->response_code = MHD_HTTP_BAD_REQUEST;
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }
  GNUNET_CRYPTO_hash (code, strlen (code), &cache_key);
  int i = 1;
  if ( GNUNET_SYSERR
       == GNUNET_CONTAINER_multihashmap_put (OIDC_ticket_once,
                                             &cache_key,
                                             &i,
                                             GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY) )
  {
    GNUNET_free_non_null(user_psw);
    handle->emsg = GNUNET_strdup("invalid_request");
    handle->edesc = GNUNET_strdup("Cannot use the same code more than once");
    handle->response_code = MHD_HTTP_BAD_REQUEST;
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }

  //decode code
  GNUNET_STRINGS_base64_decode(code,strlen(code),&code_output);
  root = json_loads (code_output, 0, &error);
  GNUNET_free(code_output);
  ticket_string = json_object_get (root, "ticket");
  nonce = json_object_get (root, "nonce");
  max_age = json_object_get (root, "max_age");

  if(ticket_string == NULL && !json_is_string(ticket_string))
  {
    GNUNET_free_non_null(user_psw);
    handle->emsg = GNUNET_strdup("invalid_request");
    handle->edesc = GNUNET_strdup("invalid code");
    handle->response_code = MHD_HTTP_BAD_REQUEST;
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }

  struct GNUNET_IDENTITY_PROVIDER_Ticket *ticket = GNUNET_new(struct GNUNET_IDENTITY_PROVIDER_Ticket);
  if ( GNUNET_OK
       != GNUNET_STRINGS_string_to_data (json_string_value(ticket_string),
                                         strlen (json_string_value(ticket_string)),
                                         ticket,
                                         sizeof(struct GNUNET_IDENTITY_PROVIDER_Ticket)))
  {
    GNUNET_free_non_null(user_psw);
    handle->emsg = GNUNET_strdup("invalid_request");
    handle->edesc = GNUNET_strdup("invalid code");
    handle->response_code = MHD_HTTP_BAD_REQUEST;
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    GNUNET_free(ticket);
    return;
  }
  // this is the current client (relying party)
  struct GNUNET_CRYPTO_EcdsaPublicKey pub_key;
  GNUNET_IDENTITY_ego_get_public_key(handle->ego_entry->ego,&pub_key);
  if (0 != memcmp(&pub_key,&ticket->audience,sizeof(struct GNUNET_CRYPTO_EcdsaPublicKey)))
  {
    GNUNET_free_non_null(user_psw);
    handle->emsg = GNUNET_strdup("invalid_request");
    handle->edesc = GNUNET_strdup("invalid code");
    handle->response_code = MHD_HTTP_BAD_REQUEST;
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    GNUNET_free(ticket);
    return;
  }

  //create jwt
  unsigned long long int expiration_time;
  if ( GNUNET_OK
       != GNUNET_CONFIGURATION_get_value_number(cfg, "identity-rest-plugin",
                                                "expiration_time", &expiration_time) )
  {
    GNUNET_free_non_null(user_psw);
    handle->emsg = GNUNET_strdup("server_error");
    handle->edesc = GNUNET_strdup ("gnunet configuration failed");
    handle->response_code = MHD_HTTP_INTERNAL_SERVER_ERROR;
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    GNUNET_free(ticket);
    return;
  }

  struct GNUNET_IDENTITY_ATTRIBUTE_ClaimList *cl = GNUNET_new (struct GNUNET_IDENTITY_ATTRIBUTE_ClaimList);
  //aud REQUIRED public key client_id must be there
  GNUNET_IDENTITY_ATTRIBUTE_list_add(cl,
                                     "aud",
                                     GNUNET_IDENTITY_ATTRIBUTE_TYPE_STRING,
                                     client_id,
                                     strlen(client_id));
  //exp REQUIRED time expired from config
  struct GNUNET_TIME_Absolute exp_time = GNUNET_TIME_relative_to_absolute (
                                                                           GNUNET_TIME_relative_multiply (GNUNET_TIME_relative_get_second_ (),
                                                                                                          expiration_time));
  const char* exp_time_string = GNUNET_STRINGS_absolute_time_to_string(exp_time);
  GNUNET_IDENTITY_ATTRIBUTE_list_add (cl,
                                      "exp",
                                      GNUNET_IDENTITY_ATTRIBUTE_TYPE_STRING,
                                      exp_time_string,
                                      strlen(exp_time_string));
  //iat REQUIRED time now
  struct GNUNET_TIME_Absolute time_now = GNUNET_TIME_absolute_get();
  const char* time_now_string = GNUNET_STRINGS_absolute_time_to_string(time_now);
  GNUNET_IDENTITY_ATTRIBUTE_list_add (cl,
                                      "iat",
                                      GNUNET_IDENTITY_ATTRIBUTE_TYPE_STRING,
                                      time_now_string,
                                      strlen(time_now_string));
  //nonce only if nonce is provided
  if ( NULL != nonce && json_is_string(nonce) )
  {
    GNUNET_IDENTITY_ATTRIBUTE_list_add (cl,
                                        "nonce",
                                        GNUNET_IDENTITY_ATTRIBUTE_TYPE_STRING,
                                        json_string_value(nonce),
                                        strlen(json_string_value(nonce)));
  }
  //auth_time only if max_age is provided
  if ( NULL != max_age && json_is_string(max_age) )
  {
    GNUNET_IDENTITY_ATTRIBUTE_list_add (cl,
                                        "auth_time",
                                        GNUNET_IDENTITY_ATTRIBUTE_TYPE_STRING,
                                        json_string_value(max_age),
                                        strlen(json_string_value(max_age)));
  }
  //TODO OPTIONAL acr,amr,azp

  struct EgoEntry *ego_entry;
  for (ego_entry = handle->ego_head; NULL != ego_entry; ego_entry = ego_entry->next)
  {
    GNUNET_IDENTITY_ego_get_public_key (ego_entry->ego, &pub_key);
    if (0 == memcmp (&pub_key, &ticket->audience, sizeof(struct GNUNET_CRYPTO_EcdsaPublicKey)))
    {
      break;
    }
  }
  if ( NULL == ego_entry )
  {
    GNUNET_free_non_null(user_psw);
    handle->emsg = GNUNET_strdup("invalid_request");
    handle->edesc = GNUNET_strdup("invalid code....");
    handle->response_code = MHD_HTTP_BAD_REQUEST;
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    GNUNET_free(ticket);
    return;
  }
  char *id_token = jwt_create_from_list(&ticket->audience,
                                        cl,
                                        GNUNET_IDENTITY_ego_get_private_key(ego_entry->ego));

  //Create random access_token
  char* access_token_number;
  char* access_token;
  uint64_t random_number;
  random_number = GNUNET_CRYPTO_random_u64(GNUNET_CRYPTO_QUALITY_NONCE, UINT64_MAX);
  GNUNET_asprintf(&access_token_number, "%" PRIu64, random_number);
  GNUNET_STRINGS_base64_encode(access_token_number,strlen(access_token_number),&access_token);



  //TODO OPTIONAL add refresh_token and scope
  GNUNET_asprintf (&json_response,
                   "{ \"access_token\" : \"%s\", "
                   "\"token_type\" : \"Bearer\", "
                   "\"expires_in\" : %d, "
                   "\"id_token\" : \"%s\"}",
                   access_token,
                   expiration_time,
                   id_token);
  GNUNET_CRYPTO_hash(access_token, strlen(access_token), &cache_key);
  char *id_ticket_combination;
  GNUNET_asprintf(&id_ticket_combination,
                  "%s;%s",
                  client_id,
                  json_string_value(ticket_string));
  GNUNET_CONTAINER_multihashmap_put(OIDC_interpret_access_token,
                                    &cache_key,
                                    id_ticket_combination,
                                    GNUNET_CONTAINER_MULTIHASHMAPOPTION_REPLACE);

  resp = GNUNET_REST_create_response (json_response);
  MHD_add_response_header (resp, "Cache-Control", "no-store");
  MHD_add_response_header (resp, "Pragma", "no-cache");
  MHD_add_response_header (resp, "Content-Type", "application/json");
  handle->proc (handle->proc_cls, resp, MHD_HTTP_OK);

  GNUNET_IDENTITY_ATTRIBUTE_list_destroy(cl);
  GNUNET_free(access_token_number);
  GNUNET_free(access_token);
  GNUNET_free(user_psw);
  GNUNET_free(json_response);
  GNUNET_free(ticket);
  GNUNET_free(id_token);
  json_decref (root);
  GNUNET_SCHEDULER_add_now(&cleanup_handle_delayed, handle);
}

/**
 * Collects claims and stores them in handle
 */
static void
consume_ticket (void *cls,
                const struct GNUNET_CRYPTO_EcdsaPublicKey *identity,
                const struct GNUNET_IDENTITY_ATTRIBUTE_Claim *attr)
{
  struct RequestHandle *handle = cls;
  char *tmp_value;
  json_t *value;

  if (NULL == identity)
  {
    GNUNET_SCHEDULER_add_now (&return_userinfo_response, handle);
    return;
  }

  tmp_value = GNUNET_IDENTITY_ATTRIBUTE_value_to_string (attr->type,
                                                         attr->data,
                                                         attr->data_size);

  value = json_string (tmp_value);


  json_object_set_new (handle->oidc->response,
                       attr->name,
                       value);
  GNUNET_free (tmp_value);
}

/**
 * Responds to userinfo GET and url-encoded POST request
 *
 * @param con_handle the connection handle
 * @param url the url
 * @param cls the RequestHandle
 */
static void
userinfo_endpoint (struct GNUNET_REST_RequestHandle *con_handle,
                   const char* url, void *cls)
{
  //TODO expiration time
  struct RequestHandle *handle = cls;
  char delimiter[] = " ";
  char delimiter_db[] = ";";
  struct GNUNET_HashCode cache_key;
  char *authorization, *authorization_type, *authorization_access_token;
  char *client_ticket, *client, *ticket_str;
  struct GNUNET_IDENTITY_PROVIDER_Ticket *ticket;

  GNUNET_CRYPTO_hash (OIDC_AUTHORIZATION_HEADER_KEY,
                      strlen (OIDC_AUTHORIZATION_HEADER_KEY),
                      &cache_key);
  if ( GNUNET_NO
       == GNUNET_CONTAINER_multihashmap_contains (
                                                  handle->rest_handle->header_param_map, &cache_key) )
  {
    handle->emsg = GNUNET_strdup("invalid_token");
    handle->edesc = GNUNET_strdup("No Access Token");
    handle->response_code = MHD_HTTP_UNAUTHORIZED;
    GNUNET_SCHEDULER_add_now (&do_userinfo_error, handle);
    return;
  }
  authorization = GNUNET_CONTAINER_multihashmap_get (
                                                     handle->rest_handle->header_param_map, &cache_key);

  //split header in "Bearer" and access_token
  authorization = GNUNET_strdup(authorization);
  authorization_type = strtok (authorization, delimiter);
  if ( 0 != strcmp ("Bearer", authorization_type) )
  {
    handle->emsg = GNUNET_strdup("invalid_token");
    handle->edesc = GNUNET_strdup("No Access Token");
    handle->response_code = MHD_HTTP_UNAUTHORIZED;
    GNUNET_SCHEDULER_add_now (&do_userinfo_error, handle);
    GNUNET_free(authorization);
    return;
  }
  authorization_access_token = strtok (NULL, delimiter);
  if ( NULL == authorization_access_token )
  {
    handle->emsg = GNUNET_strdup("invalid_token");
    handle->edesc = GNUNET_strdup("No Access Token");
    handle->response_code = MHD_HTTP_UNAUTHORIZED;
    GNUNET_SCHEDULER_add_now (&do_userinfo_error, handle);
    GNUNET_free(authorization);
    return;
  }

  GNUNET_CRYPTO_hash (authorization_access_token,
                      strlen (authorization_access_token),
                      &cache_key);
  if ( GNUNET_NO == GNUNET_CONTAINER_multihashmap_contains (OIDC_interpret_access_token,
                                                            &cache_key) )
  {
    handle->emsg = GNUNET_strdup("invalid_token");
    handle->edesc = GNUNET_strdup("The Access Token expired");
    handle->response_code = MHD_HTTP_UNAUTHORIZED;
    GNUNET_SCHEDULER_add_now (&do_userinfo_error, handle);
    GNUNET_free(authorization);
    return;
  }

  client_ticket = GNUNET_CONTAINER_multihashmap_get(OIDC_interpret_access_token,
                                                    &cache_key);
  client_ticket = GNUNET_strdup(client_ticket);
  client = strtok(client_ticket,delimiter_db);
  if (NULL == client)
  {
    handle->emsg = GNUNET_strdup("invalid_token");
    handle->edesc = GNUNET_strdup("The Access Token expired");
    handle->response_code = MHD_HTTP_UNAUTHORIZED;
    GNUNET_SCHEDULER_add_now (&do_userinfo_error, handle);
    GNUNET_free(authorization);
    GNUNET_free(client_ticket);
    return;
  }
  handle->ego_entry = handle->ego_head;
  for(; NULL != handle->ego_entry; handle->ego_entry = handle->ego_entry->next)
  {
    if (0 == strcmp(handle->ego_entry->keystring,client))
    {
      break;
    }
  }
  if (NULL == handle->ego_entry)
  {
    handle->emsg = GNUNET_strdup("invalid_token");
    handle->edesc = GNUNET_strdup("The Access Token expired");
    handle->response_code = MHD_HTTP_UNAUTHORIZED;
    GNUNET_SCHEDULER_add_now (&do_userinfo_error, handle);
    GNUNET_free(authorization);
    GNUNET_free(client_ticket);
    return;
  }
  ticket_str = strtok(NULL, delimiter_db);
  if (NULL == ticket_str)
  {
    handle->emsg = GNUNET_strdup("invalid_token");
    handle->edesc = GNUNET_strdup("The Access Token expired");
    handle->response_code = MHD_HTTP_UNAUTHORIZED;
    GNUNET_SCHEDULER_add_now (&do_userinfo_error, handle);
    GNUNET_free(authorization);
    GNUNET_free(client_ticket);
    return;
  }
  ticket = GNUNET_new(struct GNUNET_IDENTITY_PROVIDER_Ticket);
  if ( GNUNET_OK
       != GNUNET_STRINGS_string_to_data (ticket_str,
                                         strlen (ticket_str),
                                         ticket,
                                         sizeof(struct GNUNET_IDENTITY_PROVIDER_Ticket)))
  {
    handle->emsg = GNUNET_strdup("invalid_token");
    handle->edesc = GNUNET_strdup("The Access Token expired");
    handle->response_code = MHD_HTTP_UNAUTHORIZED;
    GNUNET_SCHEDULER_add_now (&do_userinfo_error, handle);
    GNUNET_free(ticket);
    GNUNET_free(authorization);
    GNUNET_free(client_ticket);
    return;
  }

  handle->idp = GNUNET_IDENTITY_PROVIDER_connect (cfg);
  handle->oidc->response = json_object();
  json_object_set_new( handle->oidc->response, "sub", json_string( handle->ego_entry->keystring));
  handle->idp_op = GNUNET_IDENTITY_PROVIDER_ticket_consume (
                                                            handle->idp,
                                                            GNUNET_IDENTITY_ego_get_private_key (handle->ego_entry->ego),
                                                            ticket,
                                                            consume_ticket,
                                                            handle);
  GNUNET_free(ticket);
  GNUNET_free(authorization);
  GNUNET_free(client_ticket);

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
    {MHD_HTTP_METHOD_GET, GNUNET_REST_API_NS_AUTHORIZE, &authorize_endpoint},
    {MHD_HTTP_METHOD_POST, GNUNET_REST_API_NS_AUTHORIZE, &authorize_endpoint}, //url-encoded
    {MHD_HTTP_METHOD_POST, GNUNET_REST_API_NS_LOGIN, &login_cont},
    {MHD_HTTP_METHOD_POST, GNUNET_REST_API_NS_TOKEN, &token_endpoint },
    {MHD_HTTP_METHOD_GET, GNUNET_REST_API_NS_USERINFO, &userinfo_endpoint },
    {MHD_HTTP_METHOD_POST, GNUNET_REST_API_NS_USERINFO, &userinfo_endpoint },
    {MHD_HTTP_METHOD_OPTIONS, GNUNET_REST_API_NS_OIDC,
      &options_cont},
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
    ego_entry->identifier = GNUNET_strdup (identifier);
    GNUNET_CONTAINER_DLL_insert_tail(handle->ego_head,handle->ego_tail, ego_entry);
    return;
  }
  /* Ego renamed or added */
  if (identifier != NULL) {
    for (ego_entry = handle->ego_head; NULL != ego_entry; ego_entry = ego_entry->next) {
      if (ego_entry->ego == ego) {
        /* Rename */
        GNUNET_free (ego_entry->identifier);
        ego_entry->identifier = GNUNET_strdup (identifier);
        break;
      }
    }
    if (NULL == ego_entry) {
      /* Add */
      ego_entry = GNUNET_new (struct EgoEntry);
      GNUNET_IDENTITY_ego_get_public_key (ego, &pk);
      ego_entry->keystring =
        GNUNET_CRYPTO_ecdsa_public_key_to_string (&pk);
      ego_entry->ego = ego;
      ego_entry->identifier = GNUNET_strdup (identifier);
      GNUNET_CONTAINER_DLL_insert_tail(handle->ego_head,handle->ego_tail, ego_entry);
    }
  } else {
    /* Delete */
    for (ego_entry = handle->ego_head; NULL != ego_entry; ego_entry = ego_entry->next) {
      if (ego_entry->ego == ego)
        break;
    }
    if (NULL != ego_entry)
      GNUNET_CONTAINER_DLL_remove(handle->ego_head,handle->ego_tail, ego_entry);
  }

}

static void
rest_identity_process_request(struct GNUNET_REST_RequestHandle *rest_handle,
                              GNUNET_REST_ResultProcessor proc,
                              void *proc_cls)
{
  struct RequestHandle *handle = GNUNET_new (struct RequestHandle);
  handle->oidc = GNUNET_new (struct OIDC_Variables);
  if ( NULL == OIDC_identity_login_time )
    OIDC_identity_login_time = GNUNET_CONTAINER_multihashmap_create (10, GNUNET_NO);
  if ( NULL == OIDC_identity_grants )
    OIDC_identity_grants = GNUNET_CONTAINER_multihashmap_create (10, GNUNET_NO);
  if ( NULL == OIDC_ticket_once )
    OIDC_ticket_once = GNUNET_CONTAINER_multihashmap_create (10, GNUNET_NO);
  if ( NULL == OIDC_interpret_access_token )
    OIDC_interpret_access_token = GNUNET_CONTAINER_multihashmap_create (10, GNUNET_NO);
  handle->response_code = 0;
  handle->timeout = GNUNET_TIME_UNIT_FOREVER_REL;
  handle->proc_cls = proc_cls;
  handle->proc = proc;
  handle->state = ID_REST_STATE_INIT;
  handle->rest_handle = rest_handle;

  handle->url = GNUNET_strdup (rest_handle->url);
  if (handle->url[strlen (handle->url)-1] == '/')
    handle->url[strlen (handle->url)-1] = '\0';
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Connecting...\n");
  handle->identity_handle = GNUNET_IDENTITY_connect (cfg,
                                                     &list_ego,
                                                     handle);
  handle->namestore_handle = GNUNET_NAMESTORE_connect (cfg);
  handle->timeout_task =
    GNUNET_SCHEDULER_add_delayed (handle->timeout,
                                  &do_timeout,
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
libgnunet_plugin_rest_openid_connect_init (void *cls)
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
  api->name = GNUNET_REST_API_NS_OIDC;
  api->process_request = &rest_identity_process_request;
  GNUNET_asprintf (&allow_methods,
                   "%s, %s, %s, %s, %s",
                   MHD_HTTP_METHOD_GET,
                   MHD_HTTP_METHOD_POST,
                   MHD_HTTP_METHOD_PUT,
                   MHD_HTTP_METHOD_DELETE,
                   MHD_HTTP_METHOD_OPTIONS);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              _("Identity Provider REST API initialized\n"));
  return api;
}


/**
 * Exit point from the plugin.
 *
 * @param cls the plugin context (as returned by "init")
 * @return always NULL
 */
void *
libgnunet_plugin_rest_openid_connect_done (void *cls)
{
  struct GNUNET_REST_Plugin *api = cls;
  struct Plugin *plugin = api->cls;
  plugin->cfg = NULL;

  struct GNUNET_CONTAINER_MultiHashMapIterator *hashmap_it;
  void *value = NULL;
  hashmap_it = GNUNET_CONTAINER_multihashmap_iterator_create (
                                                              OIDC_identity_login_time);
  while (GNUNET_YES ==
         GNUNET_CONTAINER_multihashmap_iterator_next (hashmap_it, NULL, value))
  {
    if (NULL != value)
      GNUNET_free(value);
  }
  GNUNET_CONTAINER_multihashmap_destroy(OIDC_identity_login_time);
  hashmap_it = GNUNET_CONTAINER_multihashmap_iterator_create (OIDC_identity_grants);
  while (GNUNET_YES ==
         GNUNET_CONTAINER_multihashmap_iterator_next (hashmap_it, NULL, value))
  {
    if (NULL != value)
      GNUNET_free(value);
  }
  GNUNET_CONTAINER_multihashmap_destroy(OIDC_identity_grants);
  hashmap_it = GNUNET_CONTAINER_multihashmap_iterator_create (OIDC_ticket_once);
  while (GNUNET_YES ==
         GNUNET_CONTAINER_multihashmap_iterator_next (hashmap_it, NULL, value))
  {
    if (NULL != value)
      GNUNET_free(value);
  }
  GNUNET_CONTAINER_multihashmap_destroy(OIDC_ticket_once);
  hashmap_it = GNUNET_CONTAINER_multihashmap_iterator_create (OIDC_interpret_access_token);
  while (GNUNET_YES ==
         GNUNET_CONTAINER_multihashmap_iterator_next (hashmap_it, NULL, value))
  {
    if (NULL != value)
      GNUNET_free(value);
  }
  GNUNET_CONTAINER_multihashmap_destroy(OIDC_interpret_access_token);
  GNUNET_CONTAINER_multihashmap_iterator_destroy(hashmap_it);
  GNUNET_free_non_null (allow_methods);
  GNUNET_free (api);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Identity Provider REST plugin is finished\n");
  return NULL;
}

/* end of plugin_rest_identity_provider.c */

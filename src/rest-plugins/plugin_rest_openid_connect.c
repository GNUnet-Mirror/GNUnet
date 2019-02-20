/*
   This file is part of GNUnet.
   Copyright (C) 2012-2018 GNUnet e.V.

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
#include "microhttpd.h"
#include <jansson.h>
#include <inttypes.h>
#include "gnunet_signatures.h"
#include "gnunet_reclaim_attribute_lib.h"
#include "gnunet_reclaim_service.h"
#include "oidc_helper.h"

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
 * OIDC cookie expiration (in seconds)
 */
#define OIDC_COOKIE_EXPIRATION 3

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
 * OIDC cookie header if user cancelled
 */
#define OIDC_COOKIE_HEADER_ACCESS_DENIED "Identity=Denied"

/**
 * OIDC expected response_type while authorizing
 */
#define OIDC_EXPECTED_AUTHORIZATION_RESPONSE_TYPE "code"

/**
 * OIDC expected scope part while authorizing
 */
#define OIDC_EXPECTED_AUTHORIZATION_SCOPE "openid"

/**
 * OIDC error key for invalid client
 */
#define OIDC_ERROR_KEY_INVALID_CLIENT "invalid_client"

/**
 * OIDC error key for invalid scopes
 */
#define OIDC_ERROR_KEY_INVALID_SCOPE "invalid_scope"

/**
 * OIDC error key for invalid requests
 */
#define OIDC_ERROR_KEY_INVALID_REQUEST "invalid_request"

/**
 * OIDC error key for invalid tokens
 */
#define OIDC_ERROR_KEY_INVALID_TOKEN "invalid_token"

/**
 * OIDC error key for invalid cookies
 */
#define OIDC_ERROR_KEY_INVALID_COOKIE "invalid_cookie"

/**
 * OIDC error key for generic server errors
 */
#define OIDC_ERROR_KEY_SERVER_ERROR "server_error"

/**
 * OIDC error key for unsupported grants
 */
#define OIDC_ERROR_KEY_UNSUPPORTED_GRANT_TYPE "unsupported_grant_type"

/**
 * OIDC error key for unsupported response types
 */
#define OIDC_ERROR_KEY_UNSUPPORTED_RESPONSE_TYPE "unsupported_response_type"

/**
 * OIDC error key for unauthorized clients
 */
#define OIDC_ERROR_KEY_UNAUTHORIZED_CLIENT "unauthorized_client"

/**
 * OIDC error key for denied access
 */
#define OIDC_ERROR_KEY_ACCESS_DENIED "access_denied"



/**
 * OIDC ignored parameter array
 */
static char* OIDC_ignored_parameter_array [] =
{
  "display",
  "prompt",
  "ui_locales",
  "response_mode",
  "id_token_hint",
  "login_hint",
  "acr_values"
};

/**
 * OIDC Hash map that keeps track of issued cookies
 */
struct GNUNET_CONTAINER_MultiHashMap *OIDC_cookie_jar_map;

/**
 * OIDC authorized identities and times hashmap
 */
struct GNUNET_CONTAINER_MultiHashMap *OIDC_identity_grants;

/**
 * OIDC Hash map that keeps track of used authorization code(s)
 */
struct GNUNET_CONTAINER_MultiHashMap *OIDC_used_ticket_map;

/**
 * Hash map that links the issued access token to the corresponding ticket and ego
 */
struct GNUNET_CONTAINER_MultiHashMap *OIDC_access_token_map;

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
   * User cancelled authorization/login
   */
  int user_cancelled;

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
   * GNS handle
   */
  struct GNUNET_GNS_Handle *gns_handle;

  /**
   * GNS lookup op
   */
  struct GNUNET_GNS_LookupRequest *gns_op;

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
  struct GNUNET_RECLAIM_ATTRIBUTE_ClaimList *attr_list;

  /**
   * IDENTITY Operation
   */
  struct GNUNET_IDENTITY_Operation *op;

  /**
   * Identity Provider
   */
  struct GNUNET_RECLAIM_Handle *idp;

  /**
   * Idp Operation
   */
  struct GNUNET_RECLAIM_Operation *idp_op;

  /**
   * Attribute iterator
   */
  struct GNUNET_RECLAIM_AttributeIterator *attr_it;

  /**
   * Ticket iterator
   */
  struct GNUNET_RECLAIM_TicketIterator *ticket_it;

  /**
   * A ticket
   */
  struct GNUNET_RECLAIM_Ticket ticket;

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
   * The redirect prefix
   */
  char *redirect_prefix;

  /**
   * The redirect suffix
   */
  char *redirect_suffix;

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

};

/**
 * Cleanup lookup handle
 * @param handle Handle to clean up
 */
static void
cleanup_handle (struct RequestHandle *handle)
{
  struct GNUNET_RECLAIM_ATTRIBUTE_ClaimListEntry *claim_entry;
  struct GNUNET_RECLAIM_ATTRIBUTE_ClaimListEntry *claim_tmp;
  struct EgoEntry *ego_entry;
  struct EgoEntry *ego_tmp;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Cleaning up\n");
  if (NULL != handle->timeout_task)
    GNUNET_SCHEDULER_cancel (handle->timeout_task);
  if (NULL != handle->identity_handle)
    GNUNET_IDENTITY_disconnect (handle->identity_handle);
  if (NULL != handle->attr_it)
    GNUNET_RECLAIM_get_attributes_stop (handle->attr_it);
  if (NULL != handle->ticket_it)
    GNUNET_RECLAIM_ticket_iteration_stop (handle->ticket_it);
  if (NULL != handle->idp)
    GNUNET_RECLAIM_disconnect (handle->idp);
  GNUNET_free_non_null (handle->url);
  GNUNET_free_non_null (handle->tld);
  GNUNET_free_non_null (handle->redirect_prefix);
  GNUNET_free_non_null (handle->redirect_suffix);
  GNUNET_free_non_null (handle->emsg);
  GNUNET_free_non_null (handle->edesc);
  if (NULL != handle->gns_op)
    GNUNET_GNS_lookup_cancel (handle->gns_op);
  if (NULL != handle->gns_handle)
    GNUNET_GNS_disconnect (handle->gns_handle);

  if (NULL != handle->namestore_handle)
    GNUNET_NAMESTORE_disconnect (handle->namestore_handle);
  if (NULL != handle->oidc)
  {
    GNUNET_free_non_null (handle->oidc->client_id);
    GNUNET_free_non_null (handle->oidc->login_identity);
    GNUNET_free_non_null (handle->oidc->nonce);
    GNUNET_free_non_null (handle->oidc->redirect_uri);
    GNUNET_free_non_null (handle->oidc->response_type);
    GNUNET_free_non_null (handle->oidc->scope);
    GNUNET_free_non_null (handle->oidc->state);
    json_decref (handle->oidc->response);
    GNUNET_free (handle->oidc);
  }
  if ( NULL != handle->attr_list )
  {
    for (claim_entry = handle->attr_list->list_head;
         NULL != claim_entry;)
    {
      claim_tmp = claim_entry;
      claim_entry = claim_entry->next;
      GNUNET_free (claim_tmp->claim);
      GNUNET_free (claim_tmp);
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
  GNUNET_free_non_null (handle->attr_it);
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
    handle->response_code = MHD_HTTP_BAD_REQUEST;
  resp = GNUNET_REST_create_response (json_error);
  if (MHD_HTTP_UNAUTHORIZED == handle->response_code)
    MHD_add_response_header (resp,
                             MHD_HTTP_HEADER_WWW_AUTHENTICATE,
                             "Basic");
  MHD_add_response_header (resp,
                           MHD_HTTP_HEADER_CONTENT_TYPE,
                           "application/json");
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
  MHD_add_response_header (resp,
                           MHD_HTTP_HEADER_WWW_AUTHENTICATE,
                           "Bearer");
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
 * Returns base64 encoded string urlencoded
 *
 * @param string the string to encode
 * @return base64 encoded string
 */
static char*
base64_encode (const char *s)
{
  char *enc;
  char *enc_urlencode;
  char *tmp;
  int i;
  int num_pads = 0;

  GNUNET_STRINGS_base64_encode (s, strlen (s), &enc);
  tmp = strchr (enc, '=');
  num_pads = strlen (enc) - (tmp - enc);
  GNUNET_assert ((3 > num_pads) && (0 <= num_pads));
  if (0 == num_pads)
    return enc;
  enc_urlencode = GNUNET_malloc (strlen (enc) + num_pads*2);
  strcpy (enc_urlencode, enc);
  GNUNET_free (enc);
  tmp = strchr (enc_urlencode, '=');
  for (i = 0; i < num_pads; i++)
  {
    strcpy (tmp, "%3D"); //replace '=' with '%3D'
    tmp += 3;
  }
  return enc_urlencode;
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
  char *tmp_cookies;
  char *token;
  char *value;

  //gets identity of login try with cookie
  GNUNET_CRYPTO_hash (OIDC_COOKIE_HEADER_KEY, strlen (OIDC_COOKIE_HEADER_KEY),
                      &cache_key);
  if ( GNUNET_NO == GNUNET_CONTAINER_multihashmap_contains (handle->rest_handle->header_param_map,
                                                             &cache_key) )
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "No cookie found\n");
    return;
  }
  //splits cookies and find 'Identity' cookie
  tmp_cookies = GNUNET_CONTAINER_multihashmap_get ( handle->rest_handle->header_param_map, &cache_key);
  cookies = GNUNET_strdup (tmp_cookies);
  token = strtok (cookies, delimiter);
  handle->oidc->user_cancelled = GNUNET_NO;
  handle->oidc->login_identity = NULL;
  if (NULL == token)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Unable to parse cookie: %s\n",
                cookies);
    GNUNET_free (cookies);
    return;
  }

  while (NULL != token)
  {
    if (0 == strcmp (token,
                     OIDC_COOKIE_HEADER_ACCESS_DENIED))
    {
      handle->oidc->user_cancelled = GNUNET_YES;
      GNUNET_free (cookies);
      return;
    }
    if (NULL != strstr (token, OIDC_COOKIE_HEADER_INFORMATION_KEY))
      break;
    token = strtok (NULL, delimiter);
  }
  if (NULL == token)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "No cookie value to process: %s\n",
                cookies);
    GNUNET_free (cookies);
    return;
  }
  GNUNET_CRYPTO_hash (token, strlen (token),
                      &cache_key);
  if (GNUNET_NO == GNUNET_CONTAINER_multihashmap_contains (OIDC_cookie_jar_map, &cache_key))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "Found cookie `%s', but no corresponding expiration entry present...\n",
                token);
    GNUNET_free (cookies);
    return;
  }
  relog_time = GNUNET_CONTAINER_multihashmap_get (OIDC_cookie_jar_map,
                                                  &cache_key);
  current_time = GNUNET_TIME_absolute_get ();
  // 30 min after old login -> redirect to login
  if ( current_time.abs_value_us > relog_time->abs_value_us )
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "Found cookie `%s', but it is expired.\n",
                token);
    GNUNET_free (cookies);
    return;
  }
  value = strtok (token, OIDC_COOKIE_HEADER_INFORMATION_KEY);
  GNUNET_assert (NULL != value);
  handle->oidc->login_identity = GNUNET_strdup (value);
}

/**
 * Redirects to login page stored in configuration file
 */
static void
login_redirect (void *cls)
{
  char *login_base_url;
  char *new_redirect;
  struct MHD_Response *resp;
  struct RequestHandle *handle = cls;

  if ( GNUNET_OK
       == GNUNET_CONFIGURATION_get_value_string (cfg, "reclaim-rest-plugin",
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
    GNUNET_free (login_base_url);
  }
  else
  {
    handle->emsg = GNUNET_strdup (OIDC_ERROR_KEY_SERVER_ERROR);
    handle->edesc = GNUNET_strdup ("gnunet configuration failed");
    handle->response_code = MHD_HTTP_INTERNAL_SERVER_ERROR;
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }
  handle->proc (handle->proc_cls, resp, MHD_HTTP_FOUND);
  GNUNET_free (new_redirect);
  GNUNET_SCHEDULER_add_now (&cleanup_handle_delayed, handle);
}

/**
 * Does internal server error when iteration failed.
 */
static void
oidc_iteration_error (void *cls)
{
  struct RequestHandle *handle = cls;
  handle->emsg = GNUNET_strdup (OIDC_ERROR_KEY_SERVER_ERROR);
  handle->response_code = MHD_HTTP_INTERNAL_SERVER_ERROR;
  GNUNET_SCHEDULER_add_now (&do_error, handle);
}


/**
 * Issues ticket and redirects to relying party with the authorization code as
 * parameter. Otherwise redirects with error
 */
static void
oidc_ticket_issue_cb (void* cls,
                      const struct GNUNET_RECLAIM_Ticket *ticket)
{
  struct RequestHandle *handle = cls;
  struct MHD_Response *resp;
  char *ticket_str;
  char *redirect_uri;
  char *code_json_string;
  char *code_base64_final_string;

  handle->idp_op = NULL;
  handle->ticket = *ticket;
  if (NULL == ticket)
  {
    handle->emsg = GNUNET_strdup (OIDC_ERROR_KEY_SERVER_ERROR);
    handle->edesc = GNUNET_strdup ("Server cannot generate ticket.");
    GNUNET_SCHEDULER_add_now (&do_redirect_error, handle);
    return;
  }
  ticket_str = GNUNET_STRINGS_data_to_string_alloc (&handle->ticket,
                                                    sizeof (struct GNUNET_RECLAIM_Ticket));
  //TODO change if more attributes are needed (see max_age)
  code_json_string = OIDC_build_authz_code (&handle->priv_key,
                                            &handle->ticket,
                                            handle->oidc->nonce);
  code_base64_final_string = base64_encode (code_json_string);
  if ( (NULL != handle->redirect_prefix) &&
       (NULL != handle->redirect_suffix) &&
       (NULL != handle->tld) )
  {

    GNUNET_asprintf (&redirect_uri, "%s.%s/%s?%s=%s&state=%s",
                     handle->redirect_prefix,
                     handle->tld,
                     handle->redirect_suffix,
                     handle->oidc->response_type,
                     code_base64_final_string, handle->oidc->state);
  } else {
    GNUNET_asprintf (&redirect_uri, "%s?%s=%s&state=%s",
                     handle->oidc->redirect_uri,
                     handle->oidc->response_type,
                     code_base64_final_string, handle->oidc->state);

  }
  resp = GNUNET_REST_create_response ("");
  MHD_add_response_header (resp, "Location", redirect_uri);
  handle->proc (handle->proc_cls, resp, MHD_HTTP_FOUND);
  GNUNET_SCHEDULER_add_now (&cleanup_handle_delayed, handle);
  GNUNET_free (redirect_uri);
  GNUNET_free (ticket_str);
  GNUNET_free (code_json_string);
  GNUNET_free (code_base64_final_string);
}

static void
oidc_collect_finished_cb (void *cls)
{
  struct RequestHandle *handle = cls;
  handle->attr_it = NULL;
  handle->ticket_it = NULL;
  if (NULL == handle->attr_list->list_head)
  {
    handle->emsg = GNUNET_strdup (OIDC_ERROR_KEY_INVALID_SCOPE);
    handle->edesc = GNUNET_strdup ("The requested scope is not available.");
    GNUNET_SCHEDULER_add_now (&do_redirect_error, handle);
    return;
  }
  handle->idp_op = GNUNET_RECLAIM_ticket_issue (handle->idp,
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
                   const struct GNUNET_RECLAIM_ATTRIBUTE_Claim *attr)
{
  struct RequestHandle *handle = cls;
  struct GNUNET_RECLAIM_ATTRIBUTE_ClaimListEntry *le;
  char* scope_variables;
  char* scope_variable;
  char delimiter[]=" ";

  if ( (NULL == attr->name) || (NULL == attr->data) )
  {
    GNUNET_RECLAIM_get_attributes_next (handle->attr_it);
    return;
  }

  scope_variables = GNUNET_strdup (handle->oidc->scope);
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
    GNUNET_RECLAIM_get_attributes_next (handle->attr_it);
    GNUNET_free (scope_variables);
    return;
  }
  GNUNET_free (scope_variables);

  le = GNUNET_new (struct GNUNET_RECLAIM_ATTRIBUTE_ClaimListEntry);
  le->claim = GNUNET_RECLAIM_ATTRIBUTE_claim_new (attr->name, attr->type,
                                                  attr->data, attr->data_size);
  GNUNET_CONTAINER_DLL_insert (handle->attr_list->list_head,
                               handle->attr_list->list_tail, le);
  GNUNET_RECLAIM_get_attributes_next (handle->attr_it);
}


/**
 * Checks time and cookie and redirects accordingly
 */
static void
code_redirect (void *cls)
{
  struct RequestHandle *handle = cls;
  struct GNUNET_TIME_Absolute current_time, *relog_time;
  struct GNUNET_CRYPTO_EcdsaPublicKey pubkey, ego_pkey;
  struct GNUNET_HashCode cache_key;
  char *identity_cookie;

  GNUNET_asprintf (&identity_cookie, "Identity=%s", handle->oidc->login_identity);
  GNUNET_CRYPTO_hash (identity_cookie, strlen (identity_cookie), &cache_key);
  GNUNET_free (identity_cookie);
  //No login time for identity -> redirect to login
  if ( GNUNET_YES
       == GNUNET_CONTAINER_multihashmap_contains (OIDC_cookie_jar_map,
                                                  &cache_key) )
  {
    relog_time = GNUNET_CONTAINER_multihashmap_get (OIDC_cookie_jar_map,
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
        handle->emsg = GNUNET_strdup (OIDC_ERROR_KEY_INVALID_COOKIE);
        handle->edesc = GNUNET_strdup ("The cookie of a login identity is not valid");
        GNUNET_SCHEDULER_add_now (&do_redirect_error, handle);
        return;
      }
      // iterate over egos and compare their public key
      for (handle->ego_entry = handle->ego_head;
           NULL != handle->ego_entry; handle->ego_entry = handle->ego_entry->next)
      {
        GNUNET_IDENTITY_ego_get_public_key (handle->ego_entry->ego, &ego_pkey);
        if ( 0 == memcmp (&ego_pkey,
                          &pubkey,
                          sizeof (struct GNUNET_CRYPTO_EcdsaPublicKey)) )
        {
          handle->priv_key = *GNUNET_IDENTITY_ego_get_private_key (handle->ego_entry->ego);
          handle->idp = GNUNET_RECLAIM_connect (cfg);
          handle->attr_list = GNUNET_new (struct GNUNET_RECLAIM_ATTRIBUTE_ClaimList);
          handle->attr_it = GNUNET_RECLAIM_get_attributes_start (handle->idp,
                                                                 &handle->priv_key,
                                                                 &oidc_iteration_error,
                                                                 handle,
                                                                 &oidc_attr_collect,
                                                                 handle,
                                                                 &oidc_collect_finished_cb,
                                                                 handle);
          return;
        }
      }
      GNUNET_SCHEDULER_add_now (&login_redirect, handle);
      return;
    }
  }
}


static void
build_redirect (void *cls)
{
  struct RequestHandle *handle = cls;
  struct MHD_Response *resp;
  char* redirect_uri;

  if (GNUNET_YES == handle->oidc->user_cancelled)
  {
    if ( (NULL != handle->redirect_prefix) &&
         (NULL != handle->redirect_suffix) &&
         (NULL != handle->tld) )
    {
      GNUNET_asprintf (&redirect_uri, "%s.%s/%s?error=%s&error_description=%s&state=%s",
                       handle->redirect_prefix,
                       handle->tld,
                       handle->redirect_suffix,
                       "access_denied",
                       "User denied access",
                       handle->oidc->state);
    } else {
      GNUNET_asprintf (&redirect_uri, "%s?error=%s&error_description=%s&state=%s",
                       handle->oidc->redirect_uri,
                       "access_denied",
                       "User denied access",
                       handle->oidc->state);

    }
    resp = GNUNET_REST_create_response ("");
    MHD_add_response_header (resp, "Location", redirect_uri);
    handle->proc (handle->proc_cls, resp, MHD_HTTP_FOUND);
    GNUNET_SCHEDULER_add_now (&cleanup_handle_delayed, handle);
    GNUNET_free (redirect_uri);
    return;
  }
  GNUNET_SCHEDULER_add_now (&code_redirect, handle);
}


static void
lookup_redirect_uri_result (void *cls,
                            uint32_t rd_count,
                            const struct GNUNET_GNSRECORD_Data *rd)
{
  struct RequestHandle *handle = cls;
  char *tmp;
  char *tmp_key_str;
  char *pos;
  struct GNUNET_CRYPTO_EcdsaPublicKey redirect_zone;

  handle->gns_op = NULL;
  if (0 == rd_count)
  {
    handle->emsg = GNUNET_strdup (OIDC_ERROR_KEY_SERVER_ERROR);
    handle->edesc = GNUNET_strdup ("Server cannot generate ticket, redirect uri not found.");
    GNUNET_SCHEDULER_add_now (&do_redirect_error, handle);
    return;
  }
  for (int i = 0; i < rd_count; i++)
  {
    if (GNUNET_GNSRECORD_TYPE_RECLAIM_OIDC_REDIRECT != rd[i].record_type)
      continue;
    if (0 != strncmp (rd[i].data,
                      handle->oidc->redirect_uri,
                      rd[i].data_size))
      continue;
    tmp = GNUNET_strndup (rd[i].data,
                          rd[i].data_size);
    if (NULL == strstr (tmp,
                        handle->oidc->client_id))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Redirect uri %s does not contain client_id %s",
                  tmp,
                  handle->oidc->client_id);
    } else {

      pos = strrchr (tmp,
                     (unsigned char) '.');
      *pos = '\0';
      handle->redirect_prefix = GNUNET_strdup (tmp);
      tmp_key_str = pos + 1;
      pos = strchr (tmp_key_str,
                    (unsigned char) '/');
      *pos = '\0';
      handle->redirect_suffix = GNUNET_strdup (pos + 1);

      GNUNET_STRINGS_string_to_data (tmp_key_str,
                                     strlen (tmp_key_str),
                                     &redirect_zone,
                                     sizeof (redirect_zone));
    }
    GNUNET_SCHEDULER_add_now (&build_redirect, handle);
    GNUNET_free (tmp);
    return;
  }
  handle->emsg = GNUNET_strdup (OIDC_ERROR_KEY_SERVER_ERROR);
  handle->edesc = GNUNET_strdup ("Server cannot generate ticket, redirect uri not found.");
  GNUNET_SCHEDULER_add_now (&do_redirect_error, handle);
}



/**
 * Initiate redirect back to client.
 */
static void
client_redirect (void *cls)
{
  struct RequestHandle *handle = cls;

  /* Lookup client redirect uri to verify request */
  handle->gns_op = GNUNET_GNS_lookup (handle->gns_handle,
                                      GNUNET_GNS_EMPTY_LABEL_AT,
                                      &handle->oidc->client_pkey,
                                      GNUNET_GNSRECORD_TYPE_RECLAIM_OIDC_REDIRECT,
                                      GNUNET_GNS_LO_DEFAULT,
                                      &lookup_redirect_uri_result,
                                      handle);

}


/**
 * Iteration over all results finished, build final
 * response.
 *
 * @param cls the `struct RequestHandle`
 */
static void
build_authz_response (void *cls)
{
  struct RequestHandle *handle = cls;
  struct GNUNET_HashCode cache_key;

  char *expected_scope;
  char delimiter[]=" ";
  int number_of_ignored_parameter, iterator;


  // REQUIRED value: redirect_uri
  GNUNET_CRYPTO_hash (OIDC_REDIRECT_URI_KEY, strlen (OIDC_REDIRECT_URI_KEY),
                      &cache_key);
  if (GNUNET_NO == GNUNET_CONTAINER_multihashmap_contains (handle->rest_handle->url_param_map,
                                                           &cache_key))
  {
    handle->emsg=GNUNET_strdup (OIDC_ERROR_KEY_INVALID_REQUEST);
    handle->edesc=GNUNET_strdup ("missing parameter redirect_uri");
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }
  handle->oidc->redirect_uri =
    GNUNET_strdup (GNUNET_CONTAINER_multihashmap_get (handle->rest_handle->url_param_map,
                                                      &cache_key));

  // REQUIRED value: response_type
  GNUNET_CRYPTO_hash (OIDC_RESPONSE_TYPE_KEY, strlen (OIDC_RESPONSE_TYPE_KEY),
                      &cache_key);
  if (GNUNET_NO == GNUNET_CONTAINER_multihashmap_contains (handle->rest_handle->url_param_map,
                                                           &cache_key))
  {
    handle->emsg=GNUNET_strdup (OIDC_ERROR_KEY_INVALID_REQUEST);
    handle->edesc=GNUNET_strdup ("missing parameter response_type");
    GNUNET_SCHEDULER_add_now (&do_redirect_error, handle);
    return;
  }
  handle->oidc->response_type = GNUNET_CONTAINER_multihashmap_get (handle->rest_handle->url_param_map,
                                                                   &cache_key);
  handle->oidc->response_type = GNUNET_strdup (handle->oidc->response_type);

  // REQUIRED value: scope
  GNUNET_CRYPTO_hash (OIDC_SCOPE_KEY, strlen (OIDC_SCOPE_KEY), &cache_key);
  if (GNUNET_NO == GNUNET_CONTAINER_multihashmap_contains (handle->rest_handle->url_param_map,
                                                           &cache_key))
  {
    handle->emsg=GNUNET_strdup (OIDC_ERROR_KEY_INVALID_SCOPE);
    handle->edesc=GNUNET_strdup ("missing parameter scope");
    GNUNET_SCHEDULER_add_now (&do_redirect_error, handle);
    return;
  }
  handle->oidc->scope = GNUNET_CONTAINER_multihashmap_get (handle->rest_handle->url_param_map,
                                                           &cache_key);
  handle->oidc->scope = GNUNET_strdup (handle->oidc->scope);

  //OPTIONAL value: nonce
  GNUNET_CRYPTO_hash (OIDC_NONCE_KEY, strlen (OIDC_NONCE_KEY), &cache_key);
  if (GNUNET_YES == GNUNET_CONTAINER_multihashmap_contains (handle->rest_handle->url_param_map,
                                                            &cache_key))
  {
    handle->oidc->nonce = GNUNET_CONTAINER_multihashmap_get (handle->rest_handle->url_param_map,
                                                             &cache_key);
    handle->oidc->nonce = GNUNET_strdup (handle->oidc->nonce);
  }

  //TODO check other values if needed
  number_of_ignored_parameter = sizeof (OIDC_ignored_parameter_array) / sizeof (char *);
  for (iterator = 0; iterator < number_of_ignored_parameter; iterator++)
  {
    GNUNET_CRYPTO_hash (OIDC_ignored_parameter_array[iterator],
                        strlen (OIDC_ignored_parameter_array[iterator]),
                        &cache_key);
    if (GNUNET_YES == GNUNET_CONTAINER_multihashmap_contains (handle->rest_handle->url_param_map,
                                                              &cache_key))
    {
      handle->emsg=GNUNET_strdup (OIDC_ERROR_KEY_ACCESS_DENIED);
      GNUNET_asprintf (&handle->edesc, "Server will not handle parameter: %s",
                       OIDC_ignored_parameter_array[iterator]);
      GNUNET_SCHEDULER_add_now (&do_redirect_error, handle);
      return;
    }
  }

  // Checks if response_type is 'code'
  if (0 != strcmp (handle->oidc->response_type, OIDC_EXPECTED_AUTHORIZATION_RESPONSE_TYPE))
  {
    handle->emsg=GNUNET_strdup (OIDC_ERROR_KEY_UNSUPPORTED_RESPONSE_TYPE);
    handle->edesc=GNUNET_strdup ("The authorization server does not support "
                                 "obtaining this authorization code.");
    GNUNET_SCHEDULER_add_now (&do_redirect_error, handle);
    return;
  }

  // Checks if scope contains 'openid'
  expected_scope = GNUNET_strdup (handle->oidc->scope);
  char* test;
  test = strtok (expected_scope, delimiter);
  while (NULL != test)
  {
    if ( 0 == strcmp (OIDC_EXPECTED_AUTHORIZATION_SCOPE, expected_scope) )
      break;
    test = strtok (NULL, delimiter);
  }
  if (NULL == test)
  {
    handle->emsg = GNUNET_strdup (OIDC_ERROR_KEY_INVALID_SCOPE);
    handle->edesc=GNUNET_strdup ("The requested scope is invalid, unknown, or "
                                 "malformed.");
    GNUNET_SCHEDULER_add_now (&do_redirect_error, handle);
    GNUNET_free (expected_scope);
    return;
  }

  GNUNET_free (expected_scope);
  if ( (NULL == handle->oidc->login_identity) &&
       (GNUNET_NO == handle->oidc->user_cancelled))
    GNUNET_SCHEDULER_add_now (&login_redirect, handle);
  else
    GNUNET_SCHEDULER_add_now (&client_redirect, handle);
}

/**
 * Iterate over tlds in config
 */
static void
tld_iter (void *cls,
          const char *section,
          const char *option,
          const char *value)
{
  struct RequestHandle *handle = cls;
  struct GNUNET_CRYPTO_EcdsaPublicKey pkey;

  if (GNUNET_OK !=
      GNUNET_CRYPTO_ecdsa_public_key_from_string (value,
                                                  strlen (value),
                                                  &pkey))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Skipping non key %s\n",
                value);
    return;
  }
  if (0 == memcmp (&pkey, &handle->oidc->client_pkey,
                   sizeof (struct GNUNET_CRYPTO_EcdsaPublicKey)))
    handle->tld = GNUNET_strdup (option+1);
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
  const struct GNUNET_CRYPTO_EcdsaPrivateKey *priv_key;
  struct GNUNET_CRYPTO_EcdsaPublicKey pkey;

  cookie_identity_interpretation (handle);

  //RECOMMENDED value: state - REQUIRED for answers
  GNUNET_CRYPTO_hash (OIDC_STATE_KEY, strlen (OIDC_STATE_KEY), &cache_key);
  if (GNUNET_YES == GNUNET_CONTAINER_multihashmap_contains (handle->rest_handle->url_param_map,
                                                            &cache_key))
  {
    handle->oidc->state = GNUNET_CONTAINER_multihashmap_get (handle->rest_handle->url_param_map,
                                                             &cache_key);
    handle->oidc->state = GNUNET_strdup (handle->oidc->state);
  }

  // REQUIRED value: client_id
  GNUNET_CRYPTO_hash (OIDC_CLIENT_ID_KEY, strlen (OIDC_CLIENT_ID_KEY),
                      &cache_key);
  if (GNUNET_NO == GNUNET_CONTAINER_multihashmap_contains (handle->rest_handle->url_param_map,
                                                           &cache_key))
  {
    handle->emsg = GNUNET_strdup (OIDC_ERROR_KEY_INVALID_REQUEST);
    handle->edesc = GNUNET_strdup ("missing parameter client_id");
    handle->response_code = MHD_HTTP_INTERNAL_SERVER_ERROR;
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }
  handle->oidc->client_id = GNUNET_strdup (GNUNET_CONTAINER_multihashmap_get (handle->rest_handle->url_param_map,
                                                                              &cache_key));

  if ( GNUNET_OK
       != GNUNET_CRYPTO_ecdsa_public_key_from_string (handle->oidc->client_id,
                                                      strlen (handle->oidc->client_id),
                                                      &handle->oidc->client_pkey) )
  {
    handle->emsg = GNUNET_strdup (OIDC_ERROR_KEY_UNAUTHORIZED_CLIENT);
    handle->edesc = GNUNET_strdup ("The client is not authorized to request an "
                                   "authorization code using this method.");
    handle->response_code = MHD_HTTP_INTERNAL_SERVER_ERROR;
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }


  if ( NULL == handle->ego_head )
  {
    handle->emsg = GNUNET_strdup (OIDC_ERROR_KEY_SERVER_ERROR);
    handle->edesc = GNUNET_strdup ("Egos are missing");
    handle->response_code = MHD_HTTP_INTERNAL_SERVER_ERROR;
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }

  handle->ego_entry = handle->ego_head;
  handle->priv_key = *GNUNET_IDENTITY_ego_get_private_key (handle->ego_head->ego);
  //If we know this identity, translated the corresponding TLD
  //TODO: We might want to have a reverse lookup functionality for TLDs?
  for (tmp_ego = handle->ego_head; NULL != tmp_ego; tmp_ego = tmp_ego->next)
  {
    priv_key = GNUNET_IDENTITY_ego_get_private_key (tmp_ego->ego);
    GNUNET_CRYPTO_ecdsa_key_get_public (priv_key,
                                        &pkey);
    if (0 == memcmp (&pkey, &handle->oidc->client_pkey,
                     sizeof (struct GNUNET_CRYPTO_EcdsaPublicKey)))
    {
      handle->tld = GNUNET_strdup (tmp_ego->identifier);
      handle->ego_entry = handle->ego_tail;
    }
  }
  if (NULL == handle->tld)
    GNUNET_CONFIGURATION_iterate_section_values (cfg,
                                                 "gns",
                                                 tld_iter,
                                                 handle);
  if (NULL == handle->tld)
    handle->tld = GNUNET_strdup (handle->oidc->client_id);
  GNUNET_SCHEDULER_add_now (&build_authz_response, handle);
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
  char* header_val;
  json_t *root;
  json_error_t error;
  json_t *identity;
  char term_data[handle->rest_handle->data_size+1];
  term_data[handle->rest_handle->data_size] = '\0';
  GNUNET_memcpy (term_data, handle->rest_handle->data, handle->rest_handle->data_size);
  root = json_loads (term_data, JSON_DECODE_ANY, &error);
  identity = json_object_get (root, "identity");
  if (!json_is_string (identity))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Error parsing json string from %s\n",
                term_data);
    handle->proc (handle->proc_cls, resp, MHD_HTTP_BAD_REQUEST);
    json_decref (root);
    GNUNET_SCHEDULER_add_now (&cleanup_handle_delayed, handle);
    return;
  }
  GNUNET_asprintf (&cookie,
                   "Identity=%s",
                   json_string_value (identity));
  GNUNET_asprintf (&header_val,
                   "%s;Max-Age=%d",
                   cookie,
                   OIDC_COOKIE_EXPIRATION);
  MHD_add_response_header (resp, "Set-Cookie", header_val);
  MHD_add_response_header (resp, "Access-Control-Allow-Methods", "POST");
  GNUNET_CRYPTO_hash (cookie, strlen (cookie), &cache_key);

  if (0 != strcmp (json_string_value (identity),
                   "Denied"))
  {
    current_time = GNUNET_new (struct GNUNET_TIME_Absolute);
    *current_time = GNUNET_TIME_relative_to_absolute (GNUNET_TIME_relative_multiply (GNUNET_TIME_relative_get_second_ (),
                                                                                     OIDC_COOKIE_EXPIRATION));
    last_time = GNUNET_CONTAINER_multihashmap_get (OIDC_cookie_jar_map, &cache_key);
    GNUNET_free_non_null (last_time);
    GNUNET_CONTAINER_multihashmap_put (OIDC_cookie_jar_map,
                                       &cache_key,
                                       current_time,
                                       GNUNET_CONTAINER_MULTIHASHMAPOPTION_REPLACE);
  }
  handle->proc (handle->proc_cls, resp, MHD_HTTP_OK);
  GNUNET_free (cookie);
  GNUNET_free (header_val);
  json_decref (root);
  GNUNET_SCHEDULER_add_now (&cleanup_handle_delayed, handle);
}

static int
check_authorization (struct RequestHandle *handle,
                     struct GNUNET_CRYPTO_EcdsaPublicKey *cid)
{
  struct GNUNET_HashCode cache_key;
  char *authorization;
  char *credentials;
  char *basic_authorization;
  char *client_id;
  char *pass;
  char *expected_pass;
  int client_exists = GNUNET_NO;

  GNUNET_CRYPTO_hash (OIDC_AUTHORIZATION_HEADER_KEY,
                      strlen (OIDC_AUTHORIZATION_HEADER_KEY),
                      &cache_key);
  if ( GNUNET_NO == GNUNET_CONTAINER_multihashmap_contains (handle->rest_handle->header_param_map,
                                                            &cache_key) )
  {
    handle->emsg=GNUNET_strdup (OIDC_ERROR_KEY_INVALID_CLIENT);
    handle->edesc=GNUNET_strdup ("missing authorization");
    handle->response_code = MHD_HTTP_UNAUTHORIZED;
    return GNUNET_SYSERR;
  }
  authorization = GNUNET_CONTAINER_multihashmap_get (handle->rest_handle->header_param_map,
                                                     &cache_key);

  //split header in "Basic" and [content]
  credentials = strtok (authorization, " ");
  if (0 != strcmp ("Basic", credentials))
  {
    handle->emsg=GNUNET_strdup (OIDC_ERROR_KEY_INVALID_CLIENT);
    handle->response_code = MHD_HTTP_UNAUTHORIZED;
    return GNUNET_SYSERR;
  }
  credentials = strtok (NULL, " ");
  if (NULL == credentials)
  {
    handle->emsg=GNUNET_strdup (OIDC_ERROR_KEY_INVALID_CLIENT);
    handle->response_code = MHD_HTTP_UNAUTHORIZED;
    return GNUNET_SYSERR;
  }
  GNUNET_STRINGS_base64_decode (credentials,
                                strlen (credentials),
                                (void**)&basic_authorization);

  if ( NULL == basic_authorization )
  {
    handle->emsg=GNUNET_strdup (OIDC_ERROR_KEY_INVALID_CLIENT);
    handle->response_code = MHD_HTTP_UNAUTHORIZED;
    return GNUNET_SYSERR;
  }
  client_id = strtok (basic_authorization, ":");
  if ( NULL == client_id )
  {
    GNUNET_free_non_null (basic_authorization);
    handle->emsg=GNUNET_strdup (OIDC_ERROR_KEY_INVALID_CLIENT);
    handle->response_code = MHD_HTTP_UNAUTHORIZED;
    return GNUNET_SYSERR;
  }
  pass = strtok (NULL, ":");
  if (NULL == pass)
  {
    GNUNET_free_non_null (basic_authorization);
    handle->emsg=GNUNET_strdup (OIDC_ERROR_KEY_INVALID_CLIENT);
    handle->response_code = MHD_HTTP_UNAUTHORIZED;
    return GNUNET_SYSERR;
  }

  //check client password
  if ( GNUNET_OK
       == GNUNET_CONFIGURATION_get_value_string (cfg,
                                                 "reclaim-rest-plugin",
                                                 "psw",
                                                 &expected_pass) )
  {
    if (0 != strcmp (expected_pass, pass))
    {
      GNUNET_free_non_null (basic_authorization);
      GNUNET_free (expected_pass);
      handle->emsg=GNUNET_strdup (OIDC_ERROR_KEY_INVALID_CLIENT);
      handle->response_code = MHD_HTTP_UNAUTHORIZED;
      return GNUNET_SYSERR;
    }
    GNUNET_free (expected_pass);
  }
  else
  {
    GNUNET_free_non_null (basic_authorization);
    handle->emsg = GNUNET_strdup (OIDC_ERROR_KEY_SERVER_ERROR);
    handle->edesc = GNUNET_strdup ("gnunet configuration failed");
    handle->response_code = MHD_HTTP_INTERNAL_SERVER_ERROR;
    return GNUNET_SYSERR;
  }

  //check client_id
  for (handle->ego_entry = handle->ego_head; NULL != handle->ego_entry; )
  {
    if (0 == strcmp (handle->ego_entry->keystring, client_id))
    {
      client_exists = GNUNET_YES;
      break;
    }
    handle->ego_entry = handle->ego_entry->next;
  }
  if (GNUNET_NO == client_exists)
  {
    GNUNET_free_non_null (basic_authorization);
    handle->emsg=GNUNET_strdup (OIDC_ERROR_KEY_INVALID_CLIENT);
    handle->response_code = MHD_HTTP_UNAUTHORIZED;
    return GNUNET_SYSERR;
  }
  GNUNET_STRINGS_string_to_data (client_id,
                                 strlen (client_id),
                                 cid,
                                 sizeof (struct GNUNET_CRYPTO_EcdsaPublicKey));

  GNUNET_free (basic_authorization);
  return GNUNET_OK;
}

static int
ego_exists (struct RequestHandle *handle,
            struct GNUNET_CRYPTO_EcdsaPublicKey *test_key)
{
  struct EgoEntry *ego_entry;
  struct GNUNET_CRYPTO_EcdsaPublicKey pub_key;

  for (ego_entry = handle->ego_head; NULL != ego_entry; ego_entry = ego_entry->next)
  {
    GNUNET_IDENTITY_ego_get_public_key (ego_entry->ego, &pub_key);
    if (0 == memcmp (&pub_key,
                     test_key,
                     sizeof (struct GNUNET_CRYPTO_EcdsaPublicKey)))
    {
      break;
    }
  }
  if (NULL == ego_entry)
    return GNUNET_NO;
  return GNUNET_YES;
}

static void
store_ticket_reference (const struct RequestHandle *handle,
                        const char* access_token,
                        const struct GNUNET_RECLAIM_Ticket *ticket,
                        const struct GNUNET_CRYPTO_EcdsaPublicKey *cid)
{
  struct GNUNET_HashCode cache_key;
  char *id_ticket_combination;
  char *ticket_string;
  char *client_id;

  GNUNET_CRYPTO_hash (access_token,
                      strlen (access_token),
                      &cache_key);
  client_id = GNUNET_STRINGS_data_to_string_alloc (cid,
                                                   sizeof (struct GNUNET_CRYPTO_EcdsaPublicKey));
  ticket_string = GNUNET_STRINGS_data_to_string_alloc (ticket,
                                                       sizeof (struct GNUNET_RECLAIM_Ticket));
  GNUNET_asprintf (&id_ticket_combination,
                   "%s;%s",
                   client_id,
                   ticket_string);
  GNUNET_CONTAINER_multihashmap_put (OIDC_access_token_map,
                                     &cache_key,
                                     id_ticket_combination,
                                     GNUNET_CONTAINER_MULTIHASHMAPOPTION_REPLACE);

  GNUNET_free (client_id);
  GNUNET_free (ticket_string);
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
  struct RequestHandle *handle = cls;
  struct GNUNET_TIME_Relative expiration_time;
  struct GNUNET_RECLAIM_ATTRIBUTE_ClaimList *cl;
  struct GNUNET_RECLAIM_Ticket *ticket;
  struct GNUNET_CRYPTO_EcdsaPublicKey cid;
  struct GNUNET_HashCode cache_key;
  struct MHD_Response *resp;
  char *grant_type;
  char *code;
  char *json_response;
  char *id_token;
  char *access_token;
  char *jwt_secret;
  char *nonce;
  int i = 1;

  /*
   * Check Authorization
   */
  if (GNUNET_SYSERR == check_authorization (handle,
                                            &cid))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "OIDC authorization for token endpoint failed\n");
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }

  /*
   * Check parameter
   */

  //TODO Do not allow multiple equal parameter names
  //REQUIRED grant_type
  GNUNET_CRYPTO_hash (OIDC_GRANT_TYPE_KEY, strlen (OIDC_GRANT_TYPE_KEY), &cache_key);
  if (GNUNET_NO ==
      GNUNET_CONTAINER_multihashmap_contains (handle->rest_handle->url_param_map,
                                              &cache_key))
  {
    handle->emsg = GNUNET_strdup (OIDC_ERROR_KEY_INVALID_REQUEST);
    handle->edesc = GNUNET_strdup ("missing parameter grant_type");
    handle->response_code = MHD_HTTP_BAD_REQUEST;
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }
  grant_type = GNUNET_CONTAINER_multihashmap_get (handle->rest_handle->url_param_map,
                                                  &cache_key);

  //REQUIRED code
  GNUNET_CRYPTO_hash (OIDC_CODE_KEY, strlen (OIDC_CODE_KEY), &cache_key);
  if (GNUNET_NO ==
      GNUNET_CONTAINER_multihashmap_contains (handle->rest_handle->url_param_map,
                                              &cache_key))
  {
    handle->emsg = GNUNET_strdup (OIDC_ERROR_KEY_INVALID_REQUEST);
    handle->edesc = GNUNET_strdup ("missing parameter code");
    handle->response_code = MHD_HTTP_BAD_REQUEST;
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }
  code = GNUNET_CONTAINER_multihashmap_get (handle->rest_handle->url_param_map,
                                            &cache_key);

  //REQUIRED redirect_uri
  GNUNET_CRYPTO_hash (OIDC_REDIRECT_URI_KEY, strlen (OIDC_REDIRECT_URI_KEY),
                      &cache_key);
  if (GNUNET_NO ==
      GNUNET_CONTAINER_multihashmap_contains (handle->rest_handle->url_param_map,
                                              &cache_key) )
  {
    handle->emsg = GNUNET_strdup (OIDC_ERROR_KEY_INVALID_REQUEST);
    handle->edesc = GNUNET_strdup ("missing parameter redirect_uri");
    handle->response_code = MHD_HTTP_BAD_REQUEST;
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }

  //Check parameter grant_type == "authorization_code"
  if (0 != strcmp (OIDC_GRANT_TYPE_VALUE, grant_type))
  {
    handle->emsg=GNUNET_strdup (OIDC_ERROR_KEY_UNSUPPORTED_GRANT_TYPE);
    handle->response_code = MHD_HTTP_BAD_REQUEST;
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }
  GNUNET_CRYPTO_hash (code, strlen (code), &cache_key);
  if (GNUNET_SYSERR ==
      GNUNET_CONTAINER_multihashmap_put (OIDC_used_ticket_map,
                                         &cache_key,
                                         &i,
                                         GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY) )
  {
    handle->emsg = GNUNET_strdup (OIDC_ERROR_KEY_INVALID_REQUEST);
    handle->edesc = GNUNET_strdup ("Cannot use the same code more than once");
    handle->response_code = MHD_HTTP_BAD_REQUEST;
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }

  //decode code
  if (GNUNET_OK != OIDC_parse_authz_code (&cid,
                                          code,
                                          &ticket,
                                          &nonce))
  {
    handle->emsg = GNUNET_strdup (OIDC_ERROR_KEY_INVALID_REQUEST);
    handle->edesc = GNUNET_strdup ("invalid code");
    handle->response_code = MHD_HTTP_BAD_REQUEST;
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }

  //create jwt
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_time (cfg,
                                           "reclaim-rest-plugin",
                                           "expiration_time",
                                           &expiration_time))
  {
    handle->emsg = GNUNET_strdup (OIDC_ERROR_KEY_SERVER_ERROR);
    handle->edesc = GNUNET_strdup ("gnunet configuration failed");
    handle->response_code = MHD_HTTP_INTERNAL_SERVER_ERROR;
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    GNUNET_free (ticket);
    return;
  }


  //TODO OPTIONAL acr,amr,azp
  if (GNUNET_NO == ego_exists (handle,
                               &ticket->audience))
  {
    handle->emsg = GNUNET_strdup (OIDC_ERROR_KEY_INVALID_REQUEST);
    handle->edesc = GNUNET_strdup ("invalid code...");
    handle->response_code = MHD_HTTP_BAD_REQUEST;
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    GNUNET_free (ticket);
  }
  if ( GNUNET_OK
       != GNUNET_CONFIGURATION_get_value_string (cfg,
                                                 "reclaim-rest-plugin",
                                                 "jwt_secret",
                                                 &jwt_secret) )
  {
    handle->emsg = GNUNET_strdup (OIDC_ERROR_KEY_INVALID_REQUEST);
    handle->edesc = GNUNET_strdup ("No signing secret configured!");
    handle->response_code = MHD_HTTP_INTERNAL_SERVER_ERROR;
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    GNUNET_free (ticket);
    return;
  }
  //TODO We should collect the attributes here. cl always empty
  cl = GNUNET_new (struct GNUNET_RECLAIM_ATTRIBUTE_ClaimList);
  id_token = OIDC_id_token_new (&ticket->audience,
                                &ticket->identity,
                                cl,
                                &expiration_time,
                                (NULL != nonce) ? nonce : NULL,
                                jwt_secret);
  access_token = OIDC_access_token_new ();
  OIDC_build_token_response (access_token,
                             id_token,
                             &expiration_time,
                             &json_response);

  store_ticket_reference (handle,
                          access_token,
                          ticket,
                          &cid);
  resp = GNUNET_REST_create_response (json_response);
  MHD_add_response_header (resp, "Cache-Control", "no-store");
  MHD_add_response_header (resp, "Pragma", "no-cache");
  MHD_add_response_header (resp, "Content-Type", "application/json");
  handle->proc (handle->proc_cls, resp, MHD_HTTP_OK);
  GNUNET_RECLAIM_ATTRIBUTE_list_destroy (cl);
  GNUNET_free (access_token);
  GNUNET_free (json_response);
  GNUNET_free (ticket);
  GNUNET_free (id_token);
  GNUNET_SCHEDULER_add_now (&cleanup_handle_delayed, handle);
}

/**
 * Collects claims and stores them in handle
 */
static void
consume_ticket (void *cls,
                const struct GNUNET_CRYPTO_EcdsaPublicKey *identity,
                const struct GNUNET_RECLAIM_ATTRIBUTE_Claim *attr)
{
  struct RequestHandle *handle = cls;
  char *tmp_value;
  json_t *value;

  if (NULL == identity)
  {
    GNUNET_SCHEDULER_add_now (&return_userinfo_response, handle);
    return;
  }
  tmp_value = GNUNET_RECLAIM_ATTRIBUTE_value_to_string (attr->type,
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
  struct GNUNET_RECLAIM_Ticket *ticket;

  GNUNET_CRYPTO_hash (OIDC_AUTHORIZATION_HEADER_KEY,
                      strlen (OIDC_AUTHORIZATION_HEADER_KEY),
                      &cache_key);
  if ( GNUNET_NO
       == GNUNET_CONTAINER_multihashmap_contains (handle->rest_handle->header_param_map,
                                                  &cache_key) )
  {
    handle->emsg = GNUNET_strdup (OIDC_ERROR_KEY_INVALID_TOKEN);
    handle->edesc = GNUNET_strdup ("No Access Token");
    handle->response_code = MHD_HTTP_UNAUTHORIZED;
    GNUNET_SCHEDULER_add_now (&do_userinfo_error, handle);
    return;
  }
  authorization = GNUNET_CONTAINER_multihashmap_get (
                                                     handle->rest_handle->header_param_map, &cache_key);

  //split header in "Bearer" and access_token
  authorization = GNUNET_strdup (authorization);
  authorization_type = strtok (authorization, delimiter);
  if ( 0 != strcmp ("Bearer", authorization_type) )
  {
    handle->emsg = GNUNET_strdup (OIDC_ERROR_KEY_INVALID_TOKEN);
    handle->edesc = GNUNET_strdup ("No Access Token");
    handle->response_code = MHD_HTTP_UNAUTHORIZED;
    GNUNET_SCHEDULER_add_now (&do_userinfo_error, handle);
    GNUNET_free (authorization);
    return;
  }
  authorization_access_token = strtok (NULL, delimiter);
  if ( NULL == authorization_access_token )
  {
    handle->emsg = GNUNET_strdup (OIDC_ERROR_KEY_INVALID_TOKEN);
    handle->edesc = GNUNET_strdup ("No Access Token");
    handle->response_code = MHD_HTTP_UNAUTHORIZED;
    GNUNET_SCHEDULER_add_now (&do_userinfo_error, handle);
    GNUNET_free (authorization);
    return;
  }

  GNUNET_CRYPTO_hash (authorization_access_token,
                      strlen (authorization_access_token),
                      &cache_key);
  if ( GNUNET_NO == GNUNET_CONTAINER_multihashmap_contains (OIDC_access_token_map,
                                                            &cache_key) )
  {
    handle->emsg = GNUNET_strdup (OIDC_ERROR_KEY_INVALID_TOKEN);
    handle->edesc = GNUNET_strdup ("The Access Token expired");
    handle->response_code = MHD_HTTP_UNAUTHORIZED;
    GNUNET_SCHEDULER_add_now (&do_userinfo_error, handle);
    GNUNET_free (authorization);
    return;
  }

  client_ticket = GNUNET_CONTAINER_multihashmap_get (OIDC_access_token_map,
                                                     &cache_key);
  client_ticket = GNUNET_strdup (client_ticket);
  client = strtok (client_ticket,delimiter_db);
  if (NULL == client)
  {
    handle->emsg = GNUNET_strdup (OIDC_ERROR_KEY_INVALID_TOKEN);
    handle->edesc = GNUNET_strdup ("The Access Token expired");
    handle->response_code = MHD_HTTP_UNAUTHORIZED;
    GNUNET_SCHEDULER_add_now (&do_userinfo_error, handle);
    GNUNET_free (authorization);
    GNUNET_free (client_ticket);
    return;
  }
  handle->ego_entry = handle->ego_head;
  for (; NULL != handle->ego_entry; handle->ego_entry = handle->ego_entry->next)
  {
    if (0 == strcmp (handle->ego_entry->keystring,client))
      break;
  }
  if (NULL == handle->ego_entry)
  {
    handle->emsg = GNUNET_strdup (OIDC_ERROR_KEY_INVALID_TOKEN);
    handle->edesc = GNUNET_strdup ("The Access Token expired");
    handle->response_code = MHD_HTTP_UNAUTHORIZED;
    GNUNET_SCHEDULER_add_now (&do_userinfo_error, handle);
    GNUNET_free (authorization);
    GNUNET_free (client_ticket);
    return;
  }
  ticket_str = strtok (NULL, delimiter_db);
  if (NULL == ticket_str)
  {
    handle->emsg = GNUNET_strdup (OIDC_ERROR_KEY_INVALID_TOKEN);
    handle->edesc = GNUNET_strdup ("The Access Token expired");
    handle->response_code = MHD_HTTP_UNAUTHORIZED;
    GNUNET_SCHEDULER_add_now (&do_userinfo_error, handle);
    GNUNET_free (authorization);
    GNUNET_free (client_ticket);
    return;
  }
  ticket = GNUNET_new (struct GNUNET_RECLAIM_Ticket);
  if ( GNUNET_OK
       != GNUNET_STRINGS_string_to_data (ticket_str,
                                         strlen (ticket_str),
                                         ticket,
                                         sizeof (struct GNUNET_RECLAIM_Ticket)))
  {
    handle->emsg = GNUNET_strdup (OIDC_ERROR_KEY_INVALID_TOKEN);
    handle->edesc = GNUNET_strdup ("The Access Token expired");
    handle->response_code = MHD_HTTP_UNAUTHORIZED;
    GNUNET_SCHEDULER_add_now (&do_userinfo_error, handle);
    GNUNET_free (ticket);
    GNUNET_free (authorization);
    GNUNET_free (client_ticket);
    return;
  }

  handle->idp = GNUNET_RECLAIM_connect (cfg);
  handle->oidc->response = json_object ();
  json_object_set_new (handle->oidc->response,
                       "sub",
                       json_string (handle->ego_entry->keystring));
  handle->idp_op = GNUNET_RECLAIM_ticket_consume (handle->idp,
                                                  GNUNET_IDENTITY_ego_get_private_key (handle->ego_entry->ego),
                                                  ticket,
                                                  consume_ticket,
                                                  handle);
  GNUNET_free (ticket);
  GNUNET_free (authorization);
  GNUNET_free (client_ticket);

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
    GNUNET_CONTAINER_DLL_insert_tail (handle->ego_head,
                                      handle->ego_tail,
                                      ego_entry);
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
      GNUNET_CONTAINER_DLL_insert_tail (handle->ego_head,
                                        handle->ego_tail,
                                        ego_entry);
    }
  } else {
    /* Delete */
    for (ego_entry = handle->ego_head; NULL != ego_entry; ego_entry = ego_entry->next) {
      if (ego_entry->ego == ego)
        break;
    }
    if (NULL != ego_entry)
      GNUNET_CONTAINER_DLL_remove (handle->ego_head,handle->ego_tail, ego_entry);
  }

}

static void
rest_identity_process_request (struct GNUNET_REST_RequestHandle *rest_handle,
                               GNUNET_REST_ResultProcessor proc,
                               void *proc_cls)
{
  struct RequestHandle *handle = GNUNET_new (struct RequestHandle);
  handle->oidc = GNUNET_new (struct OIDC_Variables);
  if (NULL == OIDC_cookie_jar_map)
    OIDC_cookie_jar_map = GNUNET_CONTAINER_multihashmap_create (10, GNUNET_NO);
  if (NULL == OIDC_identity_grants)
    OIDC_identity_grants = GNUNET_CONTAINER_multihashmap_create (10, GNUNET_NO);
  if (NULL == OIDC_used_ticket_map)
    OIDC_used_ticket_map = GNUNET_CONTAINER_multihashmap_create (10, GNUNET_NO);
  if (NULL == OIDC_access_token_map)
    OIDC_access_token_map = GNUNET_CONTAINER_multihashmap_create (10, GNUNET_NO);
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
  handle->gns_handle = GNUNET_GNS_connect (cfg);
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
  hashmap_it = GNUNET_CONTAINER_multihashmap_iterator_create (OIDC_cookie_jar_map);
  while (GNUNET_YES ==
         GNUNET_CONTAINER_multihashmap_iterator_next (hashmap_it, NULL, value))
    GNUNET_free_non_null (value);
  GNUNET_CONTAINER_multihashmap_destroy (OIDC_cookie_jar_map);

  hashmap_it = GNUNET_CONTAINER_multihashmap_iterator_create (OIDC_identity_grants);
  while (GNUNET_YES ==
         GNUNET_CONTAINER_multihashmap_iterator_next (hashmap_it, NULL, value))
    GNUNET_free_non_null (value);
  GNUNET_CONTAINER_multihashmap_destroy (OIDC_identity_grants);

  hashmap_it = GNUNET_CONTAINER_multihashmap_iterator_create (OIDC_used_ticket_map);
  while (GNUNET_YES ==
         GNUNET_CONTAINER_multihashmap_iterator_next (hashmap_it, NULL, value))
    GNUNET_free_non_null (value);
  GNUNET_CONTAINER_multihashmap_destroy (OIDC_used_ticket_map);

  hashmap_it = GNUNET_CONTAINER_multihashmap_iterator_create (OIDC_access_token_map);
  while (GNUNET_YES ==
         GNUNET_CONTAINER_multihashmap_iterator_next (hashmap_it, NULL, value))
    GNUNET_free_non_null (value);
  GNUNET_CONTAINER_multihashmap_destroy (OIDC_access_token_map);
  GNUNET_CONTAINER_multihashmap_iterator_destroy (hashmap_it);
  GNUNET_free_non_null (allow_methods);
  GNUNET_free (api);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Identity Provider REST plugin is finished\n");
  return NULL;
}

/* end of plugin_rest_identity_provider.c */

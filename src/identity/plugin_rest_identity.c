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
 * @file identity/plugin_rest_identity.c
 * @brief GNUnet Identity REST plugin
 */

#include "platform.h"
#include "gnunet_rest_plugin.h"
#include "gnunet_identity_service.h"
#include "gnunet_rest_lib.h"
#include "microhttpd.h"
#include <jansson.h>

/**
 * Identity Namespace
 */
#define GNUNET_REST_API_NS_IDENTITY "/identity"

/**
 * Identity Namespace with public key specifier
 */
#define GNUNET_REST_API_NS_IDENTITY_PUBKEY "/identity/pubkey"

/**
 * Identity Namespace with public key specifier
 */
#define GNUNET_REST_API_NS_IDENTITY_NAME "/identity/name"

/**
 * Identity Subsystem Namespace
 */
#define GNUNET_REST_API_NS_IDENTITY_SUBSYSTEM "/identity/subsystem"

/**
 * Parameter public key
 */
#define GNUNET_REST_IDENTITY_PARAM_PUBKEY "pubkey"

/**
 * Parameter private key
 */
#define GNUNET_REST_IDENTITY_PARAM_PRIVKEY "privkey"

/**
 * Parameter subsystem
 */
#define GNUNET_REST_IDENTITY_PARAM_SUBSYSTEM "subsystem"

/**
 * Parameter name
 */
#define GNUNET_REST_IDENTITY_PARAM_NAME "name"

/**
 * Parameter new name
 */
#define GNUNET_REST_IDENTITY_PARAM_NEWNAME "newname"

/**
 * Error message Unknown Error
 */
#define GNUNET_REST_IDENTITY_ERROR_UNKNOWN "Unknown Error"

/**
 * Error message No identity found
 */
#define GNUNET_REST_IDENTITY_NOT_FOUND "No identity found"

/**
 * Error message Missing identity name
 */
#define GNUNET_REST_IDENTITY_MISSING_NAME "Missing identity name"

/**
 * Error message Missing identity name
 */
#define GNUNET_REST_IDENTITY_MISSING_PUBKEY "Missing identity public key"

/**
 * Error message No data
 */
#define GNUNET_REST_ERROR_NO_DATA "No data"

/**
 * Error message Data invalid
 */
#define GNUNET_REST_ERROR_DATA_INVALID "Data invalid"

/**
 * State while collecting all egos
 */
#define ID_REST_STATE_INIT 0

/**
 * Done collecting egos
 */
#define ID_REST_STATE_POST_INIT 1

/**
 * The configuration handle
 */
const struct GNUNET_CONFIGURATION_Handle *cfg;

/**
 * HTTP methods allows for this plugin
 */
static char *allow_methods;

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

/**
 * The request handle
 */
struct RequestHandle
{
  /**
   * The data from the REST request
   */
  const char *data;

  /**
   * The name to look up
   */
  char *name;

  /**
   * the length of the REST data
   */
  size_t data_size;


  /**
   * Ego list
   */
  struct EgoEntry *ego_head;

  /**
   * Ego list
   */
  struct EgoEntry *ego_tail;

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
   * Response code
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
  struct EgoEntry *ego_entry;
  struct EgoEntry *ego_tmp;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Cleaning up\n");
  if (NULL != handle->timeout_task)
  {
    GNUNET_SCHEDULER_cancel (handle->timeout_task);
    handle->timeout_task = NULL;
  }

  if (NULL != handle->url)
    GNUNET_free (handle->url);
  if (NULL != handle->emsg)
    GNUNET_free (handle->emsg);
  if (NULL != handle->name)
    GNUNET_free (handle->name);
  if (NULL != handle->identity_handle)
    GNUNET_IDENTITY_disconnect (handle->identity_handle);

  for (ego_entry = handle->ego_head; NULL != ego_entry;)
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
 * Task run on errors.  Reports an error and cleans up everything.
 *
 * @param cls the `struct RequestHandle`
 */
static void
do_error (void *cls)
{
  struct RequestHandle *handle = cls;
  struct MHD_Response *resp;
  json_t *json_error = json_object ();
  char *response;

  if (NULL == handle->emsg)
    handle->emsg = GNUNET_strdup (GNUNET_REST_IDENTITY_ERROR_UNKNOWN);

  json_object_set_new (json_error, "error", json_string (handle->emsg));

  if (0 == handle->response_code)
    handle->response_code = MHD_HTTP_OK;
  response = json_dumps (json_error, 0);
  resp = GNUNET_REST_create_response (response);
  MHD_add_response_header (resp, "Content-Type", "application/json");
  handle->proc (handle->proc_cls, resp, handle->response_code);
  json_decref (json_error);
  GNUNET_free (response);
  GNUNET_SCHEDULER_add_now (&cleanup_handle, handle);
}


/**
 * Get EgoEntry from list with either a public key or a name
 * If public key and name are not NULL, it returns the public key result first
 *
 * @param handle the RequestHandle
 * @param pubkey the public key of an identity (only one can be NULL)
 * @param name the name of an identity (only one can be NULL)
 * @return EgoEntry or NULL if not found
 */
struct EgoEntry *
get_egoentry (struct RequestHandle *handle, char *pubkey, char *name)
{
  struct EgoEntry *ego_entry;

  if (NULL != pubkey)
  {
    for (ego_entry = handle->ego_head; NULL != ego_entry;
         ego_entry = ego_entry->next)
    {
      if (0 != strcasecmp (pubkey, ego_entry->keystring))
        continue;
      return ego_entry;
    }
  }
  if (NULL != name)
  {
    for (ego_entry = handle->ego_head; NULL != ego_entry;
         ego_entry = ego_entry->next)
    {
      if (0 != strcasecmp (name, ego_entry->identifier))
        continue;
      return ego_entry;
    }
  }
  return NULL;
}


/**
 * Callback for GET Request with subsystem
 *
 * @param cls the RequestHandle
 * @param ego the Ego found
 * @param ctx the context
 * @param name the id of the ego
 */
static void
ego_get_for_subsystem (void *cls,
                       struct GNUNET_IDENTITY_Ego *ego,
                       void **ctx,
                       const char *name)
{
  struct RequestHandle *handle = cls;
  struct MHD_Response *resp;
  struct GNUNET_CRYPTO_EcdsaPublicKey public_key;
  json_t *json_root;
  char *result_str;
  char *public_key_string;

  if (NULL == ego)
  {
    handle->response_code = MHD_HTTP_NOT_FOUND;
    handle->emsg = GNUNET_strdup (GNUNET_REST_IDENTITY_NOT_FOUND);
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }

  GNUNET_IDENTITY_ego_get_public_key (ego, &public_key);
  public_key_string = GNUNET_CRYPTO_ecdsa_public_key_to_string (&public_key);

  // create json with subsystem identity
  json_root = json_object ();
  json_object_set_new (json_root,
                       GNUNET_REST_IDENTITY_PARAM_PUBKEY,
                       json_string (public_key_string));
  json_object_set_new (json_root,
                       GNUNET_REST_IDENTITY_PARAM_NAME,
                       json_string (name));

  result_str = json_dumps (json_root, 0);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Result %s\n", result_str);
  resp = GNUNET_REST_create_response (result_str);
  MHD_add_response_header (resp, "Content-Type", "application/json");
  json_decref (json_root);
  handle->proc (handle->proc_cls, resp, MHD_HTTP_OK);
  GNUNET_free (result_str);
  GNUNET_free (public_key_string);
  GNUNET_SCHEDULER_add_now (&cleanup_handle, handle);
}


/**
 * Handle identity GET request for subsystem
 *
 * @param con_handle the connection handle
 * @param url the url
 * @param cls the RequestHandle
 */
void
ego_get_subsystem (struct GNUNET_REST_RequestHandle *con_handle,
                   const char *url,
                   void *cls)
{
  struct RequestHandle *handle = cls;
  char *subsystem;

  if (strlen (GNUNET_REST_API_NS_IDENTITY_SUBSYSTEM) >= strlen (handle->url))
  {
    handle->emsg = GNUNET_strdup ("Missing subsystem name");
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }
  subsystem = &handle->url[strlen (GNUNET_REST_API_NS_IDENTITY_SUBSYSTEM) + 1];
  // requested default identity of subsystem
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Looking for %s's ego\n", subsystem);

  handle->op = GNUNET_IDENTITY_get (handle->identity_handle,
                                    subsystem,
                                    &ego_get_for_subsystem,
                                    handle);

  if (NULL == handle->op)
  {
    handle->response_code = MHD_HTTP_NOT_FOUND;
    handle->emsg = GNUNET_strdup (GNUNET_REST_IDENTITY_NOT_FOUND);
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }
}


/**
 * Handle identity GET request - responds with all identities
 *
 * @param con_handle the connection handle
 * @param url the url
 * @param cls the RequestHandle
 */
void
ego_get_all (struct GNUNET_REST_RequestHandle *con_handle,
             const char *url,
             void *cls)
{
  struct RequestHandle *handle = cls;
  struct EgoEntry *ego_entry;
  struct MHD_Response *resp;
  struct GNUNET_HashCode key;
  json_t *json_root;
  json_t *json_ego;
  char *result_str;
  char *privkey_str;

  json_root = json_array ();
  // Return ego/egos
  for (ego_entry = handle->ego_head; NULL != ego_entry;
       ego_entry = ego_entry->next)
  {
    json_ego = json_object ();
    json_object_set_new (json_ego,
                         GNUNET_REST_IDENTITY_PARAM_PUBKEY,
                         json_string (ego_entry->keystring));
    GNUNET_CRYPTO_hash ("private", strlen ("private"), &key);
    if (GNUNET_YES ==
        GNUNET_CONTAINER_multihashmap_contains (
          handle->rest_handle->url_param_map, &key))
    {
      privkey_str = GNUNET_CRYPTO_ecdsa_private_key_to_string (
        GNUNET_IDENTITY_ego_get_private_key (ego_entry->ego));
      json_object_set_new (json_ego,
                           GNUNET_REST_IDENTITY_PARAM_PRIVKEY,
                           json_string (privkey_str));
      GNUNET_free (privkey_str);
    }

    json_object_set_new (json_ego,
                         GNUNET_REST_IDENTITY_PARAM_NAME,
                         json_string (ego_entry->identifier));
    json_array_append (json_root, json_ego);
    json_decref (json_ego);
  }

  result_str = json_dumps (json_root, 0);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Result %s\n", result_str);
  resp = GNUNET_REST_create_response (result_str);
  MHD_add_response_header (resp, "Content-Type", "application/json");
  json_decref (json_root);
  handle->proc (handle->proc_cls, resp, MHD_HTTP_OK);
  GNUNET_free (result_str);
  GNUNET_SCHEDULER_add_now (&cleanup_handle, handle);
}


/**
 * Responds with the ego_entry identity
 *
 * @param handle the struct RequestHandle
 * @param ego_entry the struct EgoEntry for the response
 */
void
ego_get_response (struct RequestHandle *handle, struct EgoEntry *ego_entry)
{
  struct MHD_Response *resp;
  struct GNUNET_HashCode key;
  json_t *json_ego;
  char *result_str;
  char *privkey_str;

  json_ego = json_object ();
  json_object_set_new (json_ego,
                       GNUNET_REST_IDENTITY_PARAM_PUBKEY,
                       json_string (ego_entry->keystring));
  json_object_set_new (json_ego,
                       GNUNET_REST_IDENTITY_PARAM_NAME,
                       json_string (ego_entry->identifier));
  GNUNET_CRYPTO_hash ("private", strlen ("private"), &key);
  if (GNUNET_YES ==
      GNUNET_CONTAINER_multihashmap_contains (
        handle->rest_handle->url_param_map, &key))
  {
    privkey_str = GNUNET_CRYPTO_ecdsa_private_key_to_string (
      GNUNET_IDENTITY_ego_get_private_key (ego_entry->ego));
    json_object_set_new (json_ego,
                         GNUNET_REST_IDENTITY_PARAM_PRIVKEY,
                         json_string (privkey_str));
    GNUNET_free (privkey_str);
  }

  result_str = json_dumps (json_ego, 0);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Result %s\n", result_str);
  resp = GNUNET_REST_create_response (result_str);
  handle->proc (handle->proc_cls, resp, MHD_HTTP_OK);
  MHD_add_response_header (resp, "Content-Type", "application/json");
  json_decref (json_ego);
  GNUNET_free (result_str);
  GNUNET_SCHEDULER_add_now (&cleanup_handle, handle);
}


/**
 * Handle identity GET request with a public key
 *
 * @param con_handle the connection handle
 * @param url the url
 * @param cls the RequestHandle
 */
void
ego_get_pubkey (struct GNUNET_REST_RequestHandle *con_handle,
                const char *url,
                void *cls)
{
  struct RequestHandle *handle = cls;
  struct EgoEntry *ego_entry;
  char *keystring;

  keystring = NULL;

  if (strlen (GNUNET_REST_API_NS_IDENTITY_PUBKEY) >= strlen (handle->url))
  {
    handle->response_code = MHD_HTTP_NOT_FOUND;
    handle->emsg = GNUNET_strdup (GNUNET_REST_IDENTITY_MISSING_PUBKEY);
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }
  keystring = &handle->url[strlen (GNUNET_REST_API_NS_IDENTITY_PUBKEY) + 1];
  ego_entry = get_egoentry (handle, keystring, NULL);

  if (NULL == ego_entry)
  {
    handle->response_code = MHD_HTTP_NOT_FOUND;
    handle->emsg = GNUNET_strdup (GNUNET_REST_IDENTITY_NOT_FOUND);
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }

  ego_get_response (handle, ego_entry);
}


/**
 * Handle identity GET request with a name
 *
 * @param con_handle the connection handle
 * @param url the url
 * @param cls the RequestHandle
 */
void
ego_get_name (struct GNUNET_REST_RequestHandle *con_handle,
              const char *url,
              void *cls)
{
  struct RequestHandle *handle = cls;
  struct EgoEntry *ego_entry;
  char *egoname;

  egoname = NULL;

  if (strlen (GNUNET_REST_API_NS_IDENTITY_NAME) >= strlen (handle->url))
  {
    handle->response_code = MHD_HTTP_NOT_FOUND;
    handle->emsg = GNUNET_strdup (GNUNET_REST_IDENTITY_MISSING_NAME);
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }
  egoname = &handle->url[strlen (GNUNET_REST_API_NS_IDENTITY_NAME) + 1];
  ego_entry = get_egoentry (handle, NULL, egoname);

  if (NULL == ego_entry)
  {
    handle->response_code = MHD_HTTP_NOT_FOUND;
    handle->emsg = GNUNET_strdup (GNUNET_REST_IDENTITY_NOT_FOUND);
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }

  ego_get_response (handle, ego_entry);
}


/**
 * Processing finished
 *
 * @param cls request handle
 * @param emsg error message
 */
static void
do_finished (void *cls, const char *emsg)
{
  struct RequestHandle *handle = cls;
  struct MHD_Response *resp;

  handle->op = NULL;
  if (NULL != emsg)
  {
    handle->emsg = GNUNET_strdup (emsg);
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }
  if (0 == handle->response_code)
  {
    handle->response_code = MHD_HTTP_NO_CONTENT;
  }
  resp = GNUNET_REST_create_response (NULL);
  handle->proc (handle->proc_cls, resp, handle->response_code);
  GNUNET_SCHEDULER_add_now (&cleanup_handle, handle);
}


/**
 * Processing finished, when creating an ego.
 *
 * @param cls request handle
 * @param private key of the ego, or NULL on error
 * @param emsg error message
 */
static void
do_finished_create (void *cls,
                    const struct GNUNET_CRYPTO_EcdsaPrivateKey *pk,
                    const char *emsg)
{
  struct RequestHandle *handle = cls;

  (void) pk;
  do_finished (handle, emsg);
}


/**
 * Processing edit ego with EgoEntry ego_entry
 *
 * @param handle the struct RequestHandle
 * @param ego_entry the struct EgoEntry we want to edit
 */
void
ego_edit (struct RequestHandle *handle, struct EgoEntry *ego_entry)
{
  struct EgoEntry *ego_entry_tmp;
  struct MHD_Response *resp;
  json_t *data_js;
  json_error_t err;
  char *newname;
  char term_data[handle->data_size + 1];
  int json_state;

  // if no data
  if (0 >= handle->data_size)
  {
    handle->emsg = GNUNET_strdup (GNUNET_REST_ERROR_NO_DATA);
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }
  // if not json
  term_data[handle->data_size] = '\0';
  GNUNET_memcpy (term_data, handle->data, handle->data_size);
  data_js = json_loads (term_data, JSON_DECODE_ANY, &err);

  if (NULL == data_js)
  {
    handle->emsg = GNUNET_strdup (GNUNET_REST_ERROR_NO_DATA);
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }

  newname = NULL;
  // NEW NAME
  json_state = 0;
  json_state = json_unpack (data_js,
                            "{s:s!}",
                            GNUNET_REST_IDENTITY_PARAM_NEWNAME,
                            &newname);
  // Change name with pubkey or name identifier
  if (0 != json_state)
  {
    handle->emsg = GNUNET_strdup (GNUNET_REST_ERROR_DATA_INVALID);
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    json_decref (data_js);
    return;
  }

  if (NULL == newname)
  {
    handle->emsg = GNUNET_strdup (GNUNET_REST_ERROR_DATA_INVALID);
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    json_decref (data_js);
    return;
  }

  if (0 >= strlen (newname))
  {
    handle->emsg = GNUNET_strdup (GNUNET_REST_ERROR_DATA_INVALID);
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    json_decref (data_js);
    return;
  }

  ego_entry_tmp = get_egoentry (handle, NULL, newname);
  if (NULL != ego_entry_tmp)
  {
    // Ego with same name not allowed (even if its the ego we change)
    resp = GNUNET_REST_create_response (NULL);
    handle->proc (handle->proc_cls, resp, MHD_HTTP_CONFLICT);
    GNUNET_SCHEDULER_add_now (&cleanup_handle, handle);
    json_decref (data_js);
    return;
  }
  handle->op = GNUNET_IDENTITY_rename (handle->identity_handle,
                                       ego_entry->identifier,
                                       newname,
                                       &do_finished,
                                       handle);
  if (NULL == handle->op)
  {
    handle->emsg = GNUNET_strdup ("Rename failed");
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    json_decref (data_js);
    return;
  }
  json_decref (data_js);
  return;
}


/**
 * Handle identity PUT request with public key
 *
 * @param con_handle the connection handle
 * @param url the url
 * @param cls the RequestHandle
 */
void
ego_edit_pubkey (struct GNUNET_REST_RequestHandle *con_handle,
                 const char *url,
                 void *cls)
{
  struct RequestHandle *handle = cls;
  struct EgoEntry *ego_entry;
  char *keystring;

  keystring = NULL;

  if (strlen (GNUNET_REST_API_NS_IDENTITY_PUBKEY) >= strlen (handle->url))
  {
    handle->response_code = MHD_HTTP_NOT_FOUND;
    handle->emsg = GNUNET_strdup (GNUNET_REST_IDENTITY_MISSING_PUBKEY);
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }
  keystring = &handle->url[strlen (GNUNET_REST_API_NS_IDENTITY_PUBKEY) + 1];
  ego_entry = get_egoentry (handle, keystring, NULL);

  if (NULL == ego_entry)
  {
    handle->response_code = MHD_HTTP_NOT_FOUND;
    handle->emsg = GNUNET_strdup (GNUNET_REST_IDENTITY_NOT_FOUND);
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }

  ego_edit (handle, ego_entry);
}


/**
 * Handle identity PUT request with name
 *
 * @param con_handle the connection handle
 * @param url the url
 * @param cls the RequestHandle
 */
void
ego_edit_name (struct GNUNET_REST_RequestHandle *con_handle,
               const char *url,
               void *cls)
{
  struct RequestHandle *handle = cls;
  struct EgoEntry *ego_entry;
  char *name;

  name = NULL;

  if (strlen (GNUNET_REST_API_NS_IDENTITY_NAME) >= strlen (handle->url))
  {
    handle->response_code = MHD_HTTP_NOT_FOUND;
    handle->emsg = GNUNET_strdup (GNUNET_REST_IDENTITY_MISSING_NAME);
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }
  name = &handle->url[strlen (GNUNET_REST_API_NS_IDENTITY_NAME) + 1];
  ego_entry = get_egoentry (handle, NULL, name);

  if (NULL == ego_entry)
  {
    handle->response_code = MHD_HTTP_NOT_FOUND;
    handle->emsg = GNUNET_strdup (GNUNET_REST_IDENTITY_NOT_FOUND);
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }

  ego_edit (handle, ego_entry);
}


/**
 * Handle identity subsystem PUT request with name
 *
 * @param con_handle the connection handle
 * @param url the url
 * @param cls the RequestHandle
 */
void
ego_edit_subsystem (struct GNUNET_REST_RequestHandle *con_handle,
                    const char *url,
                    void *cls)
{
  struct RequestHandle *handle = cls;
  struct EgoEntry *ego_entry;
  json_t *data_js;
  json_error_t err;
  char *newsubsys;
  char *name;
  char term_data[handle->data_size + 1];
  int json_state;

  name = NULL;

  if (strlen (GNUNET_REST_API_NS_IDENTITY_SUBSYSTEM) >= strlen (handle->url))
  {
    handle->response_code = MHD_HTTP_NOT_FOUND;
    handle->emsg = GNUNET_strdup (GNUNET_REST_IDENTITY_MISSING_NAME);
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }
  name = &handle->url[strlen (GNUNET_REST_API_NS_IDENTITY_SUBSYSTEM) + 1];
  ego_entry = get_egoentry (handle, NULL, name);

  if (NULL == ego_entry)
  {
    handle->response_code = MHD_HTTP_NOT_FOUND;
    handle->emsg = GNUNET_strdup (GNUNET_REST_IDENTITY_NOT_FOUND);
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }

  // if no data
  if (0 >= handle->data_size)
  {
    handle->emsg = GNUNET_strdup (GNUNET_REST_ERROR_NO_DATA);
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }
  // if not json
  term_data[handle->data_size] = '\0';
  GNUNET_memcpy (term_data, handle->data, handle->data_size);
  data_js = json_loads (term_data, JSON_DECODE_ANY, &err);

  if (NULL == data_js)
  {
    handle->emsg = GNUNET_strdup (GNUNET_REST_ERROR_NO_DATA);
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }

  newsubsys = NULL;
  // SUBSYSTEM
  json_state = 0;
  json_state = json_unpack (data_js,
                            "{s:s!}",
                            GNUNET_REST_IDENTITY_PARAM_SUBSYSTEM,
                            &newsubsys);
  // Change subsystem with pubkey or name identifier
  if (0 != json_state)
  {
    handle->emsg = GNUNET_strdup (GNUNET_REST_ERROR_DATA_INVALID);
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    json_decref (data_js);
    return;
  }

  if (NULL == newsubsys)
  {
    handle->emsg = GNUNET_strdup (GNUNET_REST_ERROR_DATA_INVALID);
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    json_decref (data_js);
    return;
  }

  if (0 >= strlen (newsubsys))
  {
    handle->emsg = GNUNET_strdup (GNUNET_REST_ERROR_DATA_INVALID);
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    json_decref (data_js);
    return;
  }

  handle->response_code = MHD_HTTP_NO_CONTENT;
  handle->op = GNUNET_IDENTITY_set (handle->identity_handle,
                                    newsubsys,
                                    ego_entry->ego,
                                    &do_finished,
                                    handle);
  if (NULL == handle->op)
  {
    handle->emsg = GNUNET_strdup ("Setting subsystem failed");
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }
  json_decref (data_js);
  return;
}


/**
 * Handle identity POST request
 *
 * @param con_handle the connection handle
 * @param url the url
 * @param cls the RequestHandle
 */
void
ego_create (struct GNUNET_REST_RequestHandle *con_handle,
            const char *url,
            void *cls)
{
  struct RequestHandle *handle = cls;
  struct EgoEntry *ego_entry;
  struct MHD_Response *resp;
  json_t *data_js;
  json_error_t err;
  char *egoname;
  char *privkey;
  struct GNUNET_CRYPTO_EcdsaPrivateKey pk;
  struct GNUNET_CRYPTO_EcdsaPrivateKey *pk_ptr;
  int json_unpack_state;
  char term_data[handle->data_size + 1];

  if (strlen (GNUNET_REST_API_NS_IDENTITY) != strlen (handle->url))
  {
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }

  if (0 >= handle->data_size)
  {
    handle->emsg = GNUNET_strdup (GNUNET_REST_ERROR_NO_DATA);
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }
  term_data[handle->data_size] = '\0';
  GNUNET_memcpy (term_data, handle->data, handle->data_size);
  data_js = json_loads (term_data, JSON_DECODE_ANY, &err);
  if (NULL == data_js)
  {
    handle->emsg = GNUNET_strdup (GNUNET_REST_ERROR_NO_DATA);
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    json_decref (data_js);
    return;
  }
  json_unpack_state = 0;
  privkey = NULL;
  json_unpack_state =
    json_unpack (data_js, "{s:s, s?:s!}",
                 GNUNET_REST_IDENTITY_PARAM_NAME, &egoname,
                 GNUNET_REST_IDENTITY_PARAM_PRIVKEY, &privkey);
  if (0 != json_unpack_state)
  {
    handle->emsg = GNUNET_strdup (GNUNET_REST_ERROR_DATA_INVALID);
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    json_decref (data_js);
    return;
  }

  if (NULL == egoname)
  {
    handle->emsg = GNUNET_strdup (GNUNET_REST_ERROR_DATA_INVALID);
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    json_decref (data_js);
    return;
  }
  if (0 >= strlen (egoname))
  {
    json_decref (data_js);
    handle->emsg = GNUNET_strdup (GNUNET_REST_ERROR_DATA_INVALID);
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }
  GNUNET_STRINGS_utf8_tolower (egoname, egoname);
  for (ego_entry = handle->ego_head; NULL != ego_entry;
       ego_entry = ego_entry->next)
  {
    if (0 == strcasecmp (egoname, ego_entry->identifier))
    {
      resp = GNUNET_REST_create_response (NULL);
      handle->proc (handle->proc_cls, resp, MHD_HTTP_CONFLICT);
      GNUNET_SCHEDULER_add_now (&cleanup_handle, handle);
      json_decref (data_js);
      return;
    }
  }
  handle->name = GNUNET_strdup (egoname);
  if (NULL != privkey)
  {
    GNUNET_STRINGS_string_to_data (privkey,
                                   strlen (privkey),
                                   &pk,
                                   sizeof(struct GNUNET_CRYPTO_EcdsaPrivateKey));
    pk_ptr = &pk;
  }
  else
    pk_ptr = NULL;
  json_decref (data_js);
  handle->response_code = MHD_HTTP_CREATED;
  handle->op = GNUNET_IDENTITY_create (handle->identity_handle,
                                       handle->name,
                                       pk_ptr,
                                       &do_finished_create,
                                       handle);
}


/**
 * Handle identity DELETE request with public key
 *
 * @param con_handle the connection handle
 * @param url the url
 * @param cls the RequestHandle
 */
void
ego_delete_pubkey (struct GNUNET_REST_RequestHandle *con_handle,
                   const char *url,
                   void *cls)
{
  struct RequestHandle *handle = cls;
  struct EgoEntry *ego_entry;
  char *keystring;

  keystring = NULL;

  if (strlen (GNUNET_REST_API_NS_IDENTITY_PUBKEY) >= strlen (handle->url))
  {
    handle->response_code = MHD_HTTP_NOT_FOUND;
    handle->emsg = GNUNET_strdup (GNUNET_REST_IDENTITY_MISSING_PUBKEY);
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }
  keystring = &handle->url[strlen (GNUNET_REST_API_NS_IDENTITY_PUBKEY) + 1];
  ego_entry = get_egoentry (handle, keystring, NULL);

  if (NULL == ego_entry)
  {
    handle->response_code = MHD_HTTP_NOT_FOUND;
    handle->emsg = GNUNET_strdup (GNUNET_REST_IDENTITY_NOT_FOUND);
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }

  handle->response_code = MHD_HTTP_NO_CONTENT;
  handle->op = GNUNET_IDENTITY_delete (handle->identity_handle,
                                       ego_entry->identifier,
                                       &do_finished,
                                       handle);
}


/**
 * Handle identity DELETE request with name
 *
 * @param con_handle the connection handle
 * @param url the url
 * @param cls the RequestHandle
 */
void
ego_delete_name (struct GNUNET_REST_RequestHandle *con_handle,
                 const char *url,
                 void *cls)
{
  struct RequestHandle *handle = cls;
  struct EgoEntry *ego_entry;
  char *name;

  name = NULL;

  if (strlen (GNUNET_REST_API_NS_IDENTITY_NAME) >= strlen (handle->url))
  {
    handle->response_code = MHD_HTTP_NOT_FOUND;
    handle->emsg = GNUNET_strdup (GNUNET_REST_IDENTITY_MISSING_NAME);
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }
  name = &handle->url[strlen (GNUNET_REST_API_NS_IDENTITY_NAME) + 1];
  ego_entry = get_egoentry (handle, NULL, name);

  if (NULL == ego_entry)
  {
    handle->response_code = MHD_HTTP_NOT_FOUND;
    handle->emsg = GNUNET_strdup (GNUNET_REST_IDENTITY_NOT_FOUND);
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }

  handle->response_code = MHD_HTTP_NO_CONTENT;
  handle->op = GNUNET_IDENTITY_delete (handle->identity_handle,
                                       ego_entry->identifier,
                                       &do_finished,
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
              const char *url,
              void *cls)
{
  struct MHD_Response *resp;
  struct RequestHandle *handle = cls;

  // For now, independent of path return all options
  resp = GNUNET_REST_create_response (NULL);
  MHD_add_response_header (resp, "Access-Control-Allow-Methods", allow_methods);
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
  static const struct GNUNET_REST_RequestHandler handlers[] =
  { { MHD_HTTP_METHOD_GET, GNUNET_REST_API_NS_IDENTITY, &ego_get_all },
    { MHD_HTTP_METHOD_GET, GNUNET_REST_API_NS_IDENTITY_PUBKEY,
      &ego_get_pubkey },
    { MHD_HTTP_METHOD_GET, GNUNET_REST_API_NS_IDENTITY_NAME, &ego_get_name },
    { MHD_HTTP_METHOD_GET,
      GNUNET_REST_API_NS_IDENTITY_SUBSYSTEM,
      &ego_get_subsystem },
    { MHD_HTTP_METHOD_PUT,
      GNUNET_REST_API_NS_IDENTITY_PUBKEY,
      &ego_edit_pubkey },
    { MHD_HTTP_METHOD_PUT, GNUNET_REST_API_NS_IDENTITY_NAME, &ego_edit_name },
    { MHD_HTTP_METHOD_PUT,
      GNUNET_REST_API_NS_IDENTITY_SUBSYSTEM,
      &ego_edit_subsystem },
    { MHD_HTTP_METHOD_POST, GNUNET_REST_API_NS_IDENTITY, &ego_create },
    { MHD_HTTP_METHOD_DELETE,
      GNUNET_REST_API_NS_IDENTITY_PUBKEY,
      &ego_delete_pubkey },
    { MHD_HTTP_METHOD_DELETE,
      GNUNET_REST_API_NS_IDENTITY_NAME,
      &ego_delete_name },
    { MHD_HTTP_METHOD_OPTIONS, GNUNET_REST_API_NS_IDENTITY, &options_cont },
    GNUNET_REST_HANDLER_END };

  if (GNUNET_NO ==
      GNUNET_REST_handle_request (handle->rest_handle, handlers, &err, handle))
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
init_egos (void *cls,
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
  if (ID_REST_STATE_INIT == handle->state)
  {
    ego_entry = GNUNET_new (struct EgoEntry);
    GNUNET_IDENTITY_ego_get_public_key (ego, &pk);
    ego_entry->keystring = GNUNET_CRYPTO_ecdsa_public_key_to_string (&pk);
    ego_entry->ego = ego;
    ego_entry->identifier = GNUNET_strdup (identifier);
    GNUNET_CONTAINER_DLL_insert_tail (handle->ego_head,
                                      handle->ego_tail,
                                      ego_entry);
    return;
  }
  // Check if ego exists
  for (ego_entry = handle->ego_head; NULL != ego_entry;)
  {
    struct EgoEntry *tmp = ego_entry;
    ego_entry = ego_entry->next;
    if (ego != tmp->ego)
      continue;
    // Deleted
    if (NULL == identifier)
    {
      GNUNET_CONTAINER_DLL_remove (handle->ego_head,
                                   handle->ego_tail,
                                   tmp);
      GNUNET_free (tmp->keystring);
      GNUNET_free (tmp->identifier);
      GNUNET_free (tmp);
    }
    else
    {
      // Renamed
      GNUNET_free (tmp->identifier);
      tmp->identifier = GNUNET_strdup (identifier);
    }
    return;
  }
  // New ego
  ego_entry = GNUNET_new (struct EgoEntry);
  GNUNET_IDENTITY_ego_get_public_key (ego, &pk);
  ego_entry->keystring = GNUNET_CRYPTO_ecdsa_public_key_to_string (&pk);
  ego_entry->ego = ego;
  GNUNET_asprintf (&ego_entry->identifier, "%s", identifier);
  GNUNET_CONTAINER_DLL_insert_tail (handle->ego_head,
                                    handle->ego_tail,
                                    ego_entry);

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
rest_process_request (struct GNUNET_REST_RequestHandle *rest_handle,
                      GNUNET_REST_ResultProcessor proc,
                      void *proc_cls)
{
  struct RequestHandle *handle = GNUNET_new (struct RequestHandle);

  handle->response_code = 0;
  handle->timeout = GNUNET_TIME_UNIT_FOREVER_REL;
  handle->proc_cls = proc_cls;
  handle->proc = proc;
  handle->rest_handle = rest_handle;
  handle->data = rest_handle->data;
  handle->data_size = rest_handle->data_size;

  handle->url = GNUNET_strdup (rest_handle->url);
  if (handle->url[strlen (handle->url) - 1] == '/')
    handle->url[strlen (handle->url) - 1] = '\0';
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Connecting...\n");

  handle->identity_handle = GNUNET_IDENTITY_connect (cfg, &init_egos, handle);

  handle->timeout_task =
    GNUNET_SCHEDULER_add_delayed (handle->timeout, &do_error, handle);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Connected\n");
}


/**
 * Entry point for the plugin.
 *
 * @param cls Config info
 * @return NULL on error, otherwise the plugin context
 */
void *
libgnunet_plugin_rest_identity_init (void *cls)
{
  static struct Plugin plugin;
  struct GNUNET_REST_Plugin *api;

  cfg = cls;
  if (NULL != plugin.cfg)
    return NULL; /* can only initialize once! */
  memset (&plugin, 0, sizeof(struct Plugin));
  plugin.cfg = cfg;
  api = GNUNET_new (struct GNUNET_REST_Plugin);
  api->cls = &plugin;
  api->name = GNUNET_REST_API_NS_IDENTITY;
  api->process_request = &rest_process_request;
  GNUNET_asprintf (&allow_methods,
                   "%s, %s, %s, %s, %s",
                   MHD_HTTP_METHOD_GET,
                   MHD_HTTP_METHOD_POST,
                   MHD_HTTP_METHOD_PUT,
                   MHD_HTTP_METHOD_DELETE,
                   MHD_HTTP_METHOD_OPTIONS);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, _ ("Identity REST API initialized\n"));
  return api;
}


/**
 * Exit point from the plugin.
 *
 * @param cls the plugin context (as returned by "init")
 * @return always NULL
 */
void *
libgnunet_plugin_rest_identity_done (void *cls)
{
  struct GNUNET_REST_Plugin *api = cls;
  struct Plugin *plugin = api->cls;

  plugin->cfg = NULL;

  GNUNET_free_non_null (allow_methods);
  GNUNET_free (api);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Identity REST plugin is finished\n");
  return NULL;
}


/* end of plugin_rest_identity.c */

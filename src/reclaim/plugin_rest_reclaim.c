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
 * @file reclaim/plugin_rest_reclaim.c
 * @brief GNUnet reclaim REST plugin
 *
 */
#include "platform.h"
#include "microhttpd.h"
#include <inttypes.h>
#include <jansson.h>
#include "gnunet_gns_service.h"
#include "gnunet_gnsrecord_lib.h"
#include "gnunet_identity_service.h"
#include "gnunet_reclaim_attribute_lib.h"
#include "gnunet_reclaim_service.h"
#include "gnunet_rest_lib.h"
#include "gnunet_rest_plugin.h"
#include "gnunet_signatures.h"
#include "json_reclaim.h"

/**
 * REST root namespace
 */
#define GNUNET_REST_API_NS_RECLAIM "/reclaim"

/**
 * Attribute namespace
 */
#define GNUNET_REST_API_NS_RECLAIM_ATTRIBUTES "/reclaim/attributes"

/**
 * Ticket namespace
 */
#define GNUNET_REST_API_NS_IDENTITY_TICKETS "/reclaim/tickets"

/**
 * Revoke namespace
 */
#define GNUNET_REST_API_NS_IDENTITY_REVOKE "/reclaim/revoke"

/**
 * Revoke namespace
 */
#define GNUNET_REST_API_NS_IDENTITY_CONSUME "/reclaim/consume"

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
   * Error response message
   */
  char *emsg;

  /**
   * Reponse code
   */
  int response_code;

  /**
   * Response object
   */
  json_t *resp_object;
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

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Cleaning up\n");
  if (NULL != handle->resp_object)
    json_decref (handle->resp_object);
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
  if (NULL != handle->url)
    GNUNET_free (handle->url);
  if (NULL != handle->emsg)
    GNUNET_free (handle->emsg);
  if (NULL != handle->attr_list)
  {
    for (claim_entry = handle->attr_list->list_head; NULL != claim_entry;)
    {
      claim_tmp = claim_entry;
      claim_entry = claim_entry->next;
      GNUNET_free (claim_tmp->claim);
      GNUNET_free (claim_tmp);
    }
    GNUNET_free (handle->attr_list);
  }
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

  GNUNET_asprintf (&json_error, "{ \"error\" : \"%s\" }", handle->emsg);
  if (0 == handle->response_code)
  {
    handle->response_code = MHD_HTTP_BAD_REQUEST;
  }
  resp = GNUNET_REST_create_response (json_error);
  MHD_add_response_header (resp, "Content-Type", "application/json");
  handle->proc (handle->proc_cls, resp, handle->response_code);
  GNUNET_SCHEDULER_add_now (&cleanup_handle_delayed, handle);
  GNUNET_free (json_error);
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


static void
collect_error_cb (void *cls)
{
  struct RequestHandle *handle = cls;

  do_error (handle);
}


static void
finished_cont (void *cls, int32_t success, const char *emsg)
{
  struct RequestHandle *handle = cls;
  struct MHD_Response *resp;

  resp = GNUNET_REST_create_response (emsg);
  if (GNUNET_OK != success)
  {
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }
  handle->proc (handle->proc_cls, resp, MHD_HTTP_OK);
  GNUNET_SCHEDULER_add_now (&cleanup_handle_delayed, handle);
}


/**
 * Return attributes for identity
 *
 * @param cls the request handle
 */
static void
return_response (void *cls)
{
  char *result_str;
  struct RequestHandle *handle = cls;
  struct MHD_Response *resp;

  result_str = json_dumps (handle->resp_object, 0);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Result %s\n", result_str);
  resp = GNUNET_REST_create_response (result_str);
  handle->proc (handle->proc_cls, resp, MHD_HTTP_OK);
  GNUNET_free (result_str);
  cleanup_handle (handle);
}


static void
collect_finished_cb (void *cls)
{
  struct RequestHandle *handle = cls;

  // Done
  handle->attr_it = NULL;
  handle->ticket_it = NULL;
  GNUNET_SCHEDULER_add_now (&return_response, handle);
}


/**
 * Collect all attributes for an ego
 *
 */
static void
ticket_collect (void *cls, const struct GNUNET_RECLAIM_Ticket *ticket)
{
  json_t *json_resource;
  struct RequestHandle *handle = cls;
  json_t *value;
  char *tmp;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Adding ticket\n");
  tmp = GNUNET_STRINGS_data_to_string_alloc (&ticket->rnd, sizeof(uint64_t));
  json_resource = json_object ();
  GNUNET_free (tmp);
  json_array_append (handle->resp_object, json_resource);

  tmp =
    GNUNET_STRINGS_data_to_string_alloc (&ticket->identity,
                                         sizeof(struct
                                                GNUNET_CRYPTO_EcdsaPublicKey));
  value = json_string (tmp);
  json_object_set_new (json_resource, "issuer", value);
  GNUNET_free (tmp);
  tmp =
    GNUNET_STRINGS_data_to_string_alloc (&ticket->audience,
                                         sizeof(struct
                                                GNUNET_CRYPTO_EcdsaPublicKey));
  value = json_string (tmp);
  json_object_set_new (json_resource, "audience", value);
  GNUNET_free (tmp);
  tmp = GNUNET_STRINGS_data_to_string_alloc (&ticket->rnd, sizeof(uint64_t));
  value = json_string (tmp);
  json_object_set_new (json_resource, "rnd", value);
  GNUNET_free (tmp);
  GNUNET_RECLAIM_ticket_iteration_next (handle->ticket_it);
}


/**
 * List tickets for identity request
 *
 * @param con_handle the connection handle
 * @param url the url
 * @param cls the RequestHandle
 */
static void
list_tickets_cont (struct GNUNET_REST_RequestHandle *con_handle,
                   const char *url,
                   void *cls)
{
  const struct GNUNET_CRYPTO_EcdsaPrivateKey *priv_key;
  struct RequestHandle *handle = cls;
  struct EgoEntry *ego_entry;
  char *identity;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Getting tickets for %s.\n",
              handle->url);
  if (strlen (GNUNET_REST_API_NS_IDENTITY_TICKETS) >= strlen (handle->url))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "No identity given.\n");
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }
  identity = handle->url + strlen (GNUNET_REST_API_NS_IDENTITY_TICKETS) + 1;

  for (ego_entry = handle->ego_head; NULL != ego_entry;
       ego_entry = ego_entry->next)
    if (0 == strcmp (identity, ego_entry->identifier))
      break;
  handle->resp_object = json_array ();

  if (NULL == ego_entry)
  {
    // Done
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Ego %s not found.\n", identity);
    GNUNET_SCHEDULER_add_now (&return_response, handle);
    return;
  }
  priv_key = GNUNET_IDENTITY_ego_get_private_key (ego_entry->ego);
  handle->idp = GNUNET_RECLAIM_connect (cfg);
  handle->ticket_it =
    GNUNET_RECLAIM_ticket_iteration_start (handle->idp,
                                           priv_key,
                                           &collect_error_cb,
                                           handle,
                                           &ticket_collect,
                                           handle,
                                           &collect_finished_cb,
                                           handle);
}


static void
add_attribute_cont (struct GNUNET_REST_RequestHandle *con_handle,
                    const char *url,
                    void *cls)
{
  const struct GNUNET_CRYPTO_EcdsaPrivateKey *identity_priv;
  const char *identity;
  struct RequestHandle *handle = cls;
  struct EgoEntry *ego_entry;
  struct GNUNET_RECLAIM_ATTRIBUTE_Claim *attribute;
  struct GNUNET_TIME_Relative exp;
  char term_data[handle->rest_handle->data_size + 1];
  json_t *data_json;
  json_error_t err;
  struct GNUNET_JSON_Specification attrspec[] =
  { GNUNET_RECLAIM_JSON_spec_claim (&attribute), GNUNET_JSON_spec_end () };

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Adding an attribute for %s.\n",
              handle->url);
  if (strlen (GNUNET_REST_API_NS_RECLAIM_ATTRIBUTES) >= strlen (handle->url))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "No identity given.\n");
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }
  identity = handle->url + strlen (GNUNET_REST_API_NS_RECLAIM_ATTRIBUTES) + 1;

  for (ego_entry = handle->ego_head; NULL != ego_entry;
       ego_entry = ego_entry->next)
    if (0 == strcmp (identity, ego_entry->identifier))
      break;

  if (NULL == ego_entry)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Identity unknown (%s)\n", identity);
    return;
  }
  identity_priv = GNUNET_IDENTITY_ego_get_private_key (ego_entry->ego);

  if (0 >= handle->rest_handle->data_size)
  {
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }

  term_data[handle->rest_handle->data_size] = '\0';
  GNUNET_memcpy (term_data,
                 handle->rest_handle->data,
                 handle->rest_handle->data_size);
  data_json = json_loads (term_data, JSON_DECODE_ANY, &err);
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_JSON_parse (data_json, attrspec, NULL, NULL));
  json_decref (data_json);
  if (NULL == attribute)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Unable to parse attribute from %s\n",
                term_data);
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }
  /**
   * New ID for attribute
   */
  if (0 == attribute->id)
    attribute->id =
      GNUNET_CRYPTO_random_u64 (GNUNET_CRYPTO_QUALITY_STRONG, UINT64_MAX);
  handle->idp = GNUNET_RECLAIM_connect (cfg);
  exp = GNUNET_TIME_UNIT_HOURS;
  handle->idp_op = GNUNET_RECLAIM_attribute_store (handle->idp,
                                                   identity_priv,
                                                   attribute,
                                                   &exp,
                                                   &finished_cont,
                                                   handle);
  GNUNET_JSON_parse_free (attrspec);
}


/**
 * Collect all attributes for an ego
 *
 */
static void
attr_collect (void *cls,
              const struct GNUNET_CRYPTO_EcdsaPublicKey *identity,
              const struct GNUNET_RECLAIM_ATTRIBUTE_Claim *attr)
{
  struct RequestHandle *handle = cls;
  json_t *attr_obj;
  const char *type;
  char *tmp_value;
  char *id_str;

  if ((NULL == attr->name) || (NULL == attr->data))
  {
    GNUNET_RECLAIM_get_attributes_next (handle->attr_it);
    return;
  }

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Adding attribute: %s\n", attr->name);

  tmp_value = GNUNET_RECLAIM_ATTRIBUTE_value_to_string (attr->type,
                                                        attr->data,
                                                        attr->data_size);

  attr_obj = json_object ();
  json_object_set_new (attr_obj, "value", json_string (tmp_value));
  json_object_set_new (attr_obj, "name", json_string (attr->name));
  type = GNUNET_RECLAIM_ATTRIBUTE_number_to_typename (attr->type);
  json_object_set_new (attr_obj, "type", json_string (type));
  id_str = GNUNET_STRINGS_data_to_string_alloc (&attr->id, sizeof(uint64_t));
  json_object_set_new (attr_obj, "id", json_string (id_str));
  json_array_append (handle->resp_object, attr_obj);
  json_decref (attr_obj);
  GNUNET_free (tmp_value);
  GNUNET_RECLAIM_get_attributes_next (handle->attr_it);
}


/**
 * List attributes for identity request
 *
 * @param con_handle the connection handle
 * @param url the url
 * @param cls the RequestHandle
 */
static void
list_attribute_cont (struct GNUNET_REST_RequestHandle *con_handle,
                     const char *url,
                     void *cls)
{
  const struct GNUNET_CRYPTO_EcdsaPrivateKey *priv_key;
  struct RequestHandle *handle = cls;
  struct EgoEntry *ego_entry;
  char *identity;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Getting attributes for %s.\n",
              handle->url);
  if (strlen (GNUNET_REST_API_NS_RECLAIM_ATTRIBUTES) >= strlen (handle->url))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "No identity given.\n");
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }
  identity = handle->url + strlen (GNUNET_REST_API_NS_RECLAIM_ATTRIBUTES) + 1;

  for (ego_entry = handle->ego_head; NULL != ego_entry;
       ego_entry = ego_entry->next)
    if (0 == strcmp (identity, ego_entry->identifier))
      break;
  handle->resp_object = json_array ();


  if (NULL == ego_entry)
  {
    // Done
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Ego %s not found.\n", identity);
    GNUNET_SCHEDULER_add_now (&return_response, handle);
    return;
  }
  priv_key = GNUNET_IDENTITY_ego_get_private_key (ego_entry->ego);
  handle->idp = GNUNET_RECLAIM_connect (cfg);
  handle->attr_it = GNUNET_RECLAIM_get_attributes_start (handle->idp,
                                                         priv_key,
                                                         &collect_error_cb,
                                                         handle,
                                                         &attr_collect,
                                                         handle,
                                                         &collect_finished_cb,
                                                         handle);
}


static void
delete_finished_cb (void *cls, int32_t success, const char *emsg)
{
  struct RequestHandle *handle = cls;
  struct MHD_Response *resp;

  resp = GNUNET_REST_create_response (emsg);
  if (GNUNET_OK != success)
  {
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }
  handle->proc (handle->proc_cls, resp, MHD_HTTP_OK);
  GNUNET_SCHEDULER_add_now (&cleanup_handle_delayed, handle);
}


/**
 * List attributes for identity request
 *
 * @param con_handle the connection handle
 * @param url the url
 * @param cls the RequestHandle
 */
static void
delete_attribute_cont (struct GNUNET_REST_RequestHandle *con_handle,
                       const char *url,
                       void *cls)
{
  const struct GNUNET_CRYPTO_EcdsaPrivateKey *priv_key;
  struct RequestHandle *handle = cls;
  struct GNUNET_RECLAIM_ATTRIBUTE_Claim attr;
  struct EgoEntry *ego_entry;
  char *identity_id_str;
  char *identity;
  char *id;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Deleting attributes.\n");
  if (strlen (GNUNET_REST_API_NS_RECLAIM_ATTRIBUTES) >= strlen (handle->url))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "No identity given.\n");
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }
  identity_id_str =
    strdup (handle->url + strlen (GNUNET_REST_API_NS_RECLAIM_ATTRIBUTES) + 1);
  identity = strtok (identity_id_str, "/");
  id = strtok (NULL, "/");
  if ((NULL == identity) || (NULL == id))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Malformed request.\n");
    GNUNET_free (identity_id_str);
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }

  for (ego_entry = handle->ego_head; NULL != ego_entry;
       ego_entry = ego_entry->next)
    if (0 == strcmp (identity, ego_entry->identifier))
      break;
  handle->resp_object = json_array ();
  if (NULL == ego_entry)
  {
    // Done
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Ego %s not found.\n", identity);
    GNUNET_free (identity_id_str);
    GNUNET_SCHEDULER_add_now (&return_response, handle);
    return;
  }
  priv_key = GNUNET_IDENTITY_ego_get_private_key (ego_entry->ego);
  handle->idp = GNUNET_RECLAIM_connect (cfg);
  memset (&attr, 0, sizeof(struct GNUNET_RECLAIM_ATTRIBUTE_Claim));
  GNUNET_STRINGS_string_to_data (id, strlen (id), &attr.id, sizeof(uint64_t));
  attr.name = "";
  handle->idp_op = GNUNET_RECLAIM_attribute_delete (handle->idp,
                                                    priv_key,
                                                    &attr,
                                                    &delete_finished_cb,
                                                    handle);
  GNUNET_free (identity_id_str);
}


static void
revoke_ticket_cont (struct GNUNET_REST_RequestHandle *con_handle,
                    const char *url,
                    void *cls)
{
  const struct GNUNET_CRYPTO_EcdsaPrivateKey *identity_priv;
  struct RequestHandle *handle = cls;
  struct EgoEntry *ego_entry;
  struct GNUNET_RECLAIM_Ticket *ticket = NULL;
  struct GNUNET_CRYPTO_EcdsaPublicKey tmp_pk;
  char term_data[handle->rest_handle->data_size + 1];
  json_t *data_json;
  json_error_t err;
  struct GNUNET_JSON_Specification tktspec[] =
  { GNUNET_RECLAIM_JSON_spec_ticket (&ticket), GNUNET_JSON_spec_end () };

  if (0 >= handle->rest_handle->data_size)
  {
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }

  term_data[handle->rest_handle->data_size] = '\0';
  GNUNET_memcpy (term_data,
                 handle->rest_handle->data,
                 handle->rest_handle->data_size);
  data_json = json_loads (term_data, JSON_DECODE_ANY, &err);
  if ((NULL == data_json) ||
      (GNUNET_OK != GNUNET_JSON_parse (data_json, tktspec, NULL, NULL)))
  {
    handle->emsg = GNUNET_strdup ("Not a ticket!\n");
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    GNUNET_JSON_parse_free (tktspec);
    if (NULL != data_json)
      json_decref (data_json);
    return;
  }
  json_decref (data_json);
  if (NULL == ticket)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Unable to parse ticket from %s\n",
                term_data);
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }

  for (ego_entry = handle->ego_head; NULL != ego_entry;
       ego_entry = ego_entry->next)
  {
    GNUNET_IDENTITY_ego_get_public_key (ego_entry->ego, &tmp_pk);
    if (0 == memcmp (&ticket->identity,
                     &tmp_pk,
                     sizeof(struct GNUNET_CRYPTO_EcdsaPublicKey)))
      break;
  }
  if (NULL == ego_entry)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Identity unknown\n");
    GNUNET_JSON_parse_free (tktspec);
    return;
  }
  identity_priv = GNUNET_IDENTITY_ego_get_private_key (ego_entry->ego);

  handle->idp = GNUNET_RECLAIM_connect (cfg);
  handle->idp_op = GNUNET_RECLAIM_ticket_revoke (handle->idp,
                                                 identity_priv,
                                                 ticket,
                                                 &finished_cont,
                                                 handle);
  GNUNET_JSON_parse_free (tktspec);
}


static void
consume_cont (void *cls,
              const struct GNUNET_CRYPTO_EcdsaPublicKey *identity,
              const struct GNUNET_RECLAIM_ATTRIBUTE_Claim *attr)
{
  struct RequestHandle *handle = cls;
  char *val_str;
  json_t *value;

  if (NULL == identity)
  {
    GNUNET_SCHEDULER_add_now (&return_response, handle);
    return;
  }

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Adding attribute: %s\n", attr->name);
  val_str = GNUNET_RECLAIM_ATTRIBUTE_value_to_string (attr->type,
                                                      attr->data,
                                                      attr->data_size);
  if (NULL == val_str)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Failed to parse value for: %s\n",
                attr->name);
    return;
  }
  value = json_string (val_str);
  json_object_set_new (handle->resp_object, attr->name, value);
  json_decref (value);
  GNUNET_free (val_str);
}


static void
consume_ticket_cont (struct GNUNET_REST_RequestHandle *con_handle,
                     const char *url,
                     void *cls)
{
  const struct GNUNET_CRYPTO_EcdsaPrivateKey *identity_priv;
  struct RequestHandle *handle = cls;
  struct EgoEntry *ego_entry;
  struct GNUNET_RECLAIM_Ticket *ticket;
  struct GNUNET_CRYPTO_EcdsaPublicKey tmp_pk;
  char term_data[handle->rest_handle->data_size + 1];
  json_t *data_json;
  json_error_t err;
  struct GNUNET_JSON_Specification tktspec[] =
  { GNUNET_RECLAIM_JSON_spec_ticket (&ticket), GNUNET_JSON_spec_end () };

  if (0 >= handle->rest_handle->data_size)
  {
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }

  term_data[handle->rest_handle->data_size] = '\0';
  GNUNET_memcpy (term_data,
                 handle->rest_handle->data,
                 handle->rest_handle->data_size);
  data_json = json_loads (term_data, JSON_DECODE_ANY, &err);
  if (NULL == data_json)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Unable to parse JSON Object from %s\n",
                term_data);
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }
  if (GNUNET_OK != GNUNET_JSON_parse (data_json, tktspec, NULL, NULL))
  {
    handle->emsg = GNUNET_strdup ("Not a ticket!\n");
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    GNUNET_JSON_parse_free (tktspec);
    json_decref (data_json);
    return;
  }
  for (ego_entry = handle->ego_head; NULL != ego_entry;
       ego_entry = ego_entry->next)
  {
    GNUNET_IDENTITY_ego_get_public_key (ego_entry->ego, &tmp_pk);
    if (0 == memcmp (&ticket->audience,
                     &tmp_pk,
                     sizeof(struct GNUNET_CRYPTO_EcdsaPublicKey)))
      break;
  }
  if (NULL == ego_entry)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Identity unknown\n");
    GNUNET_JSON_parse_free (tktspec);
    return;
  }
  identity_priv = GNUNET_IDENTITY_ego_get_private_key (ego_entry->ego);
  handle->resp_object = json_object ();
  handle->idp = GNUNET_RECLAIM_connect (cfg);
  handle->idp_op = GNUNET_RECLAIM_ticket_consume (handle->idp,
                                                  identity_priv,
                                                  ticket,
                                                  &consume_cont,
                                                  handle);
  GNUNET_JSON_parse_free (tktspec);
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
  struct GNUNET_REST_RequestHandlerError err;
  static const struct GNUNET_REST_RequestHandler handlers[] =
  { { MHD_HTTP_METHOD_GET,
      GNUNET_REST_API_NS_RECLAIM_ATTRIBUTES,
      &list_attribute_cont },
    { MHD_HTTP_METHOD_POST,
      GNUNET_REST_API_NS_RECLAIM_ATTRIBUTES,
      &add_attribute_cont },
    { MHD_HTTP_METHOD_DELETE,
      GNUNET_REST_API_NS_RECLAIM_ATTRIBUTES,
      &delete_attribute_cont },
    { MHD_HTTP_METHOD_GET,
      GNUNET_REST_API_NS_IDENTITY_TICKETS,
      &list_tickets_cont },
    { MHD_HTTP_METHOD_POST,
      GNUNET_REST_API_NS_IDENTITY_REVOKE,
      &revoke_ticket_cont },
    { MHD_HTTP_METHOD_POST,
      GNUNET_REST_API_NS_IDENTITY_CONSUME,
      &consume_ticket_cont },
    { MHD_HTTP_METHOD_OPTIONS, GNUNET_REST_API_NS_RECLAIM, &options_cont },
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
  }
}


static void
rest_identity_process_request (struct GNUNET_REST_RequestHandle *rest_handle,
                               GNUNET_REST_ResultProcessor proc,
                               void *proc_cls)
{
  struct RequestHandle *handle = GNUNET_new (struct RequestHandle);

  handle->response_code = 0;
  handle->timeout = GNUNET_TIME_UNIT_FOREVER_REL;
  handle->proc_cls = proc_cls;
  handle->proc = proc;
  handle->state = ID_REST_STATE_INIT;
  handle->rest_handle = rest_handle;

  handle->url = GNUNET_strdup (rest_handle->url);
  if (handle->url[strlen (handle->url) - 1] == '/')
    handle->url[strlen (handle->url) - 1] = '\0';
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Connecting...\n");
  handle->identity_handle = GNUNET_IDENTITY_connect (cfg, &list_ego, handle);
  handle->timeout_task =
    GNUNET_SCHEDULER_add_delayed (handle->timeout, &do_timeout, handle);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Connected\n");
}


/**
 * Entry point for the plugin.
 *
 * @param cls Config info
 * @return NULL on error, otherwise the plugin context
 */
void *
libgnunet_plugin_rest_reclaim_init (void *cls)
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
  api->name = GNUNET_REST_API_NS_RECLAIM;
  api->process_request = &rest_identity_process_request;
  GNUNET_asprintf (&allow_methods,
                   "%s, %s, %s, %s, %s",
                   MHD_HTTP_METHOD_GET,
                   MHD_HTTP_METHOD_POST,
                   MHD_HTTP_METHOD_PUT,
                   MHD_HTTP_METHOD_DELETE,
                   MHD_HTTP_METHOD_OPTIONS);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              _ ("Identity Provider REST API initialized\n"));
  return api;
}


/**
 * Exit point from the plugin.
 *
 * @param cls the plugin context (as returned by "init")
 * @return always NULL
 */
void *
libgnunet_plugin_rest_reclaim_done (void *cls)
{
  struct GNUNET_REST_Plugin *api = cls;
  struct Plugin *plugin = api->cls;

  plugin->cfg = NULL;

  GNUNET_free_non_null (allow_methods);
  GNUNET_free (api);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Identity Provider REST plugin is finished\n");
  return NULL;
}


/* end of plugin_rest_reclaim.c */

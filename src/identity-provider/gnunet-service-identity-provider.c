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
 * @file src/identity/gnunet-service-identity-provider.c
 * @brief Identity Token Service
 *
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_constants.h"
#include "gnunet_protocols.h"
#include "gnunet_identity_service.h"
#include "gnunet_gnsrecord_lib.h"
#include "gnunet_namestore_service.h"
#include "gnunet_statistics_service.h"
#include "gnunet_gns_service.h"
#include <jansson.h>
#include "gnunet_signatures.h"
#include "identity_provider.h"
#include "identity_token.h"

/**
 * First pass state
 */
#define STATE_INIT 0

/**
 * Normal operation state
 */
#define STATE_POST_INIT 1

/**
 * Minimum interval between updates
 */
#define MIN_WAIT_TIME GNUNET_TIME_UNIT_MINUTES

/**
 * Service state (to detect initial update pass)
 */
static int state;

/**
 * Head of ego entry DLL
 */
static struct EgoEntry *ego_head;

/**
 * Tail of ego entry DLL
 */
static struct EgoEntry *ego_tail;

/**
 * Identity handle
 */
static struct GNUNET_IDENTITY_Handle *identity_handle;

/**
 * Namestore handle
 */
static struct GNUNET_NAMESTORE_Handle *ns_handle;

/**
 * GNS handle
 */
static struct GNUNET_GNS_Handle *gns_handle;

/**
 * Namestore qe
 */
static struct GNUNET_NAMESTORE_QueueEntry *ns_qe;

/**
 * Namestore iterator
 */
static struct GNUNET_NAMESTORE_ZoneIterator *ns_it;

/**
 * Timeout task
 */
static struct GNUNET_SCHEDULER_Task * timeout_task;


/**
 * Update task
 */
static struct GNUNET_SCHEDULER_Task * update_task;

/**
 * Timeout for next update pass
 */
static struct GNUNET_TIME_Relative min_rel_exp;


/**
 * Currently processed token
 */
static struct IdentityToken *token;

/**
 * Label for currently processed token
 */
static char* label;

/**
 * Scopes for processed token
 */
static char* scopes;

/**
 * Expiration for processed token
 */
static uint64_t rd_exp;

/**
 * ECDHE Privkey for processed token metadata
 */
static struct GNUNET_CRYPTO_EcdhePrivateKey ecdhe_privkey;

/**
 * Handle to the statistics service.
 */
static struct GNUNET_STATISTICS_Handle *stats;

/**
 * Notification context, simplifies client broadcasts.
 */
static struct GNUNET_SERVER_NotificationContext *nc;

struct ExchangeHandle
{

  /**
   * Client connection
   */
  struct GNUNET_SERVER_Client *client;

  /**
   * Ticket
   */
  struct TokenTicket *ticket;

  /**
   * Token returned
   */
  struct IdentityToken *token;

  /**
   * LookupRequest
   */
  struct GNUNET_GNS_LookupRequest *lookup_request;
  
  /**
   * Audience Key
   */
  struct GNUNET_CRYPTO_EcdsaPrivateKey aud_privkey;

  /**
   * Label to return
   */
  char *label;
};

struct IssueHandle
{

  /**
   * Client connection
   */
  struct GNUNET_SERVER_Client *client;

  /**
   * Issuer Key
   */
  struct GNUNET_CRYPTO_EcdsaPrivateKey iss_key;

  /**
   * Issue pubkey
   */
  struct GNUNET_CRYPTO_EcdsaPublicKey iss_pkey;

  /**
   * Audience Key
   */
  struct GNUNET_CRYPTO_EcdsaPublicKey aud_key;

  /**
   * Expiration
   */
  struct GNUNET_TIME_Absolute expiration;

  /**
   * Scopes
   */
  char *scopes;

  /**
   * nonce
   */
  uint64_t nonce;

  /**
   * NS iterator
   */
  struct GNUNET_NAMESTORE_ZoneIterator *ns_it;

  /**
   * Attribute map
   */
  struct GNUNET_CONTAINER_MultiHashMap *attr_map;

  /**
   * Token
   */
  struct IdentityToken *token;

  /**
   * Ticket
   */
  struct TokenTicket *ticket;

  /**
   * QueueEntry
   */
  struct GNUNET_NAMESTORE_QueueEntry *ns_qe;
};

/**
 * DLL for ego handles to egos containing the ID_ATTRS in a map in json_t format
 *
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
   * Ego handle
   */
  struct GNUNET_IDENTITY_Ego *ego;

  /**
   * Attribute map. Contains the attributes as json_t
   */
  struct GNUNET_CONTAINER_MultiHashMap *attr_map;

  /**
   * Attributes are old and should be updated if GNUNET_YES
   */
  int attributes_dirty;
};

/**
 * Our configuration.
 */
  static const struct GNUNET_CONFIGURATION_Handle *cfg;


  /**
   * Continuation for token store call
   *
   * @param cls NULL
   * @param success error code
   * @param emsg error message
   */
static void
store_token_cont (void *cls,
                  int32_t success,
                  const char *emsg)
{
  ns_qe = NULL;
  if (GNUNET_SYSERR == success)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Failed to update token: %s\n",
                emsg);
    return;
  }
  GNUNET_NAMESTORE_zone_iterator_next (ns_it);
}


/**
 * This function updates the old token with new attributes,
 * removes deleted attributes and expiration times.
 *
 * @param cls the ego entry
 * @param tc task context
 */
static void
handle_token_update (void *cls,
                     const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  char *token_metadata;
  char *write_ptr;
  char *enc_token_str;
  const char *key;
  const struct GNUNET_CRYPTO_EcdsaPrivateKey *priv_key;
  struct GNUNET_CRYPTO_EcdsaPublicKey pub_key;
  struct GNUNET_CRYPTO_EcdhePrivateKey *new_ecdhe_privkey;
  struct EgoEntry *ego_entry = cls;
  struct GNUNET_GNSRECORD_Data token_record[2];
  struct GNUNET_HashCode key_hash;
  struct GNUNET_TIME_Relative token_rel_exp;
  struct GNUNET_TIME_Relative token_ttl;
  struct GNUNET_TIME_Absolute token_exp;
  struct GNUNET_TIME_Absolute token_nbf;
  struct GNUNET_TIME_Absolute new_exp;
  struct GNUNET_TIME_Absolute new_iat;
  struct GNUNET_TIME_Absolute new_nbf;
  struct IdentityToken *new_token;
  json_t *payload_json;
  json_t *value;
  json_t *cur_value;
  json_t *token_nbf_json;
  json_t *token_exp_json;
  size_t token_metadata_len;

  priv_key = GNUNET_IDENTITY_ego_get_private_key (ego_entry->ego);
  GNUNET_IDENTITY_ego_get_public_key (ego_entry->ego,
                                      &pub_key);

  //Note: We need the token expiration time here. Not the record expiration
  //time.
  //There are two types of tokens: Token that expire on GNS level with
  //an absolute expiration time. Those are basically tokens that will
  //be automatically revoked on (record)expiration.
  //Tokens stored with relative expiration times will expire on the token level (token expiration)
  //but this service will reissue new tokens that can be retrieved from GNS
  //automatically.

  payload_json = token->payload;

  token_exp_json = json_object_get (payload_json, "exp");
  token_nbf_json = json_object_get (payload_json, "nbf");
  token_exp.abs_value_us = json_integer_value(token_exp_json);
  token_nbf.abs_value_us = json_integer_value(token_nbf_json);
  token_rel_exp = GNUNET_TIME_absolute_get_difference (token_nbf, token_exp);

  token_ttl = GNUNET_TIME_absolute_get_remaining (token_exp);
  if (0 != GNUNET_TIME_absolute_get_remaining (token_exp).rel_value_us)
  {
    //This token is not yet expired! Save and skip
    if (min_rel_exp.rel_value_us > token_ttl.rel_value_us)
    {
      min_rel_exp = token_ttl;
    }
    json_decref (payload_json);
    GNUNET_free (token);
    token = NULL;
    GNUNET_free (label);
    label = NULL;
    GNUNET_free (scopes);
    scopes = NULL;
    GNUNET_NAMESTORE_zone_iterator_next (ns_it);
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Token is expired. Create a new one\n");
  new_token = token_create (&pub_key,
                            &token->aud_key);
  new_exp = GNUNET_TIME_relative_to_absolute (token_rel_exp);
  new_nbf = GNUNET_TIME_absolute_get ();
  new_iat = new_nbf;

  json_object_foreach(payload_json, key, value) {
    if (0 == strcmp (key, "exp"))
    {
      token_add_json (new_token, key, json_integer (new_exp.abs_value_us));
    }
    else if (0 == strcmp (key, "nbf"))
    {
      token_add_json (new_token, key, json_integer (new_nbf.abs_value_us));
    }
    else if (0 == strcmp (key, "iat"))
    {
      token_add_json (new_token, key, json_integer (new_iat.abs_value_us));
    }
    else if ((0 == strcmp (key, "iss"))
             || (0 == strcmp (key, "aud")))
    {
      //Omit
    }
    else if ((0 == strcmp (key, "sub"))
             || (0 == strcmp (key, "rnl")))
    {
      token_add_json (new_token, key, value);
    }
    else {
      GNUNET_CRYPTO_hash (key,
                          strlen (key),
                          &key_hash);
      //Check if attr still exists. omit of not
      if (GNUNET_NO != GNUNET_CONTAINER_multihashmap_contains (ego_entry->attr_map,
                                                               &key_hash))
      {
        cur_value = GNUNET_CONTAINER_multihashmap_get (ego_entry->attr_map,
                                                       &key_hash);
        token_add_json (new_token, key, cur_value);
      }
    }
  }

  // reassemble and set
  GNUNET_assert (token_serialize (new_token,
                                  priv_key,
                                  &new_ecdhe_privkey,
                                  &enc_token_str));

  json_decref (payload_json);

  token_record[0].data = enc_token_str;
  token_record[0].data_size = strlen (enc_token_str) + 1;
  token_record[0].expiration_time = rd_exp; //Old expiration time
  token_record[0].record_type = GNUNET_GNSRECORD_TYPE_ID_TOKEN;
  token_record[0].flags = GNUNET_GNSRECORD_RF_NONE;

  //Meta
  token_metadata_len = sizeof (struct GNUNET_CRYPTO_EcdhePrivateKey)
    + sizeof (struct GNUNET_CRYPTO_EcdsaPublicKey)
    + strlen (scopes) + 1; //With 0-Terminator
  token_metadata = GNUNET_malloc (token_metadata_len);
  write_ptr = token_metadata;
  memcpy (token_metadata, new_ecdhe_privkey, sizeof (struct GNUNET_CRYPTO_EcdhePrivateKey));
  write_ptr += sizeof (struct GNUNET_CRYPTO_EcdhePrivateKey);
  memcpy (write_ptr, &token->aud_key, sizeof (struct GNUNET_CRYPTO_EcdsaPublicKey));
  write_ptr += sizeof (struct GNUNET_CRYPTO_EcdsaPublicKey);
  memcpy (write_ptr, scopes, strlen (scopes) + 1); //with 0-Terminator;

  token_record[1].data = token_metadata;
  token_record[1].data_size = token_metadata_len;
  token_record[1].expiration_time = rd_exp;
  token_record[1].record_type = GNUNET_GNSRECORD_TYPE_ID_TOKEN_METADATA;
  token_record[1].flags = GNUNET_GNSRECORD_RF_PRIVATE;

  ns_qe = GNUNET_NAMESTORE_records_store (ns_handle,
                                          priv_key,
                                          label,
                                          2,
                                          token_record,
                                          &store_token_cont,
                                          ego_entry);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, ">>> Updating Token w/ %s\n", new_token);
  token_destroy (new_token);
  token_destroy (token);
  GNUNET_free (new_ecdhe_privkey);
  GNUNET_free (enc_token_str);
  token = NULL;
  GNUNET_free (label);
  label = NULL;
  GNUNET_free (scopes);
  scopes = NULL;
}

static void
update_identities(void *cls,
                  const struct GNUNET_SCHEDULER_TaskContext *tc);

/**
 *
 * Cleanup attr_map
 *
 * @param cls NULL
 * @param key the key
 * @param value the json_t attribute value
 * @return GNUNET_YES
 */
static int
clear_ego_attrs (void *cls,
                 const struct GNUNET_HashCode *key,
                 void *value)
{
  json_t *attr_value = value;

  json_decref (attr_value);

  return GNUNET_YES;
}


/**
 *
 * Update all ID_TOKEN records for an identity and store them
 *
 * @param cls the identity entry
 * @param zone the identity
 * @param lbl the name of the record
 * @param rd_count number of records
 * @param rd record data
 *
 */
static void
token_collect (void *cls,
               const struct GNUNET_CRYPTO_EcdsaPrivateKey *zone,
               const char *lbl,
               unsigned int rd_count,
               const struct GNUNET_GNSRECORD_Data *rd)
{
  struct EgoEntry *ego_entry = cls;
  const struct GNUNET_GNSRECORD_Data *token_record;
  const struct GNUNET_GNSRECORD_Data *token_metadata_record;
  struct GNUNET_CRYPTO_EcdsaPublicKey *aud_key;

  if (NULL == lbl)
  {
    //Done
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                ">>> Updating Ego finished\n");
    //Clear attribute map for ego
    GNUNET_CONTAINER_multihashmap_iterate (ego_entry->attr_map,
                                           &clear_ego_attrs,
                                           ego_entry);
    GNUNET_CONTAINER_multihashmap_clear (ego_entry->attr_map);
    GNUNET_SCHEDULER_add_now (&update_identities, ego_entry->next);
    return;
  }

  //There should be only a single record for a token under a label
  if (2 != rd_count)
  {
    GNUNET_NAMESTORE_zone_iterator_next (ns_it);
    return;
  }

  if (rd[0].record_type == GNUNET_GNSRECORD_TYPE_ID_TOKEN_METADATA)
  {
    token_metadata_record = &rd[0];
    token_record = &rd[1];
  } else {
    token_record = &rd[0];
    token_metadata_record = &rd[1];
  }
  GNUNET_assert (token_metadata_record->record_type == GNUNET_GNSRECORD_TYPE_ID_TOKEN_METADATA);
  GNUNET_assert (token_record->record_type == GNUNET_GNSRECORD_TYPE_ID_TOKEN);

  //Get metadata and decrypt token
  ecdhe_privkey = *((struct GNUNET_CRYPTO_EcdhePrivateKey *)token_metadata_record->data);
  aud_key = (struct GNUNET_CRYPTO_EcdsaPublicKey *)&ecdhe_privkey+sizeof(struct GNUNET_CRYPTO_EcdhePrivateKey);
  scopes = GNUNET_strdup ((char*) aud_key+sizeof (struct GNUNET_CRYPTO_EcdsaPublicKey));

  token_parse2 (token_record->data,
                &ecdhe_privkey,
                aud_key,
                &token);

  //token = GNUNET_GNSRECORD_value_to_string (rd->record_type,
  //                                          rd->data,
  //                                          rd->data_size);
  label = GNUNET_strdup (lbl); 
  rd_exp = token_record->expiration_time;

  GNUNET_SCHEDULER_add_now (&handle_token_update, ego_entry);
}


/**
 *
 * Collect all ID_ATTR records for an identity and store them
 *
 * @param cls the identity entry
 * @param zone the identity
 * @param lbl the name of the record
 * @param rd_count number of records
 * @param rd record data
 *
 */
static void
attribute_collect (void *cls,
                   const struct GNUNET_CRYPTO_EcdsaPrivateKey *zone,
                   const char *lbl,
                   unsigned int rd_count,
                   const struct GNUNET_GNSRECORD_Data *rd)
{
  struct EgoEntry *ego_entry = cls;
  json_t *attr_value;
  struct GNUNET_HashCode key;
  char* attr;
  int i;

  if (NULL == lbl)
  {
    //Done
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                ">>> Updating Attributes finished\n");
    ego_entry->attributes_dirty = GNUNET_NO;
    GNUNET_SCHEDULER_add_now (&update_identities, ego_entry);
    return;
  }

  if (0 == rd_count)
  {
    GNUNET_NAMESTORE_zone_iterator_next (ns_it);
    return;
  }
  GNUNET_CRYPTO_hash (lbl,
                      strlen (lbl),
                      &key);
  if (1 == rd_count)
  {
    if (rd->record_type == GNUNET_GNSRECORD_TYPE_ID_ATTR)
    {
      attr = GNUNET_GNSRECORD_value_to_string (rd->record_type,
                                               rd->data,
                                               rd->data_size);
      attr_value = json_string (attr);
      GNUNET_CONTAINER_multihashmap_put (ego_entry->attr_map,
                                         &key,
                                         attr_value,
                                         GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY);
      GNUNET_free (attr);
    }

    GNUNET_NAMESTORE_zone_iterator_next (ns_it);
    return;
  }

  attr_value = json_array();
  for (i = 0; i < rd_count; i++)
  {
    if (rd[i].record_type == GNUNET_GNSRECORD_TYPE_ID_ATTR)
    {
      attr = GNUNET_GNSRECORD_value_to_string (rd[i].record_type,
                                               rd[i].data,
                                               rd[i].data_size);
      json_array_append_new (attr_value, json_string (attr));
      GNUNET_free (attr);
    }

  }
  GNUNET_CONTAINER_multihashmap_put (ego_entry->attr_map,
                                     &key,
                                     attr_value,
                                     GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY);
  GNUNET_NAMESTORE_zone_iterator_next (ns_it);
  return;
}

/**
 *
 * Update identity information for ego. If attribute map is
 * dirty, first update the attributes.
 *
 * @param cls the ego to update
 * param tc task context
 *
 */
static void
update_identities(void *cls,
                  const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct EgoEntry *next_ego = cls;
  const struct GNUNET_CRYPTO_EcdsaPrivateKey *priv_key;
  if (NULL == next_ego)
  {
    if (min_rel_exp.rel_value_us < MIN_WAIT_TIME.rel_value_us)
      min_rel_exp = MIN_WAIT_TIME;
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                ">>> Finished. Rescheduling in %d\n",
                min_rel_exp.rel_value_us);
    ns_it = NULL;
    //finished -> TODO reschedule
    update_task = GNUNET_SCHEDULER_add_delayed (min_rel_exp,
                                                &update_identities,
                                                ego_head);
    min_rel_exp.rel_value_us = 0;
    return;
  }
  priv_key = GNUNET_IDENTITY_ego_get_private_key (next_ego->ego);
  if (GNUNET_YES == next_ego->attributes_dirty)
  {
    //Starting over. We must update the Attributes for they might have changed.
    ns_it = GNUNET_NAMESTORE_zone_iteration_start (ns_handle,
                                                   priv_key,
                                                   &attribute_collect,
                                                   next_ego);

  }
  else
  {
    //Ego will be dirty next time
    next_ego->attributes_dirty = GNUNET_YES;
    ns_it = GNUNET_NAMESTORE_zone_iteration_start (ns_handle,
                                                   priv_key,
                                                   &token_collect,
                                                   next_ego);
  }
}



/**
 * Function called initially to start update task
 */
static void
init_cont ()
{
  GNUNET_log (GNUNET_ERROR_TYPE_INFO, ">>> Starting Service\n");
  //Initially iterate all itenties and refresh all tokens
  update_task = GNUNET_SCHEDULER_add_now (&update_identities, ego_head);
}

/**
 * Initial ego collection function.
 *
 * @param cls NULL
 * @param ego ego
 * @param ctx context
 * @param identifier ego name
 */
static void
list_ego (void *cls,
          struct GNUNET_IDENTITY_Ego *ego,
          void **ctx,
          const char *identifier)
{
  struct EgoEntry *new_entry;
  if ((NULL == ego) && (STATE_INIT == state))
  {
    state = STATE_POST_INIT;
    init_cont ();
    return;
  }
  if (STATE_INIT == state) {
    new_entry = GNUNET_malloc (sizeof (struct EgoEntry));
    new_entry->ego = ego;
    new_entry->attr_map = GNUNET_CONTAINER_multihashmap_create (5,
                                                                GNUNET_NO);
    new_entry->attributes_dirty = GNUNET_YES;
    GNUNET_CONTAINER_DLL_insert_tail(ego_head, ego_tail, new_entry);
  }
}

/**
 * Cleanup task
 */
static void
cleanup()
{
  struct EgoEntry *ego_entry;
  struct EgoEntry *ego_tmp;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Cleaning up\n");
  if (NULL != nc)
  {
    GNUNET_SERVER_notification_context_destroy (nc);
    nc = NULL;
  }
  if (NULL != stats)
  {
    GNUNET_STATISTICS_destroy (stats, GNUNET_NO);
    stats = NULL;
  }

  if (NULL != timeout_task)
    GNUNET_SCHEDULER_cancel (timeout_task);
  if (NULL != update_task)
    GNUNET_SCHEDULER_cancel (update_task);
  if (NULL != identity_handle)
    GNUNET_IDENTITY_disconnect (identity_handle);
  if (NULL != gns_handle)
    GNUNET_GNS_disconnect (gns_handle);
  if (NULL != ns_it)
    GNUNET_NAMESTORE_zone_iteration_stop (ns_it);
  if (NULL != ns_qe)
    GNUNET_NAMESTORE_cancel (ns_qe);
  if (NULL != ns_handle)
    GNUNET_NAMESTORE_disconnect (ns_handle);
  if (NULL != token)
    GNUNET_free (token);
  if (NULL != label)
    GNUNET_free (label);

  for (ego_entry = ego_head;
       NULL != ego_entry;)
  {
    ego_tmp = ego_entry;
    if (0 != GNUNET_CONTAINER_multihashmap_size (ego_tmp->attr_map))
    {
      GNUNET_CONTAINER_multihashmap_iterate (ego_tmp->attr_map,
                                             &clear_ego_attrs,
                                             ego_tmp);

    }
    GNUNET_CONTAINER_multihashmap_destroy (ego_tmp->attr_map);
    ego_entry = ego_entry->next;
    GNUNET_free (ego_tmp);
  }
}

/**
 * Shutdown task
 *
 * @param cls NULL
 * @param tc task context
 */
static void
do_shutdown (void *cls,
             const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "Shutting down...\n");
  cleanup();
}


static struct GNUNET_IDENTITY_PROVIDER_ExchangeResultMessage*
create_exchange_result_message (const char* token,
                                const char* label)
{
  struct GNUNET_IDENTITY_PROVIDER_ExchangeResultMessage *erm;
  uint16_t token_len = strlen (token) + 1;
  erm = GNUNET_malloc (sizeof (struct GNUNET_IDENTITY_PROVIDER_ExchangeResultMessage) 
                       + token_len);
  erm->header.type = htons (GNUNET_MESSAGE_TYPE_IDENTITY_PROVIDER_EXCHANGE_RESULT);
  erm->header.size = htons (sizeof (struct GNUNET_IDENTITY_PROVIDER_ExchangeResultMessage) 
                            + token_len);
  memcpy (&erm[1], token, token_len);
  return erm;
}


static struct GNUNET_IDENTITY_PROVIDER_IssueResultMessage*
create_issue_result_message (const char* ticket)
{
  struct GNUNET_IDENTITY_PROVIDER_IssueResultMessage *irm;

  irm = GNUNET_malloc (sizeof (struct GNUNET_IDENTITY_PROVIDER_IssueResultMessage) + strlen(ticket) + 1);
  irm->header.type = htons (GNUNET_MESSAGE_TYPE_IDENTITY_PROVIDER_ISSUE_RESULT);
  irm->header.size = htons (sizeof (struct GNUNET_IDENTITY_PROVIDER_IssueResultMessage) + strlen (ticket) + 1);
  memcpy (&irm[1], ticket, strlen (ticket) + 1);
  return irm;
}

void
store_token_issue_cont (void *cls,
                        int32_t success,
                        const char *emsg)
{
  struct IssueHandle *handle = cls;
  struct GNUNET_IDENTITY_PROVIDER_IssueResultMessage *irm;
  char* token_ticket_str;
  handle->ns_qe = NULL;
  if (GNUNET_SYSERR == success)
  {
    //TODO err msg
    return;
  }
  if (GNUNET_OK != ticket_serialize (handle->ticket,
                                     &handle->iss_key,
                                     &token_ticket_str))
  {
    GNUNET_CONTAINER_multihashmap_destroy (handle->attr_map);
    ticket_destroy (handle->ticket);
    GNUNET_free (handle);
    GNUNET_SCHEDULER_add_now (&do_shutdown, NULL); 
    return;
  }
  irm = create_issue_result_message (token_ticket_str);
  GNUNET_SERVER_notification_context_unicast (nc,
                                              handle->client,
                                              &irm->header,
                                              GNUNET_NO);
  GNUNET_free (irm);
  GNUNET_free (token_ticket_str);
  GNUNET_SERVER_receive_done (handle->client, GNUNET_OK);
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
  struct GNUNET_CRYPTO_EcdsaPublicKey pub_key;
  struct GNUNET_CRYPTO_EcdsaPublicKey aud_pkey;
  struct GNUNET_CRYPTO_EcdhePrivateKey *ecdhe_privkey;
  struct IssueHandle *handle = cls;
  struct GNUNET_GNSRECORD_Data token_record[2];
  struct GNUNET_TIME_Relative etime_rel;
  char *lbl_str;
  char *nonce_str;
  char *enc_token_str;
  char *token_metadata;
  char* write_ptr;
  uint64_t time;
  uint64_t exp_time;
  uint64_t rnd_key;
  size_t token_metadata_len;

  //Remote nonce 
  nonce_str = NULL;
  GNUNET_asprintf (&nonce_str, "%d", handle->nonce);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Request nonce: %s\n", nonce_str);

  //Label
  rnd_key = GNUNET_CRYPTO_random_u64 (GNUNET_CRYPTO_QUALITY_STRONG, UINT64_MAX);
  GNUNET_STRINGS_base64_encode ((char*)&rnd_key, sizeof (uint64_t), &lbl_str);
  GNUNET_CRYPTO_ecdsa_key_get_public (&handle->iss_key,
                                      &pub_key);

  handle->ticket = ticket_create (nonce_str,
                                  &pub_key,
                                  lbl_str,
                                  &aud_pkey);



  if (GNUNET_OK !=
      GNUNET_STRINGS_fancy_time_to_relative ("1d", //TODO
                                             &etime_rel))
  {
    ticket_destroy (handle->ticket);
    GNUNET_free (handle);
    GNUNET_SCHEDULER_add_now (&do_shutdown, handle);
    return;
  }
  time = GNUNET_TIME_absolute_get().abs_value_us;
  exp_time = time + etime_rel.rel_value_us;

  token_add_json (handle->token, "nbf", json_integer (time));
  token_add_json (handle->token, "iat", json_integer (time));
  token_add_json (handle->token, "exp", json_integer (exp_time));
  token_add_attr (handle->token, "nonce", nonce_str);


  //Token in a serialized encrypted format 
  GNUNET_assert (token_serialize (handle->token,
                                  &handle->iss_key,
                                  &ecdhe_privkey,
                                  &enc_token_str));

  //Token record E,E_K (Token)
  token_record[0].data = enc_token_str;
  token_record[0].data_size = strlen (enc_token_str) + 1;
  token_record[0].expiration_time = exp_time;
  token_record[0].record_type = GNUNET_GNSRECORD_TYPE_ID_TOKEN;
  token_record[0].flags = GNUNET_GNSRECORD_RF_NONE;


  token_metadata_len = sizeof (struct GNUNET_CRYPTO_EcdhePrivateKey)
    + sizeof (struct GNUNET_CRYPTO_EcdsaPublicKey)
    + strlen (handle->scopes) + 1; //With 0-Terminator
  token_metadata = GNUNET_malloc (token_metadata_len);
  write_ptr = token_metadata;
  memcpy (token_metadata, ecdhe_privkey, sizeof (struct GNUNET_CRYPTO_EcdhePrivateKey));
  write_ptr += sizeof (struct GNUNET_CRYPTO_EcdhePrivateKey);
  memcpy (write_ptr, &handle->aud_key, sizeof (struct GNUNET_CRYPTO_EcdsaPublicKey));
  write_ptr += sizeof (struct GNUNET_CRYPTO_EcdsaPublicKey);
  memcpy (write_ptr, handle->scopes, strlen (handle->scopes) + 1); //with 0-Terminator;

  GNUNET_free (ecdhe_privkey);

  token_record[1].data = token_metadata;
  token_record[1].data_size = token_metadata_len;
  token_record[1].expiration_time = exp_time;
  token_record[1].record_type = GNUNET_GNSRECORD_TYPE_ID_TOKEN_METADATA;
  token_record[1].flags = GNUNET_GNSRECORD_RF_PRIVATE;

  //Persist token
  handle->ns_qe = GNUNET_NAMESTORE_records_store (ns_handle,
                                                  &handle->iss_key,
                                                  lbl_str,
                                                  2,
                                                  token_record,
                                                  &store_token_issue_cont,
                                                  handle);
  GNUNET_free (lbl_str);
  GNUNET_free (enc_token_str);
}

/**
 * Collect attributes for token
 */
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
  struct IssueHandle *handle = cls;
  struct GNUNET_HashCode key;

  if (NULL == label)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Adding attribute END: \n");
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

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Adding attribute: %s\n", label);

  if (1 == rd_count)
  {
    if (rd->record_type == GNUNET_GNSRECORD_TYPE_ID_ATTR)
    {
      data = GNUNET_GNSRECORD_value_to_string (rd->record_type,
                                               rd->data,
                                               rd->data_size);
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Adding value: %s\n", data);
      token_add_json (handle->token,
                      label,
                      json_string (data));
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
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Adding value: %s\n", data);
      json_array_append_new (attr_arr, json_string (data));
      GNUNET_free (data);
    }
  }

  if (0 < json_array_size (attr_arr))
  {
    token_add_json (handle->token, label, attr_arr);
  }
  json_decref (attr_arr);
  GNUNET_NAMESTORE_zone_iterator_next (handle->ns_it);
}

static void
process_lookup_result (void *cls, uint32_t rd_count,
                       const struct GNUNET_GNSRECORD_Data *rd)
{
  struct ExchangeHandle *handle = cls;
  struct GNUNET_IDENTITY_PROVIDER_ExchangeResultMessage *erm;
  char* token_str;
  char* record_str;

  handle->lookup_request = NULL;
  if (2 != rd_count)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Number of tokens %d != 2.",
                rd_count);
    GNUNET_free (handle->label);
    GNUNET_free (handle);
    GNUNET_SCHEDULER_add_now (&do_shutdown, handle);
    return;
  }

  record_str = 
    GNUNET_GNSRECORD_value_to_string (GNUNET_GNSRECORD_TYPE_ID_TOKEN,
                                      rd->data,
                                      rd->data_size);

  //Decrypt and parse
  GNUNET_assert (GNUNET_OK ==  token_parse (record_str,
                                            &handle->aud_privkey,
                                            &handle->token));

  //Readable
  GNUNET_assert (GNUNET_OK == token_to_string (handle->token,
                                               &handle->aud_privkey,
                                               &token_str));

  erm = create_exchange_result_message (token_str,
                                        handle->label);
  GNUNET_SERVER_notification_context_unicast (nc,
                                              handle->client,
                                              &erm->header,
                                              GNUNET_NO);
  GNUNET_free (erm);
  GNUNET_SERVER_receive_done (handle->client, GNUNET_OK);

}

/**
 *
 * Handler for exchange message
 *
 * @param cls unused
 * @param client who sent the message
 * @param message the message
 */
static void
handle_exchange_message (void *cls,
                         struct GNUNET_SERVER_Client *client,
                         const struct GNUNET_MessageHeader *message)
{
  const struct GNUNET_IDENTITY_PROVIDER_ExchangeMessage *em;
  struct ExchangeHandle *xchange_handle;
  uint16_t size;
  const char *ticket;
  char *lookup_query;

  size = ntohs (message->size);
  if (size <= sizeof (struct GNUNET_IDENTITY_PROVIDER_ExchangeMessage))
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  em = (const struct GNUNET_IDENTITY_PROVIDER_ExchangeMessage *) message;
  ticket = (const char *) &em[1];
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received EXCHANGE of `%s' from client\n",
              ticket);
  xchange_handle = GNUNET_malloc (sizeof (struct ExchangeHandle));
  xchange_handle->aud_privkey = em->aud_privkey;
  if (GNUNET_SYSERR == ticket_parse (ticket,
                                     &xchange_handle->aud_privkey,
                                     &xchange_handle->ticket))
  {
    GNUNET_free (xchange_handle);
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Looking for token under %s\n",
              xchange_handle->ticket->payload->label);
  GNUNET_asprintf (&lookup_query,
                   "%s.gnu",
                   xchange_handle->ticket->payload->label);
  xchange_handle->lookup_request = GNUNET_GNS_lookup (gns_handle,
                                                      lookup_query,
                                                      &xchange_handle->ticket->payload->identity_key,
                                                      GNUNET_GNSRECORD_TYPE_ID_TOKEN,
                                                      GNUNET_GNS_LO_LOCAL_MASTER,
                                                      NULL,
                                                      &process_lookup_result,
                                                      xchange_handle);
  GNUNET_free (lookup_query);

}

/**
 *
 * Handler for issue message
 *
 * @param cls unused
 * @param client who sent the message
 * @param message the message
 */
static void
handle_issue_message (void *cls,
                      struct GNUNET_SERVER_Client *client,
                      const struct GNUNET_MessageHeader *message)
{
  const struct GNUNET_IDENTITY_PROVIDER_IssueMessage *im;
  uint16_t size;
  const char *scopes;
  char *scopes_tmp;
  char *scope;
  struct GNUNET_HashCode key;
  struct IssueHandle *issue_handle;

  size = ntohs (message->size);
  if (size <= sizeof (struct GNUNET_IDENTITY_PROVIDER_IssueMessage))
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  im = (const struct GNUNET_IDENTITY_PROVIDER_IssueMessage *) message;
  scopes = (const char *) &im[1];
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received ISSUE of `%s' from client\n",
              scope);
  issue_handle = GNUNET_malloc (sizeof (struct IssueHandle));
  issue_handle->attr_map = GNUNET_CONTAINER_multihashmap_create (5,
                                                                 GNUNET_NO);
  scopes_tmp = GNUNET_strdup (scopes);
  scope = strtok(scopes_tmp, ",");
  for (; NULL != scope; scope = strtok (NULL, ","))
  {
    GNUNET_CRYPTO_hash (scope,
                        strlen (scope),
                        &key);
    GNUNET_CONTAINER_multihashmap_put (issue_handle->attr_map,
                                       &key,
                                       scope,
                                       GNUNET_CONTAINER_MULTIHASHMAPOPTION_REPLACE);
  }
  GNUNET_free (scopes_tmp);

  issue_handle->aud_key = im->aud_key;
  issue_handle->iss_key = im->iss_key;
  issue_handle->expiration = GNUNET_TIME_absolute_ntoh (im->expiration);
  issue_handle->nonce = im->nonce;
  GNUNET_CRYPTO_ecdsa_key_get_public (&im->iss_key,
                                      &issue_handle->iss_pkey);
  issue_handle->token = token_create (&issue_handle->iss_pkey,
                                      &im->aud_key);

  issue_handle->ns_it = GNUNET_NAMESTORE_zone_iteration_start (ns_handle,
                                                               &im->iss_key,
                                                               &attr_collect,
                                                               issue_handle);
  GNUNET_SERVER_receive_done (client, GNUNET_OK); //TODO here?


}

/**
 * Main function that will be run
 *
 * @param cls closure
 * @param args remaining command-line arguments
 * @param cfgfile name of the configuration file used (for saving, can be NULL)
 * @param c configuration
 */
static void
run (void *cls, 
     struct GNUNET_SERVER_Handle *server,
     const struct GNUNET_CONFIGURATION_Handle *c)
{
  static const struct GNUNET_SERVER_MessageHandler handlers[] = {
    {&handle_issue_message, NULL,
      GNUNET_MESSAGE_TYPE_IDENTITY_PROVIDER_ISSUE, 0},
    {&handle_exchange_message, NULL,
      GNUNET_MESSAGE_TYPE_IDENTITY_PROVIDER_EXCHANGE, 0},
    {NULL, NULL, 0, 0}
  };

  cfg = c;

  stats = GNUNET_STATISTICS_create ("identity-provider", cfg);
  GNUNET_SERVER_add_handlers (server, handlers);
  nc = GNUNET_SERVER_notification_context_create (server, 1);

  //Connect to identity and namestore services
  ns_handle = GNUNET_NAMESTORE_connect (cfg);
  if (NULL == ns_handle)
  {
    GNUNET_log_strerror (GNUNET_ERROR_TYPE_ERROR, "error connecting to namestore");
  }

  gns_handle = GNUNET_GNS_connect (cfg);
  if (NULL == gns_handle)
  {
    GNUNET_log_strerror (GNUNET_ERROR_TYPE_ERROR, "error connecting to gns");
  }

  identity_handle = GNUNET_IDENTITY_connect (cfg,
                                             &list_ego,
                                             NULL);

  GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_FOREVER_REL,
                                &do_shutdown, NULL);
}


/**
 *
 * The main function
 *
 * @param argc number of arguments from the cli
 * @param argv command line arguments
 * @return 0 ok, 1 on error
 *
 */
int
main (int argc, char *const *argv)
{
  return  (GNUNET_OK ==
           GNUNET_SERVICE_run (argc, argv, "identity-provider",
                               GNUNET_SERVICE_OPTION_NONE,
                               &run, NULL)) ? 0 : 1;
}

/* end of gnunet-rest-server.c */

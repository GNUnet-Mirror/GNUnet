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
 * @file src/identity-provider/gnunet-service-identity-provider.c
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
 * Standard token expiration time
 */
#define DEFAULT_TOKEN_EXPIRATION_INTERVAL GNUNET_TIME_UNIT_HOURS

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
 * Token expiration interval
 */
static struct GNUNET_TIME_Relative token_expiration_interval;

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

/**
 * Our configuration.
 */
static const struct GNUNET_CONFIGURATION_Handle *cfg;


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

  /**
   * The label the token is stored under
   */
  char *label;
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
  struct TokenAttr *cur_value;
  struct TokenAttr *attr;
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

  for (attr = token->attr_head; NULL != attr; attr = attr->next)
  {
    if (0 == strcmp (attr->name, "exp"))
    {
      sscanf (attr->val_head->value,
              "%lu",
              &token_exp.abs_value_us);
    } else if (0 == strcmp (attr->name, "nbf")) {
      sscanf (attr->val_head->value,
              "%lu",
              &token_nbf.abs_value_us);
    }
  }
  token_rel_exp = GNUNET_TIME_absolute_get_difference (token_nbf, token_exp);

  token_ttl = GNUNET_TIME_absolute_get_remaining (token_exp);
  if (0 != GNUNET_TIME_absolute_get_remaining (token_exp).rel_value_us)
  {
    //This token is not yet expired! Save and skip
    if (min_rel_exp.rel_value_us > token_ttl.rel_value_us)
    {
      min_rel_exp = token_ttl;
    }
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
  for (attr = token->attr_head; NULL != attr; attr = attr->next)
  {
    if (0 == strcmp (attr->name, "exp"))
    {
      token_add_attr_int (new_token, attr->name, new_exp.abs_value_us);
    }
    else if (0 == strcmp (attr->name, "nbf"))
    {
      token_add_attr_int (new_token, attr->name, new_nbf.abs_value_us);
    }
    else if (0 == strcmp (attr->name, "iat"))
    {
      token_add_attr_int (new_token, attr->name, new_iat.abs_value_us);
    }
    else if ((0 == strcmp (attr->name, "iss"))
             || (0 == strcmp (attr->name, "aud")))
    {
      //Omit
    }
    else if (0 == strcmp (attr->name, "sub"))
    {
      token_add_attr (new_token,
                      attr->name,
                      attr->val_head->value);
    }
    else 
    {
      GNUNET_CRYPTO_hash (attr->name,
                          strlen (attr->name),
                          &key_hash);
      //Check if attr still exists. omit of not
      if (GNUNET_NO != 
          GNUNET_CONTAINER_multihashmap_contains (ego_entry->attr_map,
                                                  &key_hash))
      {
        cur_value = GNUNET_CONTAINER_multihashmap_get (ego_entry->attr_map,
                                                       &key_hash);
        GNUNET_CONTAINER_DLL_insert (new_token->attr_head,
                                     new_token->attr_tail,
                                     cur_value);
      }
    }
  }

  // reassemble and set
  GNUNET_assert (token_serialize (new_token,
                                  priv_key,
                                  &new_ecdhe_privkey,
                                  &enc_token_str));

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
  struct TokenAttr *attr = value;
  struct TokenAttrValue *val;
  struct TokenAttrValue *tmp_val;
  for (val = attr->val_head; NULL != val;)
  {
    tmp_val = val->next;
    GNUNET_CONTAINER_DLL_remove (attr->val_head,
                                 attr->val_tail,
                                 val);
    GNUNET_free (val->value);
    GNUNET_free (val);
    val = tmp_val;
  }
  GNUNET_free (attr->name);
  GNUNET_free (attr);

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
    update_task = GNUNET_SCHEDULER_add_now (&update_identities,
                                            ego_entry->next);
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
  if (token_metadata_record->record_type != GNUNET_GNSRECORD_TYPE_ID_TOKEN_METADATA)
  {
    GNUNET_NAMESTORE_zone_iterator_next (ns_it);
    return;
  }
  if (token_record->record_type == GNUNET_GNSRECORD_TYPE_ID_TOKEN)
  {
    GNUNET_NAMESTORE_zone_iterator_next (ns_it);
    return;
  }

  //Get metadata and decrypt token
  ecdhe_privkey = *((struct GNUNET_CRYPTO_EcdhePrivateKey *)token_metadata_record->data);
  aud_key = (struct GNUNET_CRYPTO_EcdsaPublicKey *)&ecdhe_privkey+sizeof(struct GNUNET_CRYPTO_EcdhePrivateKey);
  scopes = GNUNET_strdup ((char*) aud_key+sizeof (struct GNUNET_CRYPTO_EcdsaPublicKey));

  token_parse2 (token_record->data,
                &ecdhe_privkey,
                aud_key,
                &token);

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
  struct GNUNET_HashCode key;
  struct TokenAttr *attr;
  struct TokenAttrValue *val;
  char *val_str;
  int i;

  if (NULL == lbl)
  {
    //Done
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                ">>> Updating Attributes finished\n");
    ego_entry->attributes_dirty = GNUNET_NO;
    update_task = GNUNET_SCHEDULER_add_now (&update_identities, ego_entry);
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
      val_str = GNUNET_GNSRECORD_value_to_string (rd->record_type,
                                              rd->data,
                                              rd->data_size);
      attr = GNUNET_malloc (sizeof (struct TokenAttr));
      attr->name = GNUNET_strdup (lbl);
      val = GNUNET_malloc (sizeof (struct TokenAttrValue));
      val->value = val_str;
      GNUNET_CONTAINER_DLL_insert (attr->val_head,
                                   attr->val_tail,
                                   val);
      GNUNET_CONTAINER_multihashmap_put (ego_entry->attr_map,
                                         &key,
                                         attr,
                                         GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY);
    }

    GNUNET_NAMESTORE_zone_iterator_next (ns_it);
    return;
  }

  attr = GNUNET_malloc (sizeof (struct TokenAttr));
  attr->name = GNUNET_strdup (lbl);
  for (i = 0; i < rd_count; i++)
  {
    if (rd[i].record_type == GNUNET_GNSRECORD_TYPE_ID_ATTR)
    {
      val_str = GNUNET_GNSRECORD_value_to_string (rd[i].record_type,
                                                  rd[i].data,
                                                  rd[i].data_size);
      val = GNUNET_malloc (sizeof (struct TokenAttrValue));
      val->value = val_str;
      GNUNET_CONTAINER_DLL_insert (attr->val_head,
                                   attr->val_tail,
                                   val);
    }
  }
  GNUNET_CONTAINER_multihashmap_put (ego_entry->attr_map,
                                     &key,
                                     attr,
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
  update_task = NULL;
  if (NULL == next_ego)
  {
    if (min_rel_exp.rel_value_us < MIN_WAIT_TIME.rel_value_us)
      min_rel_exp = MIN_WAIT_TIME;
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                ">>> Finished. Rescheduling in %d\n",
                min_rel_exp.rel_value_us);
    ns_it = NULL;
    //finished -> reschedule
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
create_issue_result_message (const char* label,
                             const char* ticket,
                             const char* token)
{
  struct GNUNET_IDENTITY_PROVIDER_IssueResultMessage *irm;
  char *tmp_str;

  irm = GNUNET_malloc (sizeof (struct GNUNET_IDENTITY_PROVIDER_IssueResultMessage) 
                       + strlen (label) + 1
                       + strlen (ticket) + 1
                       + strlen (token) + 1);
  irm->header.type = htons (GNUNET_MESSAGE_TYPE_IDENTITY_PROVIDER_ISSUE_RESULT);
  irm->header.size = htons (sizeof (struct GNUNET_IDENTITY_PROVIDER_IssueResultMessage) 
                            + strlen (label) + 1
                            + strlen (ticket) + 1
                            + strlen (token) + 1);
  GNUNET_asprintf (&tmp_str, "%s,%s,%s", label, ticket, token);
  memcpy (&irm[1], tmp_str, strlen (tmp_str) + 1);
  GNUNET_free (tmp_str);
  return irm;
}

static void
cleanup_issue_handle (struct IssueHandle *handle)
{
  if (NULL != handle->attr_map)
    GNUNET_CONTAINER_multihashmap_destroy (handle->attr_map);
  if (NULL != handle->scopes)
    GNUNET_free (handle->scopes);
  if (NULL != handle->token)
   token_destroy (handle->token);
  if (NULL != handle->ticket)
    ticket_destroy (handle->ticket);
  if (NULL != handle->label)
    GNUNET_free (handle->label);
  GNUNET_free (handle);
}

static void
store_token_issue_cont (void *cls,
                        int32_t success,
                        const char *emsg)
{
  struct IssueHandle *handle = cls;
  struct GNUNET_IDENTITY_PROVIDER_IssueResultMessage *irm;
  char *ticket_str;
  char *token_str;
  handle->ns_qe = NULL;
  if (GNUNET_SYSERR == success)
  {
    cleanup_issue_handle (handle);
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "%s\n",
                "Unknown Error\n");
    GNUNET_SCHEDULER_add_now (&do_shutdown, NULL);
    return;
  }
  if (GNUNET_OK != ticket_serialize (handle->ticket,
                                     &handle->iss_key,
                                     &ticket_str))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "%s\n",
                "Error serializing ticket\n");
    cleanup_issue_handle (handle);
    GNUNET_SCHEDULER_add_now (&do_shutdown, NULL); 
    return;
  }
  if (GNUNET_OK != token_to_string (handle->token,
                                    &handle->iss_key,
                                    &token_str))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "%s\n",
                "Error serializing token\n");
    GNUNET_free (ticket_str);
    cleanup_issue_handle (handle);
    GNUNET_SCHEDULER_add_now (&do_shutdown, NULL); 
    return;
  }
  irm = create_issue_result_message (handle->label, ticket_str, token_str);
  GNUNET_SERVER_notification_context_unicast (nc,
                                              handle->client,
                                              &irm->header,
                                              GNUNET_NO);
  GNUNET_SERVER_client_set_user_context (handle->client, NULL);
  cleanup_issue_handle (handle);
  GNUNET_free (irm);
  GNUNET_free (ticket_str);
  GNUNET_free (token_str);
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
  struct GNUNET_CRYPTO_EcdhePrivateKey *ecdhe_privkey;
  struct IssueHandle *handle = cls;
  struct GNUNET_GNSRECORD_Data token_record[2];
  char *nonce_str;
  char *enc_token_str;
  char *token_metadata;
  char* write_ptr;
  uint64_t time;
  uint64_t exp_time;
  size_t token_metadata_len;

  //Remote nonce 
  nonce_str = NULL;
  GNUNET_asprintf (&nonce_str, "%d", handle->nonce);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Request nonce: %s\n", nonce_str);

  GNUNET_CRYPTO_ecdsa_key_get_public (&handle->iss_key,
                                      &pub_key);
  handle->ticket = ticket_create (nonce_str,
                                  &pub_key,
                                  handle->label,
                                  &handle->aud_key);

  time = GNUNET_TIME_absolute_get().abs_value_us;
  exp_time = time + token_expiration_interval.rel_value_us;

  token_add_attr_int (handle->token, "nbf", time);
  token_add_attr_int (handle->token, "iat", time);
  token_add_attr_int (handle->token, "exp", exp_time);
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

  token_record[1].data = token_metadata;
  token_record[1].data_size = token_metadata_len;
  token_record[1].expiration_time = exp_time;
  token_record[1].record_type = GNUNET_GNSRECORD_TYPE_ID_TOKEN_METADATA;
  token_record[1].flags = GNUNET_GNSRECORD_RF_PRIVATE;

  //Persist token
  handle->ns_qe = GNUNET_NAMESTORE_records_store (ns_handle,
                                                  &handle->iss_key,
                                                  handle->label,
                                                  2,
                                                  token_record,
                                                  &store_token_issue_cont,
                                                  handle);
  GNUNET_free (ecdhe_privkey);
  GNUNET_free (nonce_str);
  GNUNET_free (enc_token_str);
  GNUNET_free (token_metadata);
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
      token_add_attr (handle->token,
                      label,
                      data);
      GNUNET_free (data);
    }
    GNUNET_NAMESTORE_zone_iterator_next (handle->ns_it);
    return;
  }

  i = 0;
  for (; i < rd_count; i++)
  {
    if (rd->record_type == GNUNET_GNSRECORD_TYPE_ID_ATTR)
    {
      data = GNUNET_GNSRECORD_value_to_string (rd[i].record_type,
                                               rd[i].data,
                                               rd[i].data_size);
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Adding value: %s\n", data);
      token_add_attr (handle->token, label, data);
      GNUNET_free (data);
    }
  }

  GNUNET_NAMESTORE_zone_iterator_next (handle->ns_it);
}

static void
cleanup_exchange_handle (struct ExchangeHandle *handle)
{
  if (NULL != handle->ticket) 
    ticket_destroy (handle->ticket);
  if (NULL != handle->token)
    token_destroy (handle->token);
  GNUNET_free (handle);
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
    cleanup_exchange_handle (handle);
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
  GNUNET_SERVER_client_set_user_context (handle->client, NULL);

  cleanup_exchange_handle (handle);
  GNUNET_free (record_str);
  GNUNET_free (token_str);
  GNUNET_free (erm);

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
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Looking for token under %s\n",
              xchange_handle->ticket->payload->label);
  GNUNET_asprintf (&lookup_query,
                   "%s.gnu",
                   xchange_handle->ticket->payload->label);
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
  GNUNET_SERVER_notification_context_add (nc, client);
  GNUNET_SERVER_client_set_user_context (client, xchange_handle);
  xchange_handle->client = client;
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
 * Look for existing token
 *
 * @param cls the identity entry
 * @param zone the identity
 * @param lbl the name of the record
 * @param rd_count number of records
 * @param rd record data
 *
 */
static void
find_existing_token (void *cls,
                     const struct GNUNET_CRYPTO_EcdsaPrivateKey *zone,
                     const char *lbl,
                     unsigned int rd_count,
                     const struct GNUNET_GNSRECORD_Data *rd)
{
  struct IssueHandle *handle = cls;
  const struct GNUNET_GNSRECORD_Data *token_metadata_record;
  struct GNUNET_CRYPTO_EcdsaPublicKey *aud_key;
  struct GNUNET_HashCode key;
  int scope_count_token;
  uint64_t rnd_key;
  char *scope;
  char *tmp_scopes;

  if (NULL == lbl)
  {
    //Done
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                ">>> No existing token found\n");
    //Label
    rnd_key = 
      GNUNET_CRYPTO_random_u64 (GNUNET_CRYPTO_QUALITY_STRONG,
                                UINT64_MAX);
    GNUNET_STRINGS_base64_encode ((char*)&rnd_key,
                                  sizeof (uint64_t),
                                  &handle->label);
    handle->ns_it = NULL;
    handle->ns_it = GNUNET_NAMESTORE_zone_iteration_start (ns_handle,
                                                           &handle->iss_key,
                                                           &attr_collect,
                                                           handle);
    return; 
  }

  //There should be only a single record for a token under a label
  if (2 != rd_count)
  {
    GNUNET_NAMESTORE_zone_iterator_next (handle->ns_it);
    return;
  }

  if (rd[0].record_type == GNUNET_GNSRECORD_TYPE_ID_TOKEN_METADATA)
  {
    token_metadata_record = &rd[0];
  } else {
    token_metadata_record = &rd[1];
  }
  if (token_metadata_record->record_type != GNUNET_GNSRECORD_TYPE_ID_TOKEN_METADATA)
  {
    GNUNET_NAMESTORE_zone_iterator_next (handle->ns_it);
    return;
  }
  ecdhe_privkey = *((struct GNUNET_CRYPTO_EcdhePrivateKey *)token_metadata_record->data);
  aud_key = 
    (struct GNUNET_CRYPTO_EcdsaPublicKey *)(token_metadata_record->data+sizeof(struct GNUNET_CRYPTO_EcdhePrivateKey));
  tmp_scopes = GNUNET_strdup ((char*) aud_key+sizeof (struct GNUNET_CRYPTO_EcdsaPublicKey));

  if (0 != memcmp (aud_key, &handle->aud_key,
                   sizeof (struct GNUNET_CRYPTO_EcdsaPublicKey)))
  {
    char *tmp2 = GNUNET_STRINGS_data_to_string_alloc (aud_key,
                                                      sizeof (struct GNUNET_CRYPTO_EcdsaPublicKey));
    //Audience does not match!
    char *tmp = GNUNET_GNSRECORD_value_to_string (GNUNET_GNSRECORD_TYPE_ID_TOKEN_METADATA,
                                                  token_metadata_record->data,
                                                  token_metadata_record->data_size);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Token does not match audience %s vs %s. Moving on\n",
                tmp2,
                tmp);
    GNUNET_free (tmp_scopes);
    GNUNET_NAMESTORE_zone_iterator_next (handle->ns_it);
    return;
  }

  scope = strtok (tmp_scopes, ",");
  scope_count_token = 0;
  while (NULL != scope)
  {
    GNUNET_CRYPTO_hash (scope,
                        strlen (scope),
                        &key);

    if ((NULL != handle->attr_map) &&
        (GNUNET_YES != GNUNET_CONTAINER_multihashmap_contains (handle->attr_map, &key)))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Issued token does not include `%s'. Moving on\n", scope);
      GNUNET_free (tmp_scopes);
      GNUNET_NAMESTORE_zone_iterator_next (handle->ns_it);
      return;
    }
    scope_count_token++;
    scope = strtok (NULL, ",");
  }
  GNUNET_free (tmp_scopes);
  //All scopes in token are also in request. Now
  //Check length
  if (GNUNET_CONTAINER_multihashmap_size (handle->attr_map) == scope_count_token)
  {
    //We have an existing token
    handle->label = GNUNET_strdup (lbl);
    handle->ns_it = NULL;
    handle->ns_it = GNUNET_NAMESTORE_zone_iteration_start (ns_handle,
                                                           &handle->iss_key,
                                                           &attr_collect,
                                                           handle);

    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
              "Nuber of attributes in token do not match request\n");
  //No luck
  GNUNET_NAMESTORE_zone_iterator_next (handle->ns_it);
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
  const char *scopes;

  uint16_t size;
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
  GNUNET_CRYPTO_ecdsa_key_get_public (&im->iss_key,
                                      &issue_handle->iss_pkey);
  issue_handle->expiration = GNUNET_TIME_absolute_ntoh (im->expiration);
  issue_handle->nonce = ntohl (im->nonce);
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
  GNUNET_SERVER_notification_context_add (nc, client);
  GNUNET_SERVER_client_set_user_context (client, issue_handle);
  issue_handle->client = client;
  issue_handle->scopes = GNUNET_strdup (scopes);
  issue_handle->token = token_create (&issue_handle->iss_pkey,
                                      &issue_handle->aud_key);

  issue_handle->ns_it = GNUNET_NAMESTORE_zone_iteration_start (ns_handle,
                                                               &im->iss_key,
                                                               &find_existing_token,
                                                               issue_handle);
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

  if (GNUNET_OK == 
      GNUNET_CONFIGURATION_get_value_time (cfg,
                                           "identity-provider",
                                           "TOKEN_EXPIRATION_INTERVAL",
                                           &token_expiration_interval))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Time window for zone iteration: %s\n",
                GNUNET_STRINGS_relative_time_to_string (token_expiration_interval,
                                                        GNUNET_YES));
  } else {
    token_expiration_interval = DEFAULT_TOKEN_EXPIRATION_INTERVAL;
  }

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

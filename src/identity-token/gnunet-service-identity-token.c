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
 * @file src/rest/gnunet-service-identity-token.c
 * @brief Identity Token Service
 *
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_identity_service.h"
#include "gnunet_gnsrecord_lib.h"
#include "gnunet_namestore_service.h"
#include <jansson.h>
#include "gnunet_signatures.h"

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
static char* token;

/**
 * Label for currently processed token
 */
static char* label;

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
  char *token_header;
  char *token_payload;
  char *token_payload_json;
  char *new_token;
  char *new_payload_str;
  char *new_payload_base64;
  char *sig_str;
  char *key;
  char *padding;
  const struct GNUNET_CRYPTO_EcdsaPrivateKey *priv_key;
  struct EgoEntry *ego_entry = cls;
  struct GNUNET_GNSRECORD_Data token_record;
  struct GNUNET_CRYPTO_EccSignaturePurpose *purpose;
  struct GNUNET_CRYPTO_EcdsaSignature sig;
  struct GNUNET_HashCode key_hash;
  struct GNUNET_TIME_Relative token_rel_exp;
  struct GNUNET_TIME_Relative token_ttl;
  struct GNUNET_TIME_Absolute token_exp;
  struct GNUNET_TIME_Absolute token_nbf;
  struct GNUNET_TIME_Absolute new_exp;
  struct GNUNET_TIME_Absolute new_iat;
  struct GNUNET_TIME_Absolute new_nbf;
  json_t *payload_json;
  json_t *value;
  json_t *cur_value;
  json_t *new_payload_json;
  json_t *token_nbf_json;
  json_t *token_exp_json;
  json_error_t json_err;

  priv_key = GNUNET_IDENTITY_ego_get_private_key (ego_entry->ego);

  //Note: We need the token expiration time here. Not the record expiration
  //time.
  //There are two types of tokens: Token that expire on GNS level with
  //an absolute expiration time. Those are basically tokens that will
  //be automatically revoked on (record)expiration.
  //Tokens stored with relative expiration times will expire on the token level (token expiration)
  //but this service will reissue new tokens that can be retrieved from GNS
  //automatically.

  token_header = strtok (token, ".");

  token_payload = strtok (NULL, ".");

  GNUNET_STRINGS_base64_decode (token_payload,
                                strlen (token_payload),
                                &token_payload_json);

  payload_json = json_loads (token_payload_json, JSON_DECODE_ANY, &json_err);
  GNUNET_free (token_payload_json);

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
    GNUNET_NAMESTORE_zone_iterator_next (ns_it);
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Token is expired. Create a new one\n");
  new_exp = GNUNET_TIME_relative_to_absolute (token_rel_exp);
  new_nbf = GNUNET_TIME_absolute_get ();
  new_iat = new_nbf;
  new_payload_json = json_object();
  json_object_foreach(payload_json, key, value) {
    if (0 == strcmp (key, "exp"))
    {
      json_object_set_new (new_payload_json, key, json_integer (new_exp.abs_value_us));
    }
    else if (0 == strcmp (key, "nbf"))
    {
      json_object_set_new (new_payload_json, key, json_integer (new_nbf.abs_value_us));
    }
    else if (0 == strcmp (key, "iat"))
    {
      json_object_set_new (new_payload_json, key, json_integer (new_iat.abs_value_us));
    }
    else if ((0 == strcmp (key, "iss"))
             || (0 == strcmp (key, "aud"))
             || (0 == strcmp (key, "sub"))
             || (0 == strcmp (key, "rnl")))
    {
      json_object_set (new_payload_json, key, value);
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
        json_object_set (new_payload_json, key, cur_value);
      }
    }
  }

  // reassemble and set
  new_payload_str = json_dumps (new_payload_json, JSON_COMPACT);
  json_decref (payload_json);
  json_decref (new_payload_json);
  GNUNET_STRINGS_base64_encode (new_payload_str,
                                strlen (new_payload_str),
                                &new_payload_base64);
  //Remove padding
  padding = strtok(new_payload_base64, "=");
  while (NULL != padding)
    padding = strtok(NULL, "=");

  GNUNET_asprintf (&new_token, "%s,%s", token_header, new_payload_base64);
  purpose =
    GNUNET_malloc (sizeof (struct GNUNET_CRYPTO_EccSignaturePurpose) +
                   strlen (new_token));
  purpose->size =
    htonl (strlen (new_token) + sizeof (struct GNUNET_CRYPTO_EccSignaturePurpose));
  purpose->purpose = htonl(GNUNET_SIGNATURE_PURPOSE_GNUID_TOKEN);
  memcpy (&purpose[1], new_token, strlen (new_token));
  if (GNUNET_OK != GNUNET_CRYPTO_ecdsa_sign (priv_key,
                                             purpose,
                                             &sig))
    GNUNET_break(0);
  GNUNET_free (new_token);
  sig_str = GNUNET_STRINGS_data_to_string_alloc (&sig,
                                                 sizeof (struct GNUNET_CRYPTO_EcdsaSignature));
  GNUNET_asprintf (&new_token, "%s.%s.%s",
                   token_header, new_payload_base64, sig_str);
  GNUNET_free (sig_str);
  GNUNET_free (new_payload_str);
  GNUNET_free (new_payload_base64);
  GNUNET_free (purpose);

  token_record.data = new_token;
  token_record.data_size = strlen (new_token);
  token_record.expiration_time = new_exp.abs_value_us;
  token_record.record_type = GNUNET_GNSRECORD_TYPE_ID_TOKEN;
  token_record.flags = GNUNET_GNSRECORD_RF_NONE | GNUNET_GNSRECORD_RF_RELATIVE_EXPIRATION;
  ns_qe = GNUNET_NAMESTORE_records_store (ns_handle,
                                          priv_key,
                                          label,
                                          1,
                                          &token_record,
                                          &store_token_cont,
                                          ego_entry);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, ">>> Updating Token w/ %s\n", new_token);
  GNUNET_free (new_token);
  GNUNET_free (token);
  token = NULL;
  GNUNET_free (label);
  label = NULL;
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
  if ((1 != rd_count)
      || (rd->record_type != GNUNET_GNSRECORD_TYPE_ID_TOKEN)
      || (0 == (GNUNET_GNSRECORD_RF_RELATIVE_EXPIRATION & rd->flags)))
  {
    GNUNET_NAMESTORE_zone_iterator_next (ns_it);
    return;
  }
  token = GNUNET_GNSRECORD_value_to_string (rd->record_type,
                                            rd->data,
                                            rd->data_size);
  label = GNUNET_strdup (lbl); 

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
  if (NULL != timeout_task)
    GNUNET_SCHEDULER_cancel (timeout_task);
  if (NULL != update_task)
    GNUNET_SCHEDULER_cancel (update_task);
  if (NULL != identity_handle)
    GNUNET_IDENTITY_disconnect (identity_handle);
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
     char *const *args, 
     const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *c)
{
  cfg = c;


  //Connect to identity and namestore services
  ns_handle = GNUNET_NAMESTORE_connect (cfg);
  if (NULL == ns_handle)
  {
    GNUNET_log_strerror (GNUNET_ERROR_TYPE_ERROR, "error connecting to namestore");
  }

  identity_handle = GNUNET_IDENTITY_connect (cfg,
                                             &list_ego,
                                             NULL);

  GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_FOREVER_REL,
                                &do_shutdown, NULL);
}


/**
 *
 * The main function for gnunet-service-identity-token
 *
 * @param argc number of arguments from the cli
 * @param argv command line arguments
 * @return 0 ok, 1 on error
 *
 */
int
main (int argc, char *const *argv)
{
  static const struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_OPTION_END
  };
  int ret;

  if (GNUNET_OK != GNUNET_STRINGS_get_utf8_args (argc, argv, &argc, &argv))
    return 2;
  GNUNET_log_setup ("gnunet-service-identity-token", "WARNING", NULL);
  ret =
    (GNUNET_OK ==
     GNUNET_PROGRAM_run (argc, argv, "gnunet-service-identity-token",
                         _("GNUnet identity token service"),
                         options,
                         &run, NULL)) ? 0: 1;
  GNUNET_free_non_null ((char *) argv);
  return ret;
}

/* end of gnunet-rest-server.c */

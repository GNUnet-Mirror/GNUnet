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

#define STATE_INIT 0

#define STATE_POST_INIT 1

#define MIN_WAIT_TIME GNUNET_TIME_UNIT_MINUTES

static int state;

static struct EgoEntry *ego_head;

static struct EgoEntry *ego_tail;

static struct GNUNET_IDENTITY_Handle *identity_handle;

static struct GNUNET_NAMESTORE_Handle *ns_handle;

static struct GNUNET_NAMESTORE_QueueEntry *ns_qe;

static struct GNUNET_NAMESTORE_ZoneIterator *ns_it;

static struct GNUNET_SCHEDULER_Task * timeout_task;

static struct GNUNET_SCHEDULER_Task * update_task;

static struct GNUNET_TIME_Relative min_rel_exp;

static char* token;

static char* label;

struct EgoEntry
{
  struct EgoEntry *next;
  struct EgoEntry *prev;
  struct GNUNET_IDENTITY_Ego *ego;
};

/**
 * Our configuration.
 */
static const struct GNUNET_CONFIGURATION_Handle *cfg;

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
  GNUNET_log (GNUNET_ERROR_TYPE_ERROR, ">>> Next token\n");
  GNUNET_NAMESTORE_zone_iterator_next (ns_it);
}

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
  struct GNUNET_TIME_Relative token_rel_exp;
  struct GNUNET_TIME_Relative token_ttl;
  struct GNUNET_TIME_Absolute token_exp;
  struct GNUNET_TIME_Absolute token_nbf;
  struct GNUNET_TIME_Absolute new_exp;
  struct GNUNET_TIME_Absolute new_iat;
  struct GNUNET_TIME_Absolute new_nbf;
  json_t *payload_json;
  json_t *value;
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

  GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Payload: %s\n",
              token_payload_json);
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
  GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
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
    else {
      json_object_set (new_payload_json, key, value);
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
  GNUNET_log (GNUNET_ERROR_TYPE_ERROR, ">>> Updating Token w/ %s\n", new_token);
  GNUNET_free (new_token);
  GNUNET_free (token);
  token = NULL;
  GNUNET_free (label);
  label = NULL;
}

static void
update_identities(void *cls,
                  const struct GNUNET_SCHEDULER_TaskContext *tc);

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
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                ">>> Updating Ego finished\n");
    GNUNET_SCHEDULER_add_now (&update_identities, ego_entry->next);
    return;
  }

  //TODO autopurge expired tokens here if set in config
  GNUNET_log (GNUNET_ERROR_TYPE_ERROR, ">>> Found record\n");
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
  GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Got token: %s\n", token);

  GNUNET_SCHEDULER_add_now (&handle_token_update, ego_entry);
}



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
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, ">>> Finished. Rescheduling in %d\n", min_rel_exp.rel_value_us);
    ns_it = NULL;
    //finished -> TODO reschedule
    update_task = GNUNET_SCHEDULER_add_delayed (min_rel_exp,
                                  &update_identities,
                                  ego_head);
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_ERROR, ">>> Updating Ego\n");
  priv_key = GNUNET_IDENTITY_ego_get_private_key (next_ego->ego);
  ns_it = GNUNET_NAMESTORE_zone_iteration_start (ns_handle,
                                                 priv_key,
                                                 &token_collect,
                                                 next_ego);
}


/* ************************* Global helpers ********************* */

static void
init_cont ()
{
  GNUNET_log (GNUNET_ERROR_TYPE_ERROR, ">>> Starting Service\n");
  //Initially iterate all itenties and refresh all tokens
  update_task = GNUNET_SCHEDULER_add_now (&update_identities, ego_head);
}

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
    GNUNET_CONTAINER_DLL_insert_tail(ego_head, ego_tail, new_entry);
  }
}

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
    ego_entry = ego_entry->next;
    GNUNET_free (ego_tmp);
  }
}

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
    GNUNET_log_strerror (GNUNET_ERROR_TYPE_ERROR, "error connectin to namestore");
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

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
#include "gnunet_credential_service.h"
#include "gnunet_statistics_service.h"
#include "gnunet_gns_service.h"
#include "gnunet_signatures.h"
#include "identity_provider.h"
#include "identity_token.h"
#include <inttypes.h>

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
 * Credential handle
 */
static struct GNUNET_CREDENTIAL_Handle *credential_handle;

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
static struct GNUNET_SCHEDULER_Task *timeout_task;

/**
 * Update task
 */
static struct GNUNET_SCHEDULER_Task *update_task;


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
 * Handle to the statistics service.
 */
static struct GNUNET_STATISTICS_Handle *stats;

/**
 * Our configuration.
 */
static const struct GNUNET_CONFIGURATION_Handle *cfg;

struct VerifiedAttributeEntry
{
  /**
   * DLL
   */
  struct VerifiedAttributeEntry *prev;

  /**
   * DLL
   */
  struct VerifiedAttributeEntry *next;

  /**
   * Attribute Name
   */
  char* name;
};

struct ParallelLookups;

struct ExchangeHandle
{

  /**
   * Client connection
   */
  struct GNUNET_SERVICE_Client *client;

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
   * ParallelLookups DLL
   */
  struct ParallelLookup *parallel_lookups_head;
  struct ParallelLookup *parallel_lookups_tail;
  
  struct GNUNET_SCHEDULER_Task *kill_task;
  struct GNUNET_CRYPTO_AbeKey *key;

  /**
   * Label to return
   */
  char *label;

  /**
   * request id
   */
  uint32_t r_id;
};

struct ParallelLookup
{
  struct ParallelLookup *next;

  struct ParallelLookup *prev;

  struct GNUNET_GNS_LookupRequest *lookup_request;

  struct ExchangeHandle *handle;
};

struct IssueHandle
{

  /**
   * Client connection
   */
  struct GNUNET_SERVICE_Client *client;

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
   * The issuer egos ABE master key
   */
  struct GNUNET_CRYPTO_AbeMasterKey *abe_key;

  /**
   * Expiration
   */
  struct GNUNET_TIME_Absolute expiration;

  /**
   * Scopes
   */
  char *scopes;

  /**
   * DLL
   */
  struct VerifiedAttributeEntry *v_attr_head;

  /**
   * DLL
   */
  struct VerifiedAttributeEntry *v_attr_tail;

  /**
   * nonce
   */
  uint64_t nonce;

  /**
   * NS iterator
   */
  struct GNUNET_NAMESTORE_ZoneIterator *ns_it;

  /**
   * Cred request
   */
  struct GNUNET_CREDENTIAL_Request *credential_request;

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

  /**
   * request id
   */
  uint32_t r_id;
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

};

/**
 * Cleanup task
 */
static void
cleanup()
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Cleaning up\n");
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
  if (NULL != credential_handle)
    GNUNET_CREDENTIAL_disconnect (credential_handle);
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

}

/**
 * Shutdown task
 *
 * @param cls NULL
 * @param tc task context
 */
static void
do_shutdown (void *cls)
{
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "Shutting down...\n");
  cleanup();
}


static struct GNUNET_MQ_Envelope*
create_exchange_result_message (const char* token,
                                const char* label,
                                uint64_t ticket_nonce,
                                uint64_t id)
{
  struct GNUNET_MQ_Envelope *env;
  struct ExchangeResultMessage *erm;
  uint16_t token_len = strlen (token) + 1;

  env = GNUNET_MQ_msg_extra (erm,
                             token_len,
                             GNUNET_MESSAGE_TYPE_IDENTITY_PROVIDER_EXCHANGE_RESULT);
  erm->ticket_nonce = htonl (ticket_nonce);
  erm->id = id;
  GNUNET_memcpy (&erm[1], token, token_len);
  return env;
}


static struct GNUNET_MQ_Envelope*
create_issue_result_message (const char* label,
                             const char* ticket,
                             const char* token,
                             uint64_t id)
{
  struct GNUNET_MQ_Envelope *env;
  struct IssueResultMessage *irm;
  char *tmp_str;
  size_t len;

  GNUNET_asprintf (&tmp_str, "%s,%s,%s", label, ticket, token);
  len = strlen (tmp_str) + 1;
  env = GNUNET_MQ_msg_extra (irm,
                             len,
                             GNUNET_MESSAGE_TYPE_IDENTITY_PROVIDER_ISSUE_RESULT);
  irm->id = id;
  GNUNET_memcpy (&irm[1], tmp_str, strlen (tmp_str) + 1);
  GNUNET_free (tmp_str);
  return env;
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
  if (NULL != handle->ns_it)
    GNUNET_NAMESTORE_zone_iteration_stop (handle->ns_it);
  if (NULL != handle->credential_request)
    GNUNET_CREDENTIAL_request_cancel (handle->credential_request);
  GNUNET_free (handle);
}

static void
store_record_issue_cont (void *cls,
                        int32_t success,
                        const char *emsg)
{
  struct IssueHandle *handle = cls;
  struct GNUNET_MQ_Envelope *env;
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
  env = create_issue_result_message (handle->label,
                                     ticket_str,
                                     token_str,
                                     handle->r_id);
  GNUNET_MQ_send (GNUNET_SERVICE_client_get_mq(handle->client),
                  env);
  cleanup_issue_handle (handle);
  GNUNET_free (ticket_str);
  GNUNET_free (token_str);
}

static int
create_sym_key_from_ecdh(const struct GNUNET_HashCode *new_key_hash,
                         struct GNUNET_CRYPTO_SymmetricSessionKey *skey,
                         struct GNUNET_CRYPTO_SymmetricInitializationVector *iv)
{
  struct GNUNET_CRYPTO_HashAsciiEncoded new_key_hash_str;

  GNUNET_CRYPTO_hash_to_enc (new_key_hash,
                             &new_key_hash_str);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Creating symmetric rsa key from %s\n", (char*)&new_key_hash_str);
  static const char ctx_key[] = "gnuid-aes-ctx-key";
  GNUNET_CRYPTO_kdf (skey, sizeof (struct GNUNET_CRYPTO_SymmetricSessionKey),
                     new_key_hash, sizeof (struct GNUNET_HashCode),
                     ctx_key, strlen (ctx_key),
                     NULL, 0);
  static const char ctx_iv[] = "gnuid-aes-ctx-iv";
  GNUNET_CRYPTO_kdf (iv, sizeof (struct GNUNET_CRYPTO_SymmetricInitializationVector),
                     new_key_hash, sizeof (struct GNUNET_HashCode),
                     ctx_iv, strlen (ctx_iv),
                     NULL, 0);
  return GNUNET_OK;
}

int
serialize_abe_keyinfo (const struct IssueHandle *handle,
                 const struct GNUNET_CRYPTO_AbeKey *rp_key,
                 struct GNUNET_CRYPTO_EcdhePrivateKey **ecdh_privkey,
                 char **result)
{
  char *enc_keyinfo;
  char *serialized_key;
  char *buf;
  struct GNUNET_CRYPTO_EcdhePublicKey *ecdh_pubkey;
  ssize_t size;
  
  struct GNUNET_CRYPTO_SymmetricSessionKey skey;
  struct GNUNET_CRYPTO_SymmetricInitializationVector iv;
  struct GNUNET_HashCode new_key_hash;
  ssize_t enc_size;
  
  size = GNUNET_CRYPTO_cpabe_serialize_key (rp_key,
                                            (void**)&serialized_key);
  buf = GNUNET_malloc (strlen (handle->scopes) + 1 + size);
  GNUNET_memcpy (buf,
                 handle->scopes,
                 strlen (handle->scopes) + 1);
  GNUNET_memcpy (buf + strlen (handle->scopes) + 1,
                 serialized_key,
                 size);
  // ECDH keypair E = eG
  ecdh_pubkey = NULL;
  *ecdh_privkey = GNUNET_CRYPTO_ecdhe_key_create();
  GNUNET_CRYPTO_ecdhe_key_get_public (*ecdh_privkey,
                                      ecdh_pubkey);
  enc_keyinfo = GNUNET_malloc (size);
  // Derived key K = H(eB)
  GNUNET_assert (GNUNET_OK == GNUNET_CRYPTO_ecdh_ecdsa (*ecdh_privkey,
                                                        &handle->aud_key,
                                                        &new_key_hash));
  create_sym_key_from_ecdh(&new_key_hash, &skey, &iv);
  enc_size = GNUNET_CRYPTO_symmetric_encrypt (buf,
                                              size + strlen (handle->scopes) + 1,
                                              &skey, &iv,
                                              enc_keyinfo);
  *result = GNUNET_malloc (sizeof (struct GNUNET_CRYPTO_EcdhePublicKey)+
                           enc_size);
  GNUNET_memcpy (*result,
                 ecdh_pubkey,
                 sizeof (struct GNUNET_CRYPTO_EcdhePublicKey));
  GNUNET_memcpy (*result + sizeof (struct GNUNET_CRYPTO_EcdhePublicKey),
                 enc_keyinfo,
                 enc_size);
  GNUNET_free (enc_keyinfo);
  return GNUNET_OK;
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


/**
 * Build a token and store it
 *
 * @param cls the IssueHandle
 */
static void
sign_and_return_token (void *cls)
{
  struct ExchangeHandle *handle = cls;
  struct GNUNET_MQ_Envelope *env;
  char *token_str;
  uint64_t time;
  uint64_t exp_time;

  time = GNUNET_TIME_absolute_get().abs_value_us;
  exp_time = time + token_expiration_interval.rel_value_us;

  token_add_attr_int (handle->token, "nbf", time);
  token_add_attr_int (handle->token, "iat", time);
  token_add_attr_int (handle->token, "exp", exp_time);
  
  //Readable
  GNUNET_assert (GNUNET_OK == token_to_string (handle->token,
                                               &handle->aud_privkey,
                                               &token_str));

  env = create_exchange_result_message (token_str,
                                        handle->label,
                                        handle->ticket->payload->nonce,
                                        handle->r_id);
  GNUNET_MQ_send (GNUNET_SERVICE_client_get_mq(handle->client),
                  env);
  cleanup_exchange_handle (handle);
  GNUNET_free (token_str);

}

/**
 * Build an ABE key and store it
 *
 * @param cls the IssueHandle
 */
static void
issue_ticket (void *cls)
{
  struct GNUNET_CRYPTO_EcdsaPublicKey pub_key;
  struct GNUNET_CRYPTO_EcdhePrivateKey *ecdhe_privkey;
  struct IssueHandle *handle = cls;
  struct GNUNET_GNSRECORD_Data code_record[1];
  struct GNUNET_CRYPTO_AbeKey *rp_key;
  char *nonce_str;
  char *code_record_data;
  char **attrs;
  char *scope;
  char *scopes_tmp;
  int attrs_len;
  int i;
  uint64_t time;
  uint64_t exp_time;
  size_t code_record_len;

  //Remote nonce
  nonce_str = NULL;
  GNUNET_asprintf (&nonce_str, "%lu", handle->nonce);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Request nonce: %s\n", nonce_str);

  GNUNET_CRYPTO_ecdsa_key_get_public (&handle->iss_key,
                                      &pub_key);
  handle->ticket = ticket_create (handle->nonce,
                                  &pub_key,
                                  handle->label,
                                  &handle->aud_key);

  time = GNUNET_TIME_absolute_get().abs_value_us;
  exp_time = time + token_expiration_interval.rel_value_us;

  token_add_attr_int (handle->token, "nbf", time);
  token_add_attr_int (handle->token, "iat", time);
  token_add_attr_int (handle->token, "exp", exp_time);
  token_add_attr (handle->token, "nonce", nonce_str);

  //Create new ABE key for RP
  attrs_len = (GNUNET_CONTAINER_multihashmap_size (handle->attr_map) + 1) * sizeof (char*);
  attrs = GNUNET_malloc (attrs_len);
  i = 0;
  scopes_tmp = GNUNET_strdup (handle->scopes);
  for (scope = strtok (scopes_tmp, ","); NULL != scope; scope = strtok (NULL, ",")) {
    attrs[i] = scope;
    i++;
  }
  rp_key = GNUNET_CRYPTO_cpabe_create_key (handle->abe_key,
                                           attrs);
  code_record_len = serialize_abe_keyinfo (handle,
                                           rp_key,
                                           &ecdhe_privkey,
                                           &code_record_data);
  code_record[0].data = code_record_data;
  code_record[0].data_size = code_record_len;
  code_record[0].expiration_time = exp_time;
  code_record[0].record_type = GNUNET_GNSRECORD_TYPE_ABE_KEY;
  code_record[0].flags = GNUNET_GNSRECORD_RF_NONE;


  //Publish record
  handle->ns_qe = GNUNET_NAMESTORE_records_store (ns_handle,
                                                  &handle->iss_key,
                                                  handle->label,
                                                  1,
                                                  code_record,
                                                  &store_record_issue_cont,
                                                  handle);
  GNUNET_free (ecdhe_privkey);
  GNUNET_free (nonce_str);
  GNUNET_free (code_record_data);
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


static void
handle_vattr_collection (void* cls,
                         unsigned int d_count,
                         struct GNUNET_CREDENTIAL_Delegation *dc,
                         unsigned int c_count,
                         struct GNUNET_CREDENTIAL_Credential *cred)
{
  struct IssueHandle *handle = cls;
  struct VerifiedAttributeEntry *vattr;
  json_t *cred_json;
  json_t *cred_array;
  int i;
  handle->credential_request = NULL;

  if (NULL == cred)
  {
    GNUNET_SCHEDULER_add_now (&issue_ticket, handle);
    return;
  }
  cred_array = json_array();
  for (i=0;i<c_count;i++)
  {
    cred_json = credential_to_json (cred);
    if (NULL == cred_json)
      continue;
    json_array_append (cred_array, cred_json);
    token_add_attr_json (handle->token,
                         handle->v_attr_head->name,
                         cred_array);
  }
  json_decref (cred_array);
  vattr = handle->v_attr_head;

  GNUNET_CONTAINER_DLL_remove (handle->v_attr_head,
                               handle->v_attr_tail,
                               vattr);
  GNUNET_free (vattr->name);
  GNUNET_free (vattr);

  if (NULL == handle->v_attr_head)
  {
    GNUNET_SCHEDULER_add_now (&issue_ticket, handle);
    return;
  }
  handle->credential_request = GNUNET_CREDENTIAL_collect (credential_handle,
                                                          &handle->aud_key,
                                                          handle->v_attr_head->name,
                                                          &handle->iss_key,
                                                          &handle_vattr_collection,
                                                          handle);

}


static void
attr_collect_error (void *cls)
{
  struct IssueHandle *handle = cls;

  GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Adding attribute Error!\n");
  handle->ns_it = NULL;
  GNUNET_SCHEDULER_add_now (&issue_ticket, handle);
}


static void
attr_collect_finished (void *cls)
{
  struct IssueHandle *handle = cls;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Adding attribute END: \n");
  handle->ns_it = NULL;

  if (NULL == handle->v_attr_head)
  {
    GNUNET_SCHEDULER_add_now (&issue_ticket, handle);
    return;
  }
  handle->credential_request = GNUNET_CREDENTIAL_collect (credential_handle,
                                                          &handle->aud_key,
                                                          handle->v_attr_head->name,
                                                          &handle->iss_key,
                                                          &handle_vattr_collection,
                                                          handle);
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
  struct IssueHandle *handle = cls;
  int i;
  char* data;
  struct GNUNET_HashCode key;

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
process_parallel_lookup (void *cls, uint32_t rd_count,
                         const struct GNUNET_GNSRECORD_Data *rd)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Parallel lookup finished\n");
  struct ParallelLookup *parallel_lookup = cls;
  struct ExchangeHandle *handle = parallel_lookup->handle;
  char *data;
  int i;

  GNUNET_CONTAINER_DLL_remove (handle->parallel_lookups_head,
                               handle->parallel_lookups_tail,
                               parallel_lookup);
  GNUNET_free (parallel_lookup);
  if (1 == rd_count)
  {
    if (rd->record_type == GNUNET_GNSRECORD_TYPE_ID_ATTR)
    {
      GNUNET_CRYPTO_cpabe_decrypt (rd->data,
                                   rd->data_size,
                                   handle->key,
                                   (void**)&data);
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Adding value: %s\n", data);
      token_add_attr (handle->token,
                      label,
                      data);
      GNUNET_free (data);
    }
  } else {
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
  }
  if (NULL != handle->parallel_lookups_head)
    return; //Wait for more
  //Else we are done
  GNUNET_SCHEDULER_cancel (handle->kill_task);
  GNUNET_SCHEDULER_add_now (&sign_and_return_token, handle);
}

void
abort_parallel_lookups (void *cls)
{
  struct ExchangeHandle *handle = cls;
  struct ParallelLookup *lu;
  struct ParallelLookup *tmp;

  for (lu = handle->parallel_lookups_head;
       NULL != lu;) {
    GNUNET_GNS_lookup_cancel (lu->lookup_request);
    tmp = lu->next;
    GNUNET_CONTAINER_DLL_remove (handle->parallel_lookups_head,
                                 handle->parallel_lookups_tail,
                                 lu);
      GNUNET_free (lu);
      lu = tmp;
  }
  GNUNET_SCHEDULER_add_now (&sign_and_return_token, handle);

}

static void
process_lookup_result (void *cls, uint32_t rd_count,
                       const struct GNUNET_GNSRECORD_Data *rd)
{
  struct ExchangeHandle *handle = cls;
  struct GNUNET_HashCode new_key_hash;
  struct GNUNET_CRYPTO_SymmetricSessionKey enc_key;
  struct GNUNET_CRYPTO_SymmetricInitializationVector enc_iv;
  struct GNUNET_CRYPTO_EcdhePublicKey *ecdh_key;
  struct ParallelLookup *parallel_lookup;
  size_t size;
  char *buf;
  char *scope;
  char *lookup_query;

  handle->lookup_request = NULL;
  if (1 != rd_count)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Number of keys %d != 1.",
                rd_count);
    cleanup_exchange_handle (handle);
    GNUNET_SCHEDULER_add_now (&do_shutdown, NULL);
    return;
  }

  //Decrypt
  ecdh_key = (struct GNUNET_CRYPTO_EcdhePublicKey *)rd->data;

  buf = GNUNET_malloc (rd->data_size - sizeof (struct GNUNET_CRYPTO_EcdhePublicKey));

  //Calculate symmetric key from ecdh parameters
  GNUNET_assert (GNUNET_OK == 
                 GNUNET_CRYPTO_ecdsa_ecdh (&handle->aud_privkey,
                                           ecdh_key,
                                           &new_key_hash));
  create_sym_key_from_ecdh (&new_key_hash,
                            &enc_key,
                            &enc_iv);
  size = GNUNET_CRYPTO_symmetric_decrypt (rd->data + sizeof (struct GNUNET_CRYPTO_EcdhePublicKey),
                                          rd->data_size - sizeof (struct GNUNET_CRYPTO_EcdhePublicKey),
                                          &enc_key,
                                          &enc_iv,
                                          buf);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Decrypted bytes: %zd Expected bytes: %zd\n",
              size, rd->data_size - sizeof (struct GNUNET_CRYPTO_EcdhePublicKey));

  scopes = GNUNET_strdup (buf);

  handle->key = GNUNET_CRYPTO_cpabe_deserialize_key ((void*)(buf + strlen (scopes) + 1),
                                         rd->data_size - sizeof (struct GNUNET_CRYPTO_EcdhePublicKey)
                                         - strlen (scopes) - 1);

  for (scope = strtok (scopes, ","); NULL != scope; scope = strtok (NULL, ","))
  {
    GNUNET_asprintf (&lookup_query,
                     "%s.%s.gnu",
                     scope,
                     GNUNET_CRYPTO_ecdsa_public_key_to_string (&handle->ticket->payload->identity_key));
    parallel_lookup = GNUNET_new (struct ParallelLookup);
    parallel_lookup->handle = handle;
    parallel_lookup->lookup_request
      = GNUNET_GNS_lookup (gns_handle,
                           lookup_query,
                           &handle->ticket->aud_key,
                           GNUNET_GNSRECORD_TYPE_ID_ATTR,
                           GNUNET_GNS_LO_LOCAL_MASTER,
                           &process_parallel_lookup,
                           parallel_lookup);
    GNUNET_CONTAINER_DLL_insert (handle->parallel_lookups_head,
                                 handle->parallel_lookups_tail,
                                 parallel_lookup);
  }
  handle->kill_task = GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_MINUTES,3),
                                &abort_parallel_lookups,
                                handle);
}

/**
 * Checks a exchange message
 *
 * @param cls client sending the message
 * @param xm message of type `struct ExchangeMessage`
 * @return #GNUNET_OK if @a xm is well-formed
 */
static int
check_exchange_message (void *cls,
                        const struct ExchangeMessage *xm)
{
  uint16_t size;

  size = ntohs (xm->header.size);
  if (size <= sizeof (struct ExchangeMessage))
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
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
                         const struct ExchangeMessage *xm)
{
  struct ExchangeHandle *xchange_handle;
  struct GNUNET_SERVICE_Client *client = cls;
  const char *ticket;
  char *lookup_query;

  ticket = (const char *) &xm[1];
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received EXCHANGE of `%s' from client\n",
              ticket);
  xchange_handle = GNUNET_malloc (sizeof (struct ExchangeHandle));
  xchange_handle->aud_privkey = xm->aud_privkey;
  xchange_handle->r_id = xm->id;
  if (GNUNET_SYSERR == ticket_parse (ticket,
                                     &xchange_handle->aud_privkey,
                                     &xchange_handle->ticket))
  {
    GNUNET_free (xchange_handle);
    GNUNET_SERVICE_client_drop (client);
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Looking for ABE key under %s\n",
              xchange_handle->ticket->payload->label);
  GNUNET_asprintf (&lookup_query,
                   "%s.gnu",
                   xchange_handle->ticket->payload->label);
  GNUNET_SERVICE_client_continue (client);
  xchange_handle->client = client;
  xchange_handle->token = token_create (&xchange_handle->ticket->payload->identity_key,
                                        &xchange_handle->ticket->payload->identity_key);
  xchange_handle->lookup_request
    = GNUNET_GNS_lookup (gns_handle,
                         lookup_query,
                         &xchange_handle->ticket->payload->identity_key,
                         GNUNET_GNSRECORD_TYPE_ABE_KEY,
                         GNUNET_GNS_LO_LOCAL_MASTER,
                         &process_lookup_result,
                         xchange_handle);
  GNUNET_free (lookup_query);

}

/**
 * Checks an issue message
 *
 * @param cls client sending the message
 * @param im message of type `struct IssueMessage`
 * @return #GNUNET_OK if @a im is well-formed
 */
static int
check_issue_message(void *cls,
                    const struct IssueMessage *im)
{
  uint16_t size;

  size = ntohs (im->header.size);
  if (size <= sizeof (struct IssueMessage))
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  scopes = (char *) &im[1];
  if ('\0' != scopes[size - sizeof (struct IssueMessage) - 1])
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Malformed scopes received!\n");
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}

void
attr_collect_task (void *cls)
{
  struct IssueHandle *issue_handle = cls;

  issue_handle->ns_it = GNUNET_NAMESTORE_zone_iteration_start (ns_handle,
                                                               &issue_handle->iss_key,
                                                               &attr_collect_error,
                                                               issue_handle,
                                                               &attr_collect,
                                                               issue_handle,
                                                               &attr_collect_finished,
                                                               issue_handle);
}

void
store_bootstrap_cont (void *cls,
                      int32_t success,
                      const char *emsg)
{
  if (GNUNET_SYSERR == success)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Failed to bootstrap ABE master %s\n",
                emsg);
    GNUNET_SCHEDULER_add_now (&do_shutdown, NULL);
    return;
  }
  GNUNET_SCHEDULER_add_now (&attr_collect_task, cls);
}

void
store_bootstrap_task (void *cls)
{
  struct IssueHandle *issue_handle = cls;
  struct GNUNET_GNSRECORD_Data rd[1];

  rd[0].data_size = GNUNET_CRYPTO_cpabe_serialize_master_key (issue_handle->abe_key,
                                                              (void**)&rd[0].data);
  rd[0].record_type = GNUNET_GNSRECORD_TYPE_ABE_MASTER;
  rd[0].flags = GNUNET_GNSRECORD_RF_NONE | GNUNET_GNSRECORD_RF_PRIVATE;
  rd[0].expiration_time = GNUNET_TIME_UNIT_HOURS.rel_value_us; //TODO sane?
  issue_handle->ns_qe = GNUNET_NAMESTORE_records_store (ns_handle,
                                                        &issue_handle->iss_key,
                                                        "+",
                                                        1,
                                                        rd,
                                                        &store_bootstrap_cont,
                                                        issue_handle);
}

void
abe_key_lookup_error (void *cls)
{
  GNUNET_SCHEDULER_add_now (&do_shutdown, cls);
}

void
abe_key_lookup_result (void *cls,
                       const struct GNUNET_CRYPTO_EcdsaPrivateKey *zone,
                       const char *label,
                       unsigned int rd_count,
                       const struct GNUNET_GNSRECORD_Data *rd)
{
  struct IssueHandle *handle = cls;
  int i;

  for (i=0;i<rd_count;i++) {
    if (GNUNET_GNSRECORD_TYPE_ABE_MASTER != rd[i].record_type)
      continue;
    handle->abe_key = GNUNET_CRYPTO_cpabe_deserialize_master_key ((void**)rd[i].data,
                                                                  rd[i].data_size);
    GNUNET_SCHEDULER_add_now (&attr_collect_task, handle);
    return;
  }

  //No ABE master found, bootstrapping...
  handle->abe_key = GNUNET_CRYPTO_cpabe_create_master_key ();
  GNUNET_SCHEDULER_add_now (&store_bootstrap_task, handle);
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
                      const struct IssueMessage *im)
{
  const char *scopes;
  char *scopes_tmp;
  char *scope;
  const char *v_attrs;
  uint64_t rnd_key;
  struct GNUNET_HashCode key;
  struct IssueHandle *issue_handle;
  struct VerifiedAttributeEntry *vattr_entry;
  struct GNUNET_SERVICE_Client *client = cls;

  scopes = (const char *) &im[1];
  v_attrs = (const char *) &im[1] + ntohl(im->scope_len);
  issue_handle = GNUNET_malloc (sizeof (struct IssueHandle));
  issue_handle->attr_map = GNUNET_CONTAINER_multihashmap_create (5,
                                                                 GNUNET_NO);
  scopes_tmp = GNUNET_strdup (scopes);

  for (scope = strtok (scopes_tmp, ","); NULL != scope; scope = strtok (NULL, ","))
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
  scopes_tmp = GNUNET_strdup (v_attrs);

  for (scope = strtok (scopes_tmp, ","); NULL != scope; scope = strtok (NULL, ","))
  {
    vattr_entry = GNUNET_new (struct VerifiedAttributeEntry);
    vattr_entry->name = GNUNET_strdup (scope);
    GNUNET_CONTAINER_DLL_insert (issue_handle->v_attr_head,
                                 issue_handle->v_attr_tail,
                                 vattr_entry);
  }
  GNUNET_free (scopes_tmp);



  issue_handle->r_id = im->id;
  issue_handle->aud_key = im->aud_key;
  issue_handle->iss_key = im->iss_key;
  GNUNET_CRYPTO_ecdsa_key_get_public (&im->iss_key,
                                      &issue_handle->iss_pkey);
  issue_handle->expiration = GNUNET_TIME_absolute_ntoh (im->expiration);
  issue_handle->nonce = ntohl (im->nonce);
  GNUNET_SERVICE_client_continue (client);
  issue_handle->client = client;
  issue_handle->scopes = GNUNET_strdup (scopes);
  issue_handle->token = token_create (&issue_handle->iss_pkey,
                                      &issue_handle->aud_key);
  rnd_key =
    GNUNET_CRYPTO_random_u64 (GNUNET_CRYPTO_QUALITY_STRONG,
                              UINT64_MAX);
  GNUNET_STRINGS_base64_encode ((char*)&rnd_key,
                                sizeof (uint64_t),
                                &issue_handle->label);
  issue_handle->ns_qe = GNUNET_NAMESTORE_records_lookup (ns_handle,
                                                         &issue_handle->iss_key,
                                                         "+",
                                                         &abe_key_lookup_error,
                                                         issue_handle,
                                                         &abe_key_lookup_result,
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
     const struct GNUNET_CONFIGURATION_Handle *c,
     struct GNUNET_SERVICE_Handle *server)
{
  cfg = c;

  stats = GNUNET_STATISTICS_create ("identity-provider", cfg);

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
  credential_handle = GNUNET_CREDENTIAL_connect (cfg);
  if (NULL == credential_handle)
  {
    GNUNET_log_strerror (GNUNET_ERROR_TYPE_ERROR, "error connecting to credential");
  }
  identity_handle = GNUNET_IDENTITY_connect (cfg,
                                             NULL,
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

  GNUNET_SCHEDULER_add_shutdown (&do_shutdown, NULL);
}

/**
 * Called whenever a client is disconnected.
 *
 * @param cls closure
 * @param client identification of the client
 * @param app_ctx @a client
 */
static void
client_disconnect_cb (void *cls,
                      struct GNUNET_SERVICE_Client *client,
                      void *app_ctx)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Client %p disconnected\n",
              client);
}


/**
 * Add a client to our list of active clients.
 *
 * @param cls NULL
 * @param client client to add
 * @param mq message queue for @a client
 * @return internal namestore client structure for this client
 */
static void *
client_connect_cb (void *cls,
                   struct GNUNET_SERVICE_Client *client,
                   struct GNUNET_MQ_Handle *mq)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Client %p connected\n",
              client);
  return client;
}



/**
 * Define "main" method using service macro.
 */
GNUNET_SERVICE_MAIN
("identity-provider",
 GNUNET_SERVICE_OPTION_NONE,
 &run,
 &client_connect_cb,
 &client_disconnect_cb,
 NULL,
 GNUNET_MQ_hd_var_size (issue_message,
                        GNUNET_MESSAGE_TYPE_IDENTITY_PROVIDER_ISSUE,
                        struct IssueMessage,
                        NULL),
 GNUNET_MQ_hd_var_size (exchange_message,
                        GNUNET_MESSAGE_TYPE_IDENTITY_PROVIDER_EXCHANGE,
                        struct ExchangeMessage,
                        NULL),
 GNUNET_MQ_handler_end());
/* end of gnunet-service-identity-provider.c */

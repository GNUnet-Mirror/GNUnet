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
#include "gnunet_identity_provider_plugin.h"
#include "gnunet_signatures.h"
#include "identity_provider.h"
#include "identity_token.h"
#include "identity_attribute.h"
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
 * Database handle
 */
static struct GNUNET_IDENTITY_PROVIDER_PluginFunctions *TKT_database;

/**
 * Name of DB plugin
 */
static char *db_lib_name;

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

/**
 * An idp client
 */
struct IdpClient;

/**
 * A ticket iteration operation.
 */
struct TicketIteration
{
  /**
   * DLL
   */
  struct TicketIteration *next;

  /**
   * DLL
   */
  struct TicketIteration *prev;

  /**
   * Client which intiated this zone iteration
   */
  struct IdpClient *client;

  /**
   * Key of the identity we are iterating over.
   */
  struct GNUNET_CRYPTO_EcdsaPublicKey identity;

  /**
   * Identity is audience
   */
  uint32_t is_audience;

  /**
   * The operation id fot the iteration in the response for the client
   */
  uint32_t r_id;

  /**
   * Offset of the iteration used to address next result of the 
   * iteration in the store
   *
   * Initialy set to 0 in handle_iteration_start
   * Incremented with by every call to handle_iteration_next
   */
  uint32_t offset;

};



/**
 * Callback after an ABE bootstrap
 *
 * @param cls closure
 * @param abe_key the ABE key that exists or was created
 */
typedef void
(*AbeBootstrapResult) (void *cls,
                       struct GNUNET_CRYPTO_AbeMasterKey *abe_key);


struct AbeBootstrapHandle
{
  /**
   * Function to call when finished
   */
  AbeBootstrapResult proc;

  /**
   * Callback closure
   */
  char *proc_cls;

  /**
   * Key of the zone we are iterating over.
   */
  struct GNUNET_CRYPTO_EcdsaPrivateKey identity;

  /**
   * Namestore Queue Entry
   */
  struct GNUNET_NAMESTORE_QueueEntry *ns_qe;

  /**
   * The issuer egos ABE master key
   */
  struct GNUNET_CRYPTO_AbeMasterKey *abe_key;
};

/**
 * An attribute iteration operation.
 */
struct AttributeIterator
{
  /**
   * Next element in the DLL
   */
  struct AttributeIterator *next;

  /**
   * Previous element in the DLL
   */
  struct AttributeIterator *prev;

  /**
   * IDP client which intiated this zone iteration
   */
  struct IdpClient *client;

  /**
   * Key of the zone we are iterating over.
   */
  struct GNUNET_CRYPTO_EcdsaPrivateKey identity;

  /**
   * The issuer egos ABE master key
   */
  struct GNUNET_CRYPTO_AbeMasterKey *abe_key;

  /**
   * Namestore iterator
   */
  struct GNUNET_NAMESTORE_ZoneIterator *ns_it;

  /**
   * The operation id fot the zone iteration in the response for the client
   */
  uint32_t request_id;

};



/**
 * An idp client
 */
struct IdpClient
{

  /**
   * The client
   */
  struct GNUNET_SERVICE_Client *client;

  /**
   * Message queue for transmission to @e client
   */
  struct GNUNET_MQ_Handle *mq;
  
  /**
   * Head of the DLL of
   * Attribute iteration operations in 
   * progress initiated by this client
   */
  struct AttributeIterator *op_head;

  /**
   * Tail of the DLL of
   * Attribute iteration operations 
   * in progress initiated by this client
   */
  struct AttributeIterator *op_tail;

  /**
   * Head of DLL of ticket iteration ops
   */
  struct TicketIteration *ticket_iter_head;

  /**
   * Tail of DLL of ticket iteration ops
   */
  struct TicketIteration *ticket_iter_tail;
};



struct AttributeStoreHandle
{

  /**
   * Client connection
   */
  struct IdpClient *client;

  /**
   * Identity
   */
  struct GNUNET_CRYPTO_EcdsaPrivateKey identity;

  /**
   * Identity pubkey
   */
  struct GNUNET_CRYPTO_EcdsaPublicKey identity_pkey;

  /**
   * The issuer egos ABE master key
   */
  struct GNUNET_CRYPTO_AbeMasterKey *abe_key;

  /**
   * QueueEntry
   */
  struct GNUNET_NAMESTORE_QueueEntry *ns_qe;

  /**
   * The attribute to store
   */
  struct GNUNET_IDENTITY_PROVIDER_Attribute *attribute;

  /**
   * request id
   */
  uint32_t r_id;
};



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

struct ParallelLookup;
struct ParallelLookup2;

struct ConsumeTicketHandle
{

  /**
   * Client connection
   */
  struct IdpClient *client;

  /**
   * Ticket
   */
  struct GNUNET_IDENTITY_PROVIDER_Ticket2 ticket;

  /**
   * LookupRequest
   */
  struct GNUNET_GNS_LookupRequest *lookup_request;

  /**
   * Audience Key
   */
  struct GNUNET_CRYPTO_EcdsaPrivateKey identity;

  /**
   * Audience Key
   */
  struct GNUNET_CRYPTO_EcdsaPublicKey identity_pub;

  /**
   * Lookup DLL
   */
  struct ParallelLookup2 *parallel_lookups_head;

  /**
   * Lookup DLL
   */
  struct ParallelLookup2 *parallel_lookups_tail;
  
  /**
   * Kill task
   */
  struct GNUNET_SCHEDULER_Task *kill_task;

  /**
   * The ABE key
   */
  struct GNUNET_CRYPTO_AbeKey *key;

  /**
   * Attributes
   */
  struct GNUNET_IDENTITY_PROVIDER_AttributeList *attrs;

  /**
   * request id
   */
  uint32_t r_id;
};

struct ParallelLookup2
{
  struct ParallelLookup2 *next;

  struct ParallelLookup2 *prev;

  struct GNUNET_GNS_LookupRequest *lookup_request;

  struct ConsumeTicketHandle *handle;

  char *label;
};


struct ExchangeHandle
{

  /**
   * Client connection
   */
  struct IdpClient *client;

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

  char *label;
};


struct TicketIssueHandle
{

  /**
   * Client connection
   */
  struct IdpClient *client;

  /**
   * Attributes to issue
   */
  struct GNUNET_IDENTITY_PROVIDER_AttributeList *attrs;

  /**
   * Issuer Key
   */
  struct GNUNET_CRYPTO_EcdsaPrivateKey identity;

  /**
   * Ticket to issue
   */
  struct GNUNET_IDENTITY_PROVIDER_Ticket2 ticket;

  /**
   * QueueEntry
   */
  struct GNUNET_NAMESTORE_QueueEntry *ns_qe;

  /**
   * request id
   */
  uint32_t r_id;
};


/**
 * DEPRECATED
 */
struct IssueHandle
{

  /**
   * Client connection
   */
  struct IdpClient *client;

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
  GNUNET_break (NULL == GNUNET_PLUGIN_unload (db_lib_name,
                                              TKT_database)); 
  GNUNET_free (db_lib_name);
  db_lib_name = NULL;
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

/**
 * Finished storing newly bootstrapped ABE key
 */
static void
bootstrap_store_cont (void *cls,
                      int32_t success,
                      const char *emsg)
{
  struct AbeBootstrapHandle *abh = cls;
  if (GNUNET_SYSERR == success)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Failed to bootstrap ABE master %s\n",
                emsg);
    abh->proc (abh->proc_cls, NULL);
    GNUNET_free (abh->abe_key);
    GNUNET_free (abh);
    return;
  }
  abh->proc (abh->proc_cls, abh->abe_key);
  GNUNET_free (abh);
}

/**
 * Generates and stores a new ABE key
 */
static void
bootstrap_store_task (void *cls)
{
  struct AbeBootstrapHandle *abh = cls;
  struct GNUNET_GNSRECORD_Data rd[1];

  rd[0].data_size = GNUNET_CRYPTO_cpabe_serialize_master_key (abh->abe_key,
                                                              (void**)&rd[0].data);
  rd[0].record_type = GNUNET_GNSRECORD_TYPE_ABE_MASTER;
  rd[0].flags = GNUNET_GNSRECORD_RF_RELATIVE_EXPIRATION | GNUNET_GNSRECORD_RF_PRIVATE;
  rd[0].expiration_time = GNUNET_TIME_UNIT_HOURS.rel_value_us; //TODO sane?
  abh->ns_qe = GNUNET_NAMESTORE_records_store (ns_handle,
                                               &abh->identity,
                                               "+",
                                               1,
                                               rd,
                                               &bootstrap_store_cont,
                                               abh);
}

/**
 * Error checking for ABE master
 */
static void
bootstrap_abe_error (void *cls)
{
  struct AbeBootstrapHandle *abh = cls;
  GNUNET_free (abh);
  abh->proc (abh->proc_cls, NULL);
  GNUNET_free (abh);
}


/**
 * Handle ABE lookup in namestore
 */
static void
bootstrap_abe_result (void *cls,
                      const struct GNUNET_CRYPTO_EcdsaPrivateKey *zone,
                      const char *label,
                      unsigned int rd_count,
                      const struct GNUNET_GNSRECORD_Data *rd)
{
  struct AbeBootstrapHandle *abh = cls;
  struct GNUNET_CRYPTO_AbeMasterKey *abe_key;
  int i;

  for (i=0;i<rd_count;i++) {
    if (GNUNET_GNSRECORD_TYPE_ABE_MASTER != rd[i].record_type)
      continue;
    abe_key = GNUNET_CRYPTO_cpabe_deserialize_master_key ((void**)rd[i].data,
                                                          rd[i].data_size);
    abh->proc (abh->proc_cls, abe_key);
    GNUNET_free (abh);
    return;
  }

  //No ABE master found, bootstrapping...
  abh->abe_key = GNUNET_CRYPTO_cpabe_create_master_key ();
  GNUNET_SCHEDULER_add_now (&bootstrap_store_task, abh);
}

/**
 * Bootstrap ABE master if it does not yet exists.
 * Will call the AbeBootstrapResult processor when done.
 */
static void
bootstrap_abe (const struct GNUNET_CRYPTO_EcdsaPrivateKey *identity,
               AbeBootstrapResult proc,
               void* cls)
{
  struct AbeBootstrapHandle *abh;

  abh = GNUNET_new (struct AbeBootstrapHandle);
  abh->proc = proc;
  abh->proc_cls = cls;
  abh->identity = *identity;
  abh->ns_qe = GNUNET_NAMESTORE_records_lookup (ns_handle,
                                                identity,
                                                "+",
                                                &bootstrap_abe_error,
                                                abh,
                                                &bootstrap_abe_result,
                                                abh);

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
  GNUNET_MQ_send (handle->client->mq,
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
  struct GNUNET_CRYPTO_EcdhePublicKey ecdh_pubkey;
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
  *ecdh_privkey = GNUNET_CRYPTO_ecdhe_key_create();
  GNUNET_CRYPTO_ecdhe_key_get_public (*ecdh_privkey,
                                      &ecdh_pubkey);
  enc_keyinfo = GNUNET_malloc (size + strlen (handle->scopes) + 1);
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
                 &ecdh_pubkey,
                 sizeof (struct GNUNET_CRYPTO_EcdhePublicKey));
  GNUNET_memcpy (*result + sizeof (struct GNUNET_CRYPTO_EcdhePublicKey),
                 enc_keyinfo,
                 enc_size);
  GNUNET_free (enc_keyinfo);
  return sizeof (struct GNUNET_CRYPTO_EcdhePublicKey)+enc_size;
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
  GNUNET_MQ_send (handle->client->mq,
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
              "Parallel lookup finished (count=%u)\n", rd_count);
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
                      parallel_lookup->label,
                      data);
      GNUNET_free (data);
    }
  } else {
    i = 0;
    for (; i < rd_count; i++)
    {
      if (rd[i].record_type == GNUNET_GNSRECORD_TYPE_ID_ATTR)
      {
        data = GNUNET_GNSRECORD_value_to_string (rd[i].record_type,
                                                 rd[i].data,
                                                 rd[i].data_size);
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Adding value: %s\n", data);
        token_add_attr (handle->token, parallel_lookup->label, data);
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
    GNUNET_free (lu->label);
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
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Scopes %s\n", scopes);
  handle->key = GNUNET_CRYPTO_cpabe_deserialize_key ((void*)(buf + strlen (scopes) + 1),
                                         rd->data_size - sizeof (struct GNUNET_CRYPTO_EcdhePublicKey)
                                         - strlen (scopes) - 1);

  for (scope = strtok (scopes, ","); NULL != scope; scope = strtok (NULL, ","))
  {
    GNUNET_asprintf (&lookup_query,
                     "%s.gnu",
                     scope);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Looking up %s\n", lookup_query);
    parallel_lookup = GNUNET_new (struct ParallelLookup);
    parallel_lookup->handle = handle;
    parallel_lookup->label = GNUNET_strdup (scope);
    parallel_lookup->lookup_request
      = GNUNET_GNS_lookup (gns_handle,
                           lookup_query,
                           &handle->ticket->payload->identity_key,
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
  struct IdpClient *idp = cls;
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
    GNUNET_SERVICE_client_drop (idp->client);
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Looking for ABE key under %s\n",
              xchange_handle->ticket->payload->label);
  GNUNET_asprintf (&lookup_query,
                   "%s.gnu",
                   xchange_handle->ticket->payload->label);
  GNUNET_SERVICE_client_continue (idp->client);
  xchange_handle->client = idp;
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
abe_key_lookup_error (void *cls)
{
  GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
              "Error looking for ABE master!\n");
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
  GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
              "No ABE master found!\n");
  GNUNET_SCHEDULER_add_now (&do_shutdown, NULL);

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
  uint64_t rnd_key;
  struct GNUNET_HashCode key;
  struct IssueHandle *issue_handle;
  struct IdpClient *idp = cls;

  scopes = (const char *) &im[1];
  //v_attrs = (const char *) &im[1] + ntohl(im->scope_len);
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
  /*scopes_tmp = GNUNET_strdup (v_attrs);

    for (scope = strtok (scopes_tmp, ","); NULL != scope; scope = strtok (NULL, ","))
    {
    vattr_entry = GNUNET_new (struct VerifiedAttributeEntry);
    vattr_entry->name = GNUNET_strdup (scope);
    GNUNET_CONTAINER_DLL_insert (issue_handle->v_attr_head,
    issue_handle->v_attr_tail,
    vattr_entry);
    }
    GNUNET_free (scopes_tmp);*/



  issue_handle->r_id = im->id;
  issue_handle->aud_key = im->aud_key;
  issue_handle->iss_key = im->iss_key;
  GNUNET_CRYPTO_ecdsa_key_get_public (&im->iss_key,
                                      &issue_handle->iss_pkey);
  issue_handle->expiration = GNUNET_TIME_absolute_ntoh (im->expiration);
  issue_handle->nonce = ntohl (im->nonce);
  GNUNET_SERVICE_client_continue (idp->client);
  issue_handle->client = idp;
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

static void
cleanup_ticket_issue_handle (struct TicketIssueHandle *handle)
{
  if (NULL != handle->attrs)
    attribute_list_destroy (handle->attrs);
  if (NULL != handle->ns_qe)
    GNUNET_NAMESTORE_cancel (handle->ns_qe);
  GNUNET_free (handle);
}


static void
send_ticket_result (struct IdpClient *client,
                    uint32_t r_id,
                    const struct GNUNET_IDENTITY_PROVIDER_Ticket2 *ticket,
                    const struct GNUNET_IDENTITY_PROVIDER_AttributeList *attrs)
{
  struct TicketResultMessage *irm;
  struct GNUNET_MQ_Envelope *env;
  size_t attrs_size;
  struct GNUNET_IDENTITY_PROVIDER_Ticket2 *ticket_buf;
  char *attrs_buf;

  attrs_size = attribute_list_serialize_get_size (attrs);

  /* store ticket in DB */
  if (GNUNET_OK != TKT_database->store_ticket (TKT_database->cls,
                                               ticket,
                                               attrs))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Unable to store ticket after issue\n");
    GNUNET_break (0);
  }

  env = GNUNET_MQ_msg_extra (irm,
                             sizeof (struct GNUNET_IDENTITY_PROVIDER_Ticket2) + attrs_size,
                             GNUNET_MESSAGE_TYPE_IDENTITY_PROVIDER_TICKET_RESULT);
  ticket_buf = (struct GNUNET_IDENTITY_PROVIDER_Ticket2 *)&irm[1];
  *ticket_buf = *ticket;
  attrs_buf = (char*)&ticket_buf[1];
  attribute_list_serialize (attrs,
                            attrs_buf);
  irm->id = htonl (r_id);

  GNUNET_MQ_send (client->mq,
                  env);
}

static void
store_ticket_issue_cont (void *cls,
                         int32_t success,
                         const char *emsg)
{
  struct TicketIssueHandle *handle = cls;

  handle->ns_qe = NULL;
  if (GNUNET_SYSERR == success)
  {
    cleanup_ticket_issue_handle (handle);
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "%s\n",
                "Unknown Error\n");
    GNUNET_SCHEDULER_add_now (&do_shutdown, NULL);
    return;
  }
  send_ticket_result (handle->client,
                      handle->r_id,
                      &handle->ticket,
                      handle->attrs);
  cleanup_ticket_issue_handle (handle);
}



int
serialize_abe_keyinfo2 (const struct TicketIssueHandle *handle,
                        const struct GNUNET_CRYPTO_AbeKey *rp_key,
                        struct GNUNET_CRYPTO_EcdhePrivateKey **ecdh_privkey,
                        char **result)
{
  struct GNUNET_CRYPTO_EcdhePublicKey ecdh_pubkey;
  struct GNUNET_IDENTITY_PROVIDER_AttributeListEntry *le;
  char *enc_keyinfo;
  char *serialized_key;
  char *buf;
  char *write_ptr;
  char attrs_str_len;
  ssize_t size;

  struct GNUNET_CRYPTO_SymmetricSessionKey skey;
  struct GNUNET_CRYPTO_SymmetricInitializationVector iv;
  struct GNUNET_HashCode new_key_hash;
  ssize_t enc_size;

  size = GNUNET_CRYPTO_cpabe_serialize_key (rp_key,
                                            (void**)&serialized_key);
  attrs_str_len = 0;
  for (le = handle->attrs->list_head; NULL != le; le = le->next) {
    attrs_str_len += strlen (le->attribute->name) + 1;
  }
  buf = GNUNET_malloc (attrs_str_len + size);
  write_ptr = buf;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Writing attributes\n");
  for (le = handle->attrs->list_head; NULL != le; le = le->next) {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "%s\n", le->attribute->name);


    GNUNET_memcpy (write_ptr,
                   le->attribute->name,
                   strlen (le->attribute->name));
    write_ptr[strlen (le->attribute->name)] = ',';
    write_ptr += strlen (le->attribute->name) + 1;
  }
  write_ptr--;
  write_ptr[0] = '\0'; //replace last , with a 0-terminator
  write_ptr++;
  GNUNET_memcpy (write_ptr,
                 serialized_key,
                 size);
  // ECDH keypair E = eG
  *ecdh_privkey = GNUNET_CRYPTO_ecdhe_key_create();
  GNUNET_CRYPTO_ecdhe_key_get_public (*ecdh_privkey,
                                      &ecdh_pubkey);
  enc_keyinfo = GNUNET_malloc (size + attrs_str_len);
  // Derived key K = H(eB)
  GNUNET_assert (GNUNET_OK == GNUNET_CRYPTO_ecdh_ecdsa (*ecdh_privkey,
                                                        &handle->ticket.audience,
                                                        &new_key_hash));
  create_sym_key_from_ecdh(&new_key_hash, &skey, &iv);
  enc_size = GNUNET_CRYPTO_symmetric_encrypt (buf,
                                              size + attrs_str_len,
                                              &skey, &iv,
                                              enc_keyinfo);
  *result = GNUNET_malloc (sizeof (struct GNUNET_CRYPTO_EcdhePublicKey)+
                           enc_size);
  GNUNET_memcpy (*result,
                 &ecdh_pubkey,
                 sizeof (struct GNUNET_CRYPTO_EcdhePublicKey));
  GNUNET_memcpy (*result + sizeof (struct GNUNET_CRYPTO_EcdhePublicKey),
                 enc_keyinfo,
                 enc_size);
  GNUNET_free (enc_keyinfo);
  return sizeof (struct GNUNET_CRYPTO_EcdhePublicKey)+enc_size;
}



static void
issue_ticket_after_abe_bootstrap (void *cls,
                                  struct GNUNET_CRYPTO_AbeMasterKey *abe_key)
{
  struct TicketIssueHandle *ih = cls;
  struct GNUNET_IDENTITY_PROVIDER_AttributeListEntry *le;
  struct GNUNET_CRYPTO_EcdhePrivateKey *ecdhe_privkey;
  struct GNUNET_GNSRECORD_Data code_record[1];
  struct GNUNET_CRYPTO_AbeKey *rp_key;
  char *code_record_data;
  char **attrs;
  char *label;
  int attrs_len;
  int i;
  size_t code_record_len;

  //Create new ABE key for RP
  attrs_len = 0;
  for (le = ih->attrs->list_head; NULL != le; le = le->next)
    attrs_len++;
  attrs = GNUNET_malloc ((attrs_len + 1)*sizeof (char*));
  i = 0;
  for (le = ih->attrs->list_head; NULL != le; le = le->next) {
    attrs[i] = (char*) le->attribute->name;
    i++;
  }
  attrs[i] = NULL;
  rp_key = GNUNET_CRYPTO_cpabe_create_key (abe_key,
                                           attrs);

  //TODO review this wireformat
  code_record_len = serialize_abe_keyinfo2 (ih,
                                            rp_key,
                                            &ecdhe_privkey,
                                            &code_record_data);
  code_record[0].data = code_record_data;
  code_record[0].data_size = code_record_len;
  code_record[0].expiration_time = GNUNET_TIME_UNIT_DAYS.rel_value_us;
  code_record[0].record_type = GNUNET_GNSRECORD_TYPE_ABE_KEY;
  code_record[0].flags = GNUNET_GNSRECORD_RF_RELATIVE_EXPIRATION;

  label = GNUNET_STRINGS_data_to_string_alloc (&ih->ticket.rnd,
                                               sizeof (uint64_t));
  //Publish record
  ih->ns_qe = GNUNET_NAMESTORE_records_store (ns_handle,
                                              &ih->identity,
                                              label,
                                              1,
                                              code_record,
                                              &store_ticket_issue_cont,
                                              ih);
  GNUNET_free (ecdhe_privkey);
  GNUNET_free (label);
  GNUNET_free (attrs);
  GNUNET_free (code_record_data);
}


/**
 * Checks a ticket issue message
 *
 * @param cls client sending the message
 * @param im message of type `struct TicketIssueMessage`
 * @return #GNUNET_OK if @a im is well-formed
 */
static int
check_ticket_issue_message(void *cls,
                           const struct TicketIssueMessage *im)
{
  uint16_t size;

  size = ntohs (im->header.size);
  if (size <= sizeof (struct TicketIssueMessage))
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 *
 * Handler for ticket issue message
 *
 * @param cls unused
 * @param client who sent the message
 * @param message the message
 */
static void
handle_ticket_issue_message (void *cls,
                             const struct TicketIssueMessage *im)
{
  struct TicketIssueHandle *ih;
  struct IdpClient *idp = cls;
  size_t attrs_len;

  ih = GNUNET_new (struct TicketIssueHandle);
  attrs_len = ntohs (im->attr_len);
  ih->attrs = attribute_list_deserialize ((char*)&im[1], attrs_len);
  ih->r_id = ntohl (im->id);
  ih->client = idp;
  ih->identity = im->identity;
  GNUNET_CRYPTO_ecdsa_key_get_public (&ih->identity,
                                      &ih->ticket.identity);
  ih->ticket.audience = im->rp;
  ih->ticket.rnd =
    GNUNET_CRYPTO_random_u64 (GNUNET_CRYPTO_QUALITY_STRONG,
                              UINT64_MAX);
  bootstrap_abe (&ih->identity, &issue_ticket_after_abe_bootstrap, ih);
  GNUNET_SERVICE_client_continue (idp->client);

}



static void
cleanup_as_handle (struct AttributeStoreHandle *handle)
{
  if (NULL != handle->attribute)
    GNUNET_free (handle->attribute);
  if (NULL != handle->abe_key)
    GNUNET_free (handle->abe_key);
  GNUNET_free (handle);
}

/**
 * Checks a ticket consume message
 *
 * @param cls client sending the message
 * @param im message of type `struct ConsumeTicketMessage`
 * @return #GNUNET_OK if @a im is well-formed
 */
static int
check_consume_ticket_message(void *cls,
                             const struct ConsumeTicketMessage *cm)
{
  uint16_t size;

  size = ntohs (cm->header.size);
  if (size <= sizeof (struct ConsumeTicketMessage))
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}

static void
process_parallel_lookup2 (void *cls, uint32_t rd_count,
                          const struct GNUNET_GNSRECORD_Data *rd)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Parallel lookup finished (count=%u)\n", rd_count);
  struct ParallelLookup2 *parallel_lookup = cls;
  struct ConsumeTicketHandle *handle = parallel_lookup->handle;
  struct ConsumeTicketResultMessage *crm;
  struct GNUNET_MQ_Envelope *env;
  struct GNUNET_IDENTITY_PROVIDER_AttributeListEntry *attr_le;
  char *data;
  char *data_tmp;
  size_t attr_len;
  size_t attrs_len;

  GNUNET_CONTAINER_DLL_remove (handle->parallel_lookups_head,
                               handle->parallel_lookups_tail,
                               parallel_lookup);
  GNUNET_free (parallel_lookup->label);
  GNUNET_free (parallel_lookup);
  if (1 != rd_count)
    GNUNET_break(0);//TODO
  if (rd->record_type == GNUNET_GNSRECORD_TYPE_ID_ATTR)
  {
    attr_len = GNUNET_CRYPTO_cpabe_decrypt (rd->data,
                                            rd->data_size,
                                            handle->key,
                                            (void**)&data);
    attr_le = GNUNET_new (struct GNUNET_IDENTITY_PROVIDER_AttributeListEntry);
    attr_le->attribute = attribute_deserialize (data,
                                                attr_len);
    GNUNET_CONTAINER_DLL_insert (handle->attrs->list_head,
                                 handle->attrs->list_tail,
                                 attr_le);
    GNUNET_free (data);
  }
  if (NULL != handle->parallel_lookups_head)
    return; //Wait for more
  /* Else we are done */

  /* Store ticket in DB */
  if (GNUNET_OK != TKT_database->store_ticket (TKT_database->cls,
                                               &handle->ticket,
                                               handle->attrs))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Unable to store ticket after consume\n");
    GNUNET_break (0);
  }
  
  GNUNET_SCHEDULER_cancel (handle->kill_task);
  attrs_len = attribute_list_serialize_get_size (handle->attrs);
  env = GNUNET_MQ_msg_extra (crm,
                             attrs_len,
                             GNUNET_MESSAGE_TYPE_IDENTITY_PROVIDER_CONSUME_TICKET_RESULT);
  crm->id = htonl (handle->r_id);
  crm->attrs_len = htons (attrs_len);
  crm->identity = handle->ticket.identity;
  data_tmp = (char *) &crm[1];
  attribute_list_serialize (handle->attrs,
                            data_tmp);
  GNUNET_MQ_send (handle->client->mq, env);
}

void
abort_parallel_lookups2 (void *cls)
{
  struct ConsumeTicketHandle *handle = cls;
  struct ParallelLookup2 *lu;
  struct ParallelLookup2 *tmp;
  struct AttributeResultMessage *arm;
  struct GNUNET_MQ_Envelope *env;

  for (lu = handle->parallel_lookups_head;
       NULL != lu;) {
    GNUNET_GNS_lookup_cancel (lu->lookup_request);
    GNUNET_free (lu->label);
    tmp = lu->next;
    GNUNET_CONTAINER_DLL_remove (handle->parallel_lookups_head,
                                 handle->parallel_lookups_tail,
                                 lu);
    GNUNET_free (lu);
    lu = tmp;
  }
  env = GNUNET_MQ_msg (arm,
                       GNUNET_MESSAGE_TYPE_IDENTITY_PROVIDER_ATTRIBUTE_RESULT);
  arm->id = htonl (handle->r_id);
  arm->attr_len = htons (0);
  GNUNET_MQ_send (handle->client->mq, env);

}

static void
cleanup_consume_ticket_handle (struct ConsumeTicketHandle *handle)
{
  if (NULL != handle->key)
    GNUNET_free (handle->key);
  GNUNET_free (handle);
}


static void
process_consume_abe_key (void *cls, uint32_t rd_count,
                         const struct GNUNET_GNSRECORD_Data *rd)
{
  struct ConsumeTicketHandle *handle = cls;
  struct GNUNET_HashCode new_key_hash;
  struct GNUNET_CRYPTO_SymmetricSessionKey enc_key;
  struct GNUNET_CRYPTO_SymmetricInitializationVector enc_iv;
  struct GNUNET_CRYPTO_EcdhePublicKey *ecdh_key;
  struct ParallelLookup2 *parallel_lookup;
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
    cleanup_consume_ticket_handle (handle);
    GNUNET_SCHEDULER_add_now (&do_shutdown, NULL);
    return;
  }

  //Decrypt
  ecdh_key = (struct GNUNET_CRYPTO_EcdhePublicKey *)rd->data;

  buf = GNUNET_malloc (rd->data_size - sizeof (struct GNUNET_CRYPTO_EcdhePublicKey));

  //Calculate symmetric key from ecdh parameters
  GNUNET_assert (GNUNET_OK == 
                 GNUNET_CRYPTO_ecdsa_ecdh (&handle->identity,
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
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Scopes %s\n", scopes);
  handle->key = GNUNET_CRYPTO_cpabe_deserialize_key ((void*)(buf + strlen (scopes) + 1),
                                                     rd->data_size - sizeof (struct GNUNET_CRYPTO_EcdhePublicKey)
                                                     - strlen (scopes) - 1);

  for (scope = strtok (scopes, ","); NULL != scope; scope = strtok (NULL, ","))
  {
    GNUNET_asprintf (&lookup_query,
                     "%s.gnu",
                     scope);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Looking up %s\n", lookup_query);
    parallel_lookup = GNUNET_new (struct ParallelLookup2);
    parallel_lookup->handle = handle;
    parallel_lookup->label = GNUNET_strdup (scope);
    parallel_lookup->lookup_request
      = GNUNET_GNS_lookup (gns_handle,
                           lookup_query,
                           &handle->ticket.identity,
                           GNUNET_GNSRECORD_TYPE_ID_ATTR,
                           GNUNET_GNS_LO_LOCAL_MASTER,
                           &process_parallel_lookup2,
                           parallel_lookup);
    GNUNET_CONTAINER_DLL_insert (handle->parallel_lookups_head,
                                 handle->parallel_lookups_tail,
                                 parallel_lookup);
    GNUNET_free (lookup_query);
  }
  handle->kill_task = GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_MINUTES,3),
                                                    &abort_parallel_lookups2,
                                                    handle);
}


/**
 *
 * Handler for ticket issue message
 *
 * @param cls unused
 * @param client who sent the message
 * @param message the message
 */
static void
handle_consume_ticket_message (void *cls,
                               const struct ConsumeTicketMessage *cm)
{
  struct ConsumeTicketHandle *ch;
  struct IdpClient *idp = cls;
  char* lookup_query;
  char* rnd_label;

  ch = GNUNET_new (struct ConsumeTicketHandle);
  ch->r_id = ntohl (cm->id);
  ch->client = idp;
  ch->identity = cm->identity;
  ch->attrs = GNUNET_new (struct GNUNET_IDENTITY_PROVIDER_AttributeList);
  GNUNET_CRYPTO_ecdsa_key_get_public (&ch->identity,
                                      &ch->identity_pub);
  ch->ticket = *((struct GNUNET_IDENTITY_PROVIDER_Ticket2*)&cm[1]);
  rnd_label = GNUNET_STRINGS_data_to_string_alloc (&ch->ticket.rnd,
                                                   sizeof (uint64_t));
  GNUNET_asprintf (&lookup_query,
                   "%s.gnu",
                   rnd_label);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Looking for ABE key under %s\n", lookup_query);

  ch->lookup_request
    = GNUNET_GNS_lookup (gns_handle,
                         lookup_query,
                         &ch->ticket.identity,
                         GNUNET_GNSRECORD_TYPE_ABE_KEY,
                         GNUNET_GNS_LO_LOCAL_MASTER,
                         &process_consume_abe_key,
                         ch);
  GNUNET_free (rnd_label);
  GNUNET_free (lookup_query);
  GNUNET_SERVICE_client_continue (idp->client);
}

void
attr_store_cont (void *cls,
                 int32_t success,
                 const char *emsg)
{
  struct AttributeStoreHandle *as_handle = cls;
  struct GNUNET_MQ_Envelope *env;
  struct AttributeStoreResponseMessage *acr_msg;

  if (GNUNET_SYSERR == success)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Failed to store attribute %s\n",
                emsg);
    GNUNET_SCHEDULER_add_now (&do_shutdown, NULL);
    return;
  }

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Sending ATTRIBUTE_STORE_RESPONSE message\n");
  env = GNUNET_MQ_msg (acr_msg,
                       GNUNET_MESSAGE_TYPE_IDENTITY_PROVIDER_ATTRIBUTE_STORE_RESPONSE);
  acr_msg->id = htonl (as_handle->r_id);
  acr_msg->op_result = htonl (GNUNET_OK);
  GNUNET_MQ_send (as_handle->client->mq,
                  env);
  cleanup_as_handle (as_handle);
}

static void
attr_store_task (void *cls)
{
  struct AttributeStoreHandle *as_handle = cls;
  struct GNUNET_GNSRECORD_Data rd[1];
  char* buf;
  size_t buf_size;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Storing attribute\n");
  buf_size = attribute_serialize_get_size (as_handle->attribute);
  buf = GNUNET_malloc (buf_size);

  attribute_serialize (as_handle->attribute,
                       buf);

  /**
   * Encrypt the attribute value and store in namestore
   */
  rd[0].data_size = GNUNET_CRYPTO_cpabe_encrypt (buf,
                                                 buf_size,
                                                 as_handle->attribute->name, //Policy
                                                 as_handle->abe_key,
                                                 (void**)&rd[0].data);
  GNUNET_free (buf);
  rd[0].record_type = GNUNET_GNSRECORD_TYPE_ID_ATTR;
  rd[0].flags = GNUNET_GNSRECORD_RF_RELATIVE_EXPIRATION;
  rd[0].expiration_time = GNUNET_TIME_UNIT_HOURS.rel_value_us; //TODO sane?
  as_handle->ns_qe = GNUNET_NAMESTORE_records_store (ns_handle,
                                                     &as_handle->identity,
                                                     as_handle->attribute->name,
                                                     1,
                                                     rd,
                                                     &attr_store_cont,
                                                     as_handle);
  GNUNET_free ((void*)rd[0].data);

}


static void
store_after_abe_bootstrap (void *cls,
                           struct GNUNET_CRYPTO_AbeMasterKey *abe_key)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Finished ABE bootstrap\n");
  struct AttributeStoreHandle *ash = cls;
  ash->abe_key = abe_key;
  GNUNET_SCHEDULER_add_now (&attr_store_task, ash);
}

/**
 * Checks a store message
 *
 * @param cls client sending the message
 * @param sam message of type `struct AttributeStoreMessage`
 * @return #GNUNET_OK if @a im is well-formed
 */
static int
check_attribute_store_message(void *cls,
                              const struct AttributeStoreMessage *sam)
{
  uint16_t size;

  size = ntohs (sam->header.size);
  if (size <= sizeof (struct AttributeStoreMessage))
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 *
 * Handler for store message
 *
 * @param cls unused
 * @param client who sent the message
 * @param message the message
 */
static void
handle_attribute_store_message (void *cls,
                                const struct AttributeStoreMessage *sam)
{
  struct AttributeStoreHandle *as_handle;
  struct IdpClient *idp = cls;
  size_t data_len;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received ATTRIBUTE_STORE message\n");

  data_len = ntohs (sam->attr_len);

  as_handle = GNUNET_new (struct AttributeStoreHandle);
  as_handle->attribute = attribute_deserialize ((char*)&sam[1],
                                                data_len);

  as_handle->r_id = ntohl (sam->id);
  as_handle->identity = sam->identity;
  GNUNET_CRYPTO_ecdsa_key_get_public (&sam->identity,
                                      &as_handle->identity_pkey);

  GNUNET_SERVICE_client_continue (idp->client);
  as_handle->client = idp;
  bootstrap_abe (&as_handle->identity, &store_after_abe_bootstrap, as_handle);
}

static void
cleanup_iter_handle (struct AttributeIterator *ai)
{
  if (NULL != ai->abe_key)
    GNUNET_free (ai->abe_key);
  GNUNET_CONTAINER_DLL_remove (ai->client->op_head,
                               ai->client->op_tail,
                               ai);
  GNUNET_free (ai);
}

static void
attr_iter_error (void *cls)
{
  //struct AttributeIterator *ai = cls;
  //TODO
  GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
              "Failed to iterate over attributes\n");
  GNUNET_SCHEDULER_add_now (&do_shutdown, NULL);
}

static void
attr_iter_finished (void *cls)
{
  struct AttributeIterator *ai = cls;
  struct GNUNET_MQ_Envelope *env;
  struct AttributeResultMessage *arm;

  env = GNUNET_MQ_msg (arm,
                       GNUNET_MESSAGE_TYPE_IDENTITY_PROVIDER_ATTRIBUTE_RESULT);
  arm->id = htonl (ai->request_id);
  arm->attr_len = htons (0);
  GNUNET_MQ_send (ai->client->mq, env);
  cleanup_iter_handle (ai);
}

static void
attr_iter_cb (void *cls,
              const struct GNUNET_CRYPTO_EcdsaPrivateKey *zone,
              const char *label,
              unsigned int rd_count,
              const struct GNUNET_GNSRECORD_Data *rd)
{
  struct AttributeIterator *ai = cls;
  struct AttributeResultMessage *arm;
  struct GNUNET_CRYPTO_AbeKey *key;
  struct GNUNET_MQ_Envelope *env;
  ssize_t msg_extra_len;
  char* attr_ser;
  char* attrs[2];
  char* data_tmp;

  if (rd_count != 1)
  {
    GNUNET_NAMESTORE_zone_iterator_next (ai->ns_it);
    return;
  }

  if (GNUNET_GNSRECORD_TYPE_ID_ATTR != rd->record_type) {
    GNUNET_NAMESTORE_zone_iterator_next (ai->ns_it);
    return;
  }
  attrs[0] = (char*)label;
  attrs[1] = 0;
  key = GNUNET_CRYPTO_cpabe_create_key (ai->abe_key,
                                        attrs);
  msg_extra_len = GNUNET_CRYPTO_cpabe_decrypt (rd->data,
                                               rd->data_size,
                                               key,
                                               (void**)&attr_ser);
  GNUNET_CRYPTO_cpabe_delete_key (key);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Found attribute: %s\n", label);
  env = GNUNET_MQ_msg_extra (arm,
                             msg_extra_len,
                             GNUNET_MESSAGE_TYPE_IDENTITY_PROVIDER_ATTRIBUTE_RESULT);
  arm->id = htonl (ai->request_id);
  arm->attr_len = htons (msg_extra_len);
  GNUNET_CRYPTO_ecdsa_key_get_public (zone,
                                      &arm->identity);
  data_tmp = (char *) &arm[1];
  GNUNET_memcpy (data_tmp,
                 attr_ser,
                 msg_extra_len);
  GNUNET_MQ_send (ai->client->mq, env);
  GNUNET_free (attr_ser);
}


void
iterate_after_abe_bootstrap (void *cls,
                             struct GNUNET_CRYPTO_AbeMasterKey *abe_key)
{
  struct AttributeIterator *ai = cls;
  ai->abe_key = abe_key;
  ai->ns_it = GNUNET_NAMESTORE_zone_iteration_start (ns_handle,
                                                     &ai->identity,
                                                     &attr_iter_error,
                                                     ai,
                                                     &attr_iter_cb,
                                                     ai,
                                                     &attr_iter_finished,
                                                     ai);
}


/**
 * Handles a #GNUNET_MESSAGE_TYPE_IDENTITY_PROVIDER_ITERATION_START message
 *
 * @param cls the client sending the message
 * @param zis_msg message from the client
 */
static void
handle_iteration_start (void *cls,
                        const struct AttributeIterationStartMessage *ais_msg)
{
  struct IdpClient *idp = cls;
  struct AttributeIterator *ai;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received ATTRIBUTE_ITERATION_START message\n");
  ai = GNUNET_new (struct AttributeIterator);
  ai->request_id = ntohl (ais_msg->id);
  ai->client = idp;
  ai->identity = ais_msg->identity;

  GNUNET_CONTAINER_DLL_insert (idp->op_head,
                               idp->op_tail,
                               ai);
  bootstrap_abe (&ai->identity, &iterate_after_abe_bootstrap, ai);
  GNUNET_SERVICE_client_continue (idp->client);
}


/**
 * Handles a #GNUNET_MESSAGE_TYPE_IDENTITY_PROVIDER_ITERATION_STOP message
 *
 * @param cls the client sending the message
 * @param ais_msg message from the client
 */
static void
handle_iteration_stop (void *cls,
                       const struct AttributeIterationStopMessage *ais_msg)
{
  struct IdpClient *idp = cls;
  struct AttributeIterator *ai;
  uint32_t rid;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received `%s' message\n",
              "ATTRIBUTE_ITERATION_STOP");
  rid = ntohl (ais_msg->id);
  for (ai = idp->op_head; NULL != ai; ai = ai->next)
    if (ai->request_id == rid)
      break;
  if (NULL == ai)
  {
    GNUNET_break (0);
    GNUNET_SERVICE_client_drop (idp->client);
    return;
  }
  GNUNET_CONTAINER_DLL_remove (idp->op_head,
                               idp->op_tail,
                               ai);
  GNUNET_free (ai);
  GNUNET_SERVICE_client_continue (idp->client);
}


/**
 * Handles a #GNUNET_MESSAGE_TYPE_IDENTITY_PROVIDER_ATTRIBUTE_ITERATION_NEXT message
 *
 * @param cls the client sending the message
 * @param message message from the client
 */
static void
handle_iteration_next (void *cls,
                       const struct AttributeIterationNextMessage *ais_msg)
{
  struct IdpClient *idp = cls;
  struct AttributeIterator *ai;
  uint32_t rid;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received ATTRIBUTE_ITERATION_NEXT message\n");
  rid = ntohl (ais_msg->id);
  for (ai = idp->op_head; NULL != ai; ai = ai->next)
    if (ai->request_id == rid)
      break;
  if (NULL == ai)
  {
    GNUNET_break (0);
    GNUNET_SERVICE_client_drop (idp->client);
    return;
  }
  GNUNET_NAMESTORE_zone_iterator_next (ai->ns_it);
  GNUNET_SERVICE_client_continue (idp->client);
}

/**
 * Ticket iteration processor result
 */
enum ZoneIterationResult
{
  /**
   * Iteration start.
   */
  IT_START = 0,

  /**
   * Found tickets,
   * Continue to iterate with next iteration_next call
   */
  IT_SUCCESS_MORE_AVAILABLE = 1,

  /**
   * Iteration complete
   */
  IT_SUCCESS_NOT_MORE_RESULTS_AVAILABLE = 2
};


/**
 * Context for ticket iteration
 */
struct TicketIterationProcResult
{
  /**
   * The ticket iteration handle
   */
  struct TicketIteration *ti;

  /**
   * Iteration result: iteration done?
   * #IT_SUCCESS_MORE_AVAILABLE:  if there may be more results overall but
   * we got one for now and have sent it to the client
   * #IT_SUCCESS_NOT_MORE_RESULTS_AVAILABLE: if there are no further results,
   * #IT_START: if we are still trying to find a result.
   */
  int res_iteration_finished;

};



/**
 * Process ticket from database
 *
 * @param cls struct TicketIterationProcResult
 * @param ticket the ticket
 * @param attrs the attributes
 */
static void
ticket_iterate_proc (void *cls,
                     const struct GNUNET_IDENTITY_PROVIDER_Ticket2 *ticket,
                     const struct GNUNET_IDENTITY_PROVIDER_AttributeList *attrs)
{
  struct TicketIterationProcResult *proc = cls;

  if (NULL == ticket)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Iteration done\n");
    proc->res_iteration_finished = IT_SUCCESS_NOT_MORE_RESULTS_AVAILABLE;
    return;
  }
  if ((NULL == ticket) || (NULL == attrs))
  {
    /* error */
    proc->res_iteration_finished = IT_START;
    GNUNET_break (0);
    return;
  }
  proc->res_iteration_finished = IT_SUCCESS_MORE_AVAILABLE;
  send_ticket_result (proc->ti->client,
                      proc->ti->r_id,
                      ticket,
                      attrs);

}

/**
 * Perform ticket iteration step
 *
 * @param ti ticket iterator to process
 */
static void
run_ticket_iteration_round (struct TicketIteration *ti)
{
  struct TicketIterationProcResult proc;
  struct GNUNET_MQ_Envelope *env;
  struct TicketResultMessage *trm;
  int ret;

  memset (&proc, 0, sizeof (proc));
  proc.ti = ti;
  proc.res_iteration_finished = IT_START;
  while (IT_START == proc.res_iteration_finished)
  {
    if (GNUNET_SYSERR ==
        (ret = TKT_database->iterate_tickets (TKT_database->cls,
                                              &ti->identity,
                                              ti->is_audience,
                                              ti->offset,
                                              &ticket_iterate_proc,
                                              &proc)))
    {
      GNUNET_break (0);
      break;
    }
    if (GNUNET_NO == ret)
      proc.res_iteration_finished = IT_SUCCESS_NOT_MORE_RESULTS_AVAILABLE;
    ti->offset++;
  }
  if (IT_SUCCESS_MORE_AVAILABLE == proc.res_iteration_finished)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "More results available\n");
    return; /* more later */
  }
  /* send empty response to indicate end of list */
  env = GNUNET_MQ_msg (trm,
                       GNUNET_MESSAGE_TYPE_IDENTITY_PROVIDER_TICKET_RESULT);
  trm->id = htonl (ti->r_id);
  GNUNET_MQ_send (ti->client->mq,
                  env);
  GNUNET_CONTAINER_DLL_remove (ti->client->ticket_iter_head,
                               ti->client->ticket_iter_tail,
                               ti);
  GNUNET_free (ti);
}

/**
 * Handles a #GNUNET_MESSAGE_TYPE_IDENTITY_PROVIDER_TICKET_ITERATION_START message
 *
 * @param cls the client sending the message
 * @param tis_msg message from the client
 */
static void
handle_ticket_iteration_start (void *cls,
                               const struct TicketIterationStartMessage *tis_msg)
{
  struct IdpClient *client = cls;
  struct TicketIteration *ti;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received TICKET_ITERATION_START message\n");
  ti = GNUNET_new (struct TicketIteration);
  ti->r_id = ntohl (tis_msg->id);
  ti->offset = 0;
  ti->client = client;
  ti->identity = tis_msg->identity;
  ti->is_audience = ntohl (tis_msg->is_audience);

  GNUNET_CONTAINER_DLL_insert (client->ticket_iter_head,
                               client->ticket_iter_tail,
                               ti);
  run_ticket_iteration_round (ti);
  GNUNET_SERVICE_client_continue (client->client);
}


/**
 * Handles a #GNUNET_MESSAGE_TYPE_IDENTITY_PROVIDER_TICKET_ITERATION_STOP message
 *
 * @param cls the client sending the message
 * @param tis_msg message from the client
 */
static void
handle_ticket_iteration_stop (void *cls,
                              const struct TicketIterationStopMessage *tis_msg)
{
  struct IdpClient *client = cls;
  struct TicketIteration *ti;
  uint32_t rid;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received `%s' message\n",
              "TICKET_ITERATION_STOP");
  rid = ntohl (tis_msg->id);
  for (ti = client->ticket_iter_head; NULL != ti; ti = ti->next)
    if (ti->r_id == rid)
      break;
  if (NULL == ti)
  {
    GNUNET_break (0);
    GNUNET_SERVICE_client_drop (client->client);
    return;
  }
  GNUNET_CONTAINER_DLL_remove (client->ticket_iter_head,
                               client->ticket_iter_tail,
                               ti);
  GNUNET_free (ti);
  GNUNET_SERVICE_client_continue (client->client);
}


/**
 * Handles a #GNUNET_MESSAGE_TYPE_IDENTITY_PROVIDER_TICKET_ITERATION_NEXT message
 *
 * @param cls the client sending the message
 * @param message message from the client
 */
static void
handle_ticket_iteration_next (void *cls,
                              const struct TicketIterationNextMessage *tis_msg)
{
  struct IdpClient *client = cls;
  struct TicketIteration *ti;
  uint32_t rid;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received TICKET_ITERATION_NEXT message\n");
  rid = ntohl (tis_msg->id);
  for (ti = client->ticket_iter_head; NULL != ti; ti = ti->next)
    if (ti->r_id == rid)
      break;
  if (NULL == ti)
  {
    GNUNET_break (0);
    GNUNET_SERVICE_client_drop (client->client);
    return;
  }
  run_ticket_iteration_round (ti);
  GNUNET_SERVICE_client_continue (client->client);
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
  char *database;
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

  /* Loading DB plugin */
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_string (cfg,
                                             "identity-provider",
                                             "database",
                                             &database))
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "No database backend configured\n");
  GNUNET_asprintf (&db_lib_name,
                   "libgnunet_plugin_identity_provider_%s",
                   database);
  TKT_database = GNUNET_PLUGIN_load (db_lib_name,
                                     (void *) cfg);
  GNUNET_free (database);
  if (NULL == TKT_database)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Could not load database backend `%s'\n",
                db_lib_name);
    GNUNET_SCHEDULER_shutdown ();
    return;
  }

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
  struct IdpClient *idp = app_ctx;
  struct AttributeIterator *ai;

  //TODO other operations

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Client %p disconnected\n",
              client);

  while (NULL != (ai = idp->op_head))
  {
    GNUNET_CONTAINER_DLL_remove (idp->op_head,
                                 idp->op_tail,
                                 ai);
    GNUNET_free (ai);
  }
  GNUNET_free (idp);
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
  struct IdpClient *idp;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Client %p connected\n",
              client);
  idp = GNUNET_new (struct IdpClient);
  idp->client = client;
  idp->mq = mq;
  return idp;
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
 GNUNET_MQ_hd_var_size (attribute_store_message,
                        GNUNET_MESSAGE_TYPE_IDENTITY_PROVIDER_ATTRIBUTE_STORE,
                        struct AttributeStoreMessage,
                        NULL),
 GNUNET_MQ_hd_fixed_size (iteration_start, 
                          GNUNET_MESSAGE_TYPE_IDENTITY_PROVIDER_ATTRIBUTE_ITERATION_START,
                          struct AttributeIterationStartMessage,
                          NULL),
 GNUNET_MQ_hd_fixed_size (iteration_next, 
                          GNUNET_MESSAGE_TYPE_IDENTITY_PROVIDER_ATTRIBUTE_ITERATION_NEXT,
                          struct AttributeIterationNextMessage,
                          NULL),
 GNUNET_MQ_hd_fixed_size (iteration_stop, 
                          GNUNET_MESSAGE_TYPE_IDENTITY_PROVIDER_ATTRIBUTE_ITERATION_STOP,
                          struct AttributeIterationStopMessage,
                          NULL),
 GNUNET_MQ_hd_var_size (ticket_issue_message,
                        GNUNET_MESSAGE_TYPE_IDENTITY_PROVIDER_TICKET_ISSUE,
                        struct TicketIssueMessage,
                        NULL),
 GNUNET_MQ_hd_var_size (consume_ticket_message,
                        GNUNET_MESSAGE_TYPE_IDENTITY_PROVIDER_CONSUME_TICKET,
                        struct ConsumeTicketMessage,
                        NULL),
 GNUNET_MQ_hd_fixed_size (ticket_iteration_start, 
                          GNUNET_MESSAGE_TYPE_IDENTITY_PROVIDER_TICKET_ITERATION_START,
                          struct TicketIterationStartMessage,
                          NULL),
 GNUNET_MQ_hd_fixed_size (ticket_iteration_next, 
                          GNUNET_MESSAGE_TYPE_IDENTITY_PROVIDER_TICKET_ITERATION_NEXT,
                          struct TicketIterationNextMessage,
                          NULL),
 GNUNET_MQ_hd_fixed_size (ticket_iteration_stop, 
                          GNUNET_MESSAGE_TYPE_IDENTITY_PROVIDER_TICKET_ITERATION_STOP,
                          struct TicketIterationStopMessage,
                          NULL),

 GNUNET_MQ_handler_end());
 /* end of gnunet-service-identity-provider.c */

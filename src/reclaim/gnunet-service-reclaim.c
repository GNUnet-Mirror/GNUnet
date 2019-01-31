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
 * @file src/reclaim/gnunet-service-reclaim.c
 * @brief reclaim Service
 *
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_constants.h"
#include "gnunet_protocols.h"
#include "gnunet_identity_service.h"
#include "gnunet_gnsrecord_lib.h"
#include "gnunet_namestore_service.h"
#include "gnunet_abe_lib.h"
#include "gnunet_credential_service.h"
#include "gnunet_statistics_service.h"
#include "gnunet_gns_service.h"
#include "gnunet_reclaim_plugin.h"
#include "gnunet_reclaim_attribute_lib.h"
#include "gnunet_signatures.h"
#include "reclaim.h"

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
static struct GNUNET_RECLAIM_PluginFunctions *TKT_database;

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
                       struct GNUNET_ABE_AbeMasterKey *abe_key);


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
  struct GNUNET_ABE_AbeMasterKey *abe_key;

  /**
   * Recreate master keys
   */
  int recreate;
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
  struct GNUNET_ABE_AbeMasterKey *abe_key;

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
  struct AttributeIterator *attr_iter_head;

  /**
   * Tail of the DLL of
   * Attribute iteration operations 
   * in progress initiated by this client
   */
  struct AttributeIterator *attr_iter_tail;

  /**
   * Head of DLL of ticket iteration ops
   */
  struct TicketIteration *ticket_iter_head;

  /**
   * Tail of DLL of ticket iteration ops
   */
  struct TicketIteration *ticket_iter_tail;

  /**
   * Head of DLL of ticket revocation ops
   */
  struct TicketRevocationHandle *revoke_op_head;

  /**
   * Tail of DLL of ticket revocation ops
   */
  struct TicketRevocationHandle *revoke_op_tail;

  /**
   * Head of DLL of ticket issue ops
   */
  struct TicketIssueHandle *issue_op_head;

  /**
   * Tail of DLL of ticket issue ops
   */
  struct TicketIssueHandle *issue_op_tail;

  /**
   * Head of DLL of ticket consume ops
   */
  struct ConsumeTicketHandle *consume_op_head;

  /**
   * Tail of DLL of ticket consume ops
   */
  struct ConsumeTicketHandle *consume_op_tail;

  /**
   * Head of DLL of attribute store ops
   */
  struct AttributeStoreHandle *store_op_head;

  /**
   * Tail of DLL of attribute store ops
   */
  struct AttributeStoreHandle *store_op_tail;

};

struct AttributeStoreHandle
{
  /**
   * DLL
   */
  struct AttributeStoreHandle *next;

  /**
   * DLL
   */
  struct AttributeStoreHandle *prev;

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
  struct GNUNET_ABE_AbeMasterKey *abe_key;

  /**
   * QueueEntry
   */
  struct GNUNET_NAMESTORE_QueueEntry *ns_qe;

  /**
   * The attribute to store
   */
  struct GNUNET_RECLAIM_ATTRIBUTE_Claim *claim;

  /**
   * The attribute expiration interval
   */
  struct GNUNET_TIME_Relative exp;

  /**
   * request id
   */
  uint32_t r_id;
};


/* Prototype */
struct ParallelLookup;

struct ConsumeTicketHandle
{
  /**
   * DLL
   */
  struct ConsumeTicketHandle *next;

  /**
   * DLL
   */
  struct ConsumeTicketHandle *prev;

  /**
   * Client connection
   */
  struct IdpClient *client;

  /**
   * Ticket
   */
  struct GNUNET_RECLAIM_Ticket ticket;

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
  struct ParallelLookup *parallel_lookups_head;

  /**
   * Lookup DLL
   */
  struct ParallelLookup *parallel_lookups_tail;
  
  /**
   * Kill task
   */
  struct GNUNET_SCHEDULER_Task *kill_task;

  /**
   * The ABE key
   */
  struct GNUNET_ABE_AbeKey *key;

  /**
   * Attributes
   */
  struct GNUNET_RECLAIM_ATTRIBUTE_ClaimList *attrs;
  
  /**
   * Lookup time
   */
  struct GNUNET_TIME_Absolute lookup_start_time;
 
  /**
   * request id
   */
  uint32_t r_id;
};

/**
 * Handle for a parallel GNS lookup job
 */
struct ParallelLookup
{
  /* DLL */
  struct ParallelLookup *next;

  /* DLL */
  struct ParallelLookup *prev;

  /* The GNS request */
  struct GNUNET_GNS_LookupRequest *lookup_request;

  /* The handle the return to */
  struct ConsumeTicketHandle *handle;

  /**
   * Lookup time
   */
  struct GNUNET_TIME_Absolute lookup_start_time;

  /* The label to look up */
  char *label;
};

/**
 * Ticket revocation request handle
 */
struct TicketRevocationHandle
{
  /**
   * DLL
   */
  struct TicketRevocationHandle *prev;

  /**
   * DLL
   */
  struct TicketRevocationHandle *next;

  /**
   * Client connection
   */
  struct IdpClient *client;

  /**
   * Attributes to reissue
   */
  struct GNUNET_RECLAIM_ATTRIBUTE_ClaimList *attrs;

  /**
   * Attributes to revoke
   */
  struct GNUNET_RECLAIM_ATTRIBUTE_ClaimList *rvk_attrs;

  /**
   * Issuer Key
   */
  struct GNUNET_CRYPTO_EcdsaPrivateKey identity;

  /**
   * Ticket to issue
   */
  struct GNUNET_RECLAIM_Ticket ticket;

  /**
   * QueueEntry
   */
  struct GNUNET_NAMESTORE_QueueEntry *ns_qe;

  /**
   * Namestore iterator
   */
  struct GNUNET_NAMESTORE_ZoneIterator *ns_it;

  /**
   * The ABE master key
   */
  struct GNUNET_ABE_AbeMasterKey *abe_key;

  /**
   * Offset
   */
  uint32_t offset;

  /**
   * request id
   */
  uint32_t r_id;
};



/**
 * Ticket issue request handle
 */
struct TicketIssueHandle
{
  /**
   * DLL
   */
  struct TicketIssueHandle *prev;

  /**
   * DLL
   */
  struct TicketIssueHandle *next;

  /**
   * Client connection
   */
  struct IdpClient *client;

  /**
   * Attributes to issue
   */
  struct GNUNET_RECLAIM_ATTRIBUTE_ClaimList *attrs;

  /**
   * Issuer Key
   */
  struct GNUNET_CRYPTO_EcdsaPrivateKey identity;

  /**
   * Ticket to issue
   */
  struct GNUNET_RECLAIM_Ticket ticket;

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
  GNUNET_free_non_null (token);
  GNUNET_free_non_null (label);

}

/**
 * Shutdown task
 *
 * @param cls NULL
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
 * Error checking for ABE master
 */
static void
bootstrap_abe_error (void *cls)
{
  struct AbeBootstrapHandle *abh = cls;
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
  struct GNUNET_ABE_AbeMasterKey *abe_key;

  for (uint32_t i=0;i<rd_count;i++) {
    if (GNUNET_GNSRECORD_TYPE_ABE_MASTER != rd[i].record_type)
      continue;
    if (GNUNET_YES == abh->recreate)
      continue;
    abe_key = GNUNET_ABE_cpabe_deserialize_master_key (rd[i].data,
                                                       rd[i].data_size);
    abh->proc (abh->proc_cls, abe_key);
    GNUNET_free (abh);
    return;
  }

  //No ABE master found, bootstrapping...
  abh->abe_key = GNUNET_ABE_cpabe_create_master_key ();

  {
    struct GNUNET_GNSRECORD_Data rdn[rd_count+1];
    char *key;
    unsigned int rd_count_new = rd_count + 1;

    for (uint32_t i=0;i<rd_count;i++) {
      if ((GNUNET_YES == abh->recreate) &&
          (GNUNET_GNSRECORD_TYPE_ABE_MASTER == rd[i].record_type))
      {
        rdn[i].data_size = GNUNET_ABE_cpabe_serialize_master_key (abh->abe_key,
                                                                  (void**)&key);
        rdn[i].data = key;
        rdn[i].record_type = GNUNET_GNSRECORD_TYPE_ABE_MASTER;
        rdn[i].flags = GNUNET_GNSRECORD_RF_RELATIVE_EXPIRATION | GNUNET_GNSRECORD_RF_PRIVATE;
        rdn[i].expiration_time = GNUNET_TIME_UNIT_HOURS.rel_value_us; //TODO sane?
        rd_count_new = rd_count;
      } else {
        GNUNET_memcpy (&rdn[i],
                       &rd[i],
                       sizeof (struct GNUNET_GNSRECORD_Data));
      }
    }
    if (rd_count < rd_count_new) {
      rdn[rd_count].data_size = GNUNET_ABE_cpabe_serialize_master_key (abh->abe_key,
                                                                       (void**)&key);
      rdn[rd_count].data = key;
      rdn[rd_count].record_type = GNUNET_GNSRECORD_TYPE_ABE_MASTER;
      rdn[rd_count].flags = GNUNET_GNSRECORD_RF_RELATIVE_EXPIRATION | GNUNET_GNSRECORD_RF_PRIVATE;
      rdn[rd_count].expiration_time = GNUNET_TIME_UNIT_HOURS.rel_value_us; //TODO sane?
    }

    abh->ns_qe = GNUNET_NAMESTORE_records_store (ns_handle,
                                                 &abh->identity,
                                                 GNUNET_GNS_EMPTY_LABEL_AT,
                                                 rd_count_new,
                                                 rdn,
                                                 &bootstrap_store_cont,
                                                 abh);
    GNUNET_free (key);
  }
}

/**
 * Bootstrap ABE master if it does not yet exists.
 * Will call the AbeBootstrapResult processor when done.
 * will always recreate the ABE key of GNUNET_YES == recreate
 */
static void
bootstrap_abe (const struct GNUNET_CRYPTO_EcdsaPrivateKey *identity,
               AbeBootstrapResult proc,
               void* cls,
               int recreate)
{
  struct AbeBootstrapHandle *abh;

  abh = GNUNET_new (struct AbeBootstrapHandle);
  abh->proc = proc;
  abh->proc_cls = cls;
  abh->identity = *identity;
  if (GNUNET_YES == recreate)
  {
    abh->abe_key = GNUNET_ABE_cpabe_create_master_key ();
    abh->recreate = GNUNET_YES;
  } else {
    abh->recreate = GNUNET_NO;
  }
  abh->ns_qe = GNUNET_NAMESTORE_records_lookup (ns_handle,
                                                identity,
                                                GNUNET_GNS_EMPTY_LABEL_AT,
                                                &bootstrap_abe_error,
                                                abh,
                                                &bootstrap_abe_result,
                                                abh);
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

/**
 * Cleanup ticket consume handle
 * @param handle the handle to clean up
 */
static void
cleanup_ticket_issue_handle (struct TicketIssueHandle *handle)
{
  if (NULL != handle->attrs)
    GNUNET_RECLAIM_ATTRIBUTE_list_destroy (handle->attrs);
  if (NULL != handle->ns_qe)
    GNUNET_NAMESTORE_cancel (handle->ns_qe);
  GNUNET_free (handle);
}


static void
send_ticket_result (struct IdpClient *client,
                    uint32_t r_id,
                    const struct GNUNET_RECLAIM_Ticket *ticket,
                    const struct GNUNET_RECLAIM_ATTRIBUTE_ClaimList *attrs)
{
  struct TicketResultMessage *irm;
  struct GNUNET_MQ_Envelope *env;
  struct GNUNET_RECLAIM_Ticket *ticket_buf;

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
                             sizeof (struct GNUNET_RECLAIM_Ticket),
                             GNUNET_MESSAGE_TYPE_RECLAIM_TICKET_RESULT);
  ticket_buf = (struct GNUNET_RECLAIM_Ticket *)&irm[1];
  *ticket_buf = *ticket;
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
  GNUNET_CONTAINER_DLL_remove (handle->client->issue_op_head,
                               handle->client->issue_op_tail,
                               handle);
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
serialize_abe_keyinfo2 (const struct GNUNET_RECLAIM_Ticket *ticket,
                        const struct GNUNET_RECLAIM_ATTRIBUTE_ClaimList *attrs,
                        const struct GNUNET_ABE_AbeKey *rp_key,
                        struct GNUNET_CRYPTO_EcdhePrivateKey **ecdh_privkey,
                        char **result)
{
  struct GNUNET_CRYPTO_EcdhePublicKey ecdh_pubkey;
  struct GNUNET_RECLAIM_ATTRIBUTE_ClaimListEntry *le;
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

  size = GNUNET_ABE_cpabe_serialize_key (rp_key,
                                         (void**)&serialized_key);
  attrs_str_len = 0;
  for (le = attrs->list_head; NULL != le; le = le->next) {
    attrs_str_len += strlen (le->claim->name) + 1;
  }
  buf = GNUNET_malloc (attrs_str_len + size);
  write_ptr = buf;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Writing attributes\n");
  for (le = attrs->list_head; NULL != le; le = le->next) {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "%s\n", le->claim->name);


    GNUNET_memcpy (write_ptr,
                   le->claim->name,
                   strlen (le->claim->name));
    write_ptr[strlen (le->claim->name)] = ',';
    write_ptr += strlen (le->claim->name) + 1;
  }
  write_ptr--;
  write_ptr[0] = '\0'; //replace last , with a 0-terminator
  write_ptr++;
  GNUNET_memcpy (write_ptr,
                 serialized_key,
                 size);
  GNUNET_free (serialized_key);
  // ECDH keypair E = eG
  *ecdh_privkey = GNUNET_CRYPTO_ecdhe_key_create();
  GNUNET_CRYPTO_ecdhe_key_get_public (*ecdh_privkey,
                                      &ecdh_pubkey);
  enc_keyinfo = GNUNET_malloc (size + attrs_str_len);
  // Derived key K = H(eB)
  GNUNET_assert (GNUNET_OK == GNUNET_CRYPTO_ecdh_ecdsa (*ecdh_privkey,
                                                        &ticket->audience,
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
  GNUNET_free (buf);
  return sizeof (struct GNUNET_CRYPTO_EcdhePublicKey)+enc_size;
}



static void
issue_ticket_after_abe_bootstrap (void *cls,
                                  struct GNUNET_ABE_AbeMasterKey *abe_key)
{
  struct TicketIssueHandle *ih = cls;
  struct GNUNET_RECLAIM_ATTRIBUTE_ClaimListEntry *le;
  struct GNUNET_CRYPTO_EcdhePrivateKey *ecdhe_privkey;
  struct GNUNET_GNSRECORD_Data code_record[1];
  struct GNUNET_ABE_AbeKey *rp_key;
  char *code_record_data;
  char **attrs;
  char *label;
  char *policy;
  int attrs_len;
  uint32_t i;
  size_t code_record_len;

  //Create new ABE key for RP
  attrs_len = 0;
  for (le = ih->attrs->list_head; NULL != le; le = le->next)
    attrs_len++;
  attrs = GNUNET_malloc ((attrs_len + 1)*sizeof (char*));
  i = 0;
  for (le = ih->attrs->list_head; NULL != le; le = le->next) {
    GNUNET_asprintf (&policy, "%s_%lu",
                     le->claim->name,
                     le->claim->version);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Adding attribute to key: %s\n",
                policy);
    attrs[i] = policy;
    i++;
  }
  attrs[i] = NULL;
  rp_key = GNUNET_ABE_cpabe_create_key (abe_key,
                                        attrs);

  //TODO review this wireformat
  code_record_len = serialize_abe_keyinfo2 (&ih->ticket,
                                            ih->attrs,
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
  //for (; i > 0; i--)
  //  GNUNET_free (attrs[i-1]);
  GNUNET_free (ecdhe_privkey);
  GNUNET_free (label);
  GNUNET_free (attrs);
  GNUNET_free (code_record_data);
  GNUNET_ABE_cpabe_delete_key (rp_key,
                               GNUNET_YES);
  GNUNET_ABE_cpabe_delete_master_key (abe_key);
}


static int
check_issue_ticket_message(void *cls,
                           const struct IssueTicketMessage *im)
{
  uint16_t size;

  size = ntohs (im->header.size);
  if (size <= sizeof (struct IssueTicketMessage))
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


static void
handle_issue_ticket_message (void *cls,
                             const struct IssueTicketMessage *im)
{
  struct TicketIssueHandle *ih;
  struct IdpClient *idp = cls;
  size_t attrs_len;

  ih = GNUNET_new (struct TicketIssueHandle);
  attrs_len = ntohs (im->attr_len);
  ih->attrs = GNUNET_RECLAIM_ATTRIBUTE_list_deserialize ((char*)&im[1], attrs_len);
  ih->r_id = ntohl (im->id);
  ih->client = idp;
  ih->identity = im->identity;
  GNUNET_CRYPTO_ecdsa_key_get_public (&ih->identity,
                                      &ih->ticket.identity);
  ih->ticket.audience = im->rp;
  ih->ticket.rnd =
    GNUNET_CRYPTO_random_u64 (GNUNET_CRYPTO_QUALITY_STRONG,
                              UINT64_MAX);
  GNUNET_CONTAINER_DLL_insert (idp->issue_op_head,
                               idp->issue_op_tail,
                               ih);
  bootstrap_abe (&ih->identity, &issue_ticket_after_abe_bootstrap, ih, GNUNET_NO);
  GNUNET_SERVICE_client_continue (idp->client);

}

/**********************************************************
 * Revocation
 **********************************************************/

/**
 * Cleanup revoke handle
 *
 * @param rh the ticket revocation handle
 */
static void
cleanup_revoke_ticket_handle (struct TicketRevocationHandle *rh)
{
  if (NULL != rh->attrs)
    GNUNET_RECLAIM_ATTRIBUTE_list_destroy (rh->attrs);
  if (NULL != rh->rvk_attrs)
    GNUNET_RECLAIM_ATTRIBUTE_list_destroy (rh->rvk_attrs);
  if (NULL != rh->abe_key)
    GNUNET_ABE_cpabe_delete_master_key (rh->abe_key);
  if (NULL != rh->ns_qe)
    GNUNET_NAMESTORE_cancel (rh->ns_qe);
  if (NULL != rh->ns_it)
    GNUNET_NAMESTORE_zone_iteration_stop (rh->ns_it);
  GNUNET_free (rh);
}


/**
 * Send revocation result
 *
 * @param rh ticket revocation handle
 * @param success GNUNET_OK if successful result
 */
static void
send_revocation_finished (struct TicketRevocationHandle *rh,
                          uint32_t success)
{
  struct GNUNET_MQ_Envelope *env;
  struct RevokeTicketResultMessage *trm;

  GNUNET_break(TKT_database->delete_ticket (TKT_database->cls,
                                            &rh->ticket));

  env = GNUNET_MQ_msg (trm,
                       GNUNET_MESSAGE_TYPE_RECLAIM_REVOKE_TICKET_RESULT);
  trm->id = htonl (rh->r_id);
  trm->success = htonl (success);
  GNUNET_MQ_send (rh->client->mq,
                  env);
  GNUNET_CONTAINER_DLL_remove (rh->client->revoke_op_head,
                               rh->client->revoke_op_tail,
                               rh);
}


/**
 * Process ticket from database
 *
 * @param cls struct TicketIterationProcResult
 * @param ticket the ticket
 * @param attrs the attributes
 */
static void
ticket_reissue_proc (void *cls,
                     const struct GNUNET_RECLAIM_Ticket *ticket,
                     const struct GNUNET_RECLAIM_ATTRIBUTE_ClaimList *attrs);

static void
revocation_reissue_tickets (struct TicketRevocationHandle *rh);


static void reissue_next (void *cls)
{
  struct TicketRevocationHandle *rh = cls;
  revocation_reissue_tickets (rh);
}


static void
reissue_ticket_cont (void *cls,
                     int32_t success,
                     const char *emsg)
{
  struct TicketRevocationHandle *rh = cls;

  rh->ns_qe = NULL;
  if (GNUNET_SYSERR == success)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "%s\n",
                "Unknown Error\n");
    send_revocation_finished (rh, GNUNET_SYSERR);
    cleanup_revoke_ticket_handle (rh);
    return;
  }
  rh->offset++;
  GNUNET_SCHEDULER_add_now (&reissue_next, rh);
}


/**
 * Process ticket from database
 *
 * @param cls struct TicketIterationProcResult
 * @param ticket the ticket
 * @param attrs the attributes
 */
static void
ticket_reissue_proc (void *cls,
                     const struct GNUNET_RECLAIM_Ticket *ticket,
                     const struct GNUNET_RECLAIM_ATTRIBUTE_ClaimList *attrs)
{
  struct TicketRevocationHandle *rh = cls;
  struct GNUNET_RECLAIM_ATTRIBUTE_ClaimListEntry *le;
  struct GNUNET_RECLAIM_ATTRIBUTE_ClaimListEntry *le_rollover;
  struct GNUNET_CRYPTO_EcdhePrivateKey *ecdhe_privkey;
  struct GNUNET_GNSRECORD_Data code_record[1];
  struct GNUNET_ABE_AbeKey *rp_key;
  char *code_record_data;
  char **attr_arr;
  char *label;
  char *policy;
  int attrs_len;
  uint32_t i;
  int reissue_ticket;
  size_t code_record_len;


  if (NULL == ticket)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Iteration done\n");
    return;
  }

  if (0 == memcmp (&ticket->audience,
                   &rh->ticket.audience,
                   sizeof (struct GNUNET_CRYPTO_EcdsaPublicKey)))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Do not reissue for this identity.!\n");
    label = GNUNET_STRINGS_data_to_string_alloc (&rh->ticket.rnd,
                                                 sizeof (uint64_t));
    //Delete record
    rh->ns_qe = GNUNET_NAMESTORE_records_store (ns_handle,
                                                &rh->identity,
                                                label,
                                                0,
                                                NULL,
                                                &reissue_ticket_cont,
                                                rh);

    GNUNET_free (label);
    return;
  }

  /* 
   * Check if any attribute of this ticket intersects with a rollover attribute
   */
  reissue_ticket = GNUNET_NO;
  for (le = attrs->list_head; NULL != le; le = le->next)
  {
    for (le_rollover = rh->rvk_attrs->list_head;
         NULL != le_rollover;
         le_rollover = le_rollover->next)
    {
      if (0 == strcmp (le_rollover->claim->name,
                       le->claim->name))
      {
        reissue_ticket = GNUNET_YES;
        le->claim->version = le_rollover->claim->version;
      }
    }
  }

  if (GNUNET_NO == reissue_ticket)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Skipping ticket.\n");

    rh->offset++;
    GNUNET_SCHEDULER_add_now (&reissue_next, rh);


    return;
  }

  //Create new ABE key for RP
  attrs_len = 0;

  /* If this is the RP we want to revoke attributes of, the do so */

  for (le = attrs->list_head; NULL != le; le = le->next)
    attrs_len++;
  attr_arr = GNUNET_malloc ((attrs_len + 1)*sizeof (char*));
  i = 0;
  for (le = attrs->list_head; NULL != le; le = le->next) {
    GNUNET_asprintf (&policy, "%s_%lu",
                     le->claim->name,
                     le->claim->version);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Recreating key with %s\n", policy);
    attr_arr[i] = policy;
    i++;
  }
  attr_arr[i] = NULL;
  rp_key = GNUNET_ABE_cpabe_create_key (rh->abe_key,
                                        attr_arr);

  //TODO review this wireformat
  code_record_len = serialize_abe_keyinfo2 (ticket,
                                            attrs,
                                            rp_key,
                                            &ecdhe_privkey,
                                            &code_record_data);
  code_record[0].data = code_record_data;
  code_record[0].data_size = code_record_len;
  code_record[0].expiration_time = GNUNET_TIME_UNIT_DAYS.rel_value_us;
  code_record[0].record_type = GNUNET_GNSRECORD_TYPE_ABE_KEY;
  code_record[0].flags = GNUNET_GNSRECORD_RF_RELATIVE_EXPIRATION;

  label = GNUNET_STRINGS_data_to_string_alloc (&ticket->rnd,
                                               sizeof (uint64_t));
  //Publish record
  rh->ns_qe = GNUNET_NAMESTORE_records_store (ns_handle,
                                              &rh->identity,
                                              label,
                                              1,
                                              code_record,
                                              &reissue_ticket_cont,
                                              rh);
  //for (; i > 0; i--)
  //  GNUNET_free (attr_arr[i-1]);
  GNUNET_free (ecdhe_privkey);
  GNUNET_free (label);
  GNUNET_free (attr_arr);
  GNUNET_free (code_record_data);
  GNUNET_ABE_cpabe_delete_key (rp_key, GNUNET_YES);
}


/* Prototype for below function */
static void
attr_reenc_cont (void *cls,
                 int32_t success,
                 const char *emsg);

static void
revocation_reissue_tickets (struct TicketRevocationHandle *rh)
{
  int ret;
  /* Done, issue new keys */
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Revocation Phase III: Reissuing Tickets\n");
  if (GNUNET_SYSERR == (ret = TKT_database->iterate_tickets (TKT_database->cls,
                                                             &rh->ticket.identity,
                                                             GNUNET_NO,
                                                             rh->offset,
                                                             &ticket_reissue_proc,
                                                             rh)))
  {
    GNUNET_break (0);
  }
  if (GNUNET_NO == ret)
  {
    send_revocation_finished (rh, GNUNET_OK);
    cleanup_revoke_ticket_handle (rh);
    return;
  }
}

/**
 * Failed to check for attribute
 */
static void
check_attr_error (void *cls)
{
  struct TicketRevocationHandle *rh = cls;
  GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
              "Unable to check for existing attribute\n");
  rh->ns_qe = NULL;
  send_revocation_finished (rh, GNUNET_SYSERR);
  cleanup_revoke_ticket_handle (rh);
}


/**
 * Revoke next attribte by reencryption with
 * new ABE master
 */
static void
reenc_next_attribute (void *cls);

/**
 * Check for existing attribute and overwrite
 */
static void
check_attr_cb (void *cls,
               const struct GNUNET_CRYPTO_EcdsaPrivateKey *zone,
               const char *label,
               unsigned int rd_count,
               const struct GNUNET_GNSRECORD_Data *rd_old)
{
  struct TicketRevocationHandle *rh = cls;
  struct GNUNET_GNSRECORD_Data rd[1];
  char* buf;
  char* enc_buf;
  size_t enc_size;
  char* rd_buf;
  size_t buf_size;
  char* policy;
  uint32_t attr_ver;

  rh->ns_qe = NULL;
  if (1 != rd_count) {
    GNUNET_SCHEDULER_add_now (&reenc_next_attribute,
                              rh);
    return;
  }

  buf_size = GNUNET_RECLAIM_ATTRIBUTE_serialize_get_size (rh->attrs->list_head->claim);
  buf = GNUNET_malloc (buf_size);
  rh->attrs->list_head->claim->version++;
  GNUNET_RECLAIM_ATTRIBUTE_serialize (rh->attrs->list_head->claim,
                                      buf);
  GNUNET_asprintf (&policy, "%s_%lu",
                   rh->attrs->list_head->claim->name,
                   rh->attrs->list_head->claim->version);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Encrypting with policy %s\n", policy);
  /**
   * Encrypt the attribute value and store in namestore
   */
  enc_size = GNUNET_ABE_cpabe_encrypt (buf,
                                       buf_size,
                                       policy, //Policy
                                       rh->abe_key,
                                       (void**)&enc_buf);
  GNUNET_free (buf);
  if (GNUNET_SYSERR == enc_size)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Unable to re-encrypt with policy %s\n",
                policy);
    GNUNET_free (policy);
    send_revocation_finished (rh, GNUNET_SYSERR);
    cleanup_revoke_ticket_handle (rh);
    return;
  }
  GNUNET_free (policy);

  rd[0].data_size = enc_size + sizeof (uint32_t);
  rd_buf = GNUNET_malloc (rd[0].data_size);
  attr_ver = htonl (rh->attrs->list_head->claim->version);
  GNUNET_memcpy (rd_buf,
                 &attr_ver,
                 sizeof (uint32_t));
  GNUNET_memcpy (rd_buf+sizeof (uint32_t),
                 enc_buf,
                 enc_size);
  rd[0].data = rd_buf;
  rd[0].record_type = GNUNET_GNSRECORD_TYPE_ID_ATTR;
  rd[0].flags = GNUNET_GNSRECORD_RF_RELATIVE_EXPIRATION;
  rd[0].expiration_time = rd_old[0].expiration_time;
  rh->ns_qe = GNUNET_NAMESTORE_records_store (ns_handle,
                                              &rh->identity,
                                              rh->attrs->list_head->claim->name,
                                              1,
                                              rd,
                                              &attr_reenc_cont,
                                              rh);
  GNUNET_free (enc_buf);
  GNUNET_free (rd_buf);
}


/**
 * Revoke next attribte by reencryption with
 * new ABE master
 */
static void
reenc_next_attribute (void *cls)
{
  struct TicketRevocationHandle *rh = cls;
  if (NULL == rh->attrs->list_head)
  {
    revocation_reissue_tickets (rh);
    return;
  }
  /* First check if attribute still exists */
  rh->ns_qe = GNUNET_NAMESTORE_records_lookup (ns_handle,
                                               &rh->identity,
                                               rh->attrs->list_head->claim->name,
                                               &check_attr_error,
                                               rh,
                                               &check_attr_cb,
                                               rh);
}


/**
 * Namestore callback after revoked attribute
 * is stored
 */
static void
attr_reenc_cont (void *cls,
                 int32_t success,
                 const char *emsg)
{
  struct TicketRevocationHandle *rh = cls;
  struct GNUNET_RECLAIM_ATTRIBUTE_ClaimListEntry *le;

  rh->ns_qe = NULL;
  if (GNUNET_SYSERR == success)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Failed to reencrypt attribute %s\n",
                emsg);
    GNUNET_SCHEDULER_add_now (&do_shutdown, NULL);
    return;
  }
  if (NULL == rh->attrs->list_head)
  {
    revocation_reissue_tickets (rh);
    return;
  }
  le = rh->attrs->list_head;
  GNUNET_CONTAINER_DLL_remove (rh->attrs->list_head,
                               rh->attrs->list_tail,
                               le);
  GNUNET_assert (NULL != rh->rvk_attrs);
  GNUNET_CONTAINER_DLL_insert (rh->rvk_attrs->list_head,
                               rh->rvk_attrs->list_tail,
                               le);


  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Re-encrypting next attribute\n");
  reenc_next_attribute (rh);
}


static void
process_attributes_to_update (void *cls,
                              const struct GNUNET_RECLAIM_Ticket *ticket,
                              const struct GNUNET_RECLAIM_ATTRIBUTE_ClaimList *attrs)
{
  struct TicketRevocationHandle *rh = cls;

  rh->attrs = GNUNET_RECLAIM_ATTRIBUTE_list_dup (attrs);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Revocation Phase I: Collecting attributes\n");
  /* Reencrypt all attributes with new key */
  if (NULL == rh->attrs->list_head)
  {
    /* No attributes to reencrypt */
    send_revocation_finished (rh, GNUNET_OK);
    cleanup_revoke_ticket_handle (rh);
    return;
  } else {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Revocation Phase II: Re-encrypting attributes\n");
    reenc_next_attribute (rh);
  }

}



static void
get_ticket_after_abe_bootstrap (void *cls,
                                struct GNUNET_ABE_AbeMasterKey *abe_key)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Finished ABE bootstrap\n");
  struct TicketRevocationHandle *rh = cls;
  rh->abe_key = abe_key;
  TKT_database->get_ticket_attributes (TKT_database->cls,
                                       &rh->ticket,
                                       &process_attributes_to_update,
                                       rh);
}

static int
check_revoke_ticket_message(void *cls,
                            const struct RevokeTicketMessage *im)
{
  uint16_t size;

  size = ntohs (im->header.size);
  if (size <= sizeof (struct RevokeTicketMessage))
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}

static void
handle_revoke_ticket_message (void *cls,
                              const struct RevokeTicketMessage *rm)
{
  struct TicketRevocationHandle *rh;
  struct IdpClient *idp = cls;
  struct GNUNET_RECLAIM_Ticket *ticket;

  rh = GNUNET_new (struct TicketRevocationHandle);
  ticket = (struct GNUNET_RECLAIM_Ticket*)&rm[1];
  rh->rvk_attrs = GNUNET_new (struct GNUNET_RECLAIM_ATTRIBUTE_ClaimList);
  rh->ticket = *ticket;
  rh->r_id = ntohl (rm->id);
  rh->client = idp;
  rh->identity = rm->identity;
  GNUNET_CRYPTO_ecdsa_key_get_public (&rh->identity,
                                      &rh->ticket.identity);
  GNUNET_CONTAINER_DLL_insert (idp->revoke_op_head,
                               idp->revoke_op_tail,
                               rh);
  bootstrap_abe (&rh->identity, &get_ticket_after_abe_bootstrap, rh, GNUNET_NO);
  GNUNET_SERVICE_client_continue (idp->client);

}

/**
 * Cleanup ticket consume handle
 * @param handle the handle to clean up
 */
static void
cleanup_consume_ticket_handle (struct ConsumeTicketHandle *handle)
{
  struct ParallelLookup *lu;  
  struct ParallelLookup *tmp;
  if (NULL != handle->lookup_request)
    GNUNET_GNS_lookup_cancel (handle->lookup_request);
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

  if (NULL != handle->key)
    GNUNET_ABE_cpabe_delete_key (handle->key,
                                 GNUNET_YES);
  if (NULL != handle->attrs)
    GNUNET_RECLAIM_ATTRIBUTE_list_destroy (handle->attrs);
  GNUNET_free (handle);
}



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
  struct ParallelLookup *parallel_lookup = cls;
  struct ConsumeTicketHandle *handle = parallel_lookup->handle;
  struct ConsumeTicketResultMessage *crm;
  struct GNUNET_MQ_Envelope *env;
  struct GNUNET_RECLAIM_ATTRIBUTE_ClaimListEntry *attr_le;
  struct GNUNET_TIME_Absolute decrypt_duration;
  char *data;
  char *data_tmp;
  ssize_t attr_len;
  size_t attrs_len;

  GNUNET_CONTAINER_DLL_remove (handle->parallel_lookups_head,
                               handle->parallel_lookups_tail,
                               parallel_lookup);
  GNUNET_free (parallel_lookup->label);

  GNUNET_STATISTICS_update (stats,
                            "attribute_lookup_time_total",
                            GNUNET_TIME_absolute_get_duration (parallel_lookup->lookup_start_time).rel_value_us,
                            GNUNET_YES);
  GNUNET_STATISTICS_update (stats,
                            "attribute_lookups_count",
                            1,
                            GNUNET_YES);


  GNUNET_free (parallel_lookup);
  if (1 != rd_count)
    GNUNET_break(0);//TODO
  if (rd->record_type == GNUNET_GNSRECORD_TYPE_ID_ATTR)
  {
    decrypt_duration = GNUNET_TIME_absolute_get ();
    attr_len = GNUNET_ABE_cpabe_decrypt (rd->data + sizeof (uint32_t),
                                         rd->data_size - sizeof (uint32_t),
                                         handle->key,
                                         (void**)&data);
    if (GNUNET_SYSERR != attr_len) 
    {
      GNUNET_STATISTICS_update (stats,
                                "abe_decrypt_time_total",
                                GNUNET_TIME_absolute_get_duration (decrypt_duration).rel_value_us,
                                GNUNET_YES);
      GNUNET_STATISTICS_update (stats,
                                "abe_decrypt_count",
                                1,
                                GNUNET_YES);

      attr_le = GNUNET_new (struct GNUNET_RECLAIM_ATTRIBUTE_ClaimListEntry);
      attr_le->claim = GNUNET_RECLAIM_ATTRIBUTE_deserialize (data,
                                                             attr_len);
      attr_le->claim->version = ntohl(*(uint32_t*)rd->data);
      GNUNET_CONTAINER_DLL_insert (handle->attrs->list_head,
                                   handle->attrs->list_tail,
                                   attr_le);
      GNUNET_free (data);
    }
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
  attrs_len = GNUNET_RECLAIM_ATTRIBUTE_list_serialize_get_size (handle->attrs);
  env = GNUNET_MQ_msg_extra (crm,
                             attrs_len,
                             GNUNET_MESSAGE_TYPE_RECLAIM_CONSUME_TICKET_RESULT);
  crm->id = htonl (handle->r_id);
  crm->attrs_len = htons (attrs_len);
  crm->identity = handle->ticket.identity;
  data_tmp = (char *) &crm[1];
  GNUNET_RECLAIM_ATTRIBUTE_list_serialize (handle->attrs,
                                           data_tmp);
  GNUNET_MQ_send (handle->client->mq, env);
  GNUNET_CONTAINER_DLL_remove (handle->client->consume_op_head,
                               handle->client->consume_op_tail,
                               handle);
  cleanup_consume_ticket_handle (handle);
}

void
abort_parallel_lookups2 (void *cls)
{
  struct ConsumeTicketHandle *handle = cls;
  struct ParallelLookup *lu;
  struct ParallelLookup *tmp;
  struct AttributeResultMessage *arm;
  struct GNUNET_MQ_Envelope *env;

  handle->kill_task = NULL;
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
                       GNUNET_MESSAGE_TYPE_RECLAIM_ATTRIBUTE_RESULT);
  arm->id = htonl (handle->r_id);
  arm->attr_len = htons (0);
  GNUNET_MQ_send (handle->client->mq, env);

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
  struct ParallelLookup *parallel_lookup;
  size_t size;
  char *buf;
  char *scope;

  handle->lookup_request = NULL;
  if (1 != rd_count)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Number of keys %d != 1.",
                rd_count);
    cleanup_consume_ticket_handle (handle);
    GNUNET_CONTAINER_DLL_remove (handle->client->consume_op_head,
                                 handle->client->consume_op_tail,
                                 handle);
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
  GNUNET_STATISTICS_update (stats,
                            "abe_key_lookup_time_total",
                            GNUNET_TIME_absolute_get_duration (handle->lookup_start_time).rel_value_us,
                            GNUNET_YES);
  GNUNET_STATISTICS_update (stats,
                            "abe_key_lookups_count",
                            1,
                            GNUNET_YES);
  scopes = GNUNET_strdup (buf);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Scopes %s\n", scopes);
  handle->key = GNUNET_ABE_cpabe_deserialize_key ((void*)(buf + strlen (scopes) + 1),
                                                  rd->data_size - sizeof (struct GNUNET_CRYPTO_EcdhePublicKey)
                                                  - strlen (scopes) - 1);

  for (scope = strtok (scopes, ","); NULL != scope; scope = strtok (NULL, ","))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Looking up %s\n", scope);
    parallel_lookup = GNUNET_new (struct ParallelLookup);
    parallel_lookup->handle = handle;
    parallel_lookup->label = GNUNET_strdup (scope);
    parallel_lookup->lookup_start_time = GNUNET_TIME_absolute_get();
    parallel_lookup->lookup_request
      = GNUNET_GNS_lookup (gns_handle,
                           scope,
                           &handle->ticket.identity,
                           GNUNET_GNSRECORD_TYPE_ID_ATTR,
                           GNUNET_GNS_LO_DEFAULT,
                           &process_parallel_lookup2,
                           parallel_lookup);
    GNUNET_CONTAINER_DLL_insert (handle->parallel_lookups_head,
                                 handle->parallel_lookups_tail,
                                 parallel_lookup);
  }
  GNUNET_free (scopes);
  GNUNET_free (buf);
  handle->kill_task = GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_MINUTES,3),
                                                    &abort_parallel_lookups2,
                                                    handle);
}


static void
handle_consume_ticket_message (void *cls,
                               const struct ConsumeTicketMessage *cm)
{
  struct ConsumeTicketHandle *ch;
  struct IdpClient *idp = cls;
  char* rnd_label;

  ch = GNUNET_new (struct ConsumeTicketHandle);
  ch->r_id = ntohl (cm->id);
  ch->client = idp;
  ch->identity = cm->identity;
  ch->attrs = GNUNET_new (struct GNUNET_RECLAIM_ATTRIBUTE_ClaimList);
  GNUNET_CRYPTO_ecdsa_key_get_public (&ch->identity,
                                      &ch->identity_pub);
  ch->ticket = *((struct GNUNET_RECLAIM_Ticket*)&cm[1]);
  rnd_label = GNUNET_STRINGS_data_to_string_alloc (&ch->ticket.rnd,
                                                   sizeof (uint64_t));
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Looking for ABE key under %s\n", rnd_label);
  ch->lookup_start_time = GNUNET_TIME_absolute_get ();
  ch->lookup_request
    = GNUNET_GNS_lookup (gns_handle,
                         rnd_label,
                         &ch->ticket.identity,
                         GNUNET_GNSRECORD_TYPE_ABE_KEY,
                         GNUNET_GNS_LO_DEFAULT,
                         &process_consume_abe_key,
                         ch);
  GNUNET_CONTAINER_DLL_insert (idp->consume_op_head,
                               idp->consume_op_tail,
                               ch);
  GNUNET_free (rnd_label);
  GNUNET_SERVICE_client_continue (idp->client);
}

/**
 * Cleanup attribute store handle
 *
 * @param handle handle to clean up
 */
static void
cleanup_as_handle (struct AttributeStoreHandle *handle)
{
  if (NULL != handle->ns_qe)
    GNUNET_NAMESTORE_cancel (handle->ns_qe);
  if (NULL != handle->claim)
    GNUNET_free (handle->claim);
  if (NULL != handle->abe_key)
    GNUNET_ABE_cpabe_delete_master_key (handle->abe_key);
  GNUNET_free (handle);
}

static void
attr_store_cont (void *cls,
                 int32_t success,
                 const char *emsg)
{
  struct AttributeStoreHandle *as_handle = cls;
  struct GNUNET_MQ_Envelope *env;
  struct AttributeStoreResultMessage *acr_msg;

  as_handle->ns_qe = NULL;
  GNUNET_CONTAINER_DLL_remove (as_handle->client->store_op_head,
                               as_handle->client->store_op_tail,
                               as_handle);

  if (GNUNET_SYSERR == success)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Failed to store attribute %s\n",
                emsg);
    cleanup_as_handle (as_handle);
    GNUNET_SCHEDULER_add_now (&do_shutdown, NULL);
    return;
  }

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Sending ATTRIBUTE_STORE_RESPONSE message\n");
  env = GNUNET_MQ_msg (acr_msg,
                       GNUNET_MESSAGE_TYPE_RECLAIM_ATTRIBUTE_STORE_RESPONSE);
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
  char* policy;
  char* enc_buf;
  char* rd_buf;
  size_t enc_size;
  size_t buf_size;
  uint32_t attr_ver;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Storing attribute\n");
  buf_size = GNUNET_RECLAIM_ATTRIBUTE_serialize_get_size (as_handle->claim);
  buf = GNUNET_malloc (buf_size);

  GNUNET_RECLAIM_ATTRIBUTE_serialize (as_handle->claim,
                                      buf);

  GNUNET_asprintf (&policy,
                   "%s_%lu",
                   as_handle->claim->name,
                   as_handle->claim->version);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Encrypting with policy %s\n", policy);
  /**
   * Encrypt the attribute value and store in namestore
   */
  enc_size = GNUNET_ABE_cpabe_encrypt (buf,
                                       buf_size,
                                       policy, //Policy
                                       as_handle->abe_key,
                                       (void**)&enc_buf);
  if (GNUNET_SYSERR == enc_size)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Failed to encrypt with policy %s\n",
                policy);
    GNUNET_CONTAINER_DLL_remove (as_handle->client->store_op_head,
                                 as_handle->client->store_op_tail,
                                 as_handle);

    cleanup_as_handle (as_handle);
    GNUNET_free (buf);
    GNUNET_free (policy);
    GNUNET_SCHEDULER_add_now (&do_shutdown, NULL);
    return;
  }
  GNUNET_free (buf);
  GNUNET_free (policy);
  rd[0].data_size = enc_size + sizeof (uint32_t);
  rd_buf = GNUNET_malloc (rd[0].data_size);
  attr_ver = htonl (as_handle->claim->version);
  GNUNET_memcpy (rd_buf,
                 &attr_ver,
                 sizeof (uint32_t));
  GNUNET_memcpy (rd_buf+sizeof (uint32_t),
                 enc_buf,
                 enc_size);
  rd[0].data = rd_buf;
  rd[0].record_type = GNUNET_GNSRECORD_TYPE_ID_ATTR;
  rd[0].flags = GNUNET_GNSRECORD_RF_RELATIVE_EXPIRATION;
  rd[0].expiration_time = as_handle->exp.rel_value_us;
  as_handle->ns_qe = GNUNET_NAMESTORE_records_store (ns_handle,
                                                     &as_handle->identity,
                                                     as_handle->claim->name,
                                                     1,
                                                     rd,
                                                     &attr_store_cont,
                                                     as_handle);
  GNUNET_free (enc_buf);
  GNUNET_free (rd_buf);
}


static void
store_after_abe_bootstrap (void *cls,
                           struct GNUNET_ABE_AbeMasterKey *abe_key)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Finished ABE bootstrap\n");
  struct AttributeStoreHandle *ash = cls;
  ash->abe_key = abe_key;
  GNUNET_SCHEDULER_add_now (&attr_store_task, ash);
}

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
  as_handle->claim = GNUNET_RECLAIM_ATTRIBUTE_deserialize ((char*)&sam[1],
                                                           data_len);

  as_handle->r_id = ntohl (sam->id);
  as_handle->identity = sam->identity;
  as_handle->exp.rel_value_us = GNUNET_ntohll (sam->exp);
  GNUNET_CRYPTO_ecdsa_key_get_public (&sam->identity,
                                      &as_handle->identity_pkey);

  GNUNET_SERVICE_client_continue (idp->client);
  as_handle->client = idp;
  GNUNET_CONTAINER_DLL_insert (idp->store_op_head,
                               idp->store_op_tail,
                               as_handle);
  bootstrap_abe (&as_handle->identity, &store_after_abe_bootstrap, as_handle, GNUNET_NO);
}

static void
cleanup_attribute_iter_handle (struct AttributeIterator *ai)
{
  if (NULL != ai->abe_key)
    GNUNET_ABE_cpabe_delete_master_key (ai->abe_key);
  GNUNET_free (ai);
}

static void
attr_iter_error (void *cls)
{
  struct AttributeIterator *ai = cls;
  //TODO
  GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
              "Failed to iterate over attributes\n");
  GNUNET_CONTAINER_DLL_remove (ai->client->attr_iter_head,
                               ai->client->attr_iter_tail,
                               ai);
  cleanup_attribute_iter_handle (ai);
  GNUNET_SCHEDULER_add_now (&do_shutdown, NULL);
}

static void
attr_iter_finished (void *cls)
{
  struct AttributeIterator *ai = cls;
  struct GNUNET_MQ_Envelope *env;
  struct AttributeResultMessage *arm;

  env = GNUNET_MQ_msg (arm,
                       GNUNET_MESSAGE_TYPE_RECLAIM_ATTRIBUTE_RESULT);
  arm->id = htonl (ai->request_id);
  arm->attr_len = htons (0);
  GNUNET_MQ_send (ai->client->mq, env);
  GNUNET_CONTAINER_DLL_remove (ai->client->attr_iter_head,
                               ai->client->attr_iter_tail,
                               ai);
  cleanup_attribute_iter_handle (ai);
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
  struct GNUNET_ABE_AbeKey *key;
  struct GNUNET_MQ_Envelope *env;
  ssize_t msg_extra_len;
  char* attr_ser;
  char* attrs[2];
  char* data_tmp;
  char* policy;
  uint32_t attr_ver;

  if (rd_count != 1)
  {
    GNUNET_NAMESTORE_zone_iterator_next (ai->ns_it,
                                         1);
    return;
  }

  if (GNUNET_GNSRECORD_TYPE_ID_ATTR != rd->record_type)
  {
    GNUNET_NAMESTORE_zone_iterator_next (ai->ns_it,
                                         1);
    return;
  }
  attr_ver = ntohl(*((uint32_t*)rd->data));
  GNUNET_asprintf (&policy, "%s_%lu",
                   label, attr_ver);
  attrs[0] = policy;
  attrs[1] = 0;
  key = GNUNET_ABE_cpabe_create_key (ai->abe_key,
                                     attrs);
  msg_extra_len = GNUNET_ABE_cpabe_decrypt (rd->data+sizeof (uint32_t),
                                            rd->data_size-sizeof (uint32_t),
                                            key,
                                            (void**)&attr_ser);
  if (GNUNET_SYSERR == msg_extra_len)
  {
    GNUNET_NAMESTORE_zone_iterator_next (ai->ns_it,
                                         1);
    return;
  }

  GNUNET_ABE_cpabe_delete_key (key,
                               GNUNET_YES);
  //GNUNET_free (policy);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Found attribute: %s\n", label);
  env = GNUNET_MQ_msg_extra (arm,
                             msg_extra_len,
                             GNUNET_MESSAGE_TYPE_RECLAIM_ATTRIBUTE_RESULT);
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
  GNUNET_ABE_cpabe_delete_master_key (ai->abe_key);
  ai->abe_key = NULL;
}


void
iterate_after_abe_bootstrap (void *cls,
                             struct GNUNET_ABE_AbeMasterKey *abe_key)
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


static void
iterate_next_after_abe_bootstrap (void *cls,
                                  struct GNUNET_ABE_AbeMasterKey *abe_key)
{
  struct AttributeIterator *ai = cls;
  ai->abe_key = abe_key;
  GNUNET_NAMESTORE_zone_iterator_next (ai->ns_it,
                                       1);
}



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

  GNUNET_CONTAINER_DLL_insert (idp->attr_iter_head,
                               idp->attr_iter_tail,
                               ai);
  bootstrap_abe (&ai->identity, &iterate_after_abe_bootstrap, ai, GNUNET_NO);
  GNUNET_SERVICE_client_continue (idp->client);
}


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
  for (ai = idp->attr_iter_head; NULL != ai; ai = ai->next)
    if (ai->request_id == rid)
      break;
  if (NULL == ai)
  {
    GNUNET_break (0);
    GNUNET_SERVICE_client_drop (idp->client);
    return;
  }
  GNUNET_CONTAINER_DLL_remove (idp->attr_iter_head,
                               idp->attr_iter_tail,
                               ai);
  GNUNET_free (ai);
  GNUNET_SERVICE_client_continue (idp->client);
}


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
  for (ai = idp->attr_iter_head; NULL != ai; ai = ai->next)
    if (ai->request_id == rid)
      break;
  if (NULL == ai)
  {
    GNUNET_break (0);
    GNUNET_SERVICE_client_drop (idp->client);
    return;
  }
  bootstrap_abe (&ai->identity,
                 &iterate_next_after_abe_bootstrap,
                 ai,
                 GNUNET_NO);
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

static void
cleanup_ticket_iter_handle (struct TicketIteration *ti)
{
  GNUNET_free (ti);
}

/**
 * Process ticket from database
 *
 * @param cls struct TicketIterationProcResult
 * @param ticket the ticket
 * @param attrs the attributes
 */
static void
ticket_iterate_proc (void *cls,
                     const struct GNUNET_RECLAIM_Ticket *ticket,
                     const struct GNUNET_RECLAIM_ATTRIBUTE_ClaimList *attrs)
{
  struct TicketIterationProcResult *proc = cls;

  if (NULL == ticket)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Iteration done\n");
    proc->res_iteration_finished = IT_SUCCESS_NOT_MORE_RESULTS_AVAILABLE;
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
                       GNUNET_MESSAGE_TYPE_RECLAIM_TICKET_RESULT);
  trm->id = htonl (ti->r_id);
  GNUNET_MQ_send (ti->client->mq,
                  env);
  GNUNET_CONTAINER_DLL_remove (ti->client->ticket_iter_head,
                               ti->client->ticket_iter_tail,
                               ti);
  cleanup_ticket_iter_handle (ti);
}

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
  cleanup_ticket_iter_handle (ti);
  GNUNET_SERVICE_client_continue (client->client);
}


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
 * @param c the configuration used 
 * @param server the service handle
 */
static void
run (void *cls,
     const struct GNUNET_CONFIGURATION_Handle *c,
     struct GNUNET_SERVICE_Handle *server)
{
  char *database;
  cfg = c;

  stats = GNUNET_STATISTICS_create ("reclaim", cfg);

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
                                             "reclaim",
                                             "database",
                                             &database))
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "No database backend configured\n");
  GNUNET_asprintf (&db_lib_name,
                   "libgnunet_plugin_reclaim_%s",
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
                                           "reclaim",
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
  struct TicketIteration *ti;
  struct TicketRevocationHandle *rh;
  struct TicketIssueHandle *iss;
  struct ConsumeTicketHandle *ct;
  struct AttributeStoreHandle *as;

  //TODO other operations

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Client %p disconnected\n",
              client);

  while (NULL != (iss = idp->issue_op_head))
  {
    GNUNET_CONTAINER_DLL_remove (idp->issue_op_head,
                                 idp->issue_op_tail,
                                 iss);
    cleanup_ticket_issue_handle (iss);
  }
  while (NULL != (ct = idp->consume_op_head))
  {
    GNUNET_CONTAINER_DLL_remove (idp->consume_op_head,
                                 idp->consume_op_tail,
                                 ct);
    cleanup_consume_ticket_handle (ct);
  }
  while (NULL != (as = idp->store_op_head))
  {
    GNUNET_CONTAINER_DLL_remove (idp->store_op_head,
                                 idp->store_op_tail,
                                 as);
    cleanup_as_handle (as);
  }

  while (NULL != (ai = idp->attr_iter_head))
  {
    GNUNET_CONTAINER_DLL_remove (idp->attr_iter_head,
                                 idp->attr_iter_tail,
                                 ai);
    cleanup_attribute_iter_handle (ai);
  }
  while (NULL != (rh = idp->revoke_op_head))
  {
    GNUNET_CONTAINER_DLL_remove (idp->revoke_op_head,
                                 idp->revoke_op_tail,
                                 rh);
    cleanup_revoke_ticket_handle (rh);
  }
  while (NULL != (ti = idp->ticket_iter_head))
  {
    GNUNET_CONTAINER_DLL_remove (idp->ticket_iter_head,
                                 idp->ticket_iter_tail,
                                 ti);
    cleanup_ticket_iter_handle (ti);
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
("reclaim",
 GNUNET_SERVICE_OPTION_NONE,
 &run,
 &client_connect_cb,
 &client_disconnect_cb,
 NULL,
 GNUNET_MQ_hd_var_size (attribute_store_message,
                        GNUNET_MESSAGE_TYPE_RECLAIM_ATTRIBUTE_STORE,
                        struct AttributeStoreMessage,
                        NULL),
 GNUNET_MQ_hd_fixed_size (iteration_start, 
                          GNUNET_MESSAGE_TYPE_RECLAIM_ATTRIBUTE_ITERATION_START,
                          struct AttributeIterationStartMessage,
                          NULL),
 GNUNET_MQ_hd_fixed_size (iteration_next, 
                          GNUNET_MESSAGE_TYPE_RECLAIM_ATTRIBUTE_ITERATION_NEXT,
                          struct AttributeIterationNextMessage,
                          NULL),
 GNUNET_MQ_hd_fixed_size (iteration_stop, 
                          GNUNET_MESSAGE_TYPE_RECLAIM_ATTRIBUTE_ITERATION_STOP,
                          struct AttributeIterationStopMessage,
                          NULL),
 GNUNET_MQ_hd_var_size (issue_ticket_message,
                        GNUNET_MESSAGE_TYPE_RECLAIM_ISSUE_TICKET,
                        struct IssueTicketMessage,
                        NULL),
 GNUNET_MQ_hd_var_size (consume_ticket_message,
                        GNUNET_MESSAGE_TYPE_RECLAIM_CONSUME_TICKET,
                        struct ConsumeTicketMessage,
                        NULL),
 GNUNET_MQ_hd_fixed_size (ticket_iteration_start, 
                          GNUNET_MESSAGE_TYPE_RECLAIM_TICKET_ITERATION_START,
                          struct TicketIterationStartMessage,
                          NULL),
 GNUNET_MQ_hd_fixed_size (ticket_iteration_next, 
                          GNUNET_MESSAGE_TYPE_RECLAIM_TICKET_ITERATION_NEXT,
                          struct TicketIterationNextMessage,
                          NULL),
 GNUNET_MQ_hd_fixed_size (ticket_iteration_stop, 
                          GNUNET_MESSAGE_TYPE_RECLAIM_TICKET_ITERATION_STOP,
                          struct TicketIterationStopMessage,
                          NULL),
 GNUNET_MQ_hd_var_size (revoke_ticket_message,
                        GNUNET_MESSAGE_TYPE_RECLAIM_REVOKE_TICKET,
                        struct RevokeTicketMessage,
                        NULL),
 GNUNET_MQ_handler_end());
/* end of gnunet-service-reclaim.c */

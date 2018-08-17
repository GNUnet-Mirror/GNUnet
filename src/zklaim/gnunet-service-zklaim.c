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
#include "gnunet_gnsrecord_lib.h"
#include "gnunet_gns_service.h"
#include "gnunet_statistics_service.h"
#include "gnunet_namestore_service.h"
#include "gnunet_zklaim_service.h"
#include "zklaim_api.h"
#include "zklaim_functions.h"
#include "zklaim/zklaim.h"

/**
 * Namestore handle
 */
static struct GNUNET_NAMESTORE_Handle *ns_handle;

/**
 * GNS handle
 */
static struct GNUNET_GNS_Handle *gns_handle;

/**
 * Handle to the statistics service.
 */
static struct GNUNET_STATISTICS_Handle *stats;

/**
 * Our configuration.
 */
static const struct GNUNET_CONFIGURATION_Handle *cfg;

/**
 * Proving key directory
 */
static char *pk_directory;

/**
 * An idp client
 */
struct ZkClient
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
   * Head of DLL of context create ops
   */
  struct CreateContextHandle *create_op_head;

  /**
   * Tail of DLL of attribute store ops
   */
  struct CreateContextHandle *create_op_tail;

  /**
   * Head of DLL of context issue ops
   */
  struct LookupHandle *lookup_op_head;

  /**
   * Tail of DLL of attribute store ops
   */
  struct LookupHandle *lookup_op_tail;


};

struct CreateContextHandle
{
  /**
   * DLL
   */
  struct CreateContextHandle *next;

  /**
   * DLL
   */
  struct CreateContextHandle *prev;

  /**
   * Client connection
   */
  struct ZkClient *client;

  /**
   * Issuer private key
   */
  struct GNUNET_CRYPTO_EcdsaPrivateKey private_key;

  /**
   * Issuer public key
   */
  struct GNUNET_CRYPTO_EcdsaPublicKey public_key;

  /**
   * QueueEntry
   */
  struct GNUNET_NAMESTORE_QueueEntry *ns_qe;

};

struct LookupHandle
{
  /**
   * DLL
   */
  struct LookupHandle *next;

  /**
   * DLL
   */
  struct LookupHandle *prev;

  /**
   * Client connection
   */
  struct ZkClient *client;

  /**
   * Issuer private key
   */
  struct GNUNET_CRYPTO_EcdsaPrivateKey private_key;

  /**
   * Issuer public key
   */
  struct GNUNET_CRYPTO_EcdsaPublicKey public_key;

  /**
   * QueueEntry
   */
  struct GNUNET_NAMESTORE_QueueEntry *ns_qe;

  /**
   * The context name
   */
  char *name;

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
  if (NULL != gns_handle)
    GNUNET_GNS_disconnect (gns_handle);
  if (NULL != ns_handle)
    GNUNET_NAMESTORE_disconnect (ns_handle);
  GNUNET_free (pk_directory);
  pk_directory = NULL;
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
 * Cleanup attribute store handle
 *
 * @param handle handle to clean up
 */
static void
cleanup_create_handle (struct CreateContextHandle *handle)
{
  if (NULL != handle->ns_qe)
    GNUNET_NAMESTORE_cancel (handle->ns_qe);
  GNUNET_free (handle);
}

static void
send_result (int32_t status,
             struct CreateContextHandle *cch)
{
  struct GNUNET_MQ_Envelope *env;
  struct ResultCodeMessage *r_msg;


  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Sending RESULT_CODE message\n");
  env = GNUNET_MQ_msg (r_msg,
                       GNUNET_MESSAGE_TYPE_ZKLAIM_RESULT_CODE);
  r_msg->result_code = htonl (status);
  GNUNET_MQ_send (cch->client->mq,
                  env);
  GNUNET_CONTAINER_DLL_remove (cch->client->create_op_head,
                               cch->client->create_op_tail,
                               cch);
  cleanup_create_handle (cch);
}

static void
context_store_cont (void *cls,
                    int32_t success,
                    const char *emsg)
{
  struct CreateContextHandle *cch = cls;

  cch->ns_qe = NULL;
  if (GNUNET_SYSERR == success)
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Failed to create context %s\n",
                emsg);
  send_result (success, cch);
}



static int
check_create_context_message(void *cls,
                             const struct CreateRequestMessage *crm)
{
  uint16_t size;

  size = ntohs (crm->header.size);
  if (size <= sizeof (struct CreateRequestMessage))
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}

static char*
get_pk_filename (char *ctx_name)
{
  char *filename;

  GNUNET_asprintf (&filename,
                   "%s%s%s",
                   pk_directory,
                   DIR_SEPARATOR_STR,
                   ctx_name);
  return filename;
}

static void
handle_create_context_message (void *cls,
                               const struct CreateRequestMessage *crm)
{
  struct CreateContextHandle *cch;
  struct ZkClient *zkc = cls;
  struct GNUNET_GNSRECORD_Data ctx_record;
  struct GNUNET_ZKLAIM_Context *ctx;
  size_t str_len;
  char *tmp;
  char *pos;
  char *rdata;
  char *fn;
  size_t rdata_len;
  int num_attrs;
  int num_pl;
  int i;

  GNUNET_log (GNUNET_ERROR_TYPE_MESSAGE,
              "Received CREATE_REQUEST message\n");

  str_len = ntohs (crm->name_len);

  cch = GNUNET_new (struct CreateContextHandle);
  ctx = GNUNET_new (struct GNUNET_ZKLAIM_Context);
  ctx->name = GNUNET_strndup ((char*)&crm[1], str_len-1);
  str_len = ntohs(crm->attrs_len);
  fprintf(stderr, "%s\n", ctx->name);
  ctx->attrs = GNUNET_strndup (((char*)&crm[1]) + strlen (ctx->name) + 1,
                               str_len-1);
  cch->private_key = crm->private_key;
  GNUNET_CRYPTO_ecdsa_key_get_public (&crm->private_key,
                                      &cch->public_key);

  GNUNET_SERVICE_client_continue (zkc->client);
  cch->client = zkc;
  GNUNET_CONTAINER_DLL_insert (zkc->create_op_head,
                               zkc->create_op_tail,
                               cch);

  tmp = GNUNET_strdup (ctx->attrs);
  pos = strtok(tmp, ",");
  num_attrs = 0;
  if (NULL == pos)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "No attributes given.\n");
    GNUNET_ZKLAIM_context_destroy (ctx);
    send_result(GNUNET_SYSERR, cch);
    GNUNET_free (tmp);
    return;
  }
  while (NULL != pos)
  {
    num_attrs++;
    pos = strtok(NULL, ",");
  }
  GNUNET_free (tmp);
  num_pl = (num_attrs / 5) + 1;
  zklaim_payload *pl = GNUNET_malloc (num_pl * sizeof (zklaim_payload));
  ctx->ctx = zklaim_context_new ();
  for (i = 0; i < num_pl; i++)
    zklaim_add_pl (ctx->ctx, pl[i]);
  zklaim_hash_ctx (ctx->ctx);
  GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
              "Starting trusted setup (%d payloads)... this might take a while...\n", num_pl);
  if (0 != zklaim_trusted_setup (ctx->ctx))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Trusted Setup failed.\n");
    send_result (GNUNET_SYSERR, cch);
    GNUNET_ZKLAIM_context_destroy (ctx);
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
              "Finished trusted setup. PK size=%lu bytes\n",
              ctx->ctx->pk_size);
  fn = get_pk_filename (ctx->name);
  (void) GNUNET_DISK_directory_create_for_file (fn);
  if (ctx->ctx->pk_size != GNUNET_DISK_fn_write (fn,
                                            ctx->ctx->pk,
                                            ctx->ctx->pk_size,
                                            GNUNET_DISK_PERM_USER_READ |
                                            GNUNET_DISK_PERM_USER_WRITE))
    GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_ERROR,
                              "write", fn);
  GNUNET_free (fn);
  rdata_len = GNUNET_ZKLAIM_context_serialize (ctx, &rdata);
  ctx_record.data_size = rdata_len;
  ctx_record.data = rdata;
  ctx_record.expiration_time = GNUNET_TIME_UNIT_DAYS.rel_value_us; //TODO config
  ctx_record.record_type = GNUNET_GNSRECORD_TYPE_ZKLAIM_CTX;
  ctx_record.flags = GNUNET_GNSRECORD_RF_RELATIVE_EXPIRATION;
  cch->ns_qe = GNUNET_NAMESTORE_records_store (ns_handle,
                                               &cch->private_key,
                                               ctx->name,
                                               1,
                                               &ctx_record,
                                               &context_store_cont,
                                               cch);
  GNUNET_free (rdata);
  GNUNET_ZKLAIM_context_destroy (ctx);
}

/**
 * Cleanup attribute store handle
 *
 * @param handle handle to clean up
 */
static void
cleanup_lookup_handle (struct LookupHandle *handle)
{
  if (NULL != handle->ns_qe)
    GNUNET_NAMESTORE_cancel (handle->ns_qe);
  GNUNET_free_non_null (handle->name);
  GNUNET_free (handle);
}


static void
send_ctx_result (struct LookupHandle *lh,
                 const char* ctx,
                 size_t len)
{
  struct GNUNET_MQ_Envelope *env;
  struct ContextMessage *r_msg;


  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Sending RESULT_CODE message\n");
  env = GNUNET_MQ_msg_extra (r_msg,
                             len,
                             GNUNET_MESSAGE_TYPE_ZKLAIM_RESULT_CTX);
  r_msg->ctx_len = htons (len);
  memcpy ((char*)&r_msg[1],
          ctx,
          len);
  GNUNET_MQ_send (lh->client->mq,
                  env);
  GNUNET_CONTAINER_DLL_remove (lh->client->lookup_op_head,
                               lh->client->lookup_op_tail,
                               lh);

  cleanup_lookup_handle (lh);
}


static void
ctx_not_found_cb (void* cls)
{
  struct LookupHandle *lh = cls;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Context %s not found!\n",
              lh->name);

  send_ctx_result (lh, NULL, 0);
}


static void
ctx_found_cb (void *cls,
              const struct GNUNET_CRYPTO_EcdsaPrivateKey *zone,
              const char *label,
              unsigned int rd_count,
              const struct GNUNET_GNSRECORD_Data *rd)
{
  struct LookupHandle *lh = cls;
  lh->ns_qe = NULL;
  send_ctx_result (lh, (char*) rd->data, rd->data_size);
}



static int
check_lookup_message(void *cls,
                     const struct LookupMessage *lm)
{
  uint16_t size;

  size = ntohs (lm->header.size);
  if (size <= sizeof (struct LookupMessage))
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


static void
handle_lookup_message (void *cls,
                       const struct LookupMessage *lm)
{
  struct LookupHandle *lh;
  struct ZkClient *zkc = cls;
  size_t str_len;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received CREATE_REQUEST message\n");

  str_len = ntohs (lm->name_len);

  lh = GNUNET_new (struct LookupHandle);
  lh->name = GNUNET_strndup ((char*)&lm[1], str_len-1);
  lh->private_key = lm->private_key;
  GNUNET_CRYPTO_ecdsa_key_get_public (&lm->private_key,
                                      &lh->public_key);

  GNUNET_SERVICE_client_continue (zkc->client);
  lh->client = zkc;
  GNUNET_CONTAINER_DLL_insert (zkc->lookup_op_head,
                               zkc->lookup_op_tail,
                               lh);

  lh->ns_qe = GNUNET_NAMESTORE_records_lookup (ns_handle,
                                               &lh->private_key,
                                               lh->name,
                                               &ctx_not_found_cb,
                                               lh,
                                               &ctx_found_cb,
                                               lh);
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
  cfg = c;

  stats = GNUNET_STATISTICS_create ("zklaim", cfg);

  //Connect to services
  ns_handle = GNUNET_NAMESTORE_connect (cfg);
  if (NULL == ns_handle)
  {
    GNUNET_log_strerror (GNUNET_ERROR_TYPE_ERROR, "error connecting to namestore");
  }
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_filename (cfg, "zklaim",
                                               "PKDIR",
                                               &pk_directory))
  {
    GNUNET_log_config_missing (GNUNET_ERROR_TYPE_ERROR, "zklaim", "PKDIR");
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  gns_handle = GNUNET_GNS_connect (cfg);
  if (NULL == gns_handle)
  {
    GNUNET_log_strerror (GNUNET_ERROR_TYPE_ERROR, "error connecting to gns");
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
  struct ZkClient *zkc = app_ctx;
  struct CreateContextHandle *cch;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Client %p disconnected\n",
              client);

  while (NULL != (cch = zkc->create_op_head))
  {
    GNUNET_CONTAINER_DLL_remove (zkc->create_op_head,
                                 zkc->create_op_tail,
                                 cch);
    cleanup_create_handle (cch);
  }
  GNUNET_free (zkc);
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
  struct ZkClient *zkc;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Client %p connected\n",
              client);
  zkc = GNUNET_new (struct ZkClient);
  zkc->client = client;
  zkc->mq = mq;
  return zkc;
}



/**
 * Define "main" method using service macro.
 */
GNUNET_SERVICE_MAIN
("zklaim",
 GNUNET_SERVICE_OPTION_NONE,
 &run,
 &client_connect_cb,
 &client_disconnect_cb,
 NULL,
 GNUNET_MQ_hd_var_size (create_context_message,
                        GNUNET_MESSAGE_TYPE_ZKLAIM_CREATE,
                        struct CreateRequestMessage,
                        NULL),
 GNUNET_MQ_hd_var_size (lookup_message,
                        GNUNET_MESSAGE_TYPE_ZKLAIM_LOOKUP_CTX,
                        struct LookupMessage,
                        NULL),
 GNUNET_MQ_handler_end());
/* end of gnunet-service-zklaim.c */

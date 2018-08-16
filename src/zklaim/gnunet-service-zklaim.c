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
#include "zklaim_api.h"
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

  /**
   * The context name
   */
  char *name;

  /**
   * The attributes to support
   */
  char *attrs;

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
  if (NULL != handle->name)
    GNUNET_free (handle->name);
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
  cleanup_create_handle (cch);

}

static void
context_store_cont (void *cls,
                    int32_t success,
                    const char *emsg)
{
  struct CreateContextHandle *cch = cls;

  cch->ns_qe = NULL;
  GNUNET_CONTAINER_DLL_remove (cch->client->create_op_head,
                               cch->client->create_op_tail,
                               cch);

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


static void
handle_create_context_message (void *cls,
                               const struct CreateRequestMessage *crm)
{
  struct CreateContextHandle *cch;
  struct ZkClient *zkc = cls;
  struct GNUNET_GNSRECORD_Data ctx_record;
  size_t str_len;
  char *tmp;
  char *pos;
  unsigned char *data;
  char *rdata;
  size_t data_len;
  size_t rdata_len;
  int num_attrs;
  int num_pl;
  int i;
  zklaim_ctx *ctx;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received CREATE_REQUEST message\n");

  str_len = ntohs (crm->name_len);

  cch = GNUNET_new (struct CreateContextHandle);
  cch->name = GNUNET_strndup ((char*)&crm[1], str_len-1);
  str_len = ntohs(crm->attrs_len);
  cch->attrs = GNUNET_strndup (((char*)&crm[1]) + strlen (cch->name) + 1,
                               str_len-1);
  cch->private_key = crm->private_key;
  GNUNET_CRYPTO_ecdsa_key_get_public (&crm->private_key,
                                      &cch->public_key);

  GNUNET_SERVICE_client_continue (zkc->client);
  cch->client = zkc;
  GNUNET_CONTAINER_DLL_insert (zkc->create_op_head,
                               zkc->create_op_tail,
                               cch);

  tmp = GNUNET_strdup (cch->attrs);
  pos = strtok(tmp, ",");
  num_attrs = 0;
  if (NULL == pos)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "No attributes given.\n");
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
  num_pl = num_attrs / 5;
  zklaim_payload pl[num_pl];
  ctx = zklaim_context_new ();
  for (i = 0; i < num_pl; i++)
    zklaim_add_pl (ctx, pl[i]);
  zklaim_hash_ctx (ctx);
  if (0 != zklaim_trusted_setup (ctx))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Trusted Setup failed.\n");
    send_result(GNUNET_SYSERR, cch);
    zklaim_ctx_free (ctx);
    return;
  }
  data_len = zklaim_ctx_serialize (ctx, &data);
  rdata_len = data_len + strlen (cch->attrs) + 1;
  zklaim_ctx_free (ctx);
  rdata = GNUNET_malloc (rdata_len);
  memcpy (rdata,
          cch->attrs,
          strlen (cch->attrs) + 1);
  memcpy (rdata + strlen (cch->attrs) + 1,
          data,
          data_len);
  ctx_record.data_size = rdata_len;
  ctx_record.data = rdata;
  ctx_record.expiration_time = GNUNET_TIME_UNIT_DAYS.rel_value_us; //TODO config
  ctx_record.record_type = GNUNET_GNSRECORD_TYPE_ZKLAIM_CTX;
  ctx_record.flags = GNUNET_GNSRECORD_RF_RELATIVE_EXPIRATION;
  cch->ns_qe = GNUNET_NAMESTORE_records_store (ns_handle,
                                              &cch->private_key,
                                              cch->name,
                                              1,
                                              &ctx_record,
                                              &context_store_cont,
                                              cch);
  GNUNET_free (rdata);
  GNUNET_free (data);
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
 GNUNET_MQ_handler_end());
/* end of gnunet-service-zklaim.c */

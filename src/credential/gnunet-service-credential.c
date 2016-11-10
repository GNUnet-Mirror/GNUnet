/*
     This file is part of GNUnet.
     Copyright (C) 2011-2013 GNUnet e.V.

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
 * @file gns/gnunet-service-credential.c
 * @brief GNU Credential Service (main service)
 * @author Adnan Husain 
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_credential_service.h"
#include "gnunet_statistics_service.h"
#include "credential.h"
#include "gnunet_protocols.h"

// For Looking up GNS request
#include <gnunet_dnsparser_lib.h>
#include <gnunet_identity_service.h>
#include <gnunet_gnsrecord_lib.h>
#include <gnunet_namestore_service.h>
#include <gnunet_gns_service.h>
#include "gnunet_gns_service.h"




#define GNUNET_CREDENTIAL_MAX_LENGTH 255

/**
 * DLL for record
 */
struct CredentialRecordEntry
{
  /**
   * DLL
   */
  struct CredentialRecordEntry *next;

  /**
   * DLL
   */
  struct CredentialRecordEntry *prev;


  /**
   * Payload
   */
  struct GNUNET_CREDENTIAL_RecordData record_data;
};

/**
 * Handle to a lookup operation from api
 */
struct ClientLookupHandle
{

  /**
   * We keep these in a DLL.
   */
  struct ClientLookupHandle *next;

  /**
   * We keep these in a DLL.
   */
  struct ClientLookupHandle *prev;

  /**
   * Handle to the requesting client
   */
  struct GNUNET_SERVICE_Client *client;

  /**
   * Handle to GNS lookup
   */
  struct GNUNET_GNS_LookupRequest *lookup_request;

  /**
   * Authority public key
   */
  struct GNUNET_CRYPTO_EcdsaPublicKey issuer_key;

  /**
   * Credential Chain
   */
  struct CredentialRecordEntry *cred_chain_head;

  /**
   * Credential Chain
   */
  struct CredentialRecordEntry *cred_chain_tail;

  /**
   * request id
   */
  uint32_t request_id;

};


/**
 * Head of the DLL.
 */
static struct ClientLookupHandle *clh_head;

/**
 * Tail of the DLL.
 */
static struct ClientLookupHandle *clh_tail;

/**
 * Handle to the statistics service
 */
static struct GNUNET_STATISTICS_Handle *statistics;



/**
 * Handle to GNS service.
 */
static struct GNUNET_GNS_Handle *gns;

/**
 * Task run during shutdown.
 *
 * @param cls unused
 * @param tc unused
 */
static void
shutdown_task (void *cls)
{
  struct ClientLookupHandle *clh;
  
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Shutting down!\n");
  while (NULL != (clh = clh_head))
  {
    //CREDENTIAL_resolver_lookup_cancel (clh->lookup);
    GNUNET_CONTAINER_DLL_remove (clh_head,
                                 clh_tail,
                                 clh);
    GNUNET_free (clh);
  }

  
  if (NULL != statistics)
  {
    GNUNET_STATISTICS_destroy (statistics,
                               GNUNET_NO);
    statistics = NULL;
  }
  
}

/**
 * Checks a #GNUNET_MESSAGE_TYPE_CREDENTIAL_LOOKUP message
 *
 * @param cls client sending the message
 * @param l_msg message of type `struct LookupMessage`
 * @return #GNUNET_OK if @a l_msg is well-formed
 */
static int
check_lookup (void *cls,
		    const struct LookupMessage *l_msg)
{
  size_t msg_size;
  const char* cred;

  msg_size = ntohs (l_msg->header.size);
  if (msg_size < sizeof (struct LookupMessage))
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  cred = (const char *) &l_msg[1];
  if ( ('\0' != cred[l_msg->header.size - sizeof (struct LookupMessage) - 1]) ||
       (strlen (cred) > GNUNET_CREDENTIAL_MAX_LENGTH) )
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * Reply to client with the result from our lookup.
 *
 * @param cls the closure (our client lookup handle)
 * @param rd_count the number of records in @a rd
 * @param rd the record data
 */
static void
send_lookup_response (void* cls,
                      uint32_t rd_count,
                      const struct GNUNET_GNSRECORD_Data *rd)
{
  struct ClientLookupHandle *clh = cls;
  size_t len;
  int i;
  int cred_record_count;
  struct GNUNET_MQ_Envelope *env;
  struct LookupResultMessage *rmsg;
  const struct GNUNET_CREDENTIAL_RecordData *crd;
  struct CredentialRecordEntry *cr_entry;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Sending LOOKUP_RESULT message with %u results\n",
              (unsigned int) rd_count);
  
  cred_record_count = 0;
  for (i=0; i < rd_count; i++)
  {
    if (GNUNET_GNSRECORD_TYPE_CREDENTIAL != rd[i].record_type)
      continue;
    cred_record_count++;
    crd = rd[i].data;
    /**
     * TODO: Check for:
     * - First time we come here subject must be subject prvided by client
     * - After that is has to be the prev issuer
     * - Terminate condition: issuer is clh->authority_key
     *
     *   In any case:
     *   Append crd to result list of RecordData
     */
    cr_entry = GNUNET_new (struct CredentialRecordEntry);
    cr_entry->record_data = *crd;
    GNUNET_CONTAINER_DLL_insert_tail (clh->cred_chain_head,
                                      clh->cred_chain_tail,
                                      cr_entry);

  }

  /**
   * Get serialized record data size
   */
  len = cred_record_count * sizeof (struct GNUNET_CREDENTIAL_RecordData);
  
  /**
   * Prepare a lookup result response message for the client
   */
  env = GNUNET_MQ_msg_extra (rmsg,
                             len,
                             GNUNET_MESSAGE_TYPE_CREDENTIAL_LOOKUP_RESULT);
  //Assign id so that client can find associated request
  rmsg->id = clh->request_id;
  rmsg->cd_count = htonl (cred_record_count);
  
  /**
   * Get serialized record data
   * Append at the end of rmsg
   */
  i = 0;
  struct GNUNET_CREDENTIAL_RecordData *tmp_record = (struct GNUNET_CREDENTIAL_RecordData*) &rmsg[1];
  for (cr_entry = clh->cred_chain_head; NULL != cr_entry; cr_entry = cr_entry->next)
  {
    memcpy (tmp_record,
            &cr_entry->record_data,
            sizeof (struct GNUNET_CREDENTIAL_RecordData));
    tmp_record++;
  }
  GNUNET_MQ_send (GNUNET_SERVICE_client_get_mq(clh->client),
                  env);

  GNUNET_CONTAINER_DLL_remove (clh_head, clh_tail, clh);
  
  /**
   * TODO:
   * - Free DLL
   * - Refactor into cleanup_handle() function for this
   */
  GNUNET_free (clh);

  GNUNET_STATISTICS_update (statistics,
                            "Completed lookups", 1,
                            GNUNET_NO);
  GNUNET_STATISTICS_update (statistics,
                            "Records resolved",
                            rd_count,
                            GNUNET_NO);
}

/**
 * Handle lookup requests from client
 *
 * @param cls the closure
 * @param client the client
 * @param message the message
 */
static void
handle_lookup (void *cls,
               const struct LookupMessage *l_msg) 
{
  char credential[GNUNET_CREDENTIAL_MAX_LENGTH + 1];
  struct ClientLookupHandle *clh;
  struct GNUNET_SERVICE_Client *client = cls;
  char *credentialptr = credential;
  const char *utf_in;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received LOOKUP message\n");

  utf_in = (const char *) &l_msg[1];
  GNUNET_STRINGS_utf8_tolower (utf_in, credentialptr);
  clh = GNUNET_new (struct ClientLookupHandle);
  GNUNET_CONTAINER_DLL_insert (clh_head, clh_tail, clh);
  clh->client = client;
  clh->request_id = l_msg->id;
  clh->issuer_key = l_msg->issuer_key;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Sending LOOKUP_RESULT message with >%u results\n",
              0);

  if (NULL == credential)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, 
                "No credential provided\n");
    send_lookup_response (clh, 0, NULL);
    return;
  }
  clh->lookup_request = GNUNET_GNS_lookup (gns,
                                           credential,
                                           &l_msg->subject_key, //subject_pkey,
                                           GNUNET_GNSRECORD_TYPE_CREDENTIAL,
                                           GNUNET_GNS_LO_DEFAULT, //TODO configurable? credential.conf
                                           NULL, //shorten_key, always NULL
                                           &send_lookup_response,
                                           clh);
}


/**
 * One of our clients disconnected, clean up after it.
 *
 * @param cls NULL
 * @param client the client that disconnected
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
 * @return this client
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
 * Process Credential requests.
 *
 * @param cls closure
 * @param server the initialized server
 * @param c configuration to use
 */
static void
run (void *cls,
     const struct GNUNET_CONFIGURATION_Handle *c,
     struct GNUNET_SERVICE_Handle *handle)
{

  gns = GNUNET_GNS_connect (c);
  if (NULL == gns)
  {
    fprintf (stderr,
             _("Failed to connect to GNS\n"));
  }

  statistics = GNUNET_STATISTICS_create ("credential", c);
  GNUNET_SCHEDULER_add_shutdown (&shutdown_task, NULL);
}


/**
 * Define "main" method using service macro
 */
GNUNET_SERVICE_MAIN
("credential",
 GNUNET_SERVICE_OPTION_NONE,
 &run,
 &client_connect_cb,
 &client_disconnect_cb,
 NULL,
 GNUNET_MQ_hd_var_size (lookup,
                        GNUNET_MESSAGE_TYPE_CREDENTIAL_LOOKUP,
                        struct LookupMessage,
                        NULL),
 GNUNET_MQ_handler_end());

/* end of gnunet-service-credential.c */

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
#include "gnunet_signatures.h"

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
  struct GNUNET_CREDENTIAL_CredentialRecordData record_data;
};

/**
 * DLL for attributes - Used as a queue
 * Insert tail - Pop head
 */
struct AttributeRecordEntry
{
  /**
   * DLL
   */
  struct AttributeRecordEntry *next;

  /**
   * DLL
   */
  struct AttributeRecordEntry *prev;

  /**
   * Payload
   */
  struct GNUNET_CREDENTIAL_AttributeRecordData record_data;
};


/**
 * Handle to a lookup operation from api
 */
struct VerifyRequestHandle
{

  /**
   * We keep these in a DLL.
   */
  struct VerifyRequestHandle *next;

  /**
   * We keep these in a DLL.
   */
  struct VerifyRequestHandle *prev;

  /**
   * Handle to the requesting client
   */
  struct GNUNET_SERVICE_Client *client;

  /**
   * Handle to GNS lookup
   */
  struct GNUNET_GNS_LookupRequest *lookup_request;

  /**
   * Issuer public key
   */
  struct GNUNET_CRYPTO_EcdsaPublicKey issuer_key;
  
  /**
   * Issuer attribute
   */
  char *issuer_attribute;

  /**
   * Subject public key
   */
  struct GNUNET_CRYPTO_EcdsaPublicKey subject_key;

  /**
   * Credential Chain
   */
  struct CredentialRecordEntry *cred_chain_head;

  /**
   * Credential Chain
   */
  struct CredentialRecordEntry *cred_chain_tail;

  /**
   * Attribute Queue
   */
  struct AttributeRecordEntry *attr_queue_head;
  
  /**
   * Attribute Queue
   */
  struct AttributeRecordEntry *attr_queue_tail;
  
  /**
   * Current Attribute Pointer
   */
  struct AttributeRecordEntry* attr_pointer; 

  /**
   * request id
   */
  uint32_t request_id;

};


/**
 * Head of the DLL.
 */
static struct VerifyRequestHandle *vrh_head;

/**
 * Tail of the DLL.
 */
static struct VerifyRequestHandle *vrh_tail;

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
  struct VerifyRequestHandle *vrh;
  
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Shutting down!\n");
  while (NULL != (vrh = vrh_head))
  {
    //CREDENTIAL_resolver_lookup_cancel (clh->lookup);
    GNUNET_CONTAINER_DLL_remove (vrh_head,
                                 vrh_tail,
                                 vrh);
    GNUNET_free (vrh);
  }

  
  if (NULL != statistics)
  {
    GNUNET_STATISTICS_destroy (statistics,
                               GNUNET_NO);
    statistics = NULL;
  }
  
}

/**
 * Checks a #GNUNET_MESSAGE_TYPE_CREDENTIAL_VERIFY message
 *
 * @param cls client sending the message
 * @param v_msg message of type `struct VerifyMessage`
 * @return #GNUNET_OK if @a v_msg is well-formed
 */
static int
check_verify (void *cls,
		    const struct VerifyMessage *v_msg)
{
  size_t msg_size;
  const char* attrs;

  msg_size = ntohs (v_msg->header.size);
  if (msg_size < sizeof (struct VerifyMessage))
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  if ((ntohs (v_msg->issuer_attribute_len) > GNUNET_CREDENTIAL_MAX_LENGTH) ||
      (ntohs (v_msg->subject_attribute_len) > GNUNET_CREDENTIAL_MAX_LENGTH))
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  attrs = (const char *) &v_msg[1];
  
  if ( ('\0' != attrs[ntohs(v_msg->header.size) - sizeof (struct VerifyMessage) - 1]) ||
       (strlen (attrs) > GNUNET_CREDENTIAL_MAX_LENGTH * 2) )
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}

static void
start_backward_resolution (void* cls,
                           uint32_t rd_count,
                           const struct GNUNET_GNSRECORD_Data *rd)
{
  struct VerifyRequestHandle *vrh = cls;
  int i;
  struct GNUNET_CREDENTIAL_CredentialRecordData *cred;
  struct GNUNET_CREDENTIAL_AttributeRecordData *attr;
  struct CredentialRecordEntry *cred_pointer;  
  const char *attribute;
  const char *cred_attribute;
  char *issuer_key;
  char *cred_issuer_key;
  const struct GNUNET_CRYPTO_EcdsaPublicKey *issuer_key_ecdsa; 
  const struct GNUNET_CRYPTO_EcdsaPublicKey *cred_issuer_key_ecdsa; 

  for(cred_pointer = vrh->cred_chain_head; cred_pointer != NULL; 
      cred_pointer = cred_pointer->next){
    cred = &cred_pointer->record_data;
    issuer_key_ecdsa =  &vrh->attr_pointer->record_data.subject_key;
    cred_issuer_key_ecdsa = &cred_pointer->record_data.issuer_key;

    issuer_key =  GNUNET_CRYPTO_ecdsa_public_key_to_string(issuer_key_ecdsa);
    cred_issuer_key = GNUNET_CRYPTO_ecdsa_public_key_to_string(cred_issuer_key_ecdsa);
    if(0 == strcmp(issuer_key,cred_issuer_key))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Found issuer\n");
    }         

  }
  

  
  //Start from next to head
  for(vrh->attr_pointer = vrh->attr_queue_head->next ; vrh->attr_pointer->next != NULL ;
        vrh->attr_pointer = vrh->attr_pointer->next ){

    //Start with backward resolution
    GNUNET_GNS_lookup (gns,
                       vrh->issuer_attribute,
                       &vrh->issuer_key, //issuer_key,
                       GNUNET_GNSRECORD_TYPE_ATTRIBUTE,
                       GNUNET_GNS_LO_DEFAULT,
                       NULL, //shorten_key, always NULL
                       &start_backward_resolution,
                       vrh);
  }


} 

/**
 * Result from GNS lookup.
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
  struct VerifyRequestHandle *vrh = cls;
  size_t len;
  int i;
  int cred_record_count;
  struct GNUNET_MQ_Envelope *env;
  struct VerifyResultMessage *rmsg;
  const struct GNUNET_CREDENTIAL_CredentialRecordData *crd;
  struct GNUNET_CRYPTO_EccSignaturePurpose *purp;
  struct CredentialRecordEntry *cr_entry;

  cred_record_count = 0;
  struct AttributeRecordEntry *attr_entry;

  struct GNUNET_CREDENTIAL_AttributeRecordData *ard = 
    GNUNET_new(struct GNUNET_CREDENTIAL_AttributeRecordData); 
  
  attr_entry->record_data = *ard; 
  ard->subject_key = vrh->issuer_key;
  GNUNET_CONTAINER_DLL_insert_tail (vrh->attr_queue_head,
                                    vrh->attr_queue_tail,
                                    attr_entry);
  for (i=0; i < rd_count; i++)
  {
    if (GNUNET_GNSRECORD_TYPE_CREDENTIAL != rd[i].record_type)
      continue;
    cred_record_count++;
    crd = rd[i].data;
    /**
     * TODO:
     * Check if we have already found our credential here
     * If so return success
     * Else
     *  Save all found attributes/issues and prepare forward
     *  resolution of issuer attribute
     */
    cr_entry = GNUNET_new (struct CredentialRecordEntry);
    cr_entry->record_data = *crd;
    GNUNET_CONTAINER_DLL_insert_tail (vrh->cred_chain_head,
                                      vrh->cred_chain_tail,
                                      cr_entry);
    purp = GNUNET_malloc (sizeof (struct GNUNET_CRYPTO_EccSignaturePurpose) +
                          sizeof (struct GNUNET_CRYPTO_EcdsaPublicKey) +
                          strlen ((char*)&crd[1]) +1 );
    purp->size = htonl (sizeof (struct GNUNET_CRYPTO_EccSignaturePurpose) +
                        sizeof (struct GNUNET_CRYPTO_EcdsaPublicKey) +
                        strlen ((char*)&crd[1]) +1 );

    purp->purpose = htonl (GNUNET_SIGNATURE_PURPOSE_CREDENTIAL);
    if(GNUNET_OK == GNUNET_CRYPTO_ecdsa_verify(GNUNET_SIGNATURE_PURPOSE_CREDENTIAL, 
                                               purp,
                                               &crd->sig,
                                               &crd->issuer_key))
    {
      GNUNET_free (purp);
      break;
    }
    GNUNET_free (purp);

  }


  /**
   * Check for attributes from the issuer and follow the chain 
   * till you get the required subject's attributes
   */
  if(cred_verified != GNUNET_YES){


    vrh->attr_pointer = vrh->attr_queue_head; 

    //Start with backward resolution
    GNUNET_GNS_lookup (gns,
                       vrh->issuer_attribute,
                       &vrh->issuer_key, //issuer_key,
                       GNUNET_GNSRECORD_TYPE_ATTRIBUTE,
                       GNUNET_GNS_LO_DEFAULT,
                       NULL, //shorten_key, always NULL
                       &start_backward_resolution,
                       vrh);
  }


  /**
   * TODO
   * Start resolution of Attribute delegations from issuer
   *
   * - Build adequate data structures for attribute(s) to lookup
   * - Use GNUNET_GNSRECORD_TYPE_XXX
   * - recursively try to find match(es) with results found top
   * - return one found credential chain
   *
   */

  /**
   * Get serialized record data size
   */
  len = cred_record_count * sizeof (struct GNUNET_CREDENTIAL_CredentialRecordData);

  /**
   * Prepare a lookup result response message for the client
   */
  env = GNUNET_MQ_msg_extra (rmsg,
                             len,
                             GNUNET_MESSAGE_TYPE_CREDENTIAL_VERIFY_RESULT);
  //Assign id so that client can find associated request
  rmsg->id = vrh->request_id;
  rmsg->ad_count = htonl (cred_record_count);

  /**
   * Get serialized record data
   * Append at the end of rmsg
   */
  i = 0;
  struct GNUNET_CREDENTIAL_CredentialRecordData *tmp_record = (struct GNUNET_CREDENTIAL_CredentialRecordData*) &rmsg[1];
  for (cr_entry = vrh->cred_chain_head; NULL != cr_entry; cr_entry = cr_entry->next)
  {
    memcpy (tmp_record,
            &cr_entry->record_data,
            sizeof (struct GNUNET_CREDENTIAL_CredentialRecordData));
    tmp_record++;
  }
  GNUNET_MQ_send (GNUNET_SERVICE_client_get_mq(vrh->client),
                  env);

  GNUNET_CONTAINER_DLL_remove (vrh_head, vrh_tail, vrh);

  /**
   * TODO:
   * - Free DLL
   * - Refactor into cleanup_handle() function for this
   */
  GNUNET_free (vrh);

  GNUNET_STATISTICS_update (statistics,
                            "Completed verifications", 1,
                            GNUNET_NO);
  GNUNET_STATISTICS_update (statistics,
                            "Credentials resolved",
                            rd_count,
                            GNUNET_NO);
}

/**
 * Handle Credential verification requests from client
 *
 * @param cls the closure
 * @param client the client
 * @param message the message
 */
static void
handle_verify (void *cls,
               const struct VerifyMessage *v_msg) 
{
  char attrs[GNUNET_CREDENTIAL_MAX_LENGTH*2 + 1];
  char issuer_attribute[GNUNET_CREDENTIAL_MAX_LENGTH + 1];
  char subject_attribute[GNUNET_CREDENTIAL_MAX_LENGTH + 1];
  struct VerifyRequestHandle *vrh;
  struct GNUNET_SERVICE_Client *client = cls;
  char *attrptr = attrs;
  const char *utf_in;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received VERIFY message\n");

  utf_in = (const char *) &v_msg[1];
  GNUNET_STRINGS_utf8_tolower (utf_in, attrptr);

  GNUNET_memcpy (issuer_attribute, attrs, ntohs (v_msg->issuer_attribute_len));
  issuer_attribute[ntohs (v_msg->issuer_attribute_len)] = '\0';
  GNUNET_memcpy (subject_attribute, attrs+strlen(issuer_attribute), ntohs (v_msg->subject_attribute_len));
  subject_attribute[ntohs (v_msg->subject_attribute_len)] = '\0';
  vrh = GNUNET_new (struct VerifyRequestHandle);
  GNUNET_CONTAINER_DLL_insert (vrh_head, vrh_tail, vrh);
  vrh->client = client;
  vrh->request_id = v_msg->id;
  vrh->issuer_key = v_msg->issuer_key;
  vrh->subject_key = v_msg->subject_key;
  vrh->issuer_attribute = issuer_attribute;

  if (NULL == subject_attribute)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, 
                "No subject attribute provided!\n");
    send_lookup_response (vrh, 0, NULL);
    return;
  }
  if (NULL == issuer_attribute)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, 
                "No issuer attribute provided!\n");
    send_lookup_response (vrh, 0, NULL);
    return;
  }
  /**
   * First, get attribute from subject
   */
  vrh->lookup_request = GNUNET_GNS_lookup (gns,
                                           subject_attribute,
                                           &v_msg->subject_key, //subject_pkey,
                                           GNUNET_GNSRECORD_TYPE_CREDENTIAL,
                                           GNUNET_GNS_LO_DEFAULT,
                                           NULL, //shorten_key, always NULL
                                           &send_lookup_response,
                                           vrh);
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
 GNUNET_MQ_hd_var_size (verify,
                        GNUNET_MESSAGE_TYPE_CREDENTIAL_VERIFY,
                        struct VerifyMessage,
                        NULL),
 GNUNET_MQ_handler_end());

/* end of gnunet-service-credential.c */

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
  struct GNUNET_CREDENTIAL_CredentialRecordData *data;

  /**
   * Size
   */
  uint64_t data_size;
};

/**
 * DLL for attributes - Used as a queue
 * Insert tail - Pop head
 */
struct AttributeQueueEntry
{
  /**
   * DLL
   */
  struct AttributeQueueEntry *next;

  /**
   * DLL
   */
  struct AttributeQueueEntry *prev;

  /**
   * Payload
   */
  struct GNUNET_CREDENTIAL_AttributeRecordData *data;

  /**
   * Size
   */
  uint64_t data_size;

  /**
   * Parent attribute delegation
   */
  struct AttributeQueueEntry *parent;

  /**
   * Trailing attribute context
   */
  char *attr_trailer;
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
   * Number of chain entries
   */
  uint32_t cred_chain_entries;

  /**
   * Attribute Queue
   */
  struct AttributeQueueEntry *attr_queue_head;
  
  /**
   * Attribute Queue
   */
  struct AttributeQueueEntry *attr_queue_tail;
  
  /**
   * Current Attribute Pointer
   */
  struct AttributeQueueEntry *current_attribute;

  /**
   * The found credential
   */
  struct GNUNET_CREDENTIAL_CredentialRecordData *credential;

  /**
   * Length of the credential
   */
  uint32_t credential_size;

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

  if (NULL != gns)
  {
    GNUNET_GNS_disconnect (gns);
    gns = NULL;
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

/**
 * Send.
 *
 * @param handle the handle to the request
 */
static void
send_lookup_response (struct VerifyRequestHandle *vrh)
{
  size_t len;
  struct GNUNET_MQ_Envelope *env;
  struct VerifyResultMessage *rmsg;

  /**
   * Get serialized record data size
   */
  len = vrh->credential_size; //TODO max length of attr

  //TODO add attr chain
  /**
   * Prepare a lookup result response message for the client
   */
  env = GNUNET_MQ_msg_extra (rmsg,
                             len,
                             GNUNET_MESSAGE_TYPE_CREDENTIAL_VERIFY_RESULT);
  //Assign id so that client can find associated request
  rmsg->id = vrh->request_id;
  rmsg->cd_count = htonl (vrh->cred_chain_entries);

  /**
   * Get serialized record data
   * Append at the end of rmsg
   */
  rmsg->cred_found = htonl (GNUNET_NO);
  if (NULL != vrh->credential)
  {
    memcpy (&rmsg[1],
            vrh->credential,
            vrh->credential_size);
    rmsg->cred_found = htonl (GNUNET_YES);
  }

  /*char* tmp_entry = (char*)&rmsg[1];
    for (cr_entry = vrh->cred_chain_head; NULL != cr_entry; cr_entry = cr_entry->next)
    {
    memcpy (tmp_entry,
    &cr_entry->record_data,
    cr_entry->record_data_size);
    tmp_entry += cr_entry->record_data_size;
    }*/
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
}


static void
start_backward_resolution (void* cls,
                           uint32_t rd_count,
                           const struct GNUNET_GNSRECORD_Data *rd)
{
  struct VerifyRequestHandle *vrh = cls;
  struct GNUNET_CREDENTIAL_CredentialRecordData *cred;
  const struct GNUNET_CREDENTIAL_AttributeRecordData *attr;
  struct CredentialRecordEntry *cred_pointer;
  struct AttributeQueueEntry *attr_entry;
  char *expanded_attr;
  char *check_attr;
  int i;
  
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Got %d attrs\n", rd_count);

  for (i=0; i < rd_count; i++) 
  {
    if (GNUNET_GNSRECORD_TYPE_ATTRIBUTE != rd[i].record_type)
      continue;

    attr = rd[i].data;
    attr_entry = GNUNET_new (struct AttributeQueueEntry);
    attr_entry->data_size = rd[i].data_size;
    if (NULL != vrh->current_attribute &&
        NULL != vrh->current_attribute->attr_trailer)
    {
      if (rd[i].data_size == sizeof (struct GNUNET_CREDENTIAL_AttributeRecordData))
      {
        GNUNET_asprintf (&expanded_attr,
                         "%s",
                         vrh->current_attribute->attr_trailer);

      } else {
        GNUNET_asprintf (&expanded_attr,
                         "%s.%s",
                         (char*)&attr[1],
                         vrh->current_attribute->attr_trailer);
      }
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Expanded to %s\n", expanded_attr);
      attr_entry->data_size += strlen (vrh->current_attribute->attr_trailer) + 1;
    } else {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Not Expanding %s\n", (char*)&attr[1]);
    }
    attr_entry->data = GNUNET_malloc (attr_entry->data_size);
    memcpy (attr_entry->data,
            rd[i].data,
            rd[i].data_size);
    if (NULL != vrh->current_attribute && NULL != vrh->current_attribute->attr_trailer)
    {
      memcpy ((char*)&attr_entry->data[1],
              expanded_attr,
              strlen (expanded_attr));
    } 
    check_attr = (char*)&attr_entry->data[1];
    check_attr[attr_entry->data_size] = '\0';
    attr_entry->parent = vrh->current_attribute;

    GNUNET_CONTAINER_DLL_insert (vrh->attr_queue_head,
                                 vrh->attr_queue_tail,
                                 attr_entry);
    for(cred_pointer = vrh->cred_chain_head; cred_pointer != NULL; 
        cred_pointer = cred_pointer->next){
      cred = cred_pointer->data;
      if(0 != memcmp (&attr->subject_key, 
                      &cred_pointer->data->issuer_key,
                      sizeof(struct GNUNET_CRYPTO_EcdsaPublicKey)))
        continue;
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Checking if %s matches %s\n",
                  (char*)&attr_entry->data[1], (char*)&cred[1]);

      if (0 != strcmp ((char*)&attr_entry->data[1], (char*)&cred[1]))
        continue;

      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Found issuer\n");
      vrh->credential = GNUNET_malloc (rd[i].data_size);
      memcpy (vrh->credential,
              rd[i].data,
              rd[i].data_size);
      vrh->credential_size = rd[i].data_size;
      //Found match 
      send_lookup_response (vrh);
      return;

    }
  }



  //Start from next to head
  vrh->current_attribute = vrh->attr_queue_head;

  if(NULL == vrh->current_attribute)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "We are all out of attributes...\n");
    send_lookup_response (vrh);
    return;
  }

  GNUNET_CONTAINER_DLL_remove (vrh->attr_queue_head,
                               vrh->attr_queue_tail,
                               vrh->current_attribute);



  //Start with backward resolution
  char issuer_attribute_name[strlen ((char*)&vrh->current_attribute->data[1])];
  char *lookup_attr;
  strcpy (issuer_attribute_name,
          (char*)&vrh->current_attribute->data[1]);
  char *next_attr = strtok (issuer_attribute_name, ".");
    GNUNET_asprintf (&lookup_attr,
                   "%s.gnu",
                   next_attr);
  next_attr += strlen (next_attr) + 1;
  vrh->current_attribute->attr_trailer = GNUNET_strdup (next_attr);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Looking up %s\n", lookup_attr);
  if (NULL != vrh->current_attribute->attr_trailer)
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "%s still to go...\n", vrh->current_attribute->attr_trailer);

  vrh->lookup_request = GNUNET_GNS_lookup (gns,
                                           lookup_attr,
                                           &vrh->current_attribute->data->subject_key, //issuer_key,
                                           GNUNET_GNSRECORD_TYPE_ATTRIBUTE,
                                           GNUNET_GNS_LO_DEFAULT,
                                           NULL, //shorten_key, always NULL
                                           &start_backward_resolution,
                                           vrh);
  GNUNET_free (lookup_attr);
} 



/**
 * Result from GNS lookup.
 *
 * @param cls the closure (our client lookup handle)
 * @param rd_count the number of records in @a rd
 * @param rd the record data
 */
static void
handle_credential_query (void* cls,
                         uint32_t rd_count,
                         const struct GNUNET_GNSRECORD_Data *rd)
{
  struct VerifyRequestHandle *vrh = cls;
  int cred_record_count;
  int i;
  const struct GNUNET_CREDENTIAL_CredentialRecordData *crd;
  struct CredentialRecordEntry *cr_entry;

  cred_record_count = 0;
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
    if(GNUNET_OK != GNUNET_CRYPTO_ecdsa_verify(GNUNET_SIGNATURE_PURPOSE_CREDENTIAL, 
                                               &crd->purpose,
                                               &crd->sig,
                                               &crd->issuer_key))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  "Invalid credential found\n");
      continue;
    }
    cr_entry = GNUNET_new (struct CredentialRecordEntry);
    cr_entry->data = GNUNET_malloc (rd[i].data_size);
    memcpy (cr_entry->data,
            crd,
            rd[i].data_size);
    cr_entry->data_size = rd[i].data_size;
    GNUNET_CONTAINER_DLL_insert_tail (vrh->cred_chain_head,
                                      vrh->cred_chain_tail,
                                      cr_entry);

    if (0 != memcmp (&crd->issuer_key,
                     &vrh->issuer_key,
                     sizeof (struct GNUNET_CRYPTO_EcdsaPublicKey)))
      continue;
    if (0 != strcmp ((char*)&crd[1], vrh->issuer_attribute))
      continue;
    vrh->credential = GNUNET_malloc (rd[i].data_size);
    memcpy (vrh->credential,
            rd[i].data,
            rd[i].data_size);
    vrh->credential_size = rd[i].data_size;
    //Found match prematurely
    send_lookup_response (vrh);
    return;

  }

  /**
   * Check for attributes from the issuer and follow the chain 
   * till you get the required subject's attributes
   */
  char issuer_attribute_name[strlen (vrh->issuer_attribute)];
  strcpy (issuer_attribute_name,
          vrh->issuer_attribute);
  strcpy (issuer_attribute_name + strlen (vrh->issuer_attribute),
          ".gnu");
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Looking up %s\n", issuer_attribute_name);

  //Start with backward resolution
  GNUNET_GNS_lookup (gns,
                     issuer_attribute_name,
                     &vrh->issuer_key, //issuer_key,
                     GNUNET_GNSRECORD_TYPE_ATTRIBUTE,
                     GNUNET_GNS_LO_DEFAULT,
                     NULL, //shorten_key, always NULL
                     &start_backward_resolution,
                     vrh);
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
  char subject_attribute[GNUNET_CREDENTIAL_MAX_LENGTH + 1 + 4];
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
  strcpy (subject_attribute+ntohs (v_msg->subject_attribute_len),
          ".gnu");
  subject_attribute[ntohs (v_msg->subject_attribute_len)+4] = '\0';
  vrh = GNUNET_new (struct VerifyRequestHandle);
  GNUNET_CONTAINER_DLL_insert (vrh_head, vrh_tail, vrh);
  vrh->client = client;
  vrh->request_id = v_msg->id;
  vrh->issuer_key = v_msg->issuer_key;
  vrh->subject_key = v_msg->subject_key;
  vrh->issuer_attribute = GNUNET_strdup (issuer_attribute);

  if (NULL == subject_attribute)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, 
                "No subject attribute provided!\n");
    send_lookup_response (vrh);
    return;
  }
  if (NULL == issuer_attribute)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, 
                "No issuer attribute provided!\n");
    send_lookup_response (vrh);
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
                                           &handle_credential_query,
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

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
  struct GNUNET_CREDENTIAL_RecordData record_data;
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
   * Subject public key
   */
  struct GNUNET_CRYPTO_EcdsaPublicKey subject_key;

  /**
   * Attribute Chain
   */
  struct AttributeRecordEntry *attr_chain_head;

  /**
   * Attribute Chain
   */
  struct AttributeRecordEntry *attr_chain_tail;

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
  size_t attr_len;
  const char* s_attr;
  const char* i_attr;

  msg_size = ntohs (v_msg->header.size);
  if (msg_size < sizeof (struct VerifyMessage))
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  i_attr = (const char *) &v_msg[1];
  if ( ('\0' != i_attr[v_msg->header.size - sizeof (struct VerifyMessage) - 1]) ||
       (strlen (i_attr) > GNUNET_CREDENTIAL_MAX_LENGTH) )
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  attr_len = strlen (i_attr);
  s_attr = ((const char *) &v_msg[1]) + attr_len + 1;
  if ( ('\0' != s_attr[v_msg->header.size - sizeof (struct VerifyMessage) - 1]) ||
       (strlen (s_attr) > GNUNET_CREDENTIAL_MAX_LENGTH) )
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
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
  int attr_record_count;
  struct GNUNET_MQ_Envelope *env;
  struct VerifyResultMessage *rmsg;
  const struct GNUNET_CREDENTIAL_RecordData *ard;
  struct AttributeRecordEntry *ar_entry;

  attr_record_count = 0;
  for (i=0; i < rd_count; i++)
  {
    if (GNUNET_GNSRECORD_TYPE_ATTRIBUTE != rd[i].record_type)
      continue;
    attr_record_count++;
    ard = rd[i].data;
    /**
     * TODO:
     * Check if we have already found our credential here
     * If so return success
     * Else
     *  Save all found attributes/issues and prepare forward
     *  resolution of issuer attribute
     */
    ar_entry = GNUNET_new (struct AttributeRecordEntry);
    ar_entry->record_data = *ard;
    GNUNET_CONTAINER_DLL_insert_tail (vrh->attr_chain_head,
                                      vrh->attr_chain_tail,
                                      ar_entry);

  }

  /**
   * Get serialized record data size
   */
  len = attr_record_count * sizeof (struct GNUNET_CREDENTIAL_RecordData);

  /**
   * Prepare a lookup result response message for the client
   */
  env = GNUNET_MQ_msg_extra (rmsg,
                             len,
                             GNUNET_MESSAGE_TYPE_CREDENTIAL_VERIFY_RESULT);
  //Assign id so that client can find associated request
  rmsg->id = vrh->request_id;
  rmsg->ad_count = htonl (attr_record_count);

  /**
   * Get serialized record data
   * Append at the end of rmsg
   */
  i = 0;
  struct GNUNET_CREDENTIAL_RecordData *tmp_record = (struct GNUNET_CREDENTIAL_RecordData*) &rmsg[1];
  for (ar_entry = vrh->attr_chain_head; NULL != ar_entry; ar_entry = ar_entry->next)
  {
    memcpy (tmp_record,
            &ar_entry->record_data,
            sizeof (struct GNUNET_CREDENTIAL_RecordData));
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
                            "Attributes resolved",
                            rd_count,
                            GNUNET_NO);
}

/**
 * Handle attribute verification requests from client
 *
 * @param cls the closure
 * @param client the client
 * @param message the message
 */
static void
handle_verify (void *cls,
               const struct VerifyMessage *v_msg) 
{
  char issuer_attribute[GNUNET_CREDENTIAL_MAX_LENGTH + 1];
  char subject_attribute[GNUNET_CREDENTIAL_MAX_LENGTH + 1];
  size_t issuer_attribute_len;
  struct VerifyRequestHandle *vrh;
  struct GNUNET_SERVICE_Client *client = cls;
  char *attrptr = issuer_attribute;
  const char *utf_in;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received VERIFY message\n");

  utf_in = (const char *) &v_msg[1];
  GNUNET_STRINGS_utf8_tolower (utf_in, attrptr);
  issuer_attribute_len = strlen (utf_in);
  utf_in = (const char *) (&v_msg[1] + issuer_attribute_len + 1);
  attrptr = subject_attribute;
  GNUNET_STRINGS_utf8_tolower (utf_in, attrptr);
  vrh = GNUNET_new (struct VerifyRequestHandle);
  GNUNET_CONTAINER_DLL_insert (vrh_head, vrh_tail, vrh);
  vrh->client = client;
  vrh->request_id = v_msg->id;
  vrh->issuer_key = v_msg->issuer_key;
  vrh->subject_key = v_msg->subject_key;

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
                                           GNUNET_GNSRECORD_TYPE_ATTRIBUTE,
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

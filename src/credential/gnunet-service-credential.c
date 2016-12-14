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
#include "credential_serialization.h"
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

struct VerifyRequestHandle;

struct GNUNET_CREDENTIAL_DelegationChainEntry
{
  /**
   * The issuer
   */
  struct GNUNET_CRYPTO_EcdsaPublicKey issuer_key;
  
  /**
   * The subject
   */
  struct GNUNET_CRYPTO_EcdsaPublicKey subject_key;
  
  /**
   * The issued attribute
   */
  char *issuer_attribute;
  
  /**
   * The delegated attribute
   */
  char *subject_attribute;
};

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
 * DLL for delegations - Used as a queue
 * Insert tail - Pop head
 */
struct DelegationQueueEntry
{
  /**
   * DLL
   */
  struct DelegationQueueEntry *next;

  /**
   * DLL
   */
  struct DelegationQueueEntry *prev;

  /**
   * Children of this attribute
   */
  struct DelegationQueueEntry *children_head;

  /**
   * Children of this attribute
   */
  struct DelegationQueueEntry *children_tail;

  /**
   * GNS handle
   */
  struct GNUNET_GNS_LookupRequest *lookup_request;

  /**
   * Verify handle
   */
  struct VerifyRequestHandle *handle;

  /**
   * Parent attribute delegation
   */
  struct DelegationQueueEntry *parent;

  /**
   * Issuer key
   */
  struct GNUNET_CRYPTO_EcdsaPublicKey *issuer_key;

  /**
   * Issuer attribute delegated to
   */
  char *issuer_attribute;

  /**
   * The current attribute to look up
   */
  char *lookup_attribute;

  /**
   * Trailing attribute context
   */
  char *attr_trailer;

  /**
   * Still to resolve delegation as string
   */
  char *unresolved_attribute_delegation;
  
  /**
   * The delegation chain entry
   */
  struct GNUNET_CREDENTIAL_DelegationChainEntry *delegation_chain_entry;

  /**
   * Delegation chain length until now
   */
  uint32_t d_count;
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
   * GNS handle
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
   * Delegation Queue
   */
  struct DelegationQueueEntry *chain_start;
  
  /**
   * Delegation Queue
   */
  struct DelegationQueueEntry *chain_end;
  
  /**
   * Current Delegation Pointer
   */
  struct DelegationQueueEntry *current_delegation;

  /**
   * The found credential
   */
  struct GNUNET_CREDENTIAL_CredentialRecordData *credential;

  /**
   * Length of the credential
   */
  uint32_t credential_size;

  /**
   * Length of found delegation chain
   */
  uint32_t d_count;

  /**
   * request id
   */
  uint32_t request_id;

  /**
   * Pending lookups
   */
  uint64_t pending_lookups;

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


static void
cleanup_delegation_queue (struct DelegationQueueEntry *dq_entry)
{
  struct DelegationQueueEntry *child;
  if (NULL == dq_entry)
    return;

  for (child = dq_entry->children_head; NULL != child; child = dq_entry->children_head)
  {
    GNUNET_CONTAINER_DLL_remove (dq_entry->children_head,
                                 dq_entry->children_tail,
                                 child);
    cleanup_delegation_queue (child);
  }
  if (NULL != dq_entry->issuer_key)
    GNUNET_free (dq_entry->issuer_key);
  if (NULL != dq_entry->lookup_attribute)
    GNUNET_free (dq_entry->lookup_attribute);
  if (NULL != dq_entry->issuer_attribute)
    GNUNET_free (dq_entry->issuer_attribute);
  if (NULL != dq_entry->unresolved_attribute_delegation)
    GNUNET_free (dq_entry->unresolved_attribute_delegation);
  if (NULL != dq_entry->attr_trailer)
    GNUNET_free (dq_entry->attr_trailer);
  if (NULL != dq_entry->lookup_request)
  {
    GNUNET_GNS_lookup_cancel (dq_entry->lookup_request);
    dq_entry->lookup_request = NULL;
  }
  if (NULL != dq_entry->delegation_chain_entry)
  {
    if (NULL != dq_entry->delegation_chain_entry->subject_attribute)
      GNUNET_free (dq_entry->delegation_chain_entry->subject_attribute);
    if (NULL != dq_entry->delegation_chain_entry->issuer_attribute)
      GNUNET_free (dq_entry->delegation_chain_entry->issuer_attribute);
    GNUNET_free (dq_entry->delegation_chain_entry);
  }
  GNUNET_free (dq_entry);
}

static void
cleanup_handle (struct VerifyRequestHandle *vrh)
{
  struct CredentialRecordEntry *cr_entry;
  GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
              "Cleaning up...\n");
  if (NULL != vrh->lookup_request)
  {
    GNUNET_GNS_lookup_cancel (vrh->lookup_request);
    vrh->lookup_request = NULL;
  }
  if (NULL != vrh->credential)
    GNUNET_free (vrh->credential);
  cleanup_delegation_queue (vrh->chain_start);
  if (NULL != vrh->issuer_attribute)
    GNUNET_free (vrh->issuer_attribute);
  for (cr_entry = vrh->cred_chain_head; 
       NULL != vrh->cred_chain_head;
       cr_entry = vrh->cred_chain_head)
  {
    GNUNET_CONTAINER_DLL_remove (vrh->cred_chain_head,
                                 vrh->cred_chain_tail,
                                 cr_entry);
    if (NULL != cr_entry->data)
      GNUNET_free (cr_entry->data);
    GNUNET_free (cr_entry);
  }
  GNUNET_free (vrh);
}

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

  GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
              "Shutting down!\n");

  while (NULL != (vrh = vrh_head))
  {
    //CREDENTIAL_resolver_lookup_cancel (clh->lookup);
    GNUNET_CONTAINER_DLL_remove (vrh_head,
                                 vrh_tail,
                                 vrh);
    cleanup_handle (vrh);
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
  struct GNUNET_MQ_Envelope *env;
  struct VerifyResultMessage *rmsg;
  struct DelegationQueueEntry *dq_entry;
  size_t size = vrh->credential_size;
  struct GNUNET_CREDENTIAL_Delegation dd[vrh->d_count];
  struct GNUNET_CREDENTIAL_Credential cred;

  GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
              "Sending response\n");
  dq_entry = vrh->chain_end;
  for (int i=0; i<vrh->d_count; i++)
  {
    dd[i].issuer_key = dq_entry->delegation_chain_entry->issuer_key;
    dd[i].subject_key = dq_entry->delegation_chain_entry->subject_key;
    dd[i].issuer_attribute = dq_entry->delegation_chain_entry->issuer_attribute;
    dd[i].issuer_attribute_len = strlen (dq_entry->delegation_chain_entry->issuer_attribute)+1;
    dd[i].subject_attribute_len = 0;
    if (NULL != dq_entry->delegation_chain_entry->subject_attribute)
    {
      dd[i].subject_attribute = dq_entry->delegation_chain_entry->subject_attribute;
      dd[i].subject_attribute_len = strlen(dq_entry->delegation_chain_entry->subject_attribute)+1;
    }
    dq_entry = dq_entry->parent;
  }

    /**
   * Get serialized record data
   * Append at the end of rmsg
   */
  cred.issuer_key = vrh->credential->issuer_key;
  cred.subject_key = vrh->credential->issuer_key;
  cred.issuer_attribute_len = strlen((char*)&vrh->credential[1]);
  cred.issuer_attribute = (char*)&vrh->credential[1];
  size = GNUNET_CREDENTIAL_delegation_chain_get_size (vrh->d_count,
                                                      dd,
                                                      &cred);
  env = GNUNET_MQ_msg_extra (rmsg,
                             size,
                             GNUNET_MESSAGE_TYPE_CREDENTIAL_VERIFY_RESULT);
  //Assign id so that client can find associated request
  rmsg->id = vrh->request_id;
  rmsg->d_count = htonl (vrh->d_count);

  if (NULL != vrh->credential)
    rmsg->cred_found = htonl (GNUNET_YES);
  else
    rmsg->cred_found = htonl (GNUNET_NO);

  GNUNET_assert (-1 != GNUNET_CREDENTIAL_delegation_chain_serialize (vrh->d_count,
                                                dd,
                                                &cred,
                                                size,
                                                (char*)&rmsg[1]));

  GNUNET_MQ_send (GNUNET_SERVICE_client_get_mq(vrh->client),
                  env);
  GNUNET_CONTAINER_DLL_remove (vrh_head, vrh_tail, vrh);
  cleanup_handle(vrh);

  GNUNET_STATISTICS_update (statistics,
                            "Completed verifications", 1,
                            GNUNET_NO);
}


static void
backward_resolution (void* cls,
                     uint32_t rd_count,
                     const struct GNUNET_GNSRECORD_Data *rd)
{

  struct VerifyRequestHandle *vrh;
  struct GNUNET_CREDENTIAL_CredentialRecordData *cred;
  const struct GNUNET_CREDENTIAL_AttributeRecordData *attr;
  struct CredentialRecordEntry *cred_pointer;
  struct DelegationQueueEntry *current_delegation;
  struct DelegationQueueEntry *dq_entry;
  char *expanded_attr;
  int i;


  current_delegation = cls;
  current_delegation->lookup_request = NULL;
  vrh = current_delegation->handle;
  vrh->pending_lookups--;
  GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
              "Got %d attrs\n", rd_count);

  for (i=0; i < rd_count; i++) 
  {
    if (GNUNET_GNSRECORD_TYPE_ATTRIBUTE != rd[i].record_type)
      continue;

    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Found new attribute delegation. Creating new Job...\n");
    attr = rd[i].data;
    dq_entry = GNUNET_new (struct DelegationQueueEntry);
    if (NULL != current_delegation->attr_trailer)
    {
      if (rd[i].data_size == sizeof (struct GNUNET_CREDENTIAL_AttributeRecordData))
      {
        GNUNET_asprintf (&expanded_attr,
                         "%s",
                         current_delegation->attr_trailer);

      } else {
        GNUNET_asprintf (&expanded_attr,
                         "%s.%s",
                         (char*)&attr[1],
                         current_delegation->attr_trailer);
      }
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  "Expanded to %s\n", expanded_attr);
      dq_entry->unresolved_attribute_delegation = expanded_attr;
    } else {
      if (rd[i].data_size > sizeof (struct GNUNET_CREDENTIAL_AttributeRecordData))
      {
        GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                    "Not Expanding %s\n", (char*)&attr[1]);
        dq_entry->unresolved_attribute_delegation = GNUNET_strdup ((char*)&attr[1]);
      }
    }

    //Add a credential chain entry
    dq_entry->delegation_chain_entry = GNUNET_new (struct GNUNET_CREDENTIAL_DelegationChainEntry);
    dq_entry->delegation_chain_entry->subject_key = attr->subject_key;
    dq_entry->issuer_key = GNUNET_new (struct GNUNET_CRYPTO_EcdsaPublicKey);
    GNUNET_memcpy (dq_entry->issuer_key,
                   &attr->subject_key,
                   sizeof (struct GNUNET_CRYPTO_EcdsaPublicKey));
    if (rd[i].data_size > sizeof (struct GNUNET_CREDENTIAL_AttributeRecordData))
      dq_entry->delegation_chain_entry->subject_attribute =  GNUNET_strdup ((char*)&attr[1]);
    dq_entry->delegation_chain_entry->issuer_key = *current_delegation->issuer_key;
    dq_entry->delegation_chain_entry->issuer_attribute = GNUNET_strdup (current_delegation->lookup_attribute);

    dq_entry->parent = current_delegation;
    dq_entry->d_count = current_delegation->d_count + 1;
    GNUNET_CONTAINER_DLL_insert (current_delegation->children_head,
                                 current_delegation->children_tail,
                                 dq_entry);
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Checking for cred match\n");
    /**
     * Check if this delegation already matches one of our credentials
     */
    for(cred_pointer = vrh->cred_chain_head; cred_pointer != NULL; 
        cred_pointer = cred_pointer->next)
    {
      cred = cred_pointer->data;
      if(0 != memcmp (&attr->subject_key, 
                      &cred_pointer->data->issuer_key,
                      sizeof(struct GNUNET_CRYPTO_EcdsaPublicKey)))
        continue;
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  "Checking if %s matches %s\n",
                  dq_entry->unresolved_attribute_delegation, (char*)&cred[1]);

      if (0 != strcmp (dq_entry->unresolved_attribute_delegation, (char*)&cred[1]))
        continue;

      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  "Found issuer\n");
      vrh->credential = GNUNET_malloc (cred_pointer->data_size);
      vrh->credential_size = cred_pointer->data_size;
      vrh->chain_end = dq_entry;
      vrh->d_count = dq_entry->d_count;
      //Found match
      send_lookup_response (vrh);
      return;

    }
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Building new lookup request\n");
    //Continue with backward resolution
    char issuer_attribute_name[strlen (dq_entry->unresolved_attribute_delegation)+1];
    strcpy (issuer_attribute_name,
            dq_entry->unresolved_attribute_delegation);
    char *next_attr = strtok (issuer_attribute_name, ".");
    GNUNET_asprintf (&dq_entry->lookup_attribute,
                     "%s.gnu",
                     next_attr);
    if (strlen (next_attr) == strlen (dq_entry->unresolved_attribute_delegation))
    {
      dq_entry->attr_trailer = NULL;
    } else {
      next_attr += strlen (next_attr) + 1;
      dq_entry->attr_trailer = GNUNET_strdup (next_attr);
    }

    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Looking up %s\n", dq_entry->lookup_attribute);
    if (NULL != dq_entry->attr_trailer)
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  "%s still to go...\n", dq_entry->attr_trailer);

    vrh->pending_lookups++;
    dq_entry->handle = vrh;
    dq_entry->lookup_request = GNUNET_GNS_lookup (gns,
                                                  dq_entry->lookup_attribute,
                                                  dq_entry->issuer_key, //issuer_key,
                                                  GNUNET_GNSRECORD_TYPE_ATTRIBUTE,
                                                  GNUNET_GNS_LO_DEFAULT,
                                                  NULL, //shorten_key, always NULL
                                                  &backward_resolution,
                                                  dq_entry);
  }

  if(0 == vrh->pending_lookups)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "We are all out of attributes...\n");
    send_lookup_response (vrh);
    return;

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
handle_credential_query (void* cls,
                         uint32_t rd_count,
                         const struct GNUNET_GNSRECORD_Data *rd)
{
  struct VerifyRequestHandle *vrh = cls;
  struct DelegationQueueEntry *dq_entry;
  const struct GNUNET_CREDENTIAL_CredentialRecordData *crd;
  struct CredentialRecordEntry *cr_entry;
  int cred_record_count;
  int i;

  vrh->lookup_request = NULL;
  cred_record_count = 0;
  for (i=0; i < rd_count; i++)
  {
    if (GNUNET_GNSRECORD_TYPE_CREDENTIAL != rd[i].record_type)
      continue;
    cred_record_count++;
    crd = rd[i].data;
    if(GNUNET_OK != GNUNET_CRYPTO_ecdsa_verify(GNUNET_SIGNATURE_PURPOSE_CREDENTIAL, 
                                               &crd->purpose,
                                               &crd->signature,
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
    vrh->chain_end = NULL;
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
  GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
              "Looking up %s\n", issuer_attribute_name);
  dq_entry = GNUNET_new (struct DelegationQueueEntry);
  dq_entry->issuer_key = GNUNET_new (struct GNUNET_CRYPTO_EcdsaPublicKey);
  memcpy (dq_entry->issuer_key,
          &vrh->issuer_key,
          sizeof (struct GNUNET_CRYPTO_EcdsaPublicKey));
  dq_entry->issuer_attribute = GNUNET_strdup (vrh->issuer_attribute);
  dq_entry->handle = vrh;
  dq_entry->lookup_attribute = GNUNET_strdup (vrh->issuer_attribute);
  dq_entry->d_count = 0;
  vrh->chain_start = dq_entry;
  vrh->pending_lookups = 1;
  //Start with backward resolution
  dq_entry->lookup_request = GNUNET_GNS_lookup (gns,
                                                issuer_attribute_name,
                                                &vrh->issuer_key, //issuer_key,
                                                GNUNET_GNSRECORD_TYPE_ATTRIBUTE,
                                                GNUNET_GNS_LO_DEFAULT,
                                                NULL, //shorten_key, always NULL
                                                &backward_resolution,
                                                dq_entry);
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

  GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
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
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Looking up %s\n",
              subject_attribute);
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
  GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
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
  GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
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

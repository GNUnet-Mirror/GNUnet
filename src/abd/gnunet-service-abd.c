/*
     This file is part of GNUnet.
     Copyright (C) 2011-2013 GNUnet e.V.

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
 * @file abd/gnunet-service-abd.c
 * @brief GNUnet Credential Service (main service)
 * @author Martin Schanzenbach
 */
#include "platform.h"

#include "gnunet_util_lib.h"

#include "abd.h"
#include "abd_serialization.h"
#include "gnunet_abd_service.h"
#include "gnunet_protocols.h"
#include "gnunet_signatures.h"
#include "gnunet_statistics_service.h"
#include <gnunet_dnsparser_lib.h>
#include <gnunet_gns_service.h>
#include <gnunet_gnsrecord_lib.h>
#include <gnunet_identity_service.h>
#include <gnunet_namestore_service.h>


#define GNUNET_ABD_MAX_LENGTH 255

struct VerifyRequestHandle;

struct DelegationSetQueueEntry;


struct DelegationChainEntry
{
  /**
   * DLL
   */
  struct DelegationChainEntry *next;

  /**
   * DLL
   */
  struct DelegationChainEntry *prev;

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
struct DelegateRecordEntry
{
  /**
   * DLL
   */
  struct DelegateRecordEntry *next;

  /**
   * DLL
   */
  struct DelegateRecordEntry *prev;

  /**
   * Number of references in delegation chains
   */
  uint32_t refcount;

  /**
   * Payload
   */
  struct GNUNET_ABD_Delegate *delegate;
};

/**
 * DLL used for delegations
 * Used for OR delegations
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
   * Parent set
   */
  struct DelegationSetQueueEntry *parent_set;

  /**
   * Required solutions
   */
  uint32_t required_solutions;
};

/**
 * DLL for delegation sets
 * Used for AND delegation set
 */
struct DelegationSetQueueEntry
{
  /**
   * DLL
   */
  struct DelegationSetQueueEntry *next;

  /**
   * DLL
   */
  struct DelegationSetQueueEntry *prev;

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
   * Queue entries of this set
   */
  struct DelegationQueueEntry *queue_entries_head;

  /**
   * Queue entries of this set
   */
  struct DelegationQueueEntry *queue_entries_tail;

  /**
   * Parent QueueEntry
   */
  struct DelegationQueueEntry *parent_queue_entry;

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
  struct DelegationChainEntry *delegation_chain_entry;

  /**
   * True if added by backward resolution
   */
  bool from_bw;
};


/**
 * Handle to a lookup operation from api
 */
struct VerifyRequestHandle
{
  /**
   * True if created by a collect request.
   */
  bool is_collect;
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
   * Size of delegation tree
   */
  uint32_t delegation_chain_size;

  /**
   * Children of this attribute
   */
  struct DelegationChainEntry *delegation_chain_head;

  /**
   * Children of this attribute
   */
  struct DelegationChainEntry *delegation_chain_tail;

  /**
   * List for bidirectional matching
   */
  struct DelegationSetQueueEntry *dsq_head;

  /**
   * List for bidirectional matching
   */
  struct DelegationSetQueueEntry *dsq_tail;

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
   * Delegate DLL
   */
  struct DelegateRecordEntry *del_chain_head;

  /**
   * Delegate DLL
   */
  struct DelegateRecordEntry *del_chain_tail;

  /**
   * Delegate DLL size
   */
  uint32_t del_chain_size;

  /**
   * Current Delegation Pointer
   */
  struct DelegationQueueEntry *current_delegation;

  /**
   * request id
   */
  uint32_t request_id;

  /**
   * Pending lookups
   */
  uint64_t pending_lookups;

  /**
   * Direction of the resolution algo
   */
  enum GNUNET_ABD_AlgoDirectionFlags resolution_algo;

  /**
   * Delegate iterator for lookup
   */
  struct GNUNET_NAMESTORE_QueueEntry *dele_qe;
};


/**
 * Head of the DLL.
 */
static struct VerifyRequestHandle *vrh_head = NULL;

/**
 * Tail of the DLL.
 */
static struct VerifyRequestHandle *vrh_tail = NULL;

/**
 * Handle to the statistics service
 */
static struct GNUNET_STATISTICS_Handle *statistics;

/**
 * Handle to GNS service.
 */
static struct GNUNET_GNS_Handle *gns;

/**
 * Handle to namestore service
 */
static struct GNUNET_NAMESTORE_Handle *namestore;

static void
print_deleset (struct DelegationSetQueueEntry *dsentry, char *text)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "%s %s.%s <- %s.%s\n",
              text,
              GNUNET_CRYPTO_ecdsa_public_key_to_string (
                &dsentry->delegation_chain_entry->issuer_key),
              dsentry->delegation_chain_entry->issuer_attribute,
              GNUNET_CRYPTO_ecdsa_public_key_to_string (
                &dsentry->delegation_chain_entry->subject_key),
              dsentry->delegation_chain_entry->subject_attribute);
}


static void
cleanup_dsq_entry (struct DelegationSetQueueEntry *ds_entry)
{
  GNUNET_free_non_null (ds_entry->issuer_key);
  GNUNET_free_non_null (ds_entry->issuer_attribute);
  GNUNET_free_non_null (ds_entry->attr_trailer);
  // those fields are only set/used in bw search
  if (ds_entry->from_bw)
  {
    GNUNET_free_non_null (ds_entry->lookup_attribute);
    GNUNET_free_non_null (ds_entry->unresolved_attribute_delegation);
  }
  if (NULL != ds_entry->lookup_request)
  {
    GNUNET_GNS_lookup_cancel (ds_entry->lookup_request);
    ds_entry->lookup_request = NULL;
  }
  if (NULL != ds_entry->delegation_chain_entry)
  {
    GNUNET_free_non_null (
      ds_entry->delegation_chain_entry->subject_attribute);
    GNUNET_free_non_null (ds_entry->delegation_chain_entry->issuer_attribute);
    GNUNET_free (ds_entry->delegation_chain_entry);
  }
  // Free DQ entries
  for (struct DelegationQueueEntry *dq_entry = ds_entry->queue_entries_head;
       NULL != ds_entry->queue_entries_head;
       dq_entry = ds_entry->queue_entries_head)
  {
    GNUNET_CONTAINER_DLL_remove (ds_entry->queue_entries_head,
                                 ds_entry->queue_entries_tail,
                                 dq_entry);
    GNUNET_free (dq_entry);
  }
  GNUNET_free (ds_entry);
}


static void
cleanup_handle (struct VerifyRequestHandle *vrh)
{
  struct DelegateRecordEntry *del_entry;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Cleaning up...\n");

  if (NULL != vrh->dsq_head)
  {
    for (struct DelegationSetQueueEntry *ds_entry = vrh->dsq_head; NULL !=
         vrh->dsq_head;
         ds_entry = vrh->dsq_head)
    {
      GNUNET_CONTAINER_DLL_remove (vrh->dsq_head, vrh->dsq_tail, ds_entry);
      cleanup_dsq_entry (ds_entry);
    }
  }
  if (NULL != vrh->del_chain_head)
  {
    for (del_entry = vrh->del_chain_head; NULL != vrh->del_chain_head;
         del_entry = vrh->del_chain_head)
    {
      GNUNET_CONTAINER_DLL_remove (vrh->del_chain_head,
                                   vrh->del_chain_tail,
                                   del_entry);
      GNUNET_free_non_null (del_entry->delegate);
      GNUNET_free (del_entry);
    }
  }
  GNUNET_free_non_null (vrh->issuer_attribute);
  GNUNET_free (vrh);
}


static void
shutdown_task (void *cls)
{
  struct VerifyRequestHandle *vrh;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Shutting down!\n");

  while (NULL != (vrh = vrh_head))
  {
    // ABD_resolver_lookup_cancel (clh->lookup);
    GNUNET_CONTAINER_DLL_remove (vrh_head, vrh_tail, vrh);
    cleanup_handle (vrh);
  }

  if (NULL != gns)
  {
    GNUNET_GNS_disconnect (gns);
    gns = NULL;
  }
  if (NULL != namestore)
  {
    GNUNET_NAMESTORE_disconnect (namestore);
    namestore = NULL;
  }
  if (NULL != statistics)
  {
    GNUNET_STATISTICS_destroy (statistics, GNUNET_NO);
    statistics = NULL;
  }
}


static void
send_intermediate_response (struct VerifyRequestHandle *vrh, struct
                            DelegationChainEntry *ch_entry, bool is_bw)
{
  struct DelegationChainIntermediateMessage *rmsg;
  struct GNUNET_MQ_Envelope *env;
  struct GNUNET_ABD_Delegation *dd;
  size_t size;

  // Don't report immediate results during collect
  if (vrh->is_collect)
    return;

  dd = GNUNET_new (struct GNUNET_ABD_Delegation);
  dd->issuer_key = ch_entry->issuer_key;
  dd->subject_key = ch_entry->subject_key;
  dd->issuer_attribute = ch_entry->issuer_attribute;
  dd->issuer_attribute_len = strlen (ch_entry->issuer_attribute) + 1;
  dd->subject_attribute_len = 0;
  dd->subject_attribute = NULL;
  if (NULL != ch_entry->subject_attribute)
  {
    dd->subject_attribute = ch_entry->subject_attribute;
    dd->subject_attribute_len = strlen (ch_entry->subject_attribute) + 1;
  }


  size = GNUNET_ABD_delegation_chain_get_size (1,
                                               dd,
                                               0,
                                               NULL);

  env = GNUNET_MQ_msg_extra (rmsg,
                             size,
                             GNUNET_MESSAGE_TYPE_ABD_INTERMEDIATE_RESULT);
  // Assign id so that client can find associated request
  rmsg->id = vrh->request_id;
  rmsg->is_bw = htons (is_bw);
  rmsg->size = htonl (size);

  GNUNET_assert (
    -1 != GNUNET_ABD_delegation_chain_serialize (1,
                                                 dd,
                                                 0,
                                                 NULL,
                                                 size,
                                                 (char *) &rmsg[1]));
  GNUNET_MQ_send (GNUNET_SERVICE_client_get_mq (vrh->client), env);
}


static void
send_lookup_response (struct VerifyRequestHandle *vrh)
{
  struct GNUNET_MQ_Envelope *env;
  struct DelegationChainResultMessage *rmsg;
  struct DelegationChainEntry *dce;
  struct GNUNET_ABD_Delegation dd[vrh->delegation_chain_size];
  struct GNUNET_ABD_Delegate dele[vrh->del_chain_size];
  struct DelegateRecordEntry *del;
  struct DelegateRecordEntry *tmp;
  size_t size;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Sending response\n");
  dce = vrh->delegation_chain_head;
  for (uint32_t i = 0; i < vrh->delegation_chain_size; i++)
  {
    dd[i].issuer_key = dce->issuer_key;
    dd[i].subject_key = dce->subject_key;
    dd[i].issuer_attribute = dce->issuer_attribute;
    dd[i].issuer_attribute_len = strlen (dce->issuer_attribute) + 1;
    dd[i].subject_attribute_len = 0;
    dd[i].subject_attribute = NULL;
    if (NULL != dce->subject_attribute)
    {
      dd[i].subject_attribute = dce->subject_attribute;
      dd[i].subject_attribute_len = strlen (dce->subject_attribute) + 1;
    }
    dce = dce->next;
  }

  // Remove all not needed credentials
  for (del = vrh->del_chain_head; NULL != del;)
  {
    if (del->refcount > 0)
    {
      del = del->next;
      continue;
    }
    tmp = del;
    del = del->next;
    GNUNET_CONTAINER_DLL_remove (vrh->del_chain_head, vrh->del_chain_tail, tmp);
    GNUNET_free (tmp->delegate);
    GNUNET_free (tmp);
    vrh->del_chain_size--;
  }

  // Get serialized record data
  // Append at the end of rmsg
  del = vrh->del_chain_head;
  for (uint32_t i = 0; i < vrh->del_chain_size; i++)
  {
    dele[i].issuer_key = del->delegate->issuer_key;
    dele[i].subject_key = del->delegate->subject_key;
    dele[i].issuer_attribute_len = strlen (del->delegate->issuer_attribute) + 1;
    dele[i].issuer_attribute = del->delegate->issuer_attribute;
    dele[i].subject_attribute_len = del->delegate->subject_attribute_len;
    dele[i].subject_attribute = del->delegate->subject_attribute;
    dele[i].expiration = del->delegate->expiration;
    dele[i].signature = del->delegate->signature;
    del = del->next;
  }
  size =
    GNUNET_ABD_delegation_chain_get_size (vrh->delegation_chain_size,
                                          dd,
                                          vrh->del_chain_size,
                                          dele);
  env = GNUNET_MQ_msg_extra (rmsg,
                             size,
                             GNUNET_MESSAGE_TYPE_ABD_VERIFY_RESULT);
  // Assign id so that client can find associated request
  rmsg->id = vrh->request_id;
  rmsg->d_count = htonl (vrh->delegation_chain_size);
  rmsg->c_count = htonl (vrh->del_chain_size);

  if (0 < vrh->del_chain_size)
    rmsg->del_found = htonl (GNUNET_YES);
  else
    rmsg->del_found = htonl (GNUNET_NO);

  GNUNET_assert (
    -1 !=
    GNUNET_ABD_delegation_chain_serialize (vrh->delegation_chain_size,
                                           dd,
                                           vrh->del_chain_size,
                                           dele,
                                           size,
                                           (char *) &rmsg[1]));

  GNUNET_MQ_send (GNUNET_SERVICE_client_get_mq (vrh->client), env);
  GNUNET_CONTAINER_DLL_remove (vrh_head, vrh_tail, vrh);
  cleanup_handle (vrh);
  GNUNET_STATISTICS_update (statistics,
                            "Completed verifications",
                            1,
                            GNUNET_NO);
}


static char *
partial_match (char *tmp_trail,
               char *tmp_subattr,
               char *parent_trail,
               char *issuer_attribute)
{
  char *saveptr1, *saveptr2;
  char *trail_token;
  char *sub_token;
  char *attr_trailer;

  // tok both, parent->attr_trailer and del->sub_attr to see how far they match,
  // take rest of parent trailer (only when del->sub_attr token is null), and
  // create new/actual trailer with del->iss_attr
  trail_token = strtok_r (tmp_trail, ".", &saveptr1);
  sub_token = strtok_r (tmp_subattr, ".", &saveptr2);
  while (NULL != trail_token && NULL != sub_token)
  {
    if (0 == strcmp (trail_token, sub_token))
    {
      // good, matches, remove
    }
    else
    {
      // not relevant for solving the chain, end for iteration here
      return NULL;
    }

    trail_token = strtok_r (NULL, ".", &saveptr1);
    sub_token = strtok_r (NULL, ".", &saveptr2);
  }
  // skip this entry and go to next for if:
  // 1. at some point the attr of the trailer and the subject dont match
  // 2. the trailer is NULL, but the subject has more attributes
  // Reason: This will lead to "startzone.attribute" but we're looking for a solution
  // for "<- startzone"
  if (NULL == trail_token)
  {
    return NULL;
  }

  // do not have to check sub_token == NULL, if both would be NULL
  // at the same time, the complete match part above should have triggered already

  // otherwise, above while only ends when sub_token == NULL
  GNUNET_asprintf (&attr_trailer, "%s", trail_token);
  trail_token = strtok_r (NULL, ".", &saveptr1);
  while (NULL != trail_token)
  {
    GNUNET_asprintf (&attr_trailer, "%s.%s", parent_trail, trail_token);
    trail_token = strtok_r (NULL, ".", &saveptr1);
  }
  GNUNET_asprintf (&attr_trailer, "%s.%s", issuer_attribute, attr_trailer);
  return attr_trailer;
}


static int
handle_bidirectional_match (struct DelegationSetQueueEntry *actual_entry,
                            struct DelegationSetQueueEntry *match_entry,
                            struct VerifyRequestHandle *vrh)
{
  struct DelegationSetQueueEntry *old_fw_parent;
  struct DelegationSetQueueEntry *fw_entry = actual_entry;
  struct DelegationSetQueueEntry *last_entry = match_entry;
  // parent fixing, combine backward and forward chain parts
  while (NULL != fw_entry->parent_queue_entry)
  {
    old_fw_parent = fw_entry->parent_queue_entry->parent_set;
    // set parent
    fw_entry->parent_queue_entry->parent_set = last_entry;

    last_entry = fw_entry;
    fw_entry = old_fw_parent;
  }
  // set last entry of chain as actual_entry
  // actual_entry = last_entry;
  // set refcount, loop all delegations
  for (struct DelegateRecordEntry *del_entry = vrh->del_chain_head;
       del_entry != NULL;
       del_entry = del_entry->next)
  {
    if (0 != memcmp (&last_entry->delegation_chain_entry->subject_key,
                     &del_entry->delegate->issuer_key,
                     sizeof (struct GNUNET_CRYPTO_EcdsaPublicKey)))
      continue;
    if (0 != strcmp (last_entry->delegation_chain_entry->subject_attribute,
                     del_entry->delegate->issuer_attribute))
      continue;

    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Found delegate.\n");
    // increase refcount of the start delegation
    del_entry->refcount++;
  }
  // backtrack
  for (struct DelegationSetQueueEntry *tmp_set = last_entry;
       NULL != tmp_set->parent_queue_entry;
       tmp_set = tmp_set->parent_queue_entry->parent_set)
  {
    tmp_set->parent_queue_entry->required_solutions--;

    // add new found entry to vrh
    vrh->delegation_chain_size++;
    GNUNET_CONTAINER_DLL_insert (vrh->delegation_chain_head,
                                 vrh->delegation_chain_tail,
                                 tmp_set->delegation_chain_entry);

    // if one node on the path still needs solutions, this current
    // patch cannot fullfil the conditions and therefore stops here
    // however, it is in the vrh and can be used by the other paths
    // related to this path/collection/verification
    if (0 < tmp_set->parent_queue_entry->required_solutions)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Chain requires more solutions, waiting...\n");
      return GNUNET_NO;
    }
  }
  return GNUNET_YES;
}


static void
forward_resolution (void *cls,
                    uint32_t rd_count,
                    const struct GNUNET_GNSRECORD_Data *rd)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Received %d entries.\n", rd_count);

  struct VerifyRequestHandle *vrh;
  struct DelegationSetQueueEntry *current_set;
  struct DelegationSetQueueEntry *ds_entry;
  struct DelegationQueueEntry *dq_entry;

  current_set = cls;
  // set handle to NULL (as el = NULL)
  current_set->lookup_request = NULL;
  vrh = current_set->handle;
  vrh->pending_lookups--;

  // Loop record entries
  for (uint32_t i = 0; i < rd_count; i++)
  {
    if (GNUNET_GNSRECORD_TYPE_DELEGATE != rd[i].record_type)
      continue;

    // Start deserialize into Delegate
    struct GNUNET_ABD_Delegate *del;
    del = GNUNET_ABD_delegate_deserialize (rd[i].data, rd[i].data_size);

    // Start: Create DQ Entry
    dq_entry = GNUNET_new (struct DelegationQueueEntry);
    // AND delegations are not possible, only 1 solution
    dq_entry->required_solutions = 1;
    dq_entry->parent_set = current_set;

    // Insert it into the current set
    GNUNET_CONTAINER_DLL_insert (current_set->queue_entries_head,
                                 current_set->queue_entries_tail,
                                 dq_entry);

    // Start: Create DS Entry
    ds_entry = GNUNET_new (struct DelegationSetQueueEntry);
    GNUNET_CONTAINER_DLL_insert (vrh->dsq_head, vrh->dsq_tail, ds_entry);
    ds_entry->from_bw = false;

    // (1) A.a <- A.b.c
    // (2) A.b <- D.d
    // (3) D.d <- E
    // (4) E.c <- F.c
    // (5) F.c <- G
    // Possibilities:
    // 1. complete match: trailer = 0, validate
    // 2. partial match: replace
    // 3. new solution: replace, add trailer

    // At resolution chain start trailer of parent is NULL
    if (NULL == current_set->attr_trailer)
    {
      // for (5) F.c <- G, remember .c when going upwards
      ds_entry->attr_trailer = GNUNET_strdup (del->issuer_attribute);
    }
    else
    {
      if (0 == del->subject_attribute_len)
      {
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Found: New solution\n");
        // new solution
        // create new trailer del->issuer_attribute, ds_entry->attr_trailer
        GNUNET_asprintf (&ds_entry->attr_trailer,
                         "%s.%s",
                         del->issuer_attribute,
                         current_set->attr_trailer);
      }
      else if (0 == strcmp (del->subject_attribute, current_set->attr_trailer))
      {
        // complete match
        // new trailer == issuer attribute (e.g. (5) to (4))
        ds_entry->attr_trailer = GNUNET_strdup (del->issuer_attribute);
      }
      else
      {
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Found: Partial match\n");
        // partial match

        char *trail = partial_match (GNUNET_strdup (current_set->attr_trailer),
                                     GNUNET_strdup (del->subject_attribute),
                                     current_set->attr_trailer,
                                     GNUNET_strdup (del->issuer_attribute));

        // if null: skip this record entry (reasons: mismatch or overmatch, both not relevant)
        if (NULL == trail)
        {
          GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                      "Entry not relevant, discarding: %s.%s <- %s.%s\n",
                      GNUNET_CRYPTO_ecdsa_public_key_to_string (
                        &del->issuer_key),
                      del->issuer_attribute,
                      GNUNET_CRYPTO_ecdsa_public_key_to_string (
                        &del->subject_key),
                      del->subject_attribute);
          continue;
        }
        else
          ds_entry->attr_trailer = trail;
      }
    }


    // Start: Credential Chain Entry
    // issuer key is subject key, who needs to be contacted to resolve this (forward, therefore subject)
    ds_entry->issuer_key = GNUNET_new (struct GNUNET_CRYPTO_EcdsaPublicKey);
    GNUNET_memcpy (ds_entry->issuer_key,
                   &del->subject_key,
                   sizeof (struct GNUNET_CRYPTO_EcdsaPublicKey));

    ds_entry->delegation_chain_entry = GNUNET_new (struct DelegationChainEntry);
    ds_entry->delegation_chain_entry->subject_key = del->subject_key;
    if (0 < del->subject_attribute_len)
      ds_entry->delegation_chain_entry->subject_attribute =
        GNUNET_strdup (del->subject_attribute);
    ds_entry->delegation_chain_entry->issuer_key = del->issuer_key;
    ds_entry->delegation_chain_entry->issuer_attribute =
      GNUNET_strdup (del->issuer_attribute);

    // Found new entry, repoting intermediate result
    send_intermediate_response (vrh, ds_entry->delegation_chain_entry, false);

    // current delegation as parent
    ds_entry->parent_queue_entry = dq_entry;

    // Check for solution
    // if: issuer key we looking for
    if (0 == memcmp (&del->issuer_key,
                     &vrh->issuer_key,
                     sizeof (struct GNUNET_CRYPTO_EcdsaPublicKey)))
    {
      // if: issuer attr we looking for
      if (0 == strcmp (del->issuer_attribute, vrh->issuer_attribute))
      {
        // if: complete match, meaning new trailer == issuer attr
        if (0 == strcmp (vrh->issuer_attribute, ds_entry->attr_trailer))
        {
          GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Found: Solution\n");

          // Add found solution into delegation_chain
          struct DelegationSetQueueEntry *tmp_set;
          for (tmp_set = ds_entry; NULL != tmp_set->parent_queue_entry;
               tmp_set = tmp_set->parent_queue_entry->parent_set)
          {
            if (NULL != tmp_set->delegation_chain_entry)
            {
              vrh->delegation_chain_size++;
              GNUNET_CONTAINER_DLL_insert (vrh->delegation_chain_head,
                                           vrh->delegation_chain_tail,
                                           tmp_set->delegation_chain_entry);
            }
          }

          // Increase refcount for this delegate
          for (struct DelegateRecordEntry *del_entry = vrh->del_chain_head;
               del_entry != NULL;
               del_entry = del_entry->next)
          {
            if (0 == memcmp (&del_entry->delegate->issuer_key,
                             &vrh->delegation_chain_head->subject_key,
                             sizeof (struct GNUNET_CRYPTO_EcdsaPublicKey)))
            {
              if (0 == strcmp (del_entry->delegate->issuer_attribute,
                               vrh->delegation_chain_head->subject_attribute))
              {
                del_entry->refcount++;
              }
            }
          }

          send_lookup_response (vrh);
          return;
        }
      }
    }

    // Check for bidirectional crossmatch
    for (struct DelegationSetQueueEntry *del_entry = vrh->dsq_head;
         del_entry != NULL;
         del_entry = del_entry->next)
    {
      // only check entries not by backward algorithm
      if (del_entry->from_bw)
      {
        // key of list entry matches actual key
        if (0 == memcmp (&del_entry->delegation_chain_entry->subject_key,
                         &ds_entry->delegation_chain_entry->issuer_key,
                         sizeof (struct GNUNET_CRYPTO_EcdsaPublicKey)))
        {
          // compare entry subject attributes to this trailer (iss attr + old trailer)
          if (0 == strcmp (del_entry->unresolved_attribute_delegation,
                           ds_entry->attr_trailer))
          {
            print_deleset (del_entry, "Forward:");
            GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                        "Forward: Found match with above!\n");

            // one node on the path still needs solutions: return
            if (GNUNET_NO ==
                handle_bidirectional_match (ds_entry, del_entry, vrh))
              return;

            send_lookup_response (vrh);
            return;
          }
        }
      }
    }

    // Starting a new GNS lookup
    vrh->pending_lookups++;
    ds_entry->handle = vrh;

    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Starting to look up trailer %s in zone %s\n",
                ds_entry->attr_trailer,
                GNUNET_CRYPTO_ecdsa_public_key_to_string (&del->issuer_key));

    ds_entry->lookup_request =
      GNUNET_GNS_lookup (gns,
                         GNUNET_GNS_EMPTY_LABEL_AT,
                         &del->issuer_key,
                         GNUNET_GNSRECORD_TYPE_DELEGATE,
                         GNUNET_GNS_LO_DEFAULT,
                         &forward_resolution,
                         ds_entry);
  }

  if (0 == vrh->pending_lookups)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "We are all out of attributes...\n");
    send_lookup_response (vrh);
    return;
  }
}


static void
backward_resolution (void *cls,
                     uint32_t rd_count,
                     const struct GNUNET_GNSRECORD_Data *rd)
{
  struct VerifyRequestHandle *vrh;
  const struct GNUNET_ABD_DelegationRecord *sets;
  struct DelegateRecordEntry *del_pointer;
  struct DelegationSetQueueEntry *current_set;
  struct DelegationSetQueueEntry *ds_entry;
  struct DelegationSetQueueEntry *tmp_set;
  struct DelegationQueueEntry *dq_entry;
  char *expanded_attr;
  char *lookup_attribute;

  current_set = cls;
  current_set->lookup_request = NULL;
  vrh = current_set->handle;
  vrh->pending_lookups--;

  // Each OR
  for (uint32_t i = 0; i < rd_count; i++)
  {
    if (GNUNET_GNSRECORD_TYPE_ATTRIBUTE != rd[i].record_type)
      continue;

    sets = rd[i].data;
    struct GNUNET_ABD_DelegationSet set[ntohl (sets->set_count)];
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Found new attribute delegation with %d sets. Creating new Job...\n",
                ntohl (sets->set_count));

    if (GNUNET_OK !=
        GNUNET_ABD_delegation_set_deserialize (GNUNET_ntohll (
                                                 sets->data_size),
                                               (const char *) &sets[1],
                                               ntohl (sets->set_count),
                                               set))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Failed to deserialize!\n");
      continue;
    }
    dq_entry = GNUNET_new (struct DelegationQueueEntry);
    dq_entry->required_solutions = ntohl (sets->set_count);
    dq_entry->parent_set = current_set;

    GNUNET_CONTAINER_DLL_insert (current_set->queue_entries_head,
                                 current_set->queue_entries_tail,
                                 dq_entry);
    // Each AND
    for (uint32_t j = 0; j < ntohl (sets->set_count); j++)
    {
      ds_entry = GNUNET_new (struct DelegationSetQueueEntry);
      GNUNET_CONTAINER_DLL_insert (vrh->dsq_head, vrh->dsq_tail, ds_entry);
      ds_entry->from_bw = true;

      if (NULL != current_set->attr_trailer)
      {
        if (0 == set[j].subject_attribute_len)
        {
          GNUNET_asprintf (&expanded_attr, "%s", current_set->attr_trailer);
        }
        else
        {
          GNUNET_asprintf (&expanded_attr,
                           "%s.%s",
                           set[j].subject_attribute,
                           current_set->attr_trailer);
        }
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Expanded to %s\n", expanded_attr);
        ds_entry->unresolved_attribute_delegation = expanded_attr;
      }
      else
      {
        if (0 != set[j].subject_attribute_len)
        {
          GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                      "Not Expanding %s\n",
                      set[j].subject_attribute);
          ds_entry->unresolved_attribute_delegation =
            GNUNET_strdup (set[j].subject_attribute);
        }
      }

      // Add a credential chain entry
      ds_entry->delegation_chain_entry =
        GNUNET_new (struct DelegationChainEntry);
      ds_entry->delegation_chain_entry->subject_key = set[j].subject_key;
      ds_entry->issuer_key = GNUNET_new (struct GNUNET_CRYPTO_EcdsaPublicKey);
      GNUNET_memcpy (ds_entry->issuer_key,
                     &set[j].subject_key,
                     sizeof (struct GNUNET_CRYPTO_EcdsaPublicKey));
      if (0 < set[j].subject_attribute_len)
        ds_entry->delegation_chain_entry->subject_attribute =
          GNUNET_strdup (set[j].subject_attribute);
      ds_entry->delegation_chain_entry->issuer_key = *current_set->issuer_key;
      ds_entry->delegation_chain_entry->issuer_attribute =
        GNUNET_strdup (current_set->lookup_attribute);

      // Found new entry, repoting intermediate result
      send_intermediate_response (vrh, ds_entry->delegation_chain_entry, true);

      ds_entry->parent_queue_entry = dq_entry; // current_delegation;

      /**
       * Check if this delegation already matches one of our credentials
       */
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Checking for cred match\n");

      for (del_pointer = vrh->del_chain_head; del_pointer != NULL;
           del_pointer = del_pointer->next)
      {
        // If key and attribute match credential: continue and backtrack
        if (0 != memcmp (&set[j].subject_key,
                         &del_pointer->delegate->issuer_key,
                         sizeof (struct GNUNET_CRYPTO_EcdsaPublicKey)))
          continue;
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                    "Checking if %s matches %s\n",
                    ds_entry->unresolved_attribute_delegation,
                    del_pointer->delegate->issuer_attribute);

        if (0 != strcmp (ds_entry->unresolved_attribute_delegation,
                         del_pointer->delegate->issuer_attribute))
          continue;

        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Found issuer\n");
        // increase refcount of the start delegation
        del_pointer->refcount++;

        // Backtrack
        for (tmp_set = ds_entry; NULL != tmp_set->parent_queue_entry;
             tmp_set = tmp_set->parent_queue_entry->parent_set)
        {
          tmp_set->parent_queue_entry->required_solutions--;
          if (NULL != tmp_set->delegation_chain_entry)
          {
            vrh->delegation_chain_size++;
            GNUNET_CONTAINER_DLL_insert (vrh->delegation_chain_head,
                                         vrh->delegation_chain_tail,
                                         tmp_set->delegation_chain_entry);
          }
          if (0 < tmp_set->parent_queue_entry->required_solutions)
            break;
        }

        // if the break above is not called the condition of the for is met
        if (NULL == tmp_set->parent_queue_entry)
        {
          GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "All solutions found\n");
          // Found match
          send_lookup_response (vrh);
          return;
        }
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Not all solutions found yet.\n");
        continue;
      }

      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Building new lookup request from %s\n",
                  ds_entry->unresolved_attribute_delegation);
      // Continue with next/new backward resolution
      char issuer_attribute_name[strlen (
                                   ds_entry->unresolved_attribute_delegation)
                                 + 1];
      strcpy (issuer_attribute_name, ds_entry->unresolved_attribute_delegation);
      char *next_attr = strtok (issuer_attribute_name, ".");
      if (NULL == next_attr)
      {
        GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                    "Failed to parse next attribute\n");
        continue;
      }
      GNUNET_asprintf (&lookup_attribute, "%s", next_attr);
      GNUNET_asprintf (&ds_entry->lookup_attribute, "%s", next_attr);
      if (strlen (next_attr) ==
          strlen (ds_entry->unresolved_attribute_delegation))
      {
        ds_entry->attr_trailer = NULL;
      }
      else
      {
        next_attr += strlen (next_attr) + 1;
        ds_entry->attr_trailer = GNUNET_strdup (next_attr);
      }

      // Check for bidirectional crossmatch
      for (struct DelegationSetQueueEntry *del_entry = vrh->dsq_head;
           del_entry != NULL;
           del_entry = del_entry->next)
      {
        // only check entries added by forward algorithm
        if (! del_entry->from_bw)
        {
          // key of list entry matches actual key
          if (0 == memcmp (&del_entry->delegation_chain_entry->issuer_key,
                           &ds_entry->delegation_chain_entry->subject_key,
                           sizeof (struct GNUNET_CRYPTO_EcdsaPublicKey)))
          {
            // compare entry subject attributes to this trailer (iss attr + old trailer)
            if (0 == strcmp (del_entry->attr_trailer,
                             ds_entry->unresolved_attribute_delegation))
            {
              print_deleset (del_entry, "Backward:");
              GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                          "Backward: Found match with above!\n");

              // if one node on the path still needs solutions: return
              if (GNUNET_NO ==
                  handle_bidirectional_match (del_entry, ds_entry, vrh))
                break;

              // Send lookup response
              send_lookup_response (vrh);
              return;
            }
          }
        }
      }

      // Starting a new GNS lookup
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Looking up %s\n",
                  ds_entry->lookup_attribute);
      if (NULL != ds_entry->attr_trailer)
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                    "%s still to go...\n",
                    ds_entry->attr_trailer);

      vrh->pending_lookups++;
      ds_entry->handle = vrh;
      ds_entry->lookup_request =
        GNUNET_GNS_lookup (gns,
                           lookup_attribute,
                           ds_entry->issuer_key, // issuer_key,
                           GNUNET_GNSRECORD_TYPE_ATTRIBUTE,
                           GNUNET_GNS_LO_DEFAULT,
                           &backward_resolution,
                           ds_entry);

      GNUNET_free (lookup_attribute);
    }
  }

  if (0 == vrh->pending_lookups)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "We are all out of attributes...\n");
    send_lookup_response (vrh);
    return;
  }
}


/**
 * Result from GNS lookup.
 *
 * @param cls the closure (our client lookup handle)
 */
static int
delegation_chain_bw_resolution_start (void *cls)
{
  GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Start Backward Resolution...\n");

  struct VerifyRequestHandle *vrh = cls;
  struct DelegationSetQueueEntry *ds_entry;
  struct DelegateRecordEntry *del_entry;

  if (0 == vrh->del_chain_size)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "No delegates found\n");
    send_lookup_response (vrh);
    return 1;
  }

  // Pre-check with vrh->dele_chain_.. if match issuer_key
  // Backward: check every cred entry if match issuer key
  // otherwise: start at issuer and go down till match
  // A.a <- ...
  // X.x <- C
  // Y.y <- C
  // if not X.x or Y.y == A.a start at A
  for (del_entry = vrh->del_chain_head; del_entry != NULL;
       del_entry = del_entry->next)
  {
    if (0 != memcmp (&del_entry->delegate->issuer_key,
                     &vrh->issuer_key,
                     sizeof (struct GNUNET_CRYPTO_EcdsaPublicKey)))
      continue;
    if (0 !=
        strcmp (del_entry->delegate->issuer_attribute, vrh->issuer_attribute))
      continue;
    del_entry->refcount++;
    // Found match prematurely
    send_lookup_response (vrh);
    return 1;
  }


  // Check for attributes from the issuer and follow the chain
  // till you get the required subject's attributes
  char issuer_attribute_name[strlen (vrh->issuer_attribute) + 1];
  strcpy (issuer_attribute_name, vrh->issuer_attribute);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Looking up %s\n",
              issuer_attribute_name);
  ds_entry = GNUNET_new (struct DelegationSetQueueEntry);
  GNUNET_CONTAINER_DLL_insert (vrh->dsq_head, vrh->dsq_tail, ds_entry);
  ds_entry->from_bw = true;
  ds_entry->issuer_key = GNUNET_new (struct GNUNET_CRYPTO_EcdsaPublicKey);
  GNUNET_memcpy (ds_entry->issuer_key,
                 &vrh->issuer_key,
                 sizeof (struct GNUNET_CRYPTO_EcdsaPublicKey));
  ds_entry->issuer_attribute = GNUNET_strdup (vrh->issuer_attribute);

  ds_entry->delegation_chain_entry = GNUNET_new (struct DelegationChainEntry);
  ds_entry->delegation_chain_entry->issuer_key = vrh->issuer_key;
  ds_entry->delegation_chain_entry->issuer_attribute =
    GNUNET_strdup (vrh->issuer_attribute);

  ds_entry->handle = vrh;
  ds_entry->lookup_attribute = GNUNET_strdup (vrh->issuer_attribute);
  ds_entry->unresolved_attribute_delegation = NULL;
  vrh->pending_lookups = 1;

  // Start with backward resolution
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Start Backward Resolution\n");

  ds_entry->lookup_request = GNUNET_GNS_lookup (gns,
                                                issuer_attribute_name,
                                                &vrh->issuer_key, // issuer_key,
                                                GNUNET_GNSRECORD_TYPE_ATTRIBUTE,
                                                GNUNET_GNS_LO_DEFAULT,
                                                &backward_resolution,
                                                ds_entry);
  return 0;
}


static int
delegation_chain_fw_resolution_start (void *cls)
{
  GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Start Forward Resolution...\n");

  struct VerifyRequestHandle *vrh = cls;
  struct DelegationSetQueueEntry *ds_entry;
  struct DelegateRecordEntry *del_entry;

  // set to 0 and increase on each lookup: for fw multiple lookups (may be) started
  vrh->pending_lookups = 0;

  if (0 == vrh->del_chain_size)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "No delegations found\n");
    send_lookup_response (vrh);
    return 1;
  }

  // Pre-check with vrh->dele_chain_.. if match issuer_key
  // otherwise FW: start mutliple lookups for each vrh->dele_chain
  // A.a <- ...
  // X.x <- C
  // Y.y <- C
  // if not X.x or Y.y  == A.a start at X and at Y
  for (del_entry = vrh->del_chain_head; del_entry != NULL;
       del_entry = del_entry->next)
  {
    if (0 != memcmp (&del_entry->delegate->issuer_key,
                     &vrh->issuer_key,
                     sizeof (struct GNUNET_CRYPTO_EcdsaPublicKey)))
      continue;
    if (0 !=
        strcmp (del_entry->delegate->issuer_attribute, vrh->issuer_attribute))
      continue;
    del_entry->refcount++;
    // Found match prematurely
    send_lookup_response (vrh);
    return 1;
  }

  // None match, therefore start for every delegation found a lookup chain
  // Return and end collect process on first chain iss <-> sub found

  // ds_entry created belongs to the first lookup, vrh still has the
  // issuer+attr we look for
  for (del_entry = vrh->del_chain_head; del_entry != NULL;
       del_entry = del_entry->next)
  {

    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Looking for %s.%s\n",
                GNUNET_CRYPTO_ecdsa_public_key_to_string (
                  &del_entry->delegate->issuer_key),
                del_entry->delegate->issuer_attribute);

    ds_entry = GNUNET_new (struct DelegationSetQueueEntry);
    GNUNET_CONTAINER_DLL_insert (vrh->dsq_head, vrh->dsq_tail, ds_entry);
    ds_entry->from_bw = false;
    ds_entry->issuer_key = GNUNET_new (struct GNUNET_CRYPTO_EcdsaPublicKey);
    GNUNET_memcpy (ds_entry->issuer_key,
                   &del_entry->delegate->subject_key,
                   sizeof (struct GNUNET_CRYPTO_EcdsaPublicKey));

    ds_entry->delegation_chain_entry = GNUNET_new (struct DelegationChainEntry);
    ds_entry->delegation_chain_entry->subject_key =
      del_entry->delegate->subject_key;
    ds_entry->delegation_chain_entry->subject_attribute = NULL;
    ds_entry->delegation_chain_entry->issuer_key =
      del_entry->delegate->issuer_key;
    ds_entry->delegation_chain_entry->issuer_attribute =
      GNUNET_strdup (del_entry->delegate->issuer_attribute);

    ds_entry->attr_trailer =
      GNUNET_strdup (del_entry->delegate->issuer_attribute);
    ds_entry->handle = vrh;

    vrh->pending_lookups++;
    // Start with forward resolution
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Start Forward Resolution\n");

    ds_entry->lookup_request =
      GNUNET_GNS_lookup (gns,
                         GNUNET_GNS_EMPTY_LABEL_AT,
                         &del_entry->delegate->issuer_key, // issuer_key,
                         GNUNET_GNSRECORD_TYPE_DELEGATE,
                         GNUNET_GNS_LO_DEFAULT,
                         &forward_resolution,
                         ds_entry);
  }
  return 0;
}


static int
check_verify (void *cls, const struct VerifyMessage *v_msg)
{
  size_t msg_size;
  const char *attr;

  msg_size = ntohs (v_msg->header.size);
  if (msg_size < sizeof (struct VerifyMessage))
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  if (ntohs (v_msg->issuer_attribute_len) > GNUNET_ABD_MAX_LENGTH)
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  attr = (const char *) &v_msg[1];

  if (strlen (attr) > GNUNET_ABD_MAX_LENGTH)
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


static void
handle_verify (void *cls, const struct VerifyMessage *v_msg)
{
  struct VerifyRequestHandle *vrh;
  struct GNUNET_SERVICE_Client *client = cls;
  struct DelegateRecordEntry *del_entry;
  uint32_t delegate_count;
  uint32_t delegate_data_size;
  char attr[GNUNET_ABD_MAX_LENGTH + 1];
  char issuer_attribute[GNUNET_ABD_MAX_LENGTH + 1];
  char *attrptr = attr;
  char *delegate_data;
  const char *utf_in;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Received VERIFY message\n");
  utf_in = (const char *) &v_msg[1];
  GNUNET_STRINGS_utf8_tolower (utf_in, attrptr);
  GNUNET_memcpy (issuer_attribute, attr, ntohs (v_msg->issuer_attribute_len));
  issuer_attribute[ntohs (v_msg->issuer_attribute_len)] = '\0';
  vrh = GNUNET_new (struct VerifyRequestHandle);
  vrh->is_collect = false;
  GNUNET_CONTAINER_DLL_insert (vrh_head, vrh_tail, vrh);
  vrh->client = client;
  vrh->request_id = v_msg->id;
  vrh->issuer_key = v_msg->issuer_key;
  vrh->subject_key = v_msg->subject_key;
  vrh->issuer_attribute = GNUNET_strdup (issuer_attribute);
  vrh->resolution_algo = ntohs (v_msg->resolution_algo);

  vrh->del_chain_head = NULL;
  vrh->del_chain_tail = NULL;
  vrh->dsq_head = NULL;
  vrh->dsq_tail = NULL;
  vrh->del_chain_head = NULL;
  vrh->del_chain_tail = NULL;

  GNUNET_SERVICE_client_continue (vrh->client);
  if (0 == strlen (issuer_attribute))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "No issuer attribute provided!\n");
    send_lookup_response (vrh);
    return;
  }

  // Parse delegates from verifaction message
  delegate_count = ntohl (v_msg->d_count);
  delegate_data_size = ntohs (v_msg->header.size)
                       - sizeof (struct VerifyMessage)
                       - ntohs (v_msg->issuer_attribute_len) - 1;
  struct GNUNET_ABD_Delegate delegates[delegate_count];
  memset (delegates,
          0,
          sizeof (struct GNUNET_ABD_Delegate) * delegate_count);
  delegate_data = (char *) &v_msg[1] + ntohs (v_msg->issuer_attribute_len) + 1;
  if (GNUNET_OK != GNUNET_ABD_delegates_deserialize (delegate_data_size,
                                                     delegate_data,
                                                     delegate_count,
                                                     delegates))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Cannot deserialize delegates!\n");
    send_lookup_response (vrh);
    return;
  }

  // Prepare vrh delegation chain for later validation
  for (uint32_t i = 0; i < delegate_count; i++)
  {
    del_entry = GNUNET_new (struct DelegateRecordEntry);
    del_entry->delegate =
      GNUNET_malloc (sizeof (struct GNUNET_ABD_Delegate)
                     + delegates[i].issuer_attribute_len + 1);
    GNUNET_memcpy (del_entry->delegate,
                   &delegates[i],
                   sizeof (struct GNUNET_ABD_Delegate));
    GNUNET_memcpy (&del_entry->delegate[1],
                   delegates[i].issuer_attribute,
                   delegates[i].issuer_attribute_len);
    del_entry->delegate->issuer_attribute_len =
      delegates[i].issuer_attribute_len;
    del_entry->delegate->issuer_attribute = (char *) &del_entry->delegate[1];
    GNUNET_CONTAINER_DLL_insert_tail (vrh->del_chain_head,
                                      vrh->del_chain_tail,
                                      del_entry);
    vrh->del_chain_size++;
  }

  // Switch resolution algo
  if (GNUNET_ABD_FLAG_BACKWARD & vrh->resolution_algo &&
      GNUNET_ABD_FLAG_FORWARD & vrh->resolution_algo)
  {
    if (1 == delegation_chain_fw_resolution_start (vrh))
      return;
    delegation_chain_bw_resolution_start (vrh);
  }
  else if (GNUNET_ABD_FLAG_BACKWARD & vrh->resolution_algo)
  {
    delegation_chain_bw_resolution_start (vrh);
  }
  else if (GNUNET_ABD_FLAG_FORWARD & vrh->resolution_algo)
  {
    delegation_chain_fw_resolution_start (vrh);
  }
}


static void
handle_delegate_collection_error_cb (void *cls)
{
  struct VerifyRequestHandle *vrh = cls;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Got disconnected from namestore database.\n");
  vrh->dele_qe = NULL;
  send_lookup_response (vrh);
}


static void
delegate_collection_finished (void *cls)
{
  struct VerifyRequestHandle *vrh = cls;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Done collecting delegates.\n");

  // if both are set: bidirectional search, meaning start both chain resolutions
  if (GNUNET_ABD_FLAG_BACKWARD & vrh->resolution_algo &&
      GNUNET_ABD_FLAG_FORWARD & vrh->resolution_algo)
  {
    // if premature match found don't start bw resultion
    if (1 == delegation_chain_fw_resolution_start (vrh))
      return;
    delegation_chain_bw_resolution_start (vrh);
  }
  else if (GNUNET_ABD_FLAG_BACKWARD & vrh->resolution_algo)
  {
    delegation_chain_bw_resolution_start (vrh);
  }
  else if (GNUNET_ABD_FLAG_FORWARD & vrh->resolution_algo)
  {
    delegation_chain_fw_resolution_start (vrh);
  }
}


static void
handle_delegate_collection_cb (void *cls,
                               const struct GNUNET_CRYPTO_EcdsaPrivateKey *key,
                               const char *label,
                               unsigned int rd_count,
                               const struct GNUNET_GNSRECORD_Data *rd)
{
  struct VerifyRequestHandle *vrh = cls;
  struct GNUNET_ABD_Delegate *del;
  struct DelegateRecordEntry *del_entry;
  int cred_record_count;
  cred_record_count = 0;
  vrh->dele_qe = NULL;

  for (uint32_t i = 0; i < rd_count; i++)
  {
    if (GNUNET_GNSRECORD_TYPE_DELEGATE != rd[i].record_type)
      continue;
    cred_record_count++;
    del = GNUNET_ABD_delegate_deserialize (rd[i].data, rd[i].data_size);
    if (NULL == del)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING, "Invalid delegate found\n");
      continue;
    }
    // only add the entries that are explicity marked as private
    // and therefor symbolize the end of a chain
    if (rd[i].flags & GNUNET_GNSRECORD_RF_PRIVATE)
    {
      del_entry = GNUNET_new (struct DelegateRecordEntry);
      del_entry->delegate = del;
      GNUNET_CONTAINER_DLL_insert_tail (vrh->del_chain_head,
                                        vrh->del_chain_tail,
                                        del_entry);
      vrh->del_chain_size++;
    }
  }

  delegate_collection_finished (vrh);
}


static void
handle_collect (void *cls, const struct CollectMessage *c_msg)
{
  char attr[GNUNET_ABD_MAX_LENGTH + 1];
  char issuer_attribute[GNUNET_ABD_MAX_LENGTH + 1];
  struct VerifyRequestHandle *vrh;
  struct GNUNET_SERVICE_Client *client = cls;
  char *attrptr = attr;
  const char *utf_in;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Received COLLECT message\n");

  utf_in = (const char *) &c_msg[1];
  GNUNET_STRINGS_utf8_tolower (utf_in, attrptr);

  GNUNET_memcpy (issuer_attribute, attr, ntohs (c_msg->issuer_attribute_len));
  issuer_attribute[ntohs (c_msg->issuer_attribute_len)] = '\0';
  vrh = GNUNET_new (struct VerifyRequestHandle);
  vrh->is_collect = true;
  GNUNET_CONTAINER_DLL_insert (vrh_head, vrh_tail, vrh);
  vrh->client = client;
  vrh->request_id = c_msg->id;
  vrh->issuer_key = c_msg->issuer_key;
  GNUNET_CRYPTO_ecdsa_key_get_public (&c_msg->subject_key, &vrh->subject_key);
  vrh->issuer_attribute = GNUNET_strdup (issuer_attribute);
  vrh->resolution_algo = ntohs (c_msg->resolution_algo);

  vrh->del_chain_head = NULL;
  vrh->del_chain_tail = NULL;
  vrh->dsq_head = NULL;
  vrh->dsq_tail = NULL;
  vrh->del_chain_head = NULL;
  vrh->del_chain_tail = NULL;

  if (0 == strlen (issuer_attribute))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "No issuer attribute provided!\n");
    send_lookup_response (vrh);
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Getting delegates for subject\n");

  // Get all delegates from subject
  vrh->dele_qe =
    GNUNET_NAMESTORE_records_lookup (namestore,
                                     &c_msg->subject_key,
                                     GNUNET_GNS_EMPTY_LABEL_AT,
                                     &handle_delegate_collection_error_cb,
                                     vrh,
                                     &handle_delegate_collection_cb,
                                     vrh);
  GNUNET_SERVICE_client_continue (vrh->client);
}


static int
check_collect (void *cls, const struct CollectMessage *c_msg)
{
  size_t msg_size;
  const char *attr;

  msg_size = ntohs (c_msg->header.size);
  if (msg_size < sizeof (struct CollectMessage))
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  if (ntohs (c_msg->issuer_attribute_len) > GNUNET_ABD_MAX_LENGTH)
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  attr = (const char *) &c_msg[1];

  if (('\0' != attr[msg_size - sizeof (struct CollectMessage) - 1]) ||
      (strlen (attr) > GNUNET_ABD_MAX_LENGTH))
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


static void
client_disconnect_cb (void *cls,
                      struct GNUNET_SERVICE_Client *client,
                      void *app_ctx)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Client %p disconnected\n", client);
}


static void *
client_connect_cb (void *cls,
                   struct GNUNET_SERVICE_Client *client,
                   struct GNUNET_MQ_Handle *mq)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Client %p connected\n", client);
  return client;
}


/**
 * Process Credential requests.
 *
 * @param cls closure
 * @param c configuration to use
 * @param handle service handle
 */
static void
run (void *cls,
     const struct GNUNET_CONFIGURATION_Handle *c,
     struct GNUNET_SERVICE_Handle *handle)
{

  gns = GNUNET_GNS_connect (c);
  if (NULL == gns)
  {
    fprintf (stderr, _ ("Failed to connect to GNS\n"));
  }
  namestore = GNUNET_NAMESTORE_connect (c);
  if (NULL == namestore)
  {
    fprintf (stderr, _ ("Failed to connect to namestore\n"));
  }

  statistics = GNUNET_STATISTICS_create ("abd", c);
  GNUNET_SCHEDULER_add_shutdown (&shutdown_task, NULL);
}


/**
 * Define "main" method using service macro
 */
GNUNET_SERVICE_MAIN (
  "abd",
  GNUNET_SERVICE_OPTION_NONE,
  &run,
  &client_connect_cb,
  &client_disconnect_cb,
  NULL,
  GNUNET_MQ_hd_var_size (verify,
                         GNUNET_MESSAGE_TYPE_ABD_VERIFY,
                         struct VerifyMessage,
                         NULL),
  GNUNET_MQ_hd_var_size (collect,
                         GNUNET_MESSAGE_TYPE_ABD_COLLECT,
                         struct CollectMessage,
                         NULL),
  GNUNET_MQ_handler_end ());

/* end of gnunet-service-abd.c */

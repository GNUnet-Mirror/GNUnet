/*
     This file is part of GNUnet.
     (C) 2011-2013 Christian Grothoff (and other contributing authors)

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
     Free Software Foundation, Inc., 59 Temple Place - Suite 330,
     Boston, MA 02111-1307, USA.
*/

/**
 * @file gns/gnunet-service-gns_shorten.c
 * @brief GNUnet GNS shortening logic
 * @author Martin Schanzenbach
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_dht_service.h"
#include "gnunet_namestore_service.h"
#include "gnunet_resolver_service.h"
#include "gnunet_gns_service.h"
#include "gns.h"
#include "gnunet-service-gns_shorten.h"
#include "gnunet_vpn_service.h"


/**
 * Default DHT timeout for lookups.
 */
#define DHT_LOOKUP_TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 60)

/**
 * DHT replication level
 */
#define DHT_GNS_REPLICATION_LEVEL 5


/**
 * Handle for a PSEU lookup used to shorten names.
 */
struct GetPseuAuthorityHandle
{
  /**
   * DLL
   */
  struct GetPseuAuthorityHandle *next;

  /**
   * DLL
   */
  struct GetPseuAuthorityHandle *prev;

  /**
   * Private key of the (shorten) zone to store the resulting
   * pseudonym in.
   */
  struct GNUNET_CRYPTO_EcdsaPrivateKey shorten_zone_key;

  /**
   * Original label (used if no PSEU record is found).
   */
  char label[GNUNET_DNSPARSER_MAX_LABEL_LENGTH + 1];

  /**
   * Label we are currently trying out (during #perform_pseu_lookup).
   */
  char *current_label;

  /**
   * The zone for which we are trying to find the PSEU record.
   */
  struct GNUNET_CRYPTO_EcdsaPublicKey target_zone;

  /**
   * Handle for DHT lookups. Should be NULL if no lookups are in progress
   */
  struct GNUNET_DHT_GetHandle *get_handle;

  /**
   * Handle to namestore request
   */
  struct GNUNET_NAMESTORE_QueueEntry *namestore_task;

  /**
   * Task to abort DHT lookup operation.
   */
  GNUNET_SCHEDULER_TaskIdentifier timeout_task;

};


/**
 * Head of PSEU/shorten operations list.
 */
static struct GetPseuAuthorityHandle *gph_head;

/**
 * Tail of PSEU/shorten operations list.
 */
static struct GetPseuAuthorityHandle *gph_tail;

/**
 * Our handle to the namestore service
 */
static struct GNUNET_NAMESTORE_Handle *namestore_handle;

/**
 * Resolver handle to the dht
 */
static struct GNUNET_DHT_Handle *dht_handle;

/**
 * Cleanup a 'struct GetPseuAuthorityHandle', terminating all
 * pending activities.
 *
 * @param gph handle to terminate
 */
static void
free_get_pseu_authority_handle (struct GetPseuAuthorityHandle *gph)
{
  if (NULL != gph->get_handle)
  {
    GNUNET_DHT_get_stop (gph->get_handle);
    gph->get_handle = NULL;
  }
  if (NULL != gph->namestore_task)
  {
    GNUNET_NAMESTORE_cancel (gph->namestore_task);
    gph->namestore_task = NULL;
  }
  if (GNUNET_SCHEDULER_NO_TASK != gph->timeout_task)
  {
    GNUNET_SCHEDULER_cancel (gph->timeout_task);
    gph->timeout_task = GNUNET_SCHEDULER_NO_TASK;
  }
  GNUNET_CONTAINER_DLL_remove (gph_head, gph_tail, gph);
  GNUNET_free_non_null (gph->current_label);
  GNUNET_free (gph);
}


/**
 * Continuation for pkey record creation (shorten)
 *
 * @param cls a GetPseuAuthorityHandle
 * @param success unused
 * @param emsg unused
 */
static void
create_pkey_cont (void* cls,
		  int32_t success,
		  const char *emsg)
{
  struct GetPseuAuthorityHandle* gph = cls;

  gph->namestore_task = NULL;
  free_get_pseu_authority_handle (gph);
}


/**
 * Namestore calls this function if we have record for this name.
 * (or with rd_count=0 to indicate no matches).
 *
 * @param cls the pending query
 * @param rd_count the number of records with 'name'
 * @param rd the record data
 */
static void
process_pseu_lookup_ns (void *cls,
			unsigned int rd_count,
			const struct GNUNET_NAMESTORE_RecordData *rd);


/**
 * We obtained a result for our query to the shorten zone from
 * the namestore.  Try to decrypt.
 *
 * @param cls the handle to our shorten operation
 * @param block resulting encrypted block
 */
static void
process_pseu_block_ns (void *cls,
		       const struct GNUNET_NAMESTORE_Block *block)
{
  struct GetPseuAuthorityHandle *gph = cls;
  struct GNUNET_CRYPTO_EcdsaPublicKey pub;

  gph->namestore_task = NULL;
  if (NULL == block)
  {
    process_pseu_lookup_ns (gph, 0, NULL);
    return;
  }
  GNUNET_CRYPTO_ecdsa_key_get_public (&gph->shorten_zone_key,
				    &pub);
  if (GNUNET_OK !=
      GNUNET_NAMESTORE_block_decrypt (block,
				      &pub,
				      gph->current_label,
				      &process_pseu_lookup_ns,
				      gph))
  {
    GNUNET_break (0);
    free_get_pseu_authority_handle (gph);
    return;
  }
}


/**
 * Lookup in the namestore for the shorten zone the given label.
 *
 * @param gph the handle to our shorten operation
 * @param label the label to lookup
 */
static void
perform_pseu_lookup (struct GetPseuAuthorityHandle *gph,
		     const char *label)
{
  struct GNUNET_CRYPTO_EcdsaPublicKey pub;
  struct GNUNET_HashCode query;

  GNUNET_CRYPTO_ecdsa_key_get_public (&gph->shorten_zone_key,
				    &pub);
  GNUNET_free_non_null (gph->current_label);
  gph->current_label = GNUNET_strdup (label);
  GNUNET_NAMESTORE_query_from_public_key (&pub,
					  label,
					  &query);
  gph->namestore_task = GNUNET_NAMESTORE_lookup_block (namestore_handle,
						       &query,
						       &process_pseu_block_ns,
						       gph);
}


/**
 * Namestore calls this function if we have record for this name.
 * (or with rd_count=0 to indicate no matches).
 *
 * @param cls the pending query
 * @param rd_count the number of records with 'name'
 * @param rd the record data
 */
static void
process_pseu_lookup_ns (void *cls,
			unsigned int rd_count,
			const struct GNUNET_NAMESTORE_RecordData *rd)
{
  struct GetPseuAuthorityHandle *gph = cls;
  struct GNUNET_NAMESTORE_RecordData new_pkey;

  gph->namestore_task = NULL;
  if (rd_count > 0)
  {
    GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
               "Name `%s' already taken, cannot shorten.\n",
	       gph->current_label);
    /* if this was not yet the original label, try one more
       time, this time not using PSEU but the original label */
    if (0 == strcmp (gph->current_label,
		     gph->label))
    {
      free_get_pseu_authority_handle (gph);
    }
    else
    {
      perform_pseu_lookup (gph, gph->label);
    }
    return;
  }
  /* name is available */
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Shortening `%s' to `%s'\n",
	      GNUNET_NAMESTORE_z2s (&gph->target_zone),
	      gph->current_label);
  new_pkey.expiration_time = UINT64_MAX;
  new_pkey.data_size = sizeof (struct GNUNET_CRYPTO_EcdsaPublicKey);
  new_pkey.data = &gph->target_zone;
  new_pkey.record_type = GNUNET_NAMESTORE_TYPE_PKEY;
  new_pkey.flags = GNUNET_NAMESTORE_RF_NONE
                 | GNUNET_NAMESTORE_RF_PRIVATE
                 | GNUNET_NAMESTORE_RF_PENDING;
  gph->namestore_task
    = GNUNET_NAMESTORE_records_store (namestore_handle,
				      &gph->shorten_zone_key,
				      gph->current_label,
				      1, &new_pkey,
				      &create_pkey_cont, gph);
}


/**
 * Process result of a DHT lookup for a PSEU record.
 *
 * @param gph the handle to our shorten operation
 * @param pseu the pseu result or NULL
 */
static void
process_pseu_result (struct GetPseuAuthorityHandle* gph,
		     const char *pseu)
{
  if (NULL == pseu)
  {
    /* no PSEU found, try original label */
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "No PSEU found, trying original label `%s' instead.\n",
		gph->label);
    perform_pseu_lookup (gph, gph->label);
    return;
  }
  /* check if 'pseu' is taken */
  perform_pseu_lookup (gph, pseu);
}


/**
 * Handle timeout for DHT request during shortening.
 *
 * @param cls the request handle as closure
 * @param tc the task context
 */
static void
handle_auth_discovery_timeout (void *cls,
                               const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GetPseuAuthorityHandle *gph = cls;

  gph->timeout_task = GNUNET_SCHEDULER_NO_TASK;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "DHT lookup for PSEU query timed out.\n");
  GNUNET_DHT_get_stop (gph->get_handle);
  gph->get_handle = NULL;
  process_pseu_result (gph, NULL);
}


/**
 * Handle decrypted records from DHT result.
 *
 * @param cls closure with our 'struct GetPseuAuthorityHandle'
 * @param rd_count number of entries in 'rd' array
 * @param rd array of records with data to store
 */
static void
process_auth_records (void *cls,
		      unsigned int rd_count,
		      const struct GNUNET_NAMESTORE_RecordData *rd)
{
  struct GetPseuAuthorityHandle *gph = cls;
  unsigned int i;

  for (i=0; i < rd_count; i++)
  {
    if (GNUNET_NAMESTORE_TYPE_PSEU == rd[i].record_type)
    {
      char pseu[rd[i].data_size + 1];

      /* found pseu */
      memcpy (pseu,
	      rd[i].data,
	      rd[i].data_size);
      pseu[rd[i].data_size] = '\0';
      process_pseu_result (gph,
			   pseu);
      return;
    }
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "No PSEU record found in DHT reply.\n");
  process_pseu_result (gph, NULL);
}


/**
 * Function called when we find a PSEU entry in the DHT
 *
 * @param cls the request handle
 * @param exp lifetime
 * @param key the key the record was stored under
 * @param get_path get path
 * @param get_path_length get path length
 * @param put_path put path
 * @param put_path_length put path length
 * @param type the block type
 * @param size the size of the record
 * @param data the record data
 */
static void
process_auth_discovery_dht_result (void* cls,
                                   struct GNUNET_TIME_Absolute exp,
                                   const struct GNUNET_HashCode *key,
                                   const struct GNUNET_PeerIdentity *get_path,
                                   unsigned int get_path_length,
                                   const struct GNUNET_PeerIdentity *put_path,
                                   unsigned int put_path_length,
                                   enum GNUNET_BLOCK_Type type,
                                   size_t size,
                                   const void *data)
{
  struct GetPseuAuthorityHandle *gph = cls;
  const struct GNUNET_NAMESTORE_Block *block;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Got DHT result for PSEU request\n");
  GNUNET_DHT_get_stop (gph->get_handle);
  gph->get_handle = NULL;
  GNUNET_SCHEDULER_cancel (gph->timeout_task);
  gph->timeout_task = GNUNET_SCHEDULER_NO_TASK;

  if (NULL == data)
  {
    /* is this allowed!? */
    GNUNET_break (0);
    process_pseu_result (gph, NULL);
    return;
  }
  if (size < sizeof (struct GNUNET_NAMESTORE_Block))
  {
    /* how did this pass DHT block validation!? */
    GNUNET_break (0);
    process_pseu_result (gph, NULL);
    return;
  }
  block = data;
  if (size !=
      ntohl (block->purpose.size) +
      sizeof (struct GNUNET_CRYPTO_EcdsaPublicKey) +
      sizeof (struct GNUNET_CRYPTO_EcdsaSignature))
  {
    /* how did this pass DHT block validation!? */
    GNUNET_break (0);
    process_pseu_result (gph, NULL);
    return;
  }
  if (GNUNET_OK !=
      GNUNET_NAMESTORE_block_decrypt (block,
				      &gph->target_zone,
				      GNUNET_GNS_TLD_PLUS,
				      &process_auth_records,
				      gph))
  {
    /* other peer encrypted invalid block, complain */
    GNUNET_break_op (0);
    process_pseu_result (gph, NULL);
    return;
  }
}


/**
 * Callback called by namestore for a zone to name result.  We're
 * trying to see if a short name for a given zone already exists.
 *
 * @param cls the closure
 * @param zone_key the zone we queried
 * @param name the name found or NULL
 * @param rd_len number of records for the name
 * @param rd the record data (PKEY) for the name
 */
static void
process_zone_to_name_discover (void *cls,
			       const struct GNUNET_CRYPTO_EcdsaPrivateKey *zone_key,
			       const char *name,
			       unsigned int rd_len,
			       const struct GNUNET_NAMESTORE_RecordData *rd)
{
  struct GetPseuAuthorityHandle* gph = cls;
  struct GNUNET_HashCode lookup_key;

  gph->namestore_task = NULL;
  if (0 != rd_len)
  {
    /* we found a match in our own zone */
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		"Shortening aborted, name `%s' already reserved for the zone\n",
		name);
    free_get_pseu_authority_handle (gph);
    return;
  }
  /* record does not yet exist, go into DHT to find PSEU record */
  GNUNET_NAMESTORE_query_from_public_key (&gph->target_zone,
					  GNUNET_GNS_TLD_PLUS, 					
					  &lookup_key);
  gph->timeout_task = GNUNET_SCHEDULER_add_delayed (DHT_LOOKUP_TIMEOUT,
						    &handle_auth_discovery_timeout,
						    gph);
  gph->get_handle = GNUNET_DHT_get_start (dht_handle,
					  GNUNET_BLOCK_TYPE_GNS_NAMERECORD,
					  &lookup_key,
					  DHT_GNS_REPLICATION_LEVEL,
					  GNUNET_DHT_RO_DEMULTIPLEX_EVERYWHERE,
					  NULL, 0,
					  &process_auth_discovery_dht_result,
					  gph);
}


/**
 * Start shortening algorithm, try to allocate a nice short
 * canonical name for @a pub in @a shorten_zone, using
 * @a original_label as one possible suggestion.
 *
 * @param original_label original label for the zone
 * @param pub public key of the zone to shorten
 * @param shorten_zone private key of the target zone for the new record
 */
void
GNS_shorten_start (const char *original_label,
		   const struct GNUNET_CRYPTO_EcdsaPublicKey *pub,
		   const struct GNUNET_CRYPTO_EcdsaPrivateKey *shorten_zone)
{
  struct GetPseuAuthorityHandle *gph;

  // if (1) return;
  if (strlen (original_label) > GNUNET_DNSPARSER_MAX_LABEL_LENGTH)
  {
    GNUNET_break (0);
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Starting shortening process for `%s' with old label `%s'\n",
	      GNUNET_NAMESTORE_z2s (pub),
	      original_label);
  gph = GNUNET_new (struct GetPseuAuthorityHandle);
  gph->shorten_zone_key = *shorten_zone;
  gph->target_zone = *pub;
  strcpy (gph->label, original_label);
  GNUNET_CONTAINER_DLL_insert (gph_head, gph_tail, gph);
  /* first, check if we *already* have a record for this zone */
  gph->namestore_task = GNUNET_NAMESTORE_zone_to_name (namestore_handle,
                                                       shorten_zone,
                                                       pub,
                                                       &process_zone_to_name_discover,
                                                       gph);
}


/**
 * Initialize the shortening subsystem
 *
 * @param nh the namestore handle
 * @param dht the dht handle
 */
void
GNS_shorten_init (struct GNUNET_NAMESTORE_Handle *nh,
		  struct GNUNET_DHT_Handle *dht)
{
  namestore_handle = nh;
  dht_handle = dht;
}


/**
 * Shutdown shortening.
 */
void
GNS_shorten_done ()
{
  /* abort active shorten operations */
  while (NULL != gph_head)
    free_get_pseu_authority_handle (gph_head);
  dht_handle = NULL;
  namestore_handle = NULL;
}

/* end of gnunet-service-gns_shorten.c */

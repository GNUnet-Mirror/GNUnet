/*
     This file is part of GNUnet.
     Copyright (C) 2011-2013 Christian Grothoff (and other contributing authors)

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
 * @file gns/gnunet-service-gns_shorten.c
 * @brief GNUnet GNS shortening logic
 * @author Martin Schanzenbach
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_dht_service.h"
#include "gnunet_gnsrecord_lib.h"
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
   * Suggested label based on NICK record
   */
  char * suggested_label;

  /**
   * Label we are currently trying out
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
   * Handle to namecache request
   */
  struct GNUNET_NAMECACHE_QueueEntry *namecache_task;

  /**
   * Task to abort DHT lookup operation.
   */
  struct GNUNET_SCHEDULER_Task * timeout_task;

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
 * Our handle to the namecache service
 */
static struct GNUNET_NAMECACHE_Handle *namecache_handle;

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
  if (NULL != gph->namecache_task)
  {
    GNUNET_NAMECACHE_cancel (gph->namecache_task);
    gph->namecache_task = NULL;
  }
  if (NULL != gph->timeout_task)
  {
    GNUNET_SCHEDULER_cancel (gph->timeout_task);
    gph->timeout_task = NULL;
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
			const struct GNUNET_GNSRECORD_Data *rd);


/**
 * We obtained a result for our query to the shorten zone from
 * the namestore.  Try to decrypt.
 *
 * @param cls the handle to our shorten operation
 * @param block resulting encrypted block
 */
static void
process_pseu_block_ns (void *cls,
		       const struct GNUNET_GNSRECORD_Block *block)
{
  struct GetPseuAuthorityHandle *gph = cls;
  struct GNUNET_CRYPTO_EcdsaPublicKey pub;

  gph->namecache_task = NULL;
  if (NULL == block)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Namecache did not return information for label `%s' \n",
                gph->current_label);
    process_pseu_lookup_ns (gph, 0, NULL);
    return;
  }
  GNUNET_CRYPTO_ecdsa_key_get_public (&gph->shorten_zone_key,
				    &pub);
  if (GNUNET_OK !=
      GNUNET_GNSRECORD_block_decrypt (block,
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
 * Lookup in the namecache for the shorten zone the given label.
 *
 * @param gph the handle to our shorten operation
 * @param label the label to lookup
 */
static void
perform_nick_lookup (struct GetPseuAuthorityHandle *gph,
		     const char *label)
{
  struct GNUNET_CRYPTO_EcdsaPublicKey pub;
  struct GNUNET_HashCode query;

  GNUNET_CRYPTO_ecdsa_key_get_public (&gph->shorten_zone_key,
				    &pub);
  GNUNET_free_non_null (gph->current_label);
  gph->current_label = GNUNET_strdup (label);
  GNUNET_GNSRECORD_query_from_public_key (&pub,
					  label,
					  &query);
  gph->namecache_task = GNUNET_NAMECACHE_lookup_block (namecache_handle,
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
			const struct GNUNET_GNSRECORD_Data *rd)
{
  struct GetPseuAuthorityHandle *gph = cls;
  struct GNUNET_GNSRECORD_Data new_pkey;

  gph->namestore_task = NULL;
  if (rd_count > 0)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
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
      perform_nick_lookup (gph, gph->label);
    }
    return;
  }
  /* name is available */
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Shortening `%s' to `%s'\n",
	      GNUNET_GNSRECORD_z2s (&gph->target_zone),
	      gph->current_label);
  new_pkey.expiration_time = UINT64_MAX;
  new_pkey.data_size = sizeof (struct GNUNET_CRYPTO_EcdsaPublicKey);
  new_pkey.data = &gph->target_zone;
  new_pkey.record_type = GNUNET_GNSRECORD_TYPE_PKEY;
  new_pkey.flags = GNUNET_GNSRECORD_RF_NONE
                 | GNUNET_GNSRECORD_RF_PRIVATE;
  gph->namestore_task
    = GNUNET_NAMESTORE_records_store (namestore_handle,
				      &gph->shorten_zone_key,
				      gph->current_label,
				      1, &new_pkey,
				      &create_pkey_cont, gph);
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
			       const struct GNUNET_GNSRECORD_Data *rd)
{
  struct GetPseuAuthorityHandle* gph = cls;
#if 0
  struct GNUNET_HashCode lookup_key;
#endif

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
  else
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Shortening continuing, no name not reserved in shorten zone\n");
  }
  /* record does not yet exist, check if suggested label is available */
  perform_nick_lookup (gph, gph->suggested_label);
}


/**
 * Start shortening algorithm, try to allocate a nice short
 * canonical name for @a pub in @a shorten_zone, using
 * @a original_label as one possible suggestion.
 *
 * @param original_label original label for the zone
 * @param suggested_label suggested label for the zone
 * @param pub public key of the zone to shorten
 * @param shorten_zone private key of the target zone for the new record
 */
void
GNS_shorten_start (const char *original_label,
                   const char *suggested_label,
		   const struct GNUNET_CRYPTO_EcdsaPublicKey *pub,
		   const struct GNUNET_CRYPTO_EcdsaPrivateKey *shorten_zone)
{
  struct GetPseuAuthorityHandle *gph;
  struct GNUNET_CRYPTO_EcdsaPublicKey shorten_pub;

  if (strlen (original_label) > GNUNET_DNSPARSER_MAX_LABEL_LENGTH)
  {
    GNUNET_break (0);
    return;
  }
  GNUNET_CRYPTO_ecdsa_key_get_public (shorten_zone, &shorten_pub);
  if (0 == memcmp (&shorten_pub, pub, sizeof (struct GNUNET_CRYPTO_EcdsaPublicKey)))
  {
    /* Do not shorten the shorten zone */
    return;
  }

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Starting shortening process for `%s' with old label `%s' and suggested nickname `%s'\n",
	      GNUNET_GNSRECORD_z2s (pub),
	      original_label, suggested_label);
  gph = GNUNET_new (struct GetPseuAuthorityHandle);
  gph->shorten_zone_key = *shorten_zone;
  gph->target_zone = *pub;
  gph->suggested_label = GNUNET_strdup (suggested_label);
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
 * @param nc the namecache handle
 * @param dht the dht handle
 */
void
GNS_shorten_init (struct GNUNET_NAMESTORE_Handle *nh,
                  struct GNUNET_NAMECACHE_Handle *nc,
		  struct GNUNET_DHT_Handle *dht)
{
  namestore_handle = nh;
  namecache_handle = nc;
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
  namecache_handle = NULL;
}

/* end of gnunet-service-gns_shorten.c */

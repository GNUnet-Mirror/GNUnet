/*
     This file is part of GNUnet.
     (C) 2012 Christian Grothoff (and other contributing authors)

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
 * @file namestore/gnunet-service-namestore.c
 * @brief namestore for the GNUnet naming system
 * @author Matthias Wachs
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_dnsparser_lib.h"
#include "gnunet_namestore_service.h"
#include "gnunet_namestore_plugin.h"
#include "gnunet_signatures.h"
#include "namestore.h"

#define LOG_STRERROR_FILE(kind,syscall,filename) GNUNET_log_from_strerror_file (kind, "util", syscall, filename)

/**
 * A namestore operation.
 */
struct GNUNET_NAMESTORE_ZoneIteration
{
  /**
   * Next element in the DLL
   */
  struct GNUNET_NAMESTORE_ZoneIteration *next;

  /**
   * Previous element in the DLL
   */
  struct GNUNET_NAMESTORE_ZoneIteration *prev;

  /**
   * Namestore client which intiated this zone iteration
   */
  struct GNUNET_NAMESTORE_Client *client;

  /**
   * GNUNET_YES if we iterate over a specific zone
   * GNUNET_NO if we iterate over all zones
   */
  int has_zone;

  /**
   * Hash of the specific zone if 'has_zone' is GNUNET_YES,
   * othwerwise set to '\0'
   */
  struct GNUNET_CRYPTO_ShortHashCode zone;

  /**
   * The operation id fot the zone iteration in the response for the client
   */
  uint64_t request_id;

  /**
   * Offset of the zone iteration used to address next result of the zone
   * iteration in the store
   *
   * Initialy set to 0 in handle_iteration_start
   * Incremented with by every call to handle_iteration_next
   */
  uint32_t offset;

  /**
   * Which flags must be included
   */
  uint16_t must_have_flags;

  /**
   * Which flags must not be included
   */
  uint16_t must_not_have_flags;
};


/**
 * A namestore client
 */
struct GNUNET_NAMESTORE_Client
{
  /**
   * Next element in the DLL
   */
  struct GNUNET_NAMESTORE_Client *next;

  /**
   * Previous element in the DLL
   */
  struct GNUNET_NAMESTORE_Client *prev;

  /**
   * The client
   */
  struct GNUNET_SERVER_Client *client;

  /**
   * Head of the DLL of
   * Zone iteration operations in progress initiated by this client
   */
  struct GNUNET_NAMESTORE_ZoneIteration *op_head;

  /**
   * Tail of the DLL of
   * Zone iteration operations in progress initiated by this client
   */
  struct GNUNET_NAMESTORE_ZoneIteration *op_tail;
};


/**
 * A container struct to store information belonging to a zone crypto key pair
 */
struct GNUNET_NAMESTORE_CryptoContainer
{
  /**
   * Filename where to store the container
   */
  char *filename;

  /**
   * Short hash of the zone's public key
   */
  struct GNUNET_CRYPTO_ShortHashCode zone;

  /**
   * Zone's private key
   */
  struct GNUNET_CRYPTO_RsaPrivateKey *privkey;

};


/**
 * Configuration handle.
 */
static const struct GNUNET_CONFIGURATION_Handle *GSN_cfg;

/**
 * Database handle
 */
static struct GNUNET_NAMESTORE_PluginFunctions *GSN_database;

/**
 * Zonefile directory
 */
static char *zonefile_directory;

/**
 * Name of the database plugin
 */
static char *db_lib_name;

/**
 * Our notification context.
 */
static struct GNUNET_SERVER_NotificationContext *snc;

/**
 * Head of the Client DLL
 */
static struct GNUNET_NAMESTORE_Client *client_head;

/**
 * Tail of the Client DLL
 */
static struct GNUNET_NAMESTORE_Client *client_tail;

/**
 * Hashmap containing the zone keys this namestore has is authoritative for
 *
 * Keys are the GNUNET_CRYPTO_HashCode of the GNUNET_CRYPTO_ShortHashCode
 * The values are 'struct GNUNET_NAMESTORE_CryptoContainer *'
 */
static struct GNUNET_CONTAINER_MultiHashMap *zonekeys;

/**
 * DLL head for key loading contexts
 */
static struct KeyLoadContext *kl_head;

/**
 * DLL tail for key loading contexts
 */
static struct KeyLoadContext *kl_tail;

struct KeyLoadContext
{
  struct KeyLoadContext *next;
  struct KeyLoadContext *prev;
  struct GNUNET_CRYPTO_RsaKeyGenerationContext *keygen;
  char *filename;
  unsigned int *counter;
};


/**
 * Writes the encrypted private key of a zone in a file
 *
 * @param filename where to store the zone
 * @param c the crypto container containing private key of the zone
 * @return GNUNET_OK on success, GNUNET_SYSERR on failure
 */
static int
write_key_to_file (const char *filename, 
		   struct GNUNET_NAMESTORE_CryptoContainer *c)
{
  struct GNUNET_CRYPTO_RsaPrivateKey *ret = c->privkey;
  struct GNUNET_CRYPTO_RsaPrivateKeyBinaryEncoded *enc;
  struct GNUNET_DISK_FileHandle *fd;
  struct GNUNET_CRYPTO_ShortHashCode zone;
  struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded pubkey;
  struct GNUNET_CRYPTO_RsaPrivateKey *privkey;

  fd = GNUNET_DISK_file_open (filename, 
			      GNUNET_DISK_OPEN_WRITE | GNUNET_DISK_OPEN_CREATE | GNUNET_DISK_OPEN_FAILIFEXISTS, 
			      GNUNET_DISK_PERM_USER_READ | GNUNET_DISK_PERM_USER_WRITE);
  if ( (NULL == fd) && (EEXIST == errno) )
  {
    privkey = GNUNET_CRYPTO_rsa_key_create_from_file (filename);
    if (NULL == privkey)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		  _("Failed to write zone key to file `%s': %s\n"),
		  filename,
		  _("file exists but reading key failed"));
      return GNUNET_SYSERR;
    }
    GNUNET_CRYPTO_rsa_key_get_public (privkey, &pubkey);
    GNUNET_CRYPTO_short_hash (&pubkey, sizeof (struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded), &zone);
    GNUNET_CRYPTO_rsa_key_free (privkey);
    if (0 == memcmp (&zone, &c->zone, sizeof(zone)))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "File zone `%s' containing this key already exists\n", 
		  GNUNET_short_h2s (&zone));
      return GNUNET_OK;
    }
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		_("Failed to write zone key to file `%s': %s\n"),
		filename,
		_("file exists with different key"));
    return GNUNET_OK;    
  }
  if (NULL == fd)
  {
    LOG_STRERROR_FILE (GNUNET_ERROR_TYPE_ERROR, "open", filename);
    return GNUNET_SYSERR;
  }
  if (GNUNET_YES != GNUNET_DISK_file_lock (fd, 0, sizeof (struct GNUNET_CRYPTO_RsaPrivateKeyBinaryEncoded), GNUNET_YES))
  {
    GNUNET_break (GNUNET_YES == GNUNET_DISK_file_close (fd));
    return GNUNET_SYSERR;
  }
  enc = GNUNET_CRYPTO_rsa_encode_key (ret);
  GNUNET_assert (NULL != enc);
  GNUNET_assert (ntohs (enc->len) == GNUNET_DISK_file_write (fd, enc, ntohs (enc->len)));
  GNUNET_free (enc);
  GNUNET_DISK_file_sync (fd);
  if (GNUNET_YES != GNUNET_DISK_file_unlock (fd, 0, sizeof (struct GNUNET_CRYPTO_RsaPrivateKeyBinaryEncoded)))
    LOG_STRERROR_FILE (GNUNET_ERROR_TYPE_WARNING, "fcntl", filename);
  GNUNET_assert (GNUNET_YES == GNUNET_DISK_file_close (fd));
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Stored zonekey for zone `%s' in file `%s'\n",
	      GNUNET_short_h2s(&c->zone), c->filename);
  return GNUNET_OK;
}


/**
 * Write allthe given zone key to disk and then removes the entry from the
 * 'zonekeys' hash map.
 *
 * @param cls unused
 * @param key zone key
 * @param value 'struct GNUNET_NAMESTORE_CryptoContainer' containing the private
 *        key
 * @return GNUNET_OK to continue iteration
 */
static int
zone_to_disk_it (void *cls,
                 const struct GNUNET_HashCode *key,
                 void *value)
{
  struct GNUNET_NAMESTORE_CryptoContainer *c = value;

  if (NULL == c->filename)
    GNUNET_asprintf(&c->filename, 
		    "%s/%s.zkey", 
		    zonefile_directory, 
		    GNUNET_short_h2s (&c->zone));
  (void) write_key_to_file(c->filename, c);
  GNUNET_assert (GNUNET_OK == GNUNET_CONTAINER_multihashmap_remove (zonekeys, key, value));
  GNUNET_CRYPTO_rsa_key_free (c->privkey);
  GNUNET_free (c->filename);
  GNUNET_free (c);
  return GNUNET_OK;
}


/**
 * Add the given private key to the set of private keys
 * this namestore can use to sign records when needed.
 *
 * @param pkey private key to add to our list (reference will
 *        be taken over or freed and should not be used afterwards)
 */
static void
learn_private_key (struct GNUNET_CRYPTO_RsaPrivateKey *pkey)
{
  struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded pub;
  struct GNUNET_HashCode long_hash;
  struct GNUNET_CRYPTO_ShortHashCode pubkey_hash;
  struct GNUNET_NAMESTORE_CryptoContainer *cc;

  GNUNET_CRYPTO_rsa_key_get_public (pkey, &pub);
  GNUNET_CRYPTO_short_hash (&pub,
			    sizeof (struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded),
			    &pubkey_hash);
  GNUNET_CRYPTO_short_hash_double (&pubkey_hash, &long_hash);

  if (GNUNET_NO != GNUNET_CONTAINER_multihashmap_contains(zonekeys, &long_hash))
  {
    GNUNET_CRYPTO_rsa_key_free (pkey);
    return;
  }  
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, 
	      "Received new private key for zone `%s'\n",
	      GNUNET_short_h2s(&pubkey_hash));
  cc = GNUNET_malloc (sizeof (struct GNUNET_NAMESTORE_CryptoContainer));
  cc->privkey = pkey;
  cc->zone = pubkey_hash;
  GNUNET_assert (GNUNET_YES ==
		 GNUNET_CONTAINER_multihashmap_put(zonekeys, &long_hash, cc, 
						   GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY));  
}


/**
 * Returns the expiration time of the given block of records. The block
 * expiration time is the expiration time of the block with smallest
 * expiration time.
 *
 * @param rd_count number of records given in 'rd'
 * @param rd array of records
 * @return absolute expiration time
 */
static struct GNUNET_TIME_Absolute
get_block_expiration_time (unsigned int rd_count, const struct GNUNET_NAMESTORE_RecordData *rd)
{
  unsigned int c;
  struct GNUNET_TIME_Absolute expire;
  struct GNUNET_TIME_Absolute at;
  struct GNUNET_TIME_Relative rt;

  if (NULL == rd)
    return GNUNET_TIME_UNIT_ZERO_ABS;
  expire = GNUNET_TIME_UNIT_FOREVER_ABS;
  for (c = 0; c < rd_count; c++)  
  {
    if (0 != (rd[c].flags & GNUNET_NAMESTORE_RF_RELATIVE_EXPIRATION))
    {
      rt.rel_value = rd[c].expiration_time;
      at = GNUNET_TIME_relative_to_absolute (rt);
    }
    else
    {
      at.abs_value = rd[c].expiration_time;
    }
    expire = GNUNET_TIME_absolute_min (at, expire);  
  }
  return expire;
}


/**
 * Task run during shutdown.
 *
 * @param cls unused
 * @param tc unused
 */
static void
cleanup_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_NAMESTORE_ZoneIteration *no;
  struct GNUNET_NAMESTORE_Client *nc;
  struct KeyLoadContext *kl;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Stopping namestore service\n");
  if (NULL != snc)
  {
    GNUNET_SERVER_notification_context_destroy (snc);
    snc = NULL;
  }

  while (NULL != (kl = kl_head))
  {
    GNUNET_CONTAINER_DLL_remove (kl_head, kl_tail, kl);
    if (NULL != kl->keygen)
      GNUNET_CRYPTO_rsa_key_create_stop (kl->keygen);
    GNUNET_free (kl->filename);
    GNUNET_free (kl);
  }

  GNUNET_CONTAINER_multihashmap_iterate (zonekeys, &zone_to_disk_it, NULL);
  GNUNET_CONTAINER_multihashmap_destroy (zonekeys);
  zonekeys = NULL;
  while (NULL != (nc = client_head))
  {
    while (NULL != (no = nc->op_head))
    {
      GNUNET_CONTAINER_DLL_remove (nc->op_head, nc->op_tail, no);
      GNUNET_free (no);
    }
    GNUNET_SERVER_client_drop(nc->client);
    GNUNET_CONTAINER_DLL_remove (client_head, client_tail, nc);
    GNUNET_free (nc);
  }
  GNUNET_break (NULL == GNUNET_PLUGIN_unload (db_lib_name, GSN_database));
  GNUNET_free (db_lib_name);
  db_lib_name = NULL;
  GNUNET_free_non_null (zonefile_directory);
  zonefile_directory = NULL;
}


/**
 * Lookup our internal data structure for a given client.
 *
 * @param client server client handle to use for the lookup
 * @return our internal structure for the client, NULL if
 *         we do not have any yet
 */
static struct GNUNET_NAMESTORE_Client *
client_lookup (struct GNUNET_SERVER_Client *client)
{
  struct GNUNET_NAMESTORE_Client *nc;

  GNUNET_assert (NULL != client);
  for (nc = client_head; NULL != nc; nc = nc->next)  
    if (client == nc->client)
      return nc;  
  return NULL;
}


/**
 * Called whenever a client is disconnected.
 * Frees our resources associated with that client.
 *
 * @param cls closure
 * @param client identification of the client
 */
static void
client_disconnect_notification (void *cls, 
				struct GNUNET_SERVER_Client *client)
{
  struct GNUNET_NAMESTORE_ZoneIteration *no;
  struct GNUNET_NAMESTORE_Client *nc;

  if (NULL == client)
    return;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, 
	      "Client %p disconnected\n", 
	      client);
  if (NULL == (nc = client_lookup (client)))
    return;
  while (NULL != (no = nc->op_head))
  {
    GNUNET_CONTAINER_DLL_remove (nc->op_head, nc->op_tail, no);
    GNUNET_free (no);
  }
  GNUNET_SERVER_client_drop (nc->client);
  GNUNET_CONTAINER_DLL_remove (client_head, client_tail, nc);
  GNUNET_free (nc);
}


/**
 * Handles a 'GNUNET_MESSAGE_TYPE_NAMESTORE_START' message
 *
 * @param cls unused
 * @param client GNUNET_SERVER_Client sending the message
 * @param message unused
 */
static void
handle_start (void *cls,
              struct GNUNET_SERVER_Client *client,
              const struct GNUNET_MessageHeader *message)
{
  struct GNUNET_NAMESTORE_Client *nc;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, 
	      "Client %p connected\n", client);
  if (NULL != client_lookup (client))
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  nc = GNUNET_malloc (sizeof (struct GNUNET_NAMESTORE_Client));
  nc->client = client;
  GNUNET_SERVER_notification_context_add (snc, client);
  GNUNET_CONTAINER_DLL_insert (client_head, client_tail, nc);
  GNUNET_SERVER_client_keep (client);
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}


/**
 * Context for name lookups passed from 'handle_lookup_name' to
 * 'handle_lookup_name_it' as closure
 */
struct LookupNameContext
{
  /**
   * The client to send the response to
   */
  struct GNUNET_NAMESTORE_Client *nc;

  /**
   * Requested zone
   */
  const struct GNUNET_CRYPTO_ShortHashCode *zone;

  /**
   * Requested name
   */
  const char *name;

  /**
   * Operation id for the name lookup
   */
  uint32_t request_id;

  /**
   * Requested specific record type
   */
  uint32_t record_type;
};


/**
 * A 'GNUNET_NAMESTORE_RecordIterator' for name lookups in handle_lookup_name
 *
 * @param cls a 'struct LookupNameContext *' with information about the request
 * @param zone_key zone key of the zone
 * @param expire expiration time
 * @param name name
 * @param rd_count number of records
 * @param rd array of records
 * @param signature signature
 */
static void
handle_lookup_name_it (void *cls,
		       const struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded *zone_key,
		       struct GNUNET_TIME_Absolute expire,
		       const char *name,
		       unsigned int rd_count,
		       const struct GNUNET_NAMESTORE_RecordData *rd,
		       const struct GNUNET_CRYPTO_RsaSignature *signature)
{
  struct LookupNameContext *lnc = cls;
  struct LookupNameResponseMessage *lnr_msg;
  struct GNUNET_NAMESTORE_RecordData *rd_selected;
  struct GNUNET_NAMESTORE_CryptoContainer *cc;
  struct GNUNET_CRYPTO_RsaSignature *signature_new;
  struct GNUNET_TIME_Absolute e;
  struct GNUNET_TIME_Relative re;
  struct GNUNET_CRYPTO_ShortHashCode zone_key_hash;
  struct GNUNET_HashCode long_hash;
  char *rd_tmp;
  char *name_tmp;
  size_t rd_ser_len;
  size_t r_size;
  size_t name_len;
  int copied_elements;
  int contains_signature;
  int authoritative;
  int rd_modified;
  unsigned int c;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Found %u records under name `%s'\n",
	      rd_count,
	      name);
  authoritative = GNUNET_NO;
  signature_new = NULL;
  cc = NULL;
  if (NULL != zone_key) 
  {
    GNUNET_CRYPTO_short_hash (zone_key, 
			      sizeof (struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded), 
			      &zone_key_hash);
    GNUNET_CRYPTO_short_hash_double (&zone_key_hash, &long_hash);
    if (NULL != (cc = GNUNET_CONTAINER_multihashmap_get (zonekeys, &long_hash)))   
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "Am authoritative for zone `%s'\n",
		  GNUNET_short_h2s (&zone_key_hash));
      authoritative = GNUNET_YES;    
    }
  }

  copied_elements = 0;
  rd_modified = GNUNET_NO;
  rd_selected = NULL;
  /* count records to copy */
  for (c = 0; c < rd_count; c++)
  {
    if ( (GNUNET_YES == authoritative) &&
	 (GNUNET_YES ==
	  GNUNET_NAMESTORE_is_expired (&rd[c]) ) )
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "Skipping expired record\n");
      continue; 
    }
    if ( (GNUNET_NAMESTORE_TYPE_ANY == lnc->record_type) || 
	 (rd[c].record_type == lnc->record_type) )
      copied_elements++; /* found matching record */
    else
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, 
		  "Skipping non-mtaching record\n");
      rd_modified = GNUNET_YES;
    }
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, 
	      "Found %u records with type %u for name `%s' in zone `%s'\n",
	      copied_elements, 
	      lnc->record_type, 
	      lnc->name, 
	      GNUNET_short_h2s(lnc->zone));
  if (copied_elements > 0)
  {
    rd_selected = GNUNET_malloc (copied_elements * sizeof (struct GNUNET_NAMESTORE_RecordData));
    copied_elements = 0;
    for (c = 0; c < rd_count; c++)
    {
      if ( (GNUNET_YES == authoritative) &&
	   (GNUNET_YES ==
	    GNUNET_NAMESTORE_is_expired (&rd[c])) )
	continue;
      if ( (GNUNET_NAMESTORE_TYPE_ANY == lnc->record_type) || 
	   (rd[c].record_type == lnc->record_type) )
      {
	if (0 != (rd[c].flags & GNUNET_NAMESTORE_RF_RELATIVE_EXPIRATION))
	{
	  GNUNET_break (GNUNET_YES == authoritative);
	  rd_modified = GNUNET_YES;
	  re.rel_value = rd[c].expiration_time;
	  e = GNUNET_TIME_relative_to_absolute (re);
	}
	else
	{
	  e.abs_value = rd[c].expiration_time;
	}
	/* found matching record, copy and convert flags to public format */
	rd_selected[copied_elements] = rd[c]; /* shallow copy! */
	rd_selected[copied_elements].expiration_time = e.abs_value;
	if (0 != (rd_selected[copied_elements].flags &
		  (GNUNET_NAMESTORE_RF_RELATIVE_EXPIRATION | GNUNET_NAMESTORE_RF_AUTHORITY)))
	{
	  rd_selected[copied_elements].flags &= ~ (GNUNET_NAMESTORE_RF_RELATIVE_EXPIRATION | 
				  GNUNET_NAMESTORE_RF_AUTHORITY);
	  rd_modified = GNUNET_YES;
	}
	copied_elements++;
      }
      else
      {
	rd_modified = GNUNET_YES;
      }
    }
  }
  else
    rd_selected = NULL;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, 
	      "Found %u matching records for name `%s' in zone `%s'\n",
	      copied_elements,
	      lnc->name, 
	      GNUNET_short_h2s (lnc->zone));
  contains_signature = GNUNET_NO;
  if (copied_elements > 0)
  {
    if (GNUNET_YES == authoritative)
    {
      GNUNET_assert (NULL != cc);
      e = get_block_expiration_time (rd_count, rd);
      signature_new = GNUNET_NAMESTORE_create_signature (cc->privkey, e, name, rd_selected, copied_elements);
      GNUNET_assert (NULL != signature_new);
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, 
		  "Creating signature for name `%s' with %u records in zone `%s'\n",
		  name, 
		  copied_elements,
		  GNUNET_short_h2s(&zone_key_hash));
    }
    else
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "Not authoritative, records modified is %d, have sig is %d\n",
		  rd_modified,
		  NULL != signature);
      if ((GNUNET_NO == rd_modified) && (NULL != signature))
	contains_signature = GNUNET_YES; /* returning all records, so include signature */
    }
  }

  rd_ser_len = GNUNET_NAMESTORE_records_get_size (copied_elements, rd_selected);
  name_len = (NULL == name) ? 0 : strlen(name) + 1;
  r_size = sizeof (struct LookupNameResponseMessage) +
           sizeof (struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded) +
           name_len +
           rd_ser_len;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, 
	      "Sending `%s' message\n", 
	      "NAMESTORE_LOOKUP_NAME_RESPONSE");
  lnr_msg = GNUNET_malloc (r_size);
  lnr_msg->gns_header.header.type = ntohs (GNUNET_MESSAGE_TYPE_NAMESTORE_LOOKUP_NAME_RESPONSE);
  lnr_msg->gns_header.header.size = ntohs (r_size);
  lnr_msg->gns_header.r_id = htonl (lnc->request_id);
  lnr_msg->rd_count = htons (copied_elements);
  lnr_msg->rd_len = htons (rd_ser_len);
  lnr_msg->name_len = htons (name_len);
  lnr_msg->expire = GNUNET_TIME_absolute_hton (get_block_expiration_time (copied_elements, 
									  rd_selected));
  name_tmp = (char *) &lnr_msg[1];
  memcpy (name_tmp, name, name_len);
  rd_tmp = &name_tmp[name_len];
  GNUNET_NAMESTORE_records_serialize (copied_elements, rd_selected, rd_ser_len, rd_tmp);
  if (rd_selected != rd)
    GNUNET_free_non_null (rd_selected);
  if (NULL != zone_key)
    lnr_msg->public_key = *zone_key;
  if ( (GNUNET_YES == authoritative) &&
       (copied_elements > 0) )
  {
    /* use new created signature */
    lnr_msg->contains_sig = htons (GNUNET_YES);
    GNUNET_assert (NULL != signature_new);
    lnr_msg->signature = *signature_new;
    GNUNET_free (signature_new);
  }
  else if (GNUNET_YES == contains_signature)
  {
    /* use existing signature */
    lnr_msg->contains_sig = htons (GNUNET_YES);
    GNUNET_assert (NULL != signature);
    lnr_msg->signature = *signature;
  }
  GNUNET_SERVER_notification_context_unicast (snc, lnc->nc->client, 
					      &lnr_msg->gns_header.header, 
					      GNUNET_NO);
  GNUNET_free (lnr_msg);
}


/**
 * Handles a 'GNUNET_MESSAGE_TYPE_NAMESTORE_LOOKUP_NAME' message
 *
 * @param cls unused
 * @param client GNUNET_SERVER_Client sending the message
 * @param message message of type 'struct LookupNameMessage'
 */
static void
handle_lookup_name (void *cls,
                    struct GNUNET_SERVER_Client *client,
                    const struct GNUNET_MessageHeader *message)
{
  const struct LookupNameMessage *ln_msg;
  struct LookupNameContext lnc;
  struct GNUNET_NAMESTORE_Client *nc;
  size_t name_len;
  const char *name;
  uint32_t rid;
  uint32_t type;
  char *conv_name;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, 
	      "Received `%s' message\n", 
	      "NAMESTORE_LOOKUP_NAME");
  if (ntohs (message->size) < sizeof (struct LookupNameMessage))
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  if (NULL == (nc = client_lookup(client)))
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  ln_msg = (const struct LookupNameMessage *) message;
  rid = ntohl (ln_msg->gns_header.r_id);
  name_len = ntohl (ln_msg->name_len);
  type = ntohl (ln_msg->record_type);
  if ((0 == name_len) || (name_len > MAX_NAME_LEN))
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  name = (const char *) &ln_msg[1];
  if ('\0' != name[name_len -1])
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  if (GNUNET_NAMESTORE_TYPE_ANY == type)
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, 
		"Looking up all records for name `%s' in zone `%s'\n", 
		name, 
		GNUNET_short_h2s(&ln_msg->zone));
  else
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, 
		"Looking up records with type %u for name `%s' in zone `%s'\n", 
		type, name, 
		GNUNET_short_h2s(&ln_msg->zone));

  conv_name = GNUNET_NAMESTORE_normalize_string (name);
  if (NULL == conv_name)
  {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  "Error converting name `%s'\n", name);
      return;
  }

  /* do the actual lookup */
  lnc.request_id = rid;
  lnc.nc = nc;
  lnc.record_type = type;
  lnc.name = conv_name;
  lnc.zone = &ln_msg->zone;
  if (GNUNET_SYSERR ==
      GSN_database->iterate_records (GSN_database->cls, 
				     &ln_msg->zone, conv_name, 0 /* offset */,
				     &handle_lookup_name_it, &lnc))
  {
    /* internal error (in database plugin); might be best to just hang up on
       plugin rather than to signal that there are 'no' results, which 
       might also be false... */
    GNUNET_break (0); 
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    GNUNET_free (conv_name);
    return;
  }
  GNUNET_free (conv_name);
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}


/**
 * Handles a 'GNUNET_MESSAGE_TYPE_NAMESTORE_RECORD_PUT' message
 *
 * @param cls unused
 * @param client GNUNET_SERVER_Client sending the message
 * @param message message of type 'struct RecordPutMessage'
 */
static void
handle_record_put (void *cls,
                   struct GNUNET_SERVER_Client *client,
                   const struct GNUNET_MessageHeader *message)
{
  struct GNUNET_NAMESTORE_Client *nc;
  const struct RecordPutMessage *rp_msg;
  struct GNUNET_TIME_Absolute expire;
  const struct GNUNET_CRYPTO_RsaSignature *signature;
  struct RecordPutResponseMessage rpr_msg;
  struct GNUNET_CRYPTO_ShortHashCode zone_hash;
  size_t name_len;
  size_t msg_size;
  size_t msg_size_exp;
  const char *name;
  const char *rd_ser;
  char * conv_name;
  uint32_t rid;
  uint32_t rd_ser_len;
  uint32_t rd_count;
  int res;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, 
	      "Received `%s' message\n",
	      "NAMESTORE_RECORD_PUT");
  if (ntohs (message->size) < sizeof (struct RecordPutMessage))
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  if (NULL == (nc = client_lookup (client)))
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  rp_msg = (const struct RecordPutMessage *) message;
  rid = ntohl (rp_msg->gns_header.r_id);
  msg_size = ntohs (rp_msg->gns_header.header.size);
  name_len = ntohs (rp_msg->name_len);
  rd_count = ntohs (rp_msg->rd_count);
  rd_ser_len = ntohs (rp_msg->rd_len);
  if ((rd_count < 1) || (rd_ser_len < 1) || (name_len >= MAX_NAME_LEN) || (0 == name_len))
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  msg_size_exp = sizeof (struct RecordPutMessage) + name_len + rd_ser_len;
  if (msg_size != msg_size_exp)
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  name = (const char *) &rp_msg[1];
  if ('\0' != name[name_len -1])
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  expire = GNUNET_TIME_absolute_ntoh (rp_msg->expire);
  signature = &rp_msg->signature;
  rd_ser = &name[name_len];
  struct GNUNET_NAMESTORE_RecordData rd[rd_count];

  if (GNUNET_OK !=
      GNUNET_NAMESTORE_records_deserialize (rd_ser_len, rd_ser, rd_count, rd))
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  GNUNET_CRYPTO_short_hash (&rp_msg->public_key,
                            sizeof (rp_msg->public_key),
                            &zone_hash);

  conv_name = GNUNET_NAMESTORE_normalize_string (name);
  if (NULL == conv_name)
  {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  "Error converting name `%s'\n", name);
      return;
  }

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Putting %u records under name `%s' in zone `%s'\n",
              rd_count, conv_name,
              GNUNET_short_h2s (&zone_hash));
  res = GSN_database->put_records(GSN_database->cls,
                                  &rp_msg->public_key,
                                  expire,
                                  conv_name,
                                  rd_count, rd,
                                  signature);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Putting record for name `%s': %s\n",
              conv_name,
              (GNUNET_OK == res) ? "OK" : "FAILED");
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, 
	      "Sending `%s' message\n", 
	      "RECORD_PUT_RESPONSE");
  GNUNET_free (conv_name);
  rpr_msg.gns_header.header.type = htons (GNUNET_MESSAGE_TYPE_NAMESTORE_RECORD_PUT_RESPONSE);
  rpr_msg.gns_header.header.size = htons (sizeof (struct RecordPutResponseMessage));
  rpr_msg.gns_header.r_id = htonl (rid);
  rpr_msg.op_result = htonl (res);
  GNUNET_SERVER_notification_context_unicast (snc, 
					      nc->client, 
					      &rpr_msg.gns_header.header, 
					      GNUNET_NO);
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}


/**
 * Context for record create operations passed from 'handle_record_create' to
 * 'handle_create_record_it' as closure
 */
struct CreateRecordContext
{
  /**
   * Record data
   */
  const struct GNUNET_NAMESTORE_RecordData *rd;

  /**
   * Zone's public key
   */
  struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded pubkey;

  /**
   * Name for the record to create
   */
  const char *name;

  /**
   * Record expiration time
   */
  struct GNUNET_TIME_Absolute expire;

  /**
   * result returned from 'handle_create_record_it'
   * GNUNET_SYSERR: failed to create the record
   * GNUNET_NO: we updated an existing record or identical entry existed
   * GNUNET_YES : we created a new record
   */
  int res;
};


/**
 * A 'GNUNET_NAMESTORE_RecordIterator' for record create operations
 * in handle_record_create
 *
 * @param cls a 'struct CreateRecordContext *' with information about the request
 * @param pubkey zone key of the zone
 * @param expire expiration time
 * @param name name
 * @param rd_count number of records
 * @param rd array of records
 * @param signature signature
 */
static void
handle_create_record_it (void *cls,
			 const struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded *pubkey,
			 struct GNUNET_TIME_Absolute expire,
			 const char *name,
			 unsigned int rd_count,
			 const struct GNUNET_NAMESTORE_RecordData *rd,
			 const struct GNUNET_CRYPTO_RsaSignature *signature)
{
  static struct GNUNET_CRYPTO_RsaSignature dummy_signature;
  struct CreateRecordContext *crc = cls;
  struct GNUNET_NAMESTORE_RecordData *rd_new;
  struct GNUNET_TIME_Absolute block_expiration;
  int exist;
  int update;
  unsigned int c;
  unsigned int rd_count_new;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, 
	      "Found %u existing records for `%s'\n", 
	      rd_count, crc->name);
  exist = -1;
  update = GNUNET_NO;
  for (c = 0; c < rd_count; c++)
  {
    if ( (crc->rd->record_type != rd[c].record_type) ||
	 ((crc->rd->flags & GNUNET_NAMESTORE_RF_RELATIVE_EXPIRATION) 
	  != (rd[c].flags & GNUNET_NAMESTORE_RF_RELATIVE_EXPIRATION)) )
      continue; /* no match */
    if ( (GNUNET_NAMESTORE_TYPE_PKEY == crc->rd->record_type) ||
	 (GNUNET_NAMESTORE_TYPE_PSEU == crc->rd->record_type) ||
	 (GNUNET_DNSPARSER_TYPE_CNAME == crc->rd->record_type) )
    {
      /* Update unique PKEY, PSEU or CNAME record; for these
	 record types, only one can be active at any time */
      exist = c;
      if ( (crc->rd->data_size != rd[c].data_size) ||
	   (0 != memcmp (crc->rd->data, rd[c].data, rd[c].data_size)) ||
	   (crc->rd->expiration_time != rd[c].expiration_time) )
	update = GNUNET_YES;
      break;
    }
    if ( (crc->rd->data_size == rd[c].data_size) &&
	 (0 == memcmp (crc->rd->data, rd[c].data, rd[c].data_size)))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, 
		  "Found matching existing record for `%s'; only updating expiration date!\n",
		  crc->name);
      exist = c;
      if (crc->rd->expiration_time != rd[c].expiration_time) 
        update = GNUNET_YES;
      break;
    }
  }

  if ( (-1 != exist) &&
       (GNUNET_NO == update) )
  {
    /* Exact same record already exists */
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, 
		"Matching record for %s' exists, no change required!\n",
		crc->name);
    crc->res = GNUNET_NO; /* identical record existed */
    return;
  }
  if (-1 == exist)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, 
		"No existing record for name `%s'!\n", 
		crc->name);
    rd_count_new = rd_count + 1;
    rd_new = GNUNET_malloc (rd_count_new * sizeof (struct GNUNET_NAMESTORE_RecordData));
    memcpy (rd_new, rd, rd_count * sizeof (struct GNUNET_NAMESTORE_RecordData));
    rd_new[rd_count] = *(crc->rd);
  }
  else 
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, 
		"Updating existing records for `%s'!\n", 
		crc->name);
    rd_count_new = rd_count;
    rd_new = GNUNET_malloc (rd_count_new * sizeof (struct GNUNET_NAMESTORE_RecordData));
    memcpy (rd_new, rd, rd_count * sizeof (struct GNUNET_NAMESTORE_RecordData));
    rd_new[exist] = *(crc->rd);
  }
  block_expiration = GNUNET_TIME_absolute_max (crc->expire, expire);
  if (GNUNET_OK !=
      GSN_database->put_records (GSN_database->cls,
				 &crc->pubkey,
				 block_expiration,
				 crc->name,
				 rd_count_new, rd_new,
				 &dummy_signature))
    crc->res = GNUNET_SYSERR; /* error */
  else if (GNUNET_YES == update)
    crc->res = GNUNET_NO; /* update */
  else
    crc->res = GNUNET_YES; /* created new record */
  GNUNET_free (rd_new);
}


/**
 * Handles a 'GNUNET_MESSAGE_TYPE_NAMESTORE_RECORD_CREATE' message
 *
 * @param cls unused
 * @param client GNUNET_SERVER_Client sending the message
 * @param message message of type 'struct RecordCreateMessage'
 */
static void
handle_record_create (void *cls,
                      struct GNUNET_SERVER_Client *client,
                      const struct GNUNET_MessageHeader *message)
{
  struct GNUNET_NAMESTORE_Client *nc;
  const struct RecordCreateMessage *rp_msg;
  struct CreateRecordContext crc;
  struct GNUNET_CRYPTO_RsaPrivateKey *pkey;
  struct RecordCreateResponseMessage rcr_msg;
  size_t name_len;
  size_t msg_size;
  size_t msg_size_exp;
  size_t rd_ser_len;
  size_t key_len;
  uint32_t rid;
  const char *pkey_tmp;
  const char *name_tmp;
  char *conv_name;
  const char *rd_ser;
  unsigned int rd_count;
  int res;
  struct GNUNET_NAMESTORE_RecordData rd;
  struct GNUNET_CRYPTO_ShortHashCode pubkey_hash;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, 
	      "Received `%s' message\n", "NAMESTORE_RECORD_CREATE");
  if (ntohs (message->size) < sizeof (struct RecordCreateMessage))
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  if (NULL == (nc = client_lookup (client)))
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  rp_msg = (const struct RecordCreateMessage *) message;
  rid = ntohl (rp_msg->gns_header.r_id);
  name_len = ntohs (rp_msg->name_len);
  msg_size = ntohs (message->size);
  rd_count = ntohs (rp_msg->rd_count);
  rd_ser_len = ntohs (rp_msg->rd_len);
  key_len = ntohs (rp_msg->pkey_len);
  msg_size_exp = sizeof (struct RecordCreateMessage) + key_len + name_len + rd_ser_len;
  if ( (msg_size != msg_size_exp) || (1 != rd_count) )
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  if ((0 == name_len) || (name_len > MAX_NAME_LEN))
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  pkey_tmp = (const char *) &rp_msg[1];
  name_tmp = &pkey_tmp[key_len];
  rd_ser = &name_tmp[name_len];
  if ('\0' != name_tmp[name_len -1])
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  if (NULL == (pkey = GNUNET_CRYPTO_rsa_decode_key (pkey_tmp, key_len)))
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  if (GNUNET_OK !=
      GNUNET_NAMESTORE_records_deserialize (rd_ser_len, rd_ser, rd_count, &rd))
  {
    GNUNET_break (0);
    GNUNET_CRYPTO_rsa_key_free (pkey);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }

  /* Extracting and converting private key */
  GNUNET_CRYPTO_rsa_key_get_public (pkey, &crc.pubkey);
  GNUNET_CRYPTO_short_hash (&crc.pubkey,
			    sizeof (struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded),
			    &pubkey_hash);
  learn_private_key (pkey);

  conv_name = GNUNET_NAMESTORE_normalize_string(name_tmp);
  if (NULL == conv_name)
  {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  "Error converting name `%s'\n", name_tmp);
      return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Creating record for name `%s' in zone `%s'\n",
	      conv_name, GNUNET_short_h2s(&pubkey_hash));
  crc.expire = GNUNET_TIME_absolute_ntoh(rp_msg->expire);
  crc.res = GNUNET_SYSERR;
  crc.rd = &rd;
  crc.name = conv_name;

  /* Get existing records for name */
  res = GSN_database->iterate_records (GSN_database->cls, &pubkey_hash, conv_name, 0,
				       &handle_create_record_it, &crc);
  GNUNET_free (conv_name);
  if (res != GNUNET_SYSERR)
    res = GNUNET_OK;

  /* Send response */
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, 
	      "Sending `%s' message\n", "RECORD_CREATE_RESPONSE");
  rcr_msg.gns_header.header.type = htons (GNUNET_MESSAGE_TYPE_NAMESTORE_RECORD_CREATE_RESPONSE);
  rcr_msg.gns_header.header.size = htons (sizeof (struct RecordCreateResponseMessage));
  rcr_msg.gns_header.r_id = htonl (rid);
  if ((GNUNET_OK == res) && (crc.res == GNUNET_YES))
    rcr_msg.op_result = htonl (GNUNET_YES);
  else if ((GNUNET_OK == res) && (crc.res == GNUNET_NO))
    rcr_msg.op_result = htonl (GNUNET_NO);
  else
    rcr_msg.op_result = htonl (GNUNET_SYSERR);
  GNUNET_SERVER_notification_context_unicast (snc, nc->client,
					      &rcr_msg.gns_header.header,
					      GNUNET_NO);
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}


/**
 * Context for record remove operations passed from 'handle_record_remove' to
 * 'handle_record_remove_it' as closure
 */
struct RemoveRecordContext
{
  /**
   * Record to remove
   */
  const struct GNUNET_NAMESTORE_RecordData *rd;

  /**
   * See RECORD_REMOVE_RESULT_*-codes.  Set by 'handle_record_remove_it'
   * to the result of the operation.
   */
  int32_t op_res;
};


/**
 * We are to remove a record (or all records for a given name).  This function
 * will be called with the existing records (if there are any) and is to then
 * compute what to keep and trigger the necessary changes.
 *
 * @param cls the 'struct RecordRemoveContext' with information about what to remove
 * @param zone_key public key of the zone
 * @param expire when does the corresponding block in the DHT expire (until
 *               when should we never do a DHT lookup for the same name again)?
 * @param name name that is being mapped (at most 255 characters long)
 * @param rd_count number of entries in 'rd' array
 * @param rd array of records with data to store
 * @param signature signature of the record block, NULL if signature is unavailable (i.e. 
 *        because the user queried for a particular record type only)
 */
static void
handle_record_remove_it (void *cls,
			 const struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded *zone_key,
			 struct GNUNET_TIME_Absolute expire,
			 const char *name,
			 unsigned int rd_count,
			 const struct GNUNET_NAMESTORE_RecordData *rd,
			 const struct GNUNET_CRYPTO_RsaSignature *signature)
{
  static struct GNUNET_CRYPTO_RsaSignature dummy_signature;
  struct RemoveRecordContext *rrc = cls;
  unsigned int c;
  int found;
  struct GNUNET_CRYPTO_ShortHashCode pubkey_hash;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, 
	      "Name `%s 'currently has %u records\n", 
	      name, rd_count);
  if (0 == rd_count)
  {
    /* Could not find record to remove */
    rrc->op_res = RECORD_REMOVE_RESULT_NO_RECORDS;
    return;
  }
  /* Find record to remove */
  found = -1;
  for (c = 0; c < rd_count; c++)
  {
    if (GNUNET_YES !=
	GNUNET_NAMESTORE_records_cmp (&rd[c],
				      rrc->rd))
      continue;
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Found record to remove!\n", rd_count);
    found = c;
    break;
  }
  if (-1 == found)
  {
    /* Could not find record to remove */
    rrc->op_res = RECORD_REMOVE_RESULT_RECORD_NOT_FOUND;
    return;
  }
  if (1 == rd_count)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "No records left for name `%s', removing name\n",
                name);
    GNUNET_CRYPTO_short_hash (zone_key, 
			      sizeof (struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded), 
			      &pubkey_hash);
    if (GNUNET_OK !=
	GSN_database->remove_records (GSN_database->cls,
				      &pubkey_hash,
				      name))
    {
      /* Could not remove records from database */
      rrc->op_res = RECORD_REMOVE_RESULT_FAILED_TO_REMOVE;
      return;
    }
    rrc->op_res = RECORD_REMOVE_RESULT_SUCCESS;
    return;
  }

  {
    struct GNUNET_NAMESTORE_RecordData rd_new[rd_count - 1];
    unsigned int c2 = 0;
    
    for (c = 0; c < rd_count; c++)
    {
      if (c == found)
	continue;	
      rd_new[c2++] = rd[c];
    }
    if (GNUNET_OK !=
	GSN_database->put_records(GSN_database->cls,
				  zone_key,
				  expire,
				  name,
				  rd_count - 1, rd_new,
				  &dummy_signature))
    {
      /* Could not put records into database */
      rrc->op_res = RECORD_REMOVE_RESULT_FAILED_TO_PUT_UPDATE;
      return;
    }
  }
  rrc->op_res = RECORD_REMOVE_RESULT_SUCCESS;
}


/**
 * Handles a 'GNUNET_MESSAGE_TYPE_NAMESTORE_RECORD_REMOVE' message
 *
 * @param cls unused
 * @param client GNUNET_SERVER_Client sending the message
 * @param message message of type 'struct RecordRemoveMessage'
 */
static void
handle_record_remove (void *cls,
		      struct GNUNET_SERVER_Client *client,
		      const struct GNUNET_MessageHeader *message)
{
  struct GNUNET_NAMESTORE_Client *nc;
  const struct RecordRemoveMessage *rr_msg;
  struct RecordRemoveResponseMessage rrr_msg;
  struct GNUNET_CRYPTO_RsaPrivateKey *pkey;
  struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded pub;
  struct GNUNET_CRYPTO_ShortHashCode pubkey_hash;
  struct GNUNET_NAMESTORE_RecordData rd;
  const char *pkey_tmp;
  const char *name_tmp;
  const char *rd_ser;
  char * conv_name;
  size_t key_len;
  size_t name_len;
  size_t rd_ser_len;
  size_t msg_size;
  size_t msg_size_exp;
  uint32_t rd_count;
  uint32_t rid;
  struct RemoveRecordContext rrc;
  int res;
  uint64_t off;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, 
	      "Received `%s' message\n", 
	      "NAMESTORE_RECORD_REMOVE");
  if (ntohs (message->size) < sizeof (struct RecordRemoveMessage))
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  if (NULL == (nc = client_lookup(client)))
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  rr_msg = (const struct RecordRemoveMessage *) message;
  rid = ntohl (rr_msg->gns_header.r_id);
  name_len = ntohs (rr_msg->name_len);
  rd_ser_len = ntohs (rr_msg->rd_len);
  rd_count = ntohs (rr_msg->rd_count);
  key_len = ntohs (rr_msg->pkey_len);
  msg_size = ntohs (message->size);
  if ((name_len >= MAX_NAME_LEN) || (0 == name_len) || (1 < rd_count) )
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  msg_size_exp = sizeof (struct RecordRemoveMessage) + key_len + name_len + rd_ser_len;
  if (msg_size != msg_size_exp)
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  pkey_tmp = (const char *) &rr_msg[1];
  name_tmp = &pkey_tmp[key_len];
  rd_ser = &name_tmp[name_len];
  if ('\0' != name_tmp[name_len -1])
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  if (NULL == (pkey = GNUNET_CRYPTO_rsa_decode_key (pkey_tmp, key_len)))
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  GNUNET_CRYPTO_rsa_key_get_public (pkey, &pub);
  GNUNET_CRYPTO_short_hash (&pub, 
			    sizeof (struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded), 
			    &pubkey_hash);
  learn_private_key (pkey);
  if (GNUNET_OK !=
      GNUNET_NAMESTORE_records_deserialize (rd_ser_len, rd_ser, rd_count, &rd))
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }

  conv_name = GNUNET_NAMESTORE_normalize_string(name_tmp);
  if (NULL == conv_name)
  {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  "Error converting name `%s'\n", name_tmp);
      return;
  }

  if (0 == rd_count)
  {
    /* remove the whole name and all records */
    res = GSN_database->remove_records (GSN_database->cls,
					&pubkey_hash,
					conv_name);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, 
		"Removing name `%s': %s\n",
		conv_name, (GNUNET_OK == res) ? "OK" : "FAILED");
    if (GNUNET_OK != res)
      /* Could not remove entry from database */
      res = RECORD_REMOVE_RESULT_FAILED_TO_PUT_UPDATE;
    else
      res = RECORD_REMOVE_RESULT_SUCCESS;
  }
  else
  {
    /* remove a single record */
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, 
		"Removing record for name `%s' in zone `%s'\n", conv_name,
		GNUNET_short_h2s (&pubkey_hash));
    rrc.rd = &rd;
    rrc.op_res = RECORD_REMOVE_RESULT_RECORD_NOT_FOUND;
    off = 0;
    res = GNUNET_OK;
    while ( (RECORD_REMOVE_RESULT_RECORD_NOT_FOUND == rrc.op_res) &&
	    (GNUNET_OK == res) )
    {
      res = GSN_database->iterate_records (GSN_database->cls,
					   &pubkey_hash,
					   conv_name,
					   off++,
					   &handle_record_remove_it, &rrc);
    } 
    switch (res)
    {
    case GNUNET_OK:
      res = rrc.op_res;
      break;
    case GNUNET_NO:
      GNUNET_break (RECORD_REMOVE_RESULT_NO_RECORDS == rrc.op_res);
      res = RECORD_REMOVE_RESULT_NO_RECORDS;
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
		  _("Failed to find record to remove\n"));
      break;
    case GNUNET_SYSERR:
      res = RECORD_REMOVE_RESULT_FAILED_ACCESS_DATABASE;
      break;
    default:
      GNUNET_break (0);
      res = RECORD_REMOVE_RESULT_FAILED_INTERNAL_ERROR;
      break;
    }
  }
  GNUNET_free (conv_name);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Sending `%s' message\n",
	      "RECORD_REMOVE_RESPONSE");
  rrr_msg.gns_header.header.type = htons (GNUNET_MESSAGE_TYPE_NAMESTORE_RECORD_REMOVE_RESPONSE);
  rrr_msg.gns_header.header.size = htons (sizeof (struct RecordRemoveResponseMessage));
  rrr_msg.gns_header.r_id = htonl (rid);
  rrr_msg.op_result = htonl (res);
  GNUNET_SERVER_notification_context_unicast (snc, nc->client, 
					      &rrr_msg.gns_header.header,
					      GNUNET_NO);
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}


/**
 * Context for record remove operations passed from 'handle_zone_to_name' to
 * 'handle_zone_to_name_it' as closure
 */
struct ZoneToNameCtx
{
  /**
   * Namestore client
   */
  struct GNUNET_NAMESTORE_Client *nc;

  /**
   * Request id (to be used in the response to the client).
   */
  uint32_t rid;

  /**
   * Set to GNUNET_OK on success, GNUNET_SYSERR on error.  Note that
   * not finding a name for the zone still counts as a 'success' here,
   * as this field is about the success of executing the IPC protocol.
   */
  int success;
};


/**
 * Zone to name iterator
 *
 * @param cls struct ZoneToNameCtx *
 * @param zone_key the zone key
 * @param expire expiration date
 * @param name name
 * @param rd_count number of records
 * @param rd record data
 * @param signature signature
 */
static void
handle_zone_to_name_it (void *cls,
			const struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded *zone_key,
			struct GNUNET_TIME_Absolute expire,
			const char *name,
			unsigned int rd_count,
			const struct GNUNET_NAMESTORE_RecordData *rd,
			const struct GNUNET_CRYPTO_RsaSignature *signature)
{
  struct ZoneToNameCtx *ztn_ctx = cls;
  struct ZoneToNameResponseMessage *ztnr_msg;
  int16_t res;
  size_t name_len;
  size_t rd_ser_len;
  size_t msg_size;
  char *name_tmp;
  char *rd_tmp;
  char *sig_tmp;

  if ((NULL != zone_key) && (NULL != name))
  {
    /* found result */
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, 
		"Found result: name `%s' has %u records\n", 
		name, rd_count);
    res = GNUNET_YES;
    name_len = strlen (name) + 1;
  }
  else
  {
    /* no result found */
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, 
		"Found no results\n");
    res = GNUNET_NO;
    name_len = 0;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, 
	      "Sending `%s' message\n", 
	      "ZONE_TO_NAME_RESPONSE");
  rd_ser_len = GNUNET_NAMESTORE_records_get_size (rd_count, rd);
  msg_size = sizeof (struct ZoneToNameResponseMessage) + name_len + rd_ser_len;
  if (NULL != signature)
    msg_size += sizeof (struct GNUNET_CRYPTO_RsaSignature);
  if (msg_size >= GNUNET_SERVER_MAX_MESSAGE_SIZE)
  {
    GNUNET_break (0);
    ztn_ctx->success = GNUNET_SYSERR;
    return;
  }
  ztnr_msg = GNUNET_malloc (msg_size);
  ztnr_msg->gns_header.header.type = htons (GNUNET_MESSAGE_TYPE_NAMESTORE_ZONE_TO_NAME_RESPONSE);
  ztnr_msg->gns_header.header.size = htons (msg_size);
  ztnr_msg->gns_header.r_id = htonl (ztn_ctx->rid);
  ztnr_msg->res = htons (res);
  ztnr_msg->rd_len = htons (rd_ser_len);
  ztnr_msg->rd_count = htons (rd_count);
  ztnr_msg->name_len = htons (name_len);
  ztnr_msg->expire = GNUNET_TIME_absolute_hton (expire);
  if (NULL != zone_key)
    ztnr_msg->zone_key = *zone_key;
  name_tmp = (char *) &ztnr_msg[1];
  if (NULL != name)
    memcpy (name_tmp, name, name_len);
  rd_tmp = &name_tmp[name_len];
  GNUNET_NAMESTORE_records_serialize (rd_count, rd, rd_ser_len, rd_tmp);
  sig_tmp = &rd_tmp[rd_ser_len];
  if (NULL != signature)
    memcpy (sig_tmp, signature, sizeof (struct GNUNET_CRYPTO_RsaSignature));
  ztn_ctx->success = GNUNET_OK;
  GNUNET_SERVER_notification_context_unicast (snc, ztn_ctx->nc->client,
					      &ztnr_msg->gns_header.header,
					      GNUNET_NO);
  GNUNET_free (ztnr_msg);
}


/**
 * Handles a 'GNUNET_MESSAGE_TYPE_NAMESTORE_ZONE_TO_NAME' message
 *
 * @param cls unused
 * @param client GNUNET_SERVER_Client sending the message
 * @param message message of type 'struct ZoneToNameMessage'
 */
static void
handle_zone_to_name (void *cls,
                     struct GNUNET_SERVER_Client *client,
                     const struct GNUNET_MessageHeader *message)
{
  struct GNUNET_NAMESTORE_Client *nc;
  const struct ZoneToNameMessage *ztn_msg;
  struct ZoneToNameCtx ztn_ctx;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, 
	      "Received `%s' message\n",
	      "ZONE_TO_NAME");
  ztn_msg = (const struct ZoneToNameMessage *) message;
  if (NULL == (nc = client_lookup(client)))
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  ztn_ctx.rid = ntohl (ztn_msg->gns_header.r_id);
  ztn_ctx.nc = nc;
  ztn_ctx.success = GNUNET_SYSERR;
  if (GNUNET_SYSERR ==
      GSN_database->zone_to_name (GSN_database->cls, 
				  &ztn_msg->zone,
				  &ztn_msg->value_zone,
				  &handle_zone_to_name_it, &ztn_ctx))
  {
    /* internal error, hang up instead of signalling something
       that might be wrong */
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;    
  }
  GNUNET_SERVER_receive_done (client, ztn_ctx.success);
}


/**
 * Zone iteration processor result
 */
enum ZoneIterationResult
{
  /**
   * Found records, but all records were filtered
   * Continue to iterate
   */
  IT_ALL_RECORDS_FILTERED = -1,

  /**
   * Found records,
   * Continue to iterate with next iteration_next call
   */
  IT_SUCCESS_MORE_AVAILABLE = 0,

  /**
   * Iteration complete
   */
  IT_SUCCESS_NOT_MORE_RESULTS_AVAILABLE = 1
};


/**
 * Context for record remove operations passed from
 * 'run_zone_iteration_round' to 'zone_iteraterate_proc' as closure
 */
struct ZoneIterationProcResult
{
  /**
   * The zone iteration handle
   */
  struct GNUNET_NAMESTORE_ZoneIteration *zi;

  /**
   * Iteration result: iteration done?
   * IT_SUCCESS_MORE_AVAILABLE:  if there may be more results overall but
   * we got one for now and have sent it to the client
   * IT_SUCCESS_NOT_MORE_RESULTS_AVAILABLE: if there are no further results,
   * IT_ALL_RECORDS_FILTERED: if all results were filtered so far.
   */
  int res_iteration_finished;

};


/**
 * Process results for zone iteration from database
 *
 * @param cls struct ZoneIterationProcResult *proc
 * @param zone_key the zone key
 * @param expire expiration time
 * @param name name
 * @param rd_count number of records for this name
 * @param rd record data
 * @param signature block signature
 */
static void
zone_iteraterate_proc (void *cls,
                       const struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded *zone_key,
                       struct GNUNET_TIME_Absolute expire,
                       const char *name,
                       unsigned int rd_count,
                       const struct GNUNET_NAMESTORE_RecordData *rd,
                       const struct GNUNET_CRYPTO_RsaSignature *signature)
{
  struct ZoneIterationProcResult *proc = cls;
  struct GNUNET_NAMESTORE_RecordData rd_filtered[rd_count];
  struct GNUNET_CRYPTO_RsaSignature *new_signature = NULL;
  struct GNUNET_NAMESTORE_CryptoContainer *cc;
  struct GNUNET_HashCode long_hash;
  struct GNUNET_CRYPTO_ShortHashCode zone_hash;
  struct ZoneIterationResponseMessage *zir_msg;
  struct GNUNET_TIME_Relative rt;
  unsigned int rd_count_filtered;
  unsigned int c;
  size_t name_len;
  size_t rd_ser_len;
  size_t msg_size;
  char *name_tmp;
  char *rd_ser;

  proc->res_iteration_finished = IT_SUCCESS_MORE_AVAILABLE;
  if ((NULL == zone_key) && (NULL == name))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, 
		"Iteration done\n");
    proc->res_iteration_finished = IT_SUCCESS_NOT_MORE_RESULTS_AVAILABLE;
    return;
  }
  if ((NULL == zone_key) || (NULL == name)) 
  {
    /* what is this!? should never happen */
    GNUNET_break (0);
    return;    
  }
  rd_count_filtered  = 0;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, 
	      "Received result for zone iteration: `%s'\n", 
	      name);
  for (c = 0; c < rd_count; c++)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		"Record %u has flags: %x must have flags are %x, must not have flags are %x\n",
		c, rd[c].flags, 
		proc->zi->must_have_flags,
		proc->zi->must_not_have_flags);
    /* Checking must have flags, except 'relative-expiration' which is a special flag */
    if ((rd[c].flags & proc->zi->must_have_flags & (~GNUNET_NAMESTORE_RF_RELATIVE_EXPIRATION))
	!= (proc->zi->must_have_flags & (~ GNUNET_NAMESTORE_RF_RELATIVE_EXPIRATION)))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Record %u lacks 'must-have' flags: Not included\n", c);
      continue;
    }
    /* Checking must-not-have flags */
    if (0 != (rd[c].flags & proc->zi->must_not_have_flags))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, 
		  "Record %u has 'must-not-have' flags: Not included\n", c);
      continue;
    }
    rd_filtered[rd_count_filtered] = rd[c];
    /* convert relative to absolute expiration time unless explicitly requested otherwise */
    if ( (0 == (proc->zi->must_have_flags & GNUNET_NAMESTORE_RF_RELATIVE_EXPIRATION)) &&
	 (0 != (rd[c].flags & GNUNET_NAMESTORE_RF_RELATIVE_EXPIRATION)) )
    {
      /* should convert relative-to-absolute expiration time */
      rt.rel_value = rd[c].expiration_time;
      rd_filtered[c].expiration_time = GNUNET_TIME_relative_to_absolute (rt).abs_value;
      rd_filtered[c].flags &= ~ GNUNET_NAMESTORE_RF_RELATIVE_EXPIRATION;
    }
    /* we NEVER keep the 'authority' flag */
    rd_filtered[c].flags &= ~ GNUNET_NAMESTORE_RF_AUTHORITY;
    rd_count_filtered++;    
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, 
	      "Included %u of %u records\n", 
	      rd_count_filtered, rd_count);

  signature = NULL;    
  if ( (rd_count_filtered > 0) &&
       (0 == (proc->zi->must_have_flags & GNUNET_NAMESTORE_RF_RELATIVE_EXPIRATION)) )
  {
    /* compute / obtain signature, but only if we (a) have records and (b) expiration times were 
       converted to absolute expiration times */
    GNUNET_CRYPTO_short_hash (zone_key, 
			      sizeof (struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded),
			      &zone_hash);
    GNUNET_CRYPTO_short_hash_double (&zone_hash, &long_hash);
    if (NULL != (cc = GNUNET_CONTAINER_multihashmap_get(zonekeys, &long_hash)))
    {
      expire = get_block_expiration_time (rd_count_filtered, rd_filtered);
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "Creating signature for `%s' in zone `%s' with %u records and expiration %llu\n",
		  name, GNUNET_short_h2s(&zone_hash), 
		  rd_count_filtered,
		  (unsigned long long) expire.abs_value);
      new_signature = GNUNET_NAMESTORE_create_signature (cc->privkey, expire, name, 
							 rd_filtered, rd_count_filtered);
      GNUNET_assert (NULL != new_signature);
      signature = new_signature;
    }
    else if (rd_count_filtered == rd_count)
    {
      if (NULL != signature)
	{
	  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, 
		      "Using provided signature for `%s' in zone `%s' with %u records and expiration %llu\n",
		      name, GNUNET_short_h2s (&zone_hash), rd_count_filtered, 
		      (unsigned long long) expire.abs_value);
	  return;
	}    
    }
  }
  if (rd_count_filtered == 0)
  {
    /* After filtering records there are no records left to return */
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "No records to transmit\n");
    proc->res_iteration_finished = IT_ALL_RECORDS_FILTERED;
    return;
  }

  if (GNUNET_YES == proc->zi->has_zone)
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, 
		"Sending name `%s' for iteration over zone `%s'\n",
		name, GNUNET_short_h2s(&proc->zi->zone));
  else
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, 
		"Sending name `%s' for iteration over all zones\n",
		name);
  name_len = strlen (name) + 1;
  rd_ser_len = GNUNET_NAMESTORE_records_get_size (rd_count_filtered, rd_filtered);  
  msg_size = sizeof (struct ZoneIterationResponseMessage) + name_len + rd_ser_len;

  zir_msg = GNUNET_malloc (msg_size);
  zir_msg->gns_header.header.type = htons (GNUNET_MESSAGE_TYPE_NAMESTORE_ZONE_ITERATION_RESPONSE);
  zir_msg->gns_header.header.size = htons (msg_size);
  zir_msg->gns_header.r_id = htonl (proc->zi->request_id);
  zir_msg->expire = GNUNET_TIME_absolute_hton (expire);
  zir_msg->reserved = htons (0);
  zir_msg->name_len = htons (name_len);
  zir_msg->rd_count = htons (rd_count_filtered);
  zir_msg->rd_len = htons (rd_ser_len);
  if (NULL != signature)
    zir_msg->signature = *signature;
  zir_msg->public_key = *zone_key;
  name_tmp = (char *) &zir_msg[1];
  memcpy (name_tmp, name, name_len);
  rd_ser = &name_tmp[name_len];
  GNUNET_NAMESTORE_records_serialize (rd_count_filtered, rd_filtered, rd_ser_len, rd_ser);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, 
	      "Sending `%s' message with size %u\n", 
	      "ZONE_ITERATION_RESPONSE",
	      msg_size);
  GNUNET_SERVER_notification_context_unicast (snc, proc->zi->client->client, 
					      (const struct GNUNET_MessageHeader *) zir_msg,
					      GNUNET_NO);
  proc->res_iteration_finished = IT_SUCCESS_MORE_AVAILABLE;
  GNUNET_free (zir_msg);
  GNUNET_free_non_null (new_signature);
}


/**
 * Perform the next round of the zone iteration.
 *
 * @param zi zone iterator to process
 */
static void
run_zone_iteration_round (struct GNUNET_NAMESTORE_ZoneIteration *zi)
{
  struct ZoneIterationProcResult proc;
  struct ZoneIterationResponseMessage zir_end;
  struct GNUNET_CRYPTO_ShortHashCode *zone;

  memset (&proc, 0, sizeof (proc));
  proc.zi = zi;
  if (GNUNET_YES == zi->has_zone)
    zone = &zi->zone;
  else
    zone = NULL;
  proc.res_iteration_finished = IT_ALL_RECORDS_FILTERED;
  while (IT_ALL_RECORDS_FILTERED == proc.res_iteration_finished)
  {
    if (GNUNET_SYSERR ==
	GSN_database->iterate_records (GSN_database->cls, zone, NULL, 
				       zi->offset, 
				       &zone_iteraterate_proc, &proc))
    {
      GNUNET_break (0);
      break;
    }
    zi->offset++;
  }
  if (IT_SUCCESS_MORE_AVAILABLE == proc.res_iteration_finished)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "More results available\n");
    return; /* more results later */
  }
  if (GNUNET_YES == zi->has_zone)
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, 
		"No more results for zone `%s'\n", 
		GNUNET_short_h2s(&zi->zone));
  else
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		"No more results for all zones\n");
  memset (&zir_end, 0, sizeof (zir_end));
  zir_end.gns_header.header.type = htons (GNUNET_MESSAGE_TYPE_NAMESTORE_ZONE_ITERATION_RESPONSE);
  zir_end.gns_header.header.size = htons (sizeof (struct ZoneIterationResponseMessage));
  zir_end.gns_header.r_id = htonl(zi->request_id);
  GNUNET_SERVER_notification_context_unicast (snc, 
					      zi->client->client, 
					      &zir_end.gns_header.header, GNUNET_NO);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, 
	      "Removing zone iterator\n");
  GNUNET_CONTAINER_DLL_remove (zi->client->op_head, zi->client->op_tail, zi);
  GNUNET_free (zi);
}


/**
 * Handles a 'GNUNET_MESSAGE_TYPE_NAMESTORE_ZONE_ITERATION_START' message
 *
 * @param cls unused
 * @param client GNUNET_SERVER_Client sending the message
 * @param message message of type 'struct ZoneIterationStartMessage'
 */
static void
handle_iteration_start (void *cls,
                        struct GNUNET_SERVER_Client *client,
                        const struct GNUNET_MessageHeader *message)
{
  static struct GNUNET_CRYPTO_ShortHashCode zeros;
  const struct ZoneIterationStartMessage *zis_msg;
  struct GNUNET_NAMESTORE_Client *nc;
  struct GNUNET_NAMESTORE_ZoneIteration *zi;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Received `%s' message\n", "ZONE_ITERATION_START");
  if (NULL == (nc = client_lookup (client)))
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  zis_msg = (const struct ZoneIterationStartMessage *) message;
  zi = GNUNET_malloc (sizeof (struct GNUNET_NAMESTORE_ZoneIteration));
  zi->request_id = ntohl (zis_msg->gns_header.r_id);
  zi->offset = 0;
  zi->client = nc;
  zi->must_have_flags = ntohs (zis_msg->must_have_flags);
  zi->must_not_have_flags = ntohs (zis_msg->must_not_have_flags);
  if (0 == memcmp (&zeros, &zis_msg->zone, sizeof (zeros)))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Starting to iterate over all zones\n");
    zi->zone = zis_msg->zone;
    zi->has_zone = GNUNET_NO;
  }
  else
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, 
		"Starting to iterate over zone `%s'\n", GNUNET_short_h2s (&zis_msg->zone));
    zi->zone = zis_msg->zone;
    zi->has_zone = GNUNET_YES;
  }
  GNUNET_CONTAINER_DLL_insert (nc->op_head, nc->op_tail, zi);
  run_zone_iteration_round (zi);
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}


/**
 * Handles a 'GNUNET_MESSAGE_TYPE_NAMESTORE_ZONE_ITERATION_STOP' message
 *
 * @param cls unused
 * @param client GNUNET_SERVER_Client sending the message
 * @param message message of type 'struct ZoneIterationStopMessage'
 */
static void
handle_iteration_stop (void *cls,
                       struct GNUNET_SERVER_Client *client,
                       const struct GNUNET_MessageHeader *message)
{
  struct GNUNET_NAMESTORE_Client *nc;
  struct GNUNET_NAMESTORE_ZoneIteration *zi;
  const struct ZoneIterationStopMessage *zis_msg;
  uint32_t rid;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Received `%s' message\n",
	      "ZONE_ITERATION_STOP");
  if (NULL == (nc = client_lookup(client)))
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  zis_msg = (const struct ZoneIterationStopMessage *) message;
  rid = ntohl (zis_msg->gns_header.r_id);
  for (zi = nc->op_head; NULL != zi; zi = zi->next)
    if (zi->request_id == rid)
      break;
  if (NULL == zi)
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  GNUNET_CONTAINER_DLL_remove (nc->op_head, nc->op_tail, zi);
  if (GNUNET_YES == zi->has_zone)
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, 
		"Stopped zone iteration for zone `%s'\n",
		GNUNET_short_h2s (&zi->zone));
  else
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, 
		"Stopped zone iteration over all zones\n");
  GNUNET_free (zi);
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}


/**
 * Handles a 'GNUNET_MESSAGE_TYPE_NAMESTORE_ZONE_ITERATION_NEXT' message
 *
 * @param cls unused
 * @param client GNUNET_SERVER_Client sending the message
 * @param message message of type 'struct ZoneIterationNextMessage'
 */
static void
handle_iteration_next (void *cls,
                       struct GNUNET_SERVER_Client *client,
                       const struct GNUNET_MessageHeader *message)
{
  struct GNUNET_NAMESTORE_Client *nc;
  struct GNUNET_NAMESTORE_ZoneIteration *zi;
  const struct ZoneIterationNextMessage *zis_msg;
  uint32_t rid;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Received `%s' message\n", "ZONE_ITERATION_NEXT");
  if (NULL == (nc = client_lookup(client)))
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  zis_msg = (const struct ZoneIterationNextMessage *) message;
  rid = ntohl (zis_msg->gns_header.r_id);
  for (zi = nc->op_head; NULL != zi; zi = zi->next)
    if (zi->request_id == rid)
      break;
  if (NULL == zi)
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  run_zone_iteration_round (zi);
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}

static void
zonekey_it_key_cb (void *cls,
                   struct GNUNET_CRYPTO_RsaPrivateKey *pk,
                   const char *emsg)
{
  struct KeyLoadContext *kl = cls;

  kl->keygen = NULL;
  if (NULL == pk)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                _("Could not parse zone key file `%s'\n"),
                kl->filename);
    return;
  }
  learn_private_key (pk);
  (*kl->counter) ++;

  GNUNET_CONTAINER_DLL_remove (kl_head, kl_tail, kl);
  GNUNET_free (kl->filename);
  GNUNET_free (kl);
}


/**
 * Load zone keys from directory by reading all .zkey files in this directory
 *
 * @param cls int * 'counter' to store the number of files found
 * @param filename directory to scan
 * @return GNUNET_OK to continue
 */
static int
zonekey_file_it (void *cls, const char *filename)
{
  struct KeyLoadContext *kl;

  if ((NULL == filename) ||
      (NULL == strstr(filename, ".zkey")))
    return GNUNET_OK;

  kl = GNUNET_malloc (sizeof (struct KeyLoadContext));
  kl->filename = strdup (filename);
  kl->counter = cls;
  kl->keygen = GNUNET_CRYPTO_rsa_key_create_start (filename, zonekey_it_key_cb, kl);
  if (NULL == kl->keygen)
  {
    GNUNET_free (kl->filename);
    GNUNET_free (kl);
    return GNUNET_OK;
  }

  GNUNET_CONTAINER_DLL_insert (kl_head, kl_tail, kl);
  return GNUNET_OK;
}


/**
 * Process namestore requests.
 *
 * @param cls closure
 * @param server the initialized server
 * @param cfg configuration to use
 */
static void
run (void *cls, struct GNUNET_SERVER_Handle *server,
     const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  static const struct GNUNET_SERVER_MessageHandler handlers[] = {
    {&handle_start, NULL,
     GNUNET_MESSAGE_TYPE_NAMESTORE_START, sizeof (struct StartMessage)},
    {&handle_lookup_name, NULL,
     GNUNET_MESSAGE_TYPE_NAMESTORE_LOOKUP_NAME, 0},
    {&handle_record_put, NULL,
    GNUNET_MESSAGE_TYPE_NAMESTORE_RECORD_PUT, 0},
    {&handle_record_create, NULL,
     GNUNET_MESSAGE_TYPE_NAMESTORE_RECORD_CREATE, 0},
    {&handle_record_remove, NULL,
     GNUNET_MESSAGE_TYPE_NAMESTORE_RECORD_REMOVE, 0},
    {&handle_zone_to_name, NULL,
     GNUNET_MESSAGE_TYPE_NAMESTORE_ZONE_TO_NAME, sizeof (struct ZoneToNameMessage) },
    {&handle_iteration_start, NULL,
     GNUNET_MESSAGE_TYPE_NAMESTORE_ZONE_ITERATION_START, sizeof (struct ZoneIterationStartMessage) },
    {&handle_iteration_next, NULL,
     GNUNET_MESSAGE_TYPE_NAMESTORE_ZONE_ITERATION_NEXT, sizeof (struct ZoneIterationNextMessage) },
     {&handle_iteration_stop, NULL,
      GNUNET_MESSAGE_TYPE_NAMESTORE_ZONE_ITERATION_STOP, sizeof (struct ZoneIterationStopMessage) },
    {NULL, NULL, 0, 0}
  };
  char *database;
  unsigned int counter;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Starting namestore service\n");
  GSN_cfg = cfg;

  /* Load private keys from disk */
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_filename (cfg, "namestore", 
					       "zonefile_directory",
					       &zonefile_directory))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, 
		_("No directory to load zonefiles specified in configuration\n"));
    GNUNET_SCHEDULER_add_now (&cleanup_task, NULL);
    return;
  }

  if (GNUNET_NO == GNUNET_DISK_file_test (zonefile_directory))
  {
    if (GNUNET_SYSERR == GNUNET_DISK_directory_create (zonefile_directory))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR, 
		  _("Creating directory `%s' for zone files failed!\n"),
		  zonefile_directory);
      GNUNET_SCHEDULER_add_now (&cleanup_task, NULL);
      return;
    }
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, 
		"Created directory `%s' for zone files\n", 
		zonefile_directory);
  }

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, 
	      "Scanning directory `%s' for zone files\n", zonefile_directory);
  zonekeys = GNUNET_CONTAINER_multihashmap_create (16, GNUNET_NO);
  counter = 0;
  GNUNET_DISK_directory_scan (zonefile_directory, zonekey_file_it, &counter);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, 
	      "Found %u zone files\n", 
	      counter);

  /* Loading database plugin */
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_string (cfg, "namestore", "database",
                                             &database))
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "No database backend configured\n");

  GNUNET_asprintf (&db_lib_name, "libgnunet_plugin_namestore_%s", database);
  GSN_database = GNUNET_PLUGIN_load (db_lib_name, (void *) GSN_cfg);
  GNUNET_free (database);
  if (NULL == GSN_database)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, 
		"Could not load database backend `%s'\n",
		db_lib_name);
    GNUNET_SCHEDULER_add_now (&cleanup_task, NULL);
    return;
  }

  /* Configuring server handles */
  GNUNET_SERVER_add_handlers (server, handlers);
  snc = GNUNET_SERVER_notification_context_create (server, 16);
  GNUNET_SERVER_disconnect_notify (server,
                                   &client_disconnect_notification,
                                   NULL);
  GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_FOREVER_REL, &cleanup_task,
                                NULL);
}


/**
 * The main function for the template service.
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return 0 ok, 1 on error
 */
int
main (int argc, char *const *argv)
{
  return (GNUNET_OK ==
          GNUNET_SERVICE_run (argc, argv, "namestore",
                              GNUNET_SERVICE_OPTION_NONE, &run, NULL)) ? 0 : 1;
}

/* end of gnunet-service-namestore.c */


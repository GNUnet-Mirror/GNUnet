/*
     This file is part of GNUnet.
     (C) 2009, 2010 Christian Grothoff (and other contributing authors)

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
 * @file gns/namestore_stub_api.c
 * @brief stub library to access the NAMESTORE service
 * @author Martin Schanzenbach
 */

#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_constants.h"
#include "gnunet_arm_service.h"
#include "gnunet_namestore_service.h"

#define DEBUG_GNS_API GNUNET_EXTRA_LOGGING

#define LOG(kind,...) GNUNET_log_from (kind, "gns-api",__VA_ARGS__)

/**
 * A QueueEntry.
 */
struct GNUNET_NAMESTORE_QueueEntry
{
  char *data; /*stub data pointer*/
};

/**
 * Connection to the NAMESTORE service.
 */
struct GNUNET_NAMESTORE_Handle
{

  /**
   * Configuration to use.
   */
  const struct GNUNET_CONFIGURATION_Handle *cfg;

  /**
   * Socket (if available).
   */
  struct GNUNET_CLIENT_Connection *client;

  /**
   * Currently pending transmission request (or NULL).
   */
  struct GNUNET_CLIENT_TransmitHandle *th;

  /* dll to use for records */
  struct GNUNET_NAMESTORE_SimpleRecord * records_head;
  struct GNUNET_NAMESTORE_SimpleRecord * records_tail;

};

struct GNUNET_NAMESTORE_SimpleRecord
{
  /**
   * DLL
   */
  struct GNUNET_NAMESTORE_SimpleRecord *next;

  /**
   * DLL
   */
  struct GNUNET_NAMESTORE_SimpleRecord *prev;
  
  const char *name;
  const GNUNET_HashCode *zone;
  uint32_t record_type;
  struct GNUNET_TIME_Absolute expiration;
  enum GNUNET_NAMESTORE_RecordFlags flags;
  size_t data_size;
  const void *data;
};

/**
 * Initialize the connection with the NAMESTORE service.
 *
 * @param cfg configuration to use
 * @return handle to the GNS service, or NULL on error
 */
struct GNUNET_NAMESTORE_Handle *
GNUNET_NAMESTORE_connect (const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  struct GNUNET_NAMESTORE_Handle *handle;

  handle = GNUNET_malloc (sizeof (struct GNUNET_NAMESTORE_Handle));
  handle->cfg = cfg;
  return handle;
}


/**
 * Shutdown connection with the NAMESTORE service.
 *
 * @param handle handle of the NAMESTORE connection to stop
 */
void
GNUNET_NAMESTORE_disconnect (struct GNUNET_NAMESTORE_Handle *handle, int drop)
{
  GNUNET_free(handle);
}

/**
 * Sign a record.  This function is used by the authority of the zone
 * to add a record.
 *
 * @param h handle to the namestore
 * @param zone_privkey private key of the zone
 * @param record_hash hash of the record to be signed
 * @param cont continuation to call when done
 * @param cont_cls closure for cont
 * @return handle to abort the request
 */
struct GNUNET_NAMESTORE_QueueEntry *
GNUNET_NAMESTORE_stree_extend (struct GNUNET_NAMESTORE_Handle *h,
             const struct GNUNET_CRYPTO_RsaPrivateKey *zone_privkey,
             const GNUNET_HashCode *record_hash,
             GNUNET_NAMESTORE_ContinuationWithSignature cont,
             void *cont_cls)
{
  struct GNUNET_NAMESTORE_QueueEntry *qe;
  qe = GNUNET_malloc(sizeof (struct GNUNET_NAMESTORE_QueueEntry));
  return qe;
}

/**
 * Rebalance the signature tree of our zone.  This function should
 * be called "rarely" to rebalance the tree.
 *
 * @param h handle to the namestore
 * @param zone_privkey private key for the zone to rebalance
 * @param cont continuation to call when done
 * @param cont_cls closure for cont
 * @return handle to abort the request
 */
struct GNUNET_NAMESTORE_QueueEntry *
GNUNET_NAMESTORE_stree_rebalance (struct GNUNET_NAMESTORE_Handle *h,
          const struct GNUNET_CRYPTO_RsaPrivateKey *zone_privkey,
          GNUNET_NAMESTORE_ContinuationWithStatus cont,
          void *cont_cls)
{
  struct GNUNET_NAMESTORE_QueueEntry *qe;
  qe = GNUNET_malloc(sizeof (struct GNUNET_NAMESTORE_QueueEntry));
  return qe;
}

/**
 * Provide the root of a signature tree.  This function is 
 * used by non-authorities as the first operation when 
 * adding a foreign zone.
 *
 * @param h handle to the namestore
 * @param zone_key public key of the zone
 * @param signature signature of the top-level entry of the zone
 * @param revision revision number of the zone
 * @param top_hash top-level hash of the zone
 * @param cont continuation to call when done
 * @param cont_cls closure for cont
 * @return handle to abort the request
 */
struct GNUNET_NAMESTORE_QueueEntry *
GNUNET_NAMESTORE_stree_start (struct GNUNET_NAMESTORE_Handle *h,
			      const struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded *zone_key,
			      const struct GNUNET_CRYPTO_RsaSignature *signature,
			      uint32_t revision,
			      const GNUNET_HashCode *top_hash,
			      GNUNET_NAMESTORE_ContinuationWithSignature cont,
			      void *cont_cls)
{
  struct GNUNET_NAMESTORE_QueueEntry *qe;
  qe = GNUNET_malloc(sizeof (struct GNUNET_NAMESTORE_QueueEntry));
  return qe;
}

/**
 * Store part of a signature B-tree in the namestore.  This function
 * is used by non-authorities to cache parts of a zone's signature tree.
 * Note that the tree must be build top-down.  This function must check
 * that the nodes being added are valid, and if not refuse the operation.
 *
 * @param h handle to the namestore
 * @param zone_key public key of the zone
 * @param loc location in the B-tree
 * @param ploc parent's location in the B-tree (must have depth = loc.depth - 1), NULL for root
 * @param top_sig signature at the top, NULL if 'loc.depth > 0'
 * @param num_entries number of entries at this node in the B-tree
 * @param entries the 'num_entries' entries to store (hashes over the
 *                records)
 * @param cont continuation to call when done
 * @param cont_cls closure for cont
 * @return handle to abort the request
 */
struct GNUNET_NAMESTORE_QueueEntry *
GNUNET_NAMESTORE_stree_put (struct GNUNET_NAMESTORE_Handle *h,
			    const struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded *zone_key,
			    const struct GNUNET_NAMESTORE_SignatureLocation *loc,
			    const struct GNUNET_NAMESTORE_SignatureLocation *ploc,
			    const struct GNUNET_CRYPTO_RsaSignature *sig,
			    unsigned int num_entries,
			    const GNUNET_HashCode *entries,
			    GNUNET_NAMESTORE_ContinuationWithStatus cont,
			    void *cont_cls)
{
  struct GNUNET_NAMESTORE_QueueEntry *qe;
  qe = GNUNET_malloc(sizeof (struct GNUNET_NAMESTORE_QueueEntry));
  return qe;
}

/**
 * Store an item in the namestore.  If the item is already present,
 * the expiration time is updated to the max of the existing time and
 * the new time.  The operation must fail if there is no matching
 * entry in the signature tree.
 *
 * @param h handle to the namestore
 * @param zone hash of the public key of the zone
 * @param name name that is being mapped (at most 255 characters long)
 * @param record_type type of the record (A, AAAA, PKEY, etc.)
 * @param expiration expiration time for the content
 * @param flags flags for the content
 * @param sig_loc where is the information about the signature for this record stored?
 * @param data_size number of bytes in data
 * @param data value, semantics depend on 'record_type' (see RFCs for DNS and 
 *             GNS specification for GNS extensions)
 * @param cont continuation to call when done
 * @param cont_cls closure for cont
 * @return handle to abort the request
 */
struct GNUNET_NAMESTORE_QueueEntry *
GNUNET_NAMESTORE_record_put (struct GNUNET_NAMESTORE_Handle *h,
			     const GNUNET_HashCode *zone,
			     const char *name,
			     uint32_t record_type,
			     struct GNUNET_TIME_Absolute expiration,
			     enum GNUNET_NAMESTORE_RecordFlags flags,
			     const struct GNUNET_NAMESTORE_SignatureLocation *sig_loc,
			     size_t data_size,
			     const void *data, 
			     GNUNET_NAMESTORE_ContinuationWithStatus cont,
			     void *cont_cls)
{
  struct GNUNET_NAMESTORE_QueueEntry *qe;
  qe = GNUNET_malloc(sizeof (struct GNUNET_NAMESTORE_QueueEntry));

  struct GNUNET_NAMESTORE_SimpleRecord *sr;
  sr = GNUNET_malloc(sizeof(struct GNUNET_NAMESTORE_SimpleRecord));
  sr->name = name;
  sr->record_type = record_type;
  sr->expiration = expiration;
  sr->flags = flags;
  sr->data_size = data_size;
  sr->data = data;
  GNUNET_CONTAINER_DLL_insert(h->records_head, h->records_tail, sr);
  return qe;
}

/**
 * Explicitly remove some content from the database.  The
 * "cont"inuation will be called with status "GNUNET_OK" if content
 * was removed, "GNUNET_NO" if no matching entry was found and
 * "GNUNET_SYSERR" on all other types of errors.
 *
 * @param h handle to the namestore
 * @param zone hash of the public key of the zone
 * @param name name that is being mapped (at most 255 characters long)
 * @param record_type type of the record (A, AAAA, PKEY, etc.)
 * @param size number of bytes in data
 * @param data content stored
 * @param cont continuation to call when done
 * @param cont_cls closure for cont
 * @return handle to abort the request
 */
struct GNUNET_NAMESTORE_QueueEntry *
GNUNET_NAMESTORE_record_remove (struct GNUNET_NAMESTORE_Handle *h,
				const GNUNET_HashCode *zone, 
				const char *name,
				uint32_t record_type,
				size_t size,
				const void *data, 
				GNUNET_NAMESTORE_ContinuationWithStatus cont,
				void *cont_cls)
{
  struct GNUNET_NAMESTORE_QueueEntry *qe;
  qe = GNUNET_malloc(sizeof (struct GNUNET_NAMESTORE_QueueEntry));
  
  struct GNUNET_NAMESTORE_SimpleRecord *iter;
  for (iter=h->records_head; iter != NULL; iter=iter->next)
  {
    if (strcmp ( iter->name, name ) &&
        iter->record_type == record_type &&
        GNUNET_CRYPTO_hash_cmp (iter->zone, zone))
      break;
  }
  if (iter)
    GNUNET_CONTAINER_DLL_remove(h->records_head,
                                h->records_tail,
                                iter);
  
  return qe;
}

/**
 * Get a result for a particular key from the namestore.  The processor
 * will only be called once.
 *
 * @param h handle to the namestore
 * @param zone zone to look up a record from
 * @param name name to look up
 * @param record_type desired record type
 * @param proc function to call on each matching value;
 *        will be called once with a NULL value at the end
 * @param proc_cls closure for proc
 * @return a handle that can be used to
 *         cancel
 */
struct GNUNET_NAMESTORE_QueueEntry *
GNUNET_NAMESTORE_lookup_name (struct GNUNET_NAMESTORE_Handle *h, 
			      const GNUNET_HashCode *zone,
			      const char *name,
			      uint32_t record_type,
			      GNUNET_NAMESTORE_RecordProcessor proc, void *proc_cls)
{
  struct GNUNET_NAMESTORE_QueueEntry *qe;
  qe = GNUNET_malloc(sizeof (struct GNUNET_NAMESTORE_QueueEntry));

  struct GNUNET_NAMESTORE_SimpleRecord *iter;
  for (iter=h->records_head; iter != NULL; iter=iter->next)
  {
    proc(proc_cls, iter->zone, iter->name, iter->record_type,
       iter->expiration,
       iter->flags,
       NULL /*sig loc*/,
       iter->data_size /*size*/,
       iter->data /* data */);
  }
  proc(proc_cls, zone, name, record_type,
       GNUNET_TIME_absolute_get_forever(), 0, NULL, 0, NULL); /*TERMINATE*/

  return qe;
}


/**
 * Get the hash of a record (what will be signed in the Stree for
 * the record).
 *
 * @param zone hash of the public key of the zone
 * @param name name that is being mapped (at most 255 characters long)
 * @param record_type type of the record (A, AAAA, PKEY, etc.)
 * @param expiration expiration time for the content
 * @param flags flags for the content
 * @param data_size number of bytes in data
 * @param data value, semantics depend on 'record_type' (see RFCs for DNS and.
 *             GNS specification for GNS extensions)
 * @param record_hash hash of the record (set)
 */
void
GNUNET_NAMESTORE_record_hash (struct GNUNET_NAMESTORE_Handle *h,
                              const GNUNET_HashCode *zone,
                              const char *name,
                              uint32_t record_type,
                              struct GNUNET_TIME_Absolute expiration,
                              enum GNUNET_NAMESTORE_RecordFlags flags,
                              size_t data_size,
                              const void *data,
                              GNUNET_HashCode *record_hash)
{
  char* teststring = "namestore-stub";
  GNUNET_CRYPTO_hash(teststring, strlen(teststring), record_hash);
}

/**
 * Obtain part of a signature B-tree.  The processor
 * will only be called once.
 *
 * @param h handle to the namestore
 * @param zone zone to look up a record from
 * @param sig_loc location to look up
 * @param proc function to call on each matching value;
 *        will be called once with a NULL value at the end
 * @param proc_cls closure for proc
 * @return a handle that can be used to
 *         cancel
 */
struct GNUNET_NAMESTORE_QueueEntry *
GNUNET_NAMESTORE_lookup_stree (struct GNUNET_NAMESTORE_Handle *h,
                      const GNUNET_HashCode *zone,
                      const struct GNUNET_NAMESTORE_SignatureLocation *sig_loc,
                      GNUNET_NAMESTORE_StreeProcessor proc, void *proc_cls)
{
  struct GNUNET_NAMESTORE_QueueEntry *qe;
  qe = GNUNET_malloc(sizeof (struct GNUNET_NAMESTORE_QueueEntry));
  return qe;
}


/**
 * Get all records of a zone.
 *
 * @param h handle to the namestore
 * @param zone zone to access
 * @param proc function to call on a random value; it
 *        will be called repeatedly with a value (if available)
 *        and always once at the end with a zone and name of NULL.
 * @param proc_cls closure for proc
 * @return a handle that can be used to
 *         cancel
 */
struct GNUNET_NAMESTORE_QueueEntry *
GNUNET_NAMESTORE_zone_transfer (struct GNUNET_NAMESTORE_Handle *h,
                                const GNUNET_HashCode *zone,
                                GNUNET_NAMESTORE_RecordProcessor proc,
                                void *proc_cls)
{
  struct GNUNET_NAMESTORE_QueueEntry *qe;
  qe = GNUNET_malloc(sizeof (struct GNUNET_NAMESTORE_QueueEntry));
  return qe;
}




/**
 * Cancel a namestore operation.  The final callback from the
 * operation must not have been done yet.
 *
 * @param qe operation to cancel
 */
void
GNUNET_NAMESTORE_cancel (struct GNUNET_NAMESTORE_QueueEntry *qe)
{
  if (qe)
    GNUNET_free(qe);
}




/* end of namestore_stub_api.c */

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

  uint32_t locked;

};

struct GNUNET_NAMESTORE_ZoneIterator
{
  struct GNUNET_NAMESTORE_Handle *handle;
  GNUNET_NAMESTORE_RecordProcessor proc;
  void* proc_cls;
  const GNUNET_HashCode * zone;
  uint32_t no_flags;
  uint32_t flags;
  struct GNUNET_NAMESTORE_Handle *h;
  struct GNUNET_NAMESTORE_SimpleRecord *sr;
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
  const struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded *zone_key;
  uint32_t rd_count;
  struct GNUNET_NAMESTORE_RecordData rd[100];
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
  handle->records_head = NULL;
  handle->records_tail = NULL;
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
 * @param data_size number of bytes in data
 * @param data value, semantics depend on 'record_type' (see RFCs for DNS and 
 *             GNS specification for GNS extensions)
 * @param cont continuation to call when done
 * @param cont_cls closure for cont
 * @return handle to abort the request
 */
struct GNUNET_NAMESTORE_QueueEntry *
GNUNET_NAMESTORE_record_put (struct GNUNET_NAMESTORE_Handle *h,
           const struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded *public_key,
			     const char *name,
			     struct GNUNET_TIME_Absolute expiration,
			     unsigned int rd_count,
           const struct GNUNET_NAMESTORE_RecordData *rd,
           const struct GNUNET_CRYPTO_RsaSignature *signature,
           GNUNET_NAMESTORE_ContinuationWithStatus cont,
			     void *cont_cls)
{
  struct GNUNET_NAMESTORE_QueueEntry *qe;
  qe = GNUNET_malloc(sizeof (struct GNUNET_NAMESTORE_QueueEntry));
  struct GNUNET_NAMESTORE_SimpleRecord* sr;
  GNUNET_HashCode *zone;
  int i;

  zone = GNUNET_malloc(sizeof(GNUNET_HashCode));
  GNUNET_CRYPTO_hash(public_key,
                     sizeof(struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded),
                     zone);

  sr = h->records_head;
  for (; sr != NULL; sr = sr->next)
  {
    if (GNUNET_CRYPTO_hash_cmp(zone, sr->zone) == 0)
    {
      sr->rd_count = rd_count;
      for (i=0; i<rd_count; i++)
      {
        sr->rd[i] = rd[i];
      }
      //Expiration, Signature etc
      return qe;
    }
  }
  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "new records for %s\n", name);
  // Not present
  sr = GNUNET_malloc(sizeof (struct GNUNET_NAMESTORE_SimpleRecord));
  sr->rd_count = rd_count;
  sr->name = GNUNET_malloc(strlen(name));
  sr->zone = zone;
  sr->zone_key = public_key; //pkey FIXME;
  sr->next = NULL;
  sr->prev = NULL;
  strcpy((char*)sr->name, name);
  
  for (i=0; i<rd_count; i++)
    sr->rd[i] = rd[i];
  
  if (h->records_head == NULL && h->records_tail == NULL)
  {
    h->records_head = sr;
    h->records_tail = sr;
  }
  else
  {
    GNUNET_CONTAINER_DLL_insert(h->records_head, h->records_tail, sr);
  }

  return qe;
}

int
GNUNET_NAMESTORE_verify_signature (const struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded *public_key,
                                   const char *name,
                                   unsigned int rd_count,
                                   const struct GNUNET_NAMESTORE_RecordData *rd,
                                   const struct GNUNET_CRYPTO_RsaSignature *signature)
{
  return GNUNET_OK;
}

struct GNUNET_NAMESTORE_QueueEntry *
GNUNET_NAMESTORE_record_create (struct GNUNET_NAMESTORE_Handle *h,
			     const struct GNUNET_CRYPTO_RsaPrivateKey *key,
			     const char *name,
           const struct GNUNET_NAMESTORE_RecordData *rd,
           GNUNET_NAMESTORE_ContinuationWithStatus cont,
			     void *cont_cls)
{
  struct GNUNET_NAMESTORE_QueueEntry *qe;
  qe = GNUNET_malloc(sizeof (struct GNUNET_NAMESTORE_QueueEntry));
  struct GNUNET_NAMESTORE_SimpleRecord* sr;

  GNUNET_HashCode *zone_hash;
  
  //memleakage.. but only stub so w/e
  struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded *pkey;
  pkey = GNUNET_malloc(sizeof(struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded));
  GNUNET_CRYPTO_rsa_key_get_public (key, pkey);

  zone_hash = GNUNET_malloc(sizeof(GNUNET_HashCode));

  GNUNET_CRYPTO_hash(pkey, sizeof(struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded),
                     zone_hash);
  
  sr = h->records_head;
  for (; sr != NULL; sr = sr->next)
  {
    if ((strcmp(sr->name, name) == 0) &&
        (0 == GNUNET_CRYPTO_hash_cmp(sr->zone, zone_hash)))
    {
      //Dangerous
      memcpy (&(sr->rd[sr->rd_count-1]), rd,
              sizeof(struct GNUNET_NAMESTORE_RecordData));

      sr->rd_count++;
      return qe;
    }
  }
      
  sr = GNUNET_malloc(sizeof (struct GNUNET_NAMESTORE_SimpleRecord));
  
  sr->rd_count = 1;
  sr->name = GNUNET_malloc(strlen(name));
  sr->zone = zone_hash;
  sr->zone_key = pkey;
  sr->next = NULL;
  sr->prev = NULL;
  strcpy((char*)sr->name, name);

  memcpy (&(sr->rd), rd,
          sizeof(struct GNUNET_NAMESTORE_RecordData));
  if (h->records_head == NULL && h->records_tail == NULL)
  {
    h->records_head = sr;
    h->records_tail = sr;
  }
  else
  {
    GNUNET_CONTAINER_DLL_insert(h->records_head, h->records_tail, sr);
  }

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
				const struct GNUNET_CRYPTO_RsaPrivateKey *pkey,
				const char *name,
				const struct GNUNET_NAMESTORE_RecordData *rd,
        GNUNET_NAMESTORE_ContinuationWithStatus cont,
				void *cont_cls)
{
  struct GNUNET_NAMESTORE_QueueEntry *qe;
  qe = GNUNET_malloc(sizeof (struct GNUNET_NAMESTORE_QueueEntry));
  
  //FIXME
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
GNUNET_NAMESTORE_lookup_record (struct GNUNET_NAMESTORE_Handle *h, 
			      const GNUNET_HashCode *zone,
			      const char *name,
			      uint32_t record_type,
			      GNUNET_NAMESTORE_RecordProcessor proc, void *proc_cls)
{
  struct GNUNET_NAMESTORE_QueueEntry *qe;
  qe = GNUNET_malloc(sizeof (struct GNUNET_NAMESTORE_QueueEntry));
  struct GNUNET_NAMESTORE_SimpleRecord *sr;
  struct GNUNET_CRYPTO_HashAsciiEncoded zone_string, zone_string_ex;
  
  GNUNET_CRYPTO_hash_to_enc (zone, &zone_string);
  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "Looking up %s in %s\n", name, (char*)&zone_string);
  sr = h->records_head;
  for (; sr != NULL; sr = sr->next)
  {
    GNUNET_CRYPTO_hash_to_enc (sr->zone, &zone_string_ex);
    if ((strcmp(sr->name, name) == 0) &&
        (0 == (GNUNET_CRYPTO_hash_cmp(sr->zone, zone))))
    {
      GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
                 "Found match for %s in %s with %d entries\n",
                 sr->name, (char*)&zone_string_ex, sr->rd_count);
      //Simply always return all records
      proc(proc_cls, sr->zone_key, GNUNET_TIME_UNIT_FOREVER_ABS, //FIXME
           name, sr->rd_count, sr->rd, NULL);
      return qe;
    }
    GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "No match\n");
  }
  proc(proc_cls, NULL, GNUNET_TIME_UNIT_ZERO_ABS, name, 0, NULL, NULL);
  //FIXME
  return qe;
}

struct GNUNET_NAMESTORE_ZoneIterator *
GNUNET_NAMESTORE_zone_iteration_start(struct GNUNET_NAMESTORE_Handle *h,
                                      const GNUNET_HashCode *zone,
                                      enum GNUNET_NAMESTORE_RecordFlags must_have_flags,
                                      enum GNUNET_NAMESTORE_RecordFlags must_not_have_flags,
                                      GNUNET_NAMESTORE_RecordProcessor proc,
                                      void *proc_cls)
{
  struct GNUNET_NAMESTORE_ZoneIterator *it;
  h->locked = 1;
  it = GNUNET_malloc(sizeof(struct GNUNET_NAMESTORE_ZoneIterator));
  it->h = h;
  it->sr = h->records_head;
  it->proc = proc;
  it->proc_cls = proc_cls;
  it->zone = zone;
  it->no_flags = must_not_have_flags;
  it->flags = must_have_flags;
  GNUNET_NAMESTORE_zone_iterator_next(it);
  return it;
}

void
GNUNET_NAMESTORE_zone_iterator_next(struct GNUNET_NAMESTORE_ZoneIterator *it)
{
  
  if (it->h->locked == 0)
    return;
  if (it->sr == NULL)
  {
    it->proc(it->proc_cls, NULL, GNUNET_TIME_UNIT_ZERO_ABS,
             NULL, 0, NULL, NULL);
    return;
  }
  if (GNUNET_CRYPTO_hash_cmp(it->sr->zone, it->zone) == 0)
  {
    //Simply always return all records
    //check flags
    it->proc(it->proc_cls, it->sr->zone_key, GNUNET_TIME_UNIT_FOREVER_ABS,
         it->sr->name, it->sr->rd_count, it->sr->rd, NULL);
  }
  it->sr = it->sr->next;
}

void
GNUNET_NAMESTORE_zone_iteration_stop(struct GNUNET_NAMESTORE_ZoneIterator *it)
{
  //it->h->locked = 0;
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

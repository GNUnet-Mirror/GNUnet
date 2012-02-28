/*
     This file is part of GNUnet
     (C) 2010 Christian Grothoff (and other contributing authors)

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
 * @file gns/plugin_block_gns.c
 * @brief blocks used for GNS records
 * @author Martin Schanzenbach
 */

#include "platform.h"
#include "gnunet_block_plugin.h"
#include "gnunet_namestore_service.h"
#include "block_gns.h"
#include "gnunet_signatures.h"

/**
 * Number of bits we set per entry in the bloomfilter.
 * Do not change! -from fs
 */
#define BLOOMFILTER_K 16

/**
 * Function called to validate a reply or a request.  For
 * request evaluation, simply pass "NULL" for the reply_block.
 * Note that it is assumed that the reply has already been
 * matched to the key (and signatures checked) as it would
 * be done with the "get_key" function.
 *
 * @param cls closure
 * @param type block type
 * @param query original query (hash)
 * @param bf pointer to bloom filter associated with query; possibly updated (!)
 * @param bf_mutator mutation value for bf
 * @param xquery extrended query data (can be NULL, depending on type)
 * @param xquery_size number of bytes in xquery
 * @param reply_block response to validate
 * @param reply_block_size number of bytes in reply block
 * @return characterization of result
 */
static enum GNUNET_BLOCK_EvaluationResult
block_plugin_gns_evaluate (void *cls, enum GNUNET_BLOCK_Type type,
                          const GNUNET_HashCode * query,
                          struct GNUNET_CONTAINER_BloomFilter **bf,
                          int32_t bf_mutator, const void *xquery,
                          size_t xquery_size, const void *reply_block,
                          size_t reply_block_size)
{
  if (type != GNUNET_BLOCK_TYPE_GNS_NAMERECORD)
    return GNUNET_BLOCK_EVALUATION_TYPE_NOT_SUPPORTED;
  if (reply_block_size == 0)
    return GNUNET_BLOCK_EVALUATION_REQUEST_VALID;
  
  char* name;
  GNUNET_HashCode pkey_hash;
  GNUNET_HashCode query_key;
  GNUNET_HashCode name_hash;
  GNUNET_HashCode mhash;
  GNUNET_HashCode chash;
  struct GNSNameRecordBlock *nrb;
  struct GNSRecordBlock *rb;
  uint32_t rd_count;
  
  nrb = (struct GNSNameRecordBlock *)reply_block;
  name = (char*)&nrb[1];
  GNUNET_CRYPTO_hash(&nrb->public_key,
                     sizeof(nrb->public_key),
                     &pkey_hash);

  GNUNET_CRYPTO_hash(name, strlen(name), &name_hash);

  GNUNET_CRYPTO_hash_xor(&pkey_hash, &name_hash, &query_key);
  
  /* Check query key against public key */
  if (0 != GNUNET_CRYPTO_hash_cmp(query, &query_key))
    return GNUNET_BLOCK_EVALUATION_REQUEST_VALID;
  
  rd_count = ntohl(nrb->rd_count);

  struct GNUNET_NAMESTORE_RecordData rd[rd_count];
  int i = 0;
  int record_match = 0;
  uint32_t record_xquery = ntohl(*((uint32_t*)xquery));
  rb = (struct GNSRecordBlock*)(&name[strlen(name) + 1]);

  for (i=0; i<rd_count; i++)
  {
    rd[i].record_type = ntohl(rb->type);
    rd[i].expiration =
      GNUNET_TIME_absolute_ntoh(rb->expiration);
    rd[i].data_size = ntohl(rb->data_length);
    rd[i].flags = ntohl(rb->flags);
    rd[i].data = (char*)&rb[1];
    rb = (struct GNSRecordBlock *)((char*)&rb[1] + rd[i].data_size);
    
    if (xquery_size == 0)
     continue;
    
    if (rd[i].record_type == record_xquery)
    {
      record_match++;
    }
  }
  

  /*if (GNUNET_OK != GNUNET_NAMESTORE_verify_signature (&nrb->public_key,
                                                      name,
                                                      rd_count,
                                                      rd,
                                                      NULL))
  {
    GNUNET_log(GNUNET_ERROR_TYPE_INFO, "Signature invalid\n");
    return GNUNET_BLOCK_EVALUATION_REQUEST_INVALID;
  }*/
  
  //No record matches query
  if ((xquery_size > 0) && (record_match == 0))
    return GNUNET_BLOCK_EVALUATION_REQUEST_VALID;

  GNUNET_log(GNUNET_ERROR_TYPE_INFO, "Records match\n");
  //FIXME do bf check before or after crypto??
  if (NULL != bf)
  {
    GNUNET_CRYPTO_hash(reply_block, reply_block_size, &chash);
    GNUNET_BLOCK_mingle_hash(&chash, bf_mutator, &mhash);
    if (NULL != *bf)
    {
      GNUNET_log(GNUNET_ERROR_TYPE_INFO, "Check BF\n");
      if (GNUNET_YES == GNUNET_CONTAINER_bloomfilter_test(*bf, &mhash))
        return GNUNET_BLOCK_EVALUATION_OK_DUPLICATE;
    }
    else
    {
      *bf = GNUNET_CONTAINER_bloomfilter_init(NULL, 8, BLOOMFILTER_K);
    }
    GNUNET_CONTAINER_bloomfilter_add(*bf, &mhash);
  }
  GNUNET_log(GNUNET_ERROR_TYPE_INFO, "No dup\n");
  return GNUNET_BLOCK_EVALUATION_OK_MORE;
}


/**
 * Function called to obtain the key for a block.
 *
 * @param cls closure
 * @param type block type
 * @param block block to get the key for
 * @param block_size number of bytes in block
 * @param key set to the key (query) for the given block
 * @return GNUNET_OK on success, GNUNET_SYSERR if type not supported
 *         (or if extracting a key from a block of this type does not work)
 */
static int
block_plugin_gns_get_key (void *cls, enum GNUNET_BLOCK_Type type,
                         const void *block, size_t block_size,
                         GNUNET_HashCode * key)
{
  if (type != GNUNET_BLOCK_TYPE_GNS_NAMERECORD)
    return GNUNET_SYSERR;
  GNUNET_HashCode name_hash;
  GNUNET_HashCode pkey_hash;
  struct GNSNameRecordBlock *nrb = (struct GNSNameRecordBlock *)block;

  GNUNET_CRYPTO_hash(&nrb[1], strlen((char*)&nrb[1]), &name_hash);
  GNUNET_CRYPTO_hash(&nrb->public_key,
                     sizeof(struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded),
                     &pkey_hash);

  GNUNET_CRYPTO_hash_xor(&name_hash, &pkey_hash, key);
  
  //FIXME calculate key from name and hash(pkey) here
  return GNUNET_OK;
}


/**
 * Entry point for the plugin.
 */
void *
libgnunet_plugin_block_gns_init (void *cls)
{
  static enum GNUNET_BLOCK_Type types[] =
  {
    GNUNET_BLOCK_TYPE_GNS_NAMERECORD,
    GNUNET_BLOCK_TYPE_ANY       /* end of list */
  };
  struct GNUNET_BLOCK_PluginFunctions *api;

  api = GNUNET_malloc (sizeof (struct GNUNET_BLOCK_PluginFunctions));
  api->evaluate = &block_plugin_gns_evaluate;
  api->get_key = &block_plugin_gns_get_key;
  api->types = types;
  return api;
}


/**
 * Exit point from the plugin.
 */
void *
libgnunet_plugin_block_gns_done (void *cls)
{
  struct GNUNET_TRANSPORT_PluginFunctions *api = cls;

  GNUNET_free (api);
  return NULL;
}

/* end of plugin_block_gns.c */

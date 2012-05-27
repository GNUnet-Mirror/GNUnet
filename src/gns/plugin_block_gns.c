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
  char* name;
  GNUNET_HashCode pkey_hash_double;
  GNUNET_HashCode query_key;
  GNUNET_HashCode name_hash_double;
  GNUNET_HashCode mhash;
  GNUNET_HashCode chash;
  struct GNUNET_CRYPTO_ShortHashCode pkey_hash;
  struct GNUNET_CRYPTO_ShortHashCode name_hash;
  struct GNSNameRecordBlock *nrb;
  uint32_t rd_count;
  char* rd_data = NULL;
  int rd_len;
  uint32_t record_xquery;
  unsigned int record_match;
  
  //GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "RB SIZE %d\n", reply_block_size);

  if (type != GNUNET_BLOCK_TYPE_GNS_NAMERECORD)
    return GNUNET_BLOCK_EVALUATION_TYPE_NOT_SUPPORTED;
  if (reply_block == NULL)
  {
    /**
     *  check if request is valid
     *  FIXME we could check for the record types here
     **/
    if (xquery_size < sizeof(uint32_t))
    {
      GNUNET_break_op (0);
      return GNUNET_BLOCK_EVALUATION_REQUEST_INVALID;
    }
    return GNUNET_BLOCK_EVALUATION_REQUEST_VALID;
  }
  
  /* this is a reply */

  nrb = (struct GNSNameRecordBlock *)reply_block;
  name = (char*)&nrb[1];
  GNUNET_CRYPTO_short_hash(&nrb->public_key,
                     sizeof(nrb->public_key),
                     &pkey_hash);

  GNUNET_CRYPTO_short_hash(name, strlen(name), &name_hash);
  
  GNUNET_CRYPTO_short_hash_double(&name_hash, &name_hash_double);
  GNUNET_CRYPTO_short_hash_double(&pkey_hash, &pkey_hash_double);

  GNUNET_CRYPTO_hash_xor(&pkey_hash_double, &name_hash_double, &query_key);
  
  struct GNUNET_CRYPTO_HashAsciiEncoded xor_exp;
  struct GNUNET_CRYPTO_HashAsciiEncoded xor_got;
  GNUNET_CRYPTO_hash_to_enc (&query_key, &xor_exp);
  GNUNET_CRYPTO_hash_to_enc (query, &xor_got);

  //GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
  //           "BLOCK_TEST for %s got %s expected %s\n",
  //           name, (char*) &xor_got, (char*) &xor_exp);

  /* Check query key against public key */
  if (0 != GNUNET_CRYPTO_hash_cmp(query, &query_key))
  {
    GNUNET_break_op (0);
    return GNUNET_BLOCK_EVALUATION_RESULT_INVALID;
  }
  
  record_match = 0;
  rd_count = ntohl(nrb->rd_count);
  rd_data = (char*)&nrb[1];
  rd_data += strlen(name) + 1;
  rd_len = reply_block_size - (strlen(name) + 1
                               + sizeof(struct GNSNameRecordBlock));
  {
    struct GNUNET_NAMESTORE_RecordData rd[rd_count];
    unsigned int i;
    struct GNUNET_TIME_Absolute exp = GNUNET_TIME_UNIT_FOREVER_ABS;
    
    if (GNUNET_SYSERR == GNUNET_NAMESTORE_records_deserialize (rd_len,
                                                               rd_data,
                                                               rd_count,
                                                               rd))
    {
      GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
                 "Data invalid (%d bytes, %d records)\n", rd_len, rd_count);
      GNUNET_break_op (0);
      return GNUNET_BLOCK_EVALUATION_RESULT_INVALID;
    }

    if (xquery_size < sizeof(uint32_t))
      record_xquery = 0;
    else
      record_xquery = ntohl(*((uint32_t*)xquery));
    
    for (i=0; i<rd_count; i++)
    {
      
      exp = GNUNET_TIME_absolute_min (exp, rd[i].expiration);
      
      GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
                 "Got record of size %d\n", rd[i].data_size);

      if ((record_xquery != 0)
          && (rd[i].record_type == record_xquery))
      {
        record_match++;
      }
    }
    
    GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
               "Verifying signature of %d records for name %s\n",
               rd_count, name);

    if (GNUNET_OK != GNUNET_NAMESTORE_verify_signature (&nrb->public_key,
                                                        exp,
                                                        name,
                                                        rd_count,
                                                        rd,
                                                        &nrb->signature))
    {
      GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "Signature invalid for name %s\n");
      GNUNET_break_op (0);
      return GNUNET_BLOCK_EVALUATION_RESULT_INVALID;
    }
  }
  
  if (NULL != bf)
  {
    GNUNET_CRYPTO_hash(reply_block, reply_block_size, &chash);
    GNUNET_BLOCK_mingle_hash(&chash, bf_mutator, &mhash);
    if (NULL != *bf)
    {
      if (GNUNET_YES == GNUNET_CONTAINER_bloomfilter_test(*bf, &mhash))
        return GNUNET_BLOCK_EVALUATION_OK_DUPLICATE;
    }
    else
    {
      *bf = GNUNET_CONTAINER_bloomfilter_init(NULL, 8, BLOOMFILTER_K);
    }
    GNUNET_CONTAINER_bloomfilter_add(*bf, &mhash);
  }
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
  struct GNUNET_CRYPTO_ShortHashCode name_hash;
  struct GNUNET_CRYPTO_ShortHashCode pkey_hash;
  GNUNET_HashCode name_hash_double;
  GNUNET_HashCode pkey_hash_double;

  struct GNSNameRecordBlock *nrb = (struct GNSNameRecordBlock *)block;

  GNUNET_CRYPTO_short_hash(&nrb[1], strlen((char*)&nrb[1]), &name_hash);
  GNUNET_CRYPTO_short_hash(&nrb->public_key,
                     sizeof(struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded),
                     &pkey_hash);
  
  GNUNET_CRYPTO_short_hash_double(&name_hash, &name_hash_double);
  GNUNET_CRYPTO_short_hash_double(&pkey_hash, &pkey_hash_double);

  GNUNET_CRYPTO_hash_xor(&name_hash_double, &pkey_hash_double, key);
  
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

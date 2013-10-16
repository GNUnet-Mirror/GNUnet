/*
     This file is part of GNUnet.
     (C) 2009-2013 Christian Grothoff (and other contributing authors)

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
 * @file namestore/namestore_api_common.c
 * @brief API to access the NAMESTORE service
 * @author Martin Schanzenbach
 * @author Matthias Wachs
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_constants.h"
#include "gnunet_signatures.h"
#include "gnunet_arm_service.h"
#include "gnunet_conversation_service.h"
#include "gnunet_namestore_service.h"
#include "gnunet_dnsparser_lib.h"
#include "gnunet_tun_lib.h"
#include "namestore.h"


#define LOG(kind,...) GNUNET_log_from (kind, "namestore-api",__VA_ARGS__)

GNUNET_NETWORK_STRUCT_BEGIN


/**
 * Internal format of a record in the serialized form.
 */
struct NetworkRecord
{

  /**
   * Expiration time for the DNS record; relative or absolute depends
   * on 'flags', network byte order.
   */
  uint64_t expiration_time GNUNET_PACKED;

  /**
   * Number of bytes in 'data', network byte order.
   */
  uint32_t data_size GNUNET_PACKED;

  /**
   * Type of the GNS/DNS record, network byte order.
   */
  uint32_t record_type GNUNET_PACKED;

  /**
   * Flags for the record, network byte order.
   */
  uint32_t flags GNUNET_PACKED;

};

GNUNET_NETWORK_STRUCT_END

/**
 * Convert a UTF-8 string to UTF-8 lowercase
 * @param src source string
 * @return converted result
 */
char *
GNUNET_NAMESTORE_normalize_string (const char *src)
{
  GNUNET_assert (NULL != src);
  char *res = strdup (src);
  /* normalize */
  GNUNET_STRINGS_utf8_tolower(src, &res);
  return res;
}


/**
 * Convert a zone key to a string (for printing debug messages).
 * This is one of the very few calls in the entire API that is
 * NOT reentrant!
 *
 * @param z the zone key
 * @return string form; will be overwritten by next call to #GNUNET_NAMESTORE_z2s
 */
const char *
GNUNET_NAMESTORE_z2s (const struct GNUNET_CRYPTO_EcdsaPublicKey *z)
{
  static char buf[sizeof (struct GNUNET_CRYPTO_EcdsaPublicKey) * 8];
  char *end;

  end = GNUNET_STRINGS_data_to_string ((const unsigned char *) z,
				       sizeof (struct GNUNET_CRYPTO_EcdsaPublicKey),
				       buf, sizeof (buf));
  if (NULL == end)
  {
    GNUNET_break (0);
    return NULL;
  }
  *end = '\0';
  return buf;
}


/**
 * Calculate how many bytes we will need to serialize the given
 * records.
 *
 * @param rd_count number of records in the rd array
 * @param rd array of #GNUNET_NAMESTORE_RecordData with @a rd_count elements
 * @return the required size to serialize
 */
size_t
GNUNET_NAMESTORE_records_get_size (unsigned int rd_count,
				   const struct GNUNET_NAMESTORE_RecordData *rd)
{
  unsigned int i;
  size_t ret;

  ret = sizeof (struct NetworkRecord) * rd_count;
  for (i=0;i<rd_count;i++)
  {
    GNUNET_assert ((ret + rd[i].data_size) >= ret);
    ret += rd[i].data_size;
  }
  return ret;
}


/**
 * Serialize the given records to the given destination buffer.
 *
 * @param rd_count number of records in the rd array
 * @param rd array of #GNUNET_NAMESTORE_RecordData with @a rd_count elements
 * @param dest_size size of the destination array
 * @param dest where to write the result
 * @return the size of serialized records, -1 if records do not fit
 */
ssize_t
GNUNET_NAMESTORE_records_serialize (unsigned int rd_count,
				    const struct GNUNET_NAMESTORE_RecordData *rd,
				    size_t dest_size,
				    char *dest)
{
  struct NetworkRecord rec;
  unsigned int i;
  size_t off;

  off = 0;
  for (i=0;i<rd_count;i++)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Serializing record %u with flags %d and expiration time %llu\n",
         i,
         rd[i].flags,
         (unsigned long long) rd[i].expiration_time);
    rec.expiration_time = GNUNET_htonll (rd[i].expiration_time);
    rec.data_size = htonl ((uint32_t) rd[i].data_size);
    rec.record_type = htonl (rd[i].record_type);
    rec.flags = htonl (rd[i].flags);
    if (off + sizeof (rec) > dest_size)
      return -1;
    memcpy (&dest[off], &rec, sizeof (rec));
    off += sizeof (rec);
    if (off + rd[i].data_size > dest_size)
      return -1;
    memcpy (&dest[off], rd[i].data, rd[i].data_size);
    off += rd[i].data_size;
  }
  return off;
}


/**
 * Compares if two records are equal (ignoring flags such
 * as authority, private and pending, but not relative vs.
 * absolute expiration time).
 *
 * @param a record
 * @param b record
 * @return #GNUNET_YES if the records are equal or #GNUNET_NO if they are not
 */
int
GNUNET_NAMESTORE_records_cmp (const struct GNUNET_NAMESTORE_RecordData *a,
                              const struct GNUNET_NAMESTORE_RecordData *b)
{
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Comparing records\n");
  if (a->record_type != b->record_type)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Record type %lu != %lu\n", a->record_type, b->record_type);
    return GNUNET_NO;
  }
  if ((a->expiration_time != b->expiration_time) &&
      ((a->expiration_time != 0) && (b->expiration_time != 0)))
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Expiration time %llu != %llu\n",
         a->expiration_time,
         b->expiration_time);
    return GNUNET_NO;
  }
  if ((a->flags & GNUNET_NAMESTORE_RF_RCMP_FLAGS)
       != (b->flags & GNUNET_NAMESTORE_RF_RCMP_FLAGS))
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Flags %lu (%lu) != %lu (%lu)\n", a->flags,
         a->flags & GNUNET_NAMESTORE_RF_RCMP_FLAGS, b->flags,
         b->flags & GNUNET_NAMESTORE_RF_RCMP_FLAGS);
    return GNUNET_NO;
  }
  if (a->data_size != b->data_size)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Data size %lu != %lu\n",
         a->data_size,
         b->data_size);
    return GNUNET_NO;
  }
  if (0 != memcmp (a->data, b->data, a->data_size))
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Data contents do not match\n");
    return GNUNET_NO;
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Records are equal\n");
  return GNUNET_YES;
}


/**
 * Deserialize the given records to the given destination.
 *
 * @param len size of the serialized record data
 * @param src the serialized record data
 * @param rd_count number of records in the rd array
 * @param dest where to put the data
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on error
 */
int
GNUNET_NAMESTORE_records_deserialize (size_t len,
				      const char *src,
				      unsigned int rd_count,
				      struct GNUNET_NAMESTORE_RecordData *dest)
{
  struct NetworkRecord rec;
  unsigned int i;
  size_t off;

  off = 0;
  for (i=0;i<rd_count;i++)
  {
    if (off + sizeof (rec) > len)
      return GNUNET_SYSERR;
    memcpy (&rec, &src[off], sizeof (rec));
    dest[i].expiration_time = GNUNET_ntohll (rec.expiration_time);
    dest[i].data_size = ntohl ((uint32_t) rec.data_size);
    dest[i].record_type = ntohl (rec.record_type);
    dest[i].flags = ntohl (rec.flags);
    off += sizeof (rec);
    if (off + dest[i].data_size > len)
      return GNUNET_SYSERR;
    dest[i].data = &src[off];
    off += dest[i].data_size;
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Deserialized record %u with flags %d and expiration time %llu\n",
         i,
         dest[i].flags,
         (unsigned long long) dest[i].expiration_time);
  }
  return GNUNET_OK;
}


/**
 * Returns the expiration time of the given block of records. The block
 * expiration time is the expiration time of the record with smallest
 * expiration time.
 *
 * @param rd_count number of records given in @a rd
 * @param rd array of records
 * @return absolute expiration time
 */
struct GNUNET_TIME_Absolute
GNUNET_NAMESTORE_record_get_expiration_time (unsigned int rd_count,
					     const struct GNUNET_NAMESTORE_RecordData *rd)
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
      rt.rel_value_us = rd[c].expiration_time;
      at = GNUNET_TIME_relative_to_absolute (rt);
    }
    else
    {
      at.abs_value_us = rd[c].expiration_time;
    }
    expire = GNUNET_TIME_absolute_min (at, expire);
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Determined expiration time for block with %u records to be %s\n",
       rd_count,
       GNUNET_STRINGS_absolute_time_to_string (expire));
  return expire;
}


/**
 * Derive session key and iv from label and public key.
 *
 * @param iv initialization vector to initialize
 * @param skey session key to initialize
 * @param label label to use for KDF
 * @param pub public key to use for KDF
 */
static void
derive_block_aes_key (struct GNUNET_CRYPTO_SymmetricInitializationVector *iv,
		      struct GNUNET_CRYPTO_SymmetricSessionKey *skey,
		      const char *label,
		      const struct GNUNET_CRYPTO_EcdsaPublicKey *pub)
{
  static const char ctx_key[] = "gns-aes-ctx-key";
  static const char ctx_iv[] = "gns-aes-ctx-iv";

  GNUNET_CRYPTO_kdf (skey, sizeof (struct GNUNET_CRYPTO_SymmetricSessionKey),
		     pub, sizeof (struct GNUNET_CRYPTO_EcdsaPublicKey),
		     label, strlen (label),
		     ctx_key, strlen (ctx_key),
		     NULL, 0);
  GNUNET_CRYPTO_kdf (iv, sizeof (struct GNUNET_CRYPTO_SymmetricInitializationVector),
		     pub, sizeof (struct GNUNET_CRYPTO_EcdsaPublicKey),
		     label, strlen (label),
		     ctx_iv, strlen (ctx_iv),
		     NULL, 0);
}


/**
 * Sign name and records
 *
 * @param key the private key
 * @param expire block expiration
 * @param label the name for the records
 * @param rd record data
 * @param rd_count number of records
 * @return NULL on error (block too large)
 */
struct GNUNET_NAMESTORE_Block *
GNUNET_NAMESTORE_block_create (const struct GNUNET_CRYPTO_EcdsaPrivateKey *key,
			       struct GNUNET_TIME_Absolute expire,
			       const char *label,
			       const struct GNUNET_NAMESTORE_RecordData *rd,
			       unsigned int rd_count)
{
  size_t payload_len = GNUNET_NAMESTORE_records_get_size (rd_count, rd);
  char payload[sizeof (uint32_t) + payload_len];
  struct GNUNET_NAMESTORE_Block *block;
  struct GNUNET_CRYPTO_EcdsaPublicKey pkey;
  struct GNUNET_CRYPTO_EcdsaPrivateKey *dkey;
  struct GNUNET_CRYPTO_SymmetricInitializationVector iv;
  struct GNUNET_CRYPTO_SymmetricSessionKey skey;
  uint32_t rd_count_nbo;

  if (payload_len > GNUNET_NAMESTORE_MAX_VALUE_SIZE)
    return NULL;
  rd_count_nbo = htonl (rd_count);
  memcpy (payload, &rd_count_nbo, sizeof (uint32_t));
  GNUNET_assert (payload_len ==
		 GNUNET_NAMESTORE_records_serialize (rd_count, rd,
						     payload_len, &payload[sizeof (uint32_t)]));
  block = GNUNET_malloc (sizeof (struct GNUNET_NAMESTORE_Block) +
			 sizeof (uint32_t) + payload_len);
  block->purpose.size = htonl (sizeof (uint32_t) + payload_len +
			       sizeof (struct GNUNET_CRYPTO_EccSignaturePurpose) +
			       sizeof (struct GNUNET_TIME_AbsoluteNBO));
  block->purpose.purpose = htonl (GNUNET_SIGNATURE_PURPOSE_GNS_RECORD_SIGN);
  block->expiration_time = GNUNET_TIME_absolute_hton (expire);
  dkey = GNUNET_CRYPTO_ecdsa_private_key_derive (key,
				       label,
				       "gns");
  GNUNET_CRYPTO_ecdsa_key_get_public (dkey,
				    &block->derived_key);
  GNUNET_CRYPTO_ecdsa_key_get_public (key,
				    &pkey);
  derive_block_aes_key (&iv, &skey, label, &pkey);
  GNUNET_break (payload_len + sizeof (uint32_t) ==
		GNUNET_CRYPTO_symmetric_encrypt (payload, payload_len + sizeof (uint32_t),
					   &skey, &iv,
					   &block[1]));
  if (GNUNET_OK !=
      GNUNET_CRYPTO_ecdsa_sign (dkey,
			      &block->purpose,
			      &block->signature))
  {
    GNUNET_break (0);
    GNUNET_free (dkey);
    GNUNET_free (block);
    return NULL;
  }
  GNUNET_free (dkey);
  return block;
}


/**
 * Check if a signature is valid.  This API is used by the GNS Block
 * to validate signatures received from the network.
 *
 * @param block block to verify
 * @return #GNUNET_OK if the signature is valid
 */
int
GNUNET_NAMESTORE_block_verify (const struct GNUNET_NAMESTORE_Block *block)
{
  return GNUNET_CRYPTO_ecdsa_verify (GNUNET_SIGNATURE_PURPOSE_GNS_RECORD_SIGN,
				   &block->purpose,
				   &block->signature,
				   &block->derived_key);
}


/**
 * Decrypt block.
 *
 * @param block block to decrypt
 * @param zone_key public key of the zone
 * @param label the name for the records
 * @param proc function to call with the result
 * @param proc_cls closure for proc
 * @return #GNUNET_OK on success, #GNUNET_SYSERR if the block was
 *        not well-formed
 */
int
GNUNET_NAMESTORE_block_decrypt (const struct GNUNET_NAMESTORE_Block *block,
				const struct GNUNET_CRYPTO_EcdsaPublicKey *zone_key,
				const char *label,
				GNUNET_NAMESTORE_RecordCallback proc,
				void *proc_cls)
{
  size_t payload_len = ntohl (block->purpose.size) -
    sizeof (struct GNUNET_CRYPTO_EccSignaturePurpose) -
    sizeof (struct GNUNET_TIME_AbsoluteNBO);
  struct GNUNET_CRYPTO_SymmetricInitializationVector iv;
  struct GNUNET_CRYPTO_SymmetricSessionKey skey;

  if (ntohl (block->purpose.size) <
      sizeof (struct GNUNET_CRYPTO_EccSignaturePurpose) +
      sizeof (struct GNUNET_TIME_AbsoluteNBO))
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  derive_block_aes_key (&iv, &skey, label, zone_key);
  {
    char payload[payload_len];
    uint32_t rd_count;

    GNUNET_break (payload_len ==
		  GNUNET_CRYPTO_symmetric_decrypt (&block[1], payload_len,
					     &skey, &iv,
					     payload));
    memcpy (&rd_count,
	    payload,
	    sizeof (uint32_t));
    rd_count = ntohl (rd_count);
    if (rd_count > 2048)
    {
      /* limit to sane value */
      GNUNET_break_op (0);
      return GNUNET_SYSERR;
    }
    {
      struct GNUNET_NAMESTORE_RecordData rd[rd_count];

      if (GNUNET_OK !=
	  GNUNET_NAMESTORE_records_deserialize (payload_len - sizeof (uint32_t),
						&payload[sizeof (uint32_t)],
						rd_count,
						rd))
      {
	GNUNET_break_op (0);
	return GNUNET_SYSERR;
      }
      if (NULL != proc)
      	proc (proc_cls, rd_count, (0 != rd_count) ? rd : NULL);
    }
  }
  return GNUNET_OK;
}


/**
 * Test if a given record is expired.
 *
 * @return #GNUNET_YES if the record is expired,
 *         #GNUNET_NO if not
 */
int
GNUNET_NAMESTORE_is_expired (const struct GNUNET_NAMESTORE_RecordData *rd)
{
  struct GNUNET_TIME_Absolute at;

  if (0 != (rd->flags & GNUNET_NAMESTORE_RF_RELATIVE_EXPIRATION))
    return GNUNET_NO;
  at.abs_value_us = rd->expiration_time;
  return (0 == GNUNET_TIME_absolute_get_remaining (at).rel_value_us) ? GNUNET_YES : GNUNET_NO;
}


/**
 * Calculate the DHT query for a given @a label in a given @a zone.
 *
 * @param zone private key of the zone
 * @param label label of the record
 * @param query hash to use for the query
 */
void
GNUNET_NAMESTORE_query_from_private_key (const struct GNUNET_CRYPTO_EcdsaPrivateKey *zone,
					 const char *label,
					 struct GNUNET_HashCode *query)
{
  struct GNUNET_CRYPTO_EcdsaPublicKey pub;

  GNUNET_CRYPTO_ecdsa_key_get_public (zone, &pub);
  GNUNET_NAMESTORE_query_from_public_key (&pub, label, query);
}


/**
 * Calculate the DHT query for a given @a label in a given @a zone.
 *
 * @param pub public key of the zone
 * @param label label of the record
 * @param query hash to use for the query
 */
void
GNUNET_NAMESTORE_query_from_public_key (const struct GNUNET_CRYPTO_EcdsaPublicKey *pub,
					const char *label,
					struct GNUNET_HashCode *query)
{
  struct GNUNET_CRYPTO_EcdsaPublicKey pd;

  GNUNET_CRYPTO_ecdsa_public_key_derive (pub, label, "gns", &pd);
  GNUNET_CRYPTO_hash (&pd, sizeof (pd), query);
}


/**
 * Convert public key to the respective absolute domain name in the
 * ".zkey" pTLD.
 * This is one of the very few calls in the entire API that is
 * NOT reentrant!
 *
 * @param pkey a public key with a point on the eliptic curve
 * @return string "X.zkey" where X is the public
 *         key in an encoding suitable for DNS labels.
 */
const char *
GNUNET_NAMESTORE_pkey_to_zkey (const struct GNUNET_CRYPTO_EcdsaPublicKey *pkey)
{
  static char ret[128];
  char *pkeys;

  pkeys = GNUNET_CRYPTO_ecdsa_public_key_to_string (pkey);
  GNUNET_snprintf (ret,
		   sizeof (ret),
		   "%s.zkey",
		   pkeys);
  GNUNET_free (pkeys);
  return ret;
}


/**
 * Convert an absolute domain name in the ".zkey" pTLD to the
 * respective public key.
 *
 * @param zkey string "X.zkey" where X is the coordinates of the public
 *         key in an encoding suitable for DNS labels.
 * @param pkey set to a public key on the eliptic curve
 * @return #GNUNET_SYSERR if @a zkey has the wrong syntax
 */
int
GNUNET_NAMESTORE_zkey_to_pkey (const char *zkey,
			       struct GNUNET_CRYPTO_EcdsaPublicKey *pkey)
{
  char *cpy;
  char *dot;
  const char *x;

  cpy = GNUNET_strdup (zkey);
  x = cpy;
  if (NULL == (dot = strchr (x, (int) '.')))
    goto error;
  *dot = '\0';
  if (0 != strcasecmp (dot + 1,
		       "zkey"))
    goto error;

  if (GNUNET_OK !=
      GNUNET_CRYPTO_ecdsa_public_key_from_string (x,
						strlen (x),
						pkey))
    goto error;
  GNUNET_free (cpy);
  return GNUNET_OK;
 error:
  GNUNET_free (cpy);
  return GNUNET_SYSERR;
}


/* end of namestore_common.c */

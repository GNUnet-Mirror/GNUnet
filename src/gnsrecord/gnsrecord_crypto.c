/*
     This file is part of GNUnet.
     Copyright (C) 2009-2013, 2018 GNUnet e.V.

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
 * @file gnsrecord/gnsrecord_crypto.c
 * @brief API for GNS record-related crypto
 * @author Martin Schanzenbach
 * @author Matthias Wachs
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_constants.h"
#include "gnunet_signatures.h"
#include "gnunet_arm_service.h"
#include "gnunet_gnsrecord_lib.h"
#include "gnunet_dnsparser_lib.h"
#include "gnunet_tun_lib.h"


#define LOG(kind, ...) GNUNET_log_from (kind, "gnsrecord", __VA_ARGS__)


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

  GNUNET_CRYPTO_kdf (skey, sizeof(struct GNUNET_CRYPTO_SymmetricSessionKey),
                     ctx_key, strlen (ctx_key),
                     pub, sizeof(struct GNUNET_CRYPTO_EcdsaPublicKey),
                     label, strlen (label),
                     NULL, 0);
  GNUNET_CRYPTO_kdf (iv, sizeof(struct
                                GNUNET_CRYPTO_SymmetricInitializationVector),
                     ctx_iv, strlen (ctx_iv),
                     pub, sizeof(struct GNUNET_CRYPTO_EcdsaPublicKey),
                     label, strlen (label),
                     NULL, 0);
}


/**
 * Sign name and records
 *
 * @param key the private key
 * @param pkey associated public key
 * @param expire block expiration
 * @param label the name for the records
 * @param rd record data
 * @param rd_count number of records
 * @return NULL on error (block too large)
 */
static struct GNUNET_GNSRECORD_Block *
block_create (const struct GNUNET_CRYPTO_EcdsaPrivateKey *key,
              const struct GNUNET_CRYPTO_EcdsaPublicKey *pkey,
              struct GNUNET_TIME_Absolute expire,
              const char *label,
              const struct GNUNET_GNSRECORD_Data *rd,
              unsigned int rd_count)
{
  ssize_t payload_len = GNUNET_GNSRECORD_records_get_size (rd_count,
                                                           rd);
  struct GNUNET_GNSRECORD_Block *block;
  struct GNUNET_CRYPTO_EcdsaPrivateKey *dkey;
  struct GNUNET_CRYPTO_SymmetricInitializationVector iv;
  struct GNUNET_CRYPTO_SymmetricSessionKey skey;
  struct GNUNET_GNSRECORD_Data rdc[GNUNET_NZL (rd_count)];
  uint32_t rd_count_nbo;
  struct GNUNET_TIME_Absolute now;

  if (payload_len < 0)
  {
    GNUNET_break (0);
    return NULL;
  }
  if (payload_len > GNUNET_GNSRECORD_MAX_BLOCK_SIZE)
  {
    GNUNET_break (0);
    return NULL;
  }
  /* convert relative to absolute times */
  now = GNUNET_TIME_absolute_get ();
  for (unsigned int i = 0; i < rd_count; i++)
  {
    rdc[i] = rd[i];
    if (0 != (rd[i].flags & GNUNET_GNSRECORD_RF_RELATIVE_EXPIRATION))
    {
      struct GNUNET_TIME_Relative t;

      /* encrypted blocks must never have relative expiration times, convert! */
      rdc[i].flags &= ~GNUNET_GNSRECORD_RF_RELATIVE_EXPIRATION;
      t.rel_value_us = rdc[i].expiration_time;
      rdc[i].expiration_time = GNUNET_TIME_absolute_add (now, t).abs_value_us;
    }
  }
  /* serialize */
  rd_count_nbo = htonl (rd_count);
  {
    char payload[sizeof(uint32_t) + payload_len];

    GNUNET_memcpy (payload,
                   &rd_count_nbo,
                   sizeof(uint32_t));
    GNUNET_assert (payload_len ==
                   GNUNET_GNSRECORD_records_serialize (rd_count,
                                                       rdc,
                                                       payload_len,
                                                       &payload[sizeof(uint32_t)
                                                       ]));
    block = GNUNET_malloc (sizeof(struct GNUNET_GNSRECORD_Block)
                           + sizeof(uint32_t)
                           + payload_len);
    block->purpose.size = htonl (sizeof(uint32_t)
                                 + payload_len
                                 + sizeof(struct
                                          GNUNET_CRYPTO_EccSignaturePurpose)
                                 + sizeof(struct GNUNET_TIME_AbsoluteNBO));
    block->purpose.purpose = htonl (GNUNET_SIGNATURE_PURPOSE_GNS_RECORD_SIGN);
    block->expiration_time = GNUNET_TIME_absolute_hton (expire);
    /* encrypt and sign */
    dkey = GNUNET_CRYPTO_ecdsa_private_key_derive (key,
                                                   label,
                                                   "gns");
    GNUNET_CRYPTO_ecdsa_key_get_public (dkey,
                                        &block->derived_key);
    derive_block_aes_key (&iv,
                          &skey,
                          label,
                          pkey);
    GNUNET_break (payload_len + sizeof(uint32_t) ==
                  GNUNET_CRYPTO_symmetric_encrypt (payload,
                                                   payload_len
                                                   + sizeof(uint32_t),
                                                   &skey,
                                                   &iv,
                                                   &block[1]));
  }
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
 * Sign name and records
 *
 * @param key the private key
 * @param expire block expiration
 * @param label the name for the records
 * @param rd record data
 * @param rd_count number of records
 * @return NULL on error (block too large)
 */
struct GNUNET_GNSRECORD_Block *
GNUNET_GNSRECORD_block_create (const struct GNUNET_CRYPTO_EcdsaPrivateKey *key,
                               struct GNUNET_TIME_Absolute expire,
                               const char *label,
                               const struct GNUNET_GNSRECORD_Data *rd,
                               unsigned int rd_count)
{
  struct GNUNET_CRYPTO_EcdsaPublicKey pkey;

  GNUNET_CRYPTO_ecdsa_key_get_public (key,
                                      &pkey);
  return block_create (key,
                       &pkey,
                       expire,
                       label,
                       rd,
                       rd_count);
}


/**
 * Line in cache mapping private keys to public keys.
 */
struct KeyCacheLine
{
  /**
   * A private key.
   */
  struct GNUNET_CRYPTO_EcdsaPrivateKey key;

  /**
   * Associated public key.
   */
  struct GNUNET_CRYPTO_EcdsaPublicKey pkey;
};


/**
 * Sign name and records, cache derived public key (also keeps the
 * private key in static memory, so do not use this function if
 * keeping the private key in the process'es RAM is a major issue).
 *
 * @param key the private key
 * @param expire block expiration
 * @param label the name for the records
 * @param rd record data
 * @param rd_count number of records
 * @return NULL on error (block too large)
 */
struct GNUNET_GNSRECORD_Block *
GNUNET_GNSRECORD_block_create2 (const struct GNUNET_CRYPTO_EcdsaPrivateKey *key,
                                struct GNUNET_TIME_Absolute expire,
                                const char *label,
                                const struct GNUNET_GNSRECORD_Data *rd,
                                unsigned int rd_count)
{
#define CSIZE 64
  static struct KeyCacheLine cache[CSIZE];
  struct KeyCacheLine *line;

  line = &cache[(*(unsigned int *) key) % CSIZE];
  if (0 != memcmp (&line->key,
                   key,
                   sizeof(*key)))
  {
    /* cache miss, recompute */
    line->key = *key;
    GNUNET_CRYPTO_ecdsa_key_get_public (key,
                                        &line->pkey);
  }
#undef CSIZE
  return block_create (key,
                       &line->pkey,
                       expire,
                       label,
                       rd,
                       rd_count);
}


/**
 * Check if a signature is valid.  This API is used by the GNS Block
 * to validate signatures received from the network.
 *
 * @param block block to verify
 * @return #GNUNET_OK if the signature is valid
 */
int
GNUNET_GNSRECORD_block_verify (const struct GNUNET_GNSRECORD_Block *block)
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
GNUNET_GNSRECORD_block_decrypt (const struct GNUNET_GNSRECORD_Block *block,
                                const struct
                                GNUNET_CRYPTO_EcdsaPublicKey *zone_key,
                                const char *label,
                                GNUNET_GNSRECORD_RecordCallback proc,
                                void *proc_cls)
{
  size_t payload_len = ntohl (block->purpose.size)
                       - sizeof(struct GNUNET_CRYPTO_EccSignaturePurpose)
                       - sizeof(struct GNUNET_TIME_AbsoluteNBO);
  struct GNUNET_CRYPTO_SymmetricInitializationVector iv;
  struct GNUNET_CRYPTO_SymmetricSessionKey skey;

  if (ntohl (block->purpose.size) <
      sizeof(struct GNUNET_CRYPTO_EccSignaturePurpose)
      + sizeof(struct GNUNET_TIME_AbsoluteNBO))
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  derive_block_aes_key (&iv,
                        &skey,
                        label,
                        zone_key);
  {
    char payload[payload_len];
    uint32_t rd_count;

    GNUNET_break (payload_len ==
                  GNUNET_CRYPTO_symmetric_decrypt (&block[1], payload_len,
                                                   &skey, &iv,
                                                   payload));
    GNUNET_memcpy (&rd_count,
                   payload,
                   sizeof(uint32_t));
    rd_count = ntohl (rd_count);
    if (rd_count > 2048)
    {
      /* limit to sane value */
      GNUNET_break_op (0);
      return GNUNET_SYSERR;
    }
    {
      struct GNUNET_GNSRECORD_Data rd[GNUNET_NZL (rd_count)];
      unsigned int j;
      struct GNUNET_TIME_Absolute now;

      if (GNUNET_OK !=
          GNUNET_GNSRECORD_records_deserialize (payload_len - sizeof(uint32_t),
                                                &payload[sizeof(uint32_t)],
                                                rd_count,
                                                rd))
      {
        GNUNET_break_op (0);
        return GNUNET_SYSERR;
      }
      /* hide expired records */
      now = GNUNET_TIME_absolute_get ();
      j = 0;
      for (unsigned int i = 0; i < rd_count; i++)
      {
        if (0 != (rd[i].flags & GNUNET_GNSRECORD_RF_RELATIVE_EXPIRATION))
        {
          /* encrypted blocks must never have relative expiration times, skip! */
          GNUNET_break_op (0);
          continue;
        }

        if (0 != (rd[i].flags & GNUNET_GNSRECORD_RF_SHADOW_RECORD))
        {
          int include_record = GNUNET_YES;
          /* Shadow record, figure out if we have a not expired active record */
          for (unsigned int k = 0; k < rd_count; k++)
          {
            if (k == i)
              continue;
            if (rd[i].expiration_time < now.abs_value_us)
              include_record = GNUNET_NO;       /* Shadow record is expired */
            if ((rd[k].record_type == rd[i].record_type) &&
                (rd[k].expiration_time >= now.abs_value_us) &&
                (0 == (rd[k].flags & GNUNET_GNSRECORD_RF_SHADOW_RECORD)))
            {
              include_record = GNUNET_NO;         /* We have a non-expired, non-shadow record of the same type */
              GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                          "Ignoring shadow record\n");
              break;
            }
          }
          if (GNUNET_YES == include_record)
          {
            rd[i].flags ^= GNUNET_GNSRECORD_RF_SHADOW_RECORD;       /* Remove Flag */
            if (j != i)
              rd[j] = rd[i];
            j++;
          }
        }
        else if (rd[i].expiration_time >= now.abs_value_us)
        {
          /* Include this record */
          if (j != i)
            rd[j] = rd[i];
          j++;
        }
        else
        {
          struct GNUNET_TIME_Absolute at;

          at.abs_value_us = rd[i].expiration_time;
          GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                      "Excluding record that expired %s (%llu ago)\n",
                      GNUNET_STRINGS_absolute_time_to_string (at),
                      (unsigned long long) rd[i].expiration_time
                      - now.abs_value_us);
        }
      }
      rd_count = j;
      if (NULL != proc)
        proc (proc_cls,
              rd_count,
              (0 != rd_count) ? rd : NULL);
    }
  }
  return GNUNET_OK;
}


/**
 * Calculate the DHT query for a given @a label in a given @a zone.
 *
 * @param zone private key of the zone
 * @param label label of the record
 * @param query hash to use for the query
 */
void
GNUNET_GNSRECORD_query_from_private_key (const struct
                                         GNUNET_CRYPTO_EcdsaPrivateKey *zone,
                                         const char *label,
                                         struct GNUNET_HashCode *query)
{
  struct GNUNET_CRYPTO_EcdsaPublicKey pub;

  GNUNET_CRYPTO_ecdsa_key_get_public (zone,
                                      &pub);
  GNUNET_GNSRECORD_query_from_public_key (&pub,
                                          label,
                                          query);
}


/**
 * Calculate the DHT query for a given @a label in a given @a zone.
 *
 * @param pub public key of the zone
 * @param label label of the record
 * @param query hash to use for the query
 */
void
GNUNET_GNSRECORD_query_from_public_key (const struct
                                        GNUNET_CRYPTO_EcdsaPublicKey *pub,
                                        const char *label,
                                        struct GNUNET_HashCode *query)
{
  struct GNUNET_CRYPTO_EcdsaPublicKey pd;
  GNUNET_CRYPTO_ecdsa_public_key_derive (pub,
                                         label,
                                         "gns",
                                         &pd);
  GNUNET_CRYPTO_hash (&pd,
                      sizeof(pd),
                      query);
}


/* end of gnsrecord_crypto.c */

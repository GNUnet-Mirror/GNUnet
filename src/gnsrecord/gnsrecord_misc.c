/*
     This file is part of GNUnet.
     Copyright (C) 2009-2013 Christian Grothoff (and other contributing authors)

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
 * @file gnsrecord/gnsrecord_misc.c
 * @brief MISC functions related to GNS records
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


#define LOG(kind,...) GNUNET_log_from (kind, "gnsrecord",__VA_ARGS__)

/**
 * Convert a UTF-8 string to UTF-8 lowercase
 * @param src source string
 * @return converted result
 */
char *
GNUNET_GNSRECORD_string_to_lowercase (const char *src)
{
  char *res;

  res = GNUNET_strdup (src);
  GNUNET_STRINGS_utf8_tolower (src, res);
  return res;
}


/**
 * Convert a zone key to a string (for printing debug messages).
 * This is one of the very few calls in the entire API that is
 * NOT reentrant!
 *
 * @param z the zone key
 * @return string form; will be overwritten by next call to #GNUNET_GNSRECORD_z2s
 */
const char *
GNUNET_GNSRECORD_z2s (const struct GNUNET_CRYPTO_EcdsaPublicKey *z)
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
 * Compares if two records are equal (ignoring flags such
 * as authority, private and pending, but not relative vs.
 * absolute expiration time).
 *
 * @param a record
 * @param b record
 * @return #GNUNET_YES if the records are equal or #GNUNET_NO if they are not
 */
int
GNUNET_GNSRECORD_records_cmp (const struct GNUNET_GNSRECORD_Data *a,
                              const struct GNUNET_GNSRECORD_Data *b)
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
  if ((a->flags & GNUNET_GNSRECORD_RF_RCMP_FLAGS)
       != (b->flags & GNUNET_GNSRECORD_RF_RCMP_FLAGS))
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Flags %lu (%lu) != %lu (%lu)\n", a->flags,
         a->flags & GNUNET_GNSRECORD_RF_RCMP_FLAGS, b->flags,
         b->flags & GNUNET_GNSRECORD_RF_RCMP_FLAGS);
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
 * Returns the expiration time of the given block of records. The block
 * expiration time is the expiration time of the record with smallest
 * expiration time.
 *
 * @param rd_count number of records given in @a rd
 * @param rd array of records
 * @return absolute expiration time
 */
struct GNUNET_TIME_Absolute
GNUNET_GNSRECORD_record_get_expiration_time (unsigned int rd_count,
					     const struct GNUNET_GNSRECORD_Data *rd)
{
  unsigned int c;
  unsigned int c2;
  struct GNUNET_TIME_Absolute expire;
  struct GNUNET_TIME_Absolute at;
  struct GNUNET_TIME_Relative rt;
  struct GNUNET_TIME_Absolute at_shadow;
  struct GNUNET_TIME_Relative rt_shadow;

  if (NULL == rd)
    return GNUNET_TIME_UNIT_ZERO_ABS;
  expire = GNUNET_TIME_UNIT_FOREVER_ABS;
  for (c = 0; c < rd_count; c++)
  {
    if (0 != (rd[c].flags & GNUNET_GNSRECORD_RF_RELATIVE_EXPIRATION))
    {
      rt.rel_value_us = rd[c].expiration_time;
      at = GNUNET_TIME_relative_to_absolute (rt);
    }
    else
    {
      at.abs_value_us = rd[c].expiration_time;
    }

    for (c2 = 0; c2 < rd_count; c2++)
    {
      /* Check for shadow record */
      if ((c == c2) ||
          (rd[c].record_type != rd[c2].record_type) ||
          (0 == (rd[c2].flags & GNUNET_GNSRECORD_RF_SHADOW_RECORD)))
          continue;
      /* We have a shadow record */
      if (0 != (rd[c2].flags & GNUNET_GNSRECORD_RF_RELATIVE_EXPIRATION))
      {
        rt_shadow.rel_value_us = rd[2].expiration_time;
        at_shadow = GNUNET_TIME_relative_to_absolute (rt_shadow);
      }
      else
      {
        at_shadow.abs_value_us = rd[c2].expiration_time;
      }
      at = GNUNET_TIME_absolute_max (at, at_shadow);
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
 * Test if a given record is expired.
 *
 * @return #GNUNET_YES if the record is expired,
 *         #GNUNET_NO if not
 */
int
GNUNET_GNSRECORD_is_expired (const struct GNUNET_GNSRECORD_Data *rd)
{
  struct GNUNET_TIME_Absolute at;

  if (0 != (rd->flags & GNUNET_GNSRECORD_RF_RELATIVE_EXPIRATION))
    return GNUNET_NO;
  at.abs_value_us = rd->expiration_time;
  return (0 == GNUNET_TIME_absolute_get_remaining (at).rel_value_us) ? GNUNET_YES : GNUNET_NO;
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
GNUNET_GNSRECORD_pkey_to_zkey (const struct GNUNET_CRYPTO_EcdsaPublicKey *pkey)
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
GNUNET_GNSRECORD_zkey_to_pkey (const char *zkey,
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


/* end of gnsrecord_misc.c */

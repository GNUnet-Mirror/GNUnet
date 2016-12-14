/*
     This file is part of GNUnet.
     Copyright (C) 2009-2013, 2016 GNUnet e.V.

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
 * @file credential/credential_serialization.c
 * @brief API to serialize and deserialize delegation chains 
 * and credentials
 * @author Martin Schanzenbach
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_constants.h"
#include "gnunet_credential_service.h"

GNUNET_NETWORK_STRUCT_BEGIN

struct DelegationRecordData
{
  /**
   * Subject key
   */
  struct GNUNET_CRYPTO_EcdsaPublicKey subject_key;
  
  /**
   * Subject attributes
   */
  uint32_t subject_attribute_len GNUNET_PACKED;
};


struct ChainEntry
{
  /**
   * Issuer key
   */
  struct GNUNET_CRYPTO_EcdsaPublicKey issuer_key;
  
  /**
   * Subject key
   */
  struct GNUNET_CRYPTO_EcdsaPublicKey subject_key;
  
  /**
   * Issuer attributes
   */
  uint32_t issuer_attribute_len GNUNET_PACKED;
  
  /**
   * Subject attributes
   */
  uint32_t subject_attribute_len GNUNET_PACKED;
};

GNUNET_NETWORK_STRUCT_END


/**
 * Calculate how many bytes we will need to serialize
 * the given delegation chain and credential
 *
 * @param d_count number of delegation chain entries
 * @param dd array of #GNUNET_CREDENTIAL_Delegation
 * @param cd a #GNUNET_CREDENTIAL_Credential
 * @return the required size to serialize
 */
size_t
GNUNET_CREDENTIAL_delegation_set_get_size (unsigned int ds_count,
                                           const struct GNUNET_CREDENTIAL_DelegationSetRecord *dsr)
{
  unsigned int i;
  size_t ret;

  ret = sizeof (struct DelegationRecordData) * (ds_count);

  for (i=0; i<ds_count;i++)
  {
    GNUNET_assert ((ret + dsr[i].subject_attribute_len) >= ret);
    ret += dsr[i].subject_attribute_len;
  }
  return ret;
}

/**
 * Serizalize the given delegation chain entries and credential
 *
 * @param d_count number of delegation chain entries
 * @param dd array of #GNUNET_CREDENTIAL_Delegation
 * @param cd a #GNUNET_CREDENTIAL_Credential
 * @param dest_size size of the destination
 * @param dest where to store the result
 * @return the size of the data, -1 on failure
 */
ssize_t
GNUNET_CREDENTIAL_delegation_set_serialize (unsigned int d_count,
                                            const struct GNUNET_CREDENTIAL_DelegationSetRecord *dsr,
                                            size_t dest_size,
                                            char *dest)
{
  struct DelegationRecordData rec;
  unsigned int i;
  size_t off;

  off = 0;
  for (i=0;i<d_count;i++)
  {
    rec.subject_attribute_len = htonl ((uint32_t) dsr[i].subject_attribute_len);
    rec.subject_key = dsr[i].subject_key;
    if (off + sizeof (rec) > dest_size)
      return -1;
    GNUNET_memcpy (&dest[off],
                   &rec,
                   sizeof (rec));
    off += sizeof (rec);
    if (0 == dsr[i].subject_attribute_len)
      continue;
    if (off + dsr[i].subject_attribute_len > dest_size)
      return -1;
    GNUNET_memcpy (&dest[off],
                   dsr[i].subject_attribute,
                   dsr[i].subject_attribute_len);
    off += dsr[i].subject_attribute_len;
  }
  return off;
}


/**
 * Deserialize the given destination
 *
 * @param len size of the serialized delegation chain and cred
 * @param src the serialized data
 * @param d_count the number of delegation chain entries
 * @param dd where to put the delegation chain entries
 * @param cd where to put the credential data
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on error
 */
int
GNUNET_CREDENTIAL_delegation_set_deserialize (size_t len,
                                              const char *src,
                                              unsigned int d_count,
                                              struct GNUNET_CREDENTIAL_DelegationSetRecord *dsr)
{
  struct DelegationRecordData rec;
  unsigned int i;
  size_t off;

  off = 0;
  for (i=0;i<d_count;i++)
  {
    if (off + sizeof (rec) > len)
      return GNUNET_SYSERR;
    GNUNET_memcpy (&rec, &src[off], sizeof (rec));
    dsr[i].subject_key = rec.subject_key;
    off += sizeof (rec);
    dsr[i].subject_attribute_len = ntohl ((uint32_t) rec.subject_attribute_len);
    if (off + dsr[i].subject_attribute_len > len)
      return GNUNET_SYSERR;
    dsr[i].subject_attribute = &src[off];
    off += dsr[i].subject_attribute_len;
  }
  return GNUNET_OK;
}
/**
 * Calculate how many bytes we will need to serialize
 * the given delegation chain and credential
 *
 * @param d_count number of delegation chain entries
 * @param dd array of #GNUNET_CREDENTIAL_Delegation
 * @param cd a #GNUNET_CREDENTIAL_Credential
 * @return the required size to serialize
 */
size_t
GNUNET_CREDENTIAL_delegation_chain_get_size (unsigned int d_count,
                                             const struct GNUNET_CREDENTIAL_Delegation *dd,
                                             const struct GNUNET_CREDENTIAL_Credential *cd)
{
  unsigned int i;
  size_t ret;

  ret = sizeof (struct ChainEntry) * (d_count + 1);

  for (i=0; i<d_count;i++)
  {
    GNUNET_assert ((ret +
                    dd[i].issuer_attribute_len +
                    dd[i].subject_attribute_len) >= ret);
    ret += dd[i].issuer_attribute_len + dd[i].subject_attribute_len;
  }
  GNUNET_assert ((ret + cd->issuer_attribute_len) >= ret);
  ret += cd->issuer_attribute_len;
  return ret;
}

/**
 * Serizalize the given delegation chain entries and credential
 *
 * @param d_count number of delegation chain entries
 * @param dd array of #GNUNET_CREDENTIAL_Delegation
 * @param cd a #GNUNET_CREDENTIAL_Credential
 * @param dest_size size of the destination
 * @param dest where to store the result
 * @return the size of the data, -1 on failure
 */
ssize_t
GNUNET_CREDENTIAL_delegation_chain_serialize (unsigned int d_count,
                                              const struct GNUNET_CREDENTIAL_Delegation *dd,
                                              const struct GNUNET_CREDENTIAL_Credential *cd,
                                              size_t dest_size,
                                              char *dest)
{
  struct ChainEntry rec;
  unsigned int i;
  size_t off;

  off = 0;
  for (i=0;i<d_count;i++)
  {
    rec.issuer_attribute_len = htonl ((uint32_t) dd[i].issuer_attribute_len);
    rec.subject_attribute_len = htonl ((uint32_t) dd[i].subject_attribute_len);
    rec.issuer_key = dd[i].issuer_key;
    rec.subject_key = dd[i].subject_key;
    if (off + sizeof (rec) > dest_size)
      return -1;
    GNUNET_memcpy (&dest[off],
                   &rec,
                   sizeof (rec));
    off += sizeof (rec);
    if (off + dd[i].issuer_attribute_len > dest_size)
      return -1;
    GNUNET_memcpy (&dest[off],
                   dd[i].issuer_attribute,
                   dd[i].issuer_attribute_len);
    off += dd[i].issuer_attribute_len;
    if (0 == dd[i].subject_attribute_len)
      continue;
    if (off + dd[i].subject_attribute_len > dest_size)
      return -1;
    GNUNET_memcpy (&dest[off],
                   dd[i].subject_attribute,
                   dd[i].subject_attribute_len);
    off += dd[i].subject_attribute_len;
  }
  rec.issuer_attribute_len = htonl ((uint32_t) cd->issuer_attribute_len);
  rec.subject_attribute_len = htonl (0);
  rec.issuer_key = cd->issuer_key;
  if (off + sizeof (rec) > dest_size)
    return -1;
  GNUNET_memcpy (&dest[off],
                 &rec,
                 sizeof (rec));
  off += sizeof (rec);
  if (off + cd->issuer_attribute_len > dest_size)
    return -1;
  GNUNET_memcpy (&dest[off],
                 cd->issuer_attribute,
                 cd->issuer_attribute_len);
  off += cd->issuer_attribute_len;

  return off;
}


/**
 * Deserialize the given destination
 *
 * @param len size of the serialized delegation chain and cred
 * @param src the serialized data
 * @param d_count the number of delegation chain entries
 * @param dd where to put the delegation chain entries
 * @param cd where to put the credential data
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on error
 */
int
GNUNET_CREDENTIAL_delegation_chain_deserialize (size_t len,
                                                const char *src,
                                                unsigned int d_count,
                                                struct GNUNET_CREDENTIAL_Delegation *dd,
                                                struct GNUNET_CREDENTIAL_Credential *cd)
{
  struct ChainEntry rec;
  unsigned int i;
  size_t off;

  off = 0;
  for (i=0;i<d_count;i++)
  {
    if (off + sizeof (rec) > len)
      return GNUNET_SYSERR;
    GNUNET_memcpy (&rec, &src[off], sizeof (rec));
    dd[i].issuer_attribute_len = ntohl ((uint32_t) rec.issuer_attribute_len);
    dd[i].issuer_key = rec.issuer_key;
    dd[i].subject_key = rec.subject_key;
    off += sizeof (rec);
    if (off + dd[i].issuer_attribute_len > len)
      return GNUNET_SYSERR;
    dd[i].issuer_attribute = &src[off];
    off += dd[i].issuer_attribute_len;
    dd[i].subject_attribute_len = ntohl ((uint32_t) rec.subject_attribute_len);
    if (off + dd[i].subject_attribute_len > len)
      return GNUNET_SYSERR;
    dd[i].subject_attribute = &src[off];
    off += dd[i].subject_attribute_len;
  }
  if (off + sizeof (rec) > len)
    return GNUNET_SYSERR;
  GNUNET_memcpy (&rec, &src[off], sizeof (rec));
  cd->issuer_attribute_len = ntohl ((uint32_t) rec.issuer_attribute_len);
  cd->issuer_key = rec.issuer_key;
  cd->subject_key = rec.subject_key;
  off += sizeof (rec);
  if (off + cd->issuer_attribute_len > len)
    return GNUNET_SYSERR;
  cd->issuer_attribute = &src[off];
  off += cd->issuer_attribute_len;
  return GNUNET_OK;
}

/* end of credential_serialization.c */

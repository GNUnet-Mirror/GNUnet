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
#include "gnunet_signatures.h"
#include "credential.h"

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
                                           const struct GNUNET_CREDENTIAL_DelegationSet *dsr)
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
                                            const struct GNUNET_CREDENTIAL_DelegationSet *dsr,
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
                                              struct GNUNET_CREDENTIAL_DelegationSet *dsr)
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
    dsr[i].subject_attribute = (char*)&src[off];
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
 * @param c_count number of credential entries
 * @param cd a #GNUNET_CREDENTIAL_Credential
 * @return the required size to serialize
 */
size_t
GNUNET_CREDENTIAL_delegation_chain_get_size (unsigned int d_count,
                                             const struct GNUNET_CREDENTIAL_Delegation *dd,
                                             unsigned int c_count,
                                             const struct GNUNET_CREDENTIAL_Credential *cd)
{
  unsigned int i;
  size_t ret;

  ret = sizeof (struct ChainEntry) * (d_count);
  ret += sizeof (struct CredentialEntry) * (c_count);

  for (i=0; i<d_count;i++)
  {
    GNUNET_assert ((ret +
                    dd[i].issuer_attribute_len +
                    dd[i].subject_attribute_len) >= ret);
    ret += dd[i].issuer_attribute_len + dd[i].subject_attribute_len;
  }
  for (i=0; i<c_count;i++)
  {
    GNUNET_assert ((ret + cd[i].issuer_attribute_len) >= ret);
    ret += cd[i].issuer_attribute_len;
  }
  return ret;
}

/**
 * Serizalize the given delegation chain entries and credential
 *
 * @param d_count number of delegation chain entries
 * @param dd array of #GNUNET_CREDENTIAL_Delegation
 * @param c_count number of credential entries
 * @param cd a #GNUNET_CREDENTIAL_Credential
 * @param dest_size size of the destination
 * @param dest where to store the result
 * @return the size of the data, -1 on failure
 */
ssize_t
GNUNET_CREDENTIAL_delegation_chain_serialize (unsigned int d_count,
                                              const struct GNUNET_CREDENTIAL_Delegation *dd,
                                              unsigned int c_count,
                                              const struct GNUNET_CREDENTIAL_Credential *cd,
                                              size_t dest_size,
                                              char *dest)
{
  struct ChainEntry rec;
  struct CredentialEntry c_rec;
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
  for (i=0;i<c_count;i++)
  {
    c_rec.issuer_attribute_len = htonl ((uint32_t) cd[i].issuer_attribute_len);
    c_rec.issuer_key = cd[i].issuer_key;
    c_rec.subject_key = cd[i].subject_key;
    c_rec.signature = cd[i].signature;
    c_rec.purpose.purpose = htonl (GNUNET_SIGNATURE_PURPOSE_CREDENTIAL);
    c_rec.purpose.size = htonl ((sizeof (struct CredentialEntry) + cd[i].issuer_attribute_len) - sizeof (struct GNUNET_CRYPTO_EcdsaSignature));
    c_rec.expiration = htonl ((uint32_t) cd[i].expiration.abs_value_us);
    if (off + sizeof (c_rec) > dest_size)
      return -1;
    GNUNET_memcpy (&dest[off],
                   &c_rec,
                   sizeof (c_rec));
    off += sizeof (c_rec);
    if (off + cd[i].issuer_attribute_len > dest_size)
      return -1;
    GNUNET_memcpy (&dest[off],
                   cd[i].issuer_attribute,
                   cd[i].issuer_attribute_len);
    off += cd[i].issuer_attribute_len;
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
 * @param c_count the number of credential entries
 * @param cd where to put the credential data
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on error
 */
int
GNUNET_CREDENTIAL_delegation_chain_deserialize (size_t len,
                                                const char *src,
                                                unsigned int d_count,
                                                struct GNUNET_CREDENTIAL_Delegation *dd,
                                                unsigned int c_count,
                                                struct GNUNET_CREDENTIAL_Credential *cd)
{
  struct ChainEntry rec;
  struct CredentialEntry c_rec;
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
  for (i=0;i<c_count;i++)
  {
    if (off + sizeof (c_rec) > len)
      return GNUNET_SYSERR;
    GNUNET_memcpy (&c_rec, &src[off], sizeof (c_rec));
    cd[i].issuer_attribute_len = ntohl ((uint32_t) c_rec.issuer_attribute_len);
    cd[i].issuer_key = c_rec.issuer_key;
    cd[i].subject_key = c_rec.subject_key;
    cd[i].signature = c_rec.signature;
    cd[i].expiration.abs_value_us = ntohl((uint32_t) c_rec.expiration);
    off += sizeof (c_rec);
    if (off + cd[i].issuer_attribute_len > len)
      return GNUNET_SYSERR;
    cd[i].issuer_attribute = &src[off];
    off += cd[i].issuer_attribute_len;
  }
  return GNUNET_OK;
}


int
GNUNET_CREDENTIAL_credential_serialize (struct GNUNET_CREDENTIAL_Credential *cred,
                                        char **data)
{
  size_t size;
  struct CredentialEntry *cdata;

  size = sizeof (struct CredentialEntry) + strlen (cred->issuer_attribute) + 1;
  *data = GNUNET_malloc (size);
  cdata = (struct CredentialEntry*)*data;
  cdata->subject_key = cred->subject_key;
  cdata->issuer_key = cred->issuer_key;
  cdata->expiration = GNUNET_htonll (cred->expiration.abs_value_us);
  cdata->signature = cred->signature;
  cdata->issuer_attribute_len = htonl (strlen (cred->issuer_attribute) + 1);
  cdata->purpose.purpose = htonl (GNUNET_SIGNATURE_PURPOSE_CREDENTIAL);
  cdata->purpose.size = htonl (size - sizeof (struct GNUNET_CRYPTO_EcdsaSignature));
  GNUNET_memcpy (&cdata[1],
                 cred->issuer_attribute,
                 strlen (cred->issuer_attribute));

  if(GNUNET_OK != GNUNET_CRYPTO_ecdsa_verify(GNUNET_SIGNATURE_PURPOSE_CREDENTIAL, 
                                             &cdata->purpose,
                                             &cdata->signature,
                                             &cdata->issuer_key))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "Invalid credential\n");
    //return NULL;
  }
  return size;
}

struct GNUNET_CREDENTIAL_Credential*
GNUNET_CREDENTIAL_credential_deserialize (const char* data,
                                          size_t data_size)
{
  struct GNUNET_CREDENTIAL_Credential *cred;
  struct CredentialEntry *cdata;
  char *issuer_attribute;

  if (data_size < sizeof (struct CredentialEntry))
    return NULL;
  cdata = (struct CredentialEntry*)data;
  if(GNUNET_OK != GNUNET_CRYPTO_ecdsa_verify(GNUNET_SIGNATURE_PURPOSE_CREDENTIAL, 
                                             &cdata->purpose,
                                             &cdata->signature,
                                             &cdata->issuer_key))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "Invalid credential\n");
    //return NULL;
  }
  issuer_attribute = (char*)&cdata[1];

  cred = GNUNET_malloc (sizeof (struct GNUNET_CREDENTIAL_Credential) + ntohl(cdata->issuer_attribute_len));

  cred->issuer_key = cdata->issuer_key;
  cred->subject_key = cdata->subject_key;
  GNUNET_memcpy (&cred[1],
                 issuer_attribute,
                 ntohl (cdata->issuer_attribute_len));
  cred->signature = cdata->signature;
  cred->issuer_attribute = (char*)&cred[1];
  cred->expiration.abs_value_us = GNUNET_ntohll (cdata->expiration);
  return cred;
}


/* end of credential_serialization.c */

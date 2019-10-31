/*
     This file is part of GNUnet.
     Copyright (C) 2009-2013, 2016 GNUnet e.V.

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
 * @file abd/abd_serialization.c
 * @brief API to serialize and deserialize delegation chains
 * and abds
 * @author Martin Schanzenbach
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_constants.h"
#include "gnunet_abd_service.h"
#include "gnunet_signatures.h"
#include "abd.h"

/**
 * Calculate how many bytes we will need to serialize
 * the given delegation chain
 *
 * @param ds_count number of delegation chain entries
 * @param dsr array of #GNUNET_ABD_DelegationSet
 * @return the required size to serialize
 */
size_t
GNUNET_ABD_delegation_set_get_size (
  unsigned int ds_count,
  const struct GNUNET_ABD_DelegationSet *dsr)
{
  unsigned int i;
  size_t ret;

  ret = sizeof (struct DelegationRecordData) * (ds_count);

  for (i = 0; i < ds_count; i++)
  {
    GNUNET_assert ((ret + dsr[i].subject_attribute_len) >= ret);
    ret += dsr[i].subject_attribute_len;
  }
  return ret;
}


/**
 * Serizalize the given delegation chain entries and abd
 *
 * @param d_count number of delegation chain entries
 * @param dsr array of #GNUNET_ABD_DelegationSet
 * @param dest_size size of the destination
 * @param dest where to store the result
 * @return the size of the data, -1 on failure
 */
ssize_t
GNUNET_ABD_delegation_set_serialize (
  unsigned int d_count,
  const struct GNUNET_ABD_DelegationSet *dsr,
  size_t dest_size,
  char *dest)
{
  struct DelegationRecordData rec;
  unsigned int i;
  size_t off;

  off = 0;
  for (i = 0; i < d_count; i++)
  {
    rec.subject_attribute_len = htonl ((uint32_t) dsr[i].subject_attribute_len);
    rec.subject_key = dsr[i].subject_key;
    if (off + sizeof (rec) > dest_size)
      return -1;
    GNUNET_memcpy (&dest[off], &rec, sizeof (rec));
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
 * @param dsr where to put the delegation chain entries
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on error
 */
int
GNUNET_ABD_delegation_set_deserialize (
  size_t len,
  const char *src,
  unsigned int d_count,
  struct GNUNET_ABD_DelegationSet *dsr)
{
  struct DelegationRecordData rec;
  unsigned int i;
  size_t off;

  off = 0;
  for (i = 0; i < d_count; i++)
  {
    if (off + sizeof (rec) > len)
      return GNUNET_SYSERR;
    GNUNET_memcpy (&rec, &src[off], sizeof (rec));
    dsr[i].subject_key = rec.subject_key;
    off += sizeof (rec);
    dsr[i].subject_attribute_len = ntohl ((uint32_t) rec.subject_attribute_len);
    if (off + dsr[i].subject_attribute_len > len)
      return GNUNET_SYSERR;
    dsr[i].subject_attribute = (char *) &src[off];
    off += dsr[i].subject_attribute_len;
  }
  return GNUNET_OK;
}


/**
 * Calculate how many bytes we will need to serialize
 * the abds
 *
 * @param c_count number of abd entries
 * @param cd a #GNUNET_ABD_Credential
 * @return the required size to serialize
 */
size_t
GNUNET_ABD_delegates_get_size (
  unsigned int c_count,
  const struct GNUNET_ABD_Delegate *cd)
{
  unsigned int i;
  size_t ret;

  ret = sizeof (struct DelegateEntry) * (c_count);

  for (i = 0; i < c_count; i++)
  {
    GNUNET_assert ((ret + cd[i].issuer_attribute_len
                    + cd[i].subject_attribute_len) >= ret);
    // subject_attribute_len should be 0
    ret += cd[i].issuer_attribute_len + cd[i].subject_attribute_len;
  }
  return ret;
}


/**
 * Serizalize the given abds
 *
 * @param c_count number of abd entries
 * @param cd a #GNUNET_ABD_Credential
 * @param dest_size size of the destination
 * @param dest where to store the result
 * @return the size of the data, -1 on failure
 */
ssize_t
GNUNET_ABD_delegates_serialize (
  unsigned int c_count,
  const struct GNUNET_ABD_Delegate *cd,
  size_t dest_size,
  char *dest)
{
  struct DelegateEntry c_rec;
  unsigned int i;
  size_t off;

  off = 0;
  for (i = 0; i < c_count; i++)
  {
    // c_rec.subject_attribute_len = htonl ((uint32_t) cd[i].subject_attribute_len);
    c_rec.issuer_attribute_len = htonl ((uint32_t) cd[i].issuer_attribute_len);
    c_rec.issuer_key = cd[i].issuer_key;
    c_rec.subject_key = cd[i].subject_key;
    c_rec.signature = cd[i].signature;
    c_rec.purpose.purpose = htonl (GNUNET_SIGNATURE_PURPOSE_DELEGATE);
    c_rec.purpose.size =
      htonl ((sizeof (struct DelegateEntry) + cd[i].issuer_attribute_len)
             - sizeof (struct GNUNET_CRYPTO_EcdsaSignature));
    c_rec.expiration = GNUNET_htonll (cd[i].expiration.abs_value_us);
    if (off + sizeof (c_rec) > dest_size)
      return -1;
    GNUNET_memcpy (&dest[off], &c_rec, sizeof (c_rec));
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
 * @param len size of the serialized creds
 * @param src the serialized data
 * @param c_count the number of abd entries
 * @param cd where to put the abd data
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on error
 */
int
GNUNET_ABD_delegates_deserialize (size_t len,
                                  const char *src,
                                  unsigned int c_count,
                                  struct GNUNET_ABD_Delegate *cd)
{
  struct DelegateEntry c_rec;
  unsigned int i;
  size_t off;

  off = 0;
  for (i = 0; i < c_count; i++)
  {
    if (off + sizeof (c_rec) > len)
      return GNUNET_SYSERR;
    GNUNET_memcpy (&c_rec, &src[off], sizeof (c_rec));
    cd[i].issuer_attribute_len = ntohl ((uint32_t) c_rec.issuer_attribute_len);
    cd[i].issuer_key = c_rec.issuer_key;
    cd[i].subject_key = c_rec.subject_key;
    cd[i].signature = c_rec.signature;
    cd[i].expiration.abs_value_us = GNUNET_ntohll (c_rec.expiration);
    off += sizeof (c_rec);
    if (off + cd[i].issuer_attribute_len > len)
      return GNUNET_SYSERR;
    cd[i].issuer_attribute = &src[off];
    off += cd[i].issuer_attribute_len;
    cd[i].subject_attribute_len = 0;
  }
  return GNUNET_OK;
}


/**
 * Calculate how many bytes we will need to serialize
 * the given delegation chain and abd
 *
 * @param d_count number of delegation chain entries
 * @param dd array of #GNUNET_ABD_Delegation
 * @param c_count number of abd entries
 * @param cd a #GNUNET_ABD_Credential
 * @return the required size to serialize
 */
size_t
GNUNET_ABD_delegation_chain_get_size (
  unsigned int d_count,
  const struct GNUNET_ABD_Delegation *dd,
  unsigned int c_count,
  const struct GNUNET_ABD_Delegate *cd)
{
  unsigned int i;
  size_t ret;

  ret = sizeof (struct ChainEntry) * (d_count);

  for (i = 0; i < d_count; i++)
  {
    GNUNET_assert (
      (ret + dd[i].issuer_attribute_len + dd[i].subject_attribute_len) >= ret);
    ret += dd[i].issuer_attribute_len + dd[i].subject_attribute_len;
  }
  return ret + GNUNET_ABD_delegates_get_size (c_count, cd);
}


/**
 * Serizalize the given delegation chain entries and abd
 *
 * @param d_count number of delegation chain entries
 * @param dd array of #GNUNET_ABD_Delegation
 * @param c_count number of abd entries
 * @param cd a #GNUNET_ABD_Credential
 * @param dest_size size of the destination
 * @param dest where to store the result
 * @return the size of the data, -1 on failure
 */
ssize_t
GNUNET_ABD_delegation_chain_serialize (
  unsigned int d_count,
  const struct GNUNET_ABD_Delegation *dd,
  unsigned int c_count,
  const struct GNUNET_ABD_Delegate *cd,
  size_t dest_size,
  char *dest)
{
  struct ChainEntry rec;
  unsigned int i;
  size_t off;

  off = 0;
  for (i = 0; i < d_count; i++)
  {
    rec.issuer_attribute_len = htonl ((uint32_t) dd[i].issuer_attribute_len);
    rec.subject_attribute_len = htonl ((uint32_t) dd[i].subject_attribute_len);
    rec.issuer_key = dd[i].issuer_key;
    rec.subject_key = dd[i].subject_key;
    if (off + sizeof (rec) > dest_size)
      return -1;
    GNUNET_memcpy (&dest[off], &rec, sizeof (rec));
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
  return off + GNUNET_ABD_delegates_serialize (c_count,
                                               cd,
                                               dest_size - off,
                                               &dest[off]);
}


/**
 * Deserialize the given destination
 *
 * @param len size of the serialized delegation chain and cred
 * @param src the serialized data
 * @param d_count the number of delegation chain entries
 * @param dd where to put the delegation chain entries
 * @param c_count the number of abd entries
 * @param cd where to put the abd data
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on error
 */
int
GNUNET_ABD_delegation_chain_deserialize (
  size_t len,
  const char *src,
  unsigned int d_count,
  struct GNUNET_ABD_Delegation *dd,
  unsigned int c_count,
  struct GNUNET_ABD_Delegate *cd)
{
  struct ChainEntry rec;
  unsigned int i;
  size_t off;

  off = 0;
  for (i = 0; i < d_count; i++)
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
  return GNUNET_ABD_delegates_deserialize (len - off,
                                           &src[off],
                                           c_count,
                                           cd);
}


int
GNUNET_ABD_delegate_serialize (struct GNUNET_ABD_Delegate *dele,
                               char **data)
{
  size_t size;
  struct DelegateEntry *cdata;
  int attr_len;

  // +1 for \0
  if (0 == dele->subject_attribute_len)
  {
    attr_len = dele->issuer_attribute_len + 1;
  }
  else
  {
    attr_len = dele->issuer_attribute_len + dele->subject_attribute_len + 2;
  }
  size = sizeof (struct DelegateEntry) + attr_len;

  char tmp_str[attr_len];
  GNUNET_memcpy (tmp_str, dele->issuer_attribute, dele->issuer_attribute_len);
  if (0 != dele->subject_attribute_len)
  {
    tmp_str[dele->issuer_attribute_len] = '\0';
    GNUNET_memcpy (tmp_str + dele->issuer_attribute_len + 1,
                   dele->subject_attribute,
                   dele->subject_attribute_len);
  }
  tmp_str[attr_len - 1] = '\0';

  *data = GNUNET_malloc (size);
  cdata = (struct DelegateEntry *) *data;
  cdata->subject_key = dele->subject_key;
  cdata->issuer_key = dele->issuer_key;
  cdata->expiration = GNUNET_htonll (dele->expiration.abs_value_us);
  cdata->signature = dele->signature;
  cdata->issuer_attribute_len = htonl (dele->issuer_attribute_len + 1);
  if (0 == dele->subject_attribute_len)
  {
    cdata->subject_attribute_len = htonl (0);
  }
  else
  {
    cdata->subject_attribute_len = htonl (dele->subject_attribute_len + 1);
  }
  cdata->purpose.purpose = htonl (GNUNET_SIGNATURE_PURPOSE_DELEGATE);
  cdata->purpose.size =
    htonl (size - sizeof (struct GNUNET_CRYPTO_EcdsaSignature));

  GNUNET_memcpy (&cdata[1], tmp_str, attr_len);

  if (GNUNET_OK !=
      GNUNET_CRYPTO_ecdsa_verify (GNUNET_SIGNATURE_PURPOSE_DELEGATE,
                                  &cdata->purpose,
                                  &cdata->signature,
                                  &cdata->issuer_key))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING, "Serialize: Invalid delegate\n");
    return 0;
  }
  return size;
}


struct GNUNET_ABD_Delegate *
GNUNET_ABD_delegate_deserialize (const char *data, size_t data_size)
{
  struct GNUNET_ABD_Delegate *dele;
  struct DelegateEntry *cdata;
  char *attr_combo_str;

  if (data_size < sizeof (struct DelegateEntry))
    return NULL;
  cdata = (struct DelegateEntry *) data;
  if (GNUNET_OK !=
      GNUNET_CRYPTO_ecdsa_verify (GNUNET_SIGNATURE_PURPOSE_DELEGATE,
                                  &cdata->purpose,
                                  &cdata->signature,
                                  &cdata->issuer_key))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING, "Deserialize: Invalid delegate\n");
    return NULL;
  }
  attr_combo_str = (char *) &cdata[1];
  int iss_len = ntohl (cdata->issuer_attribute_len);
  int sub_len = ntohl (cdata->subject_attribute_len);
  int attr_combo_len = iss_len + sub_len;

  dele =
    GNUNET_malloc (sizeof (struct GNUNET_ABD_Delegate) + attr_combo_len);

  dele->issuer_key = cdata->issuer_key;
  dele->subject_key = cdata->subject_key;
  GNUNET_memcpy (&dele[1], attr_combo_str, attr_combo_len);
  dele->signature = cdata->signature;

  // Set the pointers for the attributes
  dele->issuer_attribute = (char *) &dele[1];
  dele->issuer_attribute_len = iss_len;
  dele->subject_attribute_len = sub_len;
  if (0 == sub_len)
  {
    dele->subject_attribute = NULL;
  }
  else
  {
    dele->subject_attribute = (char *) &dele[1] + iss_len;
  }

  dele->expiration.abs_value_us = GNUNET_ntohll (cdata->expiration);

  return dele;
}


/* end of abd_serialization.c */

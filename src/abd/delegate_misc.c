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
 * @file abd/delegate_misc.c
 * @brief Misc API for delegate
 *
 * @author Martin Schanzenbach
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_constants.h"
#include "gnunet_abd_service.h"
#include "gnunet_signatures.h"
#include "abd.h"
#include <inttypes.h>

char *
GNUNET_ABD_delegate_to_string (
  const struct GNUNET_ABD_Delegate *cred)
{
  char *cred_str;
  char *subject_pkey;
  char *issuer_pkey;
  char *signature;

  subject_pkey = GNUNET_CRYPTO_ecdsa_public_key_to_string (&cred->subject_key);
  issuer_pkey = GNUNET_CRYPTO_ecdsa_public_key_to_string (&cred->issuer_key);
  GNUNET_STRINGS_base64_encode ((char *) &cred->signature,
                                sizeof (struct GNUNET_CRYPTO_EcdsaSignature),
                                &signature);
  if (0 == cred->subject_attribute_len)
  {
    GNUNET_asprintf (&cred_str,
                     "%s.%s -> %s | %s | %" SCNu64,
                     issuer_pkey,
                     cred->issuer_attribute,
                     subject_pkey,
                     signature,
                     cred->expiration.abs_value_us);
  }
  else
  {
    GNUNET_asprintf (&cred_str,
                     "%s.%s -> %s.%s | %s | %" SCNu64,
                     issuer_pkey,
                     cred->issuer_attribute,
                     subject_pkey,
                     cred->subject_attribute,
                     signature,
                     cred->expiration.abs_value_us);
  }
  GNUNET_free (subject_pkey);
  GNUNET_free (issuer_pkey);
  GNUNET_free (signature);

  return cred_str;
}


struct GNUNET_ABD_Delegate *
GNUNET_ABD_delegate_from_string (const char *s)
{
  struct GNUNET_ABD_Delegate *dele;
  size_t enclen = (sizeof (struct GNUNET_CRYPTO_EcdsaPublicKey)) * 8;
  if (enclen % 5 > 0)
    enclen += 5 - enclen % 5;
  enclen /= 5; /* 260/5 = 52 */
  char subject_pkey[enclen + 1];
  char issuer_pkey[enclen + 1];
  char iss_attr[253 + 1];
  // Needs to be initialized, in case of Type 1 credential (A.a <- B)
  char sub_attr[253 + 1] = "";
  char signature[256]; // TODO max payload size

  struct GNUNET_CRYPTO_EcdsaSignature *sig;
  struct GNUNET_TIME_Absolute etime_abs;

  // If it's A.a <- B.b...
  if (6 != sscanf (s,
                   "%52s.%253s -> %52s.%253s | %s | %" SCNu64,
                   issuer_pkey,
                   iss_attr,
                   subject_pkey,
                   sub_attr,
                   signature,
                   &etime_abs.abs_value_us))
  {
    // Try if it's A.a <- B
    if (5 != sscanf (s,
                     "%52s.%253s -> %52s | %s | %" SCNu64,
                     issuer_pkey,
                     iss_attr,
                     subject_pkey,
                     signature,
                     &etime_abs.abs_value_us))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  "Unable to parse DEL record string `%s'\n",
                  s);
      return NULL;
    }
  }

  // +1 for \0
  int attr_len;
  if (strcmp (sub_attr, "") == 0)
  {
    attr_len = strlen (iss_attr) + 1;
  }
  else
  {
    attr_len = strlen (iss_attr) + strlen (sub_attr) + 2;
  }
  dele = GNUNET_malloc (sizeof (struct GNUNET_ABD_Delegate) + attr_len);

  char tmp_str[attr_len];
  GNUNET_memcpy (tmp_str, iss_attr, strlen (iss_attr));
  if (strcmp (sub_attr, "") != 0)
  {
    tmp_str[strlen (iss_attr)] = '\0';
    GNUNET_memcpy (tmp_str + strlen (iss_attr) + 1,
                   sub_attr,
                   strlen (sub_attr));
  }
  tmp_str[attr_len - 1] = '\0';

  GNUNET_CRYPTO_ecdsa_public_key_from_string (subject_pkey,
                                              strlen (subject_pkey),
                                              &dele->subject_key);
  GNUNET_CRYPTO_ecdsa_public_key_from_string (issuer_pkey,
                                              strlen (issuer_pkey),
                                              &dele->issuer_key);
  GNUNET_assert (sizeof (struct GNUNET_CRYPTO_EcdsaSignature) ==
                 GNUNET_STRINGS_base64_decode (signature,
                                               strlen (signature),
                                               (void **) &sig));
  dele->signature = *sig;
  dele->expiration = etime_abs;
  GNUNET_free (sig);

  GNUNET_memcpy (&dele[1], tmp_str, attr_len);

  dele->issuer_attribute = (char *) &dele[1];
  dele->issuer_attribute_len = strlen (iss_attr);
  if (strcmp (sub_attr, "") == 0)
  {
    dele->subject_attribute = NULL;
    dele->subject_attribute_len = 0;
  }
  else
  {
    dele->subject_attribute = (char *) &dele[1] + strlen (iss_attr) + 1;
    dele->subject_attribute_len = strlen (sub_attr);
  }

  return dele;
}


/**
 * Issue an attribute to a subject
 *
 * @param issuer the ego that should be used to issue the attribute
 * @param subject the subject of the attribute
 * @param iss_attr the name of the attribute
 * @return handle to the queued request
 */

struct GNUNET_ABD_Delegate *
GNUNET_ABD_delegate_issue (
  const struct GNUNET_CRYPTO_EcdsaPrivateKey *issuer,
  struct GNUNET_CRYPTO_EcdsaPublicKey *subject,
  const char *iss_attr,
  const char *sub_attr,
  struct GNUNET_TIME_Absolute *expiration)
{
  struct DelegateEntry *del;
  struct GNUNET_ABD_Delegate *dele;
  size_t size;
  int attr_len;

  if (NULL == sub_attr)
  {
    // +1 for \0
    attr_len = strlen (iss_attr) + 1;
  }
  else
  {
    // +2 for both strings need to be terminated with \0
    attr_len = strlen (iss_attr) + strlen (sub_attr) + 2;
  }
  size = sizeof (struct DelegateEntry) + attr_len;

  char tmp_str[attr_len];
  GNUNET_memcpy (tmp_str, iss_attr, strlen (iss_attr));
  if (NULL != sub_attr)
  {
    tmp_str[strlen (iss_attr)] = '\0';
    GNUNET_memcpy (tmp_str + strlen (iss_attr) + 1,
                   sub_attr,
                   strlen (sub_attr));
  }
  tmp_str[attr_len - 1] = '\0';

  del = GNUNET_malloc (size);
  del->purpose.size =
    htonl (size - sizeof (struct GNUNET_CRYPTO_EcdsaSignature));
  del->purpose.purpose = htonl (GNUNET_SIGNATURE_PURPOSE_DELEGATE);
  GNUNET_CRYPTO_ecdsa_key_get_public (issuer, &del->issuer_key);
  del->subject_key = *subject;
  del->expiration = GNUNET_htonll (expiration->abs_value_us);
  del->issuer_attribute_len = htonl (strlen (iss_attr) + 1);
  if (NULL == sub_attr)
  {
    del->subject_attribute_len = htonl (0);
  }
  else
  {
    del->subject_attribute_len = htonl (strlen (sub_attr) + 1);
  }

  GNUNET_memcpy (&del[1], tmp_str, attr_len);

  if (GNUNET_OK !=
      GNUNET_CRYPTO_ecdsa_sign (issuer, &del->purpose, &del->signature))
  {
    GNUNET_break (0);
    GNUNET_free (del);
    return NULL;
  }

  dele = GNUNET_malloc (sizeof (struct GNUNET_ABD_Delegate) + attr_len);
  dele->signature = del->signature;
  dele->expiration = *expiration;
  GNUNET_CRYPTO_ecdsa_key_get_public (issuer, &dele->issuer_key);

  dele->subject_key = *subject;

  // Copy the combined string at the part in the memory where the struct ends
  GNUNET_memcpy (&dele[1], tmp_str, attr_len);

  dele->issuer_attribute = (char *) &dele[1];
  dele->issuer_attribute_len = strlen (iss_attr);
  if (NULL == sub_attr)
  {
    dele->subject_attribute = NULL;
    dele->subject_attribute_len = 0;
  }
  else
  {
    dele->subject_attribute = (char *) &dele[1] + strlen (iss_attr) + 1;
    dele->subject_attribute_len = strlen (sub_attr);
  }

  GNUNET_free (del);
  return dele;
}

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
 * @file credential/credential_mic.c
 * @brief Misc API for credentials
 *
 * @author Martin Schanzenbach
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_constants.h"
#include "gnunet_credential_service.h"
#include "gnunet_signatures.h"
#include "credential.h"
#include <inttypes.h>

char*
GNUNET_CREDENTIAL_credential_to_string (const struct GNUNET_CREDENTIAL_Credential *cred)
{
  char *cred_str;
  char *subject_pkey;
  char *issuer_pkey;
  char *signature;


  subject_pkey = GNUNET_CRYPTO_ecdsa_public_key_to_string (&cred->subject_key);
  issuer_pkey = GNUNET_CRYPTO_ecdsa_public_key_to_string (&cred->issuer_key);
  GNUNET_STRINGS_base64_encode ((char*)&cred->signature,
                                sizeof (struct GNUNET_CRYPTO_EcdsaSignature),
                                &signature);
  GNUNET_asprintf (&cred_str,
                   "%s.%s -> %s | %s | %"SCNu64,
                   issuer_pkey,
                   cred->issuer_attribute,
                   subject_pkey,
                   signature,
                   cred->expiration.abs_value_us);
  GNUNET_free (subject_pkey);
  GNUNET_free (issuer_pkey);
  GNUNET_free (signature);
  return cred_str;
}

struct GNUNET_CREDENTIAL_Credential*
GNUNET_CREDENTIAL_credential_from_string (const char* s)
{
  struct GNUNET_CREDENTIAL_Credential *cred;
  size_t enclen = (sizeof (struct GNUNET_CRYPTO_EcdsaPublicKey)) * 8;
  if (enclen % 5 > 0)
    enclen += 5 - enclen % 5;
  enclen /= 5; /* 260/5 = 52 */
  char subject_pkey[enclen + 1];
  char issuer_pkey[enclen + 1];
  char name[253 + 1];
  char signature[256]; //TODO max payload size

  struct GNUNET_CRYPTO_EcdsaSignature *sig;
  struct GNUNET_TIME_Absolute etime_abs;

  if (5 != SSCANF (s,
                   "%52s.%253s -> %52s | %s | %"SCNu64,
                   issuer_pkey,
                   name,
                   subject_pkey,
                   signature,
                   &etime_abs.abs_value_us))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _("Unable to parse CRED record string `%s'\n"),
                s);
    return NULL;
  }
  cred = GNUNET_malloc (sizeof (struct GNUNET_CREDENTIAL_Credential) + strlen (name) + 1);
  GNUNET_CRYPTO_ecdsa_public_key_from_string (subject_pkey,
                                              strlen (subject_pkey),
                                              &cred->subject_key);
  GNUNET_CRYPTO_ecdsa_public_key_from_string (issuer_pkey,
                                              strlen (issuer_pkey),
                                              &cred->issuer_key);
  GNUNET_assert (sizeof (struct GNUNET_CRYPTO_EcdsaSignature) == GNUNET_STRINGS_base64_decode (signature,
                                strlen (signature),
                                (char**)&sig));
  cred->signature = *sig;
  cred->expiration = etime_abs;
  GNUNET_free (sig);
  GNUNET_memcpy (&cred[1],
                 name,
                 strlen (name)+1);
  cred->issuer_attribute_len = strlen ((char*)&cred[1]);
  cred->issuer_attribute = (char*)&cred[1];
  return cred;
}

/**
 * Issue an attribute to a subject
 *
 * @param handle handle to the Credential service
 * @param issuer the ego that should be used to issue the attribute
 * @param subject the subject of the attribute
 * @param attribute the name of the attribute
 * @return handle to the queued request
 */
struct GNUNET_CREDENTIAL_Credential *
GNUNET_CREDENTIAL_credential_issue (const struct GNUNET_CRYPTO_EcdsaPrivateKey *issuer,
                                    struct GNUNET_CRYPTO_EcdsaPublicKey *subject,
                                    const char *attribute,
                                    struct GNUNET_TIME_Absolute *expiration)
{
  struct CredentialEntry *crd;
  struct GNUNET_CREDENTIAL_Credential *cred;
  size_t size;

  size = sizeof (struct CredentialEntry) + strlen (attribute) + 1;
  crd = GNUNET_malloc (size);
  cred = GNUNET_malloc (sizeof (struct GNUNET_CREDENTIAL_Credential) + strlen (attribute) + 1);
  crd->purpose.size = htonl (size - sizeof (struct GNUNET_CRYPTO_EcdsaSignature));

  crd->purpose.purpose = htonl (GNUNET_SIGNATURE_PURPOSE_CREDENTIAL);
  GNUNET_CRYPTO_ecdsa_key_get_public (issuer,
                                      &crd->issuer_key);
  crd->subject_key = *subject;
  crd->expiration = GNUNET_htonll (expiration->abs_value_us);
  crd->issuer_attribute_len = htonl (strlen (attribute)+1);
  GNUNET_memcpy ((char*)&crd[1],
                 attribute,
                 strlen (attribute)+1);
  if (GNUNET_OK !=
      GNUNET_CRYPTO_ecdsa_sign (issuer,
                                &crd->purpose,
                                &crd->signature))
  {
    GNUNET_break (0);
    GNUNET_free (crd);
    return NULL;
  }
  cred->signature = crd->signature;
  cred->expiration = *expiration;
  GNUNET_CRYPTO_ecdsa_key_get_public (issuer,
                                      &cred->issuer_key);

  cred->subject_key = *subject;
  GNUNET_memcpy (&cred[1],
                 attribute,
                 strlen (attribute)+1);
  cred->issuer_attribute = (char*)&cred[1];
  GNUNET_free (crd);
  return cred;
}



/*
      This file is part of GNUnet
      Copyright (C) 2010-2015 GNUnet e.V.

      GNUnet is free software: you can redistribute it and/or modify it
      under the terms of the GNU General Public License as published
      by the Free Software Foundation, either version 3 of the License,
      or (at your option) any later version.

      GNUnet is distributed in the hope that it will be useful, but
      WITHOUT ANY WARRANTY; without even the implied warranty of
      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
      Affero General Public License for more details.
 */

/**
 * @file identity-provider/jwt.c
 * @brief helper library for JSON-Web-Tokens
 * @author Martin Schanzenbach
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_signatures.h"
#include "gnunet_identity_attribute_lib.h"
#include <jansson.h>


#define JWT_ALG "alg"

/*TODO is this the correct way to define new algs? */
#define JWT_ALG_VALUE "urn:org:gnunet:jwt:alg:ecdsa:ed25519"

#define JWT_TYP "typ"

#define JWT_TYP_VALUE "jwt"

//TODO change server address
#define SERVER_ADDRESS "https://localhost"

static char*
create_jwt_header(void)
{
  json_t *root;
  char *json_str;

  root = json_object ();
  json_object_set_new (root, JWT_ALG, json_string (JWT_ALG_VALUE));
  json_object_set_new (root, JWT_TYP, json_string (JWT_TYP_VALUE));

  json_str = json_dumps (root, JSON_INDENT(1));
  json_decref (root);
  return json_str;
}

/**
 * Create a JWT from attributes
 *
 * @param aud_key the public of the subject
 * @param attrs the attribute list
 * @param priv_key the key used to sign the JWT
 * @return a new base64-encoded JWT string.
 */
char*
jwt_create_from_list (const struct GNUNET_CRYPTO_EcdsaPublicKey *aud_key,
                                                const struct GNUNET_IDENTITY_ATTRIBUTE_ClaimList *attrs,
                                                const struct GNUNET_CRYPTO_EcdsaPrivateKey *priv_key)
{
  struct GNUNET_IDENTITY_ATTRIBUTE_ClaimListEntry *le;
  struct GNUNET_CRYPTO_EcdsaPublicKey sub_key;
  struct GNUNET_CRYPTO_EcdsaSignature signature;
  struct GNUNET_CRYPTO_EccSignaturePurpose *purpose;
  char* audience;
  char* subject;
  char* header;
  char* padding;
  char* body_str;
  char* result;
  char* header_base64;
  char* body_base64;
  char* signature_target;
  char* signature_base64;
  char* attr_val_str;
  json_t* body;

  //exp REQUIRED time expired from config
  //iat REQUIRED time now
  //auth_time only if max_age
  //nonce only if nonce
  // OPTIONAL acr,amr,azp
  GNUNET_CRYPTO_ecdsa_key_get_public (priv_key, &sub_key);
  /* TODO maybe we should use a local identity here */
  subject = GNUNET_STRINGS_data_to_string_alloc (&sub_key,
                                                sizeof (struct GNUNET_CRYPTO_EcdsaPublicKey));
  audience = GNUNET_STRINGS_data_to_string_alloc (aud_key,
                                                  sizeof (struct GNUNET_CRYPTO_EcdsaPublicKey));
  header = create_jwt_header ();
  body = json_object ();
  /* TODO who is the issuer? local IdP or subject ? See self-issued tokens? */
  //iss REQUIRED case sensitive server uri with https
  json_object_set_new (body,
                       "iss", json_string (SERVER_ADDRESS));
  //sub REQUIRED public key identity, not exceed 255 ASCII  length
  json_object_set_new (body,
                       "sub", json_string (subject));
  /* TODO what should be in here exactly? */
  //aud REQUIRED public key client_id must be there
  json_object_set_new (body,
                       "aud", json_string (audience));
  for (le = attrs->list_head; NULL != le; le = le->next)
  {
    /**
     * TODO here we should have a function that
     * calls the Attribute plugins to create a
     * json representation for its value
     */
    attr_val_str = GNUNET_IDENTITY_ATTRIBUTE_value_to_string (le->claim->type,
                                                              le->claim->data,
                                                              le->claim->data_size);
    json_object_set_new (body,
                         le->claim->name,
                         json_string (attr_val_str));
    GNUNET_free (attr_val_str);
  }
  body_str = json_dumps (body, JSON_INDENT(0));
  json_decref (body);

  GNUNET_STRINGS_base64_encode (header,
                                strlen (header),
                                &header_base64);
  //Remove GNUNET padding of base64
  padding = strtok(header_base64, "=");
  while (NULL != padding)
    padding = strtok(NULL, "=");

  GNUNET_STRINGS_base64_encode (body_str,
                                strlen (body_str),
                                &body_base64);

  //Remove GNUNET padding of base64
  padding = strtok(body_base64, "=");
  while (NULL != padding)
    padding = strtok(NULL, "=");

  GNUNET_free (subject);
  GNUNET_free (audience);

  /**
   * TODO
   * Creating the JWT signature. This might not be
   * standards compliant, check.
   */
  GNUNET_asprintf (&signature_target, "%s,%s", header_base64, body_base64);

  purpose =
    GNUNET_malloc (sizeof (struct GNUNET_CRYPTO_EccSignaturePurpose) +
                   strlen (signature_target));
  purpose->size =
    htonl (strlen (signature_target) + sizeof (struct GNUNET_CRYPTO_EccSignaturePurpose));
  purpose->purpose = htonl(GNUNET_SIGNATURE_PURPOSE_GNUID_TOKEN);
  GNUNET_memcpy (&purpose[1], signature_target, strlen (signature_target));
  if (GNUNET_OK != GNUNET_CRYPTO_ecdsa_sign (priv_key,
                                             purpose,
                                             (struct GNUNET_CRYPTO_EcdsaSignature *)&signature))
  {
    GNUNET_free (signature_target);
    GNUNET_free (body_str);
    GNUNET_free (body_base64);
    GNUNET_free (header_base64);
    GNUNET_free (purpose);
    return NULL;
  }
  GNUNET_STRINGS_base64_encode ((const char*)&signature,
                                sizeof (struct GNUNET_CRYPTO_EcdsaSignature),
                                &signature_base64);
  GNUNET_asprintf (&result, "%s.%s.%s",
                   header_base64, body_base64, signature_base64);

  GNUNET_free (signature_target);
  GNUNET_free (header);
  GNUNET_free (body_str);
  GNUNET_free (signature_base64);
  GNUNET_free (body_base64);
  GNUNET_free (header_base64);
  GNUNET_free (purpose);
  return result;
}

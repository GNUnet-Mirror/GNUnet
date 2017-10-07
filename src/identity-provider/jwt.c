/*
      This file is part of GNUnet
      Copyright (C) 2010-2015 GNUnet e.V.

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
 * @file identity-provider/jwt.c
 * @brief helper library for JSON-Web-Tokens
 * @author Martin Schanzenbach
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_signatures.h"
#include "identity_attribute.h"
#include <jansson.h>


#define JWT_ALG "alg"

/*TODO is this the correct way to define new algs? */
#define JWT_ALG_VALUE "ED512"

#define JWT_TYP "typ"

#define JWT_TYP_VALUE "jwt"

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
 * Create a JWT from a ticket and attributes
 *
 * @param ticket the ticket
 * @param attrs the attribute list
 * @return a new base64-encoded JWT string.
 */
char*
jwt_create (const struct GNUNET_IDENTITY_PROVIDER_Ticket *ticket,
            const struct GNUNET_IDENTITY_PROVIDER_AttributeList *attrs,
            const struct GNUNET_CRYPTO_EcdsaPrivateKey *priv_key)
{
  struct GNUNET_IDENTITY_PROVIDER_AttributeListEntry *le;
  struct GNUNET_CRYPTO_EcdsaSignature signature;
  struct GNUNET_CRYPTO_EccSignaturePurpose *purpose;
  char* audience;
  char* issuer;
  char* header;
  char* padding;
  char* body_str;
  char* result;
  char* header_base64;
  char* body_base64;
  char* signature_target;
  char* signature_base64;
  json_t* body;

  /* TODO maybe we should use a local identity here */
  issuer = GNUNET_STRINGS_data_to_string_alloc (&ticket->identity,
                                                sizeof (struct GNUNET_CRYPTO_EcdsaPublicKey));
  audience = GNUNET_STRINGS_data_to_string_alloc (&ticket->audience,
                                                  sizeof (struct GNUNET_CRYPTO_EcdsaPublicKey));
  header = create_jwt_header ();
  body = json_object ();
  /* TODO who is the issuer? local IdP or subject ? See self-issued tokens? */
  json_object_set_new (body,
                       "iss", json_string (issuer));
  json_object_set_new (body,
                       "sub", json_string (issuer));
  /* TODO what should be in here exactly? */
  json_object_set_new (body,
                       "aud", json_string (audience));
  for (le = attrs->list_head; NULL != le; le = le->next)
  {
    /**
     * TODO here we should have a function that
     * calls the Attribute plugins to create a
     * json representation for its value
     */
    json_object_set_new (body,
                         le->attribute->name,
                         json_string (le->attribute->data));
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

  GNUNET_free (issuer);
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

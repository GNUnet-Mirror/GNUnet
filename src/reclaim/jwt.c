/*
      This file is part of GNUnet
      Copyright (C) 2010-2015 GNUnet e.V.

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
 */

/**
 * @file reclaim/jwt.c
 * @brief helper library for JSON-Web-Tokens
 * @author Martin Schanzenbach
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_signatures.h"
#include "gnunet_reclaim_attribute_lib.h"
#include <jansson.h>


#define JWT_ALG "alg"

/* Use 512bit HMAC */
#define JWT_ALG_VALUE "HS512"

#define JWT_TYP "typ"

#define JWT_TYP_VALUE "jwt"

#define SERVER_ADDRESS "https://reclaim.id"

static char*
create_jwt_header(void)
{
  json_t *root;
  char *json_str;

  root = json_object ();
  json_object_set_new (root, JWT_ALG, json_string (JWT_ALG_VALUE));
  json_object_set_new (root, JWT_TYP, json_string (JWT_TYP_VALUE));

  json_str = json_dumps (root, JSON_INDENT(0) | JSON_COMPACT);
  json_decref (root);
  return json_str;
}

static void
replace_char(char* str, char find, char replace){
  char *current_pos = strchr(str,find);
  while (current_pos){
    *current_pos = replace;
    current_pos = strchr(current_pos,find);
  }
}

//RFC4648
static void
fix_base64(char* str) {
  char *padding;
  //First, remove trailing padding '='
  padding = strtok(str, "=");
  while (NULL != padding)
    padding = strtok(NULL, "=");

  //Replace + with -
  replace_char (str, '+', '-');

  //Replace / with _
  replace_char (str, '/', '_');

}

/**
 * Create a JWT from attributes
 *
 * @param aud_key the public of the audience
 * @param sub_key the public key of the subject
 * @param attrs the attribute list
 * @param expiration_time the validity of the token
 * @param secret_key the key used to sign the JWT
 * @return a new base64-encoded JWT string.
 */
char*
jwt_create_from_list (const struct GNUNET_CRYPTO_EcdsaPublicKey *aud_key,
                      const struct GNUNET_CRYPTO_EcdsaPublicKey *sub_key,
                      const struct GNUNET_RECLAIM_ATTRIBUTE_ClaimList *attrs,
                      const struct GNUNET_TIME_Relative *expiration_time,
                      const char *nonce,
                      const char *secret_key)
{
  struct GNUNET_RECLAIM_ATTRIBUTE_ClaimListEntry *le;
  struct GNUNET_HashCode signature;
  struct GNUNET_TIME_Absolute exp_time;
  struct GNUNET_TIME_Absolute time_now;
  char* audience;
  char* subject;
  char* header;
  char* body_str;
  char* result;
  char* header_base64;
  char* body_base64;
  char* signature_target;
  char* signature_base64;
  char* attr_val_str;
  json_t* body;
  
  //iat REQUIRED time now
  time_now = GNUNET_TIME_absolute_get();
  //exp REQUIRED time expired from config
  exp_time = GNUNET_TIME_absolute_add (time_now, *expiration_time);
  //auth_time only if max_age
  //nonce only if nonce
  // OPTIONAL acr,amr,azp
  subject = GNUNET_STRINGS_data_to_string_alloc (sub_key,
                                                 sizeof (struct GNUNET_CRYPTO_EcdsaPublicKey));
  audience = GNUNET_STRINGS_data_to_string_alloc (aud_key,
                                                  sizeof (struct GNUNET_CRYPTO_EcdsaPublicKey));
  header = create_jwt_header ();
  body = json_object ();

  //iss REQUIRED case sensitive server uri with https
  //The issuer is the local reclaim instance (e.g. https://reclaim.id/api/openid)
  json_object_set_new (body,
                       "iss", json_string (SERVER_ADDRESS));
  //sub REQUIRED public key identity, not exceed 255 ASCII  length
  json_object_set_new (body,
                       "sub", json_string (subject));
  //aud REQUIRED public key client_id must be there
  json_object_set_new (body,
                       "aud", json_string (audience));
  //iat
  json_object_set_new (body,
                       "iat", json_integer (time_now.abs_value_us / (1000*1000)));
  //exp
  json_object_set_new (body,
                       "exp", json_integer (exp_time.abs_value_us / (1000*1000)));
  //nbf
  json_object_set_new (body,
                       "nbf", json_integer (time_now.abs_value_us / (1000*1000)));
  //nonce
  if (NULL != nonce)
    json_object_set_new (body,
                         "nonce", json_string (nonce));

  for (le = attrs->list_head; NULL != le; le = le->next)
  {
    attr_val_str = GNUNET_RECLAIM_ATTRIBUTE_value_to_string (le->claim->type,
                                                             le->claim->data,
                                                             le->claim->data_size);
    json_object_set_new (body,
                         le->claim->name,
                         json_string (attr_val_str));
    GNUNET_free (attr_val_str);
  }
  body_str = json_dumps (body, JSON_INDENT(0) | JSON_COMPACT);
  json_decref (body);

  GNUNET_STRINGS_base64_encode (header,
                                strlen (header),
                                &header_base64);
  fix_base64(header_base64);

  GNUNET_STRINGS_base64_encode (body_str,
                                strlen (body_str),
                                &body_base64);
  fix_base64(body_base64);

  GNUNET_free (subject);
  GNUNET_free (audience);

  /**
   * Creating the JWT signature. This might not be
   * standards compliant, check.
   */
  GNUNET_asprintf (&signature_target, "%s.%s", header_base64, body_base64);
  GNUNET_CRYPTO_hmac_raw (secret_key, strlen (secret_key), signature_target, strlen (signature_target), &signature);
  GNUNET_STRINGS_base64_encode ((const char*)&signature,
                                sizeof (struct GNUNET_HashCode),
                                &signature_base64);
  fix_base64(signature_base64);

  GNUNET_asprintf (&result, "%s.%s.%s",
                   header_base64, body_base64, signature_base64);

  GNUNET_free (signature_target);
  GNUNET_free (header);
  GNUNET_free (body_str);
  GNUNET_free (signature_base64);
  GNUNET_free (body_base64);
  GNUNET_free (header_base64);
  return result;
}

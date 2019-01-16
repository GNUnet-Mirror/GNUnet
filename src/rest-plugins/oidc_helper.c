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

     SPDX-License-Identifier: AGPL3.0-or-later
 */

/**
 * @file reclaim/oidc_helper.c
 * @brief helper library for OIDC related functions
 * @author Martin Schanzenbach
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_signatures.h"
#include "gnunet_reclaim_service.h"
#include "gnunet_reclaim_attribute_lib.h"
#include <jansson.h>
#include <inttypes.h>
#include "oidc_helper.h"

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
OIDC_id_token_new (const struct GNUNET_CRYPTO_EcdsaPublicKey *aud_key,
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
/**
 * Builds an OIDC authorization code including
 * a reclaim ticket and nonce
 *
 * @param issuer the issuer of the ticket, used to sign the ticket and nonce
 * @param ticket the ticket to include in the code
 * @param nonce the nonce to include in the code
 * @return a new authorization code (caller must free)
 */
char*
OIDC_build_authz_code (const struct GNUNET_CRYPTO_EcdsaPrivateKey *issuer,
                       const struct GNUNET_RECLAIM_Ticket *ticket,
                       const char* nonce)
{
  char *ticket_str;
  json_t *code_json;
  char *signature_payload;
  char *signature_str;
  char *authz_code;
  size_t signature_payload_len;
  struct GNUNET_CRYPTO_EcdsaSignature signature;
  struct GNUNET_CRYPTO_EccSignaturePurpose *purpose;

  signature_payload_len = sizeof (struct GNUNET_RECLAIM_Ticket);
  if (NULL != nonce)
    signature_payload_len += strlen (nonce);

  signature_payload = GNUNET_malloc (sizeof (struct GNUNET_CRYPTO_EccSignaturePurpose) + signature_payload_len);
  purpose = (struct GNUNET_CRYPTO_EccSignaturePurpose *)signature_payload;
  purpose->size = htonl (sizeof (struct GNUNET_CRYPTO_EccSignaturePurpose) + signature_payload_len);
  purpose->purpose = htonl (GNUNET_SIGNATURE_PURPOSE_RECLAIM_CODE_SIGN);
  memcpy (&purpose[1],
          ticket,
          sizeof (struct GNUNET_RECLAIM_Ticket));
  if (NULL != nonce)
    memcpy (((char*)&purpose[1]) + sizeof (struct GNUNET_RECLAIM_Ticket),
            nonce,
            strlen (nonce));
  if (GNUNET_SYSERR == GNUNET_CRYPTO_ecdsa_sign (issuer,
                                                 purpose,
                                                 &signature))
  {
    GNUNET_free (signature_payload);
    return NULL;
  }
  signature_str = GNUNET_STRINGS_data_to_string_alloc (&signature,
                                                       sizeof (signature));
  ticket_str = GNUNET_STRINGS_data_to_string_alloc (ticket,
                                                    sizeof (struct GNUNET_RECLAIM_Ticket));

  code_json = json_object ();
  json_object_set_new (code_json,
                       "ticket",
                       json_string (ticket_str));
  if (NULL != nonce)
    json_object_set_new (code_json,
                         "nonce",
                         json_string (nonce));
  json_object_set_new (code_json,
                       "signature",
                       json_string (signature_str));
  authz_code = json_dumps (code_json,
                           JSON_INDENT(0) | JSON_COMPACT);
  GNUNET_free (signature_payload);
  GNUNET_free (signature_str);
  GNUNET_free (ticket_str);
  json_decref (code_json);
  return authz_code;
}




/**
 * Parse reclaim ticket and nonce from
 * authorization code.
 * This also verifies the signature in the code.
 *
 * @param audience the expected audience of the code
 * @param code the string representation of the code
 * @param ticket where to store the ticket
 * @param nonce where to store the nonce
 * @return GNUNET_OK if successful, else GNUNET_SYSERR
 */
int
OIDC_parse_authz_code (const struct GNUNET_CRYPTO_EcdsaPublicKey *audience,
                       const char* code,
                       struct GNUNET_RECLAIM_Ticket **ticket,
                       char **nonce)
{
  json_error_t error;
  json_t *code_json;
  json_t *ticket_json;
  json_t *nonce_json;
  json_t *signature_json;
  const char *ticket_str;
  const char *signature_str;
  const char *nonce_str;
  char *code_output;
  struct GNUNET_CRYPTO_EccSignaturePurpose *purpose;
  struct GNUNET_CRYPTO_EcdsaSignature signature;
  size_t signature_payload_len;

  code_output = NULL; 
  GNUNET_STRINGS_base64_decode (code,
                                strlen(code),
                                (void**)&code_output);
  code_json = json_loads (code_output, 0 , &error);
  GNUNET_free (code_output);
  ticket_json = json_object_get (code_json, "ticket");
  nonce_json = json_object_get (code_json, "nonce");
  signature_json = json_object_get (code_json, "signature");
  *ticket = NULL;
  *nonce = NULL;

  if ((NULL == ticket_json || !json_is_string (ticket_json)) ||
      (NULL == signature_json || !json_is_string (signature_json)))
  {
    json_decref (code_json);
    return GNUNET_SYSERR;
  }
  ticket_str = json_string_value (ticket_json);
  signature_str = json_string_value (signature_json);
  nonce_str = NULL;
  if (NULL != nonce_json)
    nonce_str = json_string_value (nonce_json);
  signature_payload_len = sizeof (struct GNUNET_RECLAIM_Ticket);
  if (NULL != nonce_str)
    signature_payload_len += strlen (nonce_str);
  purpose = GNUNET_malloc (sizeof (struct GNUNET_CRYPTO_EccSignaturePurpose) +
                           signature_payload_len);
  purpose->size = htonl (sizeof (struct GNUNET_CRYPTO_EccSignaturePurpose) + signature_payload_len);
  purpose->purpose = htonl (GNUNET_SIGNATURE_PURPOSE_RECLAIM_CODE_SIGN);
  if (GNUNET_OK != GNUNET_STRINGS_string_to_data (ticket_str,
                                                  strlen (ticket_str),
                                                  &purpose[1],
                                                  sizeof (struct GNUNET_RECLAIM_Ticket)))
  {
    GNUNET_free (purpose);
    json_decref (code_json);
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Cannot parse ticket!\n");
    return GNUNET_SYSERR;
  }
  if (GNUNET_OK != GNUNET_STRINGS_string_to_data (signature_str,
                                                  strlen (signature_str),
                                                  &signature,
                                                  sizeof (struct GNUNET_CRYPTO_EcdsaSignature)))
  {
    GNUNET_free (purpose);
    json_decref (code_json);
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Cannot parse signature!\n");
    return GNUNET_SYSERR;
  }
  *ticket = GNUNET_new (struct GNUNET_RECLAIM_Ticket);
  memcpy (*ticket,
          &purpose[1],
          sizeof (struct GNUNET_RECLAIM_Ticket));
  if (0 != memcmp (audience,
                   &(*ticket)->audience,
                   sizeof (struct GNUNET_CRYPTO_EcdsaPublicKey)))
  {
    GNUNET_free (purpose);
    GNUNET_free (*ticket);
    json_decref (code_json);
    *ticket = NULL;
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Audience in ticket does not match client!\n");
    return GNUNET_SYSERR;

  }
  if (NULL != nonce_str)
    memcpy (((char*)&purpose[1]) + sizeof (struct GNUNET_RECLAIM_Ticket),
            nonce_str,
            strlen (nonce_str));
  if (GNUNET_OK != GNUNET_CRYPTO_ecdsa_verify (GNUNET_SIGNATURE_PURPOSE_RECLAIM_CODE_SIGN,
                                               purpose,
                                               &signature,
                                               &(*ticket)->identity))
  {
    GNUNET_free (purpose);
    GNUNET_free (*ticket);
    json_decref (code_json);
    *ticket = NULL;
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Signature of authZ code invalid!\n");
    return GNUNET_SYSERR;
  }
  *nonce = GNUNET_strdup (nonce_str);
  return GNUNET_OK;
}

/**
 * Build a token response for a token request
 * TODO: Maybe we should add the scope here?
 *
 * @param access_token the access token to include
 * @param id_token the id_token to include
 * @param expiration_time the expiration time of the token(s)
 * @param token_response where to store the response
 */
void
OIDC_build_token_response (const char *access_token,
                           const char *id_token,
                           const struct GNUNET_TIME_Relative *expiration_time,
                           char **token_response)
{
  json_t *root_json;

  root_json = json_object ();

  GNUNET_assert (NULL != access_token);
  GNUNET_assert (NULL != id_token);
  GNUNET_assert (NULL != expiration_time);
  json_object_set_new (root_json,
                       "access_token",
                       json_string (access_token));
  json_object_set_new (root_json,
                       "token_type",
                       json_string ("Bearer"));
  json_object_set_new (root_json,
                       "expires_in",
                       json_integer (expiration_time->rel_value_us / (1000 * 1000)));
  json_object_set_new (root_json,
                       "id_token",
                       json_string (id_token));
  *token_response = json_dumps (root_json,
                                JSON_INDENT(0) | JSON_COMPACT);
  json_decref (root_json);
}

/**
 * Generate a new access token
 */
char*
OIDC_access_token_new ()
{
  char* access_token_number;
  char* access_token;
  uint64_t random_number;

  random_number = GNUNET_CRYPTO_random_u64(GNUNET_CRYPTO_QUALITY_NONCE, UINT64_MAX);
  GNUNET_asprintf (&access_token_number, "%" PRIu64, random_number);
  GNUNET_STRINGS_base64_encode(access_token_number,strlen(access_token_number),&access_token);
  return access_token;
}

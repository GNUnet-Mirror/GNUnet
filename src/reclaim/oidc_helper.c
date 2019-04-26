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
#include <inttypes.h>
#include <jansson.h>

#include "gnunet_util_lib.h"

#include "gnunet_reclaim_attribute_lib.h"
#include "gnunet_reclaim_service.h"
#include "gnunet_signatures.h"
#include "oidc_helper.h"
static char *
create_jwt_header (void)
{
  json_t *root;
  char *json_str;

  root = json_object ();
  json_object_set_new (root, JWT_ALG, json_string (JWT_ALG_VALUE));
  json_object_set_new (root, JWT_TYP, json_string (JWT_TYP_VALUE));

  json_str = json_dumps (root, JSON_INDENT (0) | JSON_COMPACT);
  json_decref (root);
  return json_str;
}

static void
replace_char (char *str, char find, char replace)
{
  char *current_pos = strchr (str, find);
  while (current_pos)
  {
    *current_pos = replace;
    current_pos = strchr (current_pos, find);
  }
}

// RFC4648
static void
fix_base64 (char *str)
{
  // Replace + with -
  replace_char (str, '+', '-');

  // Replace / with _
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
char *
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
  char *audience;
  char *subject;
  char *header;
  char *body_str;
  char *result;
  char *header_base64;
  char *body_base64;
  char *signature_target;
  char *signature_base64;
  char *attr_val_str;
  json_t *body;

  // iat REQUIRED time now
  time_now = GNUNET_TIME_absolute_get ();
  // exp REQUIRED time expired from config
  exp_time = GNUNET_TIME_absolute_add (time_now, *expiration_time);
  // auth_time only if max_age
  // nonce only if nonce
  // OPTIONAL acr,amr,azp
  subject = GNUNET_STRINGS_data_to_string_alloc (
    sub_key,
    sizeof (struct GNUNET_CRYPTO_EcdsaPublicKey));
  audience = GNUNET_STRINGS_data_to_string_alloc (
    aud_key,
    sizeof (struct GNUNET_CRYPTO_EcdsaPublicKey));
  header = create_jwt_header ();
  body = json_object ();

  // iss REQUIRED case sensitive server uri with https
  // The issuer is the local reclaim instance (e.g.
  // https://reclaim.id/api/openid)
  json_object_set_new (body, "iss", json_string (SERVER_ADDRESS));
  // sub REQUIRED public key identity, not exceed 255 ASCII  length
  json_object_set_new (body, "sub", json_string (subject));
  // aud REQUIRED public key client_id must be there
  json_object_set_new (body, "aud", json_string (audience));
  // iat
  json_object_set_new (body,
                       "iat",
                       json_integer (time_now.abs_value_us / (1000 * 1000)));
  // exp
  json_object_set_new (body,
                       "exp",
                       json_integer (exp_time.abs_value_us / (1000 * 1000)));
  // nbf
  json_object_set_new (body,
                       "nbf",
                       json_integer (time_now.abs_value_us / (1000 * 1000)));
  // nonce
  if (NULL != nonce)
    json_object_set_new (body, "nonce", json_string (nonce));

  for (le = attrs->list_head; NULL != le; le = le->next)
  {
    attr_val_str =
      GNUNET_RECLAIM_ATTRIBUTE_value_to_string (le->claim->type,
                                                le->claim->data,
                                                le->claim->data_size);
    json_object_set_new (body, le->claim->name, json_string (attr_val_str));
    GNUNET_free (attr_val_str);
  }
  body_str = json_dumps (body, JSON_INDENT (0) | JSON_COMPACT);
  json_decref (body);

  GNUNET_STRINGS_base64_encode (header, strlen (header), &header_base64);
  fix_base64 (header_base64);

  GNUNET_STRINGS_base64_encode (body_str, strlen (body_str), &body_base64);
  fix_base64 (body_base64);

  GNUNET_free (subject);
  GNUNET_free (audience);

  /**
   * Creating the JWT signature. This might not be
   * standards compliant, check.
   */
  GNUNET_asprintf (&signature_target, "%s.%s", header_base64, body_base64);
  GNUNET_CRYPTO_hmac_raw (secret_key,
                          strlen (secret_key),
                          signature_target,
                          strlen (signature_target),
                          &signature);
  GNUNET_STRINGS_base64_encode ((const char *) &signature,
                                sizeof (struct GNUNET_HashCode),
                                &signature_base64);
  fix_base64 (signature_base64);

  GNUNET_asprintf (&result,
                   "%s.%s.%s",
                   header_base64,
                   body_base64,
                   signature_base64);

  GNUNET_free (signature_target);
  GNUNET_free (header);
  GNUNET_free (body_str);
  GNUNET_free (signature_base64);
  GNUNET_free (body_base64);
  GNUNET_free (header_base64);
  return result;
}


/**
 * Returns base64 encoded string urlencoded
 *
 * @param string the string to encode
 * @return base64 encoded string
 */
static char *
base64_encode (const char *data,
               size_t data_size)
{
  char *enc;
  char *enc_urlencode;
  char *tmp;
  int i;
  int num_pads = 0;

  GNUNET_STRINGS_base64_encode (data, data_size, &enc);
  tmp = strchr (enc, '=');
  num_pads = strlen (enc) - (tmp - enc);
  GNUNET_assert ((3 > num_pads) && (0 <= num_pads));
  if (0 == num_pads)
    return enc;
  enc_urlencode = GNUNET_malloc (strlen (enc) + num_pads * 2);
  strcpy (enc_urlencode, enc);
  GNUNET_free (enc);
  tmp = strchr (enc_urlencode, '=');
  for (i = 0; i < num_pads; i++) {
    strcpy (tmp, "%3D"); // replace '=' with '%3D'
    tmp += 3;
  }
  return enc_urlencode;
}




/**
 * Builds an OIDC authorization code including
 * a reclaim ticket and nonce
 *
 * @param issuer the issuer of the ticket, used to sign the ticket and nonce
 * @param ticket the ticket to include in the code
 * @param attrs list of attributes whicha re shared
 * @param nonce the nonce to include in the code
 * @return a new authorization code (caller must free)
 */
char *
OIDC_build_authz_code (const struct GNUNET_CRYPTO_EcdsaPrivateKey *issuer,
                       const struct GNUNET_RECLAIM_Ticket *ticket,
                       struct GNUNET_RECLAIM_ATTRIBUTE_ClaimList *attrs,
                       const char *nonce_str)
{
  char *code_payload;
  char *attrs_ser;
  char *code_str;
  char *buf_ptr;
  size_t signature_payload_len;
  size_t attr_list_len;
  size_t code_payload_len;
  unsigned int nonce;
  unsigned int nonce_tmp;
  struct GNUNET_CRYPTO_EcdsaSignature signature;
  struct GNUNET_CRYPTO_EccSignaturePurpose *purpose;

  attrs_ser = NULL;
  signature_payload_len =
    sizeof (struct GNUNET_RECLAIM_Ticket) + sizeof (unsigned int);
  if (NULL != attrs)
  {
    attr_list_len = GNUNET_RECLAIM_ATTRIBUTE_list_serialize_get_size (attrs);
    signature_payload_len += attr_list_len;
    attrs_ser = GNUNET_malloc (attr_list_len);
    GNUNET_RECLAIM_ATTRIBUTE_list_serialize (attrs, attrs_ser);
  }
  code_payload_len = sizeof (struct GNUNET_CRYPTO_EccSignaturePurpose) +
                     signature_payload_len + sizeof (signature);
  code_payload = GNUNET_malloc (code_payload_len);
  purpose = (struct GNUNET_CRYPTO_EccSignaturePurpose *) code_payload;
  purpose->size = htonl (sizeof (struct GNUNET_CRYPTO_EccSignaturePurpose) +
                         signature_payload_len);
  purpose->purpose = htonl (GNUNET_SIGNATURE_PURPOSE_RECLAIM_CODE_SIGN);
  // First, copy ticket
  buf_ptr = (char *) &purpose[1];
  memcpy (buf_ptr, ticket, sizeof (struct GNUNET_RECLAIM_Ticket));
  buf_ptr += sizeof (struct GNUNET_RECLAIM_Ticket);
  // Then copy nonce
  nonce = 0;
  if (NULL != nonce_str)
  {
    if ((1 != SSCANF (nonce_str, "%u", &nonce)) || (nonce > UINT16_MAX))
    {
      GNUNET_free (code_payload);
      GNUNET_free_non_null (attrs_ser);
      return NULL;
    }
  }
  nonce_tmp = htons (nonce);
  memcpy (buf_ptr, &nonce_tmp, sizeof (unsigned int));
  buf_ptr += sizeof (unsigned int);
  // Finally, attributes
  if (NULL != attrs_ser)
  {
    memcpy (buf_ptr, attrs_ser, attr_list_len);
    buf_ptr += attr_list_len;
  }
  if (GNUNET_SYSERR == GNUNET_CRYPTO_ecdsa_sign (issuer, purpose, &signature))
  {
    GNUNET_free (code_payload);
    GNUNET_free_non_null (attrs_ser);
    return NULL;
  }
  memcpy (buf_ptr, &signature, sizeof (signature));
  code_str = base64_encode ((const char *) &code_payload,
                            code_payload_len);
  GNUNET_free (code_payload);
  GNUNET_free_non_null (attrs_ser);
  return code_str;
}


/**
 * Parse reclaim ticket and nonce from
 * authorization code.
 * This also verifies the signature in the code.
 *
 * @param audience the expected audience of the code
 * @param code the string representation of the code
 * @param ticket where to store the ticket
 * @param attrs the attributes in the code
 * @param nonce where to store the nonce
 * @return GNUNET_OK if successful, else GNUNET_SYSERR
 */
int
OIDC_parse_authz_code (const struct GNUNET_CRYPTO_EcdsaPublicKey *audience,
                       const char *code,
                       struct GNUNET_RECLAIM_Ticket *ticket,
                       struct GNUNET_RECLAIM_ATTRIBUTE_ClaimList **attrs,
                       char **nonce_str)
{
  char *code_payload;
  char *attrs_ser;
  char *ptr;
  struct GNUNET_CRYPTO_EccSignaturePurpose *purpose;
  struct GNUNET_CRYPTO_EcdsaSignature *signature;
  size_t code_payload_len;
  size_t attrs_ser_len;
  size_t signature_offset;
  unsigned int nonce;

  code_payload = NULL;
  code_payload_len =
    GNUNET_STRINGS_base64_decode (code, strlen (code), (void **) &code_payload);
  purpose = (struct GNUNET_CRYPTO_EccSignaturePurpose *) code_payload;
  attrs_ser_len = code_payload_len;
  attrs_ser_len -= sizeof (struct GNUNET_CRYPTO_EccSignaturePurpose);
  *ticket = *((struct GNUNET_RECLAIM_Ticket*) &purpose[1]);
  attrs_ser_len -= sizeof (struct GNUNET_RECLAIM_Ticket);
  nonce = ntohs (((unsigned int *) &ticket[1]));
  attrs_ser_len -= sizeof (unsigned int);
  ptr = code_payload;
  signature_offset =
    code_payload_len - sizeof (struct GNUNET_CRYPTO_EcdsaSignature);
  signature = (struct GNUNET_CRYPTO_EcdsaSignature *)&ptr[signature_offset];
  attrs_ser_len -= sizeof (struct GNUNET_CRYPTO_EcdsaSignature);
  attrs_ser = ((char *) &ticket[1]) + sizeof (unsigned int);
  *attrs = GNUNET_RECLAIM_ATTRIBUTE_list_deserialize (attrs_ser, attrs_ser_len);
  if (0 != GNUNET_memcmp (audience, &ticket->audience))
  {
    GNUNET_RECLAIM_ATTRIBUTE_list_destroy (*attrs);
    GNUNET_free (code_payload);
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Audience in ticket does not match client!\n");
    return GNUNET_SYSERR;
  }
  if (GNUNET_OK !=
      GNUNET_CRYPTO_ecdsa_verify (GNUNET_SIGNATURE_PURPOSE_RECLAIM_CODE_SIGN,
                                  purpose,
                                  signature,
                                  &ticket->identity))
  {
    GNUNET_RECLAIM_ATTRIBUTE_list_destroy (*attrs);
    GNUNET_free (code_payload);
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Signature of AuthZ code invalid!\n");
    return GNUNET_SYSERR;
  }
  *nonce_str = NULL;
  if (nonce != 0)
    GNUNET_asprintf (nonce_str, "%u", nonce);
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
  json_object_set_new (root_json, "access_token", json_string (access_token));
  json_object_set_new (root_json, "token_type", json_string ("Bearer"));
  json_object_set_new (
    root_json,
    "expires_in",
    json_integer (expiration_time->rel_value_us / (1000 * 1000)));
  json_object_set_new (root_json, "id_token", json_string (id_token));
  *token_response = json_dumps (root_json, JSON_INDENT (0) | JSON_COMPACT);
  json_decref (root_json);
}

/**
 * Generate a new access token
 */
char *
OIDC_access_token_new ()
{
  char *access_token_number;
  char *access_token;
  uint64_t random_number;

  random_number =
    GNUNET_CRYPTO_random_u64 (GNUNET_CRYPTO_QUALITY_NONCE, UINT64_MAX);
  GNUNET_asprintf (&access_token_number, "%" PRIu64, random_number);
  GNUNET_STRINGS_base64_encode (access_token_number,
                                strlen (access_token_number),
                                &access_token);
  return access_token;
}

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
#include "gnunet_reclaim_lib.h"
#include "gnunet_reclaim_service.h"
#include "gnunet_signatures.h"
#include "oidc_helper.h"
// #include "benchmark.h"
#include <gcrypt.h>

GNUNET_NETWORK_STRUCT_BEGIN

/**
 * The signature used to generate the authorization code
 */
struct OIDC_Parameters
{
  /**
   * The reclaim ticket
   */
  struct GNUNET_RECLAIM_Ticket ticket;

  /**
   * The nonce
   */
  uint32_t nonce GNUNET_PACKED;

  /**
   * The length of the PKCE code_challenge
   */
  uint32_t code_challenge_len GNUNET_PACKED;

  /**
   * The length of the attributes list
   */
  uint32_t attr_list_len GNUNET_PACKED;

  /**
   * The length of the attestation list
   */
  uint32_t attest_list_len GNUNET_PACKED;
};

GNUNET_NETWORK_STRUCT_END

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
                   struct GNUNET_RECLAIM_AttributeList *attrs,
                   struct GNUNET_RECLAIM_AttestationList *attests,
                   const struct GNUNET_TIME_Relative *expiration_time,
                   const char *nonce,
                   const char *secret_key)
{
  struct GNUNET_RECLAIM_AttributeListEntry *le;
  struct GNUNET_RECLAIM_AttestationListEntry *ale;
  struct GNUNET_HashCode signature;
  struct GNUNET_TIME_Absolute exp_time;
  struct GNUNET_TIME_Absolute time_now;
  char *audience;
  char *subject;
  char *header;
  char *body_str;
  char *aggr_names_str;
  char *aggr_sources_str;
  char *source_name;
  char *result;
  char *header_base64;
  char *body_base64;
  char *signature_target;
  char *signature_base64;
  char *attr_val_str;
  char *attest_val_str;
  json_t *body;
  json_t *aggr_names;
  json_t *aggr_sources;
  json_t *aggr_sources_jwt;
  int num_attestations = 0;
  for (le = attrs->list_head; NULL != le; le = le->next)
  {
    if (GNUNET_NO == GNUNET_RECLAIM_id_is_zero (&le->attribute->attestation))
      num_attestations++;
  }

  // iat REQUIRED time now
  time_now = GNUNET_TIME_absolute_get ();
  // exp REQUIRED time expired from config
  exp_time = GNUNET_TIME_absolute_add (time_now, *expiration_time);
  // auth_time only if max_age
  // nonce only if nonce
  // OPTIONAL acr,amr,azp
  subject =
    GNUNET_STRINGS_data_to_string_alloc (sub_key,
                                         sizeof(struct
                                                GNUNET_CRYPTO_EcdsaPublicKey));
  audience =
    GNUNET_STRINGS_data_to_string_alloc (aud_key,
                                         sizeof(struct
                                                GNUNET_CRYPTO_EcdsaPublicKey));
  header = create_jwt_header ();
  body = json_object ();
  aggr_names = json_object ();
  aggr_sources = json_object ();

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
  attest_val_str = NULL;
  aggr_names_str = NULL;
  aggr_sources_str = NULL;
  source_name = NULL;
  int i = 0;
  for (ale = attests->list_head; NULL != ale; ale = ale->next)
  {
    // New Attestation
    GNUNET_asprintf (&source_name,
                     "src%d",
                     i);
    aggr_sources_jwt = json_object ();
    attest_val_str =
      GNUNET_RECLAIM_attestation_value_to_string (ale->attestation->type,
                                                  ale->attestation->data,
                                                  ale->attestation->data_size);
    json_object_set_new (aggr_sources_jwt, "JWT",
                         json_string (attest_val_str) );
    json_object_set_new (aggr_sources, source_name, aggr_sources_jwt);
    GNUNET_free (source_name);
    source_name = NULL;
    i++;
  }

  for (le = attrs->list_head; NULL != le; le = le->next)
  {

    if (GNUNET_YES == GNUNET_RECLAIM_id_is_zero (&le->attribute->attestation))
    {

      attr_val_str =
        GNUNET_RECLAIM_attribute_value_to_string (le->attribute->type,
                                                  le->attribute->data,
                                                  le->attribute->data_size);
      json_object_set_new (body, le->attribute->name,
                           json_string (attr_val_str));
      GNUNET_free (attr_val_str);
    }
    else
    {
      // Check if attest is there
      int j = 0;
      for (ale = attests->list_head; NULL != ale; ale = ale->next)
      {
        if (GNUNET_YES ==
            GNUNET_RECLAIM_id_is_equal (&ale->attestation->id,
                                        &le->attribute->attestation))
          break;
        j++;
      }
      GNUNET_assert (NULL != ale);
      // Attestation is existing, hence take the respective source str
      GNUNET_asprintf (&source_name,
                       "src%d",
                       j);
      json_object_set_new (aggr_names, le->attribute->data,
                           json_string (source_name));
      GNUNET_free (source_name);
    }
  }

  if (NULL != attest_val_str)
    GNUNET_free (attest_val_str);
  if (0 != i)
  {
    aggr_names_str = json_dumps (aggr_names, JSON_INDENT (0) | JSON_COMPACT);
    aggr_sources_str = json_dumps (aggr_sources, JSON_INDENT (0)
                                   | JSON_COMPACT);
    json_object_set_new (body, "_claim_names", json_string (aggr_names_str));
    json_object_set_new (body, "_claim_sources", json_string (
                           aggr_sources_str));
  }

  json_decref (aggr_names);
  json_decref (aggr_sources);

  body_str = json_dumps (body, JSON_INDENT (0) | JSON_COMPACT);
  json_decref (body);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,"ID-Token: %s\n", body_str);

  GNUNET_STRINGS_base64url_encode (header, strlen (header), &header_base64);
  fix_base64 (header_base64);

  GNUNET_STRINGS_base64url_encode (body_str, strlen (body_str), &body_base64);
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
  GNUNET_STRINGS_base64url_encode ((const char *) &signature,
                                   sizeof(struct GNUNET_HashCode),
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
  if (NULL != aggr_sources_str)
    GNUNET_free (aggr_sources_str);
  if (NULL != aggr_names_str)
    GNUNET_free (aggr_names_str);
  GNUNET_free (signature_base64);
  GNUNET_free (body_base64);
  GNUNET_free (header_base64);
  return result;
}


static void
derive_aes_key (struct GNUNET_CRYPTO_SymmetricSessionKey *key,
                struct GNUNET_CRYPTO_SymmetricInitializationVector *iv,
                struct GNUNET_HashCode *key_material)
{
  static const char ctx_key[] = "reclaim-aes-ctx-key";
  static const char ctx_iv[] = "reclaim-aes-ctx-iv";

  GNUNET_CRYPTO_kdf (key,
                     sizeof(struct GNUNET_CRYPTO_SymmetricSessionKey),
                     ctx_key,
                     strlen (ctx_key),
                     key_material,
                     sizeof(struct GNUNET_HashCode),
                     NULL);
  GNUNET_CRYPTO_kdf (iv,
                     sizeof(
                       struct GNUNET_CRYPTO_SymmetricInitializationVector),
                     ctx_iv,
                     strlen (ctx_iv),
                     key_material,
                     sizeof(struct GNUNET_HashCode),
                     NULL);
}


static void
calculate_key_priv (struct GNUNET_CRYPTO_SymmetricSessionKey *key,
                    struct GNUNET_CRYPTO_SymmetricInitializationVector *iv,
                    const struct GNUNET_CRYPTO_EcdsaPrivateKey *ecdsa_priv,
                    const struct GNUNET_CRYPTO_EcdhePublicKey *ecdh_pub)
{
  struct GNUNET_HashCode key_material;

  GNUNET_CRYPTO_ecdsa_ecdh (ecdsa_priv, ecdh_pub, &key_material);
  derive_aes_key (key, iv, &key_material);
}


static void
calculate_key_pub (struct GNUNET_CRYPTO_SymmetricSessionKey *key,
                   struct GNUNET_CRYPTO_SymmetricInitializationVector *iv,
                   const struct GNUNET_CRYPTO_EcdsaPublicKey *ecdsa_pub,
                   const struct GNUNET_CRYPTO_EcdhePrivateKey *ecdh_priv)
{
  struct GNUNET_HashCode key_material;

  GNUNET_CRYPTO_ecdh_ecdsa (ecdh_priv, ecdsa_pub, &key_material);
  derive_aes_key (key, iv, &key_material);
}


static void
decrypt_payload (const struct GNUNET_CRYPTO_EcdsaPrivateKey *ecdsa_priv,
                 const struct GNUNET_CRYPTO_EcdhePublicKey *ecdh_pub,
                 const char *ct,
                 size_t ct_len,
                 char *buf)
{
  struct GNUNET_CRYPTO_SymmetricSessionKey key;
  struct GNUNET_CRYPTO_SymmetricInitializationVector iv;

  calculate_key_priv (&key, &iv, ecdsa_priv, ecdh_pub);
  GNUNET_break (GNUNET_CRYPTO_symmetric_decrypt (ct, ct_len, &key, &iv, buf));
}


static void
encrypt_payload (const struct GNUNET_CRYPTO_EcdsaPublicKey *ecdsa_pub,
                 const struct GNUNET_CRYPTO_EcdhePrivateKey *ecdh_priv,
                 const char *payload,
                 size_t payload_len,
                 char *buf)
{
  struct GNUNET_CRYPTO_SymmetricSessionKey key;
  struct GNUNET_CRYPTO_SymmetricInitializationVector iv;

  calculate_key_pub (&key, &iv, ecdsa_pub, ecdh_priv);
  GNUNET_break (
    GNUNET_CRYPTO_symmetric_encrypt (payload, payload_len, &key, &iv, buf));
}


/**
 * Builds an OIDC authorization code including
 * a reclaim ticket and nonce
 *
 * @param issuer the issuer of the ticket, used to sign the ticket and nonce
 * @param ticket the ticket to include in the code
 * @param attrs list of attributes which are shared
 * @param nonce the nonce to include in the code
 * @param code_challenge PKCE code challenge
 * @return a new authorization code (caller must free)
 */
char *
OIDC_build_authz_code (const struct GNUNET_CRYPTO_EcdsaPrivateKey *issuer,
                       const struct GNUNET_RECLAIM_Ticket *ticket,
                       struct GNUNET_RECLAIM_AttributeList *attrs,
                       struct GNUNET_RECLAIM_AttestationList *attests,
                       const char *nonce_str,
                       const char *code_challenge)
{
  struct OIDC_Parameters params;
  char *code_payload;
  char *payload;
  char *tmp;
  char *code_str;
  char *buf_ptr = NULL;
  size_t payload_len;
  size_t code_payload_len;
  size_t attr_list_len = 0;
  size_t attests_list_len = 0;
  size_t code_challenge_len = 0;
  uint32_t nonce;
  uint32_t nonce_tmp;
  struct GNUNET_CRYPTO_EccSignaturePurpose *purpose;
  struct GNUNET_CRYPTO_EcdhePrivateKey ecdh_priv;
  struct GNUNET_CRYPTO_EcdhePublicKey ecdh_pub;

  /** PLAINTEXT **/
  // Assign ticket
  memset (&params, 0, sizeof(params));
  params.ticket = *ticket;
  // Assign nonce
  nonce = 0;
  payload_len = sizeof(struct OIDC_Parameters);
  if ((NULL != nonce_str) && (strcmp ("", nonce_str) != 0))
  {
    if ((1 != sscanf (nonce_str, "%u", &nonce)) || (nonce > UINT32_MAX))
    {
      GNUNET_break (0);
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Invalid nonce %s\n", nonce_str);
      return NULL;
    }
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Got nonce: %u from %s\n",
                nonce,
                nonce_str);
  }
  nonce_tmp = htonl (nonce);
  params.nonce = nonce_tmp;
  // Assign code challenge
  if (NULL != code_challenge)
    code_challenge_len = strlen (code_challenge);
  payload_len += code_challenge_len;
  params.code_challenge_len = htonl (code_challenge_len);
  // Assign attributes
  if (NULL != attrs)
  {
    // Get length
    attr_list_len = GNUNET_RECLAIM_attribute_list_serialize_get_size (attrs);
    params.attr_list_len = htonl (attr_list_len);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Length of serialized attributes: %lu\n",
                attr_list_len);
    // Get serialized attributes
    payload_len += attr_list_len;
  }
  if (NULL != attests)
  {
    // Get length
    attests_list_len =
      GNUNET_RECLAIM_attestation_list_serialize_get_size (attests);
    params.attest_list_len = htonl (attests_list_len);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Length of serialized attestations: %lu\n",
                attests_list_len);
    // Get serialized attributes
    payload_len += attests_list_len;
  }

  // Get plaintext length
  payload = GNUNET_malloc (payload_len);
  memcpy (payload, &params, sizeof(params));
  tmp = payload + sizeof(params);
  if (0 < code_challenge_len)
  {
    memcpy (tmp, code_challenge, code_challenge_len);
    tmp += code_challenge_len;
  }
  if (0 < attr_list_len)
    GNUNET_RECLAIM_attribute_list_serialize (attrs, tmp);
  if (0 < attests_list_len)
    GNUNET_RECLAIM_attestation_list_serialize (attests, tmp);

  /** END **/

  /** ENCRYPT **/
  // Get length
  code_payload_len = sizeof(struct GNUNET_CRYPTO_EccSignaturePurpose)
                     + sizeof(struct GNUNET_CRYPTO_EcdhePublicKey)
                     + payload_len + sizeof(struct
                                            GNUNET_CRYPTO_EcdsaSignature);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Length of data to encode: %lu\n",
              code_payload_len);

  // Generate ECDH key
  GNUNET_CRYPTO_ecdhe_key_create (&ecdh_priv);
  GNUNET_CRYPTO_ecdhe_key_get_public (&ecdh_priv, &ecdh_pub);
  // Initialize code payload
  code_payload = GNUNET_malloc (code_payload_len);
  GNUNET_assert (NULL != code_payload);
  purpose = (struct GNUNET_CRYPTO_EccSignaturePurpose *) code_payload;
  purpose->size = htonl (sizeof(struct GNUNET_CRYPTO_EccSignaturePurpose)
                         + sizeof(ecdh_pub) + payload_len);
  purpose->purpose = htonl (GNUNET_SIGNATURE_PURPOSE_RECLAIM_CODE_SIGN);
  // Store pubkey
  buf_ptr = (char *) &purpose[1];
  memcpy (buf_ptr, &ecdh_pub, sizeof(ecdh_pub));
  buf_ptr += sizeof(ecdh_pub);
  // Encrypt plaintext and store
  encrypt_payload (&ticket->audience,
                   &ecdh_priv,
                   payload,
                   payload_len,
                   buf_ptr);
  GNUNET_free (payload);
  buf_ptr += payload_len;
  // Sign and store signature
  if (GNUNET_SYSERR ==
      GNUNET_CRYPTO_ecdsa_sign_ (issuer,
                                 purpose,
                                 (struct GNUNET_CRYPTO_EcdsaSignature *)
                                 buf_ptr))
  {
    GNUNET_break (0);
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Unable to sign code\n");
    GNUNET_free (code_payload);
    return NULL;
  }
  GNUNET_STRINGS_base64url_encode (code_payload, code_payload_len, &code_str);
  GNUNET_free (code_payload);
  return code_str;
}


/**
 * Parse reclaim ticket and nonce from
 * authorization code.
 * This also verifies the signature in the code.
 *
 * @param audience the expected audience of the code
 * @param code the string representation of the code
 * @param code_verfier PKCE code verifier
 * @param ticket where to store the ticket
 * @param attrs the attributes in the code
 * @param nonce where to store the nonce
 * @return GNUNET_OK if successful, else GNUNET_SYSERR
 */
int
OIDC_parse_authz_code (const struct GNUNET_CRYPTO_EcdsaPrivateKey *ecdsa_priv,
                       const char *code,
                       const char *code_verifier,
                       struct GNUNET_RECLAIM_Ticket *ticket,
                       struct GNUNET_RECLAIM_AttributeList **attrs,
                       struct GNUNET_RECLAIM_AttestationList **attests,
                       char **nonce_str)
{
  char *code_payload;
  char *ptr;
  char *plaintext;
  char *attrs_ser;
  char *attests_ser;
  char *expected_code_challenge;
  char *code_challenge;
  char *code_verifier_hash;
  struct GNUNET_CRYPTO_EccSignaturePurpose *purpose;
  struct GNUNET_CRYPTO_EcdsaSignature *signature;
  struct GNUNET_CRYPTO_EcdsaPublicKey ecdsa_pub;
  struct GNUNET_CRYPTO_EcdhePublicKey *ecdh_pub;
  uint32_t code_challenge_len;
  uint32_t attrs_ser_len;
  uint32_t attests_ser_len;
  size_t plaintext_len;
  size_t code_payload_len;
  uint32_t nonce = 0;
  struct OIDC_Parameters *params;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Trying to decode `%s'\n", code);
  code_payload = NULL;
  code_payload_len =
    GNUNET_STRINGS_base64url_decode (code, strlen (code),
                                     (void **) &code_payload);
  if (code_payload_len < sizeof(struct GNUNET_CRYPTO_EccSignaturePurpose)
      + sizeof(struct GNUNET_CRYPTO_EcdhePublicKey)
      + sizeof(struct OIDC_Parameters)
      + sizeof(struct GNUNET_CRYPTO_EcdsaSignature))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Authorization code malformed\n");
    GNUNET_free_non_null (code_payload);
    return GNUNET_SYSERR;
  }

  purpose = (struct GNUNET_CRYPTO_EccSignaturePurpose *) code_payload;
  plaintext_len = code_payload_len;
  plaintext_len -= sizeof(struct GNUNET_CRYPTO_EccSignaturePurpose);
  ptr = (char *) &purpose[1];
  // Public ECDH key
  ecdh_pub = (struct GNUNET_CRYPTO_EcdhePublicKey *) ptr;
  ptr += sizeof(struct GNUNET_CRYPTO_EcdhePublicKey);
  plaintext_len -= sizeof(struct GNUNET_CRYPTO_EcdhePublicKey);

  // Decrypt ciphertext
  plaintext_len -= sizeof(struct GNUNET_CRYPTO_EcdsaSignature);
  plaintext = GNUNET_malloc (plaintext_len);
  decrypt_payload (ecdsa_priv, ecdh_pub, ptr, plaintext_len, plaintext);
  // ptr = plaintext;
  ptr += plaintext_len;
  signature = (struct GNUNET_CRYPTO_EcdsaSignature *) ptr;
  params = (struct OIDC_Parameters *) plaintext;

  // cmp code_challenge code_verifier
  code_challenge_len = ntohl (params->code_challenge_len);
  if (0 != code_challenge_len) /* Only check if this code requires a CV */
  {
    if (NULL == code_verifier)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  "Expected code verifier!\n");
      GNUNET_free_non_null (code_payload);
      return GNUNET_SYSERR;
    }
    code_verifier_hash = GNUNET_malloc (256 / 8);
    // hash code verifier
    gcry_md_hash_buffer (GCRY_MD_SHA256,
                         code_verifier_hash,
                         code_verifier,
                         strlen (code_verifier));
    // encode code verifier
    GNUNET_STRINGS_base64url_encode (code_verifier_hash, 256 / 8,
                                     &expected_code_challenge);
    code_challenge = (char *) &params[1];
    GNUNET_free (code_verifier_hash);
    if ((strlen (expected_code_challenge) != code_challenge_len) ||
        (0 !=
         strncmp (expected_code_challenge, code_challenge, code_challenge_len)))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  "Invalid code verifier! Expected: %s, Got: %.*s\n",
                  expected_code_challenge,
                  code_challenge_len,
                  code_challenge);
      GNUNET_free_non_null (code_payload);
      GNUNET_free (expected_code_challenge);
      return GNUNET_SYSERR;
    }
    GNUNET_free (expected_code_challenge);
  }
  // Ticket
  memcpy (ticket, &params->ticket, sizeof(params->ticket));
  // Nonce
  nonce = ntohl (params->nonce);  // ntohl (*((uint32_t *) ptr));
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Got nonce: %u\n", nonce);
  // Signature
  GNUNET_CRYPTO_ecdsa_key_get_public (ecdsa_priv, &ecdsa_pub);
  if (0 != GNUNET_memcmp (&ecdsa_pub, &ticket->audience))
  {
    GNUNET_free (code_payload);
    GNUNET_free (plaintext);
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Audience in ticket does not match client!\n");
    return GNUNET_SYSERR;
  }
  if (GNUNET_OK !=
      GNUNET_CRYPTO_ecdsa_verify_ (GNUNET_SIGNATURE_PURPOSE_RECLAIM_CODE_SIGN,
                                   purpose,
                                   signature,
                                   &ticket->identity))
  {
    GNUNET_free (code_payload);
    GNUNET_free (plaintext);
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Signature of AuthZ code invalid!\n");
    return GNUNET_SYSERR;
  }
  // Attributes
  attrs_ser = ((char *) &params[1]) + code_challenge_len;
  attrs_ser_len = ntohl (params->attr_list_len);
  *attrs = GNUNET_RECLAIM_attribute_list_deserialize (attrs_ser, attrs_ser_len);
  attests_ser = ((char*) attrs_ser) + attrs_ser_len;
  attests_ser_len = ntohl (params->attest_list_len);
  *attests = GNUNET_RECLAIM_attestation_list_deserialize (attests_ser,
                                                          attests_ser_len);

  *nonce_str = NULL;
  if (nonce != 0)
    GNUNET_asprintf (nonce_str, "%u", nonce);
  GNUNET_free (code_payload);
  GNUNET_free (plaintext);
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
  json_object_set_new (root_json,
                       "expires_in",
                       json_integer (expiration_time->rel_value_us
                                     / (1000 * 1000)));
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
  char *access_token;
  uint64_t random_number;

  random_number =
    GNUNET_CRYPTO_random_u64 (GNUNET_CRYPTO_QUALITY_NONCE, UINT64_MAX);
  GNUNET_STRINGS_base64_encode (&random_number,
                                sizeof(uint64_t),
                                &access_token);
  return access_token;
}

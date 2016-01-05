
#ifndef GNUNET_IDENTITY_TOKEN_H
#define GNUNET_IDENTITY_TOKEN_H



#include "gnunet_crypto_lib.h"
#include <jansson.h>

struct IdentityToken
{
  /**
   * JSON header
   */
  json_t *header;

  /**
   * JSON Payload
   */
  json_t *payload;

  /**
   * Token Signature
   */
  struct GNUNET_CRYPTO_EcdsaSignature signature;
  
  /**
   * Audience Pubkey
   */
  struct GNUNET_CRYPTO_EcdsaPublicKey aud_key;
};

struct IdentityTokenCodePayload
{
  /**
   * Nonce
   */
  char* nonce;

  /**
   * Label
   */
  char *label;

  /**
   * Issuing Identity
   */
  struct GNUNET_CRYPTO_EcdsaPublicKey identity_key;
};


struct IdentityTokenCode
{
  /**
   * Meta info
   */
  struct IdentityTokenCodePayload *payload;

  /**
   * ECDH Pubkey
   */
  struct GNUNET_CRYPTO_EcdhePublicKey ecdh_pubkey;

  /**
   * Signature
   */
  struct GNUNET_CRYPTO_EcdsaSignature signature;

  /**
   * Target identity
   */
  struct GNUNET_CRYPTO_EcdsaPublicKey aud_key;
};



struct IdentityToken*
identity_token_create (const char* issuer,
                       const char* audience);

void
identity_token_destroy (struct IdentityToken *token);

void
identity_token_add_attr (const struct IdentityToken *token,
                         const char* key,
                         const char* value);
void
identity_token_add_json (const struct IdentityToken *token,
                         const char* key,
                         json_t* value);

int 
identity_token_serialize (const struct IdentityToken *token,
                          const struct GNUNET_CRYPTO_EcdsaPrivateKey *priv_key,
                          char **result);

int
identity_token_parse (const char* raw_data,
                      const struct GNUNET_CRYPTO_EcdsaPrivateKey *priv_key,
                      struct IdentityToken **result);

int
identity_token_to_string (const struct IdentityToken *token,
                          const struct GNUNET_CRYPTO_EcdsaPrivateKey *priv_key,
                          char **result);

struct IdentityTokenCode*
identity_token_code_create (const char* nonce_str,
                            const struct GNUNET_CRYPTO_EcdsaPublicKey* identity_pkey,
                            const char* lbl_str,
                            const struct GNUNET_CRYPTO_EcdsaPublicKey *aud_key);

int
identity_token_code_serialize (struct IdentityTokenCode *identity_token_code,
                               const struct GNUNET_CRYPTO_EcdsaPrivateKey *priv_key,
                               char **result);

void
identity_token_code_destroy (struct IdentityTokenCode *token_code);


int
identity_token_code_parse (const char* raw_data,
                           const struct GNUNET_CRYPTO_EcdsaPrivateKey *priv_key,
                           struct IdentityTokenCode **result);

#endif

/*
   This file is part of GNUnet.
   Copyright (C) 2012-2015 Christian Grothoff (and other contributing authors)

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
 * @author Martin Schanzenbach
 * @file include/gnunet_identity_provider_lib.h
 * @brief GNUnet Identity Provider library
 *
 */
#ifndef IDENTITY_TOKEN_H
#define IDENTITY_TOKEN_H

#include "gnunet_crypto_lib.h"
#include <jansson.h>

struct IdentityToken
{
  /**
   * DLL
   */
  struct TokenAttr *attr_head;

  /**
   * DLL
   */
  struct TokenAttr *attr_tail;

  /**
   * Token Signature
   */
  struct GNUNET_CRYPTO_EcdsaSignature signature;
  
  /**
   * Audience Pubkey
   */
  struct GNUNET_CRYPTO_EcdsaPublicKey aud_key;
};

struct TokenAttr
{
  /**
   * DLL
   */
  struct TokenAttr *next;

  /**
   * DLL
   */
  struct TokenAttr *prev;

  /**
   * Attribute name
   */
  char *name;

  /**
   * Attribute value DLL
   */
  struct TokenAttrValue *val_head;

  /**
   * Attribute value DLL
   */
  struct TokenAttrValue *val_tail;

};

struct TokenAttrValue
{
  /**
   * DLL
   */
  struct TokenAttrValue *next;

  /**
   * DLL
   */
  struct TokenAttrValue *prev;

  /**
   * Attribute value
   */
  char *value;
};

struct TokenTicketPayload
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


struct TokenTicket
{
  /**
   * Meta info
   */
  struct TokenTicketPayload *payload;

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



/**
 * Create an identity token
 *
 * @param iss the issuer string for the token
 * @param aud the audience of the token
 *
 * @return a new token
 */
struct IdentityToken*
token_create (const struct GNUNET_CRYPTO_EcdsaPublicKey *iss,
                                       const struct GNUNET_CRYPTO_EcdsaPublicKey* aud);

/**
 * Destroy an identity token
 *
 * @param token the token to destroy
 */
void
token_destroy (struct IdentityToken*token);

/**
 * Add a new key value pair to the token
 * 
 * @param token the token to modify
 * @param key the key
 * @param value the value
 */
void
token_add_attr (struct IdentityToken *token,
                const char* key,
                const char* value);

/**
 * Add a value to a TokenAttribute
 *
 * @param attr the token attribute
 * @param value value to add
 */
  void
  token_attr_add_value (const struct TokenAttr *attr,
                        const char *value);

/**
 * Add a new key value pair to the token with the value as json
 *
 * @param the token to modify
 * @param key the key
 * @param value the value
 *
 */
void
token_add_json (const struct IdentityToken *token,
                const char* key,
                json_t* value);

/**
 * Serialize a token. The token will be signed and base64 according to the
 * JWT format. The signature is base32-encoded ECDSA.
 * The resulting JWT is encrypted using 
 * ECDHE for the audience and Base64
 * encoded in result. The audience requires the ECDHE public key P 
 * to decrypt the token T. The key P is included in the result and prepended
 * before the token
 *
 * @param token the token to serialize
 * @param priv_key the private key used to sign the token
 * @param ecdhe_privkey the ECDHE private key used to encrypt the token
 * @param result P,Base64(E(T))
 *
 * @return GNUNET_OK on success
 */
int 
token_serialize (const struct IdentityToken*token,
                 const struct GNUNET_CRYPTO_EcdsaPrivateKey *priv_key,
                 struct GNUNET_CRYPTO_EcdhePrivateKey **ecdhe_privkey,
                 char **result);

/**
 * Parses the serialized token and returns a token
 *
 * @param data the serialized token
 * @param priv_key the private key of the audience
 * @param result the token
 *
 * @return GNUNET_OK on success
 */
  int
  token_parse (const char* data,
               const struct GNUNET_CRYPTO_EcdsaPrivateKey *priv_key,
               struct IdentityToken **result);

/**
 * Parses the serialized token and returns a token
 * This variant is intended for the party that issued the token and also
 * wants to decrypt the serialized token.
 *
 * @param data the serialized token
 * @param priv_key the private (!) ECDHE key
 * @param aud_key the identity of the audience
 * @param result the token
 *
 * @return GNUNET_OK on success
 */
int
token_parse2 (const char* data,
              const struct GNUNET_CRYPTO_EcdhePrivateKey *priv_key,
              const struct GNUNET_CRYPTO_EcdsaPublicKey *aud_key,
              struct IdentityToken **result);


/**
 *
 * Returns a JWT-string representation of the token
 *
 * @param token the token
 * @param priv_key the private key used to sign the JWT
 * @param result the JWT
 *
 * @return GNUNET_OK on success
 */
int
token_to_string (const struct IdentityToken *token,
                 const struct GNUNET_CRYPTO_EcdsaPrivateKey *priv_key,
                 char **result);

/**
 *
 * Creates a ticket that can be exchanged by the audience for 
 * the token. The token must be placed under the label
 *
 * @param nonce_str nonce provided by the audience that requested the ticket
 * @param iss_pkey the issuer pubkey used to sign the ticket
 * @param label the label encoded in the ticket
 * @param aud_ley the audience pubkey used to encrypt the ticket payload
 *
 * @return the ticket
 */
struct TokenTicket*
ticket_create (const char* nonce_str,
               const struct GNUNET_CRYPTO_EcdsaPublicKey* iss_pkey,
               const char* lbl_str,
               const struct GNUNET_CRYPTO_EcdsaPublicKey *aud_key);

/**
 * Serialize a ticket. Returns the Base64 representation of the ticket.
 * Format: Base64( { payload: E(Payload), ecdhe: K, signature: signature } )
 *
 * @param ticket the ticket to serialize
 * @param priv_key the issuer private key to sign the ticket payload
 * @param result the serialized ticket
 *
 * @return GNUNET_OK on success
 */
int
ticket_serialize (struct TokenTicket *ticket,
                  const struct GNUNET_CRYPTO_EcdsaPrivateKey *priv_key,
                  char **result);

/**
 * Destroys a ticket
 *
 * @param the ticket to destroy
 */
void
ticket_destroy (struct TokenTicket *ticket);

/**
 * Parses a serialized ticket
 *
 * @param data the serialized ticket
 * @param priv_key the audience private key
 * @param ticket the ticket
 *
 * @return GNUNET_OK on success
 */
int
ticket_parse (const char* raw_data,
              const struct GNUNET_CRYPTO_EcdsaPrivateKey *priv_key,
              struct TokenTicket **ticket);

#endif

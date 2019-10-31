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
 * @file reclaim/oidc_helper.h
 * @brief helper library for OIDC related functions
 * @author Martin Schanzenbach
 */

#ifndef JWT_H
#define JWT_H

#define JWT_ALG "alg"

/* Use 512bit HMAC */
#define JWT_ALG_VALUE "HS512"

#define JWT_TYP "typ"

#define JWT_TYP_VALUE "jwt"

#define SERVER_ADDRESS "https://api.reclaim"

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
                   const char *secret_key);

/**
 * Builds an OIDC authorization code including
 * a reclaim ticket and nonce
 *
 * @param issuer the issuer of the ticket, used to sign the ticket and nonce
 * @param ticket the ticket to include in the code
 * @param attrs list of attributes to share
 * @param nonce the nonce to include in the code
 * @param code_challenge PKCE code challenge
 * @return a new authorization code (caller must free)
 */
char*
OIDC_build_authz_code (const struct GNUNET_CRYPTO_EcdsaPrivateKey *issuer,
                       const struct GNUNET_RECLAIM_Ticket *ticket,
                       struct GNUNET_RECLAIM_ATTRIBUTE_ClaimList *attrs,
                       const char *nonce,
                       const char *code_challenge);

/**
 * Parse reclaim ticket and nonce from
 * authorization code.
 * This also verifies the signature in the code.
 *
 * @param ecdsa_priv the audience of the ticket
 * @param code the string representation of the code
 * @param code_verfier PKCE code verifier
 * @param ticket where to store the ticket
 * @param attrs the attributes found in the code
 * @param nonce where to store the nonce
 * @return GNUNET_OK if successful, else GNUNET_SYSERR
 */
int
OIDC_parse_authz_code (const struct GNUNET_CRYPTO_EcdsaPrivateKey *ecdsa_priv,
                       const char *code,
                       const char *code_verifier,
                       struct GNUNET_RECLAIM_Ticket *ticket,
                       struct GNUNET_RECLAIM_ATTRIBUTE_ClaimList **attrs,
                       char **nonce);

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
                           char **token_response);

/**
 * Generate a new access token
 */
char*
OIDC_access_token_new ();


#endif

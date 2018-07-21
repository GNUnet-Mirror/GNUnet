#ifndef JWT_H
#define JWT_H

/**
 * Create a JWT from attributes
 *
 * @param aud_key the public of the audience
 * @param sub_key the public key of the subject
 * @param attrs the attribute list
 * @param expiration_time the validity of the token
 * @param nonce the nonce, may be NULL
 * @param secret_key the key used to sign the JWT
 * @return a new base64-encoded JWT string.
 */
char*
jwt_create_from_list (const struct GNUNET_CRYPTO_EcdsaPublicKey *aud_key,
                      const struct GNUNET_CRYPTO_EcdsaPublicKey *sub_key,
                      const struct GNUNET_RECLAIM_ATTRIBUTE_ClaimList *attrs,
                      const struct GNUNET_TIME_Relative *expiration_time,
                      const char *nonce,
                      const char *secret_key);

#endif

#ifndef JWT_H
#define JWT_H

char*
jwt_create_from_list (const struct GNUNET_CRYPTO_EcdsaPublicKey *aud_key,
                      const struct GNUNET_CRYPTO_EcdsaPublicKey *sub_key,
                                                const struct GNUNET_IDENTITY_ATTRIBUTE_ClaimList *attrs,
                                                const struct GNUNET_CRYPTO_AuthKey *priv_key);

#endif

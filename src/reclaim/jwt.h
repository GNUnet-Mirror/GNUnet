#ifndef JWT_H
#define JWT_H

char*
jwt_create_from_list (const struct GNUNET_CRYPTO_EcdsaPublicKey *aud_key,
                      const struct GNUNET_CRYPTO_EcdsaPublicKey *sub_key,
                                                const struct GNUNET_RECLAIM_ATTRIBUTE_ClaimList *attrs,
                                                const char* secret_key);

#endif

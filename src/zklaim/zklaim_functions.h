#ifndef GNUNET_ZKLAIM_FUNCTIONS_H
#define GNUNET_ZKLAIM_FUNCTIONS_H

#include "gnunet_zklaim_service.h"

/**
 * Handle for an ego.
 */
struct GNUNET_ZKLAIM_Context
{
  /**
   * ZKlaim context.
   */
  struct zklaim_ctx *ctx;

  /**
   * Current name associated with this context.
   */
  char *name;

  /**
   * Attributes associated with context
   */
  char *attrs;

};



int
ZKLAIM_context_sign (struct GNUNET_ZKLAIM_Context *ctx,
                     const struct GNUNET_CRYPTO_EcdsaPrivateKey *key);


void
ZKLAIM_context_attributes_iterate (const struct GNUNET_ZKLAIM_Context *ctx,
                                   GNUNET_ZKLAIM_PayloadIterator iter,
                                   void *iter_cls);


void
ZKLAIM_context_issue (struct GNUNET_ZKLAIM_Context *ctx,
                      const struct GNUNET_CRYPTO_EcdsaPrivateKey *key,
                      GNUNET_ZKLAIM_PayloadIterator iter,
                      void *iter_cls);
#endif

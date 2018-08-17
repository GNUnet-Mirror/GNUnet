#include "platform.h"
#include "zklaim/zklaim.h"
#include "gcrypt.h"
#include "gnunet_zklaim_service.h"
#include "zklaim_functions.h"

int
ZKLAIM_context_sign (struct GNUNET_ZKLAIM_Context *ctx,
                     const struct GNUNET_CRYPTO_EcdsaPrivateKey *key)
{
  int rc;
  gcry_sexp_t priv;

  //TODO how to ensure not hashed??
  zklaim_hash_ctx (ctx->ctx);
  rc = gcry_sexp_build (&priv, NULL,
                        "(private-key(ecc(curve \"Ed25519\")"
                        "(d %b)))",
                        (int) sizeof (key->d), key->d);
  if (0 != rc)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "GCRY error...\n");
    //send_issue_response (ih, NULL, 0);
    return GNUNET_SYSERR;
  }
  return zklaim_ctx_sign (ctx->ctx, priv);
}

void
ZKLAIM_context_attributes_iterate (const struct GNUNET_ZKLAIM_Context *ctx,
                                   GNUNET_ZKLAIM_PayloadIterator iter,
                                   void *iter_cls)
{
  int i;
  int j;
  uint64_t data;
  char *attr_name;
  char *tmp;
  zklaim_wrap_payload_ctx *plw;

  tmp = GNUNET_strdup (ctx->attrs);
  attr_name = strtok (tmp, ",");
  plw = ctx->ctx->pl_ctx_head;

  for (i = 0; i < ctx->ctx->num_of_payloads; i++)
  {
    for (j = 0; j < ZKLAIM_MAX_PAYLOAD_ATTRIBUTES; j++)
    {
      GNUNET_assert (NULL != attr_name);
      iter (iter_cls, attr_name, &data);
      zklaim_set_attr (&plw->pl,
                       data,
                       j);
      attr_name = strtok (NULL, ",");
    }
    plw = plw->next;
    GNUNET_assert (NULL != plw);
  }
  GNUNET_free (tmp);

}

void
ZKLAIM_context_issue (struct GNUNET_ZKLAIM_Context *ctx,
                      const struct GNUNET_CRYPTO_EcdsaPrivateKey *key,
                      GNUNET_ZKLAIM_PayloadIterator iter,
                      void *iter_cls)
{
  ZKLAIM_context_attributes_iterate (ctx,
                                     iter,
                                     iter_cls);
  ZKLAIM_context_sign (ctx,
                       key);
}

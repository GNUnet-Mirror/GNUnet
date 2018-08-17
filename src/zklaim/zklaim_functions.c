/*
   This file is part of GNUnet.
   Copyright (C) 2012-2015 GNUnet e.V.

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
   */
/**
 * @author Martin Schanzenbach
 * @file src/zklaim/zklaim_functions.c
 * @brief zklaim functions
 *
 */


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
  unsigned char *pubbuf;
  size_t publen;
  gcry_sexp_t priv;
  gcry_sexp_t pub;
  gcry_mpi_t q;
  gcry_ctx_t gctx;

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
    return GNUNET_SYSERR;
  }
  gcry_mpi_ec_new (&gctx, priv, NULL);
  q = gcry_mpi_ec_get_mpi ("q@eddsa", gctx, 0);
  rc = gcry_sexp_build(&pub, NULL, "(key-data (public-key (ecc (curve Ed25519) (q %M))))", q);
  if (0 != rc) {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "GCRY error...\n");
    return GNUNET_SYSERR;
  }
  gcry_mpi_release(q);
  zklaim_pub2buf(pub, &pubbuf, &publen);
  gcry_sexp_release(pub);
  gcry_ctx_release (gctx);
  memcpy(ctx->ctx->pub_key, pubbuf, sizeof(ctx->ctx->pub_key));
  free(pubbuf);
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
      if (NULL == attr_name)
        break;
      iter (iter_cls, attr_name, &data);
      zklaim_set_attr (&plw->pl,
                       data,
                       j);
      if ((attr_name - tmp) == (strlen (attr_name) + 1))
      {
        attr_name = NULL;
        break;
      }
      attr_name = strtok (attr_name + strlen (attr_name) + 1, ",");
    }
    if (NULL == attr_name)
      break;
    plw = plw->next;
    GNUNET_assert (NULL != plw);
  }
  GNUNET_free (tmp);

}

int
ZKLAIM_context_issue (struct GNUNET_ZKLAIM_Context *ctx,
                      const struct GNUNET_CRYPTO_EcdsaPrivateKey *key,
                      GNUNET_ZKLAIM_PayloadIterator iter,
                      void *iter_cls)
{
  ZKLAIM_context_attributes_iterate (ctx,
                                     iter,
                                     iter_cls);
  return ZKLAIM_context_sign (ctx,
                              key);
}

int
ZKLAIM_context_prove (struct GNUNET_ZKLAIM_Context *ctx,
                      GNUNET_ZKLAIM_PredicateIterator iter,
                      void *iter_cls)
{
  int i;
  int j;
  int ret;
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
      plw->pl.data_op[j] = zklaim_noop;
    }
    plw = plw->next;
  }
  plw = ctx->ctx->pl_ctx_head;
  for (i = 0; i < ctx->ctx->num_of_payloads; i++)
  {
    for (j = 0; j < ZKLAIM_MAX_PAYLOAD_ATTRIBUTES; j++)
    {

      if (NULL == attr_name)
        break;
      iter (iter_cls,
            attr_name,
            &plw->pl.data_op[j],
            &plw->pl.data_ref[j]);
      if ((attr_name - tmp) == (strlen (attr_name) + 1))
      {
        attr_name = NULL;
        break;
      }
      attr_name = strtok (attr_name + strlen (attr_name) + 1, ",");
    }
    if (NULL == attr_name)
      break;
    plw = plw->next;
    GNUNET_assert (NULL != plw);
  }
  GNUNET_free (tmp);
  ret = zklaim_proof_generate (ctx->ctx);
  zklaim_clear_pres(ctx->ctx);
  return ret;
}

int
ZKLAIM_context_verify (struct GNUNET_ZKLAIM_Context *ctx,
                       GNUNET_ZKLAIM_PredicateIterator iter,
                       void *iter_cls)
{
  int i;
  int j;
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

      if (NULL == attr_name)
        break;
      iter (iter_cls,
            attr_name,
            &plw->pl.data_op[j],
            &plw->pl.data_ref[j]);
      if ((attr_name - tmp) == (strlen (attr_name) + 1))
      {
        attr_name = NULL;
        break;
      }
      attr_name = strtok (attr_name + strlen (attr_name) + 1, ",");
    }
    if (NULL == attr_name)
      break;
    plw = plw->next;
    GNUNET_assert (NULL != plw);
  }
  GNUNET_free (tmp);
  return zklaim_ctx_verify (ctx->ctx);
}

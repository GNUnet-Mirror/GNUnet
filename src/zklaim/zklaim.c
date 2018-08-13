/*
     This file is part of GNUnet.  Copyright (C) 2001-2018 Christian Grothoff
     (and other contributing authors)

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
 * @file abe/abe.c
 * @brief functions for Attribute-Based Encryption
 * @author Martin Schanzenbach
 */


#include "platform.h"
#include <zklaim/zklaim.h>
#include "gnunet_crypto_lib.h"

struct GNUNET_ZKLAIM_Context
{
  zklaim_ctx* ctx;
  gcry_sexp_t priv;
  gcry_sexp_t pub;
};

struct GNUNET_ZKLAIM_Payload
{
  zklaim_payload pl;
};

struct GNUNET_ZKLAIM_Context*
GNUNET_ZKLAIM_new ()
{
  struct GNUNET_ZKLAIM_Context *ctx;
  unsigned char *pubbuf;
  size_t publen;
  
  ctx = GNUNET_new (struct GNUNET_ZKLAIM_Context);
  ctx->ctx = zklaim_context_new();
  zklaim_pub2buf(ctx->pub, &pubbuf, &publen);
  zklaim_gen_pk(&ctx->priv);
  zklaim_get_pub(ctx->priv, &ctx->pub);
   if (sizeof(ctx->ctx->pub_key) != publen) {
        printf("size mismatch!");
        return NULL;
   }

   memcpy(ctx->ctx->pub_key, pubbuf, sizeof(ctx->ctx->pub_key));
   free(pubbuf);
   return ctx;
}

int
GNUNET_ZKLAIM_add_payload (struct GNUNET_ZKLAIM_Context *ctx,
                           struct GNUNET_ZKLAIM_Payload *pl)
{
  zklaim_add_pl (ctx->ctx, pl->pl);
  return GNUNET_OK;
}

int
GNUNET_ZKLAIM_finalize (struct GNUNET_ZKLAIM_Context *ctx)
{
  zklaim_hash_ctx (ctx->ctx);
  zklaim_ctx_sign (ctx->ctx, ctx->priv);
  return 1;
}

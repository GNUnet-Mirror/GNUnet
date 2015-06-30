/*
     This file is part of GNUnet.
     Copyright (C) 2009, 2010, 2012, 2013 Christian Grothoff (and other contributing authors)

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
 * @file fs/fs_publish_ublock.h
 * @brief publish a UBLOCK in GNUnet
 * @see https://gnunet.org/encoding and #2564
 * @author Krista Bennett
 * @author Christian Grothoff
 */
#ifndef FS_PUBLISH_UBLOCK_H
#define FS_PUBLISH_UBLOCK_H

#include "gnunet_util_lib.h"
#include "gnunet_datastore_service.h"
#include "gnunet_fs_service.h"
#include "gnunet_identity_service.h"


/**
 * Decrypt the given UBlock, storing the result in output.
 *
 * @param input input data
 * @param input_len number of bytes in input
 * @param ns public key under which the UBlock was stored
 * @param label label under which the UBlock was stored
 * @param output where to write the result, has input_len bytes
 */
void
GNUNET_FS_ublock_decrypt_ (const void *input,
			   size_t input_len,
			   const struct GNUNET_CRYPTO_EcdsaPublicKey *ns,
			   const char *label,
			   void *output);


/**
 * Context for 'ublock_put_cont'.
 */
struct GNUNET_FS_PublishUblockContext;


/**
 * Signature of a function called as the continuation of a UBlock
 * publication.
 *
 * @param cls closure
 * @param emsg error message, NULL on success
 */
typedef void (*GNUNET_FS_UBlockContinuation) (void *cls,
					      const char *emsg);


/**
 * Publish a UBlock.
 *
 * @param h handle to the file sharing subsystem
 * @param dsh datastore handle to use for storage operation
 * @param label identifier to use
 * @param ulabel update label to use, may be an empty string for none
 * @param ns namespace to publish in
 * @param meta metadata to use
 * @param uri URI to refer to in the UBlock
 * @param bo per-block options
 * @param options publication options
 * @param cont continuation
 * @param cont_cls closure for cont
 * @return NULL on error ('cont' will still be called)
 */
struct GNUNET_FS_PublishUblockContext *
GNUNET_FS_publish_ublock_ (struct GNUNET_FS_Handle *h,
			   struct GNUNET_DATASTORE_Handle *dsh,
			   const char *label,
			   const char *ulabel,
			   const struct GNUNET_CRYPTO_EcdsaPrivateKey *ns,
			   const struct GNUNET_CONTAINER_MetaData *meta,
			   const struct GNUNET_FS_Uri *uri,
			   const struct GNUNET_FS_BlockOptions *bo,
			   enum GNUNET_FS_PublishOptions options,
			   GNUNET_FS_UBlockContinuation cont, void *cont_cls);


/**
 * Abort UBlock publishing operation.
 *
 * @param uc operation to abort.
 */
void
GNUNET_FS_publish_ublock_cancel_ (struct GNUNET_FS_PublishUblockContext *uc);

#endif

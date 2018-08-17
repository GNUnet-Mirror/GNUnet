/*
     This file is part of GNUnet.
     Copyright (C) 2016 GNUnet e.V.

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
 *
 * @file
 * ZKlaim service. Manage ZKlaim issuers etc.
 *
 * @defgroup zklaim  ZKlaim service
 * @{
 */
#ifndef GNUNET_ZKLAIM_SERVICE_H
#define GNUNET_ZKLAIM_SERVICE_H

#ifdef __cplusplus
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif

#include "gnunet_util_lib.h"
#include "zklaim/zklaim.h"

/**
 * Version number of GNUnet Identity Provider API.
 */
#define GNUNET_ZKLAIM_VERSION 0x00000000

/**
 * Handle to access the identity service.
 */
struct GNUNET_ZKLAIM_Handle;

/**
 * Handle for an operation with the zklaim service.
 */
struct GNUNET_ZKLAIM_Operation;

/**
 * Context
 */
struct GNUNET_ZKLAIM_Context;

/**
 * Connect to the ZKlaim service.
 *
 * @param cfg Configuration to contact the service.
 * @return handle to communicate with the service
 */
struct GNUNET_ZKLAIM_Handle *
GNUNET_ZKLAIM_connect (const struct GNUNET_CONFIGURATION_Handle *cfg);

/**
 * Iterator called for each attribute and data.
 *
 * @param cls closure
 * @param name name of attribute
 * @param data attribute data (can be modified)
 */
typedef void
(*GNUNET_ZKLAIM_PayloadIterator) (void *cls,
                                  const char* name,
                                  uint64_t *data);


/**
 * Iterator called for each attribute to set a predicate in proof generation.
 *
 * @param cls closure
 * @param name name of attribute
 * @param data attribute data (can be modified)
 */
typedef void
(*GNUNET_ZKLAIM_PredicateIterator) (void *cls,
                                    const char* name,
                                    enum zklaim_op *op,
                                    uint64_t *ref);


/**
 * Continuation called to notify client about result of the
 * operation.
 *
 * @param cls closure
 * @param success #GNUNET_SYSERR on failure (including timeout/queue drop/failure to validate)
 *                #GNUNET_NO if content was already there or not found
 *                #GNUNET_YES (or other positive value) on success
 * @param emsg NULL on success, otherwise an error message
 */
typedef void
(*GNUNET_ZKLAIM_ContextResult) (void *cls,
                                const struct GNUNET_ZKLAIM_Context *ctx);



/**
 * Continuation called to notify client about result of the
 * operation.
 *
 * @param cls closure
 * @param success #GNUNET_SYSERR on failure (including timeout/queue drop/failure to validate)
 *                #GNUNET_NO if content was already there or not found
 *                #GNUNET_YES (or other positive value) on success
 * @param emsg NULL on success, otherwise an error message
 */
typedef void
(*GNUNET_ZKLAIM_ContinuationWithStatus) (void *cls,
                                         int32_t success,
                                         const char *emsg);


/**
 * Create a new issuer context
 *
 * @param h handle to the identity provider
 * @param pkey private key of the identity
 * @param attr the attribute
 * @param exp_interval the relative expiration interval for the attribute
 * @param cont continuation to call when done
 * @param cont_cls closure for @a cont
 * @return handle to abort the request
 */
struct GNUNET_ZKLAIM_Operation *
GNUNET_ZKLAIM_context_create (struct GNUNET_ZKLAIM_Handle *h,
                              const struct GNUNET_CRYPTO_EcdsaPrivateKey *pkey,
                              const char *context_name,
                              const char *attr_list,
                              GNUNET_ZKLAIM_ContinuationWithStatus cont,
                              void *cont_cls);

int
GNUNET_ZKLAIM_issue_from_context (struct GNUNET_ZKLAIM_Context *ctx,
                                  struct GNUNET_CRYPTO_EcdsaPrivateKey *key,
                                  GNUNET_ZKLAIM_PayloadIterator iter,
                                  void* iter_cls);

/**
 * Lookup context
 */
struct GNUNET_ZKLAIM_Operation*
GNUNET_ZKLAIM_lookup_context (struct GNUNET_ZKLAIM_Handle *h,
                              const char *name,
                              const struct GNUNET_CRYPTO_EcdsaPrivateKey *key,
                              GNUNET_ZKLAIM_ContextResult cont,
                              void* cont_cls);


/**
 * Disconnect from service.
 *
 * @param h service to disconnect
 */
void
GNUNET_ZKLAIM_disconnect (struct GNUNET_ZKLAIM_Handle *h);


/**
 * Cancel an operation.  Note that the operation MAY still
 * be executed; this merely cancels the continuation; if the request
 * was already transmitted, the service may still choose to complete
 * the operation.
 *
 * @param op operation to cancel
 */
void
GNUNET_ZKLAIM_cancel (struct GNUNET_ZKLAIM_Operation *op);

size_t
GNUNET_ZKLAIM_context_serialize (const struct GNUNET_ZKLAIM_Context *ctx,
                                 char **buf);

struct GNUNET_ZKLAIM_Context *
GNUNET_ZKLAIM_context_deserialize (char *data,
                                   size_t data_len);

int
GNUNET_ZKLAIM_context_prove (struct GNUNET_ZKLAIM_Context *ctx,
                             GNUNET_ZKLAIM_PredicateIterator iter,
                             void* iter_cls);

void
GNUNET_ZKLAIM_context_destroy (struct GNUNET_ZKLAIM_Context *ctx);

int
GNUNET_ZKLAIM_context_prove_with_keyfile (struct GNUNET_ZKLAIM_Context *ctx,
                                          const char* pkey_fn,
                                          GNUNET_ZKLAIM_PredicateIterator iter,
                                          void* iter_cls);
int
GNUNET_ZKLAIM_context_verify (struct GNUNET_ZKLAIM_Context *ctx,
                              GNUNET_ZKLAIM_PredicateIterator iter,
                              void* iter_cls);


#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif


/* ifndef GNUNET_ZKLAIM_SERVICE_H */
#endif

/** @} */ /* end of group identity */

/* end of gnunet_zklaim_service.h */

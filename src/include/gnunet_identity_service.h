/*
     This file is part of GNUnet.
     (C) 2013 Christian Grothoff (and other contributing authors)

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
     Free Software Foundation, Inc., 59 Temple Place - Suite 330,
     Boston, MA 02111-1307, USA.
*/

/**
 * @file include/gnunet_identity_service.h
 * @brief Identity service; implements identity management for GNUnet
 * @author Christian Grothoff
 *
 * Egos in GNUnet are ECDSA keys.  You assume an ego by using (signing
 * with) a particular private key.  As GNUnet users are expected to
 * have many egos, we need an identity service to allow users to
 * manage their egos.  The identity service manages the egos (private
 * keys) of the local user; it does NOT manage egos of other users
 * (public keys).  For giving names to other users and manage their
 * public keys securely, we use GNS.
 *
 * @defgroup identity identity management service
 * @{
 */
#ifndef GNUNET_IDENTITY_SERVICE_H
#define GNUNET_IDENTITY_SERVICE_H

#ifdef __cplusplus
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif

#include "gnunet_util_lib.h"


/**
 * Version number of GNUnet Identity API.
 */
#define GNUNET_IDENTITY_VERSION 0x00000000

/**
 * Handle to access the identity service.
 */
struct GNUNET_IDENTITY_Handle;

/**
 * Handle for a ego.
 */
struct GNUNET_IDENTITY_Ego;

/**
 * Handle for an operation with the identity service.
 */
struct GNUNET_IDENTITY_Operation;


/**
 * Obtain the ECC key associated with a ego.
 *
 * @param ego the ego
 * @return associated ECC key, valid as long as the ego is valid
 */
const struct GNUNET_CRYPTO_EcdsaPrivateKey *
GNUNET_IDENTITY_ego_get_private_key (const struct GNUNET_IDENTITY_Ego *ego);


/**
 * Obtain the ego representing 'anonymous' users.
 *
 * @return handle for the anonymous user, must not be freed
 */
const struct GNUNET_IDENTITY_Ego *
GNUNET_IDENTITY_ego_get_anonymous (void);


/**
 * Get the identifier (public key) of an ego.
 *
 * @param ego identity handle with the private key
 * @param pk set to ego's public key
 */
void
GNUNET_IDENTITY_ego_get_public_key (const struct GNUNET_IDENTITY_Ego *ego,
				    struct GNUNET_CRYPTO_EcdsaPublicKey *pk);


/**
 * Method called to inform about the egos of
 * this peer.
 *
 * When used with #GNUNET_IDENTITY_connect, this function is
 * initially called for all egos and then again whenever a
 * ego's name changes or if it is deleted.  At the end of
 * the initial pass over all egos, the function is once called
 * with 'NULL' for @a ego. That does NOT mean that the callback won't
 * be invoked in the future or that there was an error.
 *
 * When used with #GNUNET_IDENTITY_create or #GNUNET_IDENTITY_get,
 * this function is only called ONCE, and 'NULL' being passed in
 * @a ego does indicate an error (i.e. name is taken or no default
 * value is known).  If @a ego is non-NULL and if '*ctx'
 * is set in those callbacks, the value WILL be passed to a subsequent
 * call to the identity callback of #GNUNET_IDENTITY_connect (if
 * that one was not NULL).
 *
 * When an identity is renamed, this function is called with the
 * (known) @a ego but the NEW @a name.
 *
 * When an identity is deleted, this function is called with the
 * (known) ego and "NULL" for the @a name.  In this case,
 * the @a ego is henceforth invalid (and the @a ctx should also be
 * cleaned up).
 *
 * @param cls closure
 * @param ego ego handle
 * @param ctx context for application to store data for this ego
 *                 (during the lifetime of this process, initially NULL)
 * @param name name assigned by the user for this ego,
 *                   NULL if the user just deleted the ego and it
 *                   must thus no longer be used
 */
typedef void
(*GNUNET_IDENTITY_Callback)(void *cls,
                            struct GNUNET_IDENTITY_Ego *ego,
                            void **ctx,
                            const char *name);


/**
 * Connect to the identity service.
 *
 * @param cfg Configuration to contact the identity service.
 * @param cb function to call on all identity events, can be NULL
 * @param cb_cls closure for @a cb
 * @return handle to communicate with identity service
 */
struct GNUNET_IDENTITY_Handle *
GNUNET_IDENTITY_connect (const struct GNUNET_CONFIGURATION_Handle *cfg,
			 GNUNET_IDENTITY_Callback cb,
			 void *cb_cls);


/**
 * Obtain the ego that is currently preferred/default
 * for a service.
 *
 * @param id identity service to query
 * @param service_name for which service is an identity wanted
 * @param cb function to call with the result (will only be called once)
 * @param cb_cls closure for @a cb
 * @return handle to abort the operation
 */
struct GNUNET_IDENTITY_Operation *
GNUNET_IDENTITY_get (struct GNUNET_IDENTITY_Handle *id,
		     const char *service_name,
		     GNUNET_IDENTITY_Callback cb,
		     void *cb_cls);


/**
 * Function called once the requested operation has
 * been completed.
 *
 * @param cls closure
 * @param emsg NULL on success, otherwise an error message
 */
typedef void
(*GNUNET_IDENTITY_Continuation)(void *cls,
                                const char *emsg);


/**
 * Set the preferred/default ego for a service.
 *
 * @param id identity service to inform
 * @param service_name for which service is an identity set
 * @param ego new default identity to be set for this service
 * @param cont function to call once the operation finished
 * @param cont_cls closure for @a cont
 * @return handle to abort the operation
 */
struct GNUNET_IDENTITY_Operation *
GNUNET_IDENTITY_set (struct GNUNET_IDENTITY_Handle *id,
		     const char *service_name,
		     struct GNUNET_IDENTITY_Ego *ego,
		     GNUNET_IDENTITY_Continuation cont,
		     void *cont_cls);


/**
 * Disconnect from identity service.
 *
 * @param h identity service to disconnect
 */
void
GNUNET_IDENTITY_disconnect (struct GNUNET_IDENTITY_Handle *h);


/**
 * Create a new ego with the given name.
 *
 * @param id identity service to use
 * @param name desired name
 * @param cont function to call with the result (will only be called once)
 * @param cont_cls closure for @a cont
 * @return handle to abort the operation
 */
struct GNUNET_IDENTITY_Operation *
GNUNET_IDENTITY_create (struct GNUNET_IDENTITY_Handle *id,
			const char *name,
			GNUNET_IDENTITY_Continuation cont,
			void *cont_cls);


/**
 * Renames an existing ego.
 *
 * @param id identity service to use
 * @param old_name old name
 * @param new_name desired new name
 * @param cb function to call with the result (will only be called once)
 * @param cb_cls closure for @a cb
 * @return handle to abort the operation
 */
struct GNUNET_IDENTITY_Operation *
GNUNET_IDENTITY_rename (struct GNUNET_IDENTITY_Handle *id,
			const char *old_name,
			const char *new_name,
			GNUNET_IDENTITY_Continuation cb,
			void *cb_cls);


/**
 * Delete an existing ego.
 *
 * @param id identity service to use
 * @param name name of the identity to delete
 * @param cb function to call with the result (will only be called once)
 * @param cb_cls closure for @a cb
 * @return handle to abort the operation
 */
struct GNUNET_IDENTITY_Operation *
GNUNET_IDENTITY_delete (struct GNUNET_IDENTITY_Handle *id,
			const char *name,
			GNUNET_IDENTITY_Continuation cb,
			void *cb_cls);


/**
 * Cancel an identity operation.  Note that the operation MAY still
 * be executed; this merely cancels the continuation; if the request
 * was already transmitted, the service may still choose to complete
 * the operation.
 *
 * @param op operation to cancel
 */
void
GNUNET_IDENTITY_cancel (struct GNUNET_IDENTITY_Operation *op);


/* ************* convenience API to lookup an ego ***************** */

/**
 * Function called with the result.
 *
 * @param cls closure
 * @param ego NULL on error / ego not found
 */
typedef void
(*GNUNET_IDENTITY_EgoCallback)(void *cls,
                               const struct GNUNET_IDENTITY_Ego *ego);

/**
 * Handle for ego lookup.
 */
struct GNUNET_IDENTITY_EgoLookup;


/**
 * Lookup an ego by name.
 *
 * @param cfg configuration to use
 * @param name name to look up
 * @param cb callback to invoke with the result
 * @param cb_cls closure for @a cb
 * @return NULL on error
 */
struct GNUNET_IDENTITY_EgoLookup *
GNUNET_IDENTITY_ego_lookup (const struct GNUNET_CONFIGURATION_Handle *cfg,
			    const char *name,
			    GNUNET_IDENTITY_EgoCallback cb,
			    void *cb_cls);


/**
 * Abort ego lookup attempt.
 *
 * @param el handle for lookup to abort
 */
void
GNUNET_IDENTITY_ego_lookup_cancel (struct GNUNET_IDENTITY_EgoLookup *el);


#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

/** @} */ /* end of group identity */

/* ifndef GNUNET_IDENTITY_SERVICE_H */
#endif
/* end of gnunet_identity_service.h */

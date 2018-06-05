/*
     This file is part of GNUnet.
     Copyright (C) 2016 GNUnet e.V.

     GNUnet is free software: you can redistribute it and/or modify it
     under the terms of the GNU General Public License as published
     by the Free Software Foundation, either version 3 of the License,
     or (at your option) any later version.

     GNUnet is distributed in the hope that it will be useful, but
     WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
     Affero General Public License for more details.
*/

/**
 * @author Martin Schanzenbach
 *
 * @file
 * Identity provider service; implements identity provider for GNUnet
 *
 * @defgroup identity-provider  Identity Provider service
 * @{
 */
#ifndef GNUNET_IDENTITY_PROVIDER_SERVICE_H
#define GNUNET_IDENTITY_PROVIDER_SERVICE_H

#ifdef __cplusplus
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif

#include "gnunet_util_lib.h"
#include "gnunet_identity_attribute_lib.h"

/**
 * Version number of GNUnet Identity Provider API.
 */
#define GNUNET_IDENTITY_PROVIDER_VERSION 0x00000000

/**
 * Handle to access the identity service.
 */
struct GNUNET_IDENTITY_PROVIDER_Handle;

/**
 * Handle for a token.
 */
struct GNUNET_IDENTITY_PROVIDER_Token;

/**
 * The ticket
 */
struct GNUNET_IDENTITY_PROVIDER_Ticket
{
  /**
   * The ticket issuer
   */
  struct GNUNET_CRYPTO_EcdsaPublicKey identity;

  /**
   * The ticket audience
   */
  struct GNUNET_CRYPTO_EcdsaPublicKey audience;

  /**
   * The ticket random (NBO)
   */
  uint64_t rnd;
};

/**
 * Handle for an operation with the identity provider service.
 */
struct GNUNET_IDENTITY_PROVIDER_Operation;


/**
 * Connect to the identity provider service.
 *
 * @param cfg Configuration to contact the identity provider service.
 * @return handle to communicate with identity provider service
 */
struct GNUNET_IDENTITY_PROVIDER_Handle *
GNUNET_IDENTITY_PROVIDER_connect (const struct GNUNET_CONFIGURATION_Handle *cfg);

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
(*GNUNET_IDENTITY_PROVIDER_ContinuationWithStatus) (void *cls,
                                            int32_t success,
                                            const char *emsg);


/**
 * Store an attribute.  If the attribute is already present,
 * it is replaced with the new attribute.
 *
 * @param h handle to the identity provider
 * @param pkey private key of the identity
 * @param attr the attribute
 * @param exp_interval the relative expiration interval for the attribute
 * @param cont continuation to call when done
 * @param cont_cls closure for @a cont
 * @return handle to abort the request
 */
struct GNUNET_IDENTITY_PROVIDER_Operation *
GNUNET_IDENTITY_PROVIDER_attribute_store (struct GNUNET_IDENTITY_PROVIDER_Handle *h,
                                          const struct GNUNET_CRYPTO_EcdsaPrivateKey *pkey,
                                          const struct GNUNET_IDENTITY_ATTRIBUTE_Claim *attr,
                                          const struct GNUNET_TIME_Relative *exp_interval,
                                          GNUNET_IDENTITY_PROVIDER_ContinuationWithStatus cont,
                                          void *cont_cls);


/**
 * Process an attribute that was stored in the idp.
 *
 * @param cls closure
 * @param identity the identity
 * @param attr the attribute
 */
typedef void
(*GNUNET_IDENTITY_PROVIDER_AttributeResult) (void *cls,
                                   const struct GNUNET_CRYPTO_EcdsaPublicKey *identity,
                                   const struct GNUNET_IDENTITY_ATTRIBUTE_Claim *attr);



/**
 * List all attributes for a local identity. 
 * This MUST lock the `struct GNUNET_IDENTITY_PROVIDER_Handle`
 * for any other calls than #GNUNET_IDENTITY_PROVIDER_get_attributes_next() and
 * #GNUNET_IDENTITY_PROVIDER_get_attributes_stop. @a proc will be called once
 * immediately, and then again after
 * #GNUNET_IDENTITY_PROVIDER_get_attributes_next() is invoked.
 *
 * On error (disconnect), @a error_cb will be invoked.
 * On normal completion, @a finish_cb proc will be
 * invoked.
 *
 * @param h handle to the idp
 * @param identity identity to access
 * @param error_cb function to call on error (i.e. disconnect),
 *        the handle is afterwards invalid
 * @param error_cb_cls closure for @a error_cb
 * @param proc function to call on each attribute; it
 *        will be called repeatedly with a value (if available)
 * @param proc_cls closure for @a proc
 * @param finish_cb function to call on completion
 *        the handle is afterwards invalid
 * @param finish_cb_cls closure for @a finish_cb
 * @return an iterator handle to use for iteration
 */
struct GNUNET_IDENTITY_PROVIDER_AttributeIterator *
GNUNET_IDENTITY_PROVIDER_get_attributes_start (struct GNUNET_IDENTITY_PROVIDER_Handle *h,
                                               const struct GNUNET_CRYPTO_EcdsaPrivateKey *identity,
                                               GNUNET_SCHEDULER_TaskCallback error_cb,
                                               void *error_cb_cls,
                                               GNUNET_IDENTITY_PROVIDER_AttributeResult proc,
                                               void *proc_cls,
                                               GNUNET_SCHEDULER_TaskCallback finish_cb,
                                               void *finish_cb_cls);


/**
 * Calls the record processor specified in #GNUNET_IDENTITY_PROVIDER_get_attributes_start
 * for the next record.
 *
 * @param it the iterator
 */
void
GNUNET_IDENTITY_PROVIDER_get_attributes_next (struct GNUNET_IDENTITY_PROVIDER_AttributeIterator *it);


/**
 * Stops iteration and releases the idp handle for further calls.  Must
 * be called on any iteration that has not yet completed prior to calling
 * #GNUNET_IDENTITY_PROVIDER_disconnect.
 *
 * @param it the iterator
 */
void
GNUNET_IDENTITY_PROVIDER_get_attributes_stop (struct GNUNET_IDENTITY_PROVIDER_AttributeIterator *it);


/**
 * Method called when a token has been issued.
 * On success returns a ticket that can be given to the audience to retrive the
 * token
 *
 * @param cls closure
 * @param ticket the ticket
 */
typedef void
(*GNUNET_IDENTITY_PROVIDER_TicketCallback)(void *cls,
                            const struct GNUNET_IDENTITY_PROVIDER_Ticket *ticket);

/**
 * Issues a ticket to another identity. The identity may use
 * GNUNET_IDENTITY_PROVIDER_ticket_consume to consume the ticket
 * and retrieve the attributes specified in the AttributeList.
 *
 * @param h the identity provider to use
 * @param iss the issuing identity
 * @param rp the subject of the ticket (the relying party)
 * @param attrs the attributes that the relying party is given access to
 * @param cb the callback
 * @param cb_cls the callback closure
 * @return handle to abort the operation
 */
struct GNUNET_IDENTITY_PROVIDER_Operation *
GNUNET_IDENTITY_PROVIDER_ticket_issue (struct GNUNET_IDENTITY_PROVIDER_Handle *h,
                                       const struct GNUNET_CRYPTO_EcdsaPrivateKey *iss,
                                       const struct GNUNET_CRYPTO_EcdsaPublicKey *rp,
                                       const struct GNUNET_IDENTITY_ATTRIBUTE_ClaimList *attrs,
                                       GNUNET_IDENTITY_PROVIDER_TicketCallback cb,
                                       void *cb_cls);

/**
 * Revoked an issued ticket. The relying party will be unable to retrieve
 * updated attributes.
 *
 * @param h the identity provider to use
 * @param identity the issuing identity
 * @param ticket the ticket to revoke
 * @param cb the callback
 * @param cb_cls the callback closure
 * @return handle to abort the operation
 */
struct GNUNET_IDENTITY_PROVIDER_Operation *
GNUNET_IDENTITY_PROVIDER_ticket_revoke (struct GNUNET_IDENTITY_PROVIDER_Handle *h,
                                        const struct GNUNET_CRYPTO_EcdsaPrivateKey *identity,
                                        const struct GNUNET_IDENTITY_PROVIDER_Ticket *ticket,
                                        GNUNET_IDENTITY_PROVIDER_ContinuationWithStatus cb,
                                        void *cb_cls);



/**
 * Consumes an issued ticket. The ticket is persisted
 * and used to retrieve identity information from the issuer
 *
 * @param h the identity provider to use
 * @param identity the identity that is the subject of the issued ticket (the audience)
 * @param ticket the issued ticket to consume
 * @param cb the callback to call
 * @param cb_cls the callback closure
 * @return handle to abort the operation
 */
struct GNUNET_IDENTITY_PROVIDER_Operation *
GNUNET_IDENTITY_PROVIDER_ticket_consume (struct GNUNET_IDENTITY_PROVIDER_Handle *h,
                                         const struct GNUNET_CRYPTO_EcdsaPrivateKey *identity,
                                         const struct GNUNET_IDENTITY_PROVIDER_Ticket *ticket,
                                         GNUNET_IDENTITY_PROVIDER_AttributeResult cb,
                                         void *cb_cls);

/**
 * Lists all tickets that have been issued to remote
 * identites (relying parties)
 *
 * @param h the identity provider to use
 * @param identity the issuing identity
 * @param error_cb function to call on error (i.e. disconnect),
 *        the handle is afterwards invalid
 * @param error_cb_cls closure for @a error_cb
 * @param proc function to call on each ticket; it
 *        will be called repeatedly with a value (if available)
 * @param proc_cls closure for @a proc
 * @param finish_cb function to call on completion
 *        the handle is afterwards invalid
 * @param finish_cb_cls closure for @a finish_cb
 * @return an iterator handle to use for iteration
 */
struct GNUNET_IDENTITY_PROVIDER_TicketIterator *
GNUNET_IDENTITY_PROVIDER_ticket_iteration_start (struct GNUNET_IDENTITY_PROVIDER_Handle *h,
                                                 const struct GNUNET_CRYPTO_EcdsaPrivateKey *identity,
                                                 GNUNET_SCHEDULER_TaskCallback error_cb,
                                                 void *error_cb_cls,
                                                 GNUNET_IDENTITY_PROVIDER_TicketCallback proc,
                                                 void *proc_cls,
                                                 GNUNET_SCHEDULER_TaskCallback finish_cb,
                                                 void *finish_cb_cls);

/**
 * Lists all tickets that have been issued to remote
 * identites (relying parties)
 *
 * @param h the identity provider to use
 * @param identity the issuing identity
 * @param error_cb function to call on error (i.e. disconnect),
 *        the handle is afterwards invalid
 * @param error_cb_cls closure for @a error_cb
 * @param proc function to call on each ticket; it
 *        will be called repeatedly with a value (if available)
 * @param proc_cls closure for @a proc
 * @param finish_cb function to call on completion
 *        the handle is afterwards invalid
 * @param finish_cb_cls closure for @a finish_cb
 * @return an iterator handle to use for iteration
 */
struct GNUNET_IDENTITY_PROVIDER_TicketIterator *
GNUNET_IDENTITY_PROVIDER_ticket_iteration_start_rp (struct GNUNET_IDENTITY_PROVIDER_Handle *h,
                                                    const struct GNUNET_CRYPTO_EcdsaPublicKey *identity,
                                                    GNUNET_SCHEDULER_TaskCallback error_cb,
                                                    void *error_cb_cls,
                                                    GNUNET_IDENTITY_PROVIDER_TicketCallback proc,
                                                    void *proc_cls,
                                                    GNUNET_SCHEDULER_TaskCallback finish_cb,
                                                    void *finish_cb_cls);

/**
 * Calls the record processor specified in #GNUNET_IDENTITY_PROVIDER_ticket_iteration_start
 * for the next record.
 *
 * @param it the iterator
 */
void
GNUNET_IDENTITY_PROVIDER_ticket_iteration_next (struct GNUNET_IDENTITY_PROVIDER_TicketIterator *it);

/**
 * Stops iteration and releases the idp handle for further calls.  Must
 * be called on any iteration that has not yet completed prior to calling
 * #GNUNET_IDENTITY_PROVIDER_disconnect.
 *
 * @param it the iterator
 */
void
GNUNET_IDENTITY_PROVIDER_ticket_iteration_stop (struct GNUNET_IDENTITY_PROVIDER_TicketIterator *it);

/**
 * Disconnect from identity provider service.
 *
 * @param h identity provider service to disconnect
 */
void
GNUNET_IDENTITY_PROVIDER_disconnect (struct GNUNET_IDENTITY_PROVIDER_Handle *h);


/**
 * Cancel an identity provider operation.  Note that the operation MAY still
 * be executed; this merely cancels the continuation; if the request
 * was already transmitted, the service may still choose to complete
 * the operation.
 *
 * @param op operation to cancel
 */
void
GNUNET_IDENTITY_PROVIDER_cancel (struct GNUNET_IDENTITY_PROVIDER_Operation *op);

#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif


/* ifndef GNUNET_IDENTITY_PROVIDER_SERVICE_H */
#endif

/** @} */ /* end of group identity */

/* end of gnunet_identity_provider_service.h */

/*
     This file is part of GNUnet.
     Copyright (C) 2016 GNUnet e.V.

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
 * Handle for a ticket DEPRECATED
 */
struct GNUNET_IDENTITY_PROVIDER_Ticket;

/**
 * The ticket
 */
struct GNUNET_IDENTITY_PROVIDER_Ticket2
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
 * Flags that can be set for an attribute.
 */
enum GNUNET_IDENTITY_PROVIDER_AttributeType
{

  /**
   * No value attribute.
   */
  GNUNET_IDENTITY_PROVIDER_AT_NULL = 0,

  /**
   * String attribute.
   */
  GNUNET_IDENTITY_PROVIDER_AT_STRING = 1,

};



/**
 * An attribute.
 */
struct GNUNET_IDENTITY_PROVIDER_Attribute
{

  /**
   * Type of Attribute.
   */
  uint32_t attribute_type;

  /**
   * Number of bytes in @e data.
   */
  size_t data_size;

  /**
   * The name of the attribute. Note "name" must never be individually
   * free'd
   */
  const char* name;

  /**
   * Binary value stored as attribute value.  Note: "data" must never
   * be individually 'malloc'ed, but instead always points into some
   * existing data area.
   */
  const void *data;

};

struct GNUNET_IDENTITY_PROVIDER_AttributeList
{
  /**
   * List head
   */
  struct GNUNET_IDENTITY_PROVIDER_AttributeListEntry *list_head;

  /**
   * List tail
   */
  struct GNUNET_IDENTITY_PROVIDER_AttributeListEntry *list_tail;
};

struct GNUNET_IDENTITY_PROVIDER_AttributeListEntry
{
  /**
   * DLL
   */
  struct GNUNET_IDENTITY_PROVIDER_AttributeListEntry *prev;

  /**
   * DLL
   */
  struct GNUNET_IDENTITY_PROVIDER_AttributeListEntry *next;

  /**
   * The attribute
   */
  struct GNUNET_IDENTITY_PROVIDER_Attribute *attribute;
};

/**
 * Method called when a token has been exchanged for a ticket.
 * On success returns a token
 *
 * @param cls closure
 * @param token the token
 */
typedef void
(*GNUNET_IDENTITY_PROVIDER_ExchangeCallback)(void *cls,
                            const struct GNUNET_IDENTITY_PROVIDER_Token *token,
                            uint64_t ticket_nonce);

/** TODO DEPRECATED
 * Method called when a token has been issued.
 * On success returns a ticket that can be given to the audience to retrive the
 * token
 *
 * @param cls closure
 * @param grant the label in GNS pointing to the token
 * @param ticket the ticket
 * @param token the issued token
 * @param name name assigned by the user for this ego,
 *                   NULL if the user just deleted the ego and it
 *                   must thus no longer be used
 */
typedef void
(*GNUNET_IDENTITY_PROVIDER_IssueCallback)(void *cls,
                            const char *grant,
                            const struct GNUNET_IDENTITY_PROVIDER_Ticket *ticket,
                            const struct GNUNET_IDENTITY_PROVIDER_Token *token);


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
 * @param cont continuation to call when done
 * @param cont_cls closure for @a cont
 * @return handle to abort the request
 */
struct GNUNET_IDENTITY_PROVIDER_Operation *
GNUNET_IDENTITY_PROVIDER_attribute_store (struct GNUNET_IDENTITY_PROVIDER_Handle *h,
                                          const struct GNUNET_CRYPTO_EcdsaPrivateKey *pkey,
                                          const struct GNUNET_IDENTITY_PROVIDER_Attribute *attr,
                                          GNUNET_IDENTITY_PROVIDER_ContinuationWithStatus cont,
                                          void *cont_cls);


/**
 * Create a new attribute.
 *
 * @param name the attribute name
 * @param type the attribute type
 * @param data the attribute value
 * @param data_size the attribute value size
 * @return the new attribute
 */
struct GNUNET_IDENTITY_PROVIDER_Attribute *
GNUNET_IDENTITY_PROVIDER_attribute_new (const char* attr_name,
                                        uint32_t attr_type,
                                        const void* data,
                                        size_t data_size);

/**
 * Process an attribute that was stored in the idp.
 *
 * @param cls closure
 * @param attr the attribute
 */
typedef void
(*GNUNET_IDENTITY_PROVIDER_AttributeResult) (void *cls,
                                   const struct GNUNET_CRYPTO_EcdsaPublicKey *identity,
                                   const struct GNUNET_IDENTITY_PROVIDER_Attribute *attr);



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
                            const struct GNUNET_IDENTITY_PROVIDER_Ticket2 *ticket);

/**
 * Issues a ticket to another identity. The identity may use
 * @GNUNET_IDENTITY_PROVIDER_authorization_ticket_consume to consume the ticket
 * and retrieve the attributes specified in the AttributeList.
 *
 * @param id the identity provider to use
 * @param iss the issuing identity
 * @param rp the subject of the ticket (the relying party)
 * @param attr the attributes that the relying party is given access to
 * @param cb the callback
 * @param cb_cls the callback closure
 * @return handle to abort the operation
 */
struct GNUNET_IDENTITY_PROVIDER_Operation *
GNUNET_IDENTITY_PROVIDER_idp_ticket_issue (struct GNUNET_IDENTITY_PROVIDER_Handle *id,
                                           const struct GNUNET_CRYPTO_EcdsaPrivateKey *iss,
                                           const struct GNUNET_CRYPTO_EcdsaPublicKey *rp,
                                           const struct GNUNET_IDENTITY_PROVIDER_AttributeList *attrs,
                                           GNUNET_IDENTITY_PROVIDER_TicketCallback cb,
                                           void *cb_cls);

/** TODO
 * Revoked an issued ticket. The relying party will be unable to retrieve
 * updated attributes.
 *
 * @param id the identity provider to use
 * @param identity the issuing identity
 * @param ticket the ticket to revoke
 * @param cb the callback
 * @param cb_cls the callback closure
 * @return handle to abort the operation
 */
struct GNUNET_IDENTITY_PROVIDER_Operation *
GNUNET_IDENTITY_PROVIDER_idp_ticket_revoke (struct GNUNET_IDENTITY_PROVIDER_Handle *id,
                                            const struct GNUNET_CRYPTO_EcdsaPrivateKey *identity,
                                            const struct GNUNET_IDENTITY_PROVIDER_Ticket *ticket,
                                            GNUNET_IDENTITY_PROVIDER_ContinuationWithStatus cb,
                                            void *cb_cls);



/**
 * Consumes an issued ticket. The ticket is persisted
 * and used to retrieve identity information from the issuer
 *
 * @param id the identity provider to use
 * @param identity the identity that is the subject of the issued ticket (the relying party)
 * @param ticket the issued ticket to consume
 * @param cb the callback to call
 * @param cb_cls the callback closure
 * @return handle to abort the operation
 */
struct GNUNET_IDENTITY_PROVIDER_Operation *
GNUNET_IDENTITY_PROVIDER_rp_ticket_consume (struct GNUNET_IDENTITY_PROVIDER_Handle *id,
                                            const struct GNUNET_CRYPTO_EcdsaPrivateKey * identity,
                                            const struct GNUNET_IDENTITY_PROVIDER_Ticket2 *ticket,
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
GNUNET_IDENTITY_PROVIDER_idp_ticket_iteration_start (struct GNUNET_IDENTITY_PROVIDER_Handle *h,
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
 * @param id the identity provider to use
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

/** TODO remove DEPRECATED
 * Issue a token for a specific audience.
 *
 * @param id identity provider service to use
 * @param iss issuer (identity)
 * @param aud audience (identity)
 * @param scope the identity attributes requested, comman separated
 * @param expiration the token expiration
 * @param nonce the nonce that will be included in token and ticket
 * @param cb callback to call with result
 * @param cb_cls closure
 * @return handle to abort the operation
 */
struct GNUNET_IDENTITY_PROVIDER_Operation *
GNUNET_IDENTITY_PROVIDER_issue_token (struct GNUNET_IDENTITY_PROVIDER_Handle *id,
                                      const struct GNUNET_CRYPTO_EcdsaPrivateKey *iss_key,
                                      const struct GNUNET_CRYPTO_EcdsaPublicKey *aud_key,
                                      const char* scope,
                                      const char* vattr,
                                      struct GNUNET_TIME_Absolute expiration,
                                      uint64_t nonce,
                                      GNUNET_IDENTITY_PROVIDER_IssueCallback cb,
                                      void *cb_cls);


/** TODO remove DEPRECATED
 * Exchange a ticket for a token. Intended to be used by audience that
 * received a ticket.
 *
 * @param id identity provider service to use
 * @param ticket the ticket to exchange
 * @param aud_privkey the audience of the ticket
 * @param cont function to call once the operation finished
 * @param cont_cls closure for @a cont
 * @return handle to abort the operation
 */
struct GNUNET_IDENTITY_PROVIDER_Operation *
GNUNET_IDENTITY_PROVIDER_exchange_ticket (struct GNUNET_IDENTITY_PROVIDER_Handle *id,
                                          const struct GNUNET_IDENTITY_PROVIDER_Ticket *ticket,
                                          const struct GNUNET_CRYPTO_EcdsaPrivateKey *aud_privkey,
                                          GNUNET_IDENTITY_PROVIDER_ExchangeCallback cont,
                                          void *cont_cls);


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


/**
 * Convenience API
 */

/**
 * Destroy token
 *
 * @param token the token
 */
void
GNUNET_IDENTITY_PROVIDER_token_destroy(struct GNUNET_IDENTITY_PROVIDER_Token *token);

/**
 * Returns string representation of token. A JSON-Web-Token.
 *
 * @param token the token
 * @return The JWT (must be freed)
 */
char *
GNUNET_IDENTITY_PROVIDER_token_to_string (const struct GNUNET_IDENTITY_PROVIDER_Token *token);

/**
 * Returns string representation of ticket. Base64-Encoded
 *
 * @param ticket the ticket
 * @return the Base64-Encoded ticket
 */
char *
GNUNET_IDENTITY_PROVIDER_ticket_to_string (const struct GNUNET_IDENTITY_PROVIDER_Ticket *ticket);

/**
 * Created a ticket from a string (Base64 encoded ticket)
 *
 * @param input Base64 encoded ticket
 * @param ticket pointer where the ticket is stored
 * @return GNUNET_OK
 */
int
GNUNET_IDENTITY_PROVIDER_string_to_ticket (const char* input,
                                           struct GNUNET_IDENTITY_PROVIDER_Ticket **ticket);

/**
 * Destroys a ticket
 *
 * @param ticket the ticket to destroy
 */
void
GNUNET_IDENTITY_PROVIDER_ticket_destroy(struct GNUNET_IDENTITY_PROVIDER_Ticket *ticket);

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

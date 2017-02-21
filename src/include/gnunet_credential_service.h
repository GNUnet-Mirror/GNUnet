/*
      This file is part of GNUnet
      Copyright (C) 2012-2014 GNUnet e.V.

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
 * API to the Credential service
 *
 * @defgroup credential  Credential service
 * Credentials
 *
 * @{
 */
#ifndef GNUNET_CREDENTIAL_SERVICE_H
#define GNUNET_CREDENTIAL_SERVICE_H

#include "gnunet_util_lib.h"
#include "gnunet_gns_service.h"

#ifdef __cplusplus
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif


/**
 * Connection to the Credential service.
 */
struct GNUNET_CREDENTIAL_Handle;

/**
 * Handle to control a lookup operation.
 */
struct GNUNET_CREDENTIAL_LookupRequest;


/**
 * Initialize the connection with the Credential service.
 *
 * @param cfg configuration to use
 * @return handle to the Credential service, or NULL on error
 */
struct GNUNET_Credential_Handle *
GNUNET_CREDENTIAL_connect (const struct GNUNET_CONFIGURATION_Handle *cfg);


/**
 * Shutdown connection with the Credentail service.
 *
 * @param handle connection to shut down
 */
void
GNUNET_CREDENTIAL_disconnect (struct GNUNET_CREDENTIAL_Handle *handle);


/**
 * Iterator called on obtained result for a Credential lookup.
 *
 * @param cls closure
 * @param issuer the issuer chain
 * @param issuer_len length of issuer chain
 * @param value the value returned
 */
typedef void
(*GNUNET_CREDENTIAL_LookupResultProcessor) (void *cls,
                                            struct GNUNET_IDENTITY_Ego *issuer,
                                            uint16_t issuer_len,
                                            const struct GNUNET_CREDENTIAL_Value *value);


/**
 * Perform an asynchronous lookup operation for a credential.
 *
 * @param handle handle to the Credential service
 * @param credential the credential to look up
 * @param subject Ego to check the credential for
 * @param proc function to call on result
 * @param proc_cls closure for processor
 * @return handle to the queued request
 */
struct GNUNET_CREDENTIAL_LookupRequest *
GNUNET_CREDENTIAL_lookup (struct GNUNET_CREDENTIAL_Handle *handle,
                          const char *credential,
                          const struct GNUNET_IDENTITY_Ego *subject,
                          GNUNET_CREDENTIAL_LookupResultProcessor proc,
                          void *proc_cls);


/**
 * Issue a credential to an identity
 *
 * @param handle handle to the Credential service
 * @param issuer the identity that issues the credential
 * @param subject the subject of the credential
 * @param credential the name of the credential
 * @param value the value of the credential
 * @return handle to the queued request
 */
struct GNUNET_CREDENTIAL_IssueRequest *
GNUNET_CREDENTIAL_issue (struct GNUNET_CREDENTIAL_Handle *handle,
                         struct GNUNET_IDENTITY_Ego *issuer,
                         struct GNUNET_IDENTITY_Ego *subject,
                         const char *credential,
                         struct GNUNET_CREDENTIAL_Value *value,
                         GNUNET_CREDENTIAL_IssueResultProcessor proc,
                         void *proc_cls);

/**
 * Remove a credential
 *
 * @param handle handle to the Credential service
 * @param issuer the identity that issued the credential
 * @param subject the subject of the credential
 * @param credential the name of the credential
 * @return handle to the queued request
 */
struct GNUNET_CREDENTIAL_IssueRequest *
GNUNET_CREDENTIAL_remove (struct GNUNET_CREDENTIAL_Handle *handle,
                          struct GNUNET_IDENTITY_Ego *issuer,
                          struct GNUNET_IDENTITY_Ego *subject,
                          const char *credential,
                          GNUNET_CREDENTIAL_IssueResultProcessor proc,
                          void *proc_cls);



/**
 * Cancel pending lookup request
 *
 * @param lr the lookup request to cancel
 */
void
GNUNET_CREDENTIAL_lookup_cancel (struct GNUNET_CREDENTIAL_LookupRequest *lr);


#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

#endif

/** @} */  /* end of group */

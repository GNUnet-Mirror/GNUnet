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
#include "gnunet_identity_service.h"

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

/*
* Enum used for checking whether the issuer has the authority to issue credentials or is just a subject
*/
enum GNUNET_CREDENTIAL_CredentialFlags {

  //Subject had credentials before, but have been revoked now
  GNUNET_CREDENTIAL_FLAG_REVOKED=0,

  //Subject flag indicates that the subject is a holder of this credential and may present it as such
  GNUNET_CREDENTIAL_FLAG_SUBJECT=1,

  //Issuer flag is used to signify that the subject is allowed to issue this credential and delegate issuance
  GNUNET_CREDENTIAL_FLAG_ISSUER=2

};

GNUNET_NETWORK_STRUCT_BEGIN
/*
* Data stored in the credential record 
*/
struct GNUNET_CREDENTIAL_RecordData {
  
  /*
  * Key of the 
  */
  struct GNUNET_CRYPTO_EcdsaPublicKey subject_key;
  
  struct GNUNET_CRYPTO_EcdsaPublicKey issuer_key;


  uint32_t credential_flags GNUNET_PACKED;

};

GNUNET_NETWORK_STRUCT_END



/**
 * Initialize the connection with the Credential service.
 *
 * @param cfg configuration to use
 * @return handle to the Credential service, or NULL on error
 */
struct GNUNET_CREDENTIAL_Handle *
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
 * @param rd the records in reply
 */
typedef void (*GNUNET_CREDENTIAL_VerifyResultProcessor) (void *cls,
						  struct GNUNET_IDENTITY_Ego *issuer,
              uint16_t issuer_len,
						  const struct GNUNET_CREDENTIAL_RecordData *data);


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
struct GNUNET_CREDENTIAL_VerifyRequest*
GNUNET_CREDENTIAL_verify (struct GNUNET_CREDENTIAL_Handle *handle,
                          const char *issuer_attribute,
                          const char *subject_attribute,
                          const struct GNUNET_CRYPTO_EcdsaPublicKey *subject_key,
                          const struct GNUNET_CRYPTO_EcdsaPublicKey *issuer_key,
                          uint32_t credential_flags,
                          GNUNET_CREDENTIAL_VerifyResultProcessor proc,
                          void *proc_cls);

/**
 * Issue a credential to an identity
 *
 * @param handle handle to the Credential service
 * @param issuer the identity that issues the credential
 * @param subject the subject of the credential
 * @param credential the name of the credential
 * @param data the data of the credential
 * @return handle to the queued request
 */
/**struct GNUNET_CREDENTIAL_IssueRequest *
GNUNET_CREDENTIAL_issue (struct GNUNET_CREDENTIAL_Handle *handle,
                         struct GNUNET_IDENTITY_Ego *issuer,
                         struct GNUNET_IDENTITY_Ego *subject,
                         const char *credential,
                         struct GNUNET_CREDENTIAL_Data *data,
                         GNUNET_CREDENTIAL_IssueResultProcessor proc,
                         void *proc_cls);
*/
/**
 * Remove a credential
 *
 * @param handle handle to the Credential service
 * @param issuer the identity that issued the credential
 * @param subject the subject of the credential
 * @param credential the name of the credential
 * @return handle to the queued request
 */
 /**
struct GNUNET_CREDENTIAL_IssueRequest *
GNUNET_CREDENTIAL_remove (struct GNUNET_CREDENTIAL_Handle *handle,
                          struct GNUNET_IDENTITY_Ego *issuer,
                          struct GNUNET_IDENTITY_Ego *subject,
                          const char *credential,
                          GNUNET_CREDENTIAL_IssueResultProcessor proc,
                          void *proc_cls);
*/


/**
 * Cancel pending lookup request
 *
 * @param lr the lookup request to cancel
 */
void
GNUNET_CREDENTIAL_verify_cancel (struct GNUNET_CREDENTIAL_VerifyRequest *vr);


#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

#endif

/** @} */  /* end of group */

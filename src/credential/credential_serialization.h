/*
     This file is part of GNUnet.
     Copyright (C) 2009-2013, 2016 GNUnet e.V.

     GNUnet is free software: you can redistribute it and/or modify it
     under the terms of the GNU Affero General Public License as published
     by the Free Software Foundation, either version 3 of the License,
     or (at your option) any later version.

     GNUnet is distributed in the hope that it will be useful, but
     WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
     Affero General Public License for more details.
*/


/**
 * @file credential/credential_serialization.h
 * @brief API to serialize and deserialize delegation chains 
 * and credentials
 * @author Martin Schanzenbach
 */
#ifndef CREDENTIAL_SERIALIZATION_H
#define CREDENTIAL_SERIALIZATION_H

#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_constants.h"
#include "gnunet_credential_service.h"

/**
 * Calculate how many bytes we will need to serialize
 * the given delegation record
 *
 * @param ds_count number of delegation chain entries
 * @param dsr array of #GNUNET_CREDENTIAL_Delegation
 * @return the required size to serialize
 */
size_t
GNUNET_CREDENTIAL_delegation_set_get_size (unsigned int ds_count,
                                           const struct GNUNET_CREDENTIAL_DelegationSet *dsr);

/**
 * Serizalize the given delegation record entries
 *
 * @param d_count number of delegation chain entries
 * @param dsr array of #GNUNET_CREDENTIAL_Delegation
 * @param dest_size size of the destination
 * @param dest where to store the result
 * @return the size of the data, -1 on failure
 */
ssize_t
GNUNET_CREDENTIAL_delegation_set_serialize (unsigned int d_count,
                                            const struct GNUNET_CREDENTIAL_DelegationSet *dsr,
                                            size_t dest_size,
                                            char *dest);


/**
 * Deserialize the given destination
 *
 * @param len size of the serialized delegation recird
 * @param src the serialized data
 * @param d_count the number of delegation chain entries
 * @param dsr where to put the delegation chain entries
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on error
 */
int
GNUNET_CREDENTIAL_delegation_set_deserialize (size_t len,
                                              const char *src,
                                              unsigned int d_count,
                                              struct GNUNET_CREDENTIAL_DelegationSet *dsr);

  /**
   * Calculate how many bytes we will need to serialize
   * the given delegation chain and credential
   *
   * @param d_count number of delegation chain entries
   * @param dd array of #GNUNET_CREDENTIAL_Delegation
   * @param c_count number of credential entries
   * @param cd a #GNUNET_CREDENTIAL_Credential
   * @return the required size to serialize
   */
  size_t
    GNUNET_CREDENTIAL_delegation_chain_get_size (unsigned int d_count,
                                                 const struct GNUNET_CREDENTIAL_Delegation *dd,
                                                 unsigned int c_count,
                                                 const struct GNUNET_CREDENTIAL_Credential *cd);

  /**
   * Serizalize the given delegation chain entries and credential
   *
   * @param d_count number of delegation chain entries
   * @param dd array of #GNUNET_CREDENTIAL_Delegation
   * @param c_count number of credential entries
   * @param cd a #GNUNET_CREDENTIAL_Credential
   * @param dest_size size of the destination
   * @param dest where to store the result
   * @return the size of the data, -1 on failure
   */
  ssize_t
    GNUNET_CREDENTIAL_delegation_chain_serialize (unsigned int d_count,
                                                  const struct GNUNET_CREDENTIAL_Delegation *dd,
                                                  unsigned int c_count,
                                                  const struct GNUNET_CREDENTIAL_Credential *cd,
                                                  size_t dest_size,
                                                  char *dest);


  /**
   * Deserialize the given destination
   *
   * @param len size of the serialized delegation chain and cred
   * @param src the serialized data
   * @param d_count the number of delegation chain entries
   * @param dd where to put the delegation chain entries
   * @param c_count number of credential entries
   * @param cd where to put the credential data
   * @return #GNUNET_OK on success, #GNUNET_SYSERR on error
   */
  int
    GNUNET_CREDENTIAL_delegation_chain_deserialize (size_t len,
                                                    const char *src,
                                                    unsigned int d_count,
                                                    struct GNUNET_CREDENTIAL_Delegation *dd,
                                                    unsigned int c_count,
                                                    struct GNUNET_CREDENTIAL_Credential *cd);
  size_t
  GNUNET_CREDENTIAL_credentials_get_size (unsigned int c_count,
                                          const struct GNUNET_CREDENTIAL_Credential *cd);

ssize_t
GNUNET_CREDENTIAL_credentials_serialize (unsigned int c_count,
                                         const struct GNUNET_CREDENTIAL_Credential *cd,
                                         size_t dest_size,
                                         char *dest);


int
GNUNET_CREDENTIAL_credentials_deserialize (size_t len,
                                           const char *src,
                                           unsigned int c_count,
                                           struct GNUNET_CREDENTIAL_Credential *cd);


int
GNUNET_CREDENTIAL_credential_serialize (struct GNUNET_CREDENTIAL_Credential *cred,
                                        char **data);

struct GNUNET_CREDENTIAL_Credential*
GNUNET_CREDENTIAL_credential_deserialize (const char* data,
                                          size_t data_size);
#endif
/* end of credential_serialization.h */

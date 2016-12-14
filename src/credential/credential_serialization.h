/*
     This file is part of GNUnet.
     Copyright (C) 2009-2013, 2016 GNUnet e.V.

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
 * @file credential/credential_serialization.h
 * @brief API to serialize and deserialize delegation chains 
 * and credentials
 * @author Martin Schanzenbach
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_constants.h"
#include "gnunet_credential_service.h"

/**
 * Calculate how many bytes we will need to serialize
 * the given delegation chain and credential
 *
 * @param d_count number of delegation chain entries
 * @param dd array of #GNUNET_CREDENTIAL_Delegation
 * @param cd a #GNUNET_CREDENTIAL_Credential
 * @return the required size to serialize
 */
size_t
GNUNET_CREDENTIAL_delegation_chain_get_size (unsigned int d_count,
                                             const struct GNUNET_CREDENTIAL_Delegation *dd,
                                             const struct GNUNET_CREDENTIAL_Credential *cd);

/**
 * Serizalize the given delegation chain entries and credential
 *
 * @param d_count number of delegation chain entries
 * @param dd array of #GNUNET_CREDENTIAL_Delegation
 * @param cd a #GNUNET_CREDENTIAL_Credential
 * @param dest_size size of the destination
 * @param dest where to store the result
 * @return the size of the data, -1 on failure
 */
ssize_t
GNUNET_CREDENTIAL_delegation_chain_serialize (unsigned int d_count,
                                              const struct GNUNET_CREDENTIAL_Delegation *dd,
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
 * @param cd where to put the credential data
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on error
 */
int
GNUNET_CREDENTIAL_delegation_chain_deserialize (size_t len,
                                                const char *src,
                                                unsigned int d_count,
                                                struct GNUNET_CREDENTIAL_Delegation *dd,
                                                struct GNUNET_CREDENTIAL_Credential *cd);
/* end of credential_serialization.h */

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

     You should have received a copy of the GNU Affero General Public License
     along with this program.  If not, see <http://www.gnu.org/licenses/>.

     SPDX-License-Identifier: AGPL3.0-or-later
*/


/**
 * @file abd/abd_serialization.h
 * @brief API to serialize and deserialize delegation chains
 * and abds
 * @author Martin Schanzenbach
 */
#ifndef ABD_SERIALIZATION_H
#define ABD_SERIALIZATION_H

#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_constants.h"
#include "gnunet_abd_service.h"

/**
 * Calculate how many bytes we will need to serialize
 * the given delegation record
 *
 * @param ds_count number of delegation chain entries
 * @param dsr array of #GNUNET_ABD_Delegation
 * @return the required size to serialize
 */
size_t
GNUNET_ABD_delegation_set_get_size (
  unsigned int ds_count,
  const struct GNUNET_ABD_DelegationSet *dsr);

/**
 * Serizalize the given delegation record entries
 *
 * @param d_count number of delegation chain entries
 * @param dsr array of #GNUNET_ABD_Delegation
 * @param dest_size size of the destination
 * @param dest where to store the result
 * @return the size of the data, -1 on failure
 */
ssize_t
GNUNET_ABD_delegation_set_serialize (
  unsigned int d_count,
  const struct GNUNET_ABD_DelegationSet *dsr,
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
GNUNET_ABD_delegation_set_deserialize (
  size_t len,
  const char *src,
  unsigned int d_count,
  struct GNUNET_ABD_DelegationSet *dsr);

/**
   * Calculate how many bytes we will need to serialize
   * the given delegation chain and abd
   *
   * @param d_count number of delegation chain entries
   * @param dd array of #GNUNET_ABD_Delegation
   * @param c_count number of abd entries
   * @param cd a #GNUNET_ABD_Delegate
   * @return the required size to serialize
   */
size_t
GNUNET_ABD_delegation_chain_get_size (
  unsigned int d_count,
  const struct GNUNET_ABD_Delegation *dd,
  unsigned int c_count,
  const struct GNUNET_ABD_Delegate *cd);

/**
   * Serizalize the given delegation chain entries and abd
   *
   * @param d_count number of delegation chain entries
   * @param dd array of #GNUNET_ABD_Delegation
   * @param c_count number of abd entries
   * @param cd a #GNUNET_ABD_Delegate
   * @param dest_size size of the destination
   * @param dest where to store the result
   * @return the size of the data, -1 on failure
   */
ssize_t
GNUNET_ABD_delegation_chain_serialize (
  unsigned int d_count,
  const struct GNUNET_ABD_Delegation *dd,
  unsigned int c_count,
  const struct GNUNET_ABD_Delegate *cd,
  size_t dest_size,
  char *dest);


/**
   * Deserialize the given destination
   *
   * @param len size of the serialized delegation chain and cred
   * @param src the serialized data
   * @param d_count the number of delegation chain entries
   * @param dd where to put the delegation chain entries
   * @param c_count number of abd entries
   * @param cd where to put the abd data
   * @return #GNUNET_OK on success, #GNUNET_SYSERR on error
   */
int
GNUNET_ABD_delegation_chain_deserialize (
  size_t len,
  const char *src,
  unsigned int d_count,
  struct GNUNET_ABD_Delegation *dd,
  unsigned int c_count,
  struct GNUNET_ABD_Delegate *cd);

size_t
GNUNET_ABD_delegates_get_size (
  unsigned int c_count,
  const struct GNUNET_ABD_Delegate *cd);

ssize_t
GNUNET_ABD_delegates_serialize (
  unsigned int c_count,
  const struct GNUNET_ABD_Delegate *cd,
  size_t dest_size,
  char *dest);


int
GNUNET_ABD_delegates_deserialize (size_t len,
                                  const char *src,
                                  unsigned int c_count,
                                  struct GNUNET_ABD_Delegate *cd);

int
GNUNET_ABD_delegate_serialize (struct GNUNET_ABD_Delegate *cred,
                               char **data);

struct GNUNET_ABD_Delegate *
GNUNET_ABD_delegate_deserialize (const char *data, size_t data_size);

#endif
/* end of abd_serialization.h */

/*
      This file is part of GNUnet
      Copyright (C) 2012-2013 GNUnet e.V.

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
 * @file credential/delegate.h
 * @brief IPC messages between CREDENTIAL API and CREDENTIAL service
 * @author Martin Schanzenbach
 */
#ifndef DELEGATE_H
#define DELEGATE_H

#include "gnunet_credential_service.h"

GNUNET_NETWORK_STRUCT_BEGIN

struct DelegateEntry
{

  /**
   * The signature for this credential by the issuer
   */
  struct GNUNET_CRYPTO_EcdsaSignature signature;

  /**
   * Signature meta
   */
  struct GNUNET_CRYPTO_EccSignaturePurpose purpose;

  /**
   * Public key of the issuer
   */
  struct GNUNET_CRYPTO_EcdsaPublicKey issuer_key;

  /**
   * Public key of the subject this credential was issued to
   */
  struct GNUNET_CRYPTO_EcdsaPublicKey subject_key;

  /**
   * Expiration time of this credential
   */
  uint64_t expiration GNUNET_PACKED;
   
  /**
   * Issuer subject attribute length
   */
  uint32_t issuer_attribute_len;

  /**
   * Issuer attribute length
   */
  uint32_t subject_attribute_len;

  /**
   * Followed by the subject attribute string
   */
};


GNUNET_NETWORK_STRUCT_END

#endif


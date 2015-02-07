/*
     This file is part of GNUnet.
     Copyright (C) 2013 Christian Grothoff (and other contributing authors)

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
 * @file include/block_dns.h
 * @author Christian Grothoff
 */
#ifndef BLOCK_DNS_H
#define BLOCK_DNS_H

#include "gnunet_util_lib.h"

GNUNET_NETWORK_STRUCT_BEGIN

/**
 * This is the structure describing an DNS exit service.
 */
struct GNUNET_DNS_Advertisement
{
  /**
   * Signature of the peer affirming that he is offering the service.
   */
  struct GNUNET_CRYPTO_EddsaSignature signature;

  /**
   * Beginning of signed portion of the record, signs everything until
   * the end of the struct.
   */
  struct GNUNET_CRYPTO_EccSignaturePurpose purpose;

  /**
   * When does this signature expire?
   */
  struct GNUNET_TIME_AbsoluteNBO expiration_time;

  /**
   * The peer providing this service
   */
  struct GNUNET_PeerIdentity peer;

};
GNUNET_NETWORK_STRUCT_END

#endif

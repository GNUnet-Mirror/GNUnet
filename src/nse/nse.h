/*
     This file is part of GNUnet.
     (C) 2001-2011 Christian Grothoff (and other contributing authors)

     GNUnet is free software; you can redistribute it and/or modify
     it under the terms of the GNU General Public License as published
     by the Free Software Foundation; either version 2, or (at your
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
 * @author Nathan Evans
 * @file nse/nse.h
 *
 * @brief Common type definitions for the network size estimation
 *        service and API.
 */
#ifndef NSE_H
#define NSE_H

#include "gnunet_common.h"

#define DEBUG_NSE GNUNET_YES

#define SIGNED_TIMESTAMP_SIZE sizeof(struct GNUNET_TIME_Absolute)

/** FIXME: define NSE message types here. */

struct GNUNET_Signed_Timestamp
{
  char data[SIGNED_TIMESTAMP_SIZE];
};

/**
 * Network size estimate sent from the service
 * to clients.  Contains the current size estimate
 * (or 0 if none has been calculated) and the
 * standard deviation of known estimates.
 *
 */
struct GNUNET_NSE_ClientMessage
{
  /**
   * Type:  GNUNET_MESSAGE_TYPE_NSE_UPDATE
   */
  struct GNUNET_MessageHeader header;

  /*
   * The current estimated network size.
   */
  double size_estimate;

  /**
   * The standard deviation (rounded down
   * to the nearest integer) of size
   * estimations.
   */
  double std_deviation;
};

/**
 * Network size estimate reply; sent when "this"
 * peer's timer has run out before receiving a
 * valid reply from another peer.
 *
 * FIXME: Is this the right way to do this?
 * I think we need to include both the public
 * key and the timestamp signed by the private
 * key.  This way a recipient
 * can verify that the peer at least generated
 * the public/private key pair, and that the
 * timestamp matches what the current peer
 * believes it should be.  The receiving peer
 * would then check whether the XOR of the peer
 * identity and the timestamp is within a
 * reasonable range of the current time
 * (+/- N seconds).  If a closer message which
 * also verifies hasn't been received (or this
 * message is a duplicate), the peer
 * calculates the size estimate and forwards
 * the request to all other peers.
 *
 * Hmm... Is it enought to *just* send the peer
 * identity?  Obviously this is smaller, but it
 * doesn't allow us to verify that the
 * public/private key pair were generated, right?
 */
struct GNUNET_NSE_ReplyMessage
{
  /**
   * Type: GNUNET_MESSAGE_TYPE_NSE_REPLY
   */
  struct GNUNET_MessageHeader header;

  /**
   * The current timestamp value (which all
   * peers should agree on) signed by the
   * private key of the initiating peer.
   */
  struct GNUNET_Signed_Timestamp timestamp;

  /**
   * Public key of the originator, signed timestamp
   * is decrypted by this.
   */
  struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded pkey;
};

#endif

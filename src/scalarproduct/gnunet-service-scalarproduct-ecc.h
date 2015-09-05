/*
     This file is part of GNUnet.
     Copyright (C) 2015 Christian Grothoff (and other contributing authors)

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
 * @file scalarproduct/gnunet-service-scalarproduct-ecc.h
 * @brief scalarproduct service  P2P messages
 * @author Christian M. Fuchs
 * @author Christian Grothoff
 */
#ifndef GNUNET_SERVICE_SCALARPRODUCT_ECC_H
#define GNUNET_SERVICE_SCALARPRODUCT_ECC_H


GNUNET_NETWORK_STRUCT_BEGIN

/**
 * Message type passed from requesting service Alice to responding
 * service Bob to initiate a request and make Bob participate in our
 * protocol.  Afterwards, Bob is expected to perform the set
 * intersection with Alice. Once that has succeeded, Alice will
 * send a `struct AliceCryptodataMessage *`.  Bob is not expected
 * to respond via CADET in the meantime.
 */
struct EccServiceRequestMessage
{
  /**
   * Type is #GNUNET_MESSAGE_TYPE_SCALARPRODUCT_ECC_SESSION_INITIALIZATION
   */
  struct GNUNET_MessageHeader header;

  /**
   * For alignment. Always zero.
   */
  uint32_t reserved;

  /**
   * The transaction/session key used to identify a session
   */
  struct GNUNET_HashCode session_id;

};


/**
 * Vector of ECC-encrypted values sent by Alice to Bob
 * (after set intersection).  Alice may send messages of this
 * type repeatedly to transmit all values.
 */
struct EccAliceCryptodataMessage
{
  /**
   * Type is #GNUNET_MESSAGE_TYPE_SCALARPRODUCT_ECC_ALICE_CRYPTODATA
   */
  struct GNUNET_MessageHeader header;

  /**
   * How many elements we appended to this message? In NBO.
   */
  uint32_t contained_element_count GNUNET_PACKED;

  /**
   * struct GNUNET_CRYPTO_EccPoint[contained_element_count]
   */
};


/**
 * Message type passed from responding service Bob to responding
 * service Alice to complete a request and allow Alice to compute the
 * result.  If Bob's reply does not fit into this one message, the
 * conversation may be continued with `struct BobCryptodataMultipartMessage`
 * messages afterwards.
 */
struct EccBobCryptodataMessage
{
  /**
   * GNUNET message header with type
   * #GNUNET_MESSAGE_TYPE_SCALARPRODUCT_ECC_BOB_CRYPTODATA.
   */
  struct GNUNET_MessageHeader header;

  /**
   * How many elements this individual message delivers (in NBO),
   * always TWO.
   */
  uint32_t contained_element_count GNUNET_PACKED;

  /**
   * The product of the g_i^{b_i} values.
   */
  struct GNUNET_CRYPTO_EccPoint prod_g_i_b_i;

  /**
   * The product of the h_i^{b_i} values.
   */
  struct GNUNET_CRYPTO_EccPoint prod_h_i_b_i;

};


GNUNET_NETWORK_STRUCT_END


#endif

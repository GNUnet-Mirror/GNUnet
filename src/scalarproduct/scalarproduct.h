/*
     This file is part of GNUnet.
     (C) 2009, 2010, 2011, 2012, 2013 Christian Grothoff (and other contributing authors)

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
 * @file   scalarproduct.h
 * @brief  Scalar Product Message Types
 * @author Christian M. Fuchs
 *
 * Created on September 2, 2013, 3:43 PM
 */

#ifndef SCALARPRODUCT_H
#define	SCALARPRODUCT_H

#ifdef	__cplusplus
extern "C"
{
#endif
///////////////////////////////////////////////////////////////////////////////
//                      Defines
///////////////////////////////////////////////////////////////////////////////
/**
 * Length of the key used for encryption
 */
#define KEYBITS 2048

/**
 * When performing our crypto, we may add two encrypted values with each 
 * a maximal length of GNUNET_CRYPTO_RSA_DATA_ENCODING_LENGTH.
 * thus we can receive a slightly longer element (+1 byte)
 */
#define PAILLIER_ELEMENT_LENGTH (2*KEYBITS/8 +1)

/**
 * Log an error message at log-level 'level' that indicates
 * a failure of the command 'cmd' with the message given
 * by gcry_strerror(rc).
 */
#define LOG_GCRY(level, cmd, rc) do { LOG(level, _("`%s' failed at %s:%d with error: %s\n"), cmd, __FILE__, __LINE__, gcry_strerror(rc)); } while(0)

///////////////////////////////////////////////////////////////////////////////
//                     Scalar Product Message Types
///////////////////////////////////////////////////////////////////////////////

/**
 * Message type passed from client to service 
 * to initiate a request or responder role
 */
struct GNUNET_SCALARPRODUCT_client_request
{
  /**
   * GNUNET message header
   */
  struct GNUNET_MessageHeader header;

  /**
   * how many elements the vector in payload contains
   */
  uint32_t element_count GNUNET_PACKED;

  /**
   * how many bytes the mask has
   */
  uint32_t mask_length GNUNET_PACKED;

  /**
   * the transaction/session key used to identify a session
   */
  struct GNUNET_HashCode key;

  /**
   * the identity of a remote peer we want to communicate with
   */
  struct GNUNET_PeerIdentity peer;

  /**
   * followed by long vector[element_count] | [unsigned char mask[mask_bytes]]
   */
};
  
/**
 * Message type passed from requesting service Alice to responding service Bob
 * to initiate a request and make bob participate in our protocol
 */
struct GNUNET_SCALARPRODUCT_service_request {
  /**
   * GNUNET message header
   */
  struct GNUNET_MessageHeader header;

  /**
   * how many bytes the mask has
   */
  uint32_t mask_length GNUNET_PACKED;

  /**
   * the length of the publickey contained within this message
   */
  uint32_t pk_length GNUNET_PACKED;

  /**
   * the transaction/session key used to identify a session
   */
  struct GNUNET_HashCode key;

  /**
   * how many elements the vector in payload contains
   */
  uint32_t element_count GNUNET_PACKED;

  /**
   * how many elements are actually included after the mask was applied.
   */
  uint32_t used_element_count GNUNET_PACKED;

  /**
   * followed by mask | public_key | vector[used_element_count]
   */
};

/**
 * Message type passed from responding service Bob to responding service Alice
 * to complete a request and allow Alice to compute the result
 */
struct GNUNET_SCALARPRODUCT_service_response {
  /**
   * GNUNET message header
   */
  struct GNUNET_MessageHeader header;

  /**
   * how many elements the vector in payload contains
   */
  uint32_t element_count GNUNET_PACKED;

  /**
   * how many elements are actually included after the mask was applied.
   */
  uint32_t used_element_count GNUNET_PACKED;

  /**
   * the transaction/session key used to identify a session
   */
  struct GNUNET_HashCode key;

  /**
   * followed by s | s' | kp[] | kq[]
   */
};

/**
 * Message type passed from service client
 * to finalize a session as requester or responder
 */
struct GNUNET_SCALARPRODUCT_client_response
{
  /**
   * GNUNET message header
   */
  struct GNUNET_MessageHeader header;

  /**
   * 0 if no product attached
   */
  uint32_t product_length GNUNET_PACKED;

  /**
   * the transaction/session key used to identify a session
   */
  struct GNUNET_HashCode key;

  /**
   * the identity of a remote peer we want to communicate with
   */
  struct GNUNET_PeerIdentity peer;

  /**
   * Workaround for libgcrypt: -1 if negative, 0 if zero, else 1
   */
  int8_t range;

  /**
   * followed by product of length product_length (or nothing)
   */
};
  
#ifdef	__cplusplus
}
#endif

#endif	/* SCALARPRODUCT_H */


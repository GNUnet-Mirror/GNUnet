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
 * Maximum count of elements we can put into a multipart message
 */
#define MULTIPART_ELEMENT_CAPACITY ((GNUNET_SERVER_MAX_MESSAGE_SIZE - 1 - sizeof (struct GNUNET_SCALARPRODUCT_multipart_message)) / sizeof (struct GNUNET_CRYPTO_PaillierCiphertext))

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
struct GNUNET_SCALARPRODUCT_computation_message
{
  /**
   * GNUNET message header
   */
  struct GNUNET_MessageHeader header;

  /**
   * how many elements the vector in payload contains
   */
  uint32_t element_count_total GNUNET_PACKED;
  
  /**
   * contained elements the vector in payload contains
   */
  uint32_t element_count_contained GNUNET_PACKED;

  /**
   * the transaction/session key used to identify a session
   */
  struct GNUNET_HashCode session_key;

  /**
   * the identity of a remote peer we want to communicate with
   */
  struct GNUNET_PeerIdentity peer;

  /**
   * followed by struct GNUNET_SCALARPRODUCT_Element[]
   */
};

/**
 * multipart messages following GNUNET_SCALARPRODUCT_client_request
 */
struct GNUNET_SCALARPRODUCT_computation_message_multipart
{
  /**
   * GNUNET message header
   */
  struct GNUNET_MessageHeader header;
  
  /**
   * contained elements the vector in payload contains
   */
  uint32_t element_count_contained GNUNET_PACKED;

  /**
   * followed by struct GNUNET_SCALARPRODUCT_Element[]
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
   * the transaction/session key used to identify a session
   */
  struct GNUNET_HashCode session_id;

  /**
   * Alice's public key
   */
  struct GNUNET_CRYPTO_PaillierPublicKey public_key;

};


/**
 * Message type passed from requesting service Alice to responding service Bob
 * to initiate a request and make bob participate in our protocol
 */
struct GNUNET_SCALARPRODUCT_alices_cryptodata_message {
  /**
   * GNUNET message header
   */
  struct GNUNET_MessageHeader header;

  /**
   * how many elements we appended to this message
   */
  uint32_t contained_element_count GNUNET_PACKED;

  /**
   * struct GNUNET_CRYPTO_PaillierCiphertext[contained_element_count]
   */
};

/**
 * Multipart Message type passed between to supply additional elements for the peer
 */
struct GNUNET_SCALARPRODUCT_multipart_message {
  /**
   * GNUNET message header
   */
  struct GNUNET_MessageHeader header;

  /**
   * how many elements we supply within this message
   */
  uint32_t contained_element_count GNUNET_PACKED;

  // struct GNUNET_CRYPTO_PaillierCiphertext[multipart_element_count]
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
   * how many elements the session input had
   */
  uint32_t total_element_count GNUNET_PACKED;

  /**
   * how many elements were included after the mask was applied including all multipart msgs.
   */
  uint32_t used_element_count GNUNET_PACKED;

  /**
   * how many elements this individual message delivers
   */
  uint32_t contained_element_count GNUNET_PACKED;

  /**
   * the transaction/session key used to identify a session
   */
  struct GNUNET_HashCode key;

  /**
   * followed by s | s' | k[i][perm]
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
   * status information about the outcome of this session
   */
  int32_t status;
  
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


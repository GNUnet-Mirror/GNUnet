/*
      This file is part of GNUnet.
      (C) 2013 Christian Grothoff (and other contributing authors)

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
 * @file scalarproduct/gnunet_scalarproduct.h
 * @brief API to the scalarproduct service
 * @author Christian M. Fuchs
 */

#ifndef GNUNET_SCALARPRODUCT_H
#define	GNUNET_SCALARPRODUCT_H

///////////////////////////////////////////////////////////////////////////////
//                      Defines
///////////////////////////////////////////////////////////////////////////////
#define DISABLE_CRYPTO

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

#ifdef	__cplusplus
extern "C"
{
#endif

///////////////////////////////////////////////////////////////////////////////
//                     Service Structure Definitions
///////////////////////////////////////////////////////////////////////////////

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
  uint16_t mask_length GNUNET_PACKED;

  /**
   * the length of the publickey contained within this message
   */
  uint16_t pk_length GNUNET_PACKED;

  /**
   * the transaction/session key used to identify a session
   */
  struct GNUNET_HashCode key;

  /**
   * how many elements the vector in payload contains
   */
  uint16_t element_count GNUNET_PACKED;

  /**
   * how many elements are actually included after the mask was applied.
   */
  uint16_t used_element_count GNUNET_PACKED;

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
  uint16_t element_count GNUNET_PACKED;

  /**
   * how many elements are actually included after the mask was applied.
   */
  uint16_t used_element_count GNUNET_PACKED;

  /**
   * the transaction/session key used to identify a session
   */
  struct GNUNET_HashCode key;

  /**
   * followed by s | s' | kp[] | kq[]
   */
};

///////////////////////////////////////////////////////////////////////////////
//                     Service Structure Definitions
///////////////////////////////////////////////////////////////////////////////

/**
 * state a session can be in
 */
enum SessionState
{
    WAITING_FOR_BOBS_CONNECT,
    MESSAGE_FROM_RESPONDING_CLIENT_RECEIVED,
    WAITING_FOR_RESPONSE_FROM_SERVICE,
    REQUEST_FROM_SERVICE_RECEIVED,
    FINALIZED
};

/**
 * role a peer in a session can assume
 */
enum PeerRole
{
    ALICE,
    BOB
};
/**
 * A scalarproduct session which tracks:
 * 
 * a request form the client to our final response.
 * or
 * a request from a service to us(service).
 */
struct ServiceSession
{
    /**
     * the role this peer has
     */
    enum PeerRole role;

    /**
     * session information is kept in a DLL
     */
    struct ServiceSession *next;

    /**
     * session information is kept in a DLL
     */
    struct ServiceSession *prev;

    /**
     * (hopefully) unique transaction ID
     */
    struct GNUNET_HashCode key;

    /** 
     * state of the session
     */
    enum SessionState state;

    /**
     * Alice or Bob's peerID
     */
    struct GNUNET_PeerIdentity peer;

    /**
     * the client this request is related to
     */
    struct GNUNET_SERVER_Client * client;

    /**
     * how many elements we were supplied with from the client
     */
    uint16_t element_count;

    /**
     * how many elements actually are used after applying the mask
     */
    uint16_t used_element_count;

    /**
     * how many bytes the mask is long. 
     * just for convenience so we don't have to re-re-re calculate it each time
     */
    uint16_t mask_length;

    /**
     * all the vector elements we received
     */
    int32_t * vector;

    /**
     * mask of which elements to check
     */
    unsigned char * mask;

    /**
     * Public key of the remote service, only used by bob
     */
    gcry_sexp_t remote_pubkey;

    /**
     * E(ai)(Bob) or ai(Alice) after applying the mask
     */
    gcry_mpi_t * a;

    /**
     * The computed scalar 
     */
    gcry_mpi_t product;

    /**
     * My transmit handle for the current message to a alice/bob
     */
    struct GNUNET_MESH_TransmitHandle * service_transmit_handle;

    /**
     * My transmit handle for the current message to the client
     */
    struct GNUNET_SERVER_TransmitHandle * client_transmit_handle;

    /**
     * tunnel-handle associated with our mesh handle
     */
    struct GNUNET_MESH_Tunnel * tunnel;

};

/**
 * We need to do a minimum of bookkeeping to maintain track of our transmit handles.
 * each msg is associated with a session and handle. using this information we can determine which msg was sent.
 */
struct MessageObject
{
    /**
     * The handle used to transmit with this request
     */
    void ** transmit_handle;

    /**
     * The message to send
     */
    struct GNUNET_MessageHeader * msg;
};

#ifdef	__cplusplus
}
#endif

#endif	/* GNUNET_SCALARPRODUCT_H */


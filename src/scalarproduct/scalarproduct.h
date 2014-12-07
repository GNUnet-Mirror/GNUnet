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
 */
#ifndef SCALARPRODUCT_H
#define	SCALARPRODUCT_H

GNUNET_NETWORK_STRUCT_BEGIN

/**
 * Log an error message at log-level 'level' that indicates
 * a failure of the command 'cmd' with the message given
 * by gcry_strerror(rc).
 */
#define LOG_GCRY(level, cmd, rc) do { LOG(level, _("`%s' failed at %s:%d with error: %s\n"), cmd, __FILE__, __LINE__, gcry_strerror(rc)); } while(0)


/**
 * Message type passed from client to service
 * to initiate a request or responder role
 */
struct AliceComputationMessage
{
  /**
   * GNUNET message header with type
   * #GNUNET_MESSAGE_TYPE_SCALARPRODUCT_CLIENT_TO_ALICE
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
   * Always zero.
   */
  uint32_t reserved GNUNET_PACKED;

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
 * Message type passed from client to service
 * to initiate a request or responder role
 */
struct BobComputationMessage
{
  /**
   * GNUNET message header with type
   * #GNUNET_MESSAGE_TYPE_SCALARPRODUCT_CLIENT_TO_BOB
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
   * Always zero.
   */
  uint32_t reserved GNUNET_PACKED;

  /**
   * the transaction/session key used to identify a session
   */
  struct GNUNET_HashCode session_key;

  /**
   * followed by struct GNUNET_SCALARPRODUCT_Element[]
   */
};


/**
 * multipart messages following `struct ComputationMessage`
 */
struct ComputationBobCryptodataMultipartMessage
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
 * Message type passed from service client
 * to finalize a session as requester or responder
 */
struct ClientResponseMessage
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
   * status information about the outcome of this session
   */
  int32_t status GNUNET_PACKED;

  /**
   * Workaround for libgcrypt: -1 if negative, 0 if zero, else 1
   */
  int32_t range GNUNET_PACKED;

  /**
   * followed by product of length product_length (or nothing)
   */
};

GNUNET_NETWORK_STRUCT_END

#endif	/* SCALARPRODUCT_H */


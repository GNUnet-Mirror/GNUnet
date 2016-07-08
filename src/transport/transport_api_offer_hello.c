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
 * @file transport/transport_api_offer_hello.c
 * @brief library to offer HELLOs to transport service
 * @author Christian Grothoff
 */

/**
 * Entry in linked list for all offer-HELLO requests.
 */
struct GNUNET_TRANSPORT_OfferHelloHandle
{
  /**
   * For the DLL.
   */
  struct GNUNET_TRANSPORT_OfferHelloHandle *prev;

  /**
   * For the DLL.
   */
  struct GNUNET_TRANSPORT_OfferHelloHandle *next;

  /**
   * Transport service handle we use for transmission.
   */
  struct GNUNET_TRANSPORT_Handle *th;

  /**
   * Transmission handle for this request.
   */
  struct GNUNET_TRANSPORT_TransmitHandle *tth;

  /**
   * Function to call once we are done.
   */
  GNUNET_SCHEDULER_TaskCallback cont;

  /**
   * Closure for @e cont
   */
  void *cls;

  /**
   * The HELLO message to be transmitted.
   */
  struct GNUNET_MessageHeader *msg;
};



/**
 * Offer the transport service the HELLO of another peer.  Note that
 * the transport service may just ignore this message if the HELLO is
 * malformed or useless due to our local configuration.
 *
 * @param handle connection to transport service
 * @param hello the hello message
 * @param cont continuation to call when HELLO has been sent,
 * 	tc reason #GNUNET_SCHEDULER_REASON_TIMEOUT for fail
 * 	tc reasong #GNUNET_SCHEDULER_REASON_READ_READY for success
 * @param cont_cls closure for @a cont
 * @return a `struct GNUNET_TRANSPORT_OfferHelloHandle` handle or NULL on failure,
 *      in case of failure @a cont will not be called
 *
 */
struct GNUNET_TRANSPORT_OfferHelloHandle *
GNUNET_TRANSPORT_offer_hello (struct GNUNET_TRANSPORT_Handle *handle,
                              const struct GNUNET_MessageHeader *hello,
                              GNUNET_SCHEDULER_TaskCallback cont,
                              void *cont_cls)
{
  struct GNUNET_TRANSPORT_OfferHelloHandle *ohh;
  struct GNUNET_MessageHeader *msg;
  struct GNUNET_PeerIdentity peer;
  uint16_t size;

  if (NULL == handle->mq)
    return NULL;
  GNUNET_break (ntohs (hello->type) == GNUNET_MESSAGE_TYPE_HELLO);
  size = ntohs (hello->size);
  GNUNET_break (size >= sizeof (struct GNUNET_MessageHeader));
  if (GNUNET_OK !=
      GNUNET_HELLO_get_id ((const struct GNUNET_HELLO_Message *) hello,
                           &peer))
  {
    GNUNET_break (0);
    return NULL;
  }

  msg = GNUNET_malloc (size);
  memcpy (msg, hello, size);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Offering HELLO message of `%s' to transport for validation.\n",
       GNUNET_i2s (&peer));
  ohh = GNUNET_new (struct GNUNET_TRANSPORT_OfferHelloHandle);
  ohh->th = handle;
  ohh->cont = cont;
  ohh->cls = cont_cls;
  ohh->msg = msg;
  ohh->tth = schedule_control_transmit (handle,
                                        size,
                                        &send_hello,
                                        ohh);
  GNUNET_CONTAINER_DLL_insert (handle->oh_head,
                               handle->oh_tail,
                               ohh);
  return ohh;
}


/**
 * Cancel the request to transport to offer the HELLO message
 *
 * @param ohh the handle for the operation to cancel
 */
void
GNUNET_TRANSPORT_offer_hello_cancel (struct GNUNET_TRANSPORT_OfferHelloHandle *ohh)
{
  struct GNUNET_TRANSPORT_Handle *th = ohh->th;

  cancel_control_transmit (ohh->th, ohh->tth);
  GNUNET_CONTAINER_DLL_remove (th->oh_head,
                               th->oh_tail,
                               ohh);
  GNUNET_free (ohh->msg);
  GNUNET_free (ohh);
}


/* end of transport_api_offer_hello.c */

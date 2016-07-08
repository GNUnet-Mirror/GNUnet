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
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_hello_lib.h"
#include "gnunet_protocols.h"
#include "gnunet_transport_service.h"


/**
 * Entry in linked list for all offer-HELLO requests.
 */
struct GNUNET_TRANSPORT_OfferHelloHandle
{

  /**
   * Transport service handle we use for transmission.
   */
  struct GNUNET_MQ_Handle *mq;

  /**
   * Function to call once we are done.
   */
  GNUNET_SCHEDULER_TaskCallback cont;

  /**
   * Closure for @e cont
   */
  void *cls;

};


/**
 * Done sending HELLO message to the service, notify application.
 *
 * @param cls the handle for the operation
 */
static void
finished_hello (void *cls)
{
  struct GNUNET_TRANSPORT_OfferHelloHandle *ohh = cls;

  if (NULL != ohh->cont)
    ohh->cont (ohh->cls);
  GNUNET_TRANSPORT_offer_hello_cancel (ohh);
}


/**
 * Offer the transport service the HELLO of another peer.  Note that
 * the transport service may just ignore this message if the HELLO is
 * malformed or useless due to our local configuration.
 *
 * @param cfg configuration
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
GNUNET_TRANSPORT_offer_hello (const struct GNUNET_CONFIGURATION_Handle *cfg,
                              const struct GNUNET_MessageHeader *hello,
                              GNUNET_SCHEDULER_TaskCallback cont,
                              void *cont_cls)
{
  struct GNUNET_TRANSPORT_OfferHelloHandle *ohh
    = GNUNET_new (struct GNUNET_TRANSPORT_OfferHelloHandle);
  struct GNUNET_MQ_Envelope *env;
  struct GNUNET_PeerIdentity peer;

  if (GNUNET_OK !=
      GNUNET_HELLO_get_id ((const struct GNUNET_HELLO_Message *) hello,
                           &peer))
  {
    GNUNET_break (0);
    GNUNET_free (ohh);
    return NULL;
  }
  ohh->mq = GNUNET_CLIENT_connecT (cfg,
                                   "transport",
                                   NULL,
                                   NULL,
                                   ohh);
  if (NULL == ohh->mq)
  {
    GNUNET_free (ohh);
    return NULL;
  }
  ohh->cont = cont;
  ohh->cls = cont_cls;
  GNUNET_break (ntohs (hello->type) == GNUNET_MESSAGE_TYPE_HELLO);
  env = GNUNET_MQ_msg_copy (hello);
  GNUNET_MQ_notify_sent (env,
                         &finished_hello,
                         ohh);
  GNUNET_MQ_send (ohh->mq,
                  env);
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
  GNUNET_MQ_destroy (ohh->mq);
  GNUNET_free (ohh);
}


/* end of transport_api_offer_hello.c */

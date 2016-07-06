/*
     This file is part of GNUnet.
     Copyright (C) 2009-2014, 2016 GNUnet e.V.

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
 * @file transport/transport_api_address_to_string.c
 * @author Christian Grothoff
 * @brief enable clients to convert addresses to human readable strings
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_arm_service.h"
#include "gnunet_hello_lib.h"
#include "gnunet_protocols.h"
#include "gnunet_transport_service.h"
#include "transport.h"

/**
 * Context for the address lookup.
 */
struct GNUNET_TRANSPORT_AddressToStringContext
{
  /**
   * Function to call with the human-readable address.
   */
  GNUNET_TRANSPORT_AddressToStringCallback cb;

  /**
   * Closure for @e cb.
   */
  void *cb_cls;

  /**
   * Connection to the service.
   */
  struct GNUNET_MQ_Handle *mq;

};


/**
 * Function called with responses from the service.
 *
 * @param cls our `struct GNUNET_TRANSPORT_AddressToStringContext *`
 * @param msg message with the human-readable address
 * @return #GNUNET_OK if message is well-formed
 */
static int
check_reply (void *cls,
             const struct AddressToStringResultMessage *atsm)
{
  uint16_t size = ntohs (atsm->header.size) - sizeof (*atsm);
  const char *address;
  int result;
  uint32_t addr_len;

  result = (int) ntohl (atsm->res);
  addr_len = ntohl (atsm->addr_len);
  if (GNUNET_SYSERR == result)
    return GNUNET_OK;
  if (0 == size)
  {
    if (GNUNET_OK != result)
    {
      GNUNET_break (0);
      return GNUNET_SYSERR;
    }
    return GNUNET_OK;
  }
  address = (const char *) &atsm[1];
  if ( (addr_len > size) ||
       (address[addr_len -1] != '\0') )
  {
    /* invalid reply */
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * Function called with responses from the service.
 *
 * @param cls our `struct GNUNET_TRANSPORT_AddressToStringContext *`
 * @param msg message with the human-readable address
 */
static void
handle_reply (void *cls,
              const struct AddressToStringResultMessage *atsm)
{
  struct GNUNET_TRANSPORT_AddressToStringContext *alucb = cls;
  uint16_t size = ntohs (atsm->header.size) - sizeof (*atsm);
  const char *address;
  int result;

  result = (int) ntohl (atsm->res);
  if (GNUNET_SYSERR == result)
  {
    /* expect more replies; as this is not the last
       call, we must pass the empty string for the address */
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Address resolution failed\n");
    alucb->cb (alucb->cb_cls,
               "",
               GNUNET_NO);
    return;
  }
  if (0 == size)
  {
    /* we are done (successfully, without communication errors) */
    alucb->cb (alucb->cb_cls,
               NULL,
               GNUNET_OK);
    GNUNET_TRANSPORT_address_to_string_cancel (alucb);
    return;
  }
  address = (const char *) &atsm[1];
  /* return normal reply to caller, also expect more replies */
  alucb->cb (alucb->cb_cls,
             address,
             GNUNET_OK);
}


/**
 * Generic error handler, called with the appropriate
 * error code and the same closure specified at the creation of
 * the message queue.
 * Not every message queue implementation supports an error handler.
 *
 * @param cls the `struct GNUNET_TRANSPORT_AddressToStringContext *`
 * @param error error code
 */
static void
mq_error_handler (void *cls,
                  enum GNUNET_MQ_Error error)
{
  struct GNUNET_TRANSPORT_AddressToStringContext *alucb = cls;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Disconnected from transport, address resolution failed\n");
  alucb->cb (alucb->cb_cls,
             NULL,
             GNUNET_SYSERR);
  GNUNET_TRANSPORT_address_to_string_cancel (alucb);
}


/**
 * Convert a binary address into a human readable address.
 *
 * @param cfg configuration to use
 * @param address address to convert (binary format)
 * @param numeric should (IP) addresses be displayed in numeric form
 *                (otherwise do reverse DNS lookup)
 * @param timeout how long is the lookup allowed to take at most
 * @param aluc function to call with the results
 * @param aluc_cls closure for @a aluc
 * @return handle to cancel the operation, NULL on error
 */
struct GNUNET_TRANSPORT_AddressToStringContext *
GNUNET_TRANSPORT_address_to_string (const struct GNUNET_CONFIGURATION_Handle *cfg,
                                    const struct GNUNET_HELLO_Address *address,
                                    int numeric,
                                    struct GNUNET_TIME_Relative timeout,
                                    GNUNET_TRANSPORT_AddressToStringCallback aluc,
                                    void *aluc_cls)
{
  GNUNET_MQ_hd_var_size (reply,
                         GNUNET_MESSAGE_TYPE_TRANSPORT_ADDRESS_TO_STRING_REPLY,
                         struct AddressToStringResultMessage);
  struct GNUNET_TRANSPORT_AddressToStringContext *alc
    = GNUNET_new (struct GNUNET_TRANSPORT_AddressToStringContext);
  struct GNUNET_MQ_MessageHandler handlers[] = {
    make_reply_handler (alc),
    GNUNET_MQ_handler_end ()
  };
  size_t alen;
  size_t slen;
  struct AddressLookupMessage *msg;
  struct GNUNET_MQ_Envelope *env;
  char *addrbuf;

  alen = address->address_length;
  slen = strlen (address->transport_name) + 1;
  if ( (alen + slen >= GNUNET_SERVER_MAX_MESSAGE_SIZE
        - sizeof (struct AddressLookupMessage)) ||
       (alen >= GNUNET_SERVER_MAX_MESSAGE_SIZE) ||
       (slen >= GNUNET_SERVER_MAX_MESSAGE_SIZE) )
  {
    GNUNET_break (0);
    GNUNET_free (alc);
    return NULL;
  }
  alc->cb = aluc;
  alc->cb_cls = aluc_cls;
  alc->mq = GNUNET_CLIENT_connecT (cfg,
                                   "transport",
                                   handlers,
                                   &mq_error_handler,
                                   alc);
  if (NULL == alc->mq)
  {
    GNUNET_break (0);
    GNUNET_free (alc);
    return NULL;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "Client tries to resolve for peer `%s' address plugin %s len %u\n",
              GNUNET_i2s (&address->peer),
              address->transport_name,
              (unsigned int) address->address_length);
  env = GNUNET_MQ_msg_extra (msg,
                             alen + slen,
                             GNUNET_MESSAGE_TYPE_TRANSPORT_ADDRESS_TO_STRING);
  msg->numeric_only = htons ((int16_t) numeric);
  msg->addrlen = htons ((uint16_t) alen);
  msg->timeout = GNUNET_TIME_relative_hton (timeout);
  addrbuf = (char *) &msg[1];
  memcpy (addrbuf,
          address->address,
          alen);
  memcpy (&addrbuf[alen],
          address->transport_name,
          slen);
  GNUNET_MQ_send (alc->mq,
                  env);
  return alc;
}


/**
 * Cancel request for address conversion.
 *
 * @param alc the context handle
 */
void
GNUNET_TRANSPORT_address_to_string_cancel (struct GNUNET_TRANSPORT_AddressToStringContext *alc)
{
  GNUNET_MQ_destroy (alc->mq);
  GNUNET_free (alc);
}


/* end of transport_api_address_to_string.c */

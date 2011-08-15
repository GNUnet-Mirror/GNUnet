/*
     This file is part of GNUnet.
     (C) 2009, 2010 Christian Grothoff (and other contributing authors)

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
#include "platform.h"
#include "gnunet_client_lib.h"
#include "gnunet_arm_service.h"
#include "gnunet_hello_lib.h"
#include "gnunet_protocols.h"
#include "gnunet_server_lib.h"
#include "gnunet_time_lib.h"
#include "gnunet_transport_service.h"
#include "transport.h"

/**
 * Context for the address lookup.
 */
struct AddressLookupCtx
{
  /**
   * Function to call with the human-readable address.
   */
  GNUNET_TRANSPORT_AddressLookUpCallback cb;

  /**
   * Closure for cb.
   */
  void *cb_cls;

  /**
   * Connection to the service.
   */
  struct GNUNET_CLIENT_Connection *client;

  /**
   * When should this operation time out?
   */
  struct GNUNET_TIME_Absolute timeout;
};


/**
 * Function called with responses from the service.
 *
 * @param cls our 'struct AddressLookupCtx*'
 * @param msg NULL on timeout or error, otherwise presumably a
 *        message with the human-readable address
 */
static void
address_response_processor (void *cls, const struct GNUNET_MessageHeader *msg)
{
  struct AddressLookupCtx *alucb = cls;
  const char *address;
  uint16_t size;

  if (msg == NULL)
  {
    alucb->cb (alucb->cb_cls, NULL);
    GNUNET_CLIENT_disconnect (alucb->client, GNUNET_NO);
    GNUNET_free (alucb);
    return;
  }
  GNUNET_break (ntohs (msg->type) ==
                GNUNET_MESSAGE_TYPE_TRANSPORT_ADDRESS_REPLY);
  size = ntohs (msg->size);
  if (size == sizeof (struct GNUNET_MessageHeader))
  {
    /* done! */
    alucb->cb (alucb->cb_cls, NULL);
    GNUNET_CLIENT_disconnect (alucb->client, GNUNET_NO);
    GNUNET_free (alucb);
    return;
  }
  address = (const char *) &msg[1];
  if (address[size - sizeof (struct GNUNET_MessageHeader) - 1] != '\0')
  {
    /* invalid reply */
    GNUNET_break (0);
    alucb->cb (alucb->cb_cls, NULL);
    GNUNET_CLIENT_disconnect (alucb->client, GNUNET_NO);
    GNUNET_free (alucb);
    return;
  }
  /* expect more replies */
  GNUNET_CLIENT_receive (alucb->client, &address_response_processor, alucb,
                         GNUNET_TIME_absolute_get_remaining (alucb->timeout));
  alucb->cb (alucb->cb_cls, address);
}


/**
 * Convert a binary address into a human readable address.
 *
 * @param cfg configuration to use
 * @param address address to convert (binary format)
 * @param addressLen number of bytes in address
 * @param numeric should (IP) addresses be displayed in numeric form
 *                (otherwise do reverse DNS lookup)
 * @param nameTrans name of the transport to which the address belongs
 * @param timeout how long is the lookup allowed to take at most
 * @param aluc function to call with the results
 * @param aluc_cls closure for aluc
 */
void
GNUNET_TRANSPORT_address_lookup (const struct GNUNET_CONFIGURATION_Handle *cfg,
                                 const char *address, size_t addressLen,
                                 int numeric, const char *nameTrans,
                                 struct GNUNET_TIME_Relative timeout,
                                 GNUNET_TRANSPORT_AddressLookUpCallback aluc,
                                 void *aluc_cls)
{
  size_t slen;
  size_t len;
  struct AddressLookupMessage *msg;
  struct AddressLookupCtx *aluCB;
  struct GNUNET_CLIENT_Connection *client;
  char *addrbuf;

  slen = strlen (nameTrans) + 1;
  len = sizeof (struct AddressLookupMessage) + addressLen + slen;
  if (len >= GNUNET_SERVER_MAX_MESSAGE_SIZE)
  {
    GNUNET_break (0);
    aluc (aluc_cls, NULL);
    return;
  }
  client = GNUNET_CLIENT_connect ("transport", cfg);
  if (client == NULL)
  {
    aluc (aluc_cls, NULL);
    return;
  }
  msg = GNUNET_malloc (len);
  msg->header.size = htons (len);
  msg->header.type = htons (GNUNET_MESSAGE_TYPE_TRANSPORT_ADDRESS_LOOKUP);
  msg->numeric_only = htonl (numeric);
  msg->timeout = GNUNET_TIME_relative_hton (timeout);
  msg->addrlen = htonl (addressLen);
  addrbuf = (char *) &msg[1];
  memcpy (addrbuf, address, addressLen);
  memcpy (&addrbuf[addressLen], nameTrans, slen);
  aluCB = GNUNET_malloc (sizeof (struct AddressLookupCtx));
  aluCB->cb = aluc;
  aluCB->cb_cls = aluc_cls;
  aluCB->timeout = GNUNET_TIME_relative_to_absolute (timeout);
  aluCB->client = client;
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_CLIENT_transmit_and_get_response (client, &msg->header,
                                                          timeout, GNUNET_YES,
                                                          &address_response_processor,
                                                          aluCB));
  GNUNET_free (msg);
}

/* end of transport_api_address_lookup.c */

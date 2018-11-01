/*
     This file is part of GNUnet.
     Copyright (C) 2018 GNUnet e.V.

     GNUnet is free software: you can redistribute it and/or modify it
     under the terms of the GNU Affero General Public License as published
     by the Free Software Foundation, either version 3 of the License,
     or (at your option) any later version.

     GNUnet is distributed in the hope that it will be useful, but
     WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
     Affero General Public License for more details.
    
     You should have received a copy of the GNU Affero General Public License
     along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

/**
 * @file transport/transport_api2_communication.c
 * @brief implementation of the gnunet_transport_communication_service.h API
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_protocols.h"
#include "gnunet_transport_communication_service.h"
#include "transport.h"


/**
 * Opaque handle to the transport service for communicators.
 */
struct GNUNET_TRANSPORT_CommunicatorHandle
{
  /**
   * Head of DLL of addresses this communicator offers to the transport service.
   */
  struct GNUNET_TRANSPORT_AddressIdentifier *ai_head;

  /**
   * Tail of DLL of addresses this communicator offers to the transport service.
   */
  struct GNUNET_TRANSPORT_AddressIdentifier *ai_tail;

  /**
   * Our configuration.
   */
  const struct GNUNET_CONFIGURATION_Handle *cfg;

  /**
   * Name of the communicator.
   */
  const char *name;

  /**
   * Function to call when the transport service wants us to initiate
   * a communication channel with another peer.
   */
  GNUNET_TRANSPORT_CommunicatorMqInit mq_init;

  /**
   * Closure for @e mq_init.
   */
  void *mq_init_cls;

  /**
   * MTU of the communicator
   */
  size_t mtu;
  
  /**
   * Internal UUID for the address used in communication with the
   * transport service.
   */
  uint32_t aid_gen;
  
};



/**
 * Internal representation of an address a communicator is
 * currently providing for the transport service.
 */
struct GNUNET_TRANSPORT_AddressIdentifier
{

  /**
   * Kept in a DLL.
   */
  struct GNUNET_TRANSPORT_AddressIdentifier *next;

  /**
   * Kept in a DLL.
   */
  struct GNUNET_TRANSPORT_AddressIdentifier *prev;
  
  /**
   * Transport handle where the address was added.
   */
  struct GNUNET_TRANSPORT_CommunicatorHandle *ch;

  /**
   * The actual address.
   */
  char *address;

  /**
   * When does the address expire? (Expected lifetime of the
   * address.)
   */
  struct GNUNET_TIME_Relative expiration;
  
  /**
   * Internal UUID for the address used in communication with the
   * transport service.
   */
  uint32_t aid;

  /**
   * Network type for the address.
   */
  enum GNUNET_ATS_Network_Type nt;
  
};


/**
 * (re)connect our communicator to the transport service
 *
 * @param ch handle to reconnect
 */
static void
reconnect (struct GNUNET_TRANSPORT_CommunicatorHandle *ch);


/**
 * Send message to the transport service about address @a ai
 * being now available.
 *
 * @param ai address to add
 */
static void
send_add_address (struct GNUNET_TRANSPORT_AddressIdentifier *ai)
{
  struct GNUNET_MQ_Envelope *env;
  struct GNUNET_TRANSPORT_AddAddressMessage *aam;
  
  if (NULL == ai->ch->mq)
    return;
  env = GNUNET_MQ_msg_extra (aam,
			     strlen (ai->address) + 1,
			     GNUNET_MESSAGE_TYPE_TRANSPORT_ADD_ADDRESS);
  aam->expiration = GNUNET_TIME_relative_to_nbo (ai->expiration);
  aam->nt = htonl ((uint32_t) ai->nt);
  memcpy (&aam[1],
	  ai->address,
	  strlen (ai->address) + 1);
  GNUNET_MQ_send (ai->ch->mq,
		  env);
}


/**
 * Send message to the transport service about address @a ai
 * being no longer available.
 *
 * @param ai address to delete
 */
static void
send_del_address (struct GNUNET_TRANSPORT_AddressIdentifier *ai)
{
  struct GNUNET_MQ_Envelope *env;
  struct GNUNET_TRANSPORT_DelAddressMessage *dam;
  
  if (NULL == ai->ch->mq)
    return;
  env = GNUNET_MQ_msg (dam,			     
		       GNUNET_MESSAGE_TYPE_TRANSPORT_DEL_ADDRESS);
  dam.aid = htonl (ai->aid);
  GNUNET_MQ_send (ai->ch->mq,
		  env);
}


/**
 * Function called on MQ errors.
 */
static void
error_handler (void *cls,
	       enum GNUNET_MQ_Error error)
{
  struct GNUNET_TRANSPORT_CommunicatorHandle *ch = cls;
  
  GNUNET_MQ_destroy (ch->mq);
  ch->mq = NULL;
  /* TODO: maybe do this with exponential backoff/delay */
  reconnect (ch);
}


/**
 * (re)connect our communicator to the transport service
 *
 * @param ch handle to reconnect
 */
static void
reconnect (struct GNUNET_TRANSPORT_CommunicatorHandle *ch)
{
  struct GNUNET_MQ_MessageHandler handlers[] = {
    GNUNET_MQ_handler_end()
  };
  
  ch->mq = GNUNET_CLIENT_connect (cfg,
				  "transport",
				  handlers,
				  &error_handler,
				  ch);
  for (struct GNUNET_TRANSPORT_AddressIdentifier ai = ch->ai_head;
       NULL != ai;
       ai = ai->next)
    send_add_address (ai);
}


/**
 * Connect to the transport service.
 *
 * @param cfg configuration to use
 * @param name name of the communicator that is connecting
 * @param mtu maximum message size supported by communicator, 0 if
 *            sending is not supported, SIZE_MAX for no MTU
 * @param mq_init function to call to initialize a message queue given
 *                the address of another peer, can be NULL if the
 *                communicator only supports receiving messages
 * @param mq_init_cls closure for @a mq_init
 * @return NULL on error
 */
struct GNUNET_TRANSPORT_CommunicatorHandle *
GNUNET_TRANSPORT_communicator_connect (const struct GNUNET_CONFIGURATION_Handle *cfg,
                                       const char *name,
                                       size_t mtu,
                                       GNUNET_TRANSPORT_CommunicatorMqInit mq_init,
                                       void *mq_init_cls)
{
  struct GNUNET_TRANSPORT_CommunicatorHandle *ch;
  
  ch = GNUNET_new (struct GNUNET_TRANSPORT_CommunicatorHandle);
  ch->cfg = cfg;
  ch->name = name;
  ch->mtu = mtu;
  ch->mq_init = mq_init;
  ch->mq_init_cls = mq_init_cls;
  reconnect (ch);
  if (NULL == ch->mq)
  {
    GNUNET_free (ch);
    return NULL;
  }
  return ch;
}


/**
 * Disconnect from the transport service.
 *
 * @param ch handle returned from connect
 */
void
GNUNET_TRANSPORT_communicator_disconnect (struct GNUNET_TRANSPORT_CommunicatorHandle *ch)
{
  while (NULL != ch->ai_head)
  {
    GNUNET_break (0); /* communicator forgot to remove address, warn! */
    GNUNET_TRANSPORT_communicator_address_remove (ch->ai_head);
  }
  GNUNET_MQ_destroy (ch->mq);
  GNUNET_free (ch);
}


/* ************************* Receiving *************************** */


/**
 * Notify transport service that the communicator has received
 * a message.
 *
 * @param ch connection to transport service
 * @param sender presumed sender of the message (details to be checked
 *        by higher layers)
 * @param msg the message
 * @param cb function to call once handling the message is done, NULL if
 *         flow control is not supported by this communicator
 * @param cb_cls closure for @a cb
 * @return #GNUNET_OK if all is well, #GNUNET_NO if the message was
 *         immediately dropped due to memory limitations (communicator
 *         should try to apply back pressure),
 *         #GNUNET_SYSERR if the message is ill formed and communicator
 *         should try to reset stream
 */
int
GNUNET_TRANSPORT_communicator_receive (struct GNUNET_TRANSPORT_CommunicatorHandle *ch,
                                       const struct GNUNET_PeerIdentity *sender,
                                       const struct GNUNET_MessageHeader *msg,
                                       GNUNET_TRANSPORT_MessageCompletedCallback cb,
                                       void *cb_cls)
{
  struct GNUNET_MQ_Envelope *env;
  struct GNUNET_TRANSPORT_IncomingMessage *im;
  uint16_t msize;
  
  if (NULL == ai->ch->mq)
    return;
  msize = ntohs (msg->size);
  env = GNUNET_MQ_msg_extra (im,
			     msize,
			     GNUNET_MESSAGE_TYPE_TRANSPORT_INCOMING_MSG);
  if (NULL == env)
  {
    GNUNET_break (0);
    return;
  }
  im->sender = *sender;
  memcpy (&im[1],
	  msg,
	  msize);
  GNUNET_MQ_send (ai->ch->mq,
		  env);
}


/* ************************* Discovery *************************** */

/**
 * Handle returned to identify the internal data structure the transport
 * API has created to manage a message queue to a particular peer.
 */
struct GNUNET_TRANSPORT_QueueHandle
{
};


/**
 * Notify transport service that an MQ became available due to an
 * "inbound" connection or because the communicator discovered the
 * presence of another peer.
 *
 * @param ch connection to transport service
 * @param peer peer with which we can now communicate
 * @param address address in human-readable format, 0-terminated, UTF-8
 * @param nt which network type does the @a address belong to?
 * @param mq message queue of the @a peer
 * @return API handle identifying the new MQ
 */
struct GNUNET_TRANSPORT_QueueHandle *
GNUNET_TRANSPORT_communicator_mq_add (struct GNUNET_TRANSPORT_CommunicatorHandle *ch,
                                      const struct GNUNET_PeerIdentity *peer,
                                      const char *address,
                                      enum GNUNET_ATS_Network_Type nt,
                                      struct GNUNET_MQ_Handle *mq)
{
}


/**
 * Notify transport service that an MQ became unavailable due to a
 * disconnect or timeout.
 *
 * @param qh handle for the queue that must be invalidated
 */
void
GNUNET_TRANSPORT_communicator_mq_del (struct GNUNET_TRANSPORT_QueueHandle *qh)
{
}




/**
 * Notify transport service about an address that this communicator
 * provides for this peer.
 *
 * @param ch connection to transport service
 * @param address our address in human-readable format, 0-terminated, UTF-8
 * @param nt which network type does the address belong to?
 * @param expiration when does the communicator forsee this address expiring?
 */
struct GNUNET_TRANSPORT_AddressIdentifier *
GNUNET_TRANSPORT_communicator_address_add (struct GNUNET_TRANSPORT_CommunicatorHandle *ch,
                                           const char *address,
                                           enum GNUNET_ATS_Network_Type nt,
                                           struct GNUNET_TIME_Relative expiration)
{
  struct GNUNET_TRANSPORT_AddressIdentifier *ai;

  ai = GNUNET_new (struct GNUNET_TRANSPORT_AddressIdentifier);
  ai->ch = ch;
  ai->address = GNUNET_strdup (address);
  ai->nt = nt;
  ai->expiration = expiration;
  ai->aid = handle->aid_gen++;
  GNUNET_CONTAINER_DLL_insert (handle->ai_head,
			       handle->ai_tail,
			       ai);
  send_add_address (ai);
  return ai;
}


/**
 * Notify transport service about an address that this communicator no
 * longer provides for this peer.
 *
 * @param ai address that is no longer provided
 */
void
GNUNET_TRANSPORT_communicator_address_remove (struct GNUNET_TRANSPORT_AddressIdentifier *ai)
{
  struct GNUNET_TRANSPORT_CommunicatorHandle *ch = ai->ch;

  send_del_address (ai);
  GNUNET_free (ai->address);
  GNUNET_CONTAINER_DLL_remove (ch->ai_head,
			       ch->ai_tail,
			       ai);
  GNUNET_free (ai);
}


/* end of transport_api2_communication.c */

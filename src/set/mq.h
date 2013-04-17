/*
     This file is part of GNUnet.
     (C) 2012 Christian Grothoff (and other contributing authors)

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
 * @author Florian Dold
 * @file mq/mq.h
 * @brief general purpose request queue
 */
#ifndef MQ_H
#define MQ_H

#include "platform.h"
#include "gnunet_common.h"
#include "gnunet_util_lib.h"
#include "gnunet_connection_lib.h"


#define GNUNET_MQ_msg_extra(mvar, esize, type) GNUNET_MQ_msg_(((void) mvar->header, (struct GNUNET_MessageHeader**) &mvar), (esize) + sizeof *mvar, type)

#define GNUNET_MQ_msg(mvar, type) GNUNET_MQ_msg_extra(mvar, 0, type)

#define GNUNET_MQ_msg_raw(type) GNUNET_MQ_msg_ (NULL, sizeof (struct GNUNET_MessageHeader), type)

#define GNUNET_MQ_HANDLERS_END {NULL, 0}

struct GNUNET_MQ_MessageQueue;

struct GNUNET_MQ_Message;

struct GNUNET_MQ_Handler
{
  void *cb;
  uint16_t type;
};

/**
 * Callback used for notifications
 *
 * @param cls closure
 */
typedef void (*GNUNET_MQ_NotifyCallback) (void *cls);

/**
 * Create a new message for MQ.
 * 
 * @param mhp message header to store the allocated message header in, can be NULL
 * @param size size of the message to allocate
 * @param type type of the message, will be set in the allocated message
 * @param return the allocated MQ message
 */
struct GNUNET_MQ_Message *
GNUNET_MQ_msg_ (struct GNUNET_MessageHeader **mhp, uint16_t size, uint16_t type);

void
GNUNET_MQ_send (struct GNUNET_MQ_MessageQueue *mq, struct GNUNET_MQ_Message *mqm);


/**
 * Associate the assoc_data in mq with a unique request id.
 *
 * @param mq message queue, id will be unique for the queue
 * @param mqm message to associate
 * @param data to associate
 */
uint32_t
GNUNET_MQ_assoc_add (struct GNUNET_MQ_MessageQueue *mq,
                     struct GNUNET_MQ_Message *mqm,
                     void *assoc_data);

void *
GNUNET_MQ_assoc_get (struct GNUNET_MQ_MessageQueue *mq, uint32_t request_id);

void *
GNUNET_MQ_assoc_remove (struct GNUNET_MQ_MessageQueue *mq, uint32_t request_id);



struct GNUNET_MQ_MessageQueue *
GNUNET_MQ_queue_for_connection_client (struct GNUNET_CLIENT_Connection *connection,
                                       const struct GNUNET_MQ_Handler *handlers,
                                       void *cls);


void
GNUNET_MQ_notify_sent (struct GNUNET_MQ_Message *mqm,
                       void (*)(void*),
                       void *cls);


void
GNUNET_MQ_notify_timeout (struct GNUNET_MQ_Message *mqm,
                          void (*)(void*),
                          void *cls);


void
GNUNET_MQ_notify_destroy (struct GNUNET_MQ_Message *mqm,
                          void (*)(void*),
                          void *cls);

void
GNUNET_MQ_destroy (struct GNUNET_MQ_MessageQueue *mq);

#endif

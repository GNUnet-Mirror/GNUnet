/*
     This file is part of GNUnet.
     Copyright (C) 2016 GNUnet e.V.

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
 * @file transport-testing-send.c
 * @brief convenience transmission function for tests
 * @author Christian Grothoff
 */
#include "transport-testing.h"

/**
 * Acceptable transmission delay.
 */
#define TIMEOUT_TRANSMIT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 30)


/**
 * Return @a cx in @a cls.
 */
static void
find_cr (void *cls,   
	 struct GNUNET_TRANSPORT_TESTING_ConnectRequest *cx)
{
  struct GNUNET_TRANSPORT_TESTING_ConnectRequest **cr = cls;

  if (GNUNET_NO == cx->connected)
    return;
  *cr = cx;
}


/**
 * Send a test message of type @a mtype and size @a msize from
 * peer @a sender to peer @a receiver.  The peers should be
 * connected when this function is called.
 *
 * @param sender the sending peer
 * @param receiver the receiving peer
 * @param mtype message type to use
 * @param msize size of the message, at least `sizeof (struct GNUNET_TRANSPORT_TESTING_TestMessage)`
 * @param num unique message number
 * @param cont continuation to call after transmission
 * @param cont_cls closure for @a cont
 * @return #GNUNET_OK if message was queued,
 *         #GNUNET_NO if peers are not connected
 *         #GNUNET_SYSERR if @a msize is illegal
 */
int
GNUNET_TRANSPORT_TESTING_send (struct GNUNET_TRANSPORT_TESTING_PeerContext *sender,
			       struct GNUNET_TRANSPORT_TESTING_PeerContext *receiver,
			       uint16_t mtype,
			       uint16_t msize,
			       uint32_t num,
			       GNUNET_SCHEDULER_TaskCallback cont,
			       void *cont_cls)
{
  struct GNUNET_TRANSPORT_TESTING_ConnectRequest *cr;
  struct GNUNET_MQ_Envelope *env;
  struct GNUNET_TRANSPORT_TESTING_TestMessage *test;
  
  if (msize < sizeof (struct GNUNET_TRANSPORT_TESTING_TestMessage))
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  cr = NULL;
  GNUNET_TRANSPORT_TESTING_find_connecting_context (sender,
						    receiver,
						    &find_cr,
						    &cr);
  if (NULL == cr)
    GNUNET_TRANSPORT_TESTING_find_connecting_context (receiver,
						      sender,
						      &find_cr,
						      &cr);
  if (NULL == cr)
  {
    GNUNET_break (0);
    return GNUNET_NO;
  }
  if (NULL == cr->mq) 
  {
    GNUNET_break (0);
    return GNUNET_NO;
  }
  {
    char *receiver_s = GNUNET_strdup (GNUNET_i2s (&receiver->id));

    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                "Sending message from peer %u (`%s') -> peer %u (`%s') !\n",
                sender->no,
                GNUNET_i2s (&sender->id),
                receiver->no,
                receiver_s);
    GNUNET_free (receiver_s);
  }
  env = GNUNET_MQ_msg_extra (test,
			     msize - sizeof (*test),
			     mtype);
  test->num = htonl (num);
  memset (&test[1],
	  num,
	  msize - sizeof (*test));
  GNUNET_MQ_notify_sent (env,
			 cont,
			 cont_cls);
  GNUNET_MQ_send (cr->mq,
		  env);
  return GNUNET_OK;
}


/**
 * Task that sends a test message from the 
 * first peer to the second peer.
 *
 * @param ccc context which should contain at least two peers, the
 *        first two of which should be currently connected
 * @param size desired message size
 * @param cont continuation to call after transmission
 * @param cont_cls closure for @a cont
 */
static void
do_send (struct GNUNET_TRANSPORT_TESTING_ConnectCheckContext *ccc,
	 uint16_t size,
	 GNUNET_SCHEDULER_TaskCallback cont,
	 void *cont_cls)
{
  int ret;

  ccc->global_ret = GNUNET_SYSERR;
  ret = GNUNET_TRANSPORT_TESTING_send (ccc->p[0],
				       ccc->p[1],
				       GNUNET_TRANSPORT_TESTING_SIMPLE_MTYPE,
				       size,
				       ccc->send_num_gen++,
				       cont,
				       cont_cls);
  GNUNET_assert (GNUNET_SYSERR != ret);
  if (GNUNET_NO == ret)
  {
    GNUNET_break (0);
    ccc->global_ret = GNUNET_SYSERR;
    GNUNET_SCHEDULER_shutdown ();
  }
}


/**
 * Task that sends a minimalistic test message from the 
 * first peer to the second peer.
 *
 * @param cls the `struct GNUNET_TRANSPORT_TESTING_ConnectCheckContext`
 *        which should contain at least two peers, the first two
 *        of which should be currently connected
 */
void
GNUNET_TRANSPORT_TESTING_simple_send (void *cls)
{
  struct GNUNET_TRANSPORT_TESTING_SendClosure *sc = cls;
  int done;
  size_t msize;

  if (0 < sc->num_messages)
  {
    sc->num_messages--;
    done = (0 == sc->num_messages);
  }
  else
  {
    done = 0; /* infinite loop */
  }
  msize = sizeof (struct GNUNET_TRANSPORT_TESTING_TestMessage);
  if (NULL != sc->get_size_cb)
    msize = sc->get_size_cb (sc->num_messages);
  /* if this was the last message, call the continuation,
     otherwise call this function again */
  do_send (sc->ccc,
	   msize,
	   done ? sc->cont : &GNUNET_TRANSPORT_TESTING_simple_send,
	   done ? sc->cont_cls : sc);
}


/**
 * Task that sends a large test message from the 
 * first peer to the second peer.
 *
 * @param cls the `struct GNUNET_TRANSPORT_TESTING_ConnectCheckContext`
 *        which should contain at least two peers, the first two
 *        of which should be currently connected
 */
void
GNUNET_TRANSPORT_TESTING_large_send (void *cls)
{
  struct GNUNET_TRANSPORT_TESTING_SendClosure *sc = cls;
  int done;
  size_t msize;

  if (0 < sc->num_messages)
  {
    sc->num_messages--;
    done = (0 == sc->num_messages);
  }
  else
  {
    done = 0; /* infinite loop */
  }
  msize = 2600;
  if (NULL != sc->get_size_cb)
    msize = sc->get_size_cb (sc->num_messages);
  /* if this was the last message, call the continuation,
     otherwise call this function again */
  do_send (sc->ccc,
	   msize,
	   done ? sc->cont : &GNUNET_TRANSPORT_TESTING_large_send,
	   done ? sc->cont_cls : sc);
}

/* end of transport-testing-send.c */

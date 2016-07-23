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
#define TIMEOUT_TRANSMIT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 5)


static size_t
notify_ready (void *cls,
              size_t size,
              void *buf)
{ 
  struct TRANSPORT_TESTING_SendJob *sj = cls;
  struct GNUNET_TRANSPORT_TESTING_PeerContext *sender = sj->sender;
  struct GNUNET_TRANSPORT_TESTING_PeerContext *receiver = sj->receiver;
  struct GNUNET_TRANSPORT_TESTING_Handle *tth = sender->tth;
  uint16_t msize = sj->msize;
  struct GNUNET_TRANSPORT_TESTING_TestMessage *test;

  sj->th = NULL;
  GNUNET_CONTAINER_DLL_remove (tth->sj_head,
			       tth->sj_tail,
			       sj);
  if (NULL == buf)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Timeout occurred while waiting for transmit_ready\n");
    GNUNET_SCHEDULER_shutdown ();
    GNUNET_free (sj);
    return 0;
  }

  GNUNET_assert (size >= msize);
  if (NULL != buf)
  {
    memset (buf, sj->num, msize);
    test = buf;
    test->header.size = htons (msize);
    test->header.type = htons (sj->mtype);
    test->num = htonl (sj->num);
  }

  {
    char *ps = GNUNET_strdup (GNUNET_i2s (&sender->id));

    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                "Sending message %u from %u (%s) with type %u and size %u bytes to peer %u (%s)\n",
		(unsigned int) sj->num,
		sender->no,
		ps,
                sj->mtype,
                msize,
                receiver->no,
                GNUNET_i2s (&receiver->id));
    GNUNET_free (ps);
  }
  if (NULL != sj->cont)
    GNUNET_SCHEDULER_add_now (sj->cont,
			      sj->cont_cls);
  GNUNET_free (sj);
  return msize;
}


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
  struct GNUNET_TRANSPORT_TESTING_Handle *tth = sender->tth;
  struct TRANSPORT_TESTING_SendJob *sj;
  struct GNUNET_TRANSPORT_TESTING_ConnectRequest *cr;

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
  sj = GNUNET_new (struct TRANSPORT_TESTING_SendJob);
  sj->num = num;
  sj->sender = sender;
  sj->receiver = receiver;
  sj->cont = cont;
  sj->cont_cls = cont_cls;
  sj->mtype = mtype;
  sj->msize = msize;
  GNUNET_CONTAINER_DLL_insert (tth->sj_head,
			       tth->sj_tail,
			       sj);
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
  sj->th = GNUNET_TRANSPORT_notify_transmit_ready (sender->th,
						   &receiver->id,
						   msize,
						   TIMEOUT_TRANSMIT,
						   &notify_ready,
						   sj);
  GNUNET_assert (NULL != sj->th);
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

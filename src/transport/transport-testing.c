/*
     This file is part of GNUnet.
     Copyright (C) 2006, 2009, 2015, 2016 GNUnet e.V.

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
 * @file transport-testing.c
 * @brief testing lib for transport service
 * @author Matthias Wachs
 * @author Christian Grothoff
 */
#include "transport-testing.h"


#define LOG(kind,...) GNUNET_log_from(kind, "transport-testing", __VA_ARGS__)


static struct GNUNET_TRANSPORT_TESTING_PeerContext *
find_peer_context (struct GNUNET_TRANSPORT_TESTING_Handle *tth,
                   const struct GNUNET_PeerIdentity *peer)
{
  struct GNUNET_TRANSPORT_TESTING_PeerContext *t;

  for (t = tth->p_head; NULL != t; t = t->next)
    if (0 == memcmp (&t->id,
                     peer,
                     sizeof (struct GNUNET_PeerIdentity)))
      return t;
  return NULL;
}


/**
 * Find any connecting context matching the given pair of peers.
 *
 * @param p1 first peer
 * @param p2 second peer
 * @param cb function to call
 * @param cb_cls closure for @a cb
 */
void
GNUNET_TRANSPORT_TESTING_find_connecting_context (struct GNUNET_TRANSPORT_TESTING_PeerContext *p1,
						  struct GNUNET_TRANSPORT_TESTING_PeerContext *p2,
						  GNUNET_TRANSPORT_TESTING_ConnectContextCallback cb,
						  void *cb_cls)
{
  struct GNUNET_TRANSPORT_TESTING_Handle *tth = p1->tth;
  struct GNUNET_TRANSPORT_TESTING_ConnectRequest *cc;
  struct GNUNET_TRANSPORT_TESTING_ConnectRequest *ccn;

  for (cc = tth->cc_head; NULL != cc; cc = ccn)
  {
    ccn = cc->next;
    if ( (cc->p1 == p1) &&
	 (cc->p2 == p2) )
      cb (cb_cls,
	  cc);
  }
}


static void
set_p1c (void *cls,
	 struct GNUNET_TRANSPORT_TESTING_ConnectRequest *cx)
{
  int *found = cls;

  if (NULL != found)
    *found = GNUNET_YES;
  cx->p1_c = GNUNET_YES;
}


static void
set_mq (void *cls,
	struct GNUNET_TRANSPORT_TESTING_ConnectRequest *cx)
{
  struct GNUNET_MQ_Handle *mq = cls;

  cx->mq = mq;
}


static void
set_p2c (void *cls,
	 struct GNUNET_TRANSPORT_TESTING_ConnectRequest *cx)
{
  int *found = cls;

  if (NULL != found)
    *found = GNUNET_YES;
  cx->p2_c = GNUNET_YES;
}


static void
clear_p1c (void *cls,
	   struct GNUNET_TRANSPORT_TESTING_ConnectRequest *cx)
{
  int *found = cls;

  if (NULL != found)
    *found = GNUNET_YES;
  cx->p1_c = GNUNET_NO;
}


static void
clear_p2c (void *cls,
	 struct GNUNET_TRANSPORT_TESTING_ConnectRequest *cx)
{
  int *found = cls;

  if (NULL != found)
    *found = GNUNET_YES;
  cx->p2_c = GNUNET_NO;
}


static void *
notify_connect (void *cls,
                const struct GNUNET_PeerIdentity *peer,
		struct GNUNET_MQ_Handle *mq)
{
  struct GNUNET_TRANSPORT_TESTING_PeerContext *p = cls;
  struct GNUNET_TRANSPORT_TESTING_Handle *tth = p->tth;
  char *p2_s;
  struct GNUNET_TRANSPORT_TESTING_PeerContext *p2;
  struct GNUNET_TRANSPORT_TESTING_ConnectRequest *cc;
  struct GNUNET_TRANSPORT_TESTING_ConnectRequest *ccn;
  int found;
  void *ret;

  p2 = find_peer_context (p->tth,
                          peer);
  if (NULL != p->nc)
    ret = p->nc (p->cb_cls,
		 peer,
		 mq);
  else
    ret = NULL;

  if (NULL != p2)
    GNUNET_asprintf (&p2_s,
                     "%u (`%s')",
                     p2->no,
                     GNUNET_i2s (&p2->id));
  else
    GNUNET_asprintf (&p2_s,
                     "`%s'",
                     GNUNET_i2s (peer));
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Peers %s connected to peer %u (`%s')\n",
       p2_s,
       p->no,
       GNUNET_i2s (&p->id));
  GNUNET_free (p2_s);
  /* update flags in connecting contexts */
  found = GNUNET_NO;
  GNUNET_TRANSPORT_TESTING_find_connecting_context (p,
						    p2,
						    &set_p1c,
						    &found);
  if (GNUNET_NO == found)
  {
    cc = GNUNET_new (struct GNUNET_TRANSPORT_TESTING_ConnectRequest);
    cc->p1 = p;
    cc->p2 = p2;
    cc->p1_c = GNUNET_YES;
    GNUNET_CONTAINER_DLL_insert (tth->cc_head,
				 tth->cc_tail,
				 cc);
  }
  found = GNUNET_NO;
  GNUNET_TRANSPORT_TESTING_find_connecting_context (p2,
						    p,
						    &set_p2c,
						    &found);
  if (GNUNET_NO == found)
  {
    cc = GNUNET_new (struct GNUNET_TRANSPORT_TESTING_ConnectRequest);
    cc->p1 = p2;
    cc->p2 = p;
    cc->p1_c = GNUNET_YES;
    GNUNET_CONTAINER_DLL_insert (tth->cc_head,
				 tth->cc_tail,
				 cc);
  }
  GNUNET_TRANSPORT_TESTING_find_connecting_context (p,
						    p2,
						    &set_mq,
						    mq);
  /* update set connected flag for all requests */
  for (cc = tth->cc_head; NULL != cc; cc = cc->next)
  {
    if (GNUNET_YES == cc->connected)
      continue;
    if ( (GNUNET_YES == cc->p1_c) &&
         (GNUNET_YES == cc->p2_c) )
    {
      cc->connected = GNUNET_YES;
      /* stop trying to connect */
      if (NULL != cc->tct)
      {
	GNUNET_SCHEDULER_cancel (cc->tct);
	cc->tct = NULL;
      }
      if (NULL != cc->oh)
      {
	GNUNET_TRANSPORT_offer_hello_cancel (cc->oh);
	cc->oh = NULL;
      }
      if (NULL != cc->ats_sh)
      {
	GNUNET_ATS_connectivity_suggest_cancel (cc->ats_sh);
	cc->ats_sh = NULL;
      }
    }
  }
  /* then notify application */
  for (cc = tth->cc_head; NULL != cc; cc = ccn)
  {
    ccn = cc->next;
    if ( (GNUNET_YES == cc->connected) &&
         (NULL != cc->cb) )
    {
      cc->cb (cc->cb_cls);
      cc->cb = NULL; /* only notify once! */
    }
  }
  return ret;
}


/**
 * Offer the current HELLO of P2 to P1.
 *
 * @param cls our `struct GNUNET_TRANSPORT_TESTING_ConnectRequest`
 */
static void
offer_hello (void *cls);


static void
notify_disconnect (void *cls,
                   const struct GNUNET_PeerIdentity *peer,
		   void *handler_cls)
{
  struct GNUNET_TRANSPORT_TESTING_PeerContext *p = cls;
  struct GNUNET_TRANSPORT_TESTING_Handle *tth = p->tth;
  char *p2_s;
  /* Find PeerContext */
  int no = 0;
  struct GNUNET_TRANSPORT_TESTING_PeerContext *p2 = NULL;
  struct GNUNET_TRANSPORT_TESTING_ConnectRequest *cc;

  p2 = find_peer_context (p->tth,
			  peer);
  no = p->no;
  if (NULL != p2)
    GNUNET_asprintf (&p2_s,
                     "%u (`%s')",
                     p2->no,
                     GNUNET_i2s (&p2->id));
  else
    GNUNET_asprintf (&p2_s,
                     "`%s'",
                     GNUNET_i2s (peer));
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Peers %s disconnected from peer %u (`%s')\n",
       p2_s,
       no,
       GNUNET_i2s (&p->id));
  GNUNET_free (p2_s);
  /* notify about disconnect */
  if (NULL != p->nd)
    p->nd (p->cb_cls,
           peer,
	   handler_cls);
  if (NULL == p2)
    return;
  /* clear MQ, it is now invalid */
  GNUNET_TRANSPORT_TESTING_find_connecting_context (p,
						    p2,
						    &set_mq,
						    NULL);
  /* update set connected flags for all requests */
  GNUNET_TRANSPORT_TESTING_find_connecting_context (p,
						    p2,
						    &clear_p1c,
						    NULL);
  GNUNET_TRANSPORT_TESTING_find_connecting_context (p2,
						    p,
						    &clear_p2c,
						    NULL);
  /* resume connectivity requests as necessary */
  for (cc = tth->cc_head; NULL != cc; cc = cc->next)
  {
    if (GNUNET_NO == cc->connected)
      continue;
    if ( (GNUNET_YES != cc->p1_c) ||
         (GNUNET_YES != cc->p2_c) )
    {
      cc->connected = GNUNET_NO;
      /* start trying to connect */
      if ( (NULL == cc->tct) &&
	   (NULL == cc->oh) )
	cc->tct = GNUNET_SCHEDULER_add_now (&offer_hello,
					    cc);
      if (NULL == cc->ats_sh)
	cc->ats_sh = GNUNET_ATS_connectivity_suggest (cc->p1->ats,
						      &p2->id,
						      1);
    }
  }
}


static void
get_hello (void *cb_cls,
           const struct GNUNET_MessageHeader *message)
{
  struct GNUNET_TRANSPORT_TESTING_PeerContext *p = cb_cls;
  struct GNUNET_PeerIdentity hello_id;

  GNUNET_assert (GNUNET_OK ==
                 GNUNET_HELLO_get_id ((const struct GNUNET_HELLO_Message *) message,
                                      &hello_id));
  GNUNET_assert (0 == memcmp (&hello_id,
                              &p->id,
                              sizeof (hello_id)));
  GNUNET_free_non_null (p->hello);
  p->hello = (struct GNUNET_HELLO_Message *) GNUNET_copy_message (message);

  if (NULL != p->start_cb)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Peer %u (`%s') successfully started\n",
         p->no,
         GNUNET_i2s (&p->id));
    p->start_cb (p->start_cb_cls);
    p->start_cb = NULL;
  }
}


/**
 * Start a peer with the given configuration
 * @param tth the testing handle
 * @param cfgname configuration file
 * @param peer_id a unique number to identify the peer
 * @param handlers functions for receiving messages
 * @param nc connect callback
 * @param nd disconnect callback
 * @param cb_cls closure for callback
 * @param start_cb start callback
 * @param start_cb_cls closure for callback
 * @return the peer context
 */
struct GNUNET_TRANSPORT_TESTING_PeerContext *
GNUNET_TRANSPORT_TESTING_start_peer (struct GNUNET_TRANSPORT_TESTING_Handle *tth,
                                     const char *cfgname,
                                     int peer_id,
                                     const struct GNUNET_MQ_MessageHandler *handlers,
                                     GNUNET_TRANSPORT_NotifyConnecT nc,
                                     GNUNET_TRANSPORT_NotifyDisconnecT nd,
				     void *cb_cls,
                                     GNUNET_SCHEDULER_TaskCallback start_cb,
                                     void *start_cb_cls)
{
  char *emsg = NULL;
  struct GNUNET_TRANSPORT_TESTING_PeerContext *p;
  struct GNUNET_PeerIdentity *dummy;
  unsigned int i;

  if (GNUNET_NO == GNUNET_DISK_file_test (cfgname))
  {
    LOG (GNUNET_ERROR_TYPE_ERROR,
         "File not found: `%s'\n",
         cfgname);
    return NULL;
  }

  p = GNUNET_new (struct GNUNET_TRANSPORT_TESTING_PeerContext);
  p->tth = tth;
  p->nc = nc;
  p->nd = nd;
  if (NULL != handlers)
  {
    for (i=0;NULL != handlers[i].cb;i++) ;
    p->handlers = GNUNET_new_array (i + 1,
				    struct GNUNET_MQ_MessageHandler);
    GNUNET_memcpy (p->handlers,
		   handlers,
		   i * sizeof (struct GNUNET_MQ_MessageHandler));
  }
  if (NULL != cb_cls)
    p->cb_cls = cb_cls;
  else
    p->cb_cls = p;
  p->start_cb = start_cb;
  p->start_cb_cls = start_cb_cls;
  GNUNET_CONTAINER_DLL_insert (tth->p_head,
                               tth->p_tail,
                               p);

  /* Create configuration and call testing lib to modify it */
  p->cfg = GNUNET_CONFIGURATION_create ();
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_CONFIGURATION_load (p->cfg, cfgname));
  if (GNUNET_SYSERR ==
      GNUNET_TESTING_configuration_create (tth->tl_system,
                                           p->cfg))
  {
    LOG (GNUNET_ERROR_TYPE_ERROR,
         "Testing library failed to create unique configuration based on `%s'\n",
         cfgname);
    GNUNET_CONFIGURATION_destroy (p->cfg);
    GNUNET_free (p);
    return NULL;
  }

  p->no = peer_id;
  /* Configure peer with configuration */
  p->peer = GNUNET_TESTING_peer_configure (tth->tl_system,
                                           p->cfg,
                                           p->no,
                                           NULL,
                                           &emsg);
  if (NULL == p->peer)
  {
    LOG (GNUNET_ERROR_TYPE_ERROR,
         "Testing library failed to create unique configuration based on `%s': `%s'\n",
         cfgname,
         emsg);
    GNUNET_TRANSPORT_TESTING_stop_peer (p);
    GNUNET_free_non_null (emsg);
    return NULL;
  }
  GNUNET_free_non_null (emsg);
  if (GNUNET_OK != GNUNET_TESTING_peer_start (p->peer))
  {
    LOG (GNUNET_ERROR_TYPE_ERROR,
         "Testing library failed to create unique configuration based on `%s'\n",
         cfgname);
    GNUNET_TRANSPORT_TESTING_stop_peer (p);
    return NULL;
  }

  memset (&dummy,
          '\0',
          sizeof (dummy));
  GNUNET_TESTING_peer_get_identity (p->peer,
                                    &p->id);
  if (0 == memcmp (&dummy,
                   &p->id,
                   sizeof (struct GNUNET_PeerIdentity)))
  {
    LOG (GNUNET_ERROR_TYPE_ERROR,
         "Testing library failed to obtain peer identity for peer %u\n",
         p->no);
    GNUNET_TRANSPORT_TESTING_stop_peer (p);
    return NULL;
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Peer %u configured with identity `%s'\n",
       p->no,
       GNUNET_i2s_full (&p->id));
  p->tmh = GNUNET_TRANSPORT_manipulation_connect (p->cfg);
  p->th = GNUNET_TRANSPORT_core_connect (p->cfg,
					 NULL,
					 handlers,
					 p,
					 &notify_connect,
					 &notify_disconnect,
					 NULL);
  if ( (NULL == p->th) ||
       (NULL == p->tmh) )
  {
    LOG (GNUNET_ERROR_TYPE_ERROR,
         "Failed to connect to transport service for peer `%s': `%s'\n",
         cfgname,
         emsg);
    GNUNET_TRANSPORT_TESTING_stop_peer (p);
    return NULL;
  }
  p->ats = GNUNET_ATS_connectivity_init (p->cfg);
  if (NULL == p->ats)
  {
    LOG (GNUNET_ERROR_TYPE_ERROR,
         "Failed to connect to ATS service for peer `%s': `%s'\n",
         cfgname,
         emsg);
    GNUNET_TRANSPORT_TESTING_stop_peer (p);
    return NULL;
  }
  p->ghh = GNUNET_TRANSPORT_hello_get (p->cfg,
				       GNUNET_TRANSPORT_AC_ANY,
				       &get_hello,
                                       p);
  GNUNET_assert (NULL != p->ghh);
  return p;
}


/**
 * Stops and restarts the given peer, sleeping (!) for 5s in between.
 *
 * @param p the peer
 * @param restart_cb callback to call when restarted
 * @param restart_cb_cls callback closure
 * @return #GNUNET_OK in success otherwise #GNUNET_SYSERR
 */
int
GNUNET_TRANSPORT_TESTING_restart_peer (struct GNUNET_TRANSPORT_TESTING_PeerContext *p,
                                       GNUNET_SCHEDULER_TaskCallback restart_cb,
                                       void *restart_cb_cls)
{
  struct GNUNET_TRANSPORT_TESTING_ConnectRequest *cc;
  struct GNUNET_TRANSPORT_TESTING_ConnectRequest *ccn;

  /* shutdown */
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Stopping peer %u (`%s')\n",
       p->no,
       GNUNET_i2s (&p->id));
  if (NULL != p->ghh)
  {
    GNUNET_TRANSPORT_hello_get_cancel (p->ghh);
    p->ghh = NULL;
  }
  if (NULL != p->th)
  {
    GNUNET_TRANSPORT_core_disconnect (p->th);
    p->th = NULL;
  }
  if (NULL != p->tmh)
  {
    GNUNET_TRANSPORT_manipulation_disconnect (p->tmh);
    p->tmh = NULL;
  }
  for (cc = p->tth->cc_head; NULL != cc; cc = ccn)
  {
    ccn = cc->next;
    if ( (cc->p1 == p) ||
         (cc->p2 == p) )
      GNUNET_TRANSPORT_TESTING_connect_peers_cancel (cc);
  }
  if (NULL != p->ats)
  {
    GNUNET_ATS_connectivity_done (p->ats);
    p->ats = NULL;
  }
  if (GNUNET_SYSERR ==
      GNUNET_TESTING_peer_stop (p->peer))
  {
    LOG (GNUNET_ERROR_TYPE_ERROR,
         "Failed to stop peer %u (`%s')\n",
         p->no,
         GNUNET_i2s (&p->id));
    return GNUNET_SYSERR;
  }

  sleep (5); // YUCK!

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Restarting peer %u (`%s')\n",
       p->no,
       GNUNET_i2s (&p->id));
  /* restart */
  if (GNUNET_SYSERR == GNUNET_TESTING_peer_start (p->peer))
  {
    LOG (GNUNET_ERROR_TYPE_ERROR,
         "Failed to restart peer %u (`%s')\n",
         p->no,
         GNUNET_i2s (&p->id));
    return GNUNET_SYSERR;
  }

  GNUNET_assert (NULL == p->start_cb);
  p->start_cb = restart_cb;
  p->start_cb_cls = restart_cb_cls;

  p->th = GNUNET_TRANSPORT_core_connect (p->cfg,
					 NULL,
					 p->handlers,
					 p,
					 &notify_connect,
					 &notify_disconnect,
					 NULL);
  GNUNET_assert (NULL != p->th);
  p->ats = GNUNET_ATS_connectivity_init (p->cfg);
  p->ghh = GNUNET_TRANSPORT_hello_get (p->cfg,
				       GNUNET_TRANSPORT_AC_ANY,
                                       &get_hello,
                                       p);
  GNUNET_assert (NULL != p->ghh);
  return GNUNET_OK;
}


/**
 * Shutdown the given peer
 *
 * @param p the peer
 */
void
GNUNET_TRANSPORT_TESTING_stop_peer (struct GNUNET_TRANSPORT_TESTING_PeerContext *p)
{
  struct GNUNET_TRANSPORT_TESTING_Handle *tth = p->tth;
  struct GNUNET_TRANSPORT_TESTING_ConnectRequest *cc;
  struct GNUNET_TRANSPORT_TESTING_ConnectRequest *ccn;

  for (cc = tth->cc_head; NULL != cc; cc = ccn)
  {
    ccn = cc->next;
    if ( (cc->p1 == p) ||
         (cc->p2 == p) )
      GNUNET_TRANSPORT_TESTING_connect_peers_cancel (cc);
  }
  if (NULL != p->ghh)
  {
    GNUNET_TRANSPORT_hello_get_cancel (p->ghh);
    p->ghh = NULL;
  }
  if (NULL != p->tmh)
  {
    GNUNET_TRANSPORT_manipulation_disconnect (p->tmh);
    p->tmh = NULL;
  }
  if (NULL != p->th)
  {
    GNUNET_TRANSPORT_core_disconnect (p->th);
    p->th = NULL;
  }
  if (NULL != p->peer)
  {
    if (GNUNET_OK !=
        GNUNET_TESTING_peer_stop (p->peer))
    {
      LOG (GNUNET_ERROR_TYPE_DEBUG,
           "Testing lib failed to stop peer %u (`%s')\n",
           p->no,
           GNUNET_i2s (&p->id));
    }
    GNUNET_TESTING_peer_destroy (p->peer);
    p->peer = NULL;
  }
  if (NULL != p->ats)
  {
    GNUNET_ATS_connectivity_done (p->ats);
    p->ats = NULL;
  }
  if (NULL != p->hello)
  {
    GNUNET_free (p->hello);
    p->hello = NULL;
  }
  if (NULL != p->cfg)
  {
    GNUNET_CONFIGURATION_destroy (p->cfg);
    p->cfg = NULL;
  }
  GNUNET_CONTAINER_DLL_remove (tth->p_head,
                               tth->p_tail,
                               p);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Peer %u (`%s') stopped\n",
       p->no,
       GNUNET_i2s (&p->id));
  GNUNET_free (p);
}


/**
 * Function called after the HELLO was passed to the
 * transport service.
 */
static void
hello_offered (void *cls)
{
  struct GNUNET_TRANSPORT_TESTING_ConnectRequest *cc = cls;

  cc->oh = NULL;
  cc->tct = GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_SECONDS,
                                          &offer_hello,
                                          cc);
}


/**
 * Offer the current HELLO of P2 to P1.
 *
 * @param cls our `struct GNUNET_TRANSPORT_TESTING_ConnectRequest`
 */
static void
offer_hello (void *cls)
{
  struct GNUNET_TRANSPORT_TESTING_ConnectRequest *cc = cls;
  struct GNUNET_TRANSPORT_TESTING_PeerContext *p1 = cc->p1;
  struct GNUNET_TRANSPORT_TESTING_PeerContext *p2 = cc->p2;

  cc->tct = NULL;
  {
    char *p2_s = GNUNET_strdup (GNUNET_i2s (&p2->id));

    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Asking peer %u (`%s') to connect peer %u (`%s'), providing HELLO with %u bytes\n",
         p1->no,
         GNUNET_i2s (&p1->id),
         p2->no,
         p2_s,
         GNUNET_HELLO_size (cc->p2->hello));
    GNUNET_free (p2_s);
  }

  if (NULL != cc->oh)
    GNUNET_TRANSPORT_offer_hello_cancel (cc->oh);
  cc->oh =
    GNUNET_TRANSPORT_offer_hello (cc->p1->cfg,
                                  (const struct GNUNET_MessageHeader *) cc->p2->hello,
                                  &hello_offered,
                                  cc);
}


/**
 * Initiate a connection from p1 to p2 by offering p1 p2's HELLO message
 *
 * Remarks: start_peer's notify_connect callback can be called before.
 *
 * @param tth transport testing handle
 * @param p1 peer 1
 * @param p2 peer 2
 * @param cb the callback to call when both peers notified that they are connected
 * @param cls callback cls
 * @return a connect request handle
 */
struct GNUNET_TRANSPORT_TESTING_ConnectRequest *
GNUNET_TRANSPORT_TESTING_connect_peers (struct GNUNET_TRANSPORT_TESTING_PeerContext *p1,
                                        struct GNUNET_TRANSPORT_TESTING_PeerContext *p2,
                                        GNUNET_SCHEDULER_TaskCallback cb,
                                        void *cls)
{
  struct GNUNET_TRANSPORT_TESTING_Handle *tth = p1->tth;
  struct GNUNET_TRANSPORT_TESTING_ConnectRequest *cc;
  struct GNUNET_TRANSPORT_TESTING_ConnectRequest *ccn;

  ccn = NULL;
  for (cc = tth->cc_head; NULL != cc; cc = cc->next)
  {
    if ( (cc->p1 == p1) &&
	 (cc->p2 == p2) )
    {
      ccn = cc;
      break;
    }
  }

  cc = GNUNET_new (struct GNUNET_TRANSPORT_TESTING_ConnectRequest);
  cc->p1 = p1;
  cc->p2 = p2;
  cc->cb = cb;
  if (NULL != cls)
    cc->cb_cls = cls;
  else
    cc->cb_cls = cc;
  if (NULL != ccn)
  {
    cc->p1_c = ccn->p1_c;
    cc->p2_c = ccn->p2_c;
    cc->connected = ccn->connected;
  }
  GNUNET_CONTAINER_DLL_insert (tth->cc_head,
                               tth->cc_tail,
                               cc);
  cc->tct = GNUNET_SCHEDULER_add_now (&offer_hello,
                                      cc);
  cc->ats_sh = GNUNET_ATS_connectivity_suggest (cc->p1->ats,
                                                &p2->id,
                                                1);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "New connect request %p\n",
       cc);
  return cc;
}


/**
 * Cancel the request to connect two peers
 * Tou MUST cancel the request if you stop the peers before the peers connected succesfully
 *
 * @param tth transport testing handle
 * @param cc a connect request handle
 */
void
GNUNET_TRANSPORT_TESTING_connect_peers_cancel (struct GNUNET_TRANSPORT_TESTING_ConnectRequest *cc)
{
  struct GNUNET_TRANSPORT_TESTING_Handle *tth = cc->p1->tth;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Canceling connect request!\n");
  if (NULL != cc->tct)
  {
    GNUNET_SCHEDULER_cancel (cc->tct);
    cc->tct = NULL;
  }
  if (NULL != cc->oh)
  {
    GNUNET_TRANSPORT_offer_hello_cancel (cc->oh);
    cc->oh = NULL;
  }
  if (NULL != cc->ats_sh)
  {
    GNUNET_ATS_connectivity_suggest_cancel (cc->ats_sh);
    cc->ats_sh = NULL;
  }
  GNUNET_CONTAINER_DLL_remove (tth->cc_head,
                               tth->cc_tail,
                               cc);
  GNUNET_free (cc);
}


/**
 * Clean up the transport testing
 *
 * @param tth transport testing handle
 */
void
GNUNET_TRANSPORT_TESTING_done (struct GNUNET_TRANSPORT_TESTING_Handle *tth)
{
  struct GNUNET_TRANSPORT_TESTING_ConnectRequest *cc;
  struct GNUNET_TRANSPORT_TESTING_ConnectRequest *ct;
  struct GNUNET_TRANSPORT_TESTING_PeerContext *p;
  struct GNUNET_TRANSPORT_TESTING_PeerContext *t;

  if (NULL == tth)
    return;
  cc = tth->cc_head;
  while (NULL != cc)
  {
    ct = cc->next;
    LOG (GNUNET_ERROR_TYPE_ERROR,
         "Developer forgot to cancel connect request!\n");
    GNUNET_TRANSPORT_TESTING_connect_peers_cancel (cc);
    cc = ct;
  }
  p = tth->p_head;
  while (NULL != p)
  {
    t = p->next;
    LOG (GNUNET_ERROR_TYPE_ERROR,
         "Developer forgot to stop peer!\n");
    GNUNET_TRANSPORT_TESTING_stop_peer (p);
    p = t;
  }
  GNUNET_TESTING_system_destroy (tth->tl_system,
                                 GNUNET_YES);

  GNUNET_free (tth);
}


/**
 * Initialize the transport testing
 *
 * @return transport testing handle
 */
struct GNUNET_TRANSPORT_TESTING_Handle *
GNUNET_TRANSPORT_TESTING_init ()
{
  struct GNUNET_TRANSPORT_TESTING_Handle *tth;

  tth = GNUNET_new (struct GNUNET_TRANSPORT_TESTING_Handle);
  tth->tl_system = GNUNET_TESTING_system_create ("transport-testing",
                                                 NULL,
                                                 NULL,
                                                 NULL);
  if (NULL == tth->tl_system)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Failed to initialize testing library!\n");
    GNUNET_free (tth);
    return NULL;
  }
  return tth;
}

/* end of transport-testing.c */

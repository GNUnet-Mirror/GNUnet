/*
     This file is part of GNUnet.
     (C) 2006, 2009 Christian Grothoff (and other contributing authors)

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
 * @file transport_testing.c
 * @brief testing lib for transport service
 *
 * @author Matthias Wachs
 */

#include "transport-testing.h"

struct ConnectingContext
{
  struct PeerContext *p1;
  struct PeerContext *p2;
  GNUNET_SCHEDULER_TaskIdentifier tct;
  GNUNET_TRANSPORT_TESTING_connect_cb cb;
  void *cb_cls;

  struct GNUNET_TRANSPORT_Handle *th_p1;
  struct GNUNET_TRANSPORT_Handle *th_p2;
  int p1_c;
  int p2_c;
};

static void exchange_hello_last (void *cb_cls,
                                 const struct GNUNET_MessageHeader *message);
static void exchange_hello (void *cb_cls,
                            const struct GNUNET_MessageHeader *message);

static void
notify_connect_internal (void *cls, const struct GNUNET_PeerIdentity *peer,
                         const struct GNUNET_TRANSPORT_ATS_Information *ats,
                         uint32_t ats_count)
{
  struct ConnectingContext *cc = cls;

  GNUNET_assert (cc != NULL);

  if (0 ==
      memcmp (&(*peer).hashPubKey, &cc->p1->id.hashPubKey,
              sizeof (GNUNET_HashCode)))
  {
    if (cc->p1_c == GNUNET_NO)
      cc->p1_c = GNUNET_YES;
  }
  if (0 ==
      memcmp (&(*peer).hashPubKey, &cc->p2->id.hashPubKey,
              sizeof (GNUNET_HashCode)))
  {
    if (cc->p2_c == GNUNET_NO)
      cc->p2_c = GNUNET_YES;
  }

  if ((cc->p2_c == GNUNET_YES) && (cc->p2_c == GNUNET_YES))
  {
    /* clean up */
    GNUNET_TRANSPORT_get_hello_cancel (cc->th_p2, &exchange_hello_last, cc);
    GNUNET_TRANSPORT_get_hello_cancel (cc->th_p1, &exchange_hello, cc);

    if (cc->tct != GNUNET_SCHEDULER_NO_TASK)
      GNUNET_SCHEDULER_cancel (cc->tct);

    cc->tct = GNUNET_SCHEDULER_NO_TASK;

    GNUNET_TRANSPORT_disconnect (cc->th_p1);
    GNUNET_TRANSPORT_disconnect (cc->th_p2);

    if (cc->cb != NULL)
      cc->cb (cc->p1, cc->p2, cc->cb_cls);

    GNUNET_free (cc);
  }
}

static void
notify_connect (void *cls, const struct GNUNET_PeerIdentity *peer,
                const struct GNUNET_TRANSPORT_ATS_Information *ats,
                uint32_t ats_count)
{
  struct PeerContext *p = cls;

  if (p == NULL)
    return;
  if (p->nc != NULL)
    p->nc (p->cb_cls, peer, ats, ats_count);
}

static void
notify_disconnect (void *cls, const struct GNUNET_PeerIdentity *peer)
{
  struct PeerContext *p = cls;

  if (p == NULL)
    return;
  if (p->nd != NULL)
    p->nd (p->cb_cls, peer);
}

static void
notify_receive (void *cls, const struct GNUNET_PeerIdentity *peer,
                const struct GNUNET_MessageHeader *message,
                const struct GNUNET_TRANSPORT_ATS_Information *ats,
                uint32_t ats_count)
{
  struct PeerContext *p = cls;

  if (p == NULL)
    return;
  if (p->rec != NULL)
    p->rec (p->cb_cls, peer, message, ats, ats_count);
}


static void
exchange_hello_last (void *cb_cls, const struct GNUNET_MessageHeader *message)
{
  struct ConnectingContext *cc = cb_cls;
  struct PeerContext *me = cc->p2;

  //struct PeerContext *p1 = cc->p1;

  GNUNET_assert (message != NULL);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Exchanging HELLO of size %d with peer (%s)!\n",
              (int) GNUNET_HELLO_size ((const struct GNUNET_HELLO_Message *)
                                       message), GNUNET_i2s (&me->id));
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_HELLO_get_id ((const struct GNUNET_HELLO_Message *)
                                      message, &me->id));
  GNUNET_TRANSPORT_offer_hello (cc->th_p1, message, NULL, NULL);
}


static void
exchange_hello (void *cb_cls, const struct GNUNET_MessageHeader *message)
{
  struct ConnectingContext *cc = cb_cls;
  struct PeerContext *me = cc->p1;

  //struct PeerContext *p2 = cc->p2;

  GNUNET_assert (message != NULL);
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_HELLO_get_id ((const struct GNUNET_HELLO_Message *)
                                      message, &me->id));
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Exchanging HELLO of size %d from peer %s!\n",
              (int) GNUNET_HELLO_size ((const struct GNUNET_HELLO_Message *)
                                       message), GNUNET_i2s (&me->id));
  GNUNET_TRANSPORT_offer_hello (cc->th_p2, message, NULL, NULL);
}

static void
try_connect (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct ConnectingContext *cc = cls;
  struct PeerContext *p1 = cc->p1;
  struct PeerContext *p2 = cc->p2;

  cc->tct = GNUNET_SCHEDULER_NO_TASK;
  if ((tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN) != 0)
    return;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Asking peers to connect...\n");
  /* FIXME: 'pX.id' may still be all-zeros here... */
  GNUNET_TRANSPORT_try_connect (cc->th_p1, &p2->id);
  GNUNET_TRANSPORT_try_connect (cc->th_p2, &p1->id);

  cc->tct =
      GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_SECONDS, &try_connect, cc);
}


/**
 * Start a peer with the given configuration
 * @param rec receive callback
 * @param nc connect callback
 * @param nd disconnect callback
 * @param cb_cls closure for callback
 * @return the peer context
 */
struct PeerContext *
GNUNET_TRANSPORT_TESTING_start_peer (const char *cfgname,
                                     GNUNET_TRANSPORT_ReceiveCallback rec,
                                     GNUNET_TRANSPORT_NotifyConnect nc,
                                     GNUNET_TRANSPORT_NotifyDisconnect nd,
                                     void *cb_cls)
{
  struct PeerContext *p = GNUNET_malloc (sizeof (struct PeerContext));

  p->cfg = GNUNET_CONFIGURATION_create ();

  GNUNET_assert (GNUNET_OK == GNUNET_CONFIGURATION_load (p->cfg, cfgname));
  if (GNUNET_CONFIGURATION_have_value (p->cfg, "PATHS", "SERVICEHOME"))
    GNUNET_CONFIGURATION_get_value_string (p->cfg, "PATHS", "SERVICEHOME",
                                           &p->servicehome);
  if (NULL != p->servicehome)
    GNUNET_DISK_directory_remove (p->servicehome);
  p->arm_proc =
      GNUNET_OS_start_process (NULL, NULL, "gnunet-service-arm",
                               "gnunet-service-arm", "-c", cfgname,
#if VERBOSE_PEERS
                               "-L", "DEBUG",
#else
                               "-L", "ERROR",
#endif
                               NULL);
  p->nc = nc;
  p->nd = nd;
  p->rec = rec;
  if (cb_cls != NULL)
    p->cb_cls = cb_cls;
  else
    p->cb_cls = p;

  p->th =
      GNUNET_TRANSPORT_connect (p->cfg, NULL, p, &notify_receive,
                                &notify_connect, &notify_disconnect);
  GNUNET_assert (p->th != NULL);
  return p;
}

/**
 * shutdown the given peer
 * @param p the peer
 */
void
GNUNET_TRANSPORT_TESTING_stop_peer (struct PeerContext *p)
{
  if (p->th != NULL)
    GNUNET_TRANSPORT_disconnect (p->th);

  if (NULL != p->arm_proc)
  {
    if (0 != GNUNET_OS_process_kill (p->arm_proc, SIGTERM))
      GNUNET_log_strerror (GNUNET_ERROR_TYPE_WARNING, "kill");
    GNUNET_OS_process_wait (p->arm_proc);
    GNUNET_OS_process_close (p->arm_proc);
    p->arm_proc = NULL;
  }
  GNUNET_CONFIGURATION_destroy (p->cfg);
  if (p->servicehome != NULL)
  {
    GNUNET_DISK_directory_remove (p->servicehome);
    GNUNET_free (p->servicehome);
  }
  GNUNET_free (p);
}

/**
 * Connect the two given peers and call the callback when both peers report the
 * inbound connect. Remarks: start_peer's notify_connect callback can be called
 * before.
 * @param p1 peer 1
 * @param p2 peer 2
 * @param cb the callback to call
 * @param cb_cls callback cls
 */
void
GNUNET_TRANSPORT_TESTING_connect_peers (struct PeerContext *p1,
                                        struct PeerContext *p2,
                                        GNUNET_TRANSPORT_TESTING_connect_cb cb,
                                        void *cb_cls)
{
  struct ConnectingContext *cc =
      GNUNET_malloc (sizeof (struct ConnectingContext));

  GNUNET_assert (p1 != NULL);
  GNUNET_assert (p2 != NULL);

  cc->p1 = p1;
  cc->p2 = p2;

  cc->cb = cb;
  cc->cb_cls = cb_cls;

  cc->th_p1 =
      GNUNET_TRANSPORT_connect (cc->p1->cfg, NULL, cc, NULL,
                                &notify_connect_internal, NULL);

  cc->th_p2 =
      GNUNET_TRANSPORT_connect (cc->p2->cfg, NULL, cc, NULL,
                                &notify_connect_internal, NULL);

  GNUNET_assert (cc->th_p1 != NULL);
  GNUNET_assert (cc->th_p2 != NULL);

  GNUNET_TRANSPORT_get_hello (cc->th_p1, &exchange_hello, cc);
  GNUNET_TRANSPORT_get_hello (cc->th_p2, &exchange_hello_last, cc);

  cc->tct = GNUNET_SCHEDULER_add_now (&try_connect, cc);
}



/* end of transport_testing.h */

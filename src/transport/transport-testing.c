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
  struct PeerContext * p1;
  struct PeerContext * p2;
  GNUNET_SCHEDULER_TaskIdentifier tct;
};


static void
exchange_hello_last (void *cls,
                     const struct GNUNET_MessageHeader *message)
{
  struct ConnectingContext * cc = cls;
  struct PeerContext *me = cc->p2;
  struct PeerContext *p1 = cc->p1;

  GNUNET_assert (message != NULL);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Exchanging HELLO of size %d with peer (%s)!\n",
              (int) GNUNET_HELLO_size((const struct GNUNET_HELLO_Message *)message),
              GNUNET_i2s (&me->id));
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_HELLO_get_id ((const struct GNUNET_HELLO_Message *)
                                      message, &me->id));
  GNUNET_TRANSPORT_offer_hello (p1->th, message, NULL, NULL);
}


static void
exchange_hello (void *cls,
                const struct GNUNET_MessageHeader *message)
{
  struct ConnectingContext * cc = cls;
  struct PeerContext *me = cc->p1;
  struct PeerContext *p2 = cc->p2;

  GNUNET_assert (message != NULL);
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_HELLO_get_id ((const struct GNUNET_HELLO_Message *)
                                      message, &me->id));
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Exchanging HELLO of size %d from peer %s!\n",
              (int) GNUNET_HELLO_size((const struct GNUNET_HELLO_Message *)message),
              GNUNET_i2s (&me->id));
  GNUNET_TRANSPORT_offer_hello (p2->th, message, NULL, NULL);
}

static void
try_connect (void *cls,
             const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct ConnectingContext * cc = cls;
  struct PeerContext *p1 = cc->p1;
  struct PeerContext *p2 = cc->p2;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Asking peers to connect...\n");
  /* FIXME: 'pX.id' may still be all-zeros here... */
  GNUNET_TRANSPORT_try_connect (p2->th,
                                &p1->id);
  GNUNET_TRANSPORT_try_connect (p1->th,
                                &p2->id);
  cc->tct = GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_SECONDS,
                                      &try_connect,
                                      cc);
}

struct PeerContext *
GNUNET_TRANSPORT_TESTING_start_peer (const char * cfgname)
{
  struct PeerContext * p = GNUNET_malloc (sizeof (struct PeerContext));

  p->cfg = GNUNET_CONFIGURATION_create ();

  GNUNET_assert (GNUNET_OK == GNUNET_CONFIGURATION_load (p->cfg, cfgname));
  if (GNUNET_CONFIGURATION_have_value (p->cfg,"PATHS", "SERVICEHOME"))
      GNUNET_CONFIGURATION_get_value_string (p->cfg, "PATHS", "SERVICEHOME", &p->servicehome);
  if (NULL != p->servicehome)
    GNUNET_DISK_directory_remove (p->servicehome);
  p->arm_proc = GNUNET_OS_start_process (NULL, NULL, "gnunet-service-arm",
                                        "gnunet-service-arm",
                                        "-c", cfgname, NULL);
  return p;
}

void
GNUNET_TRANSPORT_TESTING_stop_peer (struct PeerContext * p)
{
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
    GNUNET_free(p->servicehome);
    }
}

void
GNUNET_TRANSPORT_TESTING_connect_peers (struct PeerContext * p1,
                                        struct PeerContext * p2,
                                        GNUNET_TRANSPORT_TESTING_connect_cb * cb,
                                        void * cls)
{
  struct ConnectingContext * cc = GNUNET_malloc (sizeof (struct ConnectingContext));

  GNUNET_assert (p1 != NULL);
  GNUNET_assert (p1->th != NULL);

  GNUNET_assert (p2 != NULL);
  GNUNET_assert (p2->th != NULL);

  cc->p1 = p1;
  cc->p2 = p2;
  GNUNET_TRANSPORT_get_hello (p1->th, &exchange_hello, cc);
  GNUNET_TRANSPORT_get_hello (p2->th, &exchange_hello_last, cc);

  cc->tct = GNUNET_SCHEDULER_add_now (&try_connect, cc);
}



/* end of transport_testing.h */

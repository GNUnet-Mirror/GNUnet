/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2004, 2005, 2007, 2009, 2010 Christian Grothoff (and other contributing authors)

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

/**
 * @file peerinfo/peerinfo_api_notify.c
 * @brief notify API to access peerinfo service
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_client_lib.h"
#include "gnunet_peerinfo_service.h"
#include "gnunet_protocols.h"
#include "gnunet_time_lib.h"
#include "peerinfo.h"

/**
 * Context for the info handler.
 */
struct GNUNET_PEERINFO_NotifyContext
{

  /**
   * Our connection to the PEERINFO service.
   */
  struct GNUNET_CLIENT_Connection *client;

  /**
   * Function to call with information.
   */
  GNUNET_PEERINFO_Processor callback;

  /**
   * Closure for callback.
   */
  void *callback_cls;

  /**
   * Handle to our initial request for message transmission to
   * the peerinfo service.
   */
  struct GNUNET_CLIENT_TransmitHandle *init;

  /**
   * Configuration.
   */
  const struct GNUNET_CONFIGURATION_Handle *cfg;

  /**
   * Scheduler.
   */
  struct GNUNET_SCHEDULER_Handle *sched;
};


/**
 * Send a request to the peerinfo service to start being
 * notified about all changes to peer information.
 *
 * @param nc our context
 */
static void
request_notifications (struct GNUNET_PEERINFO_NotifyContext *nc);


/**
 * Read notifications from the client handle and pass them
 * to the callback.
 *
 * @param nc our context
 */
static void
receive_notifications (struct GNUNET_PEERINFO_NotifyContext *nc);


/**
 * Receive a peerinfo information message, process it and
 * go for more.
 *
 * @param cls closure
 * @param msg message received, NULL on timeout or fatal error
 */
static void
process_notification (void *cls,
		      const struct
		      GNUNET_MessageHeader * msg)
{
  struct GNUNET_PEERINFO_NotifyContext *nc = cls;
  const struct InfoMessage *im;
  const struct GNUNET_HELLO_Message *hello;
  uint16_t ms;

  if (msg == NULL)
    {
      GNUNET_CLIENT_disconnect (nc->client, GNUNET_NO);
      nc->client = GNUNET_CLIENT_connect (nc->sched, "peerinfo", nc->cfg);
      request_notifications (nc);
      return;
    }
  ms = ntohs (msg->size);
  if ((ms < sizeof (struct InfoMessage)) ||
      (ntohs (msg->type) != GNUNET_MESSAGE_TYPE_PEERINFO_INFO))
    {
      GNUNET_break (0);
      GNUNET_CLIENT_disconnect (nc->client, GNUNET_NO);
      nc->client = GNUNET_CLIENT_connect (nc->sched, "peerinfo", nc->cfg);
      request_notifications (nc);
      return;
    }
  im = (const struct InfoMessage *) msg;
  hello = NULL;
  if (ms > sizeof (struct InfoMessage) + sizeof (struct GNUNET_MessageHeader))
    {
      hello = (const struct GNUNET_HELLO_Message *) &im[1];
      if (ms != sizeof (struct InfoMessage) + GNUNET_HELLO_size (hello))
        {
          GNUNET_break (0);
	  GNUNET_CLIENT_disconnect (nc->client, GNUNET_NO);
	  nc->client = GNUNET_CLIENT_connect (nc->sched, "peerinfo", nc->cfg);
	  request_notifications (nc);
          return;
        }
    }
#if DEBUG_PEERINFO
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Received information about peer `%s' from peerinfo database\n",
	      GNUNET_i2s (&im->peer));
#endif
  nc->callback (nc->callback_cls, &im->peer, hello, ntohl (im->trust));
  receive_notifications (nc);
}


/**
 * Read notifications from the client handle and pass them
 * to the callback.
 *
 * @param nc our context
 */
static void
receive_notifications (struct GNUNET_PEERINFO_NotifyContext *nc)
{
  GNUNET_CLIENT_receive (nc->client,
			 &process_notification,
			 nc,
			 GNUNET_TIME_UNIT_FOREVER_REL);
}


/**
 * Transmit our init-notify request, start receiving.
 *
 * @param cls closure (our 'struct GNUNET_PEERINFO_NotifyContext')
 * @param size number of bytes available in buf
 * @param buf where the callee should write the message
 * @return number of bytes written to buf
 */
static size_t 
transmit_notify_request (void *cls,
			 size_t size, 
			 void *buf)
{
  struct GNUNET_PEERINFO_NotifyContext *nc = cls;
  struct GNUNET_MessageHeader hdr;

  nc->init = NULL;
  if (buf == NULL)
    {
      GNUNET_CLIENT_disconnect (nc->client, GNUNET_NO);
      nc->client = GNUNET_CLIENT_connect (nc->sched, "peerinfo", nc->cfg);
      request_notifications (nc);
      return 0;
    }
  GNUNET_assert (size >= sizeof (struct GNUNET_MessageHeader));
  hdr.size = htons (sizeof (struct GNUNET_MessageHeader));
  hdr.type = htons (GNUNET_MESSAGE_TYPE_PEERINFO_NOTIFY);
  memcpy (buf, &hdr, sizeof (struct GNUNET_MessageHeader));
  receive_notifications (nc);
  return sizeof (struct GNUNET_MessageHeader);
}


/**
 * Send a request to the peerinfo service to start being
 * notified about all changes to peer information.
 *
 * @param nc our context
 */
static void
request_notifications (struct GNUNET_PEERINFO_NotifyContext *nc)
{
  GNUNET_assert (NULL == nc->init);
  nc->init =GNUNET_CLIENT_notify_transmit_ready (nc->client,
						 sizeof (struct GNUNET_MessageHeader),
						 GNUNET_TIME_UNIT_FOREVER_REL,
						 GNUNET_YES,
						 &transmit_notify_request,
						 nc);
}


/**
 * Call a method whenever our known information about peers
 * changes.  Initially calls the given function for all known
 * peers and then only signals changes.
 *
 * @param cfg configuration to use
 * @param sched scheduler to use
 * @param callback the method to call for each peer
 * @param callback_cls closure for callback
 * @return NULL on error
 */
struct GNUNET_PEERINFO_NotifyContext *
GNUNET_PEERINFO_notify (const struct GNUNET_CONFIGURATION_Handle *cfg,
			struct GNUNET_SCHEDULER_Handle *sched,
			GNUNET_PEERINFO_Processor callback,
			void *callback_cls)
{
  struct GNUNET_PEERINFO_NotifyContext *nc;
  struct GNUNET_CLIENT_Connection *client;

  client = GNUNET_CLIENT_connect (sched, "peerinfo", cfg);
  if (client == NULL)
    {      
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  _("Could not connect to `%s' service.\n"), "peerinfo");
      return NULL;
    }
  nc = GNUNET_malloc (sizeof (struct GNUNET_PEERINFO_NotifyContext));
  nc->sched = sched;
  nc->cfg = cfg;
  nc->client = client;
  nc->callback = callback;
  nc->callback_cls = callback_cls; 
  request_notifications (nc);
  return nc;
}


/**
 * Stop notifying about changes.
 *
 * @param nc context to stop notifying
 */
void
GNUNET_PEERINFO_notify_cancel (struct GNUNET_PEERINFO_NotifyContext *nc)
{
  if (NULL != nc->init)
    {
      GNUNET_CLIENT_notify_transmit_ready_cancel (nc->init);
      nc->init = NULL;
    }
  GNUNET_CLIENT_disconnect (nc->client, GNUNET_NO);
  GNUNET_free (nc);
}

/* end of peerinfo_api_notify.c */

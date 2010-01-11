/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2004, 2005, 2007, 2009 Christian Grothoff (and other contributing authors)

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
 * @file peerinfo/peerinfo_api.c
 * @brief API to access peerinfo service
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_client_lib.h"
#include "gnunet_peerinfo_service.h"
#include "gnunet_protocols.h"
#include "gnunet_time_lib.h"
#include "peerinfo.h"

#define ADD_PEER_TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 30)


struct CAFContext
{
  struct GNUNET_CLIENT_Connection *client;
  struct GNUNET_MessageHeader *msg;
};


static size_t
copy_and_free (void *cls, size_t size, void *buf)
{
  struct CAFContext *cc = cls;
  struct GNUNET_MessageHeader *msg = cc->msg;
  uint16_t msize;

  if (buf == NULL)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  _
                  ("Failed to transmit message of type %u to `%s' service.\n"),
                  ntohs (msg->type), "peerinfo");
      GNUNET_free (msg);
      GNUNET_CLIENT_disconnect (cc->client);
      GNUNET_free (cc);
      return 0;
    }
  msize = ntohs (msg->size);
  GNUNET_assert (size >= msize);
  memcpy (buf, msg, msize);
  GNUNET_free (msg);
  GNUNET_CLIENT_disconnect (cc->client);
  GNUNET_free (cc);
  return msize;
}



/**
 * Add a host to the persistent list.
 *
 * @param cfg configuration to use
 * @param sched scheduler to use
 * @param peer identity of the peer
 * @param hello the verified (!) HELLO message
 */
void
GNUNET_PEERINFO_add_peer (const struct GNUNET_CONFIGURATION_Handle *cfg,
                          struct GNUNET_SCHEDULER_Handle *sched,
                          const struct GNUNET_PeerIdentity *peer,
                          const struct GNUNET_HELLO_Message *hello)
{
  struct GNUNET_CLIENT_Connection *client;
  struct PeerAddMessage *pam;
  uint16_t hs;
  struct CAFContext *cc;

#if DEBUG_PEERINFO
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Adding peer `%s' to peerinfo database\n",
	      GNUNET_i2s(peer));
#endif
  client = GNUNET_CLIENT_connect (sched, "peerinfo", cfg);
  if (client == NULL)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  _("Could not connect to `%s' service.\n"), "peerinfo");
      return;
    }
  hs = GNUNET_HELLO_size (hello);
  pam = GNUNET_malloc (sizeof (struct PeerAddMessage) + hs);
  pam->header.size = htons (hs + sizeof (struct PeerAddMessage));
  pam->header.type = htons (GNUNET_MESSAGE_TYPE_PEERINFO_ADD);
  memcpy (&pam->peer, peer, sizeof (struct GNUNET_PeerIdentity));
  memcpy (&pam[1], hello, hs);
  cc = GNUNET_malloc (sizeof (struct CAFContext));
  cc->client = client;
  cc->msg = &pam->header;
  GNUNET_CLIENT_notify_transmit_ready (client,
                                       ntohs (pam->header.size),
                                       ADD_PEER_TIMEOUT, 
				       GNUNET_YES,
				       &copy_and_free, cc);
}


/**
 * Context for the info handler.
 */
struct InfoContext
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
   * When should we time out?
   */
  struct GNUNET_TIME_Absolute timeout;

};


/**
 * Type of a function to call when we receive a message
 * from the service.
 *
 * @param cls closure
 * @param msg message received, NULL on timeout or fatal error
 */
static void
info_handler (void *cls, const struct GNUNET_MessageHeader *msg)
{
  struct InfoContext *ic = cls;
  const struct InfoMessage *im;
  const struct GNUNET_HELLO_Message *hello;
  uint16_t ms;

  if (msg == NULL)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  _("Failed to receive response from `%s' service.\n"),
                  "peerinfo");
      ic->callback (ic->callback_cls, NULL, NULL, 1);
      GNUNET_CLIENT_disconnect (ic->client);
      GNUNET_free (ic);
      return;
    }
  if (ntohs (msg->type) == GNUNET_MESSAGE_TYPE_PEERINFO_INFO_END)
    {
#if DEBUG_PEERINFO
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "Received end of list of peers from peerinfo database\n");
#endif
      ic->callback (ic->callback_cls, NULL, NULL, 0);
      GNUNET_CLIENT_disconnect (ic->client);
      GNUNET_free (ic);
      return;
    }
  ms = ntohs (msg->size);
  if ((ms < sizeof (struct InfoMessage)) ||
      (ntohs (msg->type) != GNUNET_MESSAGE_TYPE_PEERINFO_INFO))
    {
      GNUNET_break (0);
      ic->callback (ic->callback_cls, NULL, NULL, 2);
      GNUNET_CLIENT_disconnect (ic->client);
      GNUNET_free (ic);
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
          ic->callback (ic->callback_cls, NULL, NULL, 2);
          GNUNET_CLIENT_disconnect (ic->client);
          GNUNET_free (ic);
          return;
        }
    }
#if DEBUG_PEERINFO
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Received information about peer `%s' from peerinfo database\n",
	      GNUNET_i2s (&im->peer));
#endif
  ic->callback (ic->callback_cls, &im->peer, hello, ntohl (im->trust));
  GNUNET_CLIENT_receive (ic->client,
                         &info_handler,
                         ic,
                         GNUNET_TIME_absolute_get_remaining (ic->timeout));
}


/**
 * Call a method for each known matching host and change
 * its trust value.  The method will be invoked once for
 * each host and then finally once with a NULL pointer.
 * Note that the last call can be triggered by timeout or
 * by simply being done; however, the trust argument will
 * be set to zero if we are done and to 1 if we timed out.
 *
 * @param cfg configuration to use
 * @param sched scheduler to use
 * @param peer restrict iteration to this peer only (can be NULL)
 * @param trust_delta how much to change the trust in all matching peers
 * @param timeout how long to wait until timing out
 * @param callback the method to call for each peer
 * @param callback_cls closure for callback
 */
void
GNUNET_PEERINFO_for_all (const struct GNUNET_CONFIGURATION_Handle *cfg,
                         struct GNUNET_SCHEDULER_Handle *sched,
                         const struct GNUNET_PeerIdentity *peer,
                         int trust_delta,
                         struct GNUNET_TIME_Relative timeout,
                         GNUNET_PEERINFO_Processor callback,
                         void *callback_cls)
{
  struct GNUNET_CLIENT_Connection *client;
  struct ListAllPeersMessage *lapm;
  struct ListPeerMessage *lpm;
  struct InfoContext *ihc;

  client = GNUNET_CLIENT_connect (sched, "peerinfo", cfg);
  if (client == NULL)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  _("Could not connect to `%s' service.\n"), "peerinfo");
      callback (callback_cls, NULL, NULL, 2);
      return;
    }
#if DEBUG_PEERINFO
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Requesting list of peers from peerinfo database\n");
#endif
  ihc = GNUNET_malloc (sizeof (struct InfoContext) +
                       sizeof (struct ListPeerMessage));
  ihc->client = client;
  ihc->callback = callback;
  ihc->callback_cls = callback_cls;
  ihc->timeout = GNUNET_TIME_relative_to_absolute (timeout);
  if (peer == NULL)
    {
      lapm = (struct ListAllPeersMessage *) &ihc[1];
      lapm->header.size = htons (sizeof (struct ListAllPeersMessage));
      lapm->header.type = htons (GNUNET_MESSAGE_TYPE_PEERINFO_GET_ALL);
      lapm->trust_change = htonl (trust_delta);
    }
  else
    {
      lpm = (struct ListPeerMessage *) &ihc[1];
      lpm->header.size = htons (sizeof (struct ListPeerMessage));
      lpm->header.type = htons (GNUNET_MESSAGE_TYPE_PEERINFO_GET);
      lpm->trust_change = htonl (trust_delta);
      memcpy (&lpm->peer, peer, sizeof (struct GNUNET_PeerIdentity));
    }
  if (GNUNET_OK != 
      GNUNET_CLIENT_transmit_and_get_response (client,
					       (const struct GNUNET_MessageHeader*) &ihc[1],
					       timeout,
					       GNUNET_YES,
					       &info_handler,
					       ihc))
    {
      GNUNET_break (0);
      ihc->callback (ihc->callback_cls, NULL, NULL, 1);
      GNUNET_CLIENT_disconnect (ihc->client);
      GNUNET_free (ihc);
      return;
    }
}

/* end of peerinfo_api.c */

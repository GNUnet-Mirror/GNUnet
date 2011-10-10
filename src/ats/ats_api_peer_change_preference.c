/*
     This file is part of GNUnet.
     (C) 2010,2011 Christian Grothoff (and other contributing authors)

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
 * @file ats/ats_api_peer_change_preference.c
 * @brief automatic transport selection API, preference management
 * @author Christian Grothoff
 * @author Matthias Wachs
 *
 * TODO:
 * - write test case
 * - extend API to get performance data
 * - implement simplistic strategy based on say 'lowest latency' or strict ordering
 * - extend API to get peer preferences, implement proportional bandwidth assignment
 * - re-implement API against a real ATS service (!)
 */
#include "platform.h"
#include "gnunet_ats_service.h"
#include "ats_api.h"

struct GNUNET_ATS_InformationRequestContext
{

  /**
   * Our connection to the service.
   */
  struct GNUNET_ATS_Handle *h;

  /**
   * Link to peer record.
   */
  struct AllocationRecord *ar;

  int32_t amount;

  uint64_t preference;

  GNUNET_ATS_PeerConfigurationInfoCallback info;

  void *info_cls;
  
  struct GNUNET_PeerIdentity peer;
  
  GNUNET_SCHEDULER_TaskIdentifier task;

};


static void
exec_pcp (void *cls,
	  const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_ATS_InformationRequestContext *irc = cls;
  int32_t want_reserv;
  int32_t got_reserv;
  struct GNUNET_TIME_Relative rdelay;

  rdelay = GNUNET_TIME_UNIT_ZERO;
  want_reserv = irc->amount;
  if (want_reserv < 0)
  {
    got_reserv = want_reserv;
  }
  else if (want_reserv > 0)
  {
    rdelay =
      GNUNET_BANDWIDTH_tracker_get_delay (&irc->ar->available_recv_window,
					  want_reserv);
    if (rdelay.rel_value == 0)
      got_reserv = want_reserv;
    else
      got_reserv = 0;         /* all or nothing */
  }
  else
    got_reserv = 0;
  GNUNET_BANDWIDTH_tracker_consume (&irc->ar->available_recv_window, got_reserv);

  irc->info (irc->info_cls,
	     &irc->peer,
	     got_reserv,
	     rdelay);
  GNUNET_free (irc);
}


/**
 * Obtain statistics and/or change preferences for the given peer.
 *
 * @param h core handle
 * @param peer identifies the peer
 * @param amount reserve N bytes for receiving, negative
 *                amounts can be used to undo a (recent) reservation;
 * @param preference increase incoming traffic share preference by this amount;
 *                in the absence of "amount" reservations, we use this
 *                preference value to assign proportional bandwidth shares
 *                to all connected peers
 * @param info function to call with the resulting configuration information
 * @param info_cls closure for info
 * @return NULL on error
 */
struct GNUNET_ATS_InformationRequestContext *
GNUNET_ATS_peer_change_preference (struct GNUNET_ATS_Handle *h,
				   const struct GNUNET_PeerIdentity *peer,
                                    int32_t amount, uint64_t preference,
                                    GNUNET_ATS_PeerConfigurationInfoCallback
                                    info, void *info_cls)
{
  struct GNUNET_ATS_InformationRequestContext *irc;
  struct AllocationRecord *ar;

  ar = GNUNET_CONTAINER_multihashmap_get (h->peers, &peer->hashPubKey);
  if (NULL == ar)
  {
    /* attempt to change preference on peer that is not connected */
    GNUNET_assert (0);
    return NULL;
  }
  irc = GNUNET_malloc (sizeof (struct GNUNET_ATS_InformationRequestContext));
  irc->h = h;
  irc->peer = *peer;
  irc->ar = ar;
  irc->amount = amount;
  irc->preference = preference;
  irc->info = info;
  irc->info_cls = info_cls;
  irc->task = GNUNET_SCHEDULER_add_now (&exec_pcp, irc);
  return irc;
}


/**
 * Cancel request for getting information about a peer.
 * Note that an eventual change in preference, trust or bandwidth
 * assignment MAY have already been committed at the time,
 * so cancelling a request is NOT sure to undo the original
 * request.  The original request may or may not still commit.
 * The only thing cancellation ensures is that the callback
 * from the original request will no longer be called.
 *
 * @param irc context returned by the original GNUNET_ATS_peer_get_info call
 */
void
GNUNET_ATS_peer_change_preference_cancel (struct
                                           GNUNET_ATS_InformationRequestContext
                                           *irc)
{
  GNUNET_SCHEDULER_cancel (irc->task);
  GNUNET_free (irc);
}


#if 0
/* old CORE API implementation follows for future reference */
struct GNUNET_ATS_InformationRequestContext
{

  /**
   * Our connection to the service.
   */
  struct GNUNET_ATS_Handle *h;

  /**
   * Link to control message, NULL if CM was sent.
   */
  struct ControlMessage *cm;

  /**
   * Link to peer record.
   */
  struct PeerRecord *pr;
};


/**
 * CM was sent, remove link so we don't double-free.
 *
 * @param cls the 'struct GNUNET_ATS_InformationRequestContext'
 * @param success were we successful?
 */
static void
change_preference_send_continuation (void *cls, int success)
{
  struct GNUNET_ATS_InformationRequestContext *irc = cls;

  irc->cm = NULL;
}


/**
 * Obtain statistics and/or change preferences for the given peer.
 *
 * @param h core handle
 * @param peer identifies the peer
 * @param amount reserve N bytes for receiving, negative
 *                amounts can be used to undo a (recent) reservation;
 * @param preference increase incoming traffic share preference by this amount;
 *                in the absence of "amount" reservations, we use this
 *                preference value to assign proportional bandwidth shares
 *                to all connected peers
 * @param info function to call with the resulting configuration information
 * @param info_cls closure for info
 * @return NULL on error
 */
struct GNUNET_ATS_InformationRequestContext *
GNUNET_ATS_peer_change_preference (struct GNUNET_ATS_Handle *h,
                                    const struct GNUNET_PeerIdentity *peer,
                                    int32_t amount, uint64_t preference,
                                    GNUNET_ATS_PeerConfigurationInfoCallback
                                    info, void *info_cls)
{
  struct GNUNET_ATS_InformationRequestContext *irc;
  struct PeerRecord *pr;
  struct RequestInfoMessage *rim;
  struct ControlMessage *cm;

  pr = GNUNET_CONTAINER_multihashmap_get (h->peers, &peer->hashPubKey);
  if (NULL == pr)
  {
    /* attempt to change preference on peer that is not connected */
    GNUNET_assert (0);
    return NULL;
  }
  if (pr->pcic != NULL)
  {
    /* second change before first one is done */
    GNUNET_break (0);
    return NULL;
  }
  irc = GNUNET_malloc (sizeof (struct GNUNET_ATS_InformationRequestContext));
  irc->h = h;
  irc->pr = pr;
  cm = GNUNET_malloc (sizeof (struct ControlMessage) +
                      sizeof (struct RequestInfoMessage));
  cm->cont = &change_preference_send_continuation;
  cm->cont_cls = irc;
  irc->cm = cm;
  rim = (struct RequestInfoMessage *) &cm[1];
  rim->header.size = htons (sizeof (struct RequestInfoMessage));
  rim->header.type = htons (GNUNET_MESSAGE_TYPE_ATS_REQUEST_INFO);
  rim->rim_id = htonl (pr->rim_id = h->rim_id_gen++);
  rim->reserved = htonl (0);
  rim->reserve_inbound = htonl (amount);
  rim->preference_change = GNUNET_htonll (preference);
  rim->peer = *peer;
#if DEBUG_ATS
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Queueing CHANGE PREFERENCE request for peer `%s' with RIM %u\n",
              GNUNET_i2s (peer), (unsigned int) pr->rim_id);
#endif
  GNUNET_CONTAINER_DLL_insert_tail (h->control_pending_head,
                                    h->control_pending_tail, cm);
  pr->pcic = info;
  pr->pcic_cls = info_cls;
  pr->pcic_ptr = irc;           /* for free'ing irc */
  if (NULL != h->client)
    trigger_next_request (h, GNUNET_NO);
  return irc;
}


/**
 * Cancel request for getting information about a peer.
 * Note that an eventual change in preference, trust or bandwidth
 * assignment MAY have already been committed at the time,
 * so cancelling a request is NOT sure to undo the original
 * request.  The original request may or may not still commit.
 * The only thing cancellation ensures is that the callback
 * from the original request will no longer be called.
 *
 * @param irc context returned by the original GNUNET_ATS_peer_get_info call
 */
void
GNUNET_ATS_peer_change_preference_cancel (struct
                                           GNUNET_ATS_InformationRequestContext
                                           *irc)
{
  struct GNUNET_ATS_Handle *h = irc->h;
  struct PeerRecord *pr = irc->pr;

  GNUNET_assert (pr->pcic_ptr == irc);
  if (irc->cm != NULL)
  {
    GNUNET_CONTAINER_DLL_remove (h->control_pending_head,
                                 h->control_pending_tail, irc->cm);
    GNUNET_free (irc->cm);
  }
  pr->pcic = NULL;
  pr->pcic_cls = NULL;
  pr->pcic_ptr = NULL;
  GNUNET_free (irc);
}
#endif

/* end of ats_api_peer_change_preference.c */

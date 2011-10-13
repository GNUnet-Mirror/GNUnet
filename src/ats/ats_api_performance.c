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
 * @file include/gnunet_ats_service.h
 * @brief automatic transport selection and outbound bandwidth determination
 * @author Christian Grothoff
 * @author Matthias Wachs
  */
#include "platform.h"
#include "gnunet_ats_service.h"

/* ******************************** Performance API ***************************** */

/**
 * ATS Handle to obtain and/or modify performance information.
 */
struct GNUNET_ATS_PerformanceHandle
{
};


/**
 * Get handle to access performance API of the ATS subsystem.
 *
 * @param cfg configuration to use
 * @param infocb function to call on allocation changes, can be NULL
 * @param infocb_cls closure for infocb
 * @return ats performance context
 */
struct GNUNET_ATS_PerformanceHandle *
GNUNET_ATS_performance_init (const struct GNUNET_CONFIGURATION_Handle *cfg,
			     GNUNET_ATS_PeerInformationCallback infocb,
			     void *infocb_cls)
{
  return NULL;
}


/**
 * Client is done using the ATS performance subsystem, release resources.
 *
 * @param atc handle
 */
void
GNUNET_ATS_performance_done (struct GNUNET_ATS_SchedulingHandle *atc)
{
}


/**
 * Context that can be used to cancel a peer information request.
 */
struct GNUNET_ATS_ReservationContext
{
};


/**
 * Reserve inbound bandwidth from the given peer.  ATS will look at
 * the current amount of traffic we receive from the peer and ensure
 * that the peer could add 'amount' of data to its stream.
 *
 * @param h core handle
 * @param peer identifies the peer
 * @param amount reserve N bytes for receiving, negative
 *                amounts can be used to undo a (recent) reservation;
 * @param info function to call with the resulting reservation information
 * @param info_cls closure for info
 * @return NULL on error
 * @deprecated will be replaced soon
 */
struct GNUNET_ATS_ReservationContext *
GNUNET_ATS_reserve_bandwidth (struct GNUNET_ATS_PerformanceHandle *h,
			      const struct GNUNET_PeerIdentity *peer,
			      int32_t amount, 
			      GNUNET_ATS_ReservationCallback info, 
			      void *info_cls)
{
  return NULL;
}


/**
 * Cancel request for reserving bandwidth.
 *
 * @param rc context returned by the original GNUNET_ATS_reserve_bandwidth call
 */
void
GNUNET_ATS_reserve_bandwidth_cancel (struct
				     GNUNET_ATS_ReservationContext *rc)
{
}


/**
 * Change preferences for the given peer. Preference changes are forgotten if peers
 * disconnect.
 * 
 * @param cls closure
 * @param peer identifies the peer
 * @param ... 0-terminated specification of the desired changes
 */
void
GNUNET_ATS_change_preference (struct GNUNET_ATS_PerformanceHandle *h,
			      const struct GNUNET_PeerIdentity *peer,
			      ...)
{
}

/* end of ats_api_performance.c */


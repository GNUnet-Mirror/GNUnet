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
 * @file transport/gnunet-service-transport_manipulation.c
 * @brief transport component manipulation traffic for simulation
 * @author Christian Grothoff
 * @author Matthias Wachs
 */
#include "platform.h"
#include "gnunet-service-transport_blacklist.h"
#include "gnunet-service-transport_clients.h"
#include "gnunet-service-transport_hello.h"
#include "gnunet-service-transport_neighbours.h"
#include "gnunet-service-transport_plugins.h"
#include "gnunet-service-transport_validation.h"
#include "gnunet-service-transport.h"
#include "transport.h"

static struct GNUNET_CONTAINER_MultiHashMap *peers;

#define DELAY 0
#define DISTANCE 1

struct TM_Peer;

struct DelayQueueEntry
{
	struct DelayQueueEntry *prev;
	struct DelayQueueEntry *next;
	struct TM_Peer *tmp;
	struct GNUNET_TIME_Absolute sent_at;
	void *msg;
	size_t msg_size;
	struct GNUNET_TIME_Relative timeout;
	GST_NeighbourSendContinuation cont;
	void *cont_cls;
};

struct TM_Peer
{
	struct GNUNET_PeerIdentity peer;
	uint32_t metrics [TM_BOTH][GNUNET_ATS_QualityPropertiesCount];
	GNUNET_SCHEDULER_TaskIdentifier send_delay_task;
	struct DelayQueueEntry *send_head;
	struct DelayQueueEntry *send_tail;
};



static void
set_delay(struct TM_Peer *tmp, struct GNUNET_PeerIdentity *peer, int direction, uint32_t value)
{
	uint32_t val;
	GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Set traffic metrics %s for peer `%s' in direction %s to %u\n",
			"DELAY", GNUNET_i2s(peer),
			(TM_BOTH == direction) ? "BOTH" : (TM_SEND == direction) ? "SEND": "RECEIVE", value);

	if (UINT32_MAX == value)
		val = UINT32_MAX - 1; /* prevent overflow */
	else if (0 == value)
		val = UINT32_MAX; /* disable */
	else
		val = value;

	switch (direction) {
		case TM_BOTH:
			tmp->metrics[TM_SEND][DELAY] = val;
			tmp->metrics[TM_RECEIVE][DELAY] = val;
			break;
		case TM_SEND:
			tmp->metrics[TM_SEND][DELAY] = val;
			break;
		case TM_RECEIVE:
			tmp->metrics[TM_RECEIVE][DELAY] = val;
			break;
		default:
			break;
	}

}

static void
set_distance (struct TM_Peer *tmp, struct GNUNET_PeerIdentity *peer, int direction, uint32_t value)
{
	uint32_t val;
	GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Set traffic metrics %s for peer `%s' in direction %s to %u\n",
			"DISTANCE", GNUNET_i2s(peer),
			(TM_BOTH == direction) ? "BOTH" : (TM_SEND == direction) ? "SEND": "RECEIVE", value);

	if (UINT32_MAX == value)
		val = UINT32_MAX - 1; /* prevent overflow */
	else if (0 == value)
		val = UINT32_MAX; /* disable */
	else
		val = value;

	switch (direction) {
	case TM_BOTH:
		tmp->metrics[TM_SEND][DISTANCE] = val;
		tmp->metrics[TM_RECEIVE][DISTANCE] = val;
		break;
	case TM_SEND:
		tmp->metrics[TM_SEND][DISTANCE] = val;
		break;
	case TM_RECEIVE:
		tmp->metrics[TM_RECEIVE][DISTANCE] = val;
		break;
	default:
		break;
	}
}

void
GST_manipulation_set_metric (void *cls, struct GNUNET_SERVER_Client *client,
    const struct GNUNET_MessageHeader *message)
{
	struct TrafficMetricMessage *tm = (struct TrafficMetricMessage *) message;
	struct GNUNET_ATS_Information *ats;
	struct TM_Peer *tmp;
	uint32_t type;
	uint32_t value;
	int c;
	int c2;

	if (0 == ntohs (tm->ats_count))
	  GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);

	GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Received traffic metrics for peer `%s'\n",
			GNUNET_i2s(&tm->peer));

	if (NULL == (tmp = GNUNET_CONTAINER_multihashmap_get (peers, &tm->peer.hashPubKey)))
	{
			tmp = GNUNET_malloc (sizeof (struct TM_Peer));
			tmp->peer = (tm->peer);
			for (c = 0; c < TM_BOTH; c++)
			{
					for (c2 = 0; c2 < GNUNET_ATS_QualityPropertiesCount; c2++)
					{
							tmp->metrics[c][c2] = UINT32_MAX;
					}
			}
			GNUNET_CONTAINER_multihashmap_put (peers, &tm->peer.hashPubKey, tmp, GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST);
	}

	ats = (struct GNUNET_ATS_Information *) &tm[1];
	for (c = 0; c < ntohs (tm->ats_count); c++)
	{
			type = htonl (ats[c].type);
			value = htonl (ats[c].value);
			switch (type) {
				case GNUNET_ATS_QUALITY_NET_DELAY:
					set_delay (tmp, &tm->peer, ntohs (tm->direction), value);
					break;
				case GNUNET_ATS_QUALITY_NET_DISTANCE:
					set_distance (tmp, &tm->peer, ntohs (tm->direction), value);
					break;
				default:
					break;
			}
	}

  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}

static void
send_delayed (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
	struct DelayQueueEntry *dqe = cls;
	struct DelayQueueEntry *next;
	struct TM_Peer *tmp = dqe->tmp;
	struct GNUNET_TIME_Relative delay;
	tmp->send_delay_task = GNUNET_SCHEDULER_NO_TASK;
	GNUNET_CONTAINER_DLL_remove (tmp->send_head, tmp->send_tail, dqe);
	GST_neighbours_send (&tmp->peer, dqe->msg, dqe->msg_size, dqe->timeout, dqe->cont, dqe->cont_cls);

	next = tmp->send_head;
	if (NULL != next)
	{
			/* More delayed messages */
			delay = GNUNET_TIME_absolute_get_remaining (next->sent_at);
			tmp->send_delay_task = GNUNET_SCHEDULER_add_delayed (delay, &send_delayed, dqe);
	}

	GNUNET_free (dqe);
}

void
GST_manipulation_send (const struct GNUNET_PeerIdentity *target, const void *msg,
    size_t msg_size, struct GNUNET_TIME_Relative timeout,
    GST_NeighbourSendContinuation cont, void *cont_cls)
{
	struct TM_Peer *tmp;
	struct DelayQueueEntry *dqe;
	struct GNUNET_TIME_Relative delay;

	if (NULL != (tmp = GNUNET_CONTAINER_multihashmap_get (peers, &target->hashPubKey)))
	{
			/* Manipulate here */
			/* Delay */
			if (UINT32_MAX != tmp->metrics[TM_SEND][DELAY])
			{
					/* We have a delay */
					delay.rel_value = tmp->metrics[TM_SEND][DELAY];
					dqe = GNUNET_malloc (sizeof (struct DelayQueueEntry) + msg_size);
					dqe->tmp = tmp;
					dqe->sent_at = GNUNET_TIME_absolute_add (GNUNET_TIME_absolute_get(), delay);
					dqe->cont = cont;
					dqe->cont_cls = cont_cls;
					dqe->msg = &dqe[1];
					dqe->msg_size = msg_size;
					dqe->timeout = timeout;
					memcpy (dqe->msg, msg, msg_size);
					GNUNET_CONTAINER_DLL_insert_tail (tmp->send_head, tmp->send_tail, dqe);
					if (GNUNET_SCHEDULER_NO_TASK == tmp->send_delay_task)
						tmp->send_delay_task =GNUNET_SCHEDULER_add_delayed (delay, &send_delayed, dqe);
					return;
			}
	}
	/* Normal sending */
	GST_neighbours_send (target, msg, msg_size, timeout, cont, cont_cls);
}

struct GNUNET_TIME_Relative
GST_manipulation_recv (void *cls, const struct GNUNET_PeerIdentity *peer,
    const struct GNUNET_MessageHeader *message,
    const struct GNUNET_ATS_Information *ats,
    uint32_t ats_count, struct Session *session,
    const char *sender_address,
    uint16_t sender_address_len)
{
	struct TM_Peer *tmp;
	int d;
	struct GNUNET_ATS_Information ats_new[ats_count];
	struct GNUNET_TIME_Relative q_delay;
	struct GNUNET_TIME_Relative m_delay;

	for (d = 0; d < ats_count; d++)

	if (NULL != (tmp = GNUNET_CONTAINER_multihashmap_get (peers, &peer->hashPubKey)))
	{
			/* Manipulate distance */
			for (d = 0; d < ats_count; d++)
			{
					ats_new[d] = ats[d];
					/* Set distance */
					if ((ntohl(ats[d].type) == GNUNET_ATS_QUALITY_NET_DISTANCE) &&
						 (UINT32_MAX != tmp->metrics[TM_RECEIVE][DISTANCE]))
							ats_new[d].value = htonl(tmp->metrics[TM_RECEIVE][DISTANCE]);
			}
			/* Manipulate receive delay */
			if (UINT32_MAX != tmp->metrics[TM_RECEIVE][DELAY])
			{
					m_delay.rel_value = tmp->metrics[TM_RECEIVE][DELAY];
					q_delay = GST_receive_callback (cls, peer, message, &ats_new[0], ats_count,
							session, sender_address, sender_address_len);

					if (q_delay.rel_value >= m_delay.rel_value)
					{
							return q_delay;
					}
					else
					{
							return m_delay;
					}
			}
			else
				return GST_receive_callback (cls, peer, message, &ats_new[0], ats_count,
						session, sender_address, sender_address_len);
	}

	return GST_receive_callback (cls, peer, message, ats, ats_count,
			session, sender_address, sender_address_len);
}

void
GST_manipulation_init ()
{
	peers = GNUNET_CONTAINER_multihashmap_create (10, GNUNET_NO);
}

int free_tmps (void *cls,
							 const struct GNUNET_HashCode * key,
							 void *value)
{
	struct DelayQueueEntry *dqe;
	struct DelayQueueEntry *next;
	if (NULL != value)
	{
			struct TM_Peer *tmp = (struct TM_Peer *) value;
			GNUNET_CONTAINER_multihashmap_remove (peers, key, value);
			next = tmp->send_head;
			while (NULL != (dqe = next))
			{
					next = dqe->next;
					GNUNET_CONTAINER_DLL_remove (tmp->send_head, tmp->send_tail, dqe);
					GNUNET_free (dqe);
			}
			if (GNUNET_SCHEDULER_NO_TASK != tmp->send_delay_task)
			{
					GNUNET_SCHEDULER_cancel (tmp->send_delay_task);
					tmp->send_delay_task = GNUNET_SCHEDULER_NO_TASK;
			}
			GNUNET_free (tmp);
	}
	return GNUNET_OK;
}

void
GST_manipulation_stop ()
{
	GNUNET_CONTAINER_multihashmap_iterate (peers, &free_tmps,NULL);

	GNUNET_CONTAINER_multihashmap_destroy (peers);
	peers = NULL;
}


/* end of file gnunet-service-transport_manipulation.c */

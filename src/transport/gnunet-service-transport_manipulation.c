/*
     This file is part of GNUnet.
     (C) 2010-2013 Christian Grothoff (and other contributing authors)

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

#define DELAY 0
#define DISTANCE 1


enum TRAFFIC_METRIC_DIRECTION
{
	TM_SEND = 0,
	TM_RECEIVE = 1,
	TM_BOTH = 2
};

struct GST_ManipulationHandle man_handle;


/**
 * Struct containing information about manipulations to a specific peer
 */
struct TM_Peer;

struct PropManipulationEntry
{
	struct PropManipulationEntry *next;
	struct PropManipulationEntry *prev;

	uint32_t type;

	uint32_t metrics[TM_BOTH];

};

/**
 * Struct containing information about manipulations to a specific peer
 */
struct TM_Peer
{
	/**
	 * Peer ID
	 */
	struct GNUNET_PeerIdentity peer;

	struct PropManipulationEntry *head;
	struct PropManipulationEntry *tail;

	/**
	 * Peer specific manipulation metrics
	 */
	uint32_t metrics [TM_BOTH][GNUNET_ATS_QualityPropertiesCount];

	/**
	 * Task to schedule delayed sendding
	 */
	GNUNET_SCHEDULER_TaskIdentifier send_delay_task;

	/**
	 * Send queue DLL head
	 */
	struct DelayQueueEntry *send_head;

	/**
	 * Send queue DLL tail
	 */
	struct DelayQueueEntry *send_tail;
};


struct GST_ManipulationHandle
{
	/**
	 * Hashmap contain all peers currently manipulated
	 */
	struct GNUNET_CONTAINER_MultiHashMap *peers;

	struct TM_Peer general;

	/**
	 * General inbound delay
	 */
	struct GNUNET_TIME_Relative delay_recv;

	/**
	 * General outbound delay
	 */
	struct GNUNET_TIME_Relative delay_send;

	/**
	 * General inbound distance
	 */
	 unsigned long long distance_recv;

	/**
	 * General outbound distance
	 */
	 unsigned long long distance_send;

	 struct PropManipulationEntry *head;
	 struct PropManipulationEntry *tail;
};



/**
 * Entry in the delay queue for an outbound delayed message
 */
struct DelayQueueEntry
{
	/**
	 * Next in DLL
	 */
	struct DelayQueueEntry *prev;

	/**
	 * Previous in DLL
	 */
	struct DelayQueueEntry *next;

	/**
	 * Peer this entry is belonging to
	 */
	struct TM_Peer *tmp;

	/**
	 * Absolute time when to send
	 */
	struct GNUNET_TIME_Absolute sent_at;

	/**
	 * The message
	 */
	void *msg;

	/**
	 * The message size
	 */
	size_t msg_size;

	/**
	 * Message timeout
	 */
	struct GNUNET_TIME_Relative timeout;

	/**
	 * Transports send continuation
	 */
	GST_NeighbourSendContinuation cont;

	/**
	 * Transports send continuation cls
	 */
	void *cont_cls;
};


static void
set_metric (struct TM_Peer *dest, int direction, uint32_t type, uint32_t value)
{
	struct PropManipulationEntry *cur;
	for (cur = dest->head; NULL != cur; cur = cur->next)
	{
		if (cur->type == type)
			break;
	}
	if (NULL == cur)
	{
		cur = GNUNET_malloc (sizeof (struct PropManipulationEntry));
		GNUNET_CONTAINER_DLL_insert (dest->head, dest->tail, cur);
		cur->type = type;
		cur->metrics[TM_SEND] = UINT32_MAX;
		cur->metrics[TM_RECEIVE] = UINT32_MAX;
	}


	switch (direction) {
		case TM_BOTH:
			cur->metrics[TM_SEND] = value;
			cur->metrics[TM_RECEIVE] = value;
			break;
		case TM_SEND:
			cur->metrics[TM_SEND] = value;
			break;
		case TM_RECEIVE:
			cur->metrics[TM_RECEIVE] = value;
			break;
		default:
			break;
	}

}

static uint32_t
find_metric (struct TM_Peer *dest, uint32_t type, int direction)
{
	struct PropManipulationEntry *cur;

	for (cur = dest->head; NULL != cur; cur = cur->next)
	{
		if (cur->type == type)
			return cur->metrics[direction];

	}
	return UINT32_MAX;
}

static void
free_metric (struct TM_Peer *dest)
{
	struct PropManipulationEntry *cur;
	struct PropManipulationEntry *next;

	for (cur = dest->head; NULL != cur; cur = next)
	{
		next = cur->next;
		GNUNET_CONTAINER_DLL_remove (dest->head, dest->tail, cur);
		GNUNET_free (cur);
	}
}

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


/**
 * Set traffic metric to manipulate
 *
 * @param cls closure
 * @param client client sending message
 * @param message containing information
 */
void
GST_manipulation_set_metric (void *cls, struct GNUNET_SERVER_Client *client,
    const struct GNUNET_MessageHeader *message)
{
	struct TrafficMetricMessage *tm = (struct TrafficMetricMessage *) message;
	struct GNUNET_PeerIdentity dummy;
	struct GNUNET_ATS_Information *ats;
	struct TM_Peer *tmp;
	uint32_t type;
	uint32_t value;
	uint16_t direction;
	int c;
	int c2;

	if (0 == ntohs (tm->ats_count))
	  GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);

	switch (ntohs(tm->direction)) {
		case 1:
			direction = TM_SEND;
			break;
		case 2:
			direction = TM_RECEIVE;
			break;
		case 3:
			direction = TM_BOTH;
			break;
		default:
			break;
	}

	memset (&dummy, '\0', sizeof (struct GNUNET_PeerIdentity));
	if (0 == memcmp (&tm->peer, &dummy, sizeof (struct GNUNET_PeerIdentity)))
	{
			GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Received traffic metrics for all peers \n");

			ats = (struct GNUNET_ATS_Information *) &tm[1];
			for (c = 0; c < ntohs (tm->ats_count); c++)
			{
					type = htonl (ats[c].type);
					value = htonl (ats[c].value);

					set_metric (&man_handle.general, direction, type, value);

					switch (type) {
						case GNUNET_ATS_QUALITY_NET_DELAY:
							if ((TM_RECEIVE == direction) || (TM_BOTH == direction))
									man_handle.delay_recv.rel_value = value;
							if ((TM_SEND == direction) || (TM_BOTH == direction))
									man_handle.delay_send.rel_value = value;
							break;
						case GNUNET_ATS_QUALITY_NET_DISTANCE:
							if ((TM_RECEIVE == direction) || (TM_BOTH == direction))
									man_handle.distance_recv = value;
							if ((TM_SEND == direction) || (TM_BOTH == direction))
									man_handle.distance_send = value;
							break;
						default:
							break;
					}

			}
			return;
	}

	GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Received traffic metrics for peer `%s'\n",
			GNUNET_i2s(&tm->peer));

	if (NULL == (tmp = GNUNET_CONTAINER_multihashmap_get (man_handle.peers, &tm->peer.hashPubKey)))
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
			GNUNET_CONTAINER_multihashmap_put (man_handle.peers, &tm->peer.hashPubKey, tmp, GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST);
	}

	ats = (struct GNUNET_ATS_Information *) &tm[1];
	for (c = 0; c < ntohs (tm->ats_count); c++)
	{
			type = htonl (ats[c].type);
			value = htonl (ats[c].value);

			set_metric (tmp, direction, type, value);


			switch (type) {
				case GNUNET_ATS_QUALITY_NET_DELAY:
					set_delay (tmp, &tm->peer, direction, value);
					break;
				case GNUNET_ATS_QUALITY_NET_DISTANCE:
					set_distance (tmp, &tm->peer, direction, value);
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


/**
 * Adapter function between transport's send function and transport plugins
 *
 * @param target the peer the message to send to
 * @param msg the message received
 * @param msg_size message size
 * @param timeout timeout
 * @param cont the continuation to call after sending
 * @param cont_cls cls for continuation
 */
void
GST_manipulation_send (const struct GNUNET_PeerIdentity *target, const void *msg,
    size_t msg_size, struct GNUNET_TIME_Relative timeout,
    GST_NeighbourSendContinuation cont, void *cont_cls)
{
	struct TM_Peer *tmp;
	struct DelayQueueEntry *dqe;
	struct GNUNET_TIME_Relative delay;

	if (NULL != (tmp = GNUNET_CONTAINER_multihashmap_get (man_handle.peers, &target->hashPubKey)))
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
	else if (man_handle.delay_send.rel_value != 0)
	{
			/* We have a delay */
			delay = man_handle.delay_send;
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

	/* Normal sending */
	GST_neighbours_send (target, msg, msg_size, timeout, cont, cont_cls);
}


/**
 * Function that will be called to manipulate ATS information according to
 * current manipulation settings
 *
 * @param peer the peer
 * @param address binary address
 * @param session the session
 * @param ats the ats information
 * @param ats_count the number of ats information
 */
struct GNUNET_ATS_Information *
GST_manipulation_manipulate_metrics (const struct GNUNET_PeerIdentity *peer,
		const struct GNUNET_HELLO_Address *address,
		struct Session *session,
		const struct GNUNET_ATS_Information *ats,
		uint32_t ats_count)
{
	struct GNUNET_ATS_Information *ats_new = GNUNET_malloc (sizeof (struct GNUNET_ATS_Information) *ats_count);
	struct TM_Peer *tmp;
	uint32_t m_distance;
	int d;
	m_distance = 0;
	if (NULL != (tmp = GNUNET_CONTAINER_multihashmap_get (man_handle.peers, &peer->hashPubKey)))
	{
			if (UINT32_MAX != tmp->metrics[TM_RECEIVE][DISTANCE])
					m_distance = tmp->metrics[TM_RECEIVE][DISTANCE];
	}

	for (d = 0; d < ats_count; d++)
	{
		ats_new[d] = ats[d];
		if (ntohl(ats[d].type) == GNUNET_ATS_QUALITY_NET_DISTANCE)
		{
			if (m_distance > 0)
			{
				ats_new[d].value = htonl(m_distance);
			}
			else if  (man_handle.distance_recv > 0)
			{
				ats_new[d].value = htonl(man_handle.distance_recv);
			}
		}
	}

	return ats_new;
}


/**
 * Adapter function between transport plugins and transport receive function
 * manipulation delays for next send.
 *
 * @param cls the closure for transport
 * @param peer the peer the message was received from
 * @param message the message received
 * @param session the session the message was received on
 * @param sender_address the sender address
 * @param sender_address_len the length of the sender address
 * @return manipulated delay for next receive
 */
struct GNUNET_TIME_Relative
GST_manipulation_recv (void *cls,
		const struct GNUNET_PeerIdentity *peer,
    const struct GNUNET_MessageHeader *message,
    struct Session *session,
    const char *sender_address,
    uint16_t sender_address_len)
{
	struct TM_Peer *tmp;

	struct GNUNET_TIME_Relative quota_delay;
	struct GNUNET_TIME_Relative m_delay;

	if (man_handle.delay_recv.rel_value > GNUNET_TIME_UNIT_ZERO.rel_value)
		m_delay = man_handle.delay_recv; /* Global delay */
	else
		m_delay = GNUNET_TIME_UNIT_ZERO;

	if (NULL != (tmp = GNUNET_CONTAINER_multihashmap_get (man_handle.peers, &peer->hashPubKey)))
	{
			/* Manipulate receive delay */
			if (UINT32_MAX != tmp->metrics[TM_RECEIVE][DELAY])
					m_delay.rel_value = tmp->metrics[TM_RECEIVE][DELAY]; /* Peer specific delay */
	}

	quota_delay = GST_receive_callback (cls, peer, message,
			session, sender_address, sender_address_len);
	if (quota_delay.rel_value > m_delay.rel_value)
		return quota_delay;
	else
		return m_delay;
}


/**
 * Initialize traffic manipulation
 *
 * @param GST_cfg configuration handle
 */
void
GST_manipulation_init (const struct GNUNET_CONFIGURATION_Handle *GST_cfg)
{
	if (GNUNET_OK == GNUNET_CONFIGURATION_get_value_number (GST_cfg,
			"transport", "MANIPULATE_DISTANCE_IN", &man_handle.distance_recv))
		GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Setting inbound distance_in to %u\n",
				(unsigned long long) man_handle.distance_recv);
	else
		man_handle.distance_recv = 0;

	if (GNUNET_OK == GNUNET_CONFIGURATION_get_value_number (GST_cfg,
			"transport", "MANIPULATE_DISTANCE_OUT", &man_handle.distance_send))
		GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Setting outbound distance_in to %u\n",
				(unsigned long long) man_handle.distance_send);
	else
		man_handle.distance_send = 0;

	if (GNUNET_OK == GNUNET_CONFIGURATION_get_value_time (GST_cfg,
			"transport", "MANIPULATE_DELAY_IN", &man_handle.delay_recv))
		GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Delaying inbound traffic for %llu ms\n",
				(unsigned long long) man_handle.delay_recv.rel_value);
	else
		man_handle.delay_recv.rel_value = 0;

	if (GNUNET_OK == GNUNET_CONFIGURATION_get_value_time (GST_cfg,
			"transport", "MANIPULATE_DELAY_OUT", &man_handle.delay_send))
		GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Delaying outbound traffic for %llu ms\n",
			(unsigned long long) man_handle.delay_send.rel_value);
	else
		man_handle.delay_send.rel_value = 0;

	man_handle.peers = GNUNET_CONTAINER_multihashmap_create (10, GNUNET_NO);
}


static int 
free_tmps (void *cls,
	   const struct GNUNET_HashCode * key,
	   void *value)
{
	struct DelayQueueEntry *dqe;
	struct DelayQueueEntry *next;
	if (NULL != value)
	{
			struct TM_Peer *tmp = (struct TM_Peer *) value;
			GNUNET_CONTAINER_multihashmap_remove (man_handle.peers, key, value);
			free_metric (tmp);
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


/**
 * Stop traffic manipulation
 */
void
GST_manipulation_stop ()
{
	GNUNET_CONTAINER_multihashmap_iterate (man_handle.peers, &free_tmps,NULL);

	GNUNET_CONTAINER_multihashmap_destroy (man_handle.peers);
	free_metric (&man_handle.general);
	man_handle.peers = NULL;
}


/* end of file gnunet-service-transport_manipulation.c */

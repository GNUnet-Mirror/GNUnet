/*
     This file is part of GNUnet.
     (C) 2009 Christian Grothoff (and other contributing authors)

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
 * @file experimentation/gnunet-daemon-experimentation_scheduler.c
 * @brief experimentation daemon: execute experiments
 * @author Christian Grothoff
 * @author Matthias Wachs
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_core_service.h"
#include "gnunet_statistics_service.h"
#include "gnunet-daemon-experimentation.h"

/**
 * An experiment is added during startup as not running NOT_RUNNING
 *
 * The scheduler then decides to schedule it and sends a request to the
 * remote peer, if core cannot send since it is busy we wait for some time
 * and change state to BUSY, if we can send we change to REQUESTED and wait
 * for remote peers ACK.
 *
 * When we receive an ACK we change to STARTED and when scheduler decides that
 * the experiment is finished we change to STOPPED.
 */

enum ExperimentState
{
	/* Experiment is added and waiting to be executed */
	NOT_RUNNING,
	/* Cannot send request to remote peer, core is busy*/
	BUSY,
	/* We requested experiment and wait for remote peer to ACK */
	REQUESTED,
	/* Experiment is running */
	STARTED,
	/* Experiment is done */
	STOPPED
};

struct ScheduledExperiment {
	struct ScheduledExperiment *next;
	struct ScheduledExperiment *prev;

	struct Experiment *e;
	struct Node *n;
	int state;
	int outbound;
	GNUNET_SCHEDULER_TaskIdentifier task;
};

struct ScheduledExperiment *waiting_in_head;
struct ScheduledExperiment *waiting_in_tail;

struct ScheduledExperiment *running_in_head;
struct ScheduledExperiment *running_in_tail;

struct ScheduledExperiment *waiting_out_head;
struct ScheduledExperiment *waiting_out_tail;

struct ScheduledExperiment *running_out_head;
struct ScheduledExperiment *running_out_tail;


static unsigned int experiments_scheduled;
static unsigned int experiments_outbound_running;
static unsigned int experiments_inbound_running;
static unsigned int experiments_requested;


static struct ScheduledExperiment *
find_experiment (struct ScheduledExperiment *head, struct ScheduledExperiment *tail,
								 struct Node *n, struct Experiment *e, int outbound)
{
	struct ScheduledExperiment *cur;
	for (cur = head; NULL != cur; cur = cur->next)
	{
		if ((cur->n == n) && (cur->e == e) && (cur->outbound == outbound)) /* Node and experiment are equal */
			break;
	}
	return cur;
}

static void
request_timeout (void *cls,const struct GNUNET_SCHEDULER_TaskContext* tc)
{
	struct ScheduledExperiment *se = cls;
	se->task = GNUNET_SCHEDULER_NO_TASK;

	GNUNET_log (GNUNET_ERROR_TYPE_INFO, _("Peer `%s' did not respond to request for experiment `%s'\n"),
			GNUNET_i2s (&se->n->id), se->e->name);

	GNUNET_CONTAINER_DLL_remove (waiting_out_head, waiting_out_tail, se);
	GNUNET_free (se);

	/* Remove experiment */
	GNUNET_assert (experiments_requested > 0);
	experiments_requested --;
	GNUNET_STATISTICS_set (GED_stats, "# experiments requested", experiments_requested, GNUNET_NO);
}

static void run_experiment_inbound (void *cls,const struct GNUNET_SCHEDULER_TaskContext* tc)
{
	struct ScheduledExperiment *se = cls;
	struct GNUNET_TIME_Relative start;
	struct GNUNET_TIME_Relative end;

	se->task = GNUNET_SCHEDULER_NO_TASK;

	switch (se->state) {
		case NOT_RUNNING:
			/* Send START_ACK message */
			GED_nodes_send_start_ack (se->n, se->e);
			se->state = REQUESTED;
			/* Schedule to run */
			start = GNUNET_TIME_absolute_get_remaining(se->e->start);
			if (0 == start.rel_value_us)
					se->task = GNUNET_SCHEDULER_add_now (&run_experiment_inbound, se);
			else
					se->task = GNUNET_SCHEDULER_add_delayed (start, &run_experiment_inbound, se);
			break;
		case REQUESTED:
			experiments_inbound_running ++;
			GNUNET_STATISTICS_set (GED_stats, "# experiments inbound running", experiments_inbound_running, GNUNET_NO);
			GNUNET_log (GNUNET_ERROR_TYPE_INFO, _("Starting inbound experiment `%s' with peer `%s'\n"),
					se->e->name, GNUNET_i2s (&se->n->id));
			se->state = STARTED;
			se->task = GNUNET_SCHEDULER_add_now (&run_experiment_inbound, se);
			break;
		case STARTED:
			/* Experiment is running */
			GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Running %s experiment `%s' peer for `%s'\n",
					"inbound", GNUNET_i2s (&se->n->id), se->e->name);

			/* do work here */

			/* Reschedule */
			end = GNUNET_TIME_absolute_get_remaining(GNUNET_TIME_absolute_add (se->e->stop, se->e->frequency));
			if (0 == end.rel_value_us)
			{
				se->state = STOPPED;
				return;	/* End of experiment is reached */
			}
			/* Reschedule */
			se->task = GNUNET_SCHEDULER_add_delayed (se->e->frequency, &run_experiment_inbound, se);
			break;
		case STOPPED:
			/* Experiment expired */
			break;
		default:
			break;
	}

}

static void run_experiment_outbound (void *cls,const struct GNUNET_SCHEDULER_TaskContext* tc)
{
	struct ScheduledExperiment *se = cls;
	struct GNUNET_TIME_Relative end;

	se->task = GNUNET_SCHEDULER_NO_TASK;

	switch (se->state) {
		case NOT_RUNNING:
			/* Send START message */
			GED_nodes_send_start (se->n, se->e);
			se->state = REQUESTED;
			se->task = GNUNET_SCHEDULER_add_delayed (EXP_RESPONSE_TIMEOUT, &request_timeout, se);
			experiments_requested ++;
			GNUNET_STATISTICS_set (GED_stats, "# experiments requested", experiments_requested, GNUNET_NO);
			break;
		case REQUESTED:
			/* Expecting START_ACK */
			GNUNET_break (0);
			break;
		case STARTED:
			/* Experiment is running */
			GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Running %s experiment `%s' peer for `%s'\n",
					"outbound", GNUNET_i2s (&se->n->id), se->e->name);

			/* do work here */

			/* Reschedule */
			end = GNUNET_TIME_absolute_get_remaining(GNUNET_TIME_absolute_add (se->e->stop, se->e->frequency));
			if (0 == end.rel_value_us)
			{
				se->state = STOPPED;
				return;	/* End of experiment is reached */
			}
			/* Reschedule */
		se->task = GNUNET_SCHEDULER_add_delayed (se->e->frequency, &run_experiment_outbound, se);
			break;
		case STOPPED:
			/* Experiment expired */
			break;
		default:
			break;
	}
}


/**
 * Handle a START message from a remote node
 *
 * @param n the node
 * @param e the experiment
 */
void
GED_scheduler_handle_start (struct Node *n, struct Experiment *e)
{
  if ((NULL != find_experiment (waiting_in_head, waiting_in_tail, n, e, GNUNET_NO)) ||
      (NULL != find_experiment (running_in_head, running_in_tail, n, e, GNUNET_NO)))
  {
    GNUNET_break_op (0);
    return;
  }

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Received %s message from peer %s for experiment `%s'\n",
	      "START", GNUNET_i2s (&n->id), e->name);
  GED_scheduler_add (n, e, GNUNET_NO);
}


/**
 * Handle a START_ACK message from a remote node
 *
 * @param n the node
 * @param e the experiment
 */
void
GED_scheduler_handle_start_ack (struct Node *n, struct Experiment *e)
{
	struct ScheduledExperiment *se;

	if (NULL == (se = find_experiment (waiting_out_head, waiting_out_tail, n, e, GNUNET_YES)))
	{
		GNUNET_break (0);
		return;
	}

	GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Received %s message from peer %s for requested experiment `%s'\n",
			"START_ACK", GNUNET_i2s (&n->id), e->name);

	if (GNUNET_SCHEDULER_NO_TASK != se->task)
	{
		GNUNET_SCHEDULER_cancel (se->task); /* *Canceling timeout task */
		se->task = GNUNET_SCHEDULER_NO_TASK;
	}

	/* Remove from waiting list, add to running list */
	GNUNET_CONTAINER_DLL_remove (waiting_out_head, waiting_out_tail, se);
	GNUNET_CONTAINER_DLL_insert (running_out_head, running_out_tail, se);

	/* Change state and schedule to run */
	experiments_outbound_running ++;
	GNUNET_STATISTICS_set (GED_stats, "# experiments outbound running", experiments_outbound_running, GNUNET_NO);
	GNUNET_log (GNUNET_ERROR_TYPE_INFO, _("Starting outbound experiment `%s' with peer `%s'\n"),
			e->name, GNUNET_i2s (&n->id));
	se->state = STARTED;
	se->task = GNUNET_SCHEDULER_add_now (&run_experiment_outbound, se);
}


/**
 * Handle a STOP message from a remote node
 *
 * @param n the node
 * @param e the experiment
 */
void
GED_scheduler_handle_stop (struct Node *n, struct Experiment *e)
{
	struct ScheduledExperiment *se;

	GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, _("Received %s message from peer %s for experiment `%s'\n"),
			"STOP", GNUNET_i2s (&n->id), e->name);

	if (NULL != (se = find_experiment (waiting_in_head, waiting_in_tail, n, e, GNUNET_NO)))
	{
		GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Received %s message from peer %s for waiting experiment `%s'\n",
				"STOP", GNUNET_i2s (&n->id), e->name);
	}

	if (NULL != (se = find_experiment (running_in_head, running_in_tail, n, e, GNUNET_NO)))
	{
		GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Received %s message from peer %s for running experiment `%s'\n",
				"STOP", GNUNET_i2s (&n->id), e->name);
	}

}

/**
 * Add a new experiment for a node
 *
 * @param n the node
 * @param e the experiment
 * @param outbound are we initiator (GNUNET_YES) or client (GNUNET_NO)?
 */
void
GED_scheduler_add (struct Node *n, struct Experiment *e, int outbound)
{
	struct ScheduledExperiment *se;
	struct GNUNET_TIME_Relative start;
	struct GNUNET_TIME_Relative end;

	GNUNET_assert ((GNUNET_YES == outbound) || (GNUNET_NO == outbound));

	start = GNUNET_TIME_absolute_get_remaining(e->start);
	end = GNUNET_TIME_absolute_get_remaining(e->stop);
	if (0 == end.rel_value_us)
			return;	/* End of experiment is reached */

	/* Add additional checks here if required */
	se = GNUNET_malloc (sizeof (struct ScheduledExperiment));
	se->state = NOT_RUNNING;
	se->outbound = outbound;
	se->e = e;
	se->n = n;

	if (GNUNET_YES == outbound)
	{
	  if (0 == start.rel_value_us)
				se->task = GNUNET_SCHEDULER_add_now (&run_experiment_outbound, se);
		else
				se->task = GNUNET_SCHEDULER_add_delayed (start, &run_experiment_outbound, se);
		GNUNET_CONTAINER_DLL_insert (waiting_out_head, waiting_out_tail, se);
	}
	else
	{
		if (0 == start.rel_value_us)
				se->task = GNUNET_SCHEDULER_add_now (&run_experiment_inbound, se);
		else
				se->task = GNUNET_SCHEDULER_add_delayed (start, &run_experiment_inbound, se);
		GNUNET_CONTAINER_DLL_insert (waiting_in_head, waiting_in_tail, se);
	}

	GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Added %s experiment `%s' for node to be scheduled\n",
			(GNUNET_YES == outbound) ? "outbound" : "inbound", e->name, GNUNET_i2s(&se->n->id));
	experiments_scheduled ++;
	GNUNET_STATISTICS_set (GED_stats, "# experiments scheduled", experiments_scheduled, GNUNET_NO);

}

/**
 * Start the scheduler component
 */
void
GED_scheduler_start ()
{
	experiments_requested = 0;
	experiments_scheduled = 0;
}


/**
 * Stop the scheduler component
 */
void
GED_scheduler_stop ()
{
	struct ScheduledExperiment *cur;
	struct ScheduledExperiment *next;

	next = waiting_in_head;
	while (NULL != (cur = next))
	{
			next = cur->next;
			GNUNET_CONTAINER_DLL_remove (waiting_in_head, waiting_in_tail, cur);
			if (GNUNET_SCHEDULER_NO_TASK != cur->task)
			{
					GNUNET_SCHEDULER_cancel (cur->task);
					cur->task = GNUNET_SCHEDULER_NO_TASK;
			}
			GNUNET_free (cur);
			GNUNET_assert (experiments_scheduled > 0);
			experiments_scheduled --;
			GNUNET_STATISTICS_set (GED_stats, "# experiments scheduled", experiments_scheduled, GNUNET_NO);
	}

	next = running_in_head;
	while (NULL != (cur = next))
	{
			next = cur->next;
			GNUNET_CONTAINER_DLL_remove (running_in_head, running_in_tail, cur);
			if (GNUNET_SCHEDULER_NO_TASK != cur->task)
			{
					GNUNET_SCHEDULER_cancel (cur->task);
					cur->task = GNUNET_SCHEDULER_NO_TASK;
			}
			GNUNET_free (cur);
			GNUNET_assert (experiments_outbound_running > 0);
			experiments_inbound_running --;
			GNUNET_STATISTICS_set (GED_stats, "# experiments inbound running", experiments_inbound_running, GNUNET_NO);
	}

	next = waiting_out_head;
	while (NULL != (cur = next))
	{
			next = cur->next;
			GNUNET_CONTAINER_DLL_remove (waiting_out_head, waiting_out_tail, cur);
			if (GNUNET_SCHEDULER_NO_TASK != cur->task)
			{
					GNUNET_SCHEDULER_cancel (cur->task);
					cur->task = GNUNET_SCHEDULER_NO_TASK;
			}
			GNUNET_free (cur);
			GNUNET_assert (experiments_scheduled > 0);
			experiments_scheduled --;
			GNUNET_STATISTICS_set (GED_stats, "# experiments scheduled", experiments_scheduled, GNUNET_NO);
	}

	next = running_out_head;
	while (NULL != (cur = next))
	{
			next = cur->next;
			GNUNET_CONTAINER_DLL_remove (running_out_head, running_out_tail, cur);
			if (GNUNET_SCHEDULER_NO_TASK != cur->task)
			{
					GNUNET_SCHEDULER_cancel (cur->task);
					cur->task = GNUNET_SCHEDULER_NO_TASK;
			}
			GNUNET_free (cur);
			GNUNET_assert (experiments_outbound_running > 0);
			experiments_outbound_running --;
			GNUNET_STATISTICS_set (GED_stats, "# experiments outbound running", experiments_outbound_running, GNUNET_NO);
	}
}

/* end of gnunet-daemon-experimentation_scheduler.c */

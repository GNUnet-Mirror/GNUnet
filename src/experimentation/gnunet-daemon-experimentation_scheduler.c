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
#include "gnunet_getopt_lib.h"
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
	GNUNET_SCHEDULER_TaskIdentifier task;
};

struct ScheduledExperiment *waiting_head;
struct ScheduledExperiment *waiting_tail;

struct ScheduledExperiment *running_head;
struct ScheduledExperiment *running_tail;

static unsigned int experiments_scheduled;
static unsigned int experiments_running;
static unsigned int experiments_requested;

static void
request_timeout (void *cls,const struct GNUNET_SCHEDULER_TaskContext* tc)
{
	struct ScheduledExperiment *se = cls;
	se->task = GNUNET_SCHEDULER_NO_TASK;

	GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Peer `%s' did not respond to request for experiment `%s'\n",
			GNUNET_i2s (&se->n->id), se->e->name);

	GNUNET_CONTAINER_DLL_remove (waiting_head, waiting_tail, se);
	GNUNET_free (se);

	/* Remove experiment */

	GNUNET_assert (experiments_requested > 0);
	experiments_requested --;
	GNUNET_STATISTICS_set (GSE_stats, "# experiments requested", experiments_requested, GNUNET_NO);
}

static void start_experiment (void *cls,const struct GNUNET_SCHEDULER_TaskContext* tc)
{
	struct ScheduledExperiment *se = cls;
	struct GNUNET_TIME_Relative end;
	struct GNUNET_TIME_Relative backoff;

	se->task = GNUNET_SCHEDULER_NO_TASK;

	if (GNUNET_NO == GED_nodes_rts (se->n))
	{
		se->state = BUSY;
		backoff = GNUNET_TIME_UNIT_SECONDS;
		backoff.rel_value += GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK, 1000);
		GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Delaying start request to peer `%s' for `%s' for %llu ms\n",
				GNUNET_i2s (&se->n->id), se->e->name, (unsigned long long) backoff.rel_value);
		se->task = GNUNET_SCHEDULER_add_delayed (backoff, &start_experiment, se);
		return;
	}
	else if (BUSY == se->state)
		se->state = NOT_RUNNING;

	if (NOT_RUNNING == se->state)
	{
			/* Send start message */
			GED_nodes_request_start (se->n, se->e);
			se->state = REQUESTED;
			se->task = GNUNET_SCHEDULER_add_delayed (EXP_RESPONSE_TIMEOUT, &request_timeout, se);

			GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Sending start request to peer `%s' for `%s'\n",
					GNUNET_i2s (&se->n->id), se->e->name);
			experiments_requested ++;
			GNUNET_STATISTICS_set (GSE_stats, "# experiments requested", experiments_requested, GNUNET_NO);
			return;
	}
	else if (REQUESTED == se->state)
	{
			/* Already requested */
			return;
	}
	else if (STARTED == se->state)
	{
			/* Experiment is running */
			GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Running experiment `%s' peer for `%s'\n",
					GNUNET_i2s (&se->n->id), se->e->name);

			/* do work here */

			/* Reschedule */
			end = GNUNET_TIME_absolute_get_remaining(GNUNET_TIME_absolute_add (se->e->stop, se->e->frequency));
			if (0 == end.rel_value)
			{
				se->state = STOPPED;
				return;	/* End of experiment is reached */
			}
			/* Reschedule */
		se->task = GNUNET_SCHEDULER_add_delayed (se->e->frequency, &start_experiment, se);
	}

	else if (STOPPED == se->state)
	{
			/* Experiment expired */
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

}

/**
 * Handle a START_ACL message from a remote node
 *
 * @param n the node
 * @param e the experiment
 */
void
GED_scheduler_handle_start_ack (struct Node *n, struct Experiment *e)
{

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

}

/**
 * Add a new experiment for a node
 *
 * @param n the node
 * @param e the experiment
 */
void
GED_scheduler_add (struct Node *n, struct Experiment *e)
{
	struct ScheduledExperiment *se;
	struct GNUNET_TIME_Relative start;
	struct GNUNET_TIME_Relative end;

	start = GNUNET_TIME_absolute_get_remaining(e->start);
	end = GNUNET_TIME_absolute_get_remaining(e->stop);
	if (0 == end.rel_value)
			return;	/* End of experiment is reached */

	/* Add additional checks here if required */

	se = GNUNET_malloc (sizeof (struct ScheduledExperiment));
	se->state = NOT_RUNNING;
	se->e = e;
	se->n = n;
	if (0 == start.rel_value)
			se->task = GNUNET_SCHEDULER_add_now (&start_experiment, se);
	else
			se->task = GNUNET_SCHEDULER_add_delayed (start, &start_experiment, se);

	GNUNET_CONTAINER_DLL_insert (waiting_head, waiting_tail, se);
	GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Added experiment `%s' for node to be scheduled\n",
			e->name, GNUNET_i2s(&se->n->id));
	experiments_scheduled ++;
	GNUNET_STATISTICS_set (GSE_stats, "# experiments scheduled", experiments_scheduled, GNUNET_NO);
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

	next = waiting_head;
	while (NULL != (cur = next))
	{
			next = cur->next;
			GNUNET_CONTAINER_DLL_remove (waiting_head, waiting_tail, cur);
			if (GNUNET_SCHEDULER_NO_TASK != cur->task)
			{
					GNUNET_SCHEDULER_cancel (cur->task);
					cur->task = GNUNET_SCHEDULER_NO_TASK;
			}
			GNUNET_free (cur);
			GNUNET_assert (experiments_scheduled > 0);
			experiments_scheduled --;
			GNUNET_STATISTICS_set (GSE_stats, "# experiments scheduled", experiments_scheduled, GNUNET_NO);
	}

	next = running_head;
	while (NULL != (cur = next))
	{
			next = cur->next;
			GNUNET_CONTAINER_DLL_remove (running_head, running_tail, cur);
			if (GNUNET_SCHEDULER_NO_TASK != cur->task)
			{
					GNUNET_SCHEDULER_cancel (cur->task);
					cur->task = GNUNET_SCHEDULER_NO_TASK;
			}
			GNUNET_free (cur);
			GNUNET_assert (experiments_running > 0);
			experiments_running --;
			GNUNET_STATISTICS_set (GSE_stats, "# experiments running", experiments_running, GNUNET_NO);
	}
}

/* end of gnunet-daemon-experimentation_scheduler.c */

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

struct ScheduledExperiment {
	struct ScheduledExperiment *next;
	struct ScheduledExperiment *prev;

	struct Experiment *e;
	GNUNET_SCHEDULER_TaskIdentifier task;
};

struct ScheduledExperiment *list_head;
struct ScheduledExperiment *list_tail;


static void run (void *cls,const struct GNUNET_SCHEDULER_TaskContext* tc)
{
	struct ScheduledExperiment *se = cls;
	//struct GNUNET_TIME_Relative end;
	se->task = GNUNET_SCHEDULER_NO_TASK;

	GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Running `%s'\n", se->e->name);

//	end = GNUNET_TIME_absolute_get_remaining(se->e->stop);
//	if (0 < end.rel_value)
//			return;	/* End of experiment is reached */

//GNUNET_break (0);
	se->task = GNUNET_SCHEDULER_add_delayed (se->e->frequency, &run, se);
}

/**
 * Start the scheduler component
 */
void
GNUNET_EXPERIMENTATION_scheduler_add (struct Experiment *e)
{
	struct ScheduledExperiment *se;
	struct GNUNET_TIME_Relative start;
	struct GNUNET_TIME_Relative end;

	start = GNUNET_TIME_absolute_get_remaining(e->start);
	end = GNUNET_TIME_absolute_get_remaining(e->stop);

	if (0 == end.rel_value)
			return;	/* End of experiment is reached */

	se = GNUNET_malloc (sizeof (struct ScheduledExperiment));
	se->e = e;
	if (0 == start.rel_value)
			se->task = GNUNET_SCHEDULER_add_now (&run, se);
	else
			se->task = GNUNET_SCHEDULER_add_delayed (start, &run, se);

	GNUNET_CONTAINER_DLL_insert (list_head, list_tail, se);
	GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Scheduled `%s'\n", e->name);
}

/**
 * Start the scheduler component
 */
void
GNUNET_EXPERIMENTATION_scheduler_start ()
{

}


/**
 * Stop the scheduler component
 */
void
GNUNET_EXPERIMENTATION_scheduler_stop ()
{
	struct ScheduledExperiment *cur;
	struct ScheduledExperiment *next;

	next = list_head;
	while (NULL != (cur = next))
	{
			next = cur->next;
			GNUNET_CONTAINER_DLL_remove (list_head, list_tail, cur);
			if (GNUNET_SCHEDULER_NO_TASK != cur->task)
			{
					GNUNET_SCHEDULER_cancel (cur->task);
					cur->task = GNUNET_SCHEDULER_NO_TASK;
			}
			GNUNET_free (cur);
	}
}

/* end of gnunet-daemon-experimentation_scheduler.c */

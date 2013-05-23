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
 * @file experimentation/gnunet-daemon-experimentation.c
 * @brief experimentation daemon
 * @author Christian Grothoff
 * @author Matthias Wachs
 */
#include "platform.h"
#include "gnunet_getopt_lib.h"
#include "gnunet_util_lib.h"
#include "gnunet_core_service.h"
#include "gnunet_statistics_service.h"

#define EXP_RESPONSE_TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 10)
/**
 * A experimentation node
 */
struct Node
{
	struct GNUNET_PeerIdentity id;

	GNUNET_SCHEDULER_TaskIdentifier timeout_task;

	struct GNUNET_CORE_TransmitHandle *cth;
};


struct Experimentation_Request
{
	struct GNUNET_MessageHeader msg;
};

struct Experimentation_Response
{
	struct GNUNET_MessageHeader msg;
};


/**
 * The main function for the experimentation daemon.
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 */
void
GNUNET_EXPERIMENTATION_nodes_start (const struct GNUNET_CONFIGURATION_Handle *cfg);

void
GNUNET_EXPERIMENTATION_nodes_stop ();

/* end of gnunet-daemon-experimentation.c */

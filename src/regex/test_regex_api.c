/*
     This file is part of GNUnet.
     (C) 2013 Christian Grothoff (and other contributing authors)

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
 * @file regex/test_regex_api.c
 * @brief base test case for regex api (and DHT functions)
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_testing_lib.h"
#include "gnunet_regex_service.h"


/**
 * How long until we really give up on a particular testcase portion?
 */
#define TOTAL_TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 600)

/**
 * How long until we give up on any particular operation (and retry)?
 */
#define BASE_TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 3)


static struct GNUNET_REGEX_Announcement *a;

static struct GNUNET_REGEX_Search *s;

static int ok = 1;

static struct GNUNET_SCHEDULER_Task * die_task;


static void
end (void *cls,
     const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  die_task = NULL;
  GNUNET_REGEX_announce_cancel (a);
  a = NULL;
  GNUNET_REGEX_search_cancel (s);
  s = NULL;
  ok = 0;
}


static void
end_badly ()
{
  die_task = NULL;
  FPRINTF (stderr, "%s",  "Testcase failed (timeout).\n");
  GNUNET_REGEX_announce_cancel (a);
  a = NULL;
  GNUNET_REGEX_search_cancel (s);
  s = NULL;
  ok = 1;
}


/**
 * Search callback function, invoked for every result that was found.
 *
 * @param cls Closure provided in GNUNET_REGEX_search.
 * @param id Peer providing a regex that matches the string.
 * @param get_path Path of the get request.
 * @param get_path_length Lenght of get_path.
 * @param put_path Path of the put request.
 * @param put_path_length Length of the put_path.
 */
static void
found_cb (void *cls,
	  const struct GNUNET_PeerIdentity *id,
	  const struct GNUNET_PeerIdentity *get_path,
	  unsigned int get_path_length,
	  const struct GNUNET_PeerIdentity *put_path,
	  unsigned int put_path_length)
{
  GNUNET_SCHEDULER_cancel (die_task);
  die_task =
    GNUNET_SCHEDULER_add_now (&end, NULL);
}


static void
run (void *cls,
     const struct GNUNET_CONFIGURATION_Handle *cfg,
     struct GNUNET_TESTING_Peer *peer)
{
  die_task =
    GNUNET_SCHEDULER_add_delayed (TOTAL_TIMEOUT,
				  &end_badly, NULL);
  a = GNUNET_REGEX_announce (cfg,
			     "my long prefix - hello world(0|1)*",
			     GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS,
							    5),
			     1);
  s = GNUNET_REGEX_search (cfg,
			   "my long prefix - hello world0101",
			   &found_cb, NULL);
}


int
main (int argc, char *argv[])
{
  if (0 != GNUNET_TESTING_peer_run ("test-regex-api",
				    "test_regex_api_data.conf",
				    &run, NULL))
    return 1;
  return ok;
}

/* end of test_regex_api.c */

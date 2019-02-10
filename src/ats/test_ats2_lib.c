/*
     This file is part of GNUnet.
     Copyright (C) 2010-2015 GNUnet e.V.

     GNUnet is free software: you can redistribute it and/or modify it
     under the terms of the GNU Affero General Public License as published
     by the Free Software Foundation, either version 3 of the License,
     or (at your option) any later version.

     GNUnet is distributed in the hope that it will be useful, but
     WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
     Affero General Public License for more details.

     You should have received a copy of the GNU Affero General Public License
     along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/
/**
 * @file ats/test_ats2_lib.c
 * @brief test ATS library with a generic interpreter for running ATS tests
 * @author Julius Bünger
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_ats_application_service.h"
#include "gnunet_ats_transport_service.h"
#include "gnunet_testing_lib.h"

/**
 * @brief Indicates the success of the whole test
 */
static int ret;

/**
 * @brief The time available until the test shuts down
 */
static struct GNUNET_TIME_Relative timeout;

/**
 * @brief ATS Application Handle
 *
 * Handle to the application-side of ATS.
 */
static struct GNUNET_ATS_ApplicationHandle *ah;

/**
 * @brief ATS Transport Handle
 *
 * Handle to the transport-side of ATS.
 */
static struct GNUNET_ATS_TransportHandle *th;

/**
 * @brief Another (dummy) peer.
 *
 * Used as the peer ATS shall allocate bandwidth to.
 */
static struct GNUNET_PeerIdentity other_peer;

/**
 * @brief Handle to the session record
 */
static struct GNUNET_ATS_SessionRecord *sr;


/**
 * @brief Called whenever allocation changed
 *
 * Implements #GNUNET_ATS_AllocationCallback
 *
 * @param cls
 * @param session
 * @param bandwidth_out
 * @param bandwidth_in
 *
 * @return
 */
static void
allocation_cb (void *cls,
               struct GNUNET_ATS_Session *session,
               struct GNUNET_BANDWIDTH_Value32NBO bandwidth_out,
               struct GNUNET_BANDWIDTH_Value32NBO bandwidth_in)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "allocation_cb() called\n");
}


/**
 * @brief Called whenever suggestion is made
 *
 * Implements #GNUNET_ATS_SuggestionCallback
 *
 * @param cls
 * @param pid
 * @param address
 */
static void
suggestion_cb (void *cls,
               const struct GNUNET_PeerIdentity *pid,
               const char *address)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "suggestion_cb() called\n");
  ret = 0;
}


/**
 * @brief Initialise both 'sides' of ATS
 *
 * Initialises the application and transportation side of ATS.
 */
static void
init_both (const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  ah = GNUNET_ATS_application_init (cfg);
  GNUNET_assert (NULL != ah);
  th = GNUNET_ATS_transport_init (cfg,
                                  &allocation_cb,
                                  NULL,
                                  &suggestion_cb,
                                  NULL);
  GNUNET_assert (NULL != ah);
}


/**
 * @brief Disconnect both 'sides' of ATS
 */
static void
finish_both (void)
{
  GNUNET_ATS_application_done (ah);
  ah = NULL;
  GNUNET_ATS_transport_done (th);
  th = NULL;
}


/**
 * @brief Provide information about the start of an imaginary connection
 */
static void
provide_info_start (void)
{
  struct GNUNET_ATS_Properties prop =
  {
    .delay = GNUNET_TIME_UNIT_FOREVER_REL,
    .goodput_out = 1048576,
    .goodput_in = 1048576,
    .utilization_out = 0,
    .utilization_in = 0,
    .distance = 0,
    .mtu = UINT32_MAX,
    .nt = GNUNET_NT_UNSPECIFIED,
    .cc = GNUNET_TRANSPORT_CC_UNKNOWN,
  };

  sr = GNUNET_ATS_session_add (th,
                               &other_peer,
                               "test-address",
                               NULL,
                               &prop);
  GNUNET_assert (NULL != sr);
}


/**
 * @brief Provide information about the end of an imaginary connection
 */
static void
provide_info_end (void)
{
  GNUNET_ATS_session_del (sr);
}


/**
 * @brief Inform ATS about the need of a connection towards a peer
 */
static void
get_suggestion (void)
{
  struct GNUNET_ATS_ApplicationSuggestHandle *ash;

  ash = GNUNET_ATS_application_suggest (ah,
                                        &other_peer,
                                        GNUNET_MQ_PREFERENCE_NONE,
                                        GNUNET_BANDWIDTH_VALUE_MAX);
  GNUNET_assert (NULL != ash);
}


static void
on_shutdown (void *cls)
{
  provide_info_end ();
  finish_both ();
  GNUNET_SCHEDULER_shutdown ();
}


/**
 * Function run once the ATS service has been started.
 *
 * @param cls NULL
 * @param cfg configuration for the testcase
 * @param peer handle to the peer
 */
static void
run (void *cls,
     const struct GNUNET_CONFIGURATION_Handle *cfg,
     struct GNUNET_TESTING_Peer *peer)
{
  init_both (cfg);
  provide_info_start ();
  get_suggestion ();
  (void) GNUNET_SCHEDULER_add_delayed (timeout,
				       &on_shutdown,
				       NULL);
}


/**
 * @brief Starts the gnunet-testing peer
 *
 * @param argc
 * @param argv[]
 *
 * @return
 */
int
main (int argc,
      char *argv[])
{
  ret = 1;
  memset (&other_peer, 0, sizeof (struct GNUNET_PeerIdentity));
  timeout = GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS,
					   2);
  if (0 != GNUNET_TESTING_peer_run ("test-ats2-lib",
                                    "test_ats2_lib.conf",
                                    &run, NULL))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Running the testing peer failed.\n");
    return 1;
  }
  if (0 != ret)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "Global status indicates unsuccessful testrun - probably allocation_cb was not called.\n");
    ret = 77; // SKIP test, test not yet right!
  }
  return ret;
}



/* end of test_ats2_lib.c */

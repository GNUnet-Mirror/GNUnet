/*
     This file is part of GNUnet.
     (C) 2009, 2010 Christian Grothoff (and other contributing authors)

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
 * @file transport/test_transport_api.c
 * @brief base test case for transport implementations
 *
 * This test case serves as a base for tcp, udp, and udp-nat
 * transport test cases.  Based on the executable being run
 * the correct test case will be performed.  Conservation of
 * C code apparently.
 */
#include "platform.h"
#include "gnunet_common.h"
#include "gnunet_hello_lib.h"
#include "gnunet_getopt_lib.h"
#include "gnunet_os_lib.h"
#include "gnunet_program_lib.h"
#include "gnunet_scheduler_lib.h"
#include "gnunet_transport_service.h"
#include "transport.h"
#include "transport-testing.h"

#define VERBOSE GNUNET_NO

#define VERBOSE_ARM GNUNET_NO

#define START_ARM GNUNET_YES

/**
 * How long until we give up on transmitting the message?
 */
#define TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 30)

static struct PeerContext * p;

static void
notify_connect (void *cls,
                const struct GNUNET_PeerIdentity *peer,
                const struct GNUNET_TRANSPORT_ATS_Information *ats,
                uint32_t ats_count)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Peer `%s' connected \n",
       GNUNET_i2s (peer));
}

static void
notify_disconnect (void *cls, const struct GNUNET_PeerIdentity *peer)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Peer `%s' disconnected \n",
       GNUNET_i2s (peer));
}

static void
notify_receive (void *cls,
                const struct GNUNET_PeerIdentity *peer,
                const struct GNUNET_MessageHeader *message,
                const struct GNUNET_TRANSPORT_ATS_Information *ats,
                uint32_t ats_count)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Receiving\n");
}


static void
run (void *cls,
     char *const *args,
     const char *cfgfile, const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Starting peer\n");
  p = GNUNET_TRANSPORT_TESTING_start_peer("test_quota_compliance_tcp_peer1.conf");

  if (p != NULL)
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Peer was successfully started\n");
  else
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Peer was not started successfully\n");
  GNUNET_assert (p != NULL);


  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "\tConnecting to transport service\n");
  GNUNET_assert (p->th == NULL);
  p->th = GNUNET_TRANSPORT_connect(p->cfg, NULL,
                            NULL,
                            &notify_receive,
                            &notify_connect,
                            &notify_disconnect);
  GNUNET_assert (p->th != NULL);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "\tDisconnecting to transport service\n");
  GNUNET_TRANSPORT_disconnect(p->th);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Stopping peer\n");
  GNUNET_TRANSPORT_TESTING_stop_peer(p);

  GNUNET_free (p);
}

int
main (int argc, char *argv[])
{
  int ret = 0;

  GNUNET_log_setup ("test_transport_testing",
#if VERBOSE
                    "DEBUG",
#else
                    "WARNING",
#endif
                    NULL);

  char *const argv_1[] = { "test_transport_testing",
    "-c",
    "test_transport_api_data.conf",
#if VERBOSE
    "-L", "DEBUG",
#endif
    NULL
  };

  struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_OPTION_END
  };

  GNUNET_PROGRAM_run ((sizeof (argv_1) / sizeof (char *)) - 1,
                      argv_1, "test_transport_testing", "nohelp",
                      options, &run, &ret);

  return ret;
}

/* end of test_transport_api.c */

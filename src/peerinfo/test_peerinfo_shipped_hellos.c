/*
     This file is part of GNUnet.
     Copyright (C) 2004, 2009 GNUnet e.V.

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

     SPDX-License-Identifier: AGPL3.0-or-later
 */

/**
 * @file peerinfo/test_peerinfo_shipped_hellos.c
 * @brief testcase for shipped HELLOs getting parsed
 * @author Christian Grothoff
 * @author Matthias Wachs
 *
 */
#include "platform.h"
#include "gnunet_hello_lib.h"
#include "gnunet_util_lib.h"
#include "gnunet_peerinfo_service.h"
#include "gnunet_testing_lib.h"
#include "peerinfo.h"

static struct GNUNET_PEERINFO_IteratorContext *ic;

static struct GNUNET_PEERINFO_Handle *h;

static int global_ret;


static int
addr_cb(void *cls,
        const struct GNUNET_HELLO_Address *address,
        struct GNUNET_TIME_Absolute expiration)
{
  unsigned int *addr = cls;

  (*addr)++;
  return GNUNET_OK;
}


static void
process(void *cls,
        const struct GNUNET_PeerIdentity *peer,
        const struct GNUNET_HELLO_Message *hello,
        const char *err_msg)
{
  static unsigned int calls = 0;
  unsigned int addr;

  if (NULL != err_msg)
    {
      GNUNET_log(GNUNET_ERROR_TYPE_ERROR,
                 "Error in communication with PEERINFO service: %s\n",
                 err_msg);
    }
  if (NULL != peer)
    {
      addr = 0;
      if (NULL != hello)
        {
          GNUNET_HELLO_iterate_addresses(hello,
                                         GNUNET_NO,
                                         &addr_cb,
                                         &addr);
          GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
                     "Got information about peer %s with %u addresses\n",
                     GNUNET_i2s(peer),
                     addr);
          calls++;
        }
      else
        {
          GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
                     "Got no HELLP for peer %s\n",
                     GNUNET_i2s(peer));
        }
    }
  else
    {
      if (0 == calls)
        {
          fprintf(stderr,
                  "Failed: got no callbacks!\n");
          global_ret = 1;
          GNUNET_PEERINFO_disconnect(h);
          h = NULL;
        }
      else
        {
          GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
                     "Got %u HELLOs in total\n",
                     calls);
          global_ret = 0;
          GNUNET_PEERINFO_disconnect(h);
          h = NULL;
        }
    }
}


static void
run(void *cls,
    const struct GNUNET_CONFIGURATION_Handle *cfg,
    struct GNUNET_TESTING_Peer *peer)
{
  h = GNUNET_PEERINFO_connect(cfg);
  GNUNET_assert(NULL != h);
  ic = GNUNET_PEERINFO_iterate(h,
                               GNUNET_YES,
                               NULL,
                               &process,
                               cls);
  GNUNET_assert(NULL != ic);
}


int
main(int argc,
     char *argv[])
{
  global_ret = 3;
  if (0 != GNUNET_TESTING_service_run("test_peerinfo_shipped_hellos",
                                      "peerinfo",
                                      "test_peerinfo_api_data.conf",
                                      &run, NULL))
    return 1;
  return global_ret;
}

/* end of test_peerinfo_shipped_hellos.c */

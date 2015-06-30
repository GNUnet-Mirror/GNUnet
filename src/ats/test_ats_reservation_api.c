/*
     This file is part of GNUnet.
     Copyright (C) 2010-2015 Christian Grothoff (and other contributing authors)

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
     Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
     Boston, MA 02110-1301, USA.
*/
/**
 * @file ats/test_ats_reservation_api.c
 * @brief test ATS bandwidth reservation API
 * @author Christian Grothoff
 */
#include "platform.h"
#include "test_ats_lib.h"

/**
 * Global timeout for the testcase.
 */
#define TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 15)

/**
 * Definition of the test as a sequence of commands.
 */
static struct Command test_commands[] = {
  /* 0: add initial address */
  {
    .code = CMD_ADD_ADDRESS,
    .label = "add-address-0-0",
    .details.add_address = {
      .pid = 0,
      .addr_num = 0,
      .session = 0,
      .properties = {
        /* use network with 65k quota! */
        .scope = GNUNET_ATS_NET_WAN
      }
    }
  },
  /* 1: some solver still require explicit start */
  {
    .code = CMD_REQUEST_CONNECTION_START,
    .label = "request-0",
    .details.request_connection_start = {
      .pid = 0
    }
  },
  /* 2: check we got an address */
  {
    .code = CMD_AWAIT_ADDRESS_SUGGESTION,
    .details.await_address_suggestion = {
      .add_label = "add-address-0-0"
    }
  },
  /* 3: sleep 7s, should give us 5s * 64k/s = 320k buffer;
     Note that this depends on MAX_BANDWIDTH_CARRY_S.  We
     sleep more than 5s to show that only MAX_BANDWIDTH carries. */
  {
    .code = CMD_SLEEP,
    .label = "sleep",
    .details.sleep.delay = { 7 * 1000LL * 1000LL }
  },
  /* 4: reserve 128k -- should work (5s carry, so we had 320k) */
  {
    .code = CMD_RESERVE_BANDWIDTH,
    .details.reserve_bandwidth = {
      .pid = 0,
      .amount = 128 * 1024,
      .expected_result = GNUNET_YES
    }
  },
  /* 5: reserve another 192k -- should just work (now exactly pushing the limit) */
  {
    .code = CMD_RESERVE_BANDWIDTH,
    .label = "big reservation",
    .details.reserve_bandwidth = {
      .pid = 0,
      .amount = 192 * 1024,
      .expected_result = GNUNET_YES
    }
  },
  /* 6: reserve another 32k -- should now fail (if MAX_BANDWIDTH_CARRY_S
     is precisely observed) */
  {
    .code = CMD_RESERVE_BANDWIDTH,
    .label = "failing reservation",
    .details.reserve_bandwidth = {
      .pid = 0,
      .amount = 32 * 1024,
      .expected_result = GNUNET_SYSERR
    }
  },
  /* 7: sleep 3s, should give us 3s * 64k/s - 32k = 160k buffer */
  {
    .code = CMD_SLEEP,
    .label = "sleep",
    .details.sleep.delay = { 6 * 1000LL * 1000LL }
  },
  /* 8: reserve another 160k -- should now work */
  {
    .code = CMD_RESERVE_BANDWIDTH,
    .label = "successful final reservation",
    .details.reserve_bandwidth = {
      .pid = 0,
      .amount = 160 * 1024,
      .expected_result = GNUNET_YES
    }
  },
  /* 9: remove address */
  {
    .code = CMD_DEL_ADDRESS,
    .details.del_address = {
      .add_label = "add-address-0-0"
    }
  },
  /* 10: check we got disconnected */
  {
    .code = CMD_AWAIT_DISCONNECT_SUGGESTION,
    .details.await_disconnect_suggestion = {
      .pid = 0
    }
  },
  /* 11: just for symmetry, also stop asking for the connection */
  {
    .code = CMD_REQUEST_CONNECTION_STOP,
    .details.request_connection_stop = {
      .connect_label = "request-0",
    }
  },
  /* Test ends successfully */
  {
    .code = CMD_END_PASS
  }
};


int
main (int argc,
      char *argv[])
{
  return TEST_ATS_run (argc,
                       argv,
                       test_commands,
                       TIMEOUT);
}


/* end of file test_ats_reservation_api.c */

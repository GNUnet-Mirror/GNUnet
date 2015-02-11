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
     Free Software Foundation, Inc., 59 Temple Place - Suite 330,
     Boston, MA 02111-1307, USA.
*/
/**
 * @file ats/test_ats_reservation_api.c
 * @brief test ATS
 * @author Christian Grothoff
 */
#include "platform.h"
#include "test_ats_lib.h"

/**
 * Global timeout for the testcase.
 */
#define TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 3)

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
  /* 3: reserve 32k -- should work */
  {
    .code = CMD_RESERVE_BANDWIDTH,
    .label = "initial reservation",
    .details.reserve_bandwidth = {
      .pid = 0,
      .amount = 32 * 1024,
      .expected_result = GNUNET_OK
    }
  },
  /* 4: reserve another 32k -- might work */
  {
    .code = CMD_RESERVE_BANDWIDTH,
    .details.reserve_bandwidth = {
      .pid = 0,
      .amount = 32 * 1024,
      .expected_result = GNUNET_NO
    }
  },
  /* 5: reserve another 128k -- might work */
  {
    .code = CMD_RESERVE_BANDWIDTH,
    .label = "big reservation",
    .details.reserve_bandwidth = {
      .pid = 0,
      .amount = 128 * 1024,
      .expected_result = GNUNET_NO
    }
  },
  /* 6: reserve another 32k -- should now fail */
  {
    .code = CMD_RESERVE_BANDWIDTH,
    .label = "failing reservation",
    .details.reserve_bandwidth = {
      .pid = 0,
      .amount = 32 * 1024,
      .expected_result = GNUNET_SYSERR
    }
  },
  /* 7: remove address */
  {
    .code = CMD_DEL_ADDRESS,
    .details.del_address = {
      .add_label = "add-address-0-0"
    }
  },
  /* 8: check we got disconnected */
  {
    .code = CMD_AWAIT_DISCONNECT_SUGGESTION,
    .details.await_disconnect_suggestion = {
      .pid = 0
    }
  },
  /* 9: just for symmetry, also stop asking for the connection */
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

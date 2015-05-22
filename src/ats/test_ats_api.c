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
 * @file ats/test_ats_api.c
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
  {
    .code = CMD_ADD_ADDRESS,
    .label = "add-address-0-0",
    .details.add_address = {
      .pid = 0,
      .addr_num = 0,
      .addr_flags = GNUNET_HELLO_ADDRESS_INFO_NONE,
      .session = 0,
      .properties = {
        .scope = GNUNET_ATS_NET_LAN
      }
    }
  },
  /* 1: adding same address again should fail */
  {
    .code = CMD_ADD_ADDRESS,
    .label = "add-address-0-0:FAIL",
    .details.add_address = {
      .pid = 0,
      .addr_num = 0,
      .addr_flags = GNUNET_HELLO_ADDRESS_INFO_NONE,
      .session = 0,
      .properties = {
        .scope = GNUNET_ATS_NET_LAN
      },
      .expect_fail = 1
    }
  },
  /* 2: some solver still require explicit start */
  {
    .code = CMD_REQUEST_CONNECTION_START,
    .label = "request-0",
    .details.request_connection_start = {
      .pid = 0
    }
  },
  /* 3: check we got an address */
  {
    .code = CMD_AWAIT_ADDRESS_SUGGESTION,
    .details.await_address_suggestion = {
      .add_label = "add-address-0-0"
    }
  },
  /* 4: check monitor also got the address */
  {
    .code = CMD_AWAIT_ADDRESS_INFORMATION,
    .details.await_address_information = {
      .add_label = "add-address-0-0"
    }
  },
  /* 5: test session API */
  {
    .code = CMD_ADD_SESSION,
    .label = "add-session-0-0-1",
    .details.add_session = {
      .add_label ="add-address-0-0",
      .session = 1
    }
  },
  {
    .code = CMD_DEL_SESSION,
    .details.del_session = {
      .add_session_label = "add-session-0-0-1",
    }
  },
  /* 7: test preference API */
  {
    .code = CMD_CHANGE_PREFERENCE,
    .details.change_preference = {
      .pid = 0
      /* FIXME: preference details */
    }
  },
  {
    .code = CMD_PROVIDE_FEEDBACK,
    .details.provide_feedback = {
      .pid = 0,
      .scope = { 50LL }
      /* FIXME: preference details */
    }
  },
  /* 9: test sanity check address listing */
  {
    .code = CMD_LIST_ADDRESSES,
    .details.list_addresses = {
      .pid = 0,
      .all = 1,
      .min_calls = 2, // ?
      .max_calls = 2,
      .min_active_calls = 1,
      .max_active_calls = 1
    }
  },
  /* 10: remove address testing */
  {
    .code = CMD_DEL_ADDRESS,
    .details.del_address = {
      .add_label = "add-address-0-0"
    }
  },
  /* 11: check we got disconnected */
  {
    .code = CMD_AWAIT_DISCONNECT_SUGGESTION,
    .details.await_disconnect_suggestion = {
      .pid = 0
    }
  },
  /* 12: just for symmetry, also stop asking for the connection */
  {
    .code = CMD_REQUEST_CONNECTION_STOP,
    .details.request_connection_stop = {
      .connect_label = "request-0",
    }
  },
  /* 13: add address again */
  {
    .code = CMD_ADD_ADDRESS,
    .label = "add-address-0-0:1",
    .details.add_address = {
      .pid = 0,
      .addr_num = 0,
      .session = 0,
      .properties = {
        .scope = GNUNET_ATS_NET_LAN
      }
    }
  },
  /* 14: some solver still require explicit start */
  {
    .code = CMD_REQUEST_CONNECTION_START,
    .label = "request-0",
    .details.request_connection_start = {
      .pid = 0
    }
  },
  /* 15: check we got an address */
  {
    .code = CMD_AWAIT_ADDRESS_SUGGESTION,
    .details.await_address_suggestion = {
      .add_label = "add-address-0-0:1"
    }
  },
  /* 16: add alternative address */
  {
    .code = CMD_ADD_ADDRESS,
    .label = "add-address-0-1",
    .details.add_address = {
      .pid = 0,
      .addr_num = 1,
      .addr_flags = GNUNET_HELLO_ADDRESS_INFO_NONE,
      .session = 0,
      .properties = {
        .scope = GNUNET_ATS_NET_LAN
      }
    }
  },
  /* 17: remove original address */
  {
    .code = CMD_DEL_ADDRESS,
    .details.del_address = {
      .add_label = "add-address-0-0:1"
    }
  },
  /* 18: check we switched to alternative address */
  {
    .code = CMD_AWAIT_ADDRESS_SUGGESTION,
    .details.await_address_suggestion = {
      .add_label = "add-address-0-1"
    }
  },
  /* 19: remove alternative address */
  {
    .code = CMD_DEL_ADDRESS,
    .details.del_address = {
      .add_label = "add-address-0-1"
    }
  },
  /* 20: check we got disconnected */
  {
    .code = CMD_AWAIT_DISCONNECT_SUGGESTION,
    .details.await_disconnect_suggestion = {
      .pid = 0
    }
  },
  /* 21: just for symmetry, also stop asking for the connection */
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


/* end of file test_ats_api.c */

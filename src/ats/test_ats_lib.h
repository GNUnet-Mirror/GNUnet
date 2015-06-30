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
 * @file ats/test_ats_lib.h
 * @brief test ATS library with a generic interpreter for running ATS tests
 * @author Christian Grothoff
 */
#ifndef TEST_ATS_LIB_H
#define TEST_ATS_LIB_H

#include "gnunet_util_lib.h"
#include "gnunet_ats_service.h"
#include "gnunet_testing_lib.h"


/**
 * Commands for the interpreter.
 */
enum CommandCode
{
  /**
   * End the test (passing).
   */
  CMD_END_PASS = 0,

  /**
   * Call #GNUNET_ATS_address_add().
   */
  CMD_ADD_ADDRESS,

  /**
   * Call #GNUNET_ATS_address_del().
   */
  CMD_DEL_ADDRESS,

  /**
   * Wait for ATS to suggest address.
   */
  CMD_AWAIT_ADDRESS_SUGGESTION,

  /**
   * Wait for ATS to suggest disconnect.
   */
  CMD_AWAIT_DISCONNECT_SUGGESTION,

  /**
   * Ask ATS to connect to a peer, using
   * #GNUNET_ATS_connectivity_suggest().
   */
  CMD_REQUEST_CONNECTION_START,

  /**
   * Tell ATS we no longer need a connection to a peer, using
   * #GNUNET_ATS_connectivity_suggest_cancel().
   */
  CMD_REQUEST_CONNECTION_STOP,

  /**
   * Wait for certain address information to be provided.
   */
  CMD_AWAIT_ADDRESS_INFORMATION,

  /**
   * Update properties of an address, using
   * #GNUNET_ATS_address_update().
   */
  CMD_UPDATE_ADDRESS,

  /**
   * Add session to an address, using
   * #GNUNET_ATS_address_add_session().
   */
  CMD_ADD_SESSION,

  /**
   * Remove session from an address, using
   * #GNUNET_ATS_address_del_session().
   */
  CMD_DEL_SESSION,

  /**
   * Change performance preferences for a peer, testing
   * #GNUNET_ATS_performance_change_preference().
   */
  CMD_CHANGE_PREFERENCE,

  /**
   * Provide allocation quality feedback, testing
   * #GNUNET_ATS_performance_give_feedback().
   */
  CMD_PROVIDE_FEEDBACK,

  /**
   * Obtain list of all addresses, testing
   * #GNUNET_ATS_performance_list_addresses().
   */
  CMD_LIST_ADDRESSES,

  /**
   * Reserve bandwidth, testing
   * #GNUNET_ATS_reserve_bandwidth().
   */
  CMD_RESERVE_BANDWIDTH,

  /**
   * Wait for a bit.
   */
  CMD_SLEEP

};


/**
 * Details for the #CMD_ADD_ADDRESS command.
 */
struct CommandAddAddress
{
  /**
   * Number of the peer (used to generate PID).
   */
  unsigned int pid;

  /**
   * Number of the address (used to generate binary address).
   */
  unsigned int addr_num;

  /**
   * Session to supply, 0 for NULL.
   */
  unsigned int session;

  /**
   * Flags to set for the address.
   */
  enum GNUNET_HELLO_AddressInfo addr_flags;

  /**
   * Performance properties to supply.
   */
  struct GNUNET_ATS_Properties properties;

  /**
   * Expect the operation to fail (duplicate).
   */
  int expect_fail;

  /**
   * Here the result of the add address operation will be stored.
   */
  struct GNUNET_ATS_AddressRecord *ar;
};


/**
 * Details for the #CMD_DEL_ADDRESS command.
 */
struct CommandDelAddress
{
  /**
   * Label of the corresponding #CMD_ADD_ADDRESS that
   * we are now to remove.
   */
  const char *add_label;
};


/**
 * Details for the #CMD_AWAIT_ADDRESS_SUGGESTION command.
 */
struct CommandAwaitAddressSuggestion
{
  /**
   * For which peer do we expect a suggestion?
   */
  unsigned int pid;

  /**
   * If we expect the address suggested to match a particular
   * addition, specify the label of the add operation here. Otherwise
   * use NULL for "any" available address.
   */
  const char *add_label;

};


/**
 * Details for the #CMD_AWAIT_DISCONNECT_SUGGESTION command.
 */
struct CommandAwaitDisconnectSuggestion
{
  /**
   * For which peer do we expect the disconnect?
   */
  unsigned int pid;

};


/**
 * Details for the #CMD_REQUEST_CONNECTION_START command.
 */
struct CommandRequestConnectionStart
{
  /**
   * Identity of the peer we would like to connect to.
   */
  unsigned int pid;

  /**
   * Location where we store the handle returned from
   * #GNUNET_ATS_connectivity_suggest().
   */
  struct GNUNET_ATS_ConnectivitySuggestHandle *csh;
};


/**
 * Details for the #CMD_REQUEST_CONNECTION_STOP command.
 */
struct CommandRequestConnectionStop
{
  /**
   * Label of the corresponding #CMD_REQUEST_CONNECTION_START that
   * we are now stopping.
   */
  const char *connect_label;
};


/**
 * Details for the #CMD_AWAIT_ADDRESS_INFORMATION command.
 */
struct CommandAwaitAddressInformation
{
  /**
   * For which address do we expect information?
   * The address is identified by the respective
   * label of the corresponding add operation.
   */
  const char *add_label;

  /**
   * Label of a possible update operation that may
   * have modified the properties.  NULL to use
   * the properties from the @e add_label.
   */
  const char *update_label;

};


/**
 * Details for the #CMD_UPDATE_ADDRESS command.
 */
struct CommandUpdateAddress
{
  /**
   * Label of the addresses's add operation.
   */
  const char *add_label;

  /**
   * Performance properties to supply.
   */
  struct GNUNET_ATS_Properties properties;

};


/**
 * Details for the #CMD_ADD_SESSION command.
 */
struct CommandAddSession
{
 /**
   * Label of the addresses's add operation.
   */
  const char *add_label;

  /**
   * Session to supply.
   */
  unsigned int session;

};


/**
 * Details for the #CMD_DEL_SESSION command.
 */
struct CommandDelSession
{
 /**
   * Label of the addresses's add operation.
   */
  const char *add_session_label;

};


/**
 * Details for the #CMD_CHANGE_PREFERENCE command.
 */
struct CommandChangePreference
{
  /**
   * Identity of the peer we have a preference change towards.
   */
  unsigned int pid;

  /* FIXME: preference details! */

};


/**
 * Details for the #CMD_PROVIDE_FEEDBACK command.
 */
struct CommandProvideFeedback
{
  /**
   * Identity of the peer we have a feedback for.
   */
  unsigned int pid;

  /**
   * Over which timeframe does the feedback apply?
   */
  struct GNUNET_TIME_Relative scope;

  /* FIXME: feedback details! */
};


/**
 * Details for the #CMD_LIST_ADDRESSES command.
 */
struct CommandListAddresses
{
  /**
   * Identity of the peer we want a list for.
   */
  unsigned int pid;

  /**
   * All addresses or just active?
   */
  int all;

  /**
   * Minimum number of addresses the callback may report.
   */
  unsigned int min_calls;

  /**
   * Maximum number of addresses the callback may report.
   */
  unsigned int max_calls;

  /**
   * Minimum number of active addresses the callback may report.
   */
  unsigned int min_active_calls;

  /**
   * Maximum number of active addresses the callback may report.
   */
  unsigned int max_active_calls;

  /**
   * Number of calls the command invoked the callback with
   * an address marked as active. (Set by command).
   */
  unsigned int active_calls;

  /**
   * Number of calls the command invoked the callback with
   * any address marked as available to ATS. (Set by command).
   */
  unsigned int calls;

  /**
   * Location where we store the return value from
   * #GNUNET_ATS_performance_list_addresses().
   */
  struct GNUNET_ATS_AddressListHandle *alh;

};


/**
 * Details for the #CMD_RESERVE_BANDWIDTH command.
 */
struct CommandReserveBandwidth
{
  /**
   * For which peer do we reserve bandwidth?
   */
  unsigned int pid;

  /**
   * How much should we try to reserve?
   */
  int32_t amount;

  /**
   * Should we expect this to work or fail?
   * #GNUNET_YES: must work
   * #GNUNET_NO: may work or fail
   * #GNUNET_SYSERR: must fail
   */
  int expected_result;

  /**
   * Location where we store the return value from
   * #GNUNET_ATS_reserve_bandwidth().
   */
  struct GNUNET_ATS_ReservationContext *rc;

};


/**
 * Details for the #CMD_SLEEP command.
 */
struct CommandSleep
{
  /**
   * How long should we wait before running the next command?
   */
  struct GNUNET_TIME_Relative delay;
};


/**
 * A command for the test case interpreter.
 */
struct Command
{
  /**
   * Command code to run.
   */
  enum CommandCode code;

  /**
   * Commands can be given a label so we can reference them later.
   */
  const char *label;

  /**
   * Additional arguments to commands, if any.
   */
  union {

    struct CommandAddAddress add_address;

    struct CommandDelAddress del_address;

    struct CommandAwaitAddressSuggestion await_address_suggestion;

    struct CommandAwaitDisconnectSuggestion await_disconnect_suggestion;

    struct CommandRequestConnectionStart request_connection_start;

    struct CommandRequestConnectionStop request_connection_stop;

    struct CommandAwaitAddressInformation await_address_information;

    struct CommandUpdateAddress update_address;

    struct CommandAddSession add_session;

    struct CommandDelSession del_session;

    struct CommandChangePreference change_preference;

    struct CommandProvideFeedback provide_feedback;

    struct CommandListAddresses list_addresses;

    struct CommandReserveBandwidth reserve_bandwidth;

    struct CommandSleep sleep;

  } details;

};


/**
 * Run ATS test.
 *
 * @param argc length of @a argv
 * @param argv command line
 * @param cmds commands to run with the interpreter
 * @param timeout how long is the test allowed to take?
 * @return 0 on success
 */
int
TEST_ATS_run (int argc,
              char *argv[],
              struct Command *cmds,
              struct GNUNET_TIME_Relative timeout);

#endif

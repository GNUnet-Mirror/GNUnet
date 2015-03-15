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
 * @file ats/test_ats_lib.c
 * @brief test ATS library with a generic interpreter for running ATS tests
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_ats_service.h"
#include "gnunet_testing_lib.h"
#include "test_ats_lib.h"

/**
 * Information about the last address suggestion we got for a peer.
 */
struct AddressSuggestData
{
  /**
   * Which session were we given?
   */
  struct Session *session;

  /**
   * What address was assigned?
   */
  struct GNUNET_HELLO_Address *address;

  /**
   * Outbound bandwidth assigned.
   */
  struct GNUNET_BANDWIDTH_Value32NBO bandwidth_out;

  /**
   * Inbound bandwidth assigned.
   */
  struct GNUNET_BANDWIDTH_Value32NBO bandwidth_in;

  /**
   * Was the bandwidth assigned non-zero?
   */
  int active;
};


/**
 * Information about the last address information we got for an address.
 */
struct AddressInformationData
{
  /**
   * What address is this data about?
   */
  struct GNUNET_HELLO_Address *address;

  /**
   * Which properties were given?
   */
  struct GNUNET_ATS_Properties properties;

  /**
   * Outbound bandwidth reported.
   */
  struct GNUNET_BANDWIDTH_Value32NBO bandwidth_out;

  /**
   * Inbound bandwidth reported.
   */
  struct GNUNET_BANDWIDTH_Value32NBO bandwidth_in;

  /**
   * Was the address said to be 'active'?
   */
  int active;
};


/**
 * Scheduling handle
 */
static struct GNUNET_ATS_SchedulingHandle *sched_ats;

/**
 * Connectivity handle
 */
static struct GNUNET_ATS_ConnectivityHandle *con_ats;

/**
 * Performance handle
 */
static struct GNUNET_ATS_PerformanceHandle *perf_ats;

/**
 * Handle for the interpreter task.
 */
static struct GNUNET_SCHEDULER_Task *interpreter_task;

/**
 * Map from peer identities to the last address suggestion
 * `struct AddressSuggestData` we got for the respective peer.
 */
static struct GNUNET_CONTAINER_MultiPeerMap *p2asd;

/**
 * Map from peer identities to the last address information
 * sets for all addresses of this peer. Each peer is mapped
 * to one or more `struct AddressInformationData` entries.
 */
static struct GNUNET_CONTAINER_MultiPeerMap *p2aid;

/**
 * Global timeout for the test.
 */
static struct GNUNET_TIME_Relative TIMEOUT;

/**
 * Return value from #main().
 */
static int ret;

/**
 * Current global command offset into the #commands array.
 */
static unsigned int off;

/**
 * Commands for the current test.
 */
static struct Command *test_commands;



/**
 * Free `struct AddressSuggestData` entry.
 *
 * @param cls NULL
 * @param key ignored
 * @param value the `struct AddressSuggestData` to release
 * @return #GNUNET_OK (continue to iterate)
 */
static int
free_asd (void *cls,
          const struct GNUNET_PeerIdentity *key,
          void *value)
{
  struct AddressSuggestData *asd = value;

  GNUNET_assert (GNUNET_YES ==
                 GNUNET_CONTAINER_multipeermap_remove (p2asd,
                                                       key,
                                                       asd));
  GNUNET_free_non_null (asd->address);
  GNUNET_free (asd);
  return GNUNET_OK;
}


/**
 * Free `struct AddressInformationData` entry.
 *
 * @param cls NULL
 * @param key ignored
 * @param value the `struct AddressSuggestData` to release
 * @return #GNUNET_OK (continue to iterate)
 */
static int
free_aid (void *cls,
          const struct GNUNET_PeerIdentity *key,
          void *value)
{
  struct AddressInformationData *aid = value;

  GNUNET_assert (GNUNET_YES ==
                 GNUNET_CONTAINER_multipeermap_remove (p2aid,
                                                       key,
                                                       aid));
  GNUNET_free (aid->address);
  GNUNET_free (aid);
  return GNUNET_OK;
}


/**
 * Find latest address suggestion made for the given peer.
 *
 * @param pid peer to look up
 * @return NULL if peer was never involved
 */
static struct AddressSuggestData *
find_address_suggestion (const struct GNUNET_PeerIdentity *pid)
{
  return GNUNET_CONTAINER_multipeermap_get (p2asd,
                                            pid);
}


/**
 * Closure for #match_address()
 */
struct MatchAddressContext
{
  /**
   * Address to find.
   */
  const struct GNUNET_HELLO_Address *addr;

  /**
   * Where to return address information if found.
   */
  struct AddressInformationData *ret;
};


/**
 * Find matching address information.
 *
 * @param cls a `struct MatchAddressContext`
 * @param key unused
 * @param value a `struct AddressInformationData`
 * @return #GNUNET_OK if not found
 */
static int
match_address (void *cls,
               const struct GNUNET_PeerIdentity *key,
               void *value)
{
  struct MatchAddressContext *mac = cls;
  struct AddressInformationData *aid = value;

  if (0 == GNUNET_HELLO_address_cmp (mac->addr,
                                     aid->address))
  {
    mac->ret = aid;
    return GNUNET_NO;
  }
  return GNUNET_OK;
}


/**
 * Find latest address information made for the given address.
 *
 * @param addr address to look up
 * @return NULL if peer was never involved
 */
static struct AddressInformationData *
find_address_information (const struct GNUNET_HELLO_Address *addr)
{
  struct MatchAddressContext mac;

  mac.ret = NULL;
  mac.addr = addr;
  GNUNET_CONTAINER_multipeermap_get_multiple (p2aid,
                                              &addr->peer,
                                              &match_address,
                                              &mac);
  return mac.ret;
}


/**
 * Task run to terminate the testcase.
 *
 * @param cls NULL
 * @param tc unused
 */
static void
end (void *cls,
     const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  if (0 != ret)
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Test failed at stage %u %s\n",
                off,
                (NULL != test_commands[off].label)
                ? test_commands[off].label
                : "");
  if (NULL != interpreter_task)
  {
    GNUNET_SCHEDULER_cancel (interpreter_task);
    interpreter_task = NULL;
  }
  if (NULL != sched_ats)
  {
    GNUNET_ATS_scheduling_done (sched_ats);
    sched_ats = NULL;
  }
  if (NULL != con_ats)
  {
    GNUNET_ATS_connectivity_done (con_ats);
    con_ats = NULL;
  }
  if (NULL != perf_ats)
  {
    GNUNET_ATS_performance_done (perf_ats);
    perf_ats = NULL;
  }
  if (NULL != p2asd)
  {
    GNUNET_CONTAINER_multipeermap_iterate (p2asd,
                                           &free_asd,
                                           NULL);
    GNUNET_CONTAINER_multipeermap_destroy (p2asd);
    p2asd = NULL;
  }
  if (NULL != p2aid)
  {
    GNUNET_CONTAINER_multipeermap_iterate (p2aid,
                                           &free_aid,
                                           NULL);
    GNUNET_CONTAINER_multipeermap_destroy (p2aid);
    p2aid = NULL;
  }
}


/**
 * Main interpreter loop. Runs the steps of the test.
 *
 * @param cls NULL
 * @param tc unused
 */
static void
interpreter (void *cls,
             const struct GNUNET_SCHEDULER_TaskContext *tc);


/**
 * Run the interpreter next.
 */
static void
run_interpreter ()
{
  if (NULL != interpreter_task)
    GNUNET_SCHEDULER_cancel (interpreter_task);
  interpreter_task = GNUNET_SCHEDULER_add_now (&interpreter,
                                               NULL);
}


/**
 * Initialize public key of a peer based on a single number.
 *
 * @param pid number to use as the basis
 * @param pk resulting fake public key
 */
static void
make_peer (uint32_t pid,
           struct GNUNET_PeerIdentity *pk)
{
  memset (pk,
          (int) pid,
          sizeof (struct GNUNET_PeerIdentity));
  memcpy (pk,
          &pid,
          sizeof (uint32_t));
}


/**
 * Generate a fake address based on the given parameters.
 *
 * @param pid number of the peer
 * @param num number of the address at peer @a pid
 * @param addr_flags flags to use for the address
 * @return the address
 */
static struct GNUNET_HELLO_Address *
make_address (uint32_t pid,
              uint32_t num,
              enum GNUNET_HELLO_AddressInfo addr_flags)
{
  struct GNUNET_PeerIdentity pk;
  uint32_t nbo;

  nbo = htonl (num);
  make_peer (pid,
             &pk);
  return GNUNET_HELLO_address_allocate (&pk,
                                        "test",
                                        &nbo,
                                        sizeof (nbo),
                                        addr_flags);
}


/**
 * Our dummy sessions.
 */
struct Session
{
  /**
   * Field to avoid `0 == sizeof(struct Session)`.
   */
  unsigned int non_empty;
};


/**
 * Create a session instance for ATS.
 *
 * @param i which session number to return
 * @return NULL if @a i is 0, otherwise a pointer unique to @a i
 */
static struct Session *
make_session (unsigned int i)
{
  struct Session *baseptr = NULL;

  if (0 == i)
    return NULL;
  /* Yes, these are *intentionally* out-of-bounds,
     and offset from NULL, as nobody should ever
     use those other than to compare pointers! */
  return baseptr + i;
}


/**
 * Find a @a code command before the global #off with the
 * specified @a label.
 *
 * @param code opcode to look for
 * @param label label to look for, NULL for none
 * @return previous command with the matching label
 */
static struct Command *
find_command (enum CommandCode code,
              const char *label)
{
  int i;

  if (NULL == label)
    return NULL;
  for (i=off-1;i>=0;i--)
    if ( (code == test_commands[i].code) &&
         (0 == strcmp (test_commands[i].label,
                       label)) )
      return &test_commands[i];
  GNUNET_break (0);
  return NULL;
}


/**
 * Function called from #GNUNET_ATS_performance_list_addresses when
 * we process a #CMD_LIST_ADDRESSES command.
 *
 * @param cls the `struct Command` that caused the call
 * @param address the address, NULL if ATS service was disconnected
 * @param address_active #GNUNET_YES if this address is actively used
 *        to maintain a connection to a peer;
 *        #GNUNET_NO if the address is not actively used;
 *        #GNUNET_SYSERR if this address is no longer available for ATS
 * @param bandwidth_out assigned outbound bandwidth for the connection
 * @param bandwidth_in assigned inbound bandwidth for the connection
 * @param prop performance data for the address
 */
static void
info_cb (void *cls,
         const struct GNUNET_HELLO_Address *address,
         int address_active,
         struct GNUNET_BANDWIDTH_Value32NBO bandwidth_out,
         struct GNUNET_BANDWIDTH_Value32NBO bandwidth_in,
         const struct GNUNET_ATS_Properties *prop)
{
  struct Command *c = cls;
  struct CommandListAddresses *cmd = &c->details.list_addresses;

  if (NULL == address)
  {
    cmd->alh = NULL;
    /* we are done with the iteration, continue to execute */
    if ( (cmd->calls < cmd->min_calls) &&
         (cmd->active_calls < cmd->min_active_calls) )
    {
      GNUNET_SCHEDULER_shutdown ();
      return;
    }
    off++;
    run_interpreter ();
    return;
  }
  switch (address_active)
  {
  case GNUNET_YES:
    cmd->active_calls++;
    cmd->calls++;
    break;
  case GNUNET_NO:
    cmd->calls++;
    break;
  case GNUNET_SYSERR:
    return;
  }
  if ( (cmd->calls > cmd->max_calls) &&
       (cmd->active_calls < cmd->max_active_calls) )
  {
    GNUNET_break (0);
    GNUNET_ATS_performance_list_addresses_cancel (cmd->alh);
    cmd->alh = NULL;
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
}


/**
 * Function called with reservation result.
 *
 * @param cls closure with the reservation command (`struct Command`)
 * @param peer identifies the peer
 * @param amount set to the amount that was actually reserved or unreserved;
 *               either the full requested amount or zero (no partial reservations)
 * @param res_delay if the reservation could not be satisfied (amount was 0), how
 *        long should the client wait until re-trying?
 */
static void
reservation_cb (void *cls,
                const struct GNUNET_PeerIdentity *peer,
                int32_t amount,
                struct GNUNET_TIME_Relative res_delay)
{
  struct Command *cmd = cls;
  struct GNUNET_PeerIdentity pid;

  cmd->details.reserve_bandwidth.rc = NULL;
  make_peer (cmd->details.reserve_bandwidth.pid,
             &pid);
  GNUNET_assert (0 == memcmp (peer,
                              &pid,
                              sizeof (struct GNUNET_PeerIdentity)));
  switch (cmd->details.reserve_bandwidth.expected_result)
  {
  case GNUNET_OK:
    if (amount != cmd->details.reserve_bandwidth.amount)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  "Unexpectedly failed to reserve %d/%d bytes with delay %s!\n",
                  (int) amount,
                  (int) cmd->details.reserve_bandwidth.amount,
                  GNUNET_STRINGS_relative_time_to_string (res_delay,
                                                          GNUNET_YES));
      GNUNET_break (0);
      GNUNET_SCHEDULER_shutdown ();
      return;
    }
    break;
  case GNUNET_NO:
    GNUNET_break ( (0 != amount) ||
                   (0 != res_delay.rel_value_us) );
    break;
  case GNUNET_SYSERR:
    if ( (amount != 0) ||
         (0 == res_delay.rel_value_us) )
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  "Unexpectedly reserved %d bytes with delay %s!\n",
                  (int) amount,
                  GNUNET_STRINGS_relative_time_to_string (res_delay,
                                                          GNUNET_YES));
      GNUNET_break (0);
      GNUNET_SCHEDULER_shutdown ();
      return;
    }
    break;
  }
  off++;
  run_interpreter ();
}


/**
 * Main interpreter loop. Runs the steps of the test.
 *
 * @param cls NULL
 * @param tc unused
 */
static void
interpreter (void *cls,
             const struct GNUNET_SCHEDULER_TaskContext *tc)

{
  struct Command *cmd;

  interpreter_task = NULL;
  while (1)
  {
    cmd = &test_commands[off];
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "#%u: %d %s\n",
                off,
                (int) cmd->code,
                (NULL != cmd->label) ? cmd->label : "");
    switch (cmd->code)
    {
    case CMD_END_PASS:
      ret = 0;
      GNUNET_SCHEDULER_shutdown ();
      return;
    case CMD_ADD_ADDRESS:
      {
        struct GNUNET_HELLO_Address *addr;
        struct Session *session;

        addr = make_address (cmd->details.add_address.pid,
                             cmd->details.add_address.addr_num,
                             cmd->details.add_address.addr_flags);
        session = make_session (cmd->details.add_address.session);
        if (cmd->details.add_address.expect_fail)
          GNUNET_log_skip (1, GNUNET_NO);
        cmd->details.add_address.ar
          = GNUNET_ATS_address_add (sched_ats,
                                    addr,
                                    session,
                                    &cmd->details.add_address.properties);
        GNUNET_free (addr);
        if (cmd->details.add_address.expect_fail)
        {
          GNUNET_log_skip (0, GNUNET_YES);
        }
        else if (NULL == cmd->details.add_address.ar)
        {
          GNUNET_break (0);
          GNUNET_SCHEDULER_shutdown ();
          return;
        }
        off++;
        break;
      }
    case CMD_DEL_ADDRESS:
      {
        struct Command *add;

        add = find_command (CMD_ADD_ADDRESS,
                            cmd->details.del_address.add_label);
        GNUNET_assert (NULL != add->details.add_address.ar);
        GNUNET_ATS_address_destroy (add->details.add_address.ar);
        add->details.add_address.ar = NULL;
        off++;
        break;
      }
    case CMD_AWAIT_ADDRESS_SUGGESTION:
      {
        struct GNUNET_PeerIdentity pid;
        struct GNUNET_HELLO_Address *addr;
        struct Command *add;
        struct AddressSuggestData *asd;
        int done;

        make_peer (cmd->details.await_address_suggestion.pid,
                   &pid);
        asd = find_address_suggestion (&pid);
        if (NULL == asd)
          return;
        if (GNUNET_NO == asd->active)
          return;
        done = GNUNET_YES;
        if (NULL != cmd->details.await_address_suggestion.add_label)
        {
          done = GNUNET_NO;
          add = find_command (CMD_ADD_ADDRESS,
                              cmd->details.await_address_suggestion.add_label);
          addr = make_address (add->details.add_address.pid,
                               add->details.add_address.addr_num,
                               add->details.add_address.addr_flags);
          if ( (asd->session ==
                make_session (add->details.add_address.session)) &&
               (0 ==
                GNUNET_HELLO_address_cmp (addr,
                                          asd->address)) )
            done = GNUNET_YES;
          GNUNET_free (addr);
        }
        if (GNUNET_NO == done)
          return;
        off++;
        break;
      }
    case CMD_AWAIT_DISCONNECT_SUGGESTION:
      {
        struct GNUNET_PeerIdentity pid;
        struct AddressSuggestData *asd;

        make_peer (cmd->details.await_disconnect_suggestion.pid,
                   &pid);
        asd = find_address_suggestion (&pid);
        if (NULL == asd)
          return;
        if (GNUNET_NO == asd->active)
          return;
        off++;
        break;
      }
    case CMD_REQUEST_CONNECTION_START:
      {
        struct GNUNET_PeerIdentity pid;

        make_peer (cmd->details.request_connection_start.pid,
                   &pid);
        cmd->details.request_connection_start.csh
          = GNUNET_ATS_connectivity_suggest (con_ats,
                                             &pid);
        off++;
        break;
      }
    case CMD_REQUEST_CONNECTION_STOP:
      {
        struct Command *start;

        start = find_command (CMD_REQUEST_CONNECTION_START,
                              cmd->details.request_connection_stop.connect_label);
        GNUNET_ATS_connectivity_suggest_cancel (start->details.request_connection_start.csh);
        start->details.request_connection_start.csh = NULL;
        off++;
        break;
      }
    case CMD_AWAIT_ADDRESS_INFORMATION:
      {
        struct AddressInformationData *aid;
        struct Command *add;
        struct Command *update;
        struct GNUNET_HELLO_Address *addr;
        const struct GNUNET_ATS_Properties *cmp;

        add = find_command (CMD_ADD_ADDRESS,
                            cmd->details.await_address_information.add_label);
        update = find_command (CMD_UPDATE_ADDRESS,
                               cmd->details.await_address_information.update_label);
        addr = make_address (add->details.add_address.pid,
                             add->details.add_address.addr_num,
                             add->details.add_address.addr_flags);
        aid = find_address_information (addr);
        GNUNET_free (addr);
        if (NULL == update)
          cmp = &add->details.add_address.properties;
        else
          cmp = &update->details.update_address.properties;
        if ( (NULL != aid) &&
             (0 == memcmp (cmp,
                           &aid->properties,
                           sizeof (struct GNUNET_ATS_Properties))) )
        {
          off++;
          break;
        }
        return;
      }
    case CMD_UPDATE_ADDRESS:
      {
        struct Command *add;

        add = find_command (CMD_ADD_ADDRESS,
                            cmd->details.update_address.add_label);
        GNUNET_assert (NULL != add->details.add_address.ar);
        GNUNET_ATS_address_update (add->details.add_address.ar,
                                   &cmd->details.update_address.properties);
        off++;
        break;
      }
    case CMD_ADD_SESSION:
      {
        struct Command *add;
        struct Session *session;

        add = find_command (CMD_ADD_ADDRESS,
                            cmd->details.add_session.add_label);
        session = make_session (cmd->details.add_session.session);
        GNUNET_assert (NULL != add->details.add_address.ar);
        GNUNET_ATS_address_add_session (add->details.add_address.ar,
                                        session);
        off++;
        break;
      }
    case CMD_DEL_SESSION:
      {
        struct Command *add_address;
        struct Command *add_session;
        struct Session *session;

        add_session = find_command (CMD_ADD_SESSION,
                                    cmd->details.del_session.add_session_label);
        add_address = find_command (CMD_ADD_ADDRESS,
                                    add_session->details.add_session.add_label);
        GNUNET_assert (NULL != add_address->details.add_address.ar);
        session = make_session (add_session->details.add_session.session);
        GNUNET_ATS_address_del_session (add_address->details.add_address.ar,
                                        session);
        off++;
        break;
      }
    case CMD_CHANGE_PREFERENCE:
      {
        struct GNUNET_PeerIdentity pid;

        make_peer (cmd->details.change_preference.pid,
                   &pid);
        GNUNET_ATS_performance_change_preference (perf_ats,
                                                  &pid,
                                                  GNUNET_ATS_PREFERENCE_END);
        off++;
        break;
      }
    case CMD_PROVIDE_FEEDBACK:
      {
        struct GNUNET_PeerIdentity pid;

        make_peer (cmd->details.provide_feedback.pid,
                   &pid);
        GNUNET_ATS_performance_give_feedback (perf_ats,
                                              &pid,
                                              cmd->details.provide_feedback.scope,
                                              GNUNET_ATS_PREFERENCE_END);
        off++;
        break;
      }
    case CMD_LIST_ADDRESSES:
      {
        struct GNUNET_PeerIdentity pid;

        make_peer (cmd->details.list_addresses.pid,
                   &pid);
        cmd->details.list_addresses.alh
          = GNUNET_ATS_performance_list_addresses (perf_ats,
                                                   &pid,
                                                   cmd->details.list_addresses.all,
                                                   &info_cb,
                                                   cmd);
        return;
      }
    case CMD_RESERVE_BANDWIDTH:
      {
        struct GNUNET_PeerIdentity pid;

        make_peer (cmd->details.reserve_bandwidth.pid,
                   &pid);
        cmd->details.reserve_bandwidth.rc
          = GNUNET_ATS_reserve_bandwidth (perf_ats,
                                          &pid,
                                          cmd->details.reserve_bandwidth.amount,
                                          &reservation_cb,
                                          cmd);
        return;
      }
    case CMD_SLEEP:
      off++;
      interpreter_task = GNUNET_SCHEDULER_add_delayed (cmd->details.sleep.delay,
                                                       &interpreter,
                                                       NULL);
      return;
    } /* end switch */
  } /* end while(1) */
}


/**
 * Signature of a function called by ATS with the current bandwidth
 * and address preferences as determined by ATS.
 *
 * @param cls closure, should point to "asc-closure"
 * @param peer for which we suggest an address, NULL if ATS connection died
 * @param address suggested address (including peer identity of the peer),
 *             may be NULL to signal disconnect from peer
 * @param session session to use, NULL to establish a new outgoing session
 * @param bandwidth_out assigned outbound bandwidth for the connection,
 *        0 to signal disconnect
 * @param bandwidth_in assigned inbound bandwidth for the connection,
 *        0 to signal disconnect
 */
static void
address_suggest_cb (void *cls,
                    const struct GNUNET_PeerIdentity *peer,
                    const struct GNUNET_HELLO_Address *address,
                    struct Session *session,
                    struct GNUNET_BANDWIDTH_Value32NBO bandwidth_out,
                    struct GNUNET_BANDWIDTH_Value32NBO bandwidth_in)
{
  const char *asc_cls = cls;
  struct AddressSuggestData *asd;

  GNUNET_break (0 == strcmp (asc_cls, "asc-closure"));
  if (NULL == peer)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Connection to ATS died, likely a crash!\n");
    GNUNET_SCHEDULER_shutdown ();
#if 0
    /* This is what we should do if we wanted to continue past
       the ATS crash. */
    GNUNET_CONTAINER_multipeermap_iterate (p2asd,
                                           &free_asd,
                                           NULL);
    GNUNET_CONTAINER_multipeermap_iterate (p2aid,
                                           &free_aid,
                                           NULL);
#endif
    return;
  }

  asd = find_address_suggestion (peer);
  if (NULL == asd)
  {
    asd = GNUNET_new (struct AddressSuggestData);
    GNUNET_assert (GNUNET_YES ==
                   GNUNET_CONTAINER_multipeermap_put (p2asd,
                                                      peer,
                                                      asd,
                                                      GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY));
  }
  if ( (0 == ntohl (bandwidth_out.value__)) &&
       (0 == ntohl (bandwidth_in.value__)) )
    asd->active = GNUNET_NO;
  else
    asd->active = GNUNET_YES;
  asd->bandwidth_out = bandwidth_out;
  asd->bandwidth_in = bandwidth_in;
  asd->session = session;
  GNUNET_free_non_null (asd->address);
  asd->address = NULL;
  if (NULL != address)
    asd->address = GNUNET_HELLO_address_copy (address);
  if (NULL == interpreter_task)
    run_interpreter ();
}


/**
 * Signature of a function that is called with QoS information about an address.
 *
 * @param cls closure, should point to "aic-closure"
 * @param address the address, NULL if ATS service was disconnected
 * @param address_active #GNUNET_YES if this address is actively used
 *        to maintain a connection to a peer;
 *        #GNUNET_NO if the address is not actively used;
 *        #GNUNET_SYSERR if this address is no longer available for ATS
 * @param bandwidth_out assigned outbound bandwidth for the connection
 * @param bandwidth_in assigned inbound bandwidth for the connection
 * @param prop performance data for the address
 */
static void
address_information_cb (void *cls,
                        const struct GNUNET_HELLO_Address *address,
                        int address_active,
                        struct GNUNET_BANDWIDTH_Value32NBO bandwidth_out,
                        struct GNUNET_BANDWIDTH_Value32NBO bandwidth_in,
                        const struct GNUNET_ATS_Properties *prop)
{
  const char *aic_cls = cls;
  struct AddressInformationData *aid;

  GNUNET_break (0 == strcmp (aic_cls, "aic-closure"));
  if (NULL == address)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Connection to ATS died, likely a crash!\n");
    GNUNET_CONTAINER_multipeermap_iterate (p2aid,
                                           &free_aid,
                                           NULL);
    return;
  }

  aid = find_address_information (address);
  if (NULL == aid)
  {
    aid = GNUNET_new (struct AddressInformationData);
    aid->address = GNUNET_HELLO_address_copy (address);
    GNUNET_assert (GNUNET_YES ==
                   GNUNET_CONTAINER_multipeermap_put (p2aid,
                                                      &address->peer,
                                                      aid,
                                                      GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE));
  }
  aid->active = address_active;
  aid->bandwidth_out = bandwidth_out;
  aid->bandwidth_in = bandwidth_in;
  aid->properties = *prop;
  run_interpreter ();
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
  p2asd = GNUNET_CONTAINER_multipeermap_create (128,
                                                GNUNET_NO);
  p2aid = GNUNET_CONTAINER_multipeermap_create (128,
                                                GNUNET_NO);
  GNUNET_SCHEDULER_add_delayed (TIMEOUT,
                                &end,
                                NULL);

  sched_ats = GNUNET_ATS_scheduling_init (cfg,
                                          &address_suggest_cb,
                                          "asc-closure");
  if (NULL == sched_ats)
  {
    GNUNET_break (0);
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  con_ats = GNUNET_ATS_connectivity_init (cfg);
  if (NULL == con_ats)
  {
    GNUNET_break (0);
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  perf_ats = GNUNET_ATS_performance_init (cfg,
                                          &address_information_cb,
                                          "aic-closure");
  if (NULL == perf_ats)
  {
    GNUNET_break (0);
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  run_interpreter ();
}


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
              struct GNUNET_TIME_Relative timeout)
{
  char *test_filename = GNUNET_strdup (argv[0]);
  char *sep;
  char *config_file;
  char *underscore;

  test_commands = cmds;
  TIMEOUT = timeout;
  if (NULL != (sep = strstr (test_filename, ".exe")))
    sep[0] = '\0';
  underscore = strrchr (test_filename, (int) '_');
  GNUNET_assert (NULL != underscore);
  GNUNET_asprintf (&config_file,
                   "test_ats_api_%s.conf",
                   underscore + 1);
  ret = 2;
  if (0 != GNUNET_TESTING_peer_run ("test-ats-api",
                                    config_file,
                                    &run, NULL))
    ret = 1;
  GNUNET_free (test_filename);
  GNUNET_free (config_file);
  return ret;
}

/* end of test_ats_lib.c */

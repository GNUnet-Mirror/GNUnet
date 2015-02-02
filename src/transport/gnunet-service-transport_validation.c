/*
     This file is part of GNUnet.
     (C) 2010-2015 Christian Grothoff (and other contributing authors)

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
 * @file transport/gnunet-service-transport_validation.c
 * @brief address validation subsystem
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet-service-transport_ats.h"
#include "gnunet-service-transport_blacklist.h"
#include "gnunet-service-transport_clients.h"
#include "gnunet-service-transport_hello.h"
#include "gnunet-service-transport_neighbours.h"
#include "gnunet-service-transport_plugins.h"
#include "gnunet-service-transport_validation.h"
#include "gnunet-service-transport.h"
#include "gnunet_hello_lib.h"
#include "gnunet_ats_service.h"
#include "gnunet_peerinfo_service.h"
#include "gnunet_signatures.h"


/**
 * How long is a PONG signature valid?  We'll recycle a signature until
 * 1/4 of this time is remaining.  PONGs should expire so that if our
 * external addresses change an adversary cannot replay them indefinitely.
 * OTOH, we don't want to spend too much time generating PONG signatures,
 * so they must have some lifetime to reduce our CPU usage.
 */
#define PONG_SIGNATURE_LIFETIME GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_HOURS, 1)

/**
 * After how long do we expire an address in a HELLO that we just
 * validated?  This value is also used for our own addresses when we
 * create a HELLO.
 */
#define HELLO_ADDRESS_EXPIRATION GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_HOURS, 12)

/**
 * How often do we allow PINGing an address that we have not yet
 * validated?  This also determines how long we track an address that
 * we cannot validate (because after this time we can destroy the
 * validation record).
 */
#define UNVALIDATED_PING_KEEPALIVE GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MINUTES, 5)

/**
 * How often do we PING an address that we have successfully validated
 * in the past but are not actively using?  Should be (significantly)
 * smaller than HELLO_ADDRESS_EXPIRATION.
 */
#define VALIDATED_PING_FREQUENCY GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MINUTES, 15)

/**
 * How often do we PING an address that we are currently using?
 */
#define CONNECTED_PING_FREQUENCY GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MINUTES, 2)

/**
 * How much delay is acceptable for sending the PING or PONG?
 */
#define ACCEPTABLE_PING_DELAY GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 1)

/**
 * Size of the validation map hashmap.
 */
#define VALIDATION_MAP_SIZE 256

/**
 * Priority to use for PINGs
 */
#define PING_PRIORITY 2

/**
 * Priority to use for PONGs
 */
#define PONG_PRIORITY 4


GNUNET_NETWORK_STRUCT_BEGIN

/**
 * Message used to ask a peer to validate receipt (to check an address
 * from a HELLO).  Followed by the address we are trying to validate,
 * or an empty address if we are just sending a PING to confirm that a
 * connection which the receiver (of the PING) initiated is still valid.
 */
struct TransportPingMessage
{

  /**
   * Type will be #GNUNET_MESSAGE_TYPE_TRANSPORT_PING
   */
  struct GNUNET_MessageHeader header;

  /**
   * Challenge code (to ensure fresh reply).
   */
  uint32_t challenge GNUNET_PACKED;

  /**
   * Who is the intended recipient?
   */
  struct GNUNET_PeerIdentity target;

};


/**
 * Message used to validate a HELLO.  The challenge is included in the
 * confirmation to make matching of replies to requests possible.  The
 * signature signs our public key, an expiration time and our address.<p>
 *
 * This message is followed by our transport address that the PING tried
 * to confirm (if we liked it).  The address can be empty (zero bytes)
 * if the PING had not address either (and we received the request via
 * a connection that we initiated).
 */
struct TransportPongMessage
{

  /**
   * Type will be #GNUNET_MESSAGE_TYPE_TRANSPORT_PONG
   */
  struct GNUNET_MessageHeader header;

  /**
   * Challenge code from PING (showing freshness).  Not part of what
   * is signed so that we can re-use signatures.
   */
  uint32_t challenge GNUNET_PACKED;

  /**
   * Signature.
   */
  struct GNUNET_CRYPTO_EddsaSignature signature;

  /**
   * #GNUNET_SIGNATURE_PURPOSE_TRANSPORT_PONG_OWN to confirm that this is a
   * plausible address for the signing peer.
   */
  struct GNUNET_CRYPTO_EccSignaturePurpose purpose;

  /**
   * When does this signature expire?
   */
  struct GNUNET_TIME_AbsoluteNBO expiration;

  /**
   * Size of address appended to this message (part of what is
   * being signed, hence not redundant).
   */
  uint32_t addrlen GNUNET_PACKED;

};
GNUNET_NETWORK_STRUCT_END

/**
 * Information about an address under validation
 */
struct ValidationEntry
{

  /**
   * The address.
   */
  struct GNUNET_HELLO_Address *address;

  /**
   * Handle to the blacklist check (if we're currently in it).
   */
  struct GST_BlacklistCheck *bc;

  /**
   * Cached PONG signature
   */
  struct GNUNET_CRYPTO_EddsaSignature pong_sig_cache;

  /**
   * ID of task that will clean up this entry if nothing happens.
   */
  struct GNUNET_SCHEDULER_Task *timeout_task;

  /**
   * ID of task that will trigger address revalidation.
   */
  struct GNUNET_SCHEDULER_Task *revalidation_task;

  /**
   * At what time did we send the latest validation request (PING)?
   */
  struct GNUNET_TIME_Absolute send_time;

  /**
   * At what time do we send the next validation request (PING)?
   */
  struct GNUNET_TIME_Absolute next_validation;

  /**
   * Until when is this address valid?
   * ZERO if it is not currently considered valid.
   */
  struct GNUNET_TIME_Absolute valid_until;

  /**
   * Until when is the cached PONG signature valid?
   * ZERO if it is not currently considered valid.
   */
  struct GNUNET_TIME_Absolute pong_sig_valid_until;

  /**
   * How long until we can try to validate this address again?
   * FOREVER if the address is for an unsupported plugin (from PEERINFO)
   * ZERO if the address is considered valid (no validation needed)
   * otherwise a time in the future if we're currently denying re-validation
   */
  struct GNUNET_TIME_Absolute revalidation_block;

  /**
   * Last observed latency for this address (round-trip), delay between
   * last PING sent and PONG received; FOREVER if we never got a PONG.
   */
  struct GNUNET_TIME_Relative latency;

  /**
   * Current state of this validation entry
   */
  enum GNUNET_TRANSPORT_ValidationState state;

  /**
   * Challenge number we used.
   */
  uint32_t challenge;

  /**
   * When passing the address in #add_valid_peer_address(), did we
   * copy the address to the HELLO yet?
   */
  int copied;

  /**
   * Are we currently using this address for a connection?
   */
  int in_use;

  /**
   * Are we expecting a PONG message for this validation entry?
   */
  int expecting_pong;

  /**
   * Is this address known to ATS as valid right now?
   */
  int known_to_ats;

  /**
   * Which network type does our address belong to?
   */
  enum GNUNET_ATS_Network_Type network;
};


/**
 * Map of PeerIdentities to 'struct ValidationEntry*'s (addresses
 * of the given peer that we are currently validating, have validated
 * or are blocked from re-validation for a while).
 */
static struct GNUNET_CONTAINER_MultiPeerMap *validation_map;

/**
 * Context for peerinfo iteration.
 */
static struct GNUNET_PEERINFO_NotifyContext *pnc;

/**
 * Minimum delay between to validations
 */
static struct GNUNET_TIME_Relative validation_delay;

/**
 * Number of validations running; any PING that was not yet
 * matched by a PONG and for which we have not yet hit the
 * timeout is considered a running 'validation'.
 */
static unsigned int validations_running;

/**
 * Validition fast start threshold
 */
static unsigned int validations_fast_start_threshold;

/**
 * When is next validation allowed
 */
static struct GNUNET_TIME_Absolute validation_next;


/**
 * Context for the validation entry match function.
 */
struct ValidationEntryMatchContext
{
  /**
   * Where to store the result?
   */
  struct ValidationEntry *ve;

  /**
   * Address we're interested in.
   */
  const struct GNUNET_HELLO_Address *address;

};


/**
 * Provide an update on the `validation_map` map size to statistics.
 * This function should be called whenever the `validation_map`
 * is changed.
 */
static void
publish_ve_stat_update ()
{
  GNUNET_STATISTICS_set (GST_stats,
			 gettext_noop ("# Addresses in validation map"),
			 GNUNET_CONTAINER_multipeermap_size (validation_map),
			 GNUNET_NO);
}


/**
 * Iterate over validation entries until a matching one is found.
 *
 * @param cls the `struct ValidationEntryMatchContext *`
 * @param key peer identity (unused)
 * @param value a `struct ValidationEntry *` to match
 * @return #GNUNET_YES if the entry does not match,
 *         #GNUNET_NO if the entry does match
 */
static int
validation_entry_match (void *cls,
                        const struct GNUNET_PeerIdentity *key,
                        void *value)
{
  struct ValidationEntryMatchContext *vemc = cls;
  struct ValidationEntry *ve = value;

  if (0 == GNUNET_HELLO_address_cmp (ve->address,
				     vemc->address))
  {
    vemc->ve = ve;
    return GNUNET_NO;
  }
  return GNUNET_YES;
}


/**
 * A validation entry changed.  Update the state and notify
 * monitors.
 *
 * @param ve validation entry that changed
 * @param state new state
 */
static void
validation_entry_changed (struct ValidationEntry *ve,
                          enum GNUNET_TRANSPORT_ValidationState state)
{
  ve->state = state;
  GST_clients_broadcast_validation_notification (&ve->address->peer,
                                                 ve->address,
                                                 ve->send_time,
                                                 ve->valid_until,
                                                 ve->next_validation,
                                                 state);
}


/**
 * Iterate over validation entries and free them.
 *
 * @param cls (unused)
 * @param key peer identity (unused)
 * @param value a `struct ValidationEntry *` to clean up
 * @return #GNUNET_YES (continue to iterate)
 */
static int
cleanup_validation_entry (void *cls,
                          const struct GNUNET_PeerIdentity *key,
                          void *value)
{
  struct ValidationEntry *ve = value;

  ve->next_validation = GNUNET_TIME_UNIT_ZERO_ABS;
  ve->valid_until = GNUNET_TIME_UNIT_ZERO_ABS;

  /* Notify about deleted entry */
  validation_entry_changed (ve, GNUNET_TRANSPORT_VS_REMOVE);

  if (NULL != ve->bc)
  {
    GST_blacklist_test_cancel (ve->bc);
    ve->bc = NULL;
  }
  GNUNET_break (GNUNET_OK ==
                GNUNET_CONTAINER_multipeermap_remove (validation_map,
                                                      &ve->address->peer,
						      ve));
  publish_ve_stat_update ();
  if (GNUNET_YES == ve->known_to_ats)
  {
    GST_ats_expire_address (ve->address);
    ve->known_to_ats = GNUNET_NO;
  }
  GNUNET_HELLO_address_free (ve->address);
  if (NULL != ve->timeout_task)
  {
    GNUNET_SCHEDULER_cancel (ve->timeout_task);
    ve->timeout_task = NULL;
  }
  if (NULL != ve->revalidation_task)
  {
    GNUNET_SCHEDULER_cancel (ve->revalidation_task);
    ve->revalidation_task = NULL;
  }
  if ( (GNUNET_YES == ve->expecting_pong) &&
       (validations_running > 0) )
  {
    validations_running--;
    GNUNET_STATISTICS_set (GST_stats,
                           gettext_noop ("# validations running"),
                           validations_running,
                           GNUNET_NO);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Validation finished, %u validation processes running\n",
                validations_running);
  }
  GNUNET_free (ve);
  return GNUNET_OK;
}


/**
 * Address validation cleanup task.  Assesses if the record is no
 * longer valid and then possibly triggers its removal.
 *
 * @param cls the `struct ValidationEntry`
 * @param tc scheduler context (unused)
 */
static void
timeout_hello_validation (void *cls,
                          const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct ValidationEntry *ve = cls;
  struct GNUNET_TIME_Absolute max;
  struct GNUNET_TIME_Relative left;

  ve->timeout_task = NULL;
  max = GNUNET_TIME_absolute_max (ve->valid_until,
                                  ve->revalidation_block);
  left = GNUNET_TIME_absolute_get_remaining (max);
  if (left.rel_value_us > 0)
  {
    /* should wait a bit longer */
    ve->timeout_task =
        GNUNET_SCHEDULER_add_delayed (left, &timeout_hello_validation, ve);
    return;
  }
  GNUNET_STATISTICS_update (GST_stats,
                            gettext_noop ("# address records discarded"), 1,
                            GNUNET_NO);
  cleanup_validation_entry (NULL, &ve->address->peer, ve);
}


/**
 * Function called with the result from blacklisting.
 * Send a PING to the other peer if a communication is allowed.
 *
 * @param cls our `struct ValidationEntry`
 * @param pid identity of the other peer
 * @param result #GNUNET_OK if the connection is allowed, #GNUNET_NO if not
 */
static void
transmit_ping_if_allowed (void *cls,
                          const struct GNUNET_PeerIdentity *pid,
                          int result)
{
  struct ValidationEntry *ve = cls;
  struct TransportPingMessage ping;
  struct GNUNET_TRANSPORT_PluginFunctions *papi;
  struct GNUNET_TIME_Absolute next;
  const struct GNUNET_MessageHeader *hello;
  enum GNUNET_ATS_Network_Type network;
  ssize_t ret;
  size_t tsize;
  size_t slen;
  uint16_t hsize;

  ve->bc = NULL;
  if (GNUNET_NO == result)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Blacklist denies to send PING to `%s' `%s' `%s'\n",
                GNUNET_i2s (pid),
                GST_plugins_a2s (ve->address),
                ve->address->transport_name);
    cleanup_validation_entry (NULL, pid, ve);
    return;
  }

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Transmitting plain PING to `%s' `%s' `%s'\n",
              GNUNET_i2s (pid),
              GST_plugins_a2s (ve->address),
              ve->address->transport_name);

  slen = strlen (ve->address->transport_name) + 1;
  hello = GST_hello_get ();
  hsize = ntohs (hello->size);
  tsize =
      sizeof (struct TransportPingMessage) + ve->address->address_length +
      slen + hsize;

  ping.header.size =
      htons (sizeof (struct TransportPingMessage) +
             ve->address->address_length + slen);
  ping.header.type = htons (GNUNET_MESSAGE_TYPE_TRANSPORT_PING);
  ping.challenge = htonl (ve->challenge);
  ping.target = *pid;

  if (tsize >= GNUNET_SERVER_MAX_MESSAGE_SIZE)
  {
    GNUNET_break (0);
    hsize = 0;
    tsize =
        sizeof (struct TransportPingMessage) + ve->address->address_length +
        slen + hsize;
  }
  {
    char message_buf[tsize];

    /* build message with structure:
     *  [HELLO][TransportPingMessage][Transport name][Address] */
    memcpy (message_buf, hello, hsize);
    memcpy (&message_buf[hsize],
	    &ping,
	    sizeof (struct TransportPingMessage));
    memcpy (&message_buf[sizeof (struct TransportPingMessage) + hsize],
            ve->address->transport_name,
	    slen);
    memcpy (&message_buf[sizeof (struct TransportPingMessage) + slen + hsize],
            ve->address->address,
	    ve->address->address_length);
    papi = GST_plugins_find (ve->address->transport_name);
    GNUNET_assert (NULL != papi);
    GNUNET_assert (NULL != papi->send);
    struct Session *session = papi->get_session (papi->cls,
                                                 ve->address);

    if (NULL != session)
    {
      ret = papi->send (papi->cls, session,
                        message_buf, tsize,
                        PING_PRIORITY,
                        ACCEPTABLE_PING_DELAY,
                        NULL, NULL);
      network = papi->get_network (papi->cls, session);
      if (GNUNET_ATS_NET_UNSPECIFIED == network)
      {
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                    "Could not obtain a valid network for `%s' `%s'\n",
                    GNUNET_i2s (pid),
                    GST_plugins_a2s (ve->address));
        GNUNET_break(0);
      }
      GST_neighbours_notify_data_sent (ve->address, session, tsize);
    }
    else
    {
      /* Could not get a valid session */
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Could not get a valid session for `%s' `%s'\n",
                  GNUNET_i2s (pid),
                  GST_plugins_a2s (ve->address));
      ret = -1;
    }
  }
  if (-1 != ret)
  {
    next = GNUNET_TIME_relative_to_absolute (validation_delay);
    validation_next = GNUNET_TIME_absolute_max (next,
                                                validation_next);
    ve->send_time = GNUNET_TIME_absolute_get ();
    GNUNET_STATISTICS_update (GST_stats,
                              gettext_noop ("# PINGs for address validation sent"),
                              1,
                              GNUNET_NO);
    ve->network = network;
    ve->expecting_pong = GNUNET_YES;
    validations_running++;
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Validation started, %u validation processes running\n",
                validations_running);
    GNUNET_STATISTICS_set (GST_stats,
                           gettext_noop ("# validations running"),
                           validations_running,
                           GNUNET_NO);
    /*  Notify about PING sent */
    validation_entry_changed (ve, GNUNET_TRANSPORT_VS_UPDATE);
  }
}


/**
 * Do address validation again to keep address valid.
 *
 * @param cls the `struct ValidationEntry`
 * @param tc scheduler context (unused)
 */
static void
revalidate_address (void *cls,
                    const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct ValidationEntry *ve = cls;
  struct GNUNET_TIME_Relative canonical_delay;
  struct GNUNET_TIME_Relative delay;
  struct GNUNET_TIME_Relative blocked_for;
  struct GST_BlacklistCheck *bc;
  uint32_t rdelay;

  ve->revalidation_task = NULL;
  delay = GNUNET_TIME_absolute_get_remaining (ve->revalidation_block);
  /* Considering current connectivity situation, what is the maximum
     block period permitted? */
  if (GNUNET_YES == ve->in_use)
    canonical_delay = CONNECTED_PING_FREQUENCY;
  else if (GNUNET_TIME_absolute_get_remaining (ve->valid_until).rel_value_us > 0)
    canonical_delay = VALIDATED_PING_FREQUENCY;
  else
    canonical_delay = UNVALIDATED_PING_KEEPALIVE;
  /* Use delay that is MIN of original delay and possibly adjusted
     new maximum delay (which may be lower); the real delay
     is originally randomized between "canonical_delay" and "2 * canonical_delay",
     so continue to permit that window for the operation. */
  delay = GNUNET_TIME_relative_min (delay,
                                    GNUNET_TIME_relative_multiply (canonical_delay,
                                                                   2));
  ve->revalidation_block = GNUNET_TIME_relative_to_absolute (delay);
  if (delay.rel_value_us > 0)
  {
    /* should wait a bit longer */
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Waiting for %s longer before validating address `%s'\n",
                GNUNET_STRINGS_relative_time_to_string (delay,
                                                        GNUNET_YES),
                GST_plugins_a2s (ve->address));
    ve->revalidation_task =
        GNUNET_SCHEDULER_add_delayed (delay,
                                      &revalidate_address, ve);
    ve->next_validation = GNUNET_TIME_relative_to_absolute (delay);
    return;
  }
  /* check if globally we have too many active validations at a
     too high rate, if so, delay ours */
  blocked_for = GNUNET_TIME_absolute_get_remaining (validation_next);
  if ( (validations_running > validations_fast_start_threshold) &&
       (blocked_for.rel_value_us > 0) )
  {
    /* Validations are blocked, have to wait for blocked_for time */
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Validations blocked for another %s, delaying validating address `%s'\n",
                GNUNET_STRINGS_relative_time_to_string (blocked_for,
                                                        GNUNET_YES),
                GST_plugins_a2s (ve->address));
    ve->revalidation_task =
      GNUNET_SCHEDULER_add_delayed (blocked_for, &revalidate_address, ve);
    ve->next_validation = GNUNET_TIME_relative_to_absolute (blocked_for);
    return;
  }

  /* We are good to go; remember to not go again for `canonical_delay` time;
     add up to `canonical_delay` to randomize start time */
  ve->revalidation_block = GNUNET_TIME_relative_to_absolute (canonical_delay);
  /* schedule next PINGing with some extra random delay to avoid synchronous re-validations */
  rdelay =
      GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK,
                                canonical_delay.rel_value_us);

  delay = GNUNET_TIME_relative_add (canonical_delay,
                                    GNUNET_TIME_relative_multiply
                                    (GNUNET_TIME_UNIT_MICROSECONDS, rdelay));

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Validating now, next scheduled for %s, now validating address `%s'\n",
              GNUNET_STRINGS_relative_time_to_string (blocked_for,
                                                      GNUNET_YES),
              GST_plugins_a2s (ve->address));
  ve->revalidation_task =
      GNUNET_SCHEDULER_add_delayed (delay, &revalidate_address, ve);
  ve->next_validation = GNUNET_TIME_relative_to_absolute (delay);

  /* start PINGing by checking blacklist */
  GNUNET_STATISTICS_update (GST_stats,
                            gettext_noop ("# address revalidations started"), 1,
                            GNUNET_NO);
  bc = GST_blacklist_test_allowed (&ve->address->peer,
				   ve->address->transport_name,
                                   &transmit_ping_if_allowed, ve);
  if (NULL != bc)
    ve->bc = bc;                /* only set 'bc' if 'transmit_ping_if_allowed' was not already
                                 * called... */
}


/**
 * Find a ValidationEntry entry for the given neighbour that matches
 * the given address and transport.  If none exists, create one (but
 * without starting any validation).
 *
 * @param address address to find
 * @return validation entry matching the given specifications, NULL
 *         if we don't have an existing entry and no public key was given
 */
static struct ValidationEntry *
find_validation_entry (const struct GNUNET_HELLO_Address *address)
{
  struct ValidationEntryMatchContext vemc;
  struct ValidationEntry *ve;

  vemc.ve = NULL;
  vemc.address = address;
  GNUNET_CONTAINER_multipeermap_get_multiple (validation_map,
                                              &address->peer,
                                              &validation_entry_match, &vemc);
  if (NULL != (ve = vemc.ve))
    return ve;
  ve = GNUNET_new (struct ValidationEntry);
  ve->in_use = GNUNET_SYSERR; /* not defined */
  ve->address = GNUNET_HELLO_address_copy (address);
  ve->pong_sig_valid_until = GNUNET_TIME_absolute_get_zero_();
  memset (&ve->pong_sig_cache, '\0', sizeof (struct GNUNET_CRYPTO_EddsaSignature));
  ve->latency = GNUNET_TIME_UNIT_FOREVER_REL;
  ve->challenge =
      GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_NONCE, UINT32_MAX);
  ve->timeout_task =
      GNUNET_SCHEDULER_add_delayed (UNVALIDATED_PING_KEEPALIVE,
                                    &timeout_hello_validation, ve);
  GNUNET_CONTAINER_multipeermap_put (validation_map, &address->peer,
                                     ve,
                                     GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE);
  publish_ve_stat_update ();
  validation_entry_changed (ve, GNUNET_TRANSPORT_VS_NEW);
  return ve;
}


/**
 * Iterator which adds the given address to the set of validated
 * addresses.
 *
 * @param cls original HELLO message
 * @param address the address
 * @param expiration expiration time
 * @return #GNUNET_OK (keep the address)
 */
static int
add_valid_address (void *cls,
                   const struct GNUNET_HELLO_Address *address,
                   struct GNUNET_TIME_Absolute expiration)
{
  const struct GNUNET_HELLO_Message *hello = cls;
  struct ValidationEntry *ve;
  struct GNUNET_PeerIdentity pid;
  struct GNUNET_ATS_Information ats;

  if (0 == GNUNET_TIME_absolute_get_remaining (expiration).rel_value_us)
    return GNUNET_OK;           /* expired */
  if (GNUNET_OK != GNUNET_HELLO_get_id (hello, &pid))
  {
    GNUNET_break (0);
    return GNUNET_OK;           /* invalid HELLO !? */
  }
  if (0 == memcmp (&GST_my_identity,
                   &pid,
                   sizeof (struct GNUNET_PeerIdentity)))
  {
    /* Peerinfo returned own identity, skip validation */
    return GNUNET_OK;
  }
  if (NULL == GST_plugins_find (address->transport_name))
  {
    /* might have been valid in the past, but we don't have that
       plugin loaded right now */
    return GNUNET_OK;
  }

  ve = find_validation_entry (address);
  ve->valid_until = GNUNET_TIME_absolute_max (ve->valid_until,
                                              expiration);
  if (NULL == ve->revalidation_task)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Starting revalidations for valid address `%s'\n",
                GST_plugins_a2s (ve->address));
    ve->next_validation = GNUNET_TIME_absolute_get();
    ve->revalidation_task = GNUNET_SCHEDULER_add_now (&revalidate_address, ve);
  }
  validation_entry_changed (ve, GNUNET_TRANSPORT_VS_UPDATE);

  ats.type = htonl (GNUNET_ATS_NETWORK_TYPE);
  ats.value = htonl (ve->network);
  if (GNUNET_YES != ve->known_to_ats)
  {
    ve->known_to_ats = GNUNET_YES;
    GST_ats_add_address (address, NULL, &ats, 1);
  }
  return GNUNET_OK;
}


/**
 * Function called for any HELLO known to PEERINFO.
 *
 * @param cls unused
 * @param peer id of the peer, NULL for last call
 * @param hello hello message for the peer (can be NULL)
 * @param err_msg error message
 */
static void
process_peerinfo_hello (void *cls, const struct GNUNET_PeerIdentity *peer,
                        const struct GNUNET_HELLO_Message *hello,
                        const char *err_msg)
{
  GNUNET_assert (NULL != peer);
  if (NULL == hello)
    return;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Handling HELLO for peer `%s'\n",
              GNUNET_i2s (peer));
  GNUNET_assert (NULL ==
                 GNUNET_HELLO_iterate_addresses (hello, GNUNET_NO,
                                                 &add_valid_address,
                                                 (void *) hello));
}


/**
 * Start the validation subsystem.
 *
 * @param max_fds maximum number of fds to use
 */
void
GST_validation_start (unsigned int max_fds)
{
  /**
   * Initialization for validation throttling
   *
   * We have a maximum number max_fds of connections we can use for validation
   * We monitor the number of validations in parallel and start to throttle it
   * when doing to many validations in parallel:
   * if (running validations < (max_fds / 2))
   * - "fast start": run validation immediately
   * - have delay of (GNUNET_CONSTANTS_IDLE_CONNECTION_TIMEOUT.rel_value_us) / (max_fds / 2)
   *   (300 sec / ~150 == ~2 sec.) between two validations
   */

  validation_next = GNUNET_TIME_absolute_get();
  validation_delay.rel_value_us = (GNUNET_CONSTANTS_IDLE_CONNECTION_TIMEOUT.rel_value_us) / (max_fds / 2);
  validations_fast_start_threshold = (max_fds / 2);
  validations_running = 0;
  GNUNET_STATISTICS_set (GST_stats,
                         gettext_noop ("# validations running"),
                         validations_running,
                         GNUNET_NO);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Validation uses a fast start threshold of %u connections and a delay between of %s\n ",
              validations_fast_start_threshold,
              GNUNET_STRINGS_relative_time_to_string (validation_delay,
                                                      GNUNET_YES));
  validation_map = GNUNET_CONTAINER_multipeermap_create (VALIDATION_MAP_SIZE,
							 GNUNET_NO);
  pnc = GNUNET_PEERINFO_notify (GST_cfg, GNUNET_YES,
                                &process_peerinfo_hello, NULL);
}


/**
 * Stop the validation subsystem.
 */
void
GST_validation_stop ()
{
  GNUNET_CONTAINER_multipeermap_iterate (validation_map,
                                         &cleanup_validation_entry, NULL);
  GNUNET_CONTAINER_multipeermap_destroy (validation_map);
  validation_map = NULL;
  GNUNET_PEERINFO_notify_cancel (pnc);
}


/**
 * Send the given PONG to the given address.
 *
 * @param cls the PONG message
 * @param valid_until is ZERO if we never validated the address,
 *                    otherwise a time up to when we consider it (or was) valid
 * @param validation_block  is FOREVER if the address is for an unsupported plugin (from PEERINFO)
 *                          is ZERO if the address is considered valid (no validation needed)
 *                          otherwise a time in the future if we're currently denying re-validation
 * @param address target address
 */
static void
multicast_pong (void *cls,
		struct GNUNET_TIME_Absolute valid_until,
                struct GNUNET_TIME_Absolute validation_block,
                const struct GNUNET_HELLO_Address *address)
{
  struct TransportPongMessage *pong = cls;
  struct GNUNET_TRANSPORT_PluginFunctions *papi;
  struct Session *session;

  papi = GST_plugins_find (address->transport_name);
  if (NULL == papi)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Plugin %s not supported, cannot send PONG\n",
                address->transport_name);
    return;
  }

  GNUNET_assert (NULL != papi->send);
  GNUNET_assert (NULL != papi->get_session);
  session = papi->get_session(papi->cls, address);
  if (NULL == session)
  {
     GNUNET_break (0);
     return;
  }
  GST_ats_new_session (address, session);
  papi->send (papi->cls, session,
              (const char *) pong,
              ntohs (pong->header.size),
              PONG_PRIORITY,
              ACCEPTABLE_PING_DELAY,
              NULL, NULL);
  GST_neighbours_notify_data_sent (address,
                                   session,
                                   pong->header.size);

}


/**
 * We've received a PING.  If appropriate, generate a PONG.
 *
 * @param sender peer sending the PING
 * @param hdr the PING
 * @param sender_address the sender address as we got it
 * @param session session we got the PING from
 * @return #GNUNET_OK if the message was fine, #GNUNET_SYSERR on serious error
 */
int
GST_validation_handle_ping (const struct GNUNET_PeerIdentity *sender,
                            const struct GNUNET_MessageHeader *hdr,
                            const struct GNUNET_HELLO_Address *sender_address,
                            struct Session *session)
{
  const struct TransportPingMessage *ping;
  struct TransportPongMessage *pong;
  struct GNUNET_TRANSPORT_PluginFunctions *papi;
  struct GNUNET_CRYPTO_EddsaSignature *sig_cache;
  struct GNUNET_TIME_Absolute *sig_cache_exp;
  const char *addr;
  const char *addrend;
  char *plugin_name;
  char *pos;
  size_t len_address;
  size_t len_plugin;
  ssize_t ret;
  int buggy = GNUNET_NO;
  struct GNUNET_HELLO_Address address;

  if (ntohs (hdr->size) < sizeof (struct TransportPingMessage))
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  ping = (const struct TransportPingMessage *) hdr;
  if (0 !=
      memcmp (&ping->target, &GST_my_identity,
              sizeof (struct GNUNET_PeerIdentity)))
  {
    GNUNET_STATISTICS_update (GST_stats,
                              gettext_noop
                              ("# PING message for different peer received"), 1,
                              GNUNET_NO);
    return GNUNET_SYSERR;
  }
  GNUNET_STATISTICS_update (GST_stats,
                            gettext_noop ("# PING messages received"), 1,
                            GNUNET_NO);
  addr = (const char *) &ping[1];
  len_address = ntohs (hdr->size) - sizeof (struct TransportPingMessage);
  /* peer wants to confirm that this is one of our addresses, this is what is
   * used for address validation */

  sig_cache = NULL;
  sig_cache_exp = NULL;
  papi = NULL;
  if (len_address > 0)
  {
    addrend = memchr (addr, '\0', len_address);
    if (NULL == addrend)
    {
      GNUNET_break_op (0);
      return GNUNET_SYSERR;
    }
    addrend++;
    len_plugin = strlen (addr) + 1;
    len_address -= len_plugin;
    address.local_info = GNUNET_HELLO_ADDRESS_INFO_NONE;
    address.address = addrend;
    address.address_length = len_address;
    address.transport_name = addr;
    address.peer = GST_my_identity;

    if (NULL == address.transport_name)
    {
      GNUNET_break (0);
    }

    if (0 != strstr (address.transport_name, "_client"))
    {
      plugin_name = GNUNET_strdup (address.transport_name);
      pos = strstr (plugin_name, "_client");
      GNUNET_assert (NULL != pos);
      GNUNET_snprintf (pos, strlen ("_server") + 1, "%s", "_server");
    }
    else
      plugin_name = GNUNET_strdup (address.transport_name);

    if (NULL == (papi = GST_plugins_find (plugin_name)))
    {
      /* we don't have the plugin for this address */
      GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                  _("Plugin `%s' not available, cannot confirm having this address\n"),
                  plugin_name);
      GNUNET_free (plugin_name);
      return GNUNET_SYSERR;
    }
    GNUNET_free (plugin_name);
    if (GNUNET_OK != papi->check_address (papi->cls, addrend, len_address))
    {
      GNUNET_STATISTICS_update (GST_stats,
                                gettext_noop
                                ("# failed address checks during validation"), 1,
                                GNUNET_NO);
      GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                  _("Address `%s' is not one of my addresses, not confirming PING\n"),
                  GST_plugins_a2s (&address));
      return GNUNET_SYSERR;
    }
    else
    {
      GNUNET_STATISTICS_update (GST_stats,
                                gettext_noop
                                ("# successful address checks during validation"), 1,
                                GNUNET_NO);
      GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                  "Address `%s' is one of my addresses, confirming PING\n",
                  GST_plugins_a2s (&address));
    }

    if (GNUNET_YES != GST_hello_test_address (&address, &sig_cache, &sig_cache_exp))
    {
      if (GNUNET_NO == buggy)
      {
        GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                    _("Not confirming PING from peer `%s' with address `%s' since I cannot confirm having this address.\n"),
                    GNUNET_i2s (sender),
                    GST_plugins_a2s (&address));
        return GNUNET_SYSERR;
      }
      else
      {
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                    _("Received a PING message with validation bug from `%s'\n"),
                    GNUNET_i2s (sender));
      }
    }
  }
  else
  {
    addrend = NULL;             /* make gcc happy */
    len_plugin = 0;
    static struct GNUNET_CRYPTO_EddsaSignature no_address_signature;
    static struct GNUNET_TIME_Absolute no_address_signature_expiration;

    sig_cache = &no_address_signature;
    sig_cache_exp = &no_address_signature_expiration;
  }

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "I am `%s', sending PONG to peer `%s'\n",
	      GNUNET_i2s_full (&GST_my_identity),
              GNUNET_i2s (sender));

  /* message with structure:
   * [TransportPongMessage][Transport name][Address] */

  pong = GNUNET_malloc (sizeof (struct TransportPongMessage) + len_address + len_plugin);
  pong->header.size =
      htons (sizeof (struct TransportPongMessage) + len_address + len_plugin);
  pong->header.type = htons (GNUNET_MESSAGE_TYPE_TRANSPORT_PONG);
  pong->purpose.size =
      htonl (sizeof (struct GNUNET_CRYPTO_EccSignaturePurpose) +
             sizeof (uint32_t) + sizeof (struct GNUNET_TIME_AbsoluteNBO) +
             len_address + len_plugin);
  pong->purpose.purpose = htonl (GNUNET_SIGNATURE_PURPOSE_TRANSPORT_PONG_OWN);
  memcpy (&pong->challenge, &ping->challenge, sizeof (ping->challenge));
  pong->addrlen = htonl (len_address + len_plugin);
  memcpy (&pong[1], addr, len_plugin);   /* Copy transport plugin */
  if (len_address > 0)
  {
    GNUNET_assert (NULL != addrend);
    memcpy (&((char *) &pong[1])[len_plugin], addrend, len_address);
  }
  if (GNUNET_TIME_absolute_get_remaining (*sig_cache_exp).rel_value_us <
      PONG_SIGNATURE_LIFETIME.rel_value_us / 4)
  {
    /* create / update cached sig */
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		"Creating PONG signature to indicate ownership.\n");
    *sig_cache_exp = GNUNET_TIME_relative_to_absolute (PONG_SIGNATURE_LIFETIME);
    pong->expiration = GNUNET_TIME_absolute_hton (*sig_cache_exp);
    if (GNUNET_OK !=
		   GNUNET_CRYPTO_eddsa_sign (GST_my_private_key, &pong->purpose,
					   sig_cache))
    {
        GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
    		_("Failed to create PONG signature for peer `%s'\n"), GNUNET_i2s (sender));
    }
  }
  else
  {
    pong->expiration = GNUNET_TIME_absolute_hton (*sig_cache_exp);
  }
  pong->signature = *sig_cache;

  GNUNET_assert (sender_address != NULL);

  /* first see if the session we got this PING from can be used to transmit
   * a response reliably */
  if (NULL == papi)
  {
    ret = -1;
  }
  else
  {
    GNUNET_assert (NULL != papi->send);
    GNUNET_assert (NULL != papi->get_session);
    if (NULL == session)
    {
      session = papi->get_session (papi->cls, sender_address);
    }
    if (NULL == session)
    {
      GNUNET_break (0);
      ret = -1;
    }
    else
    {
      ret = papi->send (papi->cls, session,
                        (const char *) pong,
			ntohs (pong->header.size),
                        PONG_PRIORITY, ACCEPTABLE_PING_DELAY,
                        NULL, NULL);
      if (-1 != ret)
        GST_neighbours_notify_data_sent (sender_address,
					 session,
                                         pong->header.size);
    }
  }
  if (-1 != ret)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Transmitted PONG to `%s' via reliable mechanism\n",
                GNUNET_i2s (sender));
    /* done! */
    GNUNET_STATISTICS_update (GST_stats,
                              gettext_noop
                              ("# PONGs unicast via reliable transport"), 1,
                              GNUNET_NO);
    GNUNET_free (pong);
    return GNUNET_OK;
  }

  /* no reliable method found, try transmission via all known addresses */
  GNUNET_STATISTICS_update (GST_stats,
                            gettext_noop
                            ("# PONGs multicast to all available addresses"), 1,
                            GNUNET_NO);
  GST_validation_get_addresses (sender,
                                &multicast_pong, pong);
  GNUNET_free (pong);
  return GNUNET_OK;
}


/**
 * Iterator callback to go over all addresses and try to validate them
 * (unless blocked or already validated).
 *
 * @param cls NULL
 * @param address the address
 * @param expiration expiration time
 * @return #GNUNET_OK (keep the address)
 */
static int
validate_address_iterator (void *cls,
                           const struct GNUNET_HELLO_Address *address,
                           struct GNUNET_TIME_Absolute expiration)
{
  struct GNUNET_TRANSPORT_PluginFunctions * papi;
  struct ValidationEntry *ve;

  if (0 == GNUNET_TIME_absolute_get_remaining (expiration).rel_value_us)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Skipping expired address from HELLO\n");
    return GNUNET_OK;           /* expired */
  }
  papi = GST_plugins_find (address->transport_name);
  if (NULL == papi)
  {
    /* This plugin is currently unvailable ... ignore */
    return GNUNET_OK;
  }
  ve = find_validation_entry (address);
  if (NULL == ve->revalidation_task)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                "Validation process started for fresh address `%s'\n",
                GST_plugins_a2s (ve->address));
    ve->revalidation_task = GNUNET_SCHEDULER_add_now (&revalidate_address, ve);
  }
  return GNUNET_OK;
}


/**
 * Add the validated peer address to the HELLO.
 *
 * @param cls the `struct ValidationEntry *` with the validated address
 * @param max space in @a buf
 * @param buf where to add the address
 * @return number of bytes written, #GNUNET_SYSERR to signal the
 *         end of the iteration.
 */
static ssize_t
add_valid_peer_address (void *cls,
                        size_t max,
                        void *buf)
{
  struct ValidationEntry *ve = cls;

  if (GNUNET_YES == ve->copied)
    return GNUNET_SYSERR; /* Done */
  ve->copied = GNUNET_YES;
  return GNUNET_HELLO_add_address (ve->address, ve->valid_until, buf, max);
}


/**
 * We've received a PONG.  Check if it matches a pending PING and
 * mark the respective address as confirmed.
 *
 * @param sender peer sending the PONG
 * @param hdr the PONG
 * @return #GNUNET_OK if the message was fine, #GNUNET_SYSERR on serious error
 */
int
GST_validation_handle_pong (const struct GNUNET_PeerIdentity *sender,
                            const struct GNUNET_MessageHeader *hdr)
{
  const struct TransportPongMessage *pong;
  struct ValidationEntry *ve;
  const char *tname;
  const char *addr;
  size_t addrlen;
  size_t slen;
  size_t size;
  struct GNUNET_HELLO_Message *hello;
  struct GNUNET_HELLO_Address address;
  int sig_res;
  int do_verify;

  if (ntohs (hdr->size) < sizeof (struct TransportPongMessage))
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  GNUNET_STATISTICS_update (GST_stats,
                            gettext_noop ("# PONG messages received"), 1,
                            GNUNET_NO);

  /* message with structure:
   * [TransportPongMessage][Transport name][Address] */

  pong = (const struct TransportPongMessage *) hdr;
  tname = (const char *) &pong[1];
  size = ntohs (hdr->size) - sizeof (struct TransportPongMessage);
  addr = memchr (tname, '\0', size);
  if (NULL == addr)
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  addr++;
  slen = strlen (tname) + 1;
  addrlen = size - slen;

  if (NULL == GST_plugins_find (tname))
  {
    /* we got the PONG, but the transport plugin specified in it
       is not supported by this peer, so this cannot be a good
       PONG for us. */
    GNUNET_break_op (0);
    return GNUNET_OK;
  }

  address.peer = *sender;
  address.address = addr;
  address.address_length = addrlen;
  address.transport_name = tname;
  address.local_info = GNUNET_HELLO_ADDRESS_INFO_NONE;
  ve = find_validation_entry (&address);
  if ((NULL == ve) || (GNUNET_NO == ve->expecting_pong))
  {
    GNUNET_STATISTICS_update (GST_stats,
                              gettext_noop
                              ("# PONGs dropped, no matching pending validation"),
                              1, GNUNET_NO);
    return GNUNET_OK;
  }
  /* now check that PONG is well-formed */
  if (0 != memcmp (&ve->address->peer,
		   sender,
		   sizeof (struct GNUNET_PeerIdentity)))
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  if (0 ==
      GNUNET_TIME_absolute_get_remaining
      (GNUNET_TIME_absolute_ntoh (pong->expiration)).rel_value_us)
  {
    GNUNET_STATISTICS_update (GST_stats,
                              gettext_noop
                              ("# PONGs dropped, signature expired"), 1,
                              GNUNET_NO);
    return GNUNET_SYSERR;
  }

  sig_res = GNUNET_SYSERR;
  do_verify = GNUNET_YES;
  if (0 != GNUNET_TIME_absolute_get_remaining (ve->pong_sig_valid_until).rel_value_us)
  {
    /* We have a cached and valid signature for this peer,
     * try to compare instead of verify */
    if (0 == memcmp (&ve->pong_sig_cache, &pong->signature, sizeof (struct GNUNET_CRYPTO_EddsaSignature)))
    {
      /* signatures are identical, we can skip verification */
      sig_res = GNUNET_OK;
      do_verify = GNUNET_NO;
    }
    else
    {
      sig_res = GNUNET_SYSERR;
      /* signatures do not match, we have to verify */
    }
  }

  if (GNUNET_YES == do_verify)
  {
    /* Do expensive verification */
    sig_res = GNUNET_CRYPTO_eddsa_verify (GNUNET_SIGNATURE_PURPOSE_TRANSPORT_PONG_OWN,
                                          &pong->purpose, &pong->signature,
                                          &ve->address->peer.public_key);
    if (sig_res == GNUNET_SYSERR)
    {
      GNUNET_break_op (0);
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  "Failed to verify: invalid signature on address `%s':%s from peer `%s'\n",
                  tname,
                  GST_plugins_a2s (ve->address),
                  GNUNET_i2s (sender));
    }
  }
  if (sig_res == GNUNET_SYSERR)
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }

  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "Validation process successful for peer `%s' with plugin `%s' address `%s'\n",
              GNUNET_i2s (sender),
              tname,
              GST_plugins_a2s (ve->address));
  GNUNET_STATISTICS_update (GST_stats,
                            gettext_noop ("# validations succeeded"),
                            1,
                            GNUNET_NO);
  /* validity achieved, remember it! */
  ve->expecting_pong = GNUNET_NO;
  ve->valid_until = GNUNET_TIME_relative_to_absolute (HELLO_ADDRESS_EXPIRATION);
  ve->pong_sig_cache = pong->signature;
 	ve->pong_sig_valid_until = GNUNET_TIME_absolute_ntoh (pong->expiration);
  ve->latency = GNUNET_TIME_absolute_get_duration (ve->send_time);
  {
    struct GNUNET_ATS_Information ats[2];

    ats[0].type = htonl (GNUNET_ATS_QUALITY_NET_DELAY);
    ats[0].value = htonl ((uint32_t) ve->latency.rel_value_us);
    ats[1].type = htonl (GNUNET_ATS_NETWORK_TYPE);
    ats[1].value = htonl ((uint32_t) ve->network);
    if (GNUNET_YES == ve->known_to_ats)
    {
      GST_ats_update_metrics (ve->address, NULL, ats, 2);
    }
    else
    {
      ve->known_to_ats = GNUNET_YES;
      GST_ats_add_address (ve->address, NULL, ats, 2);
    }
  }
  if (validations_running > 0)
  {
    validations_running--;
    GNUNET_STATISTICS_set (GST_stats,
                           gettext_noop ("# validations running"),
                           validations_running,
                           GNUNET_NO);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Validation finished, %u validation processes running\n",
                validations_running);
  }
  else
  {
    GNUNET_break (0);
  }

  /* Notify about new validity */
  validation_entry_changed (ve, GNUNET_TRANSPORT_VS_UPDATE);

  /* build HELLO to store in PEERINFO */
  ve->copied = GNUNET_NO;
  hello = GNUNET_HELLO_create (&ve->address->peer.public_key,
                               &add_valid_peer_address, ve,
                               GNUNET_NO);
  GNUNET_PEERINFO_add_peer (GST_peerinfo, hello, NULL, NULL);
  GNUNET_free (hello);
  return GNUNET_OK;
}


/**
 * We've received a HELLO, check which addresses are new and trigger
 * validation.
 *
 * @param hello the HELLO we received
 * @return #GNUNET_OK if the message was fine, #GNUNET_SYSERR on serious error
 */
int
GST_validation_handle_hello (const struct GNUNET_MessageHeader *hello)
{
  const struct GNUNET_HELLO_Message *hm =
      (const struct GNUNET_HELLO_Message *) hello;
  struct GNUNET_PeerIdentity pid;
  struct GNUNET_HELLO_Message *h;
  int friend;

  friend = GNUNET_HELLO_is_friend_only (hm);
  if ( ( (GNUNET_YES != friend) &&
         (GNUNET_NO != friend) ) ||
       (GNUNET_OK != GNUNET_HELLO_get_id (hm, &pid)) )
  {
    /* malformed HELLO */
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  if (0 ==
      memcmp (&GST_my_identity,
	      &pid,
	      sizeof (struct GNUNET_PeerIdentity)))
    return GNUNET_OK;
  /* Add peer identity without addresses to peerinfo service */
  h = GNUNET_HELLO_create (&pid.public_key, NULL, NULL, friend);
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              _("Validation received new %s message for peer `%s' with size %u\n"),
              "HELLO",
              GNUNET_i2s (&pid),
              ntohs (hello->size));
  GNUNET_PEERINFO_add_peer (GST_peerinfo, h, NULL, NULL);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              _("Adding `%s' without addresses for peer `%s'\n"), "HELLO",
              GNUNET_i2s (&pid));

  GNUNET_free (h);
  GNUNET_assert (NULL ==
                 GNUNET_HELLO_iterate_addresses (hm,
						 GNUNET_NO,
                                                 &validate_address_iterator,
                                                 NULL));
  return GNUNET_OK;
}


/**
 * Closure for #iterate_addresses().
 */
struct IteratorContext
{
  /**
   * Function to call on each address.
   */
  GST_ValidationAddressCallback cb;

  /**
   * Closure for @e cb.
   */
  void *cb_cls;

};


/**
 * Call the callback in the closure for each validation entry.
 *
 * @param cls the `struct IteratorContext`
 * @param key the peer's identity
 * @param value the `struct ValidationEntry`
 * @return #GNUNET_OK (continue to iterate)
 */
static int
iterate_addresses (void *cls,
                   const struct GNUNET_PeerIdentity *key,
                   void *value)
{
  struct IteratorContext *ic = cls;
  struct ValidationEntry *ve = value;

  ic->cb (ic->cb_cls,
          ve->valid_until,
          ve->revalidation_block,
          ve->address);
  return GNUNET_OK;
}


/**
 * Call the given function for each address for the given target.
 * Can either give a snapshot (synchronous API) or be continuous.
 *
 * @param target peer information is requested for
 * @param cb function to call; will not be called after this function returns
 * @param cb_cls closure for @a cb
 */
void
GST_validation_get_addresses (const struct GNUNET_PeerIdentity *target,
                              GST_ValidationAddressCallback cb,
			      void *cb_cls)
{
  struct IteratorContext ic;

  ic.cb = cb;
  ic.cb_cls = cb_cls;
  GNUNET_CONTAINER_multipeermap_get_multiple (validation_map,
                                              target,
                                              &iterate_addresses, &ic);
}


/**
 * Update if we are using an address for a connection actively right now.
 * Based on this, the validation module will measure latency for the
 * address more or less often.
 *
 * @param address the address
 * @param session the session
 * @param in_use #GNUNET_YES if we are now using the address for a connection,
 *               #GNUNET_NO if we are no longer using the address for a connection
 */
void
GST_validation_set_address_use (const struct GNUNET_HELLO_Address *address,
                                struct Session *session,
                                int in_use)
{
  struct ValidationEntry *ve;

  if (GNUNET_HELLO_address_check_option (address,
                                         GNUNET_HELLO_ADDRESS_INFO_INBOUND))
    return; /* ignore inbound for validation */
  if (NULL == GST_plugins_find (address->transport_name))
  {
    /* How can we use an address for which we don't have the plugin? */
    GNUNET_break (0);
    return;
  }
  if (NULL != address)
    ve = find_validation_entry (address);
  else
    ve = NULL;                  /* FIXME: lookup based on session... */
  if (NULL == ve)
  {
    /* this can happen for inbound connections (sender_address_len == 0); */
    return;
  }
  if (ve->in_use == in_use)
  {
    if (GNUNET_YES == in_use)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  "Error setting address in use for peer `%s' `%s' to USED\n",
                  GNUNET_i2s (&address->peer), GST_plugins_a2s (address));
    }
    if (GNUNET_NO == in_use)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  "Error setting address in use for peer `%s' `%s' to NOT_USED\n",
                  GNUNET_i2s (&address->peer), GST_plugins_a2s (address));
    }
  }

  GNUNET_break (ve->in_use != in_use);  /* should be different... */
  ve->in_use = in_use;
  if (in_use == GNUNET_YES)
  {
    /* from now on, higher frequeny, so reschedule now */
    if (NULL != ve->revalidation_task)
      GNUNET_SCHEDULER_cancel (ve->revalidation_task);
    ve->revalidation_task = GNUNET_SCHEDULER_add_now (&revalidate_address, ve);
  }
}


/**
 * Query validation about the latest observed latency on a given
 * address.
 *
 * @param address the address
 * @param session session
 * @return observed latency of the address, FOREVER if the address was
 *         never successfully validated
 */
struct GNUNET_TIME_Relative
GST_validation_get_address_latency (const struct GNUNET_HELLO_Address *address,
                                    struct Session *session)
{
  struct ValidationEntry *ve;

  if (NULL == address)
  {
    GNUNET_break (0);
    return GNUNET_TIME_UNIT_FOREVER_REL;
  }
  if (NULL == GST_plugins_find (address->transport_name))
  {
    GNUNET_break (0); /* but we don't have the plugin! */
    return GNUNET_TIME_UNIT_FOREVER_REL;
  }

  ve = find_validation_entry (address);
  if (NULL == ve)
    return GNUNET_TIME_UNIT_FOREVER_REL;
  return ve->latency;
}

/**
 * Closure for the validation_entries_iterate function.
 */
struct ValidationIteratorContext
{
  /**
   * Function to call on each validation entry
   */
  GST_ValidationChangedCallback cb;

  /**
   * Closure for @e cb.
   */
  void *cb_cls;
};


/**
 * Function called on each entry in the validation map.
 * Passes the information from the validation entry to
 * the callback given in the closure.
 *
 * @param cls the `struct ValidationIteratorContext`
 * @param key peer this is about
 * @param value the `struct ValidationEntry`
 * @return #GNUNET_OK (continue to iterate)
 */
static int
validation_entries_iterate (void *cls,
			    const struct GNUNET_PeerIdentity *key,
			    void *value)
{
  struct ValidationIteratorContext *ic = cls;
  struct ValidationEntry *ve = value;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Notifying about validation entry for peer `%s' address `%s' \n",
	      GNUNET_i2s (&ve->address->peer),
	      GST_plugins_a2s (ve->address));
  ic->cb (ic->cb_cls,
	  ve->address,
	  ve->send_time,
	  ve->valid_until,
	  ve->next_validation,
	  ve->state);
  return GNUNET_OK;
}


/**
 * Iterate over all iteration entries
 *
 * @param cb function to call
 * @param cb_cls closure for cb
 */
void
GST_validation_iterate (GST_ValidationChangedCallback cb,
                        void *cb_cls)
{
  struct ValidationIteratorContext ic;

  if (NULL == validation_map)
    return; /* can happen during shutdown */
  ic.cb = cb;
  ic.cb_cls = cb_cls;
  GNUNET_CONTAINER_multipeermap_iterate (validation_map,
                                         &validation_entries_iterate,
                                         &ic);
}

/* end of file gnunet-service-transport_validation.c */

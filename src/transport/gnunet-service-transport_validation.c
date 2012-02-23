/*
     This file is part of GNUnet.
     (C) 2010,2011 Christian Grothoff (and other contributing authors)

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
#include "gnunet-service-transport_validation.h"
#include "gnunet-service-transport_plugins.h"
#include "gnunet-service-transport_hello.h"
#include "gnunet-service-transport_blacklist.h"
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
   * Type will be GNUNET_MESSAGE_TYPE_TRANSPORT_PING
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
   * Type will be GNUNET_MESSAGE_TYPE_TRANSPORT_PONG
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
  struct GNUNET_CRYPTO_RsaSignature signature;

  /**
   * GNUNET_SIGNATURE_PURPOSE_TRANSPORT_PONG_OWN to confirm that this is a
   * plausible address for the signing peer.
   */
  struct GNUNET_CRYPTO_RsaSignaturePurpose purpose;

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
   * Public key of the peer.
   */
  struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded public_key;

  /**
   * The identity of the peer. FIXME: duplicated (also in 'address')
   */
  struct GNUNET_PeerIdentity pid;

  /**
   * ID of task that will clean up this entry if nothing happens.
   */
  GNUNET_SCHEDULER_TaskIdentifier timeout_task;

  /**
   * ID of task that will trigger address revalidation.
   */
  GNUNET_SCHEDULER_TaskIdentifier revalidation_task;

  /**
   * At what time did we send the latest validation request (PING)?
   */
  struct GNUNET_TIME_Absolute send_time;

  /**
   * Until when is this address valid?
   * ZERO if it is not currently considered valid.
   */
  struct GNUNET_TIME_Absolute valid_until;

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
   * Challenge number we used.
   */
  uint32_t challenge;

  /**
   * When passing the address in 'add_valid_peer_address', did we
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
};


/**
 * Context of currently active requests to peerinfo
 * for validation of HELLOs.
 */
struct CheckHelloValidatedContext
{

  /**
   * This is a doubly-linked list.
   */
  struct CheckHelloValidatedContext *next;

  /**
   * This is a doubly-linked list.
   */
  struct CheckHelloValidatedContext *prev;

  /**
   * Hello that we are validating.
   */
  const struct GNUNET_HELLO_Message *hello;

};


/**
 * Head of linked list of HELLOs awaiting validation.
 */
static struct CheckHelloValidatedContext *chvc_head;

/**
 * Tail of linked list of HELLOs awaiting validation
 */
static struct CheckHelloValidatedContext *chvc_tail;

/**
 * Map of PeerIdentities to 'struct ValidationEntry*'s (addresses
 * of the given peer that we are currently validating, have validated
 * or are blocked from re-validation for a while).
 */
static struct GNUNET_CONTAINER_MultiHashMap *validation_map;

/**
 * Context for peerinfo iteration.
 */
static struct GNUNET_PEERINFO_NotifyContext *pnc;


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
 * Iterate over validation entries until a matching one is found.
 *
 * @param cls the 'struct ValidationEntryMatchContext'
 * @param key peer identity (unused)
 * @param value a 'struct ValidationEntry' to match
 * @return GNUNET_YES if the entry does not match,
 *         GNUNET_NO if the entry does match
 */
static int
validation_entry_match (void *cls, const GNUNET_HashCode * key, void *value)
{
  struct ValidationEntryMatchContext *vemc = cls;
  struct ValidationEntry *ve = value;

  if (0 == GNUNET_HELLO_address_cmp (ve->address, vemc->address))
  {
    vemc->ve = ve;
    return GNUNET_NO;
  }
  return GNUNET_YES;
}


/**
 * Iterate over validation entries and free them.
 *
 * @param cls (unused)
 * @param key peer identity (unused)
 * @param value a 'struct ValidationEntry' to clean up
 * @return GNUNET_YES (continue to iterate)
 */
static int
cleanup_validation_entry (void *cls, const GNUNET_HashCode * key, void *value)
{
  struct ValidationEntry *ve = value;

  if (NULL != ve->bc)
  {
    GST_blacklist_test_cancel (ve->bc);
    ve->bc = NULL;
  }
  GNUNET_break (GNUNET_OK ==
                GNUNET_CONTAINER_multihashmap_remove (validation_map,
                                                      &ve->pid.hashPubKey, ve));
  GNUNET_HELLO_address_free (ve->address);
  if (GNUNET_SCHEDULER_NO_TASK != ve->timeout_task)
  {
    GNUNET_SCHEDULER_cancel (ve->timeout_task);
    ve->timeout_task = GNUNET_SCHEDULER_NO_TASK;
  }
  if (GNUNET_SCHEDULER_NO_TASK != ve->revalidation_task)
  {
    GNUNET_SCHEDULER_cancel (ve->revalidation_task);
    ve->revalidation_task = GNUNET_SCHEDULER_NO_TASK;
  }
  GNUNET_free (ve);
  return GNUNET_OK;
}


/**
 * Address validation cleanup task.  Assesses if the record is no
 * longer valid and then possibly triggers its removal.
 *
 * @param cls the 'struct ValidationEntry'
 * @param tc scheduler context (unused)
 */
static void
timeout_hello_validation (void *cls,
                          const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct ValidationEntry *ve = cls;
  struct GNUNET_TIME_Absolute max;
  struct GNUNET_TIME_Relative left;

  ve->timeout_task = GNUNET_SCHEDULER_NO_TASK;
  max = GNUNET_TIME_absolute_max (ve->valid_until, ve->revalidation_block);
  left = GNUNET_TIME_absolute_get_remaining (max);
  if (left.rel_value > 0)
  {
    /* should wait a bit longer */
    ve->timeout_task =
        GNUNET_SCHEDULER_add_delayed (left, &timeout_hello_validation, ve);
    return;
  }
  GNUNET_STATISTICS_update (GST_stats,
                            gettext_noop ("# address records discarded"), 1,
                            GNUNET_NO);
  cleanup_validation_entry (NULL, &ve->pid.hashPubKey, ve);
}


/**
 * Function called with the result from blacklisting.
 * Send a PING to the other peer if a communication is allowed.
 *
 * @param cls our 'struct ValidationEntry'
 * @param pid identity of the other peer
 * @param result GNUNET_OK if the connection is allowed, GNUNET_NO if not
 */
static void
transmit_ping_if_allowed (void *cls, const struct GNUNET_PeerIdentity *pid,
                          int result)
{
  struct ValidationEntry *ve = cls;
  struct TransportPingMessage ping;
  struct GNUNET_TRANSPORT_PluginFunctions *papi;
  const struct GNUNET_MessageHeader *hello;
  ssize_t ret;
  size_t tsize;
  size_t slen;
  uint16_t hsize;

  ve->bc = NULL;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Transmitting plain PING to `%s' %s\n",
              GNUNET_i2s (pid), GST_plugins_a2s (ve->address));

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
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _
                ("Not transmitting `%s' with `%s', message too big (%u bytes!). This should not happen.\n"),
                "HELLO", "PING", (unsigned int) tsize);
    /* message too big (!?), get rid of HELLO */
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
    memcpy (&message_buf[hsize], &ping, sizeof (struct TransportPingMessage));
    memcpy (&message_buf[sizeof (struct TransportPingMessage) + hsize],
            ve->address->transport_name, slen);
    memcpy (&message_buf[sizeof (struct TransportPingMessage) + slen + hsize],
            ve->address, ve->address->address_length);
    papi = GST_plugins_find (ve->address->transport_name);
    if (papi == NULL)
      ret = -1;
    else
    {
      GNUNET_assert (papi->send != NULL);
      GNUNET_assert (papi->get_session != NULL);
      struct Session * session = papi->get_session(papi->cls, ve->address);

      if (session != NULL)
      {
        ret = papi->send (papi->cls, session,
                          message_buf, tsize,
                          PING_PRIORITY, ACCEPTABLE_PING_DELAY,
                          NULL, NULL);
      }
      else
      {
        /* Could not get a valid session */
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Could not get a valid session for `%s' %s\n",
                    GNUNET_i2s (pid), GST_plugins_a2s (ve->address));
        ret = -1;
      }
    }
  }
  if (-1 != ret)
  {
    ve->send_time = GNUNET_TIME_absolute_get ();
    GNUNET_STATISTICS_update (GST_stats,
                              gettext_noop
                              ("# PING without HELLO messages sent"), 1,
                              GNUNET_NO);
    ve->expecting_pong = GNUNET_YES;
  }
}


/**
 * Do address validation again to keep address valid.
 *
 * @param cls the 'struct ValidationEntry'
 * @param tc scheduler context (unused)
 */
static void
revalidate_address (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct ValidationEntry *ve = cls;
  struct GNUNET_TIME_Relative canonical_delay;
  struct GNUNET_TIME_Relative delay;
  struct GST_BlacklistCheck *bc;
  uint32_t rdelay;

  ve->revalidation_task = GNUNET_SCHEDULER_NO_TASK;
  delay = GNUNET_TIME_absolute_get_remaining (ve->revalidation_block);
  /* How long until we can possibly permit the next PING? */
  canonical_delay =
      (ve->in_use ==
       GNUNET_YES) ? CONNECTED_PING_FREQUENCY
      : ((GNUNET_TIME_absolute_get_remaining (ve->valid_until).rel_value >
          0) ? VALIDATED_PING_FREQUENCY : UNVALIDATED_PING_KEEPALIVE);
  if (delay.rel_value > canonical_delay.rel_value * 2)
  {
    /* situation changed, recalculate delay */
    delay = canonical_delay;
    ve->revalidation_block = GNUNET_TIME_relative_to_absolute (delay);
  }
  if (delay.rel_value > 0)
  {
    /* should wait a bit longer */
    ve->revalidation_task =
        GNUNET_SCHEDULER_add_delayed (delay, &revalidate_address, ve);
    return;
  }
  ve->revalidation_block = GNUNET_TIME_relative_to_absolute (canonical_delay);

  /* schedule next PINGing with some extra random delay to avoid synchronous re-validations */
  rdelay =
      GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK,
                                canonical_delay.rel_value);
  delay =
      GNUNET_TIME_relative_add (canonical_delay,
                                GNUNET_TIME_relative_multiply
                                (GNUNET_TIME_UNIT_MILLISECONDS, rdelay));
  ve->revalidation_task =
      GNUNET_SCHEDULER_add_delayed (delay, &revalidate_address, ve);

  /* start PINGing by checking blacklist */
  GNUNET_STATISTICS_update (GST_stats,
                            gettext_noop ("# address revalidations started"), 1,
                            GNUNET_NO);
  bc = GST_blacklist_test_allowed (&ve->pid, ve->address->transport_name,
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
 * @param public_key public key of the peer, NULL for unknown
 * @param address address to find
 * @return validation entry matching the given specifications, NULL
 *         if we don't have an existing entry and no public key was given
 */
static struct ValidationEntry *
find_validation_entry (const struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded
                       *public_key, const struct GNUNET_HELLO_Address *address)
{
  struct ValidationEntryMatchContext vemc;
  struct ValidationEntry *ve;

  vemc.ve = NULL;
  vemc.address = address;
  GNUNET_CONTAINER_multihashmap_get_multiple (validation_map,
                                              &address->peer.hashPubKey,
                                              &validation_entry_match, &vemc);
  if (NULL != (ve = vemc.ve))
    return ve;
  if (public_key == NULL)
    return NULL;
  ve = GNUNET_malloc (sizeof (struct ValidationEntry));
  ve->address = GNUNET_HELLO_address_copy (address);
  ve->public_key = *public_key;
  ve->pid = address->peer;
  ve->latency = GNUNET_TIME_UNIT_FOREVER_REL;
  ve->challenge =
      GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_NONCE, UINT32_MAX);
  ve->timeout_task =
      GNUNET_SCHEDULER_add_delayed (UNVALIDATED_PING_KEEPALIVE,
                                    &timeout_hello_validation, ve);
  GNUNET_CONTAINER_multihashmap_put (validation_map, &address->peer.hashPubKey,
                                     ve,
                                     GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE);
  ve->expecting_pong = GNUNET_NO;
  return ve;
}


/**
 * Iterator which adds the given address to the set of validated
 * addresses.
 *
 * @param cls original HELLO message
 * @param address the address
 * @param expiration expiration time
 * @return GNUNET_OK (keep the address)
 */
static int
add_valid_address (void *cls, const struct GNUNET_HELLO_Address *address,
                   struct GNUNET_TIME_Absolute expiration)
{
  const struct GNUNET_HELLO_Message *hello = cls;
  struct ValidationEntry *ve;
  struct GNUNET_PeerIdentity pid;
  struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded public_key;

  if (GNUNET_TIME_absolute_get_remaining (expiration).rel_value == 0)
    return GNUNET_OK;           /* expired */
  if ((GNUNET_OK != GNUNET_HELLO_get_id (hello, &pid)) ||
      (GNUNET_OK != GNUNET_HELLO_get_key (hello, &public_key)))
  {
    GNUNET_break (0);
    return GNUNET_OK;           /* invalid HELLO !? */
  }
  if (0 == memcmp (&GST_my_identity, &pid, sizeof (struct GNUNET_PeerIdentity)))
  {
    /* Peerinfo returned own identity, skip validation */
    return GNUNET_OK;
  }

  ve = find_validation_entry (&public_key, address);
  ve->valid_until = GNUNET_TIME_absolute_max (ve->valid_until, expiration);

  if (GNUNET_SCHEDULER_NO_TASK == ve->revalidation_task)
    ve->revalidation_task = GNUNET_SCHEDULER_add_now (&revalidate_address, ve);
  GNUNET_ATS_address_update (GST_ats, address, NULL, NULL, 0);
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
  GNUNET_assert (NULL ==
                 GNUNET_HELLO_iterate_addresses (hello, GNUNET_NO,
                                                 &add_valid_address,
                                                 (void *) hello));
}


/**
 * Start the validation subsystem.
 */
void
GST_validation_start ()
{
  validation_map = GNUNET_CONTAINER_multihashmap_create (VALIDATION_MAP_SIZE);
  pnc = GNUNET_PEERINFO_notify (GST_cfg, &process_peerinfo_hello, NULL);
}


/**
 * Stop the validation subsystem.
 */
void
GST_validation_stop ()
{
  struct CheckHelloValidatedContext *chvc;

  GNUNET_CONTAINER_multihashmap_iterate (validation_map,
                                         &cleanup_validation_entry, NULL);
  GNUNET_CONTAINER_multihashmap_destroy (validation_map);
  validation_map = NULL;
  while (NULL != (chvc = chvc_head))
  {
    GNUNET_CONTAINER_DLL_remove (chvc_head, chvc_tail, chvc);
    GNUNET_free (chvc);
  }
  GNUNET_PEERINFO_notify_cancel (pnc);
}


/**
 * Send the given PONG to the given address.
 *
 * @param cls the PONG message
 * @param public_key public key for the peer, never NULL
 * @param valid_until is ZERO if we never validated the address,
 *                    otherwise a time up to when we consider it (or was) valid
 * @param validation_block  is FOREVER if the address is for an unsupported plugin (from PEERINFO)
 *                          is ZERO if the address is considered valid (no validation needed)
 *                          otherwise a time in the future if we're currently denying re-validation
 * @param address target address
 */
static void
multicast_pong (void *cls,
                const struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded
                *public_key, struct GNUNET_TIME_Absolute valid_until,
                struct GNUNET_TIME_Absolute validation_block,
                const struct GNUNET_HELLO_Address *address)
{
  struct TransportPongMessage *pong = cls;
  struct GNUNET_TRANSPORT_PluginFunctions *papi;

  papi = GST_plugins_find (address->transport_name);
  if (papi == NULL)
    return;

  GNUNET_assert (papi->send != NULL);
  GNUNET_assert (papi->get_session != NULL);

  struct Session * session = papi->get_session(papi->cls, address);
  if (session == NULL)
  {
     GNUNET_break (0);
     return;
  }

  papi->send (papi->cls, session,
              (const char *) pong, ntohs (pong->header.size),
              PONG_PRIORITY, ACCEPTABLE_PING_DELAY,
              NULL, NULL);
}


/**
 * We've received a PING.  If appropriate, generate a PONG.
 *
 * @param sender peer sending the PING
 * @param hdr the PING
 * @param sender_address the sender address as we got it
 * @param session session we got the PING from
 */
void
GST_validation_handle_ping (const struct GNUNET_PeerIdentity *sender,
                            const struct GNUNET_MessageHeader *hdr,
                            const struct GNUNET_HELLO_Address *sender_address,
                            struct Session *session)
{
  const struct TransportPingMessage *ping;
  struct TransportPongMessage *pong;
  struct GNUNET_TRANSPORT_PluginFunctions *papi;
  struct GNUNET_CRYPTO_RsaSignature *sig_cache;
  struct GNUNET_TIME_Absolute *sig_cache_exp;
  const char *addr;
  const char *addrend;
  size_t alen;
  size_t slen;
  ssize_t ret;
  struct GNUNET_HELLO_Address address;

  if (ntohs (hdr->size) < sizeof (struct TransportPingMessage))
  {
    GNUNET_break_op (0);
    return;
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
    return;
  }
  GNUNET_STATISTICS_update (GST_stats,
                            gettext_noop ("# PING messages received"), 1,
                            GNUNET_NO);
  addr = (const char *) &ping[1];
  alen = ntohs (hdr->size) - sizeof (struct TransportPingMessage);
  /* peer wants to confirm that this is one of our addresses, this is what is
   * used for address validation */

  sig_cache = NULL;
  sig_cache_exp = NULL;

  if (0 < alen)
  {
    addrend = memchr (addr, '\0', alen);
    if (NULL == addrend)
    {
      GNUNET_break_op (0);
      return;
    }
    addrend++;
    slen = strlen (addr) + 1;
    alen -= slen;
    address.address = addrend;
    address.address_length = alen;
    address.transport_name = addr;
    address.peer = *sender;
    if (GNUNET_YES !=
        GST_hello_test_address (&address, &sig_cache, &sig_cache_exp))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                  _
                  ("Not confirming PING with address `%s' since I cannot confirm having this address.\n"),
                  GST_plugins_a2s (&address));
      return;
    }
  }
  else
  {
    addrend = NULL;             /* make gcc happy */
    slen = 0;
    static struct GNUNET_CRYPTO_RsaSignature no_address_signature;
    static struct GNUNET_TIME_Absolute no_address_signature_expiration;

    sig_cache = &no_address_signature;
    sig_cache_exp = &no_address_signature_expiration;
  }

  pong = GNUNET_malloc (sizeof (struct TransportPongMessage) + alen + slen);
  pong->header.size =
      htons (sizeof (struct TransportPongMessage) + alen + slen);
  pong->header.type = htons (GNUNET_MESSAGE_TYPE_TRANSPORT_PONG);
  pong->purpose.size =
      htonl (sizeof (struct GNUNET_CRYPTO_RsaSignaturePurpose) +
             sizeof (uint32_t) + sizeof (struct GNUNET_TIME_AbsoluteNBO) +
             alen + slen);
  pong->purpose.purpose = htonl (GNUNET_SIGNATURE_PURPOSE_TRANSPORT_PONG_OWN);
  pong->challenge = ping->challenge;
  pong->addrlen = htonl (alen + slen);
  memcpy (&pong[1], addr, slen);
  memcpy (&((char *) &pong[1])[slen], addrend, alen);
  if (GNUNET_TIME_absolute_get_remaining (*sig_cache_exp).rel_value <
      PONG_SIGNATURE_LIFETIME.rel_value / 4)
  {
    /* create / update cached sig */
#if DEBUG_TRANSPORT
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Creating PONG signature to indicate ownership.\n");
#endif
    *sig_cache_exp = GNUNET_TIME_relative_to_absolute (PONG_SIGNATURE_LIFETIME);
    pong->expiration = GNUNET_TIME_absolute_hton (*sig_cache_exp);
    GNUNET_assert (GNUNET_OK ==
                   GNUNET_CRYPTO_rsa_sign (GST_my_private_key, &pong->purpose,
                                           sig_cache));
  }
  else
  {
    pong->expiration = GNUNET_TIME_absolute_hton (*sig_cache_exp);
  }
  pong->signature = *sig_cache;

  GNUNET_assert (sender_address != NULL);

  /* first see if the session we got this PING from can be used to transmit
   * a response reliably */
  papi = GST_plugins_find (sender_address->transport_name);
  if (papi == NULL)
    ret = -1;
  else
  {
    GNUNET_assert (papi->send != NULL);
    GNUNET_assert (papi->get_session != NULL);

    if (session == NULL)
    {
      session = papi->get_session (papi->cls, sender_address);
    }
    if (session == NULL)
    {
      GNUNET_break (0);
      ret = -1;
    }
    else
    {
      ret = papi->send (papi->cls, session,
                        (const char *) pong, ntohs (pong->header.size),
                        PONG_PRIORITY, ACCEPTABLE_PING_DELAY,
                        NULL, NULL);
    }
  }
  if (ret != -1)
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
    return;
  }

  /* no reliable method found, try transmission via all known addresses */
  GNUNET_STATISTICS_update (GST_stats,
                            gettext_noop
                            ("# PONGs multicast to all available addresses"), 1,
                            GNUNET_NO);
  GST_validation_get_addresses (sender, &multicast_pong, pong);
  GNUNET_free (pong);
}


/**
 * Context for the 'validate_address' function
 */
struct ValidateAddressContext
{
  /**
   * Hash of the public key of the peer whose address is being validated.
   */
  struct GNUNET_PeerIdentity pid;

  /**
   * Public key of the peer whose address is being validated.
   */
  struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded public_key;
};


/**
 * Iterator callback to go over all addresses and try to validate them
 * (unless blocked or already validated).
 *
 * @param cls pointer to a 'struct ValidateAddressContext'
 * @param address the address
 * @param expiration expiration time
 * @return GNUNET_OK (keep the address)
 */
static int
validate_address_iterator (void *cls,
                           const struct GNUNET_HELLO_Address *address,
                           struct GNUNET_TIME_Absolute expiration)
{
  const struct ValidateAddressContext *vac = cls;
  struct ValidationEntry *ve;

  if (GNUNET_TIME_absolute_get_remaining (expiration).rel_value == 0)
    return GNUNET_OK;           /* expired */
  ve = find_validation_entry (&vac->public_key, address);
  if (GNUNET_SCHEDULER_NO_TASK == ve->revalidation_task)
    ve->revalidation_task = GNUNET_SCHEDULER_add_now (&revalidate_address, ve);
  return GNUNET_OK;
}


/**
 * Add the validated peer address to the HELLO.
 *
 * @param cls the 'struct ValidationEntry' with the validated address
 * @param max space in buf
 * @param buf where to add the address
 * @return number of bytes written, 0 to signal the
 *         end of the iteration.
 */
static size_t
add_valid_peer_address (void *cls, size_t max, void *buf)
{
  struct ValidationEntry *ve = cls;

  if (GNUNET_YES == ve->copied)
    return 0;                   /* terminate */
  ve->copied = GNUNET_YES;
  return GNUNET_HELLO_add_address (ve->address, ve->valid_until, buf, max);
}


/**
 * We've received a PONG.  Check if it matches a pending PING and
 * mark the respective address as confirmed.
 *
 * @param sender peer sending the PONG
 * @param hdr the PONG
 */
void
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

  if (ntohs (hdr->size) < sizeof (struct TransportPongMessage))
  {
    GNUNET_break_op (0);
    return;
  }
  GNUNET_STATISTICS_update (GST_stats,
                            gettext_noop ("# PONG messages received"), 1,
                            GNUNET_NO);

  pong = (const struct TransportPongMessage *) hdr;
  tname = (const char *) &pong[1];
  size = ntohs (hdr->size) - sizeof (struct TransportPongMessage);
  addr = memchr (tname, '\0', size);
  if (NULL == addr)
  {
    GNUNET_break_op (0);
    return;
  }
  addr++;
  slen = strlen (tname) + 1;
  addrlen = size - slen;
  address.peer = *sender;
  address.address = addr;
  address.address_length = addrlen;
  address.transport_name = tname;
  ve = find_validation_entry (NULL, &address);
  if ((NULL == ve) || (ve->expecting_pong == GNUNET_NO))
  {
    GNUNET_STATISTICS_update (GST_stats,
                              gettext_noop
                              ("# PONGs dropped, no matching pending validation"),
                              1, GNUNET_NO);
    return;
  }
  /* now check that PONG is well-formed */
  if (0 != memcmp (&ve->pid, sender, sizeof (struct GNUNET_PeerIdentity)))
  {
    GNUNET_break_op (0);
    return;
  }

  if (GNUNET_OK !=
      GNUNET_CRYPTO_rsa_verify (GNUNET_SIGNATURE_PURPOSE_TRANSPORT_PONG_OWN,
                                &pong->purpose, &pong->signature,
                                &ve->public_key))
  {
    GNUNET_break_op (0);
    return;
  }

  if (GNUNET_TIME_absolute_get_remaining
      (GNUNET_TIME_absolute_ntoh (pong->expiration)).rel_value == 0)
  {
    GNUNET_STATISTICS_update (GST_stats,
                              gettext_noop
                              ("# PONGs dropped, signature expired"), 1,
                              GNUNET_NO);
    return;
  }
#if DEBUG_TRANSPORT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Address validated for peer `%s' with plugin `%s': `%s'\n",
              GNUNET_i2s (sender), tname, GST_plugins_a2s (tname, addr,
                                                           addrlen));
#endif

  /* validity achieved, remember it! */
  ve->expecting_pong = GNUNET_NO;
  ve->valid_until = GNUNET_TIME_relative_to_absolute (HELLO_ADDRESS_EXPIRATION);
  ve->latency = GNUNET_TIME_absolute_get_duration (ve->send_time);
  {
    struct GNUNET_ATS_Information ats;

    ats.type = htonl (GNUNET_ATS_QUALITY_NET_DELAY);
    ats.value = htonl ((uint32_t) ve->latency.rel_value);
    GNUNET_ATS_address_update (GST_ats, ve->address, NULL, &ats, 1);
  }
  /* build HELLO to store in PEERINFO */
  ve->copied = GNUNET_NO;
  hello = GNUNET_HELLO_create (&ve->public_key, &add_valid_peer_address, ve);
  GNUNET_PEERINFO_add_peer (GST_peerinfo, hello);
  GNUNET_free (hello);
}


/**
 * We've received a HELLO, check which addresses are new and trigger
 * validation.
 *
 * @param hello the HELLO we received
 */
void
GST_validation_handle_hello (const struct GNUNET_MessageHeader *hello)
{
  const struct GNUNET_HELLO_Message *hm =
      (const struct GNUNET_HELLO_Message *) hello;
  struct ValidateAddressContext vac;
  struct GNUNET_HELLO_Message *h;

  if ((GNUNET_OK != GNUNET_HELLO_get_id (hm, &vac.pid)) ||
      (GNUNET_OK != GNUNET_HELLO_get_key (hm, &vac.public_key)))
  {
    /* malformed HELLO */
    GNUNET_break (0);
    return;
  }
  if (0 ==
      memcmp (&GST_my_identity, &vac.pid, sizeof (struct GNUNET_PeerIdentity)))
    return;
  /* Add peer identity without addresses to peerinfo service */
  h = GNUNET_HELLO_create (&vac.public_key, NULL, NULL);
  GNUNET_PEERINFO_add_peer (GST_peerinfo, h);
#if VERBOSE_VALIDATION
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              _("Adding `%s' without addresses for peer `%s'\n"), "HELLO",
              GNUNET_i2s (&vac.pid));
#endif
  GNUNET_free (h);
  GNUNET_assert (NULL ==
                 GNUNET_HELLO_iterate_addresses (hm, GNUNET_NO,
                                                 &validate_address_iterator,
                                                 &vac));
}


/**
 * Closure for 'iterate_addresses'
 */
struct IteratorContext
{
  /**
   * Function to call on each address.
   */
  GST_ValidationAddressCallback cb;

  /**
   * Closure for 'cb'.
   */
  void *cb_cls;

};


/**
 * Call the callback in the closure for each validation entry.
 *
 * @param cls the 'struct GST_ValidationIteratorContext'
 * @param key the peer's identity
 * @param value the 'struct ValidationEntry'
 * @return GNUNET_OK (continue to iterate)
 */
static int
iterate_addresses (void *cls, const GNUNET_HashCode * key, void *value)
{
  struct IteratorContext *ic = cls;
  struct ValidationEntry *ve = value;

  ic->cb (ic->cb_cls, &ve->public_key, ve->valid_until, ve->revalidation_block,
          ve->address);
  return GNUNET_OK;
}


/**
 * Call the given function for each address for the given target.
 * Can either give a snapshot (synchronous API) or be continuous.
 *
 * @param target peer information is requested for
 * @param cb function to call; will not be called after this function returns
 * @param cb_cls closure for 'cb'
 */
void
GST_validation_get_addresses (const struct GNUNET_PeerIdentity *target,
                              GST_ValidationAddressCallback cb, void *cb_cls)
{
  struct IteratorContext ic;

  ic.cb = cb;
  ic.cb_cls = cb_cls;
  GNUNET_CONTAINER_multihashmap_get_multiple (validation_map,
                                              &target->hashPubKey,
                                              &iterate_addresses, &ic);
}


/**
 * Update if we are using an address for a connection actively right now.
 * Based on this, the validation module will measure latency for the
 * address more or less often.
 *
 * @param address the address
 * @param session the session
 * @param in_use GNUNET_YES if we are now using the address for a connection,
 *               GNUNET_NO if we are no longer using the address for a connection
 */
void
GST_validation_set_address_use (const struct GNUNET_HELLO_Address *address,
                                struct Session *session,
                                int in_use)
{
  struct ValidationEntry *ve;

  if (NULL != address)
    ve = find_validation_entry (NULL, address);
  else
    ve = NULL;                  /* FIXME: lookup based on session... */
  if (NULL == ve)
  {
    /* this can happen for inbound connections (sender_address_len == 0); */
    return;
  }
  if (ve->in_use == in_use)
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "GST_validation_set_address_use: %s %s: ve->in_use %i <-> in_use %i\n",
                GNUNET_i2s (&address->peer), GST_plugins_a2s (address), ve->in_use,
                in_use);
  GNUNET_break (ve->in_use != in_use);  /* should be different... */
  ve->in_use = in_use;
  if (in_use == GNUNET_YES)
  {
    /* from now on, higher frequeny, so reschedule now */
    GNUNET_SCHEDULER_cancel (ve->revalidation_task);
    ve->revalidation_task = GNUNET_SCHEDULER_add_now (&revalidate_address, ve);
  }
}


/**
 * Query validation about the latest observed latency on a given
 * address.
 *
 * @param sender peer
 * @param address the address
 * @param session session
 * @return observed latency of the address, FOREVER if the address was
 *         never successfully validated
 */
struct GNUNET_TIME_Relative
GST_validation_get_address_latency (const struct GNUNET_PeerIdentity *sender,
                                    const struct GNUNET_HELLO_Address *address,
                                    struct Session *session)
{
  struct ValidationEntry *ve;

  if (NULL == address)
  {
    GNUNET_break (0);           // FIXME: support having latency only with session...
    return GNUNET_TIME_UNIT_FOREVER_REL;
  }
  ve = find_validation_entry (NULL, address);
  if (NULL == ve)
    return GNUNET_TIME_UNIT_FOREVER_REL;
  return ve->latency;
}


/* end of file gnunet-service-transport_validation.c */

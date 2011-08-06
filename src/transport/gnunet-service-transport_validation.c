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
#include "gnunet-service-transport.h"
#include "gnunet_hello_lib.h"
#include "gnunet_peerinfo_service.h"

/**
 * How long until a HELLO verification attempt should time out?
 * Must be rather small, otherwise a partially successful HELLO
 * validation (some addresses working) might not be available
 * before a client's request for a connection fails for good.
 * Besides, if a single request to an address takes a long time,
 * then the peer is unlikely worthwhile anyway.
 */
#define HELLO_VERIFICATION_TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 15)

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
 * How long before an existing address expires should we again try to
 * validate it?  Must be (significantly) smaller than
 * HELLO_ADDRESS_EXPIRATION.
 */
#define HELLO_REVALIDATION_START_TIME GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_HOURS, 1)

/**
 * Size of the validation map hashmap.
 */
#define VALIDATION_MAP_SIZE 256


/**
 * Information about an address under validation
 */
struct ValidationEntry 
{

  /**
   * Name of the transport.
   */
  char *transport_name;

  /**
   * The address, actually a pointer to the end
   * of this struct.  Do not free!
   */
  const void *addr;

  /**
   * The identity of the peer.
   */
  struct GNUNET_PeerIdentity pid;

  /**
   * ID of task that will clean up this entry if nothing happens.
   */
  GNUNET_SCHEDULER_TaskIdentifier timeout_task;

  /**
   * At what time did we send the latest validation request?
   */
  struct GNUNET_TIME_Absolute send_time;

  /**
   * When did we last succeed with validating this address?
   * FOREVER if the address has not been validated (we're currently checking)
   * ZERO if the address was validated a long time ago (from PEERINFO)
   * otherwise a time in the past if this process validated the address
   */
  struct GNUNET_TIME_Absolute last_validated_at;

  /**
   * How long until we can try to validate this address again?
   * FOREVER if the address is for an unsupported plugin (from PEERINFO)
   * ZERO if the address is considered valid (no validation needed)
   * otherwise a time in the future if we're currently denying re-validation
   */
  struct GNUNET_TIME_Absolute validation_block;
					    
  /**
   * Challenge number we used.
   */
  uint32_t challenge;

  /**
   * Length of addr.
   */
  size_t addrlen;

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

  /**
   * Context for peerinfo iteration.
   */
  struct GNUNET_PEERINFO_IteratorContext *piter;

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
 * Map of PeerIdentities to 'struct GST_ValidationIteratorContext's.
 */
static struct GNUNET_CONTAINER_MultiHashMap *notify_map;


/**
 * Start the validation subsystem.
 */
void 
GST_validation_start ()
{
  validation_map = GNUNET_CONTAINER_multihashmap_create (VALIDATION_MAP_SIZE);
  notify_map = GNUNET_CONTAINER_multihashmap_create (VALIDATION_MAP_SIZE);
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
cleanup_validation_entry (void *cls,
			  const GNUNET_HashCode *key,
			  void *value)
{
  struct ValidationEntry *ve = value;
    
  GNUNET_free (ve->transport_name);
  if (GNUNET_SCHEDULER_NO_TASK != ve->timeout_task)
    {
      GNUNET_SCHEDULER_cancel (ve->timeout_task);
      ve->timeout_task = GNUNET_SCHEDULER_NO_TASK;
    }
  GNUNET_free (ve);
  return GNUNET_OK;
}


/**
 * Stop the validation subsystem.
 */
void
GST_validation_stop ()
{
  struct CheckHelloValidatedContext *chvc;

  GNUNET_CONTAINER_multihashmap_iterate (validation_map,
					 &cleanup_validation_entry,
					 NULL);
  GNUNET_CONTAINER_multihashmap_destroy (validation_map);
  validation_map = NULL;
  GNUNET_assert (GNUNET_CONTAINER_multihashmap_size (notify_map) == 0);
  GNUNET_CONTAINER_multihashmap_destroy (notify_map);
  notify_map = NULL;
  while (NULL != (chvc = chvc_head))
    {
      GNUNET_CONTAINER_DLL_remove (chvc_head,
				   chvc_tail,
				   chvc);
      GNUNET_PEERINFO_iterate_cancel (chvc->piter);      
      GNUNET_free (chvc);
    }
}


#if 0
/**
 * Address validation cleanup task (record no longer needed).
 *
 * @param cls the 'struct ValidationEntry'
 * @param tc scheduler context (unused)
 */
static void
timeout_hello_validation (void *cls, 
			  const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct ValidationEntry *va = cls;

  va->timeout_task = GNUNET_SCHEDULER_NO_TASK;
  GNUNET_STATISTICS_update (GST_stats,
			    gettext_noop ("# address records discarded"),
			    1,
			    GNUNET_NO);
  GNUNET_break (GNUNET_OK ==
                GNUNET_CONTAINER_multihashmap_remove (validation_map,
						      &va->pid.hashPubKey,
						      va));
  GNUNET_free (va->transport_name);
  GNUNET_free (va);
}
#endif


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
   * Transport name we're looking for.
   */
  const char *transport_name;

  /**
   * Address we're interested in.
   */
  const char *addr;

  /**
   * Number of bytes in 'addr'.
   */
  size_t addrlen;
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
validation_entry_match (void *cls,
			const GNUNET_HashCode *key,
			void *value)
{
  struct ValidationEntryMatchContext *vemc = cls;
  struct ValidationEntry *ve = value;

  if ( (ve->addrlen == vemc->addrlen) &&
       (0 == memcmp (ve->addr, vemc->addr, ve->addrlen)) &&
       (0 == strcmp (ve->transport_name, vemc->transport_name)) )
    {
      vemc->ve = ve;
      return GNUNET_NO;
    }
  return GNUNET_YES;
}


/**
 * Find a ValidationEntry entry for the given neighbour that matches
 * the given address and transport.  If none exists, create one (but
 * without starting any validation).
 *
 * @param neighbour which peer we care about
 * @param tname name of the transport plugin
 * @param session session to look for, NULL for 'any'; otherwise
 *        can be used for the service to "learn" this session ID
 *        if 'addr' matches
 * @param addr binary address
 * @param addrlen length of addr
 * @return validation entry matching the given specifications
 */
static struct ValidationEntry *
find_validation_entry (struct GNUNET_PeerIdentity *neighbour,
		       const char *tname,
		       const char *addr,
		       size_t addrlen)
{
  struct ValidationEntryMatchContext vemc;
  struct ValidationEntry *ve;

  vemc.ve = NULL;
  vemc.transport_name = tname;
  vemc.addr = addr;
  vemc.addrlen = addrlen;
  GNUNET_CONTAINER_multihashmap_get_multiple (validation_map,
					      &neighbour->hashPubKey,
					      &validation_entry_match,
					      &vemc);
  if (NULL != (ve = vemc.ve))
    return ve;
  ve = GNUNET_malloc (sizeof (struct ValidationEntry) + addrlen);
  ve->transport_name = GNUNET_strdup (tname);
  ve->addr = (void*) &ve[1];
  ve->pid = *neighbour;
  memcpy (&ve[1], addr, addrlen);
  ve->addrlen = addrlen;
  ve->last_validated_at = GNUNET_TIME_UNIT_FOREVER_ABS;
  GNUNET_CONTAINER_multihashmap_put (validation_map,
				     &neighbour->hashPubKey,
				     ve,
				     GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE);
  return ve;
}


/**
 * We've received a PING.  If appropriate, generate a PONG.
 *
 * @param sender peer sending the PING
 * @param hdr the PING
 * @param plugin_name name of plugin that received the PING
 * @param sender_address address of the sender as known to the plugin, NULL
 *                       if we did not initiate the connection
 * @param sender_address_len number of bytes in sender_address
 */
void
GST_validation_handle_ping (const struct GNUNET_PeerIdentity *sender,
			    const struct GNUNET_MessageHeader *hdr,
			    const char *plugin_name,
			    const void *sender_address,
			    size_t sender_address_len)
{
}


/**
 * We've received a PONG.  Check if it matches a pending PING and
 * mark the respective address as confirmed.
 *
 * @param sender peer sending the PONG
 * @param hdr the PONG
 * @param plugin_name name of plugin that received the PONG
 * @param sender_address address of the sender as known to the plugin, NULL
 *                       if we did not initiate the connection
 * @param sender_address_len number of bytes in sender_address
 */
void
GST_validation_handle_pong (const struct GNUNET_PeerIdentity *sender,
			    const struct GNUNET_MessageHeader *hdr,
			    const char *plugin_name,
			    const void *sender_address,
			    size_t sender_address_len)
{
}


/**
 * Iterator callback to go over all addresses and try to validate them
 * (unless blocked or already validated).
 *
 * @param cls pointer to the 'struct PeerIdentity' of the peer
 * @param tname name of the transport
 * @param expiration expiration time
 * @param addr the address
 * @param addrlen length of the address
 * @return GNUNET_OK (keep the address)
 */
static int
validate_address (void *cls,
		  const char *tname,
		  struct GNUNET_TIME_Absolute expiration,
		  const void *addr, 
		  uint16_t addrlen)
{
  struct GNUNET_PeerIdentity *pid = cls;
  struct ValidationEntry *ve;
  
  if (GNUNET_TIME_absolute_get_remaining (expiration).rel_value == 0)
    return GNUNET_OK; /* expired */
  ve = find_validation_entry (pid, tname, addr, addrlen);
  // FIXME: check if validated/blocked, if not start validation...
  ve++; // make compiler happy
  return GNUNET_OK;
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
  const struct GNUNET_HELLO_Message* hm = (const struct GNUNET_HELLO_Message*) hello;
  struct GNUNET_PeerIdentity pid;

  if (GNUNET_OK !=
      GNUNET_HELLO_get_id (hm, &pid))    
    {
      /* malformed HELLO */
      GNUNET_break (0);
      return; 
    }
  GNUNET_assert (NULL ==
		 GNUNET_HELLO_iterate_addresses (hm,
						 GNUNET_NO,
						 &validate_address,
						 &pid));
}


/**
 * Opaque handle to stop incremental validation address callbacks.
 */
struct GST_ValidationIteratorContext
{
  /**
   * Function to call on each address.
   */
  GST_ValidationAddressCallback cb;

  /**
   * Closure for 'cb'.
   */
  void *cb_cls;

  /**
   * Which peer are we monitoring?
   */   
  struct GNUNET_PeerIdentity target;
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
iterate_addresses (void *cls,
		   const GNUNET_HashCode *key,
		   void *value)
{
  struct GST_ValidationIteratorContext *vic = cls;
  struct ValidationEntry *ve = value;

  vic->cb (vic->cb_cls,
	   &ve->pid,
	   ve->last_validated_at,
	   ve->validation_block,
	   ve->transport_name,
	   ve->addr,
	   ve->addrlen);
  return GNUNET_OK;
}


/**
 * Call the given function for each address for the given target.
 * Can either give a snapshot (synchronous API) or be continuous.
 *
 * @param target peer information is requested for
 * @param snapshot_only GNUNET_YES to iterate over addresses once, GNUNET_NO to
 *                      continue to give information about addresses as it evolves
 * @param cb function to call; will not be called after this function returns
 *                             if snapshot_only is GNUNET_YES
 * @param cb_cls closure for 'cb'
 * @return context to cancel, NULL if 'snapshot_only' is GNUNET_YES
 */
struct GST_ValidationIteratorContext *
GST_validation_get_addresses (const struct GNUNET_PeerIdentity *target,
			      int snapshot_only,
			      GST_ValidationAddressCallback cb,
			      void *cb_cls)
{
  struct GST_ValidationIteratorContext *vic;

  vic = GNUNET_malloc (sizeof (struct GST_ValidationIteratorContext));
  vic->cb = cb;
  vic->cb_cls = cb_cls;
  vic->target = *target;
  GNUNET_CONTAINER_multihashmap_get_multiple (validation_map,
					      &target->hashPubKey,
					      &iterate_addresses,
					      vic);
  if (GNUNET_YES == snapshot_only)
    {
      GNUNET_free (vic);
      return NULL;
    }
  GNUNET_CONTAINER_multihashmap_put (notify_map,
				     &target->hashPubKey,
				     vic,
				     GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE);
  return vic;
}


/**
 * Cancel an active validation address iteration.
 *
 * @param ctx the context of the operation that is cancelled
 */
void
GST_validation_get_addresses_cancel (struct GST_ValidationIteratorContext *ctx)
{
  GNUNET_assert (GNUNET_OK ==
		 GNUNET_CONTAINER_multihashmap_remove (notify_map,
						       &ctx->target.hashPubKey,
						       ctx));
  GNUNET_free (ctx);
}


/* end of file gnunet-service-transport_validation.c */

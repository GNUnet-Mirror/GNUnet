/*
     This file is part of GNUnet.
     (C) 2015 Christian Grothoff (and other contributing authors)

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
 * @file transport/gnunet-service-transport_ats.h
 * @brief interfacing between transport and ATS service
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet-service-transport.h"
#include "gnunet-service-transport_ats.h"
#include "gnunet-service-transport_manipulation.h"
#include "gnunet-service-transport_plugins.h"
#include "gnunet_ats_service.h"


/**
 * Information we track for each address known to ATS.
 */
struct AddressInfo
{

  /**
   * The address (with peer identity).
   */
  struct GNUNET_HELLO_Address *address;

  /**
   * Session (can be NULL)
   */
  struct Session *session;

  /**
   * Record with ATS API for the address.
   */
  struct GNUNET_ATS_AddressRecord *ar;
};


/**
 * Map from peer identities to one or more `struct AddressInfo` values
 * for the peer.
 */
static struct GNUNET_CONTAINER_MultiPeerMap *p2a;


/**
 * Closure for #find_ai().
 */
struct FindClosure
{

  /**
   * Session to look for (only used if the address is inbound).
   */
  struct Session *session;

  /**
   * Address to look for.
   */
  const struct GNUNET_HELLO_Address *address;

  /**
   * Where to store the result.
   */
  struct AddressInfo *ret;

};


/**
 * Find matching address info.
 *
 * @param cls the `struct FindClosure`
 * @param key which peer is this about
 * @param value the `struct AddressInfo`
 * @return #GNUNET_YES to continue to iterate, #GNUNET_NO if we found the value
 */
static int
find_ai_cb (void *cls,
            const struct GNUNET_PeerIdentity *key,
            void *value)
{
  struct FindClosure *fc = cls;
  struct AddressInfo *ai = value;

  if ( (0 ==
        GNUNET_HELLO_address_cmp (fc->address,
                                  ai->address) ) &&
       (fc->session == ai->session) )
  {
    fc->ret = ai;
    return GNUNET_NO;
  }
  GNUNET_assert ( (fc->session != ai->session) ||
                  (NULL == ai->session) );
  return GNUNET_YES;
}


/**
 * Find the address information struct for the
 * given address and session.
 *
 * @param address address to look for
 * @param session session to match for inbound connections
 * @return NULL if this combination is unknown
 */
static struct AddressInfo *
find_ai (const struct GNUNET_HELLO_Address *address,
         struct Session *session)
{
  struct FindClosure fc;

  fc.address = address;
  fc.session = session;
  fc.ret = NULL;
  GNUNET_CONTAINER_multipeermap_get_multiple (p2a,
                                              &address->peer,
                                              &find_ai_cb,
                                              &fc);
  return fc.ret;
}


/**
 * Test if ATS knows about this address.
 *
 * @param address the address
 * @param session the session
 * @return #GNUNET_YES if address is known, #GNUNET_NO if not.
 */
int
GST_ats_is_known (const struct GNUNET_HELLO_Address *address,
                  struct Session *session)
{
  return (NULL != find_ai (address, session)) ? GNUNET_YES : GNUNET_NO;
}


/**
 * Notify ATS about the new address including the network this address is
 * located in.
 *
 * @param address the address
 * @param session the session
 * @param ats ats information
 * @param ats_count number of @a ats information
 */
void
GST_ats_add_address (const struct GNUNET_HELLO_Address *address,
                     struct Session *session,
                     const struct GNUNET_ATS_Information *ats,
                     uint32_t ats_count)
{
  struct GNUNET_TRANSPORT_PluginFunctions *papi;
  struct GNUNET_ATS_Information ats2[ats_count + 1];
  struct GNUNET_ATS_AddressRecord *ar;
  struct AddressInfo *ai;
  uint32_t net;

  /* valid new address, let ATS know! */
  if (NULL == address->transport_name)
  {
    GNUNET_break(0);
    return;
  }
  if (GNUNET_YES ==
      GNUNET_HELLO_address_check_option (address,
                                         GNUNET_HELLO_ADDRESS_INFO_INBOUND))
  {
    GNUNET_break (NULL != session);
  }
  ai = find_ai (address, session);
  if (NULL != ai)
  {
    GNUNET_break (0);
    return;
  }
  if (NULL == (papi = GST_plugins_find (address->transport_name)))
  {
    /* we don't have the plugin for this address */
    GNUNET_assert (0);
    return;
  }
  if (NULL != session)
  {
    net = papi->get_network (papi->cls, session);
    if (GNUNET_ATS_NET_UNSPECIFIED == net)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  _ ("Could not obtain a valid network for `%s' %s (%s)\n"),
                  GNUNET_i2s (&address->peer),
                  GST_plugins_a2s (address),
                  address->transport_name);
      return;
    }
    ats2[0].type = htonl (GNUNET_ATS_NETWORK_TYPE);
    ats2[0].value = htonl (net);
    memcpy (&ats2[1],
            ats,
            sizeof(struct GNUNET_ATS_Information) * ats_count);
  }
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "Notifying ATS about peer `%s''s new address `%s' session %p in network %s\n",
              GNUNET_i2s (&address->peer),
              (0 == address->address_length)
              ? "<inbound>"
              : GST_plugins_a2s (address),
              session,
              GNUNET_ATS_print_network_type (net));
  ar = GNUNET_ATS_address_add (GST_ats,
                               address,
                               session,
                               (NULL != session) ? ats2 : ats,
                               (NULL != session) ? ats_count + 1 : ats_count);
  ai = GNUNET_new (struct AddressInfo);
  ai->address = GNUNET_HELLO_address_copy (address);
  ai->session = session;
  ai->ar = ar;
  (void) GNUNET_CONTAINER_multipeermap_put (p2a,
                                            &ai->address->peer,
                                            ai,
                                            GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE);
}


/**
 * Notify ATS about a new session now existing for the given
 * address.
 *
 * @param address the address
 * @param session the session
 */
void
GST_ats_new_session (const struct GNUNET_HELLO_Address *address,
                     struct Session *session)
{
  struct AddressInfo *ai;

  ai = find_ai (address, NULL);
  if (NULL == ai)
  {
    /* We may already be aware of the session, even if some other part
       of the code could not tell if it just created a new session or
       just got one recycled from the plugin; hence, we may be called
       with "new" session even for an "old" session; in that case,
       check that this is the case, but just ignore it. */
    GNUNET_assert (NULL != (find_ai (address, session)));
    return;
  }
  GNUNET_break (NULL == ai->session);
  ai->session = session;
  GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG,
                   "transport-ats",
                   "Telling ATS about new session %p for peer %s\n",
                   session,
                   GNUNET_i2s (&address->peer));
  GNUNET_ATS_address_add_session (ai->ar,
                                  session);
}


/**
 * Notify ATS that the session (but not the address) of
 * a given address is no longer relevant.
 *
 * @param address the address
 * @param session the session
 */
void
GST_ats_del_session (const struct GNUNET_HELLO_Address *address,
                     struct Session *session)
{
  struct AddressInfo *ai;

  if (NULL == session)
  {
    GNUNET_break (0);
    return;
  }
  ai = find_ai (address, session);
  if (NULL == ai)
  {
    /* We sometimes create sessions just for sending a PING,
       and if those are destroyed they were never known to
       ATS which means we end up here (however, in this
       case, the address must be an outbound address). */
    GNUNET_break (GNUNET_YES !=
                  GNUNET_HELLO_address_check_option (address,
                                                     GNUNET_HELLO_ADDRESS_INFO_INBOUND));

    return;
  }
  GNUNET_assert (session == ai->session);
  ai->session = NULL;
  GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG,
                   "transport-ats",
                   "Telling ATS to destroy session %p from peer %s\n",
                   session,
                   GNUNET_i2s (&address->peer));
  if (GNUNET_YES ==
      GNUNET_ATS_address_del_session (ai->ar, session))
  {
    ai->ar = NULL;
    GST_ats_expire_address (address);
  }
}


/**
 * Notify ATS about property changes to an address.
 *
 * @param address our information about the address
 * @param session the session
 * @param ats performance information
 * @param ats_count number of elements in @a ats
 */
void
GST_ats_update_metrics (const struct GNUNET_HELLO_Address *address,
                        struct Session *session,
                        const struct GNUNET_ATS_Information *ats,
                        uint32_t ats_count)
{
  struct GNUNET_ATS_Information *ats_new;
  struct AddressInfo *ai;

  ai = find_ai (address, session);
  if (NULL == ai)
  {
    /* We sometimes create sessions just for sending a PING,
       and if we get metrics for those, they were never known to
       ATS which means we end up here (however, in this
       case, the address must be an outbound address). */
    GNUNET_assert (GNUNET_YES !=
                   GNUNET_HELLO_address_check_option (address,
                                                      GNUNET_HELLO_ADDRESS_INFO_INBOUND));

    return;
  }
  /* Call to manipulation to manipulate ATS information */
  GNUNET_assert (NULL != GST_ats);
  if ((NULL == ats) || (0 == ats_count))
    return;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Updating metrics for peer `%s' address %s session %p\n",
              GNUNET_i2s (&address->peer),
              GST_plugins_a2s (address),
              session);
  ats_new = GST_manipulation_manipulate_metrics (address,
                                                 session,
                                                 ats,
                                                 ats_count);
  GNUNET_ATS_address_update (ai->ar,
                             ats_new, ats_count);
  GNUNET_free_non_null (ats_new);
}


/**
 * Notify ATS about a new session now being in use (or not).
 *
 * @param address the address
 * @param session the session
 * @param in_use #GNUNET_YES or #GNUNET_NO
 */
void
GST_ats_set_in_use (const struct GNUNET_HELLO_Address *address,
                    struct Session *session,
                    int in_use)
{
  struct AddressInfo *ai;

  ai = find_ai (address, session);
  if (NULL == ai)
  {
    GNUNET_break (0);
    return;
  }
  GNUNET_ATS_address_set_in_use (ai->ar, in_use);
}


/**
 * Notify ATS that the address has expired and thus cannot
 * be used any longer.  This function must only be called
 * if the corresponding session is already gone.
 *
 * @param address the address
 */
void
GST_ats_expire_address (const struct GNUNET_HELLO_Address *address)
{
  struct AddressInfo *ai;

  ai = find_ai (address, NULL);
  if (NULL == ai)
  {
    GNUNET_assert (0);
    return;
  }
  GNUNET_assert (GNUNET_YES ==
                 GNUNET_CONTAINER_multipeermap_remove (p2a,
                                                       &address->peer,
                                                       ai));
  GNUNET_break (NULL == ai->session);
  GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG,
                   "transport-ats",
                   "Telling ATS to destroy address from peer %s\n",
                   GNUNET_i2s (&address->peer));
  if (NULL != ai->ar)
    GNUNET_ATS_address_destroy (ai->ar);
  GNUNET_HELLO_address_free (ai->address);
  GNUNET_free (ai);
}


/**
 * Initialize ATS subsystem.
 */
void
GST_ats_init ()
{
  p2a = GNUNET_CONTAINER_multipeermap_create (4, GNUNET_YES);
}


/**
 * Release memory used by the given address data.
 *
 * @param cls NULL
 * @param key which peer is this about
 * @param value the `struct AddressInfo`
 * @return #GNUNET_OK (continue to iterate)
 */
static int
destroy_ai (void *cls,
            const struct GNUNET_PeerIdentity *key,
            void *value)
{
  struct AddressInfo *ai = value;

  GNUNET_HELLO_address_free (ai->address);
  GNUNET_free (ai);
  return GNUNET_OK;
}


/**
 * Shutdown ATS subsystem.
 */
void
GST_ats_done ()
{
  GNUNET_CONTAINER_multipeermap_iterate (p2a,
                                         &destroy_ai,
                                         NULL);
  GNUNET_CONTAINER_multipeermap_destroy (p2a);
  p2a = NULL;
}

/* end of gnunet-service-transport_ats.c */

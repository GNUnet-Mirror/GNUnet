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
 * @file transport/gnunet-service-transport_hello.c
 * @brief hello management implementation
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_constants.h"
#include "gnunet_hello_lib.h"
#include "gnunet_peerinfo_service.h"
#include "gnunet_statistics_service.h"
#include "gnunet-service-transport_hello.h"
#include "gnunet-service-transport.h"
#include "gnunet-service-transport_plugins.h"


/**
 * How often do we refresh our HELLO (due to expiration concerns)?
 */
#define HELLO_REFRESH_PERIOD GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_HOURS, 6)


/**
 * Entry in linked list of network addresses for ourselves.  Also
 * includes a cached signature for 'struct TransportPongMessage's.
 */
struct OwnAddressList
{
  /**
   * This is a doubly-linked list.
   */
  struct OwnAddressList *next;

  /**
   * This is a doubly-linked list.
   */
  struct OwnAddressList *prev;

  /**
   * The address.
   */
  struct GNUNET_HELLO_Address *address;

  /**
   * How long until the current signature expires? (ZERO if the
   * signature was never created).
   */
  struct GNUNET_TIME_Absolute pong_sig_expires;

  /**
   * Signature for a 'struct TransportPongMessage' for this address.
   */
  struct GNUNET_CRYPTO_RsaSignature pong_signature;

};


/**
 * Our HELLO message.
 */
static struct GNUNET_HELLO_Message *our_hello;

/**
 * Function to call on HELLO changes.
 */
static GST_HelloCallback hello_cb;

/**
 * Closure for 'hello_cb'.
 */
static void *hello_cb_cls;

/**
 * Head of my addresses.
 */
struct OwnAddressList *oal_head;

/**
 * Tail of my addresses.
 */
struct OwnAddressList *oal_tail;

/**
 * Identifier of 'refresh_hello' task.
 */
static GNUNET_SCHEDULER_TaskIdentifier hello_task;


/**
 * Closure for 'address_generator'.
 */
struct GeneratorContext
{
  /**
   * Where are we in the DLL?
   */
  struct OwnAddressList *addr_pos;

  /**
   * When do addresses expire?
   */
  struct GNUNET_TIME_Absolute expiration;
};


/**
 * Add an address from the 'OwnAddressList' to the buffer.
 *
 * @param cls the 'struct GeneratorContext'
 * @param max maximum number of bytes left
 * @param buf where to write the address
 */
static size_t
address_generator (void *cls, size_t max, void *buf)
{
  struct GeneratorContext *gc = cls;
  size_t ret;

  if (NULL == gc->addr_pos)
    return 0;
  ret =
      GNUNET_HELLO_add_address (gc->addr_pos->address, gc->expiration, buf,
                                max);
  gc->addr_pos = gc->addr_pos->next;
  return ret;
}


/**
 * Construct our HELLO message from all of the addresses of
 * all of the transports.
 *
 * @param cls unused
 * @param tc scheduler context
 */
static void
refresh_hello_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GeneratorContext gc;

  hello_task = GNUNET_SCHEDULER_NO_TASK;
  gc.addr_pos = oal_head;
  gc.expiration =
      GNUNET_TIME_relative_to_absolute
      (GNUNET_CONSTANTS_HELLO_ADDRESS_EXPIRATION);
  GNUNET_free (our_hello);
  our_hello = GNUNET_HELLO_create (&GST_my_public_key, &address_generator, &gc);
#if DEBUG_TRANSPORT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG | GNUNET_ERROR_TYPE_BULK,
              "Refreshed my `%s', new size is %d\n", "HELLO",
              GNUNET_HELLO_size (our_hello));
#endif
  GNUNET_STATISTICS_update (GST_stats, gettext_noop ("# refreshed my HELLO"), 1,
                            GNUNET_NO);
  if (NULL != hello_cb)
    hello_cb (hello_cb_cls, GST_hello_get ());
  GNUNET_PEERINFO_add_peer (GST_peerinfo, our_hello);
  hello_task =
      GNUNET_SCHEDULER_add_delayed (HELLO_REFRESH_PERIOD, &refresh_hello_task,
                                    NULL);

}


/**
 * Schedule task to refresh hello (unless such a
 * task exists already).
 */
static void
refresh_hello ()
{
  if (hello_task != GNUNET_SCHEDULER_NO_TASK)
    GNUNET_SCHEDULER_cancel (hello_task);
  hello_task = GNUNET_SCHEDULER_add_now (&refresh_hello_task, NULL);
}


/**
 * Initialize the HELLO module.
 *
 * @param cb function to call whenever our HELLO changes
 * @param cb_cls closure for cb
 */
void
GST_hello_start (GST_HelloCallback cb, void *cb_cls)
{
  hello_cb = cb;
  hello_cb_cls = cb_cls;
  our_hello = GNUNET_HELLO_create (&GST_my_public_key, NULL, NULL);
  refresh_hello ();
}


/**
 * Shutdown the HELLO module.
 */
void
GST_hello_stop ()
{
  hello_cb = NULL;
  hello_cb_cls = NULL;
  if (GNUNET_SCHEDULER_NO_TASK != hello_task)
  {
    GNUNET_SCHEDULER_cancel (hello_task);
    hello_task = GNUNET_SCHEDULER_NO_TASK;
  }
  if (NULL != our_hello)
  {
    GNUNET_free (our_hello);
    our_hello = NULL;
  }
}


/**
 * Obtain this peers HELLO message.
 *
 * @return our HELLO message
 */
const struct GNUNET_MessageHeader *
GST_hello_get ()
{
  return (struct GNUNET_MessageHeader *) our_hello;
}


/**
 * Add or remove an address from this peer's HELLO message.
 *
 * @param addremove GNUNET_YES to add, GNUNET_NO to remove
 * @param address address to add or remove
 */
void
GST_hello_modify_addresses (int addremove,
                            const struct GNUNET_HELLO_Address *address)
{
  struct OwnAddressList *al;

#if DEBUG_TRANSPORT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              (add_remove ==
               GNUNET_YES) ? "Adding `%s':%s to the set of our addresses\n" :
              "Removing `%s':%s from the set of our addresses\n",
              GST_plugins_a2s (address), p->short_name);
#endif
  GNUNET_assert (address != NULL);
  if (GNUNET_NO == addremove)
  {
    for (al = oal_head; al != NULL; al = al->next)
      if (0 == GNUNET_HELLO_address_cmp (address, al->address))
      {
        GNUNET_CONTAINER_DLL_remove (oal_head, oal_tail, al);
        GNUNET_HELLO_address_free (al->address);
        GNUNET_free (al);
        refresh_hello ();
        return;
      }
    /* address to be removed not found!? */
    GNUNET_break (0);
    return;
  }
  al = GNUNET_malloc (sizeof (struct OwnAddressList));
  GNUNET_CONTAINER_DLL_insert (oal_head, oal_tail, al);
  al->address = GNUNET_HELLO_address_copy (address);
  refresh_hello ();
}


/**
 * Test if a particular address is one of ours.
 *
 * @param address address to test
 * @param sig location where to cache PONG signatures for this address [set]
 * @param sig_expiration how long until the current 'sig' expires?
 *            (ZERO if sig was never created) [set]
 * @return GNUNET_YES if this is one of our addresses,
 *         GNUNET_NO if not
 */
int
GST_hello_test_address (const struct GNUNET_HELLO_Address *address,
                        struct GNUNET_CRYPTO_RsaSignature **sig,
                        struct GNUNET_TIME_Absolute **sig_expiration)
{
  struct OwnAddressList *al;

  for (al = oal_head; al != NULL; al = al->next)
    if (0 == GNUNET_HELLO_address_cmp (address, al->address))
    {
      *sig = &al->pong_signature;
      *sig_expiration = &al->pong_sig_expires;
      return GNUNET_YES;
    }
  *sig = NULL;
  *sig_expiration = NULL;
  return GNUNET_NO;
}


/* end of file gnunet-service-transport_hello.c */

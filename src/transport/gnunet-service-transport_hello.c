/*
     This file is part of GNUnet.
     Copyright (C) 2010,2011 GNUnet e.V.

     GNUnet is free software: you can redistribute it and/or modify it
     under the terms of the GNU General Public License as published
     by the Free Software Foundation, either version 3 of the License,
     or (at your option) any later version.

     GNUnet is distributed in the hope that it will be useful, but
     WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
     Affero General Public License for more details.
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
 * Hello address expiration
 */
extern struct GNUNET_TIME_Relative hello_expiration;


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
  struct GNUNET_CRYPTO_EddsaSignature pong_signature;

  /**
   * How often has this address been added/removed? Used as
   * some plugins may learn the same external address from
   * multiple origins.
   */
  unsigned int rc;

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
 * Closure for #hello_cb.
 */
static void *hello_cb_cls;

/**
 * Head of my addresses.
 */
static struct OwnAddressList *oal_head;

/**
 * Tail of my addresses.
 */
static struct OwnAddressList *oal_tail;

/**
 * Should we use a friend-only HELLO?
 */
static int friend_option;

/**
 * Identifier of #refresh_hello_task().
 */
static struct GNUNET_SCHEDULER_Task *hello_task;


/**
 * Closure for #address_generator().
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
 * Add an address from the `struct OwnAddressList` to the buffer.
 *
 * @param cls the `struct GeneratorContext`
 * @param max maximum number of bytes left
 * @param buf where to write the address
 * @return bytes written or #GNUNET_SYSERR to signal the
 *         end of the iteration.
 */
static ssize_t
address_generator (void *cls,
                   size_t max,
                   void *buf)
{
  struct GeneratorContext *gc = cls;
  ssize_t ret;

  if (NULL == gc->addr_pos)
    return GNUNET_SYSERR; /* Done */
  ret = GNUNET_HELLO_add_address (gc->addr_pos->address,
                                  gc->expiration,
                                  buf,
                                  max);
  gc->addr_pos = gc->addr_pos->next;
  return ret;
}


/**
 * Construct our HELLO message from all of the addresses of
 * all of the transports.
 *
 * @param cls unused
 */
static void
refresh_hello_task (void *cls)
{
  struct GeneratorContext gc;

  hello_task = NULL;
  gc.addr_pos = oal_head;
  gc.expiration = GNUNET_TIME_relative_to_absolute (hello_expiration);

  GNUNET_free_non_null (our_hello);
  our_hello = GNUNET_HELLO_create (&GST_my_identity.public_key,
				   &address_generator,
				   &gc,
                                   friend_option);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Refreshed my %s HELLO, new size is %d\n",
              (GNUNET_YES == friend_option) ? "friend-only" : "public",
              GNUNET_HELLO_size (our_hello));
  GNUNET_STATISTICS_update (GST_stats,
                            gettext_noop ("# refreshed my HELLO"),
                            1,
                            GNUNET_NO);
  if (NULL != hello_cb)
    hello_cb (hello_cb_cls,
              GST_hello_get ());
  GNUNET_PEERINFO_add_peer (GST_peerinfo,
                            our_hello,
                            NULL,
                            NULL);
  hello_task =
      GNUNET_SCHEDULER_add_delayed (HELLO_REFRESH_PERIOD,
                                    &refresh_hello_task,
                                    NULL);
}


/**
 * Schedule task to refresh hello (but only if such a
 * task exists already, as otherwise the module might
 * have been shutdown).
 */
static void
refresh_hello ()
{
  if (NULL != hello_task)
  {
    GNUNET_SCHEDULER_cancel (hello_task);
    hello_task = GNUNET_SCHEDULER_add_now (&refresh_hello_task,
                                           NULL);
  }
}


/**
 * Initialize the HELLO module.
 *
 * @param friend_only use a friend only hello
 * @param cb function to call whenever our HELLO changes
 * @param cb_cls closure for @a cb
 */
void
GST_hello_start (int friend_only,
                 GST_HelloCallback cb,
                 void *cb_cls)
{
  hello_cb = cb;
  hello_cb_cls = cb_cls;
  friend_option = friend_only;
  refresh_hello_task (NULL);
}


/**
 * Shutdown the HELLO module.
 */
void
GST_hello_stop ()
{
  hello_cb = NULL;
  hello_cb_cls = NULL;
  if (NULL != hello_task)
  {
    GNUNET_SCHEDULER_cancel (hello_task);
    hello_task = NULL;
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
  return (const struct GNUNET_MessageHeader *) our_hello;
}


/**
 * Add or remove an address from this peer's HELLO message.
 *
 * @param addremove #GNUNET_YES to add, #GNUNET_NO to remove
 * @param address address to add or remove
 */
void
GST_hello_modify_addresses (int addremove,
                            const struct GNUNET_HELLO_Address *address)
{
  struct OwnAddressList *al;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              (GNUNET_YES == addremove)
              ? "Adding `%s' to the set of our addresses\n"
              : "Removing `%s' from the set of our addresses\n",
              GST_plugins_a2s (address));
  GNUNET_assert (NULL != address);
  for (al = oal_head; al != NULL; al = al->next)
    if (0 == GNUNET_HELLO_address_cmp (address, al->address))
      break;
  if (GNUNET_NO == addremove)
  {
    if (NULL == al)
    {
      /* address to be removed not found!? */
      GNUNET_break (0);
      return;
    }
    al->rc--;
    if (0 != al->rc)
      return; /* RC not yet zero */
    GNUNET_CONTAINER_DLL_remove (oal_head,
                                 oal_tail,
                                 al);
    GNUNET_HELLO_address_free (al->address);
    GNUNET_free (al);
    refresh_hello ();
    return;
  }
  if (NULL != al)
  {
    /* address added twice or more */
    al->rc++;
    return;
  }
  al = GNUNET_new (struct OwnAddressList);
  al->rc = 1;
  GNUNET_CONTAINER_DLL_insert (oal_head,
                               oal_tail,
                               al);
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
 * @return #GNUNET_YES if this is one of our addresses,
 *         #GNUNET_NO if not
 */
int
GST_hello_test_address (const struct GNUNET_HELLO_Address *address,
                        struct GNUNET_CRYPTO_EddsaSignature **sig,
                        struct GNUNET_TIME_Absolute **sig_expiration)
{
  struct OwnAddressList *al;

  for (al = oal_head; al != NULL; al = al->next)
    if (0 == GNUNET_HELLO_address_cmp (address,
                                       al->address))
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

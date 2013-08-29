/*
     This file is part of GNUnet
     (C) 2012, 2013 Christian Grothoff (and other contributing authors)

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
 * @file include/gnunet_psycstore_plugin.h
 * @brief plugin API for the PSYCstore database backend
 * @author Gabor X Toth
 */
#ifndef GNUNET_PSYCSTORE_PLUGIN_H
#define GNUNET_PSYCSTORE_PLUGIN_H

#include "gnunet_common.h"
#include "gnunet_util_lib.h"
#include "gnunet_psycstore_service.h"

#ifdef __cplusplus
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif


/**
 * @brief struct returned by the initialization function of the plugin
 */
struct GNUNET_PSYCSTORE_PluginFunctions
{

  /**
   * Closure to pass to all plugin functions.
   */
  void *cls;

  /** 
   * Store join/leave events for a PSYC channel in order to be able to answer
   * membership test queries later.
   *
   * @see GNUNET_PSYCSTORE_membership_store()
   *
   * @return #GNUNET_OK on success, else #GNUNET_SYSERR
   */
  int
  (*membership_store) (void *cls, 
                       const struct GNUNET_HashCode *channel_key,
                       const struct GNUNET_HashCode *slave_key,
                       int did_join,
                       uint64_t announced_at,
                       uint64_t effective_since,
                       uint64_t group_generation);

  /** 
   * Test if a member was admitted to the channel at the given message ID.
   *
   * @see GNUNET_PSYCSTORE_membership_test()
   * 
   * @return #GNUNET_YES if the member was admitted, #GNUNET_NO if not,
   *         #GNUNET_SYSERR if there was en error.
   */
  int
  (*membership_test) (void *cls,
                      const struct GNUNET_CRYPTO_EccPublicKey *channel_key,
                      const struct GNUNET_CRYPTO_EccPublicKey *slave_key,
                      uint64_t message_id,
                      uint64_t group_generation);

  /** 
   * Store a message fragment sent to a channel.
   *
   * @see GNUNET_PSYCSTORE_fragment_store()
   * 
   * @return #GNUNET_OK on success, else #GNUNET_SYSERR
   */
  int
  (*fragment_store) (void *cls,
                     const struct GNUNET_CRYPTO_EccPublicKey *channel_key,
                     const struct GNUNET_MULTICAST_MessageHeader *message);

  /** 
   * Set additional flags for a given message.
   *
   * @param message_id ID of the message.
   * @param flags Flags to add.
   * 
   * @return #GNUNET_OK on success, else #GNUNET_SYSERR
   */
  int
  (*fragment_add_flags) (void *cls,
                         const struct GNUNET_CRYPTO_EccPublicKey *channel_key,
                         uint64_t message_id,
                         uint64_t multicast_flags,
                         uint64_t psyc_flags);

  /** 
   * Retrieve a message fragment by fragment ID.
   *
   * @see GNUNET_PSYCSTORE_fragment_get()
   * 
   * @return #GNUNET_OK on success, else #GNUNET_SYSERR
   */
  int
  (*fragment_get) (void *cls,
                   const struct GNUNET_CRYPTO_EccPublicKey *channel_key,
                   uint64_t fragment_id,
                   GNUNET_PSYCSTORE_FragmentCallback cb,
                   void *cb_cls);

  /** 
   * Retrieve all fragments of a message.
   *
   * @see GNUNET_PSYCSTORE_message_get()
   * 
   * @return #GNUNET_OK on success, else #GNUNET_SYSERR
   */
  int
  (*message_get) (void *cls,
                  const struct GNUNET_CRYPTO_EccPublicKey *channel_key,
                  uint64_t message_id,
                  GNUNET_PSYCSTORE_FragmentCallback cb,
                  void *cb_cls);

  /** 
   * Retrieve a fragment of message specified by its message ID and fragment
   * offset.
   *
   * @see GNUNET_PSYCSTORE_message_get_fragment()
   * 
   * @return #GNUNET_OK on success, else #GNUNET_SYSERR
   */
  int
  (*message_get_fragment) (void *cls,
                           const struct GNUNET_CRYPTO_EccPublicKey *channel_key,
                           uint64_t message_id,
                           uint64_t fragment_offset,
                           GNUNET_PSYCSTORE_FragmentCallback cb,
                           void *cb_cls);

  /** 
   * Retrieve latest values of counters for a channel master.
   *
   * @see GNUNET_PSYCSTORE_counters_get_master()
   * 
   * @return #GNUNET_OK on success, else #GNUNET_SYSERR
   */
  int
  (*counters_get_master) (void *cls,
                          const struct GNUNET_CRYPTO_EccPublicKey *channel_key,
                          uint64_t *fragment_id,
                          uint64_t *message_id,
                          uint64_t *group_generation);

  /** 
   * Retrieve latest values of counters for a channel slave. 
   *
   * @see GNUNET_PSYCSTORE_counters_get_slave()
   * 
   * @return #GNUNET_OK on success, else #GNUNET_SYSERR
   */
  int
  (*counters_get_slave) (void *cls,
                         const struct GNUNET_CRYPTO_EccPublicKey *channel_key,
                         uint64_t *max_state_msg_id);

  /** 
   * Set a state variable to the given value.
   *
   * @see GNUNET_PSYCSTORE_state_modify()
   * 
   * @return #GNUNET_OK on success, else #GNUNET_SYSERR
   */
  int
  (*state_set) (struct GNUNET_PSYCSTORE_Handle *h,
                const struct GNUNET_CRYPTO_EccPublicKey *channel_key,
                const char *name,
                size_t value_size,
                const void *value);

  /** 
   * Retrieve a state variable by name.
   *
   * @param name Name of the variable to retrieve.
   * @param[out] value_size Size of value.
   * @param[out] value Returned value.
   * 
   * @return #GNUNET_OK on success, else #GNUNET_SYSERR
   */
  int
  (*state_get) (struct GNUNET_PSYCSTORE_Handle *h,
                const struct GNUNET_CRYPTO_EccPublicKey *channel_key,
                const char *name,
                GNUNET_PSYCSTORE_StateCallback cb,
                void *cb_cls);

  /** 
   * Retrieve all state variables for a channel with the given prefix.
   *
   * @see GNUNET_PSYCSTORE_state_get_all()
   * 
   * @return #GNUNET_OK on success, else #GNUNET_SYSERR
   */
  int
  (*state_get_all) (struct GNUNET_PSYCSTORE_Handle *h,
                    const struct GNUNET_CRYPTO_EccPublicKey *channel_key,
                    const char *name,
                    GNUNET_PSYCSTORE_StateCallback cb,
                    void *cb_cls);

};


#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

/* end of gnunet_psycstore_plugin.h */
#endif

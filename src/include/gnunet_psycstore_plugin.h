/*
     This file is part of GNUnet
     (C) 2013 Christian Grothoff (and other contributing authors)

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
 * Struct returned by the initialization function of the plugin.
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
                       const struct GNUNET_CRYPTO_EccPublicSignKey *channel_key,
                       const struct GNUNET_CRYPTO_EccPublicSignKey *slave_key,
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
                      const struct GNUNET_CRYPTO_EccPublicSignKey *channel_key,
                      const struct GNUNET_CRYPTO_EccPublicSignKey *slave_key,
                      uint64_t message_id);

  /** 
   * Store a message fragment sent to a channel.
   *
   * @see GNUNET_PSYCSTORE_fragment_store()
   *
   * @return #GNUNET_OK on success, else #GNUNET_SYSERR
   */
  int
  (*fragment_store) (void *cls,
                     const struct GNUNET_CRYPTO_EccPublicSignKey *channel_key,
                     const struct GNUNET_MULTICAST_MessageHeader *message,
                     uint32_t psycstore_flags);

  /** 
   * Set additional flags for a given message.
   *
   * They are OR'd with any existing flags set.
   *
   * @param cls Closure.
   * @param channel_key Public key of the channel.
   * @param message_id ID of the message.
   * @param psycstore_flags OR'd GNUNET_PSYCSTORE_MessageFlags.
   *
   * @return #GNUNET_OK on success, else #GNUNET_SYSERR
   */
  int
  (*message_add_flags) (void *cls,
                        const struct GNUNET_CRYPTO_EccPublicSignKey *channel_key,
                        uint64_t message_id,
                        uint64_t psycstore_flags);

  /** 
   * Retrieve a message fragment by fragment ID.
   *
   * @see GNUNET_PSYCSTORE_fragment_get()
   *
   * @return #GNUNET_OK on success, else #GNUNET_SYSERR
   */
  int
  (*fragment_get) (void *cls,
                   const struct GNUNET_CRYPTO_EccPublicSignKey *channel_key,
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
                  const struct GNUNET_CRYPTO_EccPublicSignKey *channel_key,
                  uint64_t message_id,
                  uint64_t *returned_fragments,
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
                           const struct GNUNET_CRYPTO_EccPublicSignKey *channel_key,
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
                          const struct GNUNET_CRYPTO_EccPublicSignKey *channel_key,
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
                         const struct GNUNET_CRYPTO_EccPublicSignKey *channel_key,
                         uint64_t *max_state_msg_id);


  /** 
   * Begin modifying current state.
   *
   * @see GNUNET_PSYCSTORE_state_modify()
   *
   * @return #GNUNET_OK on success, else #GNUNET_SYSERR
   */
  int
  (*state_modify_begin) (void *cls,
                         const struct GNUNET_CRYPTO_EccPublicSignKey *channel_key,
                         uint64_t message_id, uint64_t state_delta);

  /** 
   * Set the current value of a state variable.
   *
   * The state modification process is started with state_modify_begin(),
   * which is followed by one or more calls to this function,
   * and finished with state_modify_end().
   *
   * @see GNUNET_PSYCSTORE_state_modify()
   *
   * @return #GNUNET_OK on success, else #GNUNET_SYSERR
   */
  int
  (*state_modify_set) (void *cls,
                       const struct GNUNET_CRYPTO_EccPublicSignKey *channel_key,
                       const char *name, const void *value, size_t value_size);


  /** 
   * End modifying current state.
   *
   * @see GNUNET_PSYCSTORE_state_modify()
   *
   * @return #GNUNET_OK on success, else #GNUNET_SYSERR
   */
  int
  (*state_modify_end) (void *cls,
                       const struct GNUNET_CRYPTO_EccPublicSignKey *channel_key,
                       uint64_t message_id);


  /** 
   * Begin synchronizing state.
   *
   * @see GNUNET_PSYCSTORE_state_sync()
   *
   * @return #GNUNET_OK on success, else #GNUNET_SYSERR
   */
  int
  (*state_sync_begin) (void *cls,
                         const struct GNUNET_CRYPTO_EccPublicSignKey *channel_key);

  /** 
   * Set the value of a state variable while synchronizing state.
   *
   * The state synchronization process is started with state_sync_begin(),
   * which is followed by one or more calls to this function,
   * and finished with state_sync_end().
   *
   * @see GNUNET_PSYCSTORE_state_sync()
   *
   * @return #GNUNET_OK on success, else #GNUNET_SYSERR
   */
  int
  (*state_sync_set) (void *cls,
                     const struct GNUNET_CRYPTO_EccPublicSignKey *channel_key,
                     const char *name, const void *value, size_t value_size);


  /** 
   * End synchronizing state.
   *
   * @see GNUNET_PSYCSTORE_state_sync()
   *
   * @return #GNUNET_OK on success, else #GNUNET_SYSERR
   */
  int
  (*state_sync_end) (void *cls,
                     const struct GNUNET_CRYPTO_EccPublicSignKey *channel_key,
                     uint64_t message_id);


  /** 
   * Reset the state of a channel.
   *
   * Delete all state variables stored for the given channel.
   *
   * @see GNUNET_PSYCSTORE_state_reset()
   *
   * @return #GNUNET_OK on success, else #GNUNET_SYSERR
   */
  int
  (*state_reset) (void *cls,
                  const struct GNUNET_CRYPTO_EccPublicSignKey *channel_key);

  /**
   * Update signed state values from the current ones.
   *
   * Sets value_signed = value_current for each variable for the given channel.
   */
  int
  (*state_update_signed) (void *cls,
                          const struct GNUNET_CRYPTO_EccPublicSignKey *channel_key);


  /** 
   * Retrieve a state variable by name (exact match).
   *
   * @return #GNUNET_OK on success, else #GNUNET_SYSERR
   */
  int
  (*state_get) (void *cls,
                const struct GNUNET_CRYPTO_EccPublicSignKey *channel_key,
                const char *name,
                GNUNET_PSYCSTORE_StateCallback cb,
                void *cb_cls);

  /** 
   * Retrieve all state variables for a channel with the given prefix.
   *
   * @see GNUNET_PSYCSTORE_state_get_prefix()
   *
   * @return #GNUNET_OK on success, else #GNUNET_SYSERR
   */
  int
  (*state_get_prefix) (void *cls,
                       const struct GNUNET_CRYPTO_EccPublicSignKey *channel_key,
                       const char *name,
                       GNUNET_PSYCSTORE_StateCallback cb,
                       void *cb_cls);


  /** 
   * Retrieve all signed state variables for a channel.
   *
   * @return #GNUNET_OK on success, else #GNUNET_SYSERR
   */
  int
  (*state_get_signed) (void *cls,
                       const struct GNUNET_CRYPTO_EccPublicSignKey *channel_key,
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

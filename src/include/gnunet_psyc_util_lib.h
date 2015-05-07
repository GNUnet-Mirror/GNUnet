/*
     This file is part of GNUnet.
     Copyright (C) 2012, 2013 Christian Grothoff (and other contributing authors)

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
 * @file include/gnunet_psyc_service.h
 * @brief PSYC utilities; receiving/transmitting/logging PSYC messages.
 * @author Gabor X Toth
 */

#ifndef GNUNET_PSYC_UTIL_LIB_H
#define GNUNET_PSYC_UTIL_LIB_H

#ifdef __cplusplus
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif

#include "gnunet_util_lib.h"
#include "gnunet_env_lib.h"
#include "gnunet_psyc_service.h"


/**
 * Create a PSYC message.
 *
 * @param method_name
 *        PSYC method for the message.
 * @param env
 *        Environment for the message.
 * @param data
 *        Data payload for the message.
 * @param data_size
 *        Size of @a data.
 *
 * @return Message header with size information,
 *         followed by the message parts.
 */
struct GNUNET_PSYC_Message *
GNUNET_PSYC_message_create (const char *method_name,
                            const struct GNUNET_ENV_Environment *env,
                            const void *data,
                            size_t data_size);

/**
 * Parse PSYC message.
 *
 * @param msg
 *        The PSYC message to parse.
 * @param env
 *        The environment for the message with a list of modifiers.
 * @param[out] method_name
 *        Pointer to the method name inside @a pmsg.
 * @param[out] data
 *        Pointer to data inside @a pmsg.
 * @param[out] data_size
 *        Size of @data is written here.
 *
 * @return #GNUNET_OK on success,
 *         #GNUNET_SYSERR on parse error.
 */
int
GNUNET_PSYC_message_parse (const struct GNUNET_PSYC_Message *msg,
                           const char **method_name,
                           struct GNUNET_ENV_Environment *env,
                           const void **data,
                           uint16_t *data_size);


void
GNUNET_PSYC_log_message (enum GNUNET_ErrorType kind,
                         const struct GNUNET_MessageHeader *msg);


int
GNUNET_PSYC_check_message_parts (uint16_t data_size, const char *data,
                                 uint16_t *first_ptype, uint16_t *last_ptype);


struct GNUNET_PSYC_TransmitHandle;

/**
 * Create a transmission handle.
 */
struct GNUNET_PSYC_TransmitHandle *
GNUNET_PSYC_transmit_create ();


/**
 * Destroy a transmission handle.
 */
void
GNUNET_PSYC_transmit_destroy (struct GNUNET_PSYC_TransmitHandle *tmit);


/**
 * Transmit a message.
 *
 * @param tmit
 *        Transmission handle.
 * @param method_name
 *        Which method should be invoked.
 * @param env
 *        Environment for the message.
 *        Should stay available until the first call to notify_data.
 *        Can be NULL if there are no modifiers or @a notify_mod is
 *        provided instead.
 * @param notify_mod
 *        Function to call to obtain modifiers.
 *        Can be NULL if there are no modifiers or @a env is provided instead.
 * @param notify_data
 *        Function to call to obtain fragments of the data.
 * @param notify_cls
 *        Closure for @a notify_mod and @a notify_data.
 * @param flags
 *        Flags for the message being transmitted.
 *
 * @return #GNUNET_OK if the transmission was started.
 *         #GNUNET_SYSERR if another transmission is already going on.
 */
int
GNUNET_PSYC_transmit_message (struct GNUNET_PSYC_TransmitHandle *tmit,
                              const char *method_name,
                              const struct GNUNET_ENV_Environment *env,
                              GNUNET_PSYC_TransmitNotifyModifier notify_mod,
                              GNUNET_PSYC_TransmitNotifyData notify_data,
                              void *notify_cls,
                              uint32_t flags);


/**
 * Resume transmission.
 *
 * @param tmit  Transmission handle.
 */
void
GNUNET_PSYC_transmit_resume (struct GNUNET_PSYC_TransmitHandle *tmit);


/**
 * Abort transmission request.
 *
 * @param tmit  Transmission handle.
 */
void
GNUNET_PSYC_transmit_cancel (struct GNUNET_PSYC_TransmitHandle *tmit);


/**
 * Got acknowledgement of a transmitted message part, continue transmission.
 *
 * @param tmit  Transmission handle.
 */
void
GNUNET_PSYC_transmit_got_ack (struct GNUNET_PSYC_TransmitHandle *tmit);


struct GNUNET_PSYC_ReceiveHandle;


/**
 * Create handle for receiving messages.
 */
struct GNUNET_PSYC_ReceiveHandle *
GNUNET_PSYC_receive_create (GNUNET_PSYC_MessageCallback message_cb,
                            GNUNET_PSYC_MessagePartCallback message_part_cb,
                            void *cb_cls);


/**
 * Destroy handle for receiving messages.
 */
void
GNUNET_PSYC_receive_destroy (struct GNUNET_PSYC_ReceiveHandle *recv);


/**
 * Reset stored data related to the last received message.
 */
void
GNUNET_PSYC_receive_reset (struct GNUNET_PSYC_ReceiveHandle *recv);


/**
 * Handle incoming PSYC message.
 *
 * @param recv  Receive handle.
 * @param msg   The message.
 *
 * @return #GNUNET_OK on success,
 *         #GNUNET_SYSERR on receive error.
 */
int
GNUNET_PSYC_receive_message (struct GNUNET_PSYC_ReceiveHandle *recv,
                             const struct GNUNET_PSYC_MessageHeader *msg);


/**
 * Check if @a data contains a series of valid message parts.
 *
 * @param      data_size    Size of @a data.
 * @param      data	    Data.
 * @param[out] first_ptype  Type of first message part.
 * @param[out] last_ptype   Type of last message part.
 *
 * @return Number of message parts found in @a data.
 *         or GNUNET_SYSERR if the message contains invalid parts.
 */
int
GNUNET_PSYC_receive_check_parts (uint16_t data_size, const char *data,
                                 uint16_t *first_ptype, uint16_t *last_ptype);


#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

/* ifndef GNUNET_PSYC_UTIL_LIB_H */
#endif
/* end of gnunet_psyc_util_lib.h */

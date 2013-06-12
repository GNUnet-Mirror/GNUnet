/*
     This file is part of GNUnet.
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
 * @file include/gnunet_psycstore_service.h
 * @brief PSYCstore service; implements persistent storage for the PSYC service
 * @author tg
 * @author Christian Grothoff
 */
#ifndef GNUNET_PSYCSTORE_SERVICE_H
#define GNUNET_PSYCSTORE_SERVICE_H

#ifdef __cplusplus
extern "C"
{no
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif

#include "gnunet_util_lib.h"

/**
 * Version number of GNUnet PSYCstore API.
 */
#define GNUNET_PSYCSTORE_VERSION 0x00000000

/**
 * Handle for a PSYCstore
 */
struct GNUNET_PSYCSTORE_Handle;


struct GNUNET_PSYCSTORE_Handle *
GNUNET_PSYCSTORE_connect (const struct GNUNET_CONFIGURATION_Handle *cfg);


void
GNUNET_PSYCSTORE_disconnect (struct GNUNET_PSYCSTORE_Handle *h);


/**
 * Handle for an operation on the PSYCSTORE (useful to cancel the operation).
 */
struct GNUNET_PSYCSTORE_OperationHandle;


/**
 *
 * @param result GNUNET_SYSERR on error,
 *        GNUNET_YES on success or if the peer was a member,
 *        GNUNET_NO if the peer was not a member
 */
typedef void (*GNUNET_PSYCSTORE_ContinuationCallback)(void *cls,
						      int result);


struct GNUNET_PSYCSTORE_OperationHandle *
GNUNET_PSYCSTORE_membership_store (struct GNUNET_PSYCSTORE_Handle *h,
			      const struct GNUNET_HashCode *channel_id,
			      uint64_t message_id,
			      const struct GNUNET_PeerIdentity *peer,
			      int did_join,
			      GNUNET_PSYCSTORE_ContinuationCallback ccb,
			      void *ccb_cls);


struct GNUNET_PSYCSTORE_OperationHandle *
GNUNET_PSYCSTORE_membership_test (struct GNUNET_PSYCSTORE_Handle *h,
				  const struct GNUNET_HashCode *channel_id,
				  uint64_t message_id,
				  const struct GNUNET_PeerIdentity *peer,
				  GNUNET_PSYCSTORE_ContinuationCallback ccb,
				  void *ccb_cls);


struct GNUNET_PSYCSTORE_OperationHandle *
GNUNET_PSYCSTORE_message_store (struct GNUNET_PSYCSTORE_Handle *h,
				const struct GNUNET_HashCode *channel_id,
				const struct GNUNET_MULTICAST_MessageHeader *message,
				GNUNET_PSYCSTORE_ContinuationCallback ccb,
				void *ccb_cls);


typedef void (*GNUNET_PSYCSTORE_MessageResultCallback)(void *cls,	
						       uint64_t message_id,				       
						       const struct GNUNET_MULTICAST_MessageHeader *message);


struct GNUNET_PSYCSTORE_OperationHandle *
GNUNET_PSYCSTORE_message_get (struct GNUNET_PSYCSTORE_Handle *h,
			      const struct GNUNET_HashCode *channel_id,
			      uint64_t message_id,
			      GNUNET_PSYCSTORE_MessageResultCallback rcb,
			      void *rcb_cls);


struct GNUNET_PSYCSTORE_OperationHandle *
GNUNET_PSYCSTORE_message_get_latest (struct GNUNET_PSYCSTORE_Handle *h,
				     const struct GNUNET_HashCode *channel_id,
				     GNUNET_PSYCSTORE_MessageResultCallback rcb,
				     void *rcb_cls);


struct GNUNET_PSYCSTORE_OperationHandle *
GNUNET_PSYCSTORE_state_set (struct GNUNET_PSYCSTORE_Handle *h,
			    const struct GNUNET_HashCode *channel_id,
			    const char *state_name,
			    size_t size,
			    const void *value,
			    GNUNET_PSYCSTORE_ContinuationCallback ccb,
			    void *ccb_cls);


typedef void (*GNUNET_PSYCSTORE_StateResultCallback)(void *cls,
						     const char *state_name,
						     size_t size,
						     const void *value);


struct GNUNET_PSYCSTORE_OperationHandle *
GNUNET_PSYCSTORE_state_get (struct GNUNET_PSYCSTORE_Handle *h,
			    const struct GNUNET_HashCode *channel_id,
			    const char *state_name,
			    GNUNET_PSYCSTORE_StateResultCallback rcb,
			    void *rcb_cls);


struct GNUNET_PSYCSTORE_OperationHandle *
GNUNET_PSYCSTORE_state_get_all (struct GNUNET_PSYCSTORE_Handle *h,
				const struct GNUNET_HashCode *channel_id,
				GNUNET_PSYCSTORE_StateResultCallback rcb,
				void *rcb_cls);


void
GNUNET_PSYCSTORE_operation_cancel (struct GNUNET_PSYCSTORE_OperationHandle *oh);




#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

/* ifndef GNUNET_PSYCSTORE_SERVICE_H */
#endif
/* end of gnunet_psycstore_service.h */

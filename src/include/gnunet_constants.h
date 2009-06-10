/*
     This file is part of GNUnet.
     (C) 2009 Christian Grothoff (and other contributing authors)

     GNUnet is free software; you can redistribute it and/or modify
     it under the terms of the GNU General Public License as published
     by the Free Software Foundation; either version 2, or (at your
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
 * @file include/gnunet_constants.h
 * @brief "global" constants for performance tuning
 * @author Christian Grothoff
 */

#ifndef GNUNET_CONSTANTS_H
#define GNUNET_CONSTANTS_H

#ifdef __cplusplus
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif

/**
 * Amount of bytes per minute (in/out) to assume initially (before
 * either peer has communicated any particular preference).  Should be
 * rather low; set so that at least one maximum-size message can be
 * send each minute.
 */
#define GNUNET_CONSTANTS_DEFAULT_BPM_IN_OUT GNUNET_SERVER_MAX_MESSAGE_SIZE

/**
 * After how long do we consider a connection to a peer dead
 * if we don't receive messages from the peer?
 */
#define GNUNET_CONSTANTS_IDLE_CONNECTION_TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MINUTES, 5)


#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

#endif

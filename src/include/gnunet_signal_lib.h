/*
     This file is part of GNUnet.
     Copyright (C) 2001, 2002, 2003, 2004, 2005, 2006, 2007, 2009 GNUnet e.V.

     GNUnet is free software: you can redistribute it and/or modify it
     under the terms of the GNU Affero General Public License as published
     by the Free Software Foundation, either version 3 of the License,
     or (at your option) any later version.

     GNUnet is distributed in the hope that it will be useful, but
     WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
     Affero General Public License for more details.

     You should have received a copy of the GNU Affero General Public License
     along with this program.  If not, see <http://www.gnu.org/licenses/>.

     SPDX-License-Identifier: AGPL3.0-or-later
 */

/**
 * @author Christian Grothoff
 *
 * @file
 * Functions related to signals
 *
 * @defgroup signal  Signal library
 * Manage signal handlers.
 * @{
 */

#ifndef GNUNET_SIGNAL_LIB_H
#define GNUNET_SIGNAL_LIB_H

#ifdef __cplusplus
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif

/**
 * Context created when a signal handler is installed;
 * can be used to restore it to the previous state later.
 */
struct GNUNET_SIGNAL_Context;


/**
 * A signal handler.  Since different OSes have different signatures
 * for their handlers, the API only gives the most restrictive
 * signature -- no arguments, no return value.  Note that this will
 * work even if the OS expects a function with arguments.  However,
 * the implementation must guarantee that this handler is not called
 * for signals other than the one that it has been registered for.
 */
typedef void
(*GNUNET_SIGNAL_Handler) (void);


/**
 * Install a signal handler that will be run if the
 * given signal is received.
 *
 * @param signal the number of the signal
 * @param handler the function to call
 * @return context that can be used to restore, NULL on error
 */
struct GNUNET_SIGNAL_Context *
GNUNET_SIGNAL_handler_install (int signal,
                               GNUNET_SIGNAL_Handler handler);


/**
 * Uninstall a previously installed signal hander.
 *
 * @param ctx context that was returned when the
 *            signal handler was installed
 */
void
GNUNET_SIGNAL_handler_uninstall (struct GNUNET_SIGNAL_Context *ctx);


/**
 * Raise the given signal by calling the installed signal handlers.  This will
 * not use the @em raise() system call but only calls the handlers registered
 * through GNUNET_SIGNAL_handler_install().
 *
 * @param sig the signal to raise
 */
void
GNUNET_SIGNAL_raise (const int sig);


#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

/* ifndef GNUNET_SIGNAL_LIB_H */
#endif

/** @} */  /* end of group */

/* end of gnunet_signal_lib.h */

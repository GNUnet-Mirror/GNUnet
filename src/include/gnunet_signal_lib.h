/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2003, 2004, 2005, 2006, 2007, 2009 Christian Grothoff (and other contributing authors)

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
 * @file include/gnunet_signal_lib.h
 * @brief functions related to signals
 * @author Christian Grothoff
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
typedef void (*GNUNET_SIGNAL_Handler) (void);

/**
 * Install a signal handler that will be run if the
 * given signal is received.
 *
 * @param signal the number of the signal
 * @param handler the function to call
 * @return context that can be used to restore, NULL on error
 */
struct GNUNET_SIGNAL_Context *
GNUNET_SIGNAL_handler_install (int signal, GNUNET_SIGNAL_Handler handler);

/**
 * Uninstall a previously installed signal hander.
 *
 * @param ctx context that was returned when the
 *            signal handler was installed
 */
void
GNUNET_SIGNAL_handler_uninstall (struct GNUNET_SIGNAL_Context *ctx);


#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

/* ifndef GNUNET_SIGNAL_LIB_H */
#endif
/* end of gnunet_signal_lib.h */

/*
     This file is part of GNUnet.
     Copyright (C) 2001, 2002, 2006 GNUnet e.V.

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
 * @file util/signal.c
 * @brief code for installing and uninstalling signal handlers
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_util_lib.h"

#define LOG(kind, ...) GNUNET_log_from (kind, "util-signal", __VA_ARGS__)


struct GNUNET_SIGNAL_Context
{
  struct GNUNET_SIGNAL_Context *next;

  struct GNUNET_SIGNAL_Context *prev;

  int sig;

  GNUNET_SIGNAL_Handler method;

  struct sigaction oldsig;
};

static struct GNUNET_SIGNAL_Context *sc_head;

static struct GNUNET_SIGNAL_Context *sc_tail;

struct GNUNET_SIGNAL_Context *
GNUNET_SIGNAL_handler_install (int signum, GNUNET_SIGNAL_Handler handler)
{
  struct GNUNET_SIGNAL_Context *ret;

  struct sigaction sig;

  ret = GNUNET_new (struct GNUNET_SIGNAL_Context);
  ret->sig = signum;
  ret->method = handler;

  memset (&sig, 0, sizeof(sig));
  sig.sa_handler = (void *) handler;
  sigemptyset (&sig.sa_mask);
#ifdef SA_INTERRUPT
  sig.sa_flags = SA_INTERRUPT;  /* SunOS */
#else
  sig.sa_flags = SA_RESTART;
#endif
  sigaction (signum, &sig, &ret->oldsig);

  GNUNET_CONTAINER_DLL_insert_tail (sc_head, sc_tail, ret);
  return ret;
}


void
GNUNET_SIGNAL_handler_uninstall (struct GNUNET_SIGNAL_Context *ctx)
{
  struct sigaction sig;

  sigemptyset (&sig.sa_mask);
  sigaction (ctx->sig, &ctx->oldsig, &sig);

  GNUNET_CONTAINER_DLL_remove (sc_head, sc_tail, ctx);
  GNUNET_free (ctx);
}


/**
 * Raise the given signal by calling the installed signal handlers.  This will
 * not use the @em raise() system call but only calls the handlers registered
 * through GNUNET_SIGNAL_handler_install().
 *
 * @param sig the signal to raise
 */
void
GNUNET_SIGNAL_raise (const int sig)
{
  struct GNUNET_SIGNAL_Context *ctx;

  for (ctx = sc_head; NULL != ctx; ctx = ctx->next)
  {
    if (sig != ctx->sig)
      continue;
    if (NULL == ctx->method)
      continue;
    ctx->method ();
  }
}

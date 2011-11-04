/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2006 Christian Grothoff (and other contributing authors)

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
 * @file util/signal.c
 * @brief code for installing and uninstalling signal handlers
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_common.h"
#include "gnunet_signal_lib.h"

#define LOG(kind,...) GNUNET_log_from (kind, "util", __VA_ARGS__)


struct GNUNET_SIGNAL_Context
{
  int sig;

  GNUNET_SIGNAL_Handler method;

#ifndef MINGW
  struct sigaction oldsig;
#endif
};

#ifdef WINDOWS
GNUNET_SIGNAL_Handler w32_sigchld_handler = NULL;
#endif

struct GNUNET_SIGNAL_Context *
GNUNET_SIGNAL_handler_install (int signum, GNUNET_SIGNAL_Handler handler)
{
  struct GNUNET_SIGNAL_Context *ret;

#ifndef MINGW
  struct sigaction sig;
#endif

  ret = GNUNET_malloc (sizeof (struct GNUNET_SIGNAL_Context));
  ret->sig = signum;
  ret->method = handler;
#ifndef MINGW
  memset (&sig, 0, sizeof (sig));
  sig.sa_handler = (void *) handler;
  sigemptyset (&sig.sa_mask);
#ifdef SA_INTERRUPT
  sig.sa_flags = SA_INTERRUPT;  /* SunOS */
#else
  sig.sa_flags = SA_RESTART;
#endif
  sigaction (signum, &sig, &ret->oldsig);
#else
  if (signum == GNUNET_SIGCHLD)
    w32_sigchld_handler = handler;
  else
  {
    __p_sig_fn_t sigret = signal (signum, (__p_sig_fn_t) handler);

    if (sigret == SIG_ERR)
    {
      LOG (GNUNET_ERROR_TYPE_WARNING, _("signal (%d, %p) returned %d.\n"),
           signum, handler, sigret);
    }
  }
#endif
  return ret;
}

void
GNUNET_SIGNAL_handler_uninstall (struct GNUNET_SIGNAL_Context *ctx)
{
#ifndef MINGW
  struct sigaction sig;

  sigemptyset (&sig.sa_mask);
  sigaction (ctx->sig, &ctx->oldsig, &sig);
#endif
  GNUNET_free (ctx);
}

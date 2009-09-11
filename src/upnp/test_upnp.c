/*
     This file is part of GNUnet.
     (C) 2006 Christian Grothoff (and other contributing authors)

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
 * @file upnp/test_upnp.c
 * @brief Testcase for UPnP
 * @author Christian Grothoff
 */

#include "gnunet_util.h"
#include "gnunet_upnp_service.h"
#include "gnunet_core.h"
#include "platform.h"



int
main (int argc, const char *argv[])
{
  static GNUNET_CoreAPIForPlugins capi;
  struct GNUNET_GE_Context *ectx;
  struct GNUNET_GC_Configuration *cfg;
  struct in_addr addr;
  int i;
  GNUNET_UPnP_ServiceAPI *upnp;
  struct GNUNET_PluginHandle *plug;
  GNUNET_ServicePluginInitializationMethod init;
  GNUNET_ServicePluginShutdownMethod done;
  char ntop_buf[INET_ADDRSTRLEN];

  ectx = GNUNET_GE_create_context_stderr (GNUNET_NO,
                                          GNUNET_GE_WARNING | GNUNET_GE_ERROR
                                          | GNUNET_GE_FATAL | GNUNET_GE_USER |
                                          GNUNET_GE_ADMIN |
                                          GNUNET_GE_DEVELOPER |
                                          GNUNET_GE_IMMEDIATE |
                                          GNUNET_GE_BULK);
  GNUNET_GE_setDefaultContext (ectx);
  cfg = GNUNET_GC_create ();
  GNUNET_GE_ASSERT (ectx, cfg != NULL);
  GNUNET_os_init (ectx);
  capi.ectx = ectx;
  capi.cfg = cfg;
  plug = GNUNET_plugin_load (ectx, "libgnunet", "module_upnp");
  if (plug == NULL)
    {
      GNUNET_GC_free (cfg);
      GNUNET_GE_free_context (ectx);
      return 1;
    }
  init = GNUNET_plugin_resolve_function (plug, "provide_", GNUNET_YES);
  if (init == NULL)
    {
      GNUNET_plugin_unload (plug);
      GNUNET_GC_free (cfg);
      GNUNET_GE_free_context (ectx);
      return 1;
    }
  upnp = init (&capi);
  if (upnp == NULL)
    {
      GNUNET_plugin_unload (plug);
      GNUNET_GC_free (cfg);
      GNUNET_GE_free_context (ectx);
      return 1;
    }
  for (i = 0; i < 10; i++)
    {
      if (GNUNET_shutdown_test () != GNUNET_NO)
        break;
      if (GNUNET_OK == upnp->get_ip (2086, "TCP", &addr))
        {
          printf ("UPnP returned external IP %s\n",
                  inet_ntop (AF_INET, &addr, ntop_buf, INET_ADDRSTRLEN));
        }
      else
        {
          /* we cannot be sure that there is a UPnP-capable
             NAT-box out there, so test should not fail
             just because of this! */
          printf ("No UPnP response (yet).\n");
        }
      GNUNET_thread_sleep (2 * GNUNET_CRON_SECONDS);
    }
  done = GNUNET_plugin_resolve_function (plug, "release_", GNUNET_YES);
  if (done != NULL)
    done ();
  GNUNET_plugin_unload (plug);
  GNUNET_GC_free (cfg);
  GNUNET_GE_free_context (ectx);
  return 0;
}

/* end of upnptest.c */

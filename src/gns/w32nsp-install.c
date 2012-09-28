/*
     This file is part of GNUnet.
     (C) 2012 Christian Grothoff (and other contributing authors)

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
 * @file gns/w32nsp-install.c
 * @brief W32 integration installer for GNS
 * @author LRN
 */

#define INITGUID
#include <windows.h>
#include <nspapi.h>
#include <ws2spi.h>
#include "gnunet_w32nsp_lib.h"
#include <stdio.h>

int
main (int argc, char **argv)
{
  int ret;
  int r = 1;
  WSADATA wsd;
  GUID id = GNUNET_NAMESPACE_PROVIDER_DNS;
  wchar_t *cmdl;
  int wargc;
  wchar_t **wargv;

  if (WSAStartup(MAKEWORD(2,2), &wsd) != 0)
  {
    fprintf (stderr, "WSAStartup() failed: %lu\n", GetLastError());
    return 5;
  }

  cmdl = GetCommandLineW ();
  if (cmdl == NULL)
  {
    WSACleanup();
    return 2;
  }
  wargv = CommandLineToArgvW (cmdl, &wargc);
  if (wargv == NULL)
  {
    WSACleanup();
    return 3;
  }
  r = 4;

  if (wargc == 2)
  {
    ret = WSCInstallNameSpace (L"GNUnet DNS provider", wargv[1], NS_DNS, 1, &id);
    if (ret == NO_ERROR)
    {
      r = 0;
    }
    else
    {
      r = 1;
      fprintf (stderr,
          "WSCInstallNameSpace(L\"GNUnet DNS provider\", \"%S\", %d, 0, %p) failed: %lu\n",
          wargv[1], NS_DNS, &id, GetLastError ());
    }
  }
  WSACleanup();
  return r;
}

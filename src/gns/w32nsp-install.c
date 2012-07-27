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
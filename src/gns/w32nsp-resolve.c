#define INITGUID
#include <windows.h>
#include <nspapi.h>
#include <ws2spi.h>
#include <nspapi.h>
#include <ws2tcpip.h>
#include "gnunet_w32nsp_lib.h"
#include <stdio.h>

typedef int (WSPAPI *LPNSPSTARTUP) (LPGUID lpProviderId, LPNSP_ROUTINE lpnspRoutines);

GUID host = {0x0002a800,0,0,{ 0xC0,0,0,0,0,0,0,0x46 }};
GUID ip4 = {0x00090035,0,1,{ 0xc0,0,0,0,0,0,0,0x046}}; 
GUID ip6 = {0x00090035,0,0x001c, { 0xc0,0,0,0,0,0,0,0x046}};

DEFINE_GUID(W32_DNS, 0x22059D40, 0x7E9E, 0x11CF, 0xAE, 0x5A, 0x00, 0xAA, 0x00, 0xA7, 0x11, 0x2B);

#define DEFINE_DNS_GUID(a,x) DEFINE_GUID(a, 0x00090035, 0x0000, x, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46)
DEFINE_DNS_GUID(SVCID_DNS_TYPE_A, 0x0001);
DEFINE_DNS_GUID(SVCID_DNS_TYPE_NS, 0x0002);
DEFINE_DNS_GUID(SVCID_DNS_TYPE_CNAME, 0x0005);
DEFINE_DNS_GUID(SVCID_DNS_TYPE_SOA, 0x0006);
DEFINE_DNS_GUID(SVCID_DNS_TYPE_PTR, 0x000c);
DEFINE_DNS_GUID(SVCID_DNS_TYPE_MX, 0x000f);
DEFINE_DNS_GUID(SVCID_DNS_TYPE_TEXT, 0x0010);
DEFINE_DNS_GUID(SVCID_DNS_TYPE_AAAA, 0x001c);
DEFINE_DNS_GUID(SVCID_DNS_TYPE_SRV, 0x0021);
DEFINE_GUID(SVCID_HOSTNAME, 0x0002a800, 0x0000, 0x0000, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46);
DEFINE_GUID(SVCID_INET_HOSTADDRBYNAME, 0x0002a803, 0x0000, 0x0000, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46);

//
// Utility to turn a list of offsets into a list of addresses. Used
// to convert structures returned as BLOBs.
//

VOID FixList(PCHAR ** List, PCHAR Base)
{
    if(*List)
    {
        PCHAR * Addr;

        Addr = *List = (PCHAR *)( ((DWORD)*List + Base) );
        while(*Addr)
        {
            *Addr = (PCHAR)(((DWORD)*Addr + Base));
            Addr++;
        }
    }
}


//
// Routine to convert a hostent returned in a BLOB to one with
// usable pointers. The structure is converted in-place.
//
VOID UnpackHostEnt(struct hostent * hostent)
{
     PCHAR pch;

     pch = (PCHAR)hostent;

     if(hostent->h_name)
     {
         hostent->h_name = (PCHAR)((DWORD)hostent->h_name + pch);
     }
     FixList(&hostent->h_aliases, pch);
     FixList(&hostent->h_addr_list, pch);
}

void
print_hostent (struct hostent *he)
{
  int i;
  char **pAlias;
  printf("\tOfficial name: %s\n", he->h_name);
  for (pAlias = he->h_aliases; *pAlias != 0; pAlias++) {
      printf("\tAlternate name #%d: %s\n", ++i, *pAlias);
  }
  printf("\tAddress type: ");
  switch (he->h_addrtype) {
  case AF_INET:
      printf("AF_INET\n");
      break;
  case AF_INET6:
      printf("AF_INET6\n");
      break;
  case AF_NETBIOS:
      printf("AF_NETBIOS\n");
      break;
  default:
      printf(" %d\n", he->h_addrtype);
      break;
  }
  printf("\tAddress length: %d\n", he->h_length);

  if (he->h_addrtype == AF_INET) {
    struct sockaddr_in addr;
    memset (&addr, 0, sizeof (addr));
    addr.sin_family = AF_INET;
    addr.sin_port = 0;
    i = 0;
    while (he->h_addr_list[i] != 0) {
      char buf[1024];
      DWORD buflen = 1024;
      addr.sin_addr = *(struct in_addr *) he->h_addr_list[i++];
      if (NO_ERROR == WSAAddressToStringA ((LPSOCKADDR) &addr, sizeof (addr), NULL, buf, &buflen))
        printf("\tIPv4 Address #%d: %s\n", i, buf);
      else
        printf("\tIPv4 Address #%d: Can't convert: %lu\n", i, GetLastError ());
    }
  } else if (he->h_addrtype == AF_INET6) {
    struct sockaddr_in6 addr;
    memset (&addr, 0, sizeof (addr));
    addr.sin6_family = AF_INET6;
    addr.sin6_port = 0;
    i = 0;
    while (he->h_addr_list[i] != 0) {
      char buf[1024];
      DWORD buflen = 1024;
      addr.sin6_addr = *(struct in6_addr *) he->h_addr_list[i++];
      if (NO_ERROR == WSAAddressToStringA ((LPSOCKADDR) &addr, sizeof (addr), NULL, buf, &buflen))
        printf("\tIPv6 Address #%d: %s\n", i, buf);
      else
        printf("\tIPv6 Address #%d: Can't convert: %lu\n", i, GetLastError ());
    }
  }
}

int
main (int argc, char **argv)
{
  int ret;
  int r = 1;
  WSADATA wsd;
  GUID *prov = NULL;
  GUID *sc = NULL;
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

  if (wargc == 5)
  {
    if (wcscmp (wargv[1], L"A") == 0)
      sc = &SVCID_DNS_TYPE_A;
    else if (wcscmp (wargv[1], L"AAAA") == 0)
      sc = &SVCID_DNS_TYPE_AAAA;
    else if (wcscmp (wargv[1], L"name") == 0)
      sc = &SVCID_HOSTNAME;
    else if (wcscmp (wargv[1], L"addr") == 0)
      sc = &SVCID_INET_HOSTADDRBYNAME;
    else
      wargc -= 1;
    if (wcscmp (wargv[4], L"mswdns") == 0)
      prov = &W32_DNS;
    else if (wcscmp (wargv[4], L"gnunetdns") == 0)
      prov = &GNUNET_NAMESPACE_PROVIDER_DNS;
    else
      wargc -= 1;
  }

  if (wargc == 5)
  {
    HMODULE nsp;
   
    nsp = LoadLibraryW (wargv[3]);
    if (nsp == NULL)
    {
      fprintf (stderr, "Failed to load library `%S'\n", wargv[3]);
    }
    else
    {
      LPNSPSTARTUP startup = (LPNSPSTARTUP) GetProcAddress (nsp, "NSPStartup");
      if (startup != NULL)
      {
        NSP_ROUTINE api;
        ret = startup (prov, &api);
        if (NO_ERROR != ret)
          fprintf (stderr, "startup failed\n");
        else
        {
          HANDLE lookup;
          WSAQUERYSETW search;
          char buf[4096];
          WSAQUERYSETW *result = (WSAQUERYSETW *) buf;
          DWORD resultsize;
          DWORD err;
          memset (&search, 0, sizeof (search));
          search.dwSize = sizeof (search);
          search.lpszServiceInstanceName = (wcscmp (wargv[2], L" ") == 0) ? NULL : wargv[2];
          search.lpServiceClassId = sc;
          search.lpNSProviderId = prov;
          search.dwNameSpace = NS_ALL;
          ret = api.NSPLookupServiceBegin (prov, &search, NULL, LUP_RETURN_ALL, &lookup);
          if (ret != NO_ERROR)
          {
            fprintf (stderr, "lookup start failed\n");
          }
          else
          {
            resultsize = 4096;
            ret = api.NSPLookupServiceNext (lookup, LUP_RETURN_ALL, &resultsize, result);
            err = GetLastError ();
            if (ret != NO_ERROR)
            {
              fprintf (stderr, "lookup next failed\n");
            }
            else
            {
              int i;
              printf ("Got result:\n");
              printf ("  lpszServiceInstanceName: %S\n", result->lpszServiceInstanceName ? result->lpszServiceInstanceName : L"NULL");
              if (result->lpServiceClassId)
                printf ("  lpServiceClassId:        { 0x%08lX,0x%04X,0x%04X, { 0x%02X, 0x%02X, 0x%02X, 0x%02X, 0x%02X, 0x%02X, 0x%02X, 0x%02X } }\n",
                    result->lpServiceClassId->Data1, result->lpServiceClassId->Data2, result->lpServiceClassId->Data3, result->lpServiceClassId->Data4[0],
                    result->lpServiceClassId->Data4[1], result->lpServiceClassId->Data4[2], result->lpServiceClassId->Data4[3], result->lpServiceClassId->Data4[4],
                    result->lpServiceClassId->Data4[5], result->lpServiceClassId->Data4[6], result->lpServiceClassId->Data4[7]);
              else
                printf ("  lpServiceClassId:        NULL\n");
              if (result->lpVersion)
                printf ("  lpVersion:               0x%08lX, %d\n", result->lpVersion->dwVersion, result->lpVersion->ecHow);
              else
                printf ("  lpVersion:               NULL\n");
              printf ("  lpszComment:             %S\n", result->lpszComment ? result->lpszComment : L"NULL");
              printf ("  dwNameSpace:             %lu\n", result->dwNameSpace);
              if (result->lpNSProviderId)
                printf ("  lpNSProviderId:          { 0x%08lX,0x%04X,0x%04X, { 0x%02X, 0x%02X, 0x%02X, 0x%02X, 0x%02X, 0x%02X, 0x%02X, 0x%02X } }\n",
                    result->lpNSProviderId->Data1, result->lpNSProviderId->Data2, result->lpNSProviderId->Data3, result->lpNSProviderId->Data4[0],
                    result->lpNSProviderId->Data4[1], result->lpNSProviderId->Data4[2], result->lpNSProviderId->Data4[3], result->lpNSProviderId->Data4[4],
                    result->lpNSProviderId->Data4[5], result->lpNSProviderId->Data4[6], result->lpNSProviderId->Data4[7]);
              else
                printf ("  lpNSProviderId:          NULL\n");
              printf ("  lpszContext:             %S\n", result->lpszContext ? result->lpszContext : L"NULL");
              printf ("  dwNumberOfProtocols:     %lu\n", result->dwNumberOfProtocols);
              printf ("  lpszQueryString:         %S\n", result->lpszQueryString ? result->lpszQueryString : L"NULL");
              printf ("  dwNumberOfCsAddrs:       %lu\n", result->dwNumberOfCsAddrs);
              for (i = 0; i < result->dwNumberOfCsAddrs; i++)
              {
                switch (result->lpcsaBuffer[i].iSocketType)
                {
                case SOCK_STREAM:
                  printf ("    %d: iSocketType = SOCK_STREAM\n", i);
                  break;
                case SOCK_DGRAM:
                  printf ("    %d: iSocketType = SOCK_DGRAM\n", i);
                  break;
                default:
                  printf ("    %d: iSocketType = %d\n", i, result->lpcsaBuffer[i].iSocketType);
                }
                switch (result->lpcsaBuffer[i].iProtocol)
                {
                case IPPROTO_TCP:
                  printf ("    %d: iProtocol   = IPPROTO_TCP\n", i);
                  break;
                case IPPROTO_UDP:
                  printf ("    %d: iProtocol   = IPPROTO_UDP\n", i);
                  break;
                default:
                  printf ("    %d: iProtocol   = %d\n", i, result->lpcsaBuffer[i].iProtocol);
                }
                switch (result->lpcsaBuffer[i].LocalAddr.lpSockaddr->sa_family)
                {
                case AF_INET:
                  printf ("    %d: loc family  = AF_INET\n", i);
                  break;
                case AF_INET6:
                  printf ("    %d: loc family  = AF_INET6\n", i);
                  break;
                default:
                  printf ("    %d: loc family  = %hu\n", i, result->lpcsaBuffer[i].LocalAddr.lpSockaddr->sa_family);
                }
                switch (result->lpcsaBuffer[i].RemoteAddr.lpSockaddr->sa_family)
                {
                case AF_INET:
                  printf ("    %d: rem family  = AF_INET\n", i);
                  break;
                case AF_INET6:
                  printf ("    %d: rem family  = AF_INET6\n", i);
                  break;
                default:
                  printf ("    %d: rem family = %hu\n", i, result->lpcsaBuffer[i].RemoteAddr.lpSockaddr->sa_family);
                }
                char buf[1024];
                DWORD buflen = 1024;
                if (NO_ERROR == WSAAddressToStringA (result->lpcsaBuffer[i].LocalAddr.lpSockaddr, result->lpcsaBuffer[i].LocalAddr.iSockaddrLength, NULL, buf, &buflen))
                  printf("\tLocal Address #%d: %s\n", i, buf);
                else
                  printf("\tLocal Address #%d: Can't convert: %lu\n", i, GetLastError ());
                buflen = 1024;
                if (NO_ERROR == WSAAddressToStringA (result->lpcsaBuffer[i].RemoteAddr.lpSockaddr, result->lpcsaBuffer[i].RemoteAddr.iSockaddrLength, NULL, buf, &buflen))
                  printf("\tRemote Address #%d: %s\n", i, buf);
                else
                  printf("\tRemote Address #%d: Can't convert: %lu\n", i, GetLastError ());
              }
              printf ("  dwOutputFlags:           0x%08lX\n", result->dwOutputFlags);
              printf ("  lpBlob:                  0x%p\n", result->lpBlob);
              if (result->lpBlob)
              {
                struct hostent *he = malloc (result->lpBlob->cbSize);
                if (he != NULL)
                {
                  memcpy (he, result->lpBlob->pBlobData, result->lpBlob->cbSize);
                  UnpackHostEnt (he);
                  print_hostent (he);
                  free (he);
                }
              }
            }
            ret = api.NSPLookupServiceEnd (lookup);
            if (ret != NO_ERROR)
              printf ("NSPLookupServiceEnd() failed: %lu\n", GetLastError ());
          }
          api.NSPCleanup (prov);
        }
      }
      FreeLibrary (nsp);
    }
  }
  WSACleanup();
  return r;
}
/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2003, 2004, 2005, 2006 Christian Grothoff (and other contributing authors)

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
 * @file util/win.cc
 * @brief Helper functions for MS Windows in C++
 * @author Nils Durner
 */

#ifndef _WIN_CC
#define _WIN_CC

#include "winproc.h"
#include "platform.h"
#include "gnunet_common.h"
#include "gnunet_connection_lib.h"

#include <list>
using namespace std;
#include <ntdef.h>

#ifndef INHERITED_ACE
#define INHERITED_ACE 0x10
#endif

extern "C" {

int plibc_conv_to_win_path(const char *pszUnix, char *pszWindows);

#define _IP_ADAPTER_UNICAST_ADDRESS_HEAD \
  union { \
    struct { \
      ULONG Length; \
      DWORD Flags; \
    }; \
  }; \

#define _IP_ADAPTER_UNICAST_ADDRESS_BASE \
  SOCKET_ADDRESS                     Address; \
  IP_PREFIX_ORIGIN                   PrefixOrigin; \
  IP_SUFFIX_ORIGIN                   SuffixOrigin; \
  IP_DAD_STATE                       DadState; \
  ULONG                              ValidLifetime; \
  ULONG                              PreferredLifetime; \
  ULONG                              LeaseLifetime;

#define _IP_ADAPTER_UNICAST_ADDRESS_ADD_VISTA \
  UINT8                              OnLinkPrefixLength;


#define _IP_ADAPTER_UNICAST_ADDRESS_DEFINE(suffix,addition) \
typedef struct _IP_ADAPTER_UNICAST_ADDRESS##suffix { \
  _IP_ADAPTER_UNICAST_ADDRESS_HEAD \
  struct _IP_ADAPTER_UNICAST_ADDRESS##suffix *Next; \
  _IP_ADAPTER_UNICAST_ADDRESS_BASE \
  addition \
} IP_ADAPTER_UNICAST_ADDRESS##suffix, *PIP_ADAPTER_UNICAST_ADDRESS##suffix;

/* _IP_ADAPTER_UNICAST_ADDRESS_DEFINE(,) defined in w32api headers */
_IP_ADAPTER_UNICAST_ADDRESS_DEFINE(_VISTA,_IP_ADAPTER_UNICAST_ADDRESS_ADD_VISTA)


typedef struct _IP_ADAPTER_WINS_SERVER_ADDRESS {
  union {
    ULONGLONG Alignment;
    struct {
      ULONG Length;
      DWORD Reserved;
    };
  };
  struct _IP_ADAPTER_WINS_SERVER_ADDRESS  *Next;
  SOCKET_ADDRESS                         Address;
} IP_ADAPTER_WINS_SERVER_ADDRESS, *PIP_ADAPTER_WINS_SERVER_ADDRESS, *PIP_ADAPTER_WINS_SERVER_ADDRESS_LH;

typedef struct _IP_ADAPTER_GATEWAY_ADDRESS {
  union {
    ULONGLONG Alignment;
    struct {
      ULONG Length;
      DWORD Reserved;
    };
  };
  struct _IP_ADAPTER_GATEWAY_ADDRESS  *Next;
  SOCKET_ADDRESS                     Address;
} IP_ADAPTER_GATEWAY_ADDRESS, *PIP_ADAPTER_GATEWAY_ADDRESS, *PIP_ADAPTER_GATEWAY_ADDRESS_LH;

typedef UINT32 NET_IF_COMPARTMENT_ID;
typedef GUID NET_IF_NETWORK_GUID;

typedef enum _NET_IF_CONNECTION_TYPE {
  NET_IF_CONNECTION_DEDICATED   = 1,
  NET_IF_CONNECTION_PASSIVE,
  NET_IF_CONNECTION_DEMAND,
  NET_IF_CONNECTION_MAXIMUM 
} NET_IF_CONNECTION_TYPE, *PNET_IF_CONNECTION_TYPE;

typedef enum  {
  TUNNEL_TYPE_NONE      = 0,
  TUNNEL_TYPE_OTHER,
  TUNNEL_TYPE_DIRECT,
  TUNNEL_TYPE_6TO4,
  TUNNEL_TYPE_ISATAP,
  TUNNEL_TYPE_TEREDO,
  TUNNEL_TYPE_IPHTTPS 
} TUNNEL_TYPE, *PTUNNEL_TYPE;

/*
A DUID consists of a two-octet type code represented in network byte
   order, followed by a variable number of octets that make up the
   actual identifier.  A DUID can be no more than 128 octets long (not
   including the type code).
*/
#define MAX_DHCPV6_DUID_LENGTH 130

typedef union _NET_LUID {
  ULONG64 Value;
  struct {
    ULONG64 Reserved  :24;
    ULONG64 NetLuidIndex  :24;
    ULONG64 IfType  :16;
  } Info;
} NET_LUID, *PNET_LUID, IF_LUID;

#define MAX_DNS_SUFFIX_STRING_LENGTH 246

typedef struct _IP_ADAPTER_DNS_SUFFIX {
  struct _IP_ADAPTER_DNS_SUFFIX  *Next;
  WCHAR                         String[MAX_DNS_SUFFIX_STRING_LENGTH];
} IP_ADAPTER_DNS_SUFFIX, *PIP_ADAPTER_DNS_SUFFIX;



#define _IP_ADAPTER_ADDRESSES_HEAD \
  union { \
    ULONGLONG Alignment; \
    struct { \
      ULONG Length; \
      DWORD IfIndex; \
    }; \
  };

#define _IP_ADAPTER_ADDRESSES_BASE \
  PCHAR                              AdapterName; \
  PIP_ADAPTER_UNICAST_ADDRESS        FirstUnicastAddress; \
  PIP_ADAPTER_ANYCAST_ADDRESS        FirstAnycastAddress; \
  PIP_ADAPTER_MULTICAST_ADDRESS      FirstMulticastAddress; \
  PIP_ADAPTER_DNS_SERVER_ADDRESS     FirstDnsServerAddress; \
  PWCHAR                             DnsSuffix; \
  PWCHAR                             Description; \
  PWCHAR                             FriendlyName; \
  BYTE                               PhysicalAddress[MAX_ADAPTER_ADDRESS_LENGTH]; \
  DWORD                              PhysicalAddressLength; \
  DWORD                              Flags; \
  DWORD                              Mtu; \
  DWORD                              IfType; \
  IF_OPER_STATUS                     OperStatus;

#define _IP_ADAPTER_ADDRESSES_ADD_XPSP1 \
  DWORD                              Ipv6IfIndex; \
  DWORD                              ZoneIndices[16]; \
  PIP_ADAPTER_PREFIX                 FirstPrefix; \


#define _IP_ADAPTER_ADDRESSES_ADD_VISTA \
  _IP_ADAPTER_ADDRESSES_ADD_XPSP1 \
  ULONG64                            TransmitLinkSpeed; \
  ULONG64                            ReceiveLinkSpeed; \
  PIP_ADAPTER_WINS_SERVER_ADDRESS_LH FirstWinsServerAddress; \
  PIP_ADAPTER_GATEWAY_ADDRESS_LH     FirstGatewayAddress; \
  ULONG                              Ipv4Metric; \
  ULONG                              Ipv6Metric; \
  IF_LUID                            Luid; \
  SOCKET_ADDRESS                     Dhcpv4Server; \
  NET_IF_COMPARTMENT_ID              CompartmentId; \
  NET_IF_NETWORK_GUID                NetworkGuid; \
  NET_IF_CONNECTION_TYPE             ConnectionType; \
  TUNNEL_TYPE                        TunnelType; \
  SOCKET_ADDRESS                     Dhcpv6Server; \
  BYTE                               Dhcpv6ClientDuid[MAX_DHCPV6_DUID_LENGTH]; \
  ULONG                              Dhcpv6ClientDuidLength; \
  ULONG                              Dhcpv6Iaid;

#define _IP_ADAPTER_ADDRESSES_ADD_2008_OR_VISTASP1 \
  _IP_ADAPTER_ADDRESSES_ADD_VISTA \
  PIP_ADAPTER_DNS_SUFFIX             FirstDnsSuffix;

#define _IP_ADAPTER_ADDRESSES_DEFINE(suffix,addition) \
typedef struct _IP_ADAPTER_ADDRESSES##suffix { \
  _IP_ADAPTER_ADDRESSES_HEAD \
  struct _IP_ADAPTER_ADDRESSES##suffix *Next; \
  _IP_ADAPTER_ADDRESSES_BASE \
  addition \
} IP_ADAPTER_ADDRESSES##suffix, *PIP_ADAPTER_ADDRESSES##suffix;
  

/* _IP_ADAPTER_ADDRESSES_DEFINE(,) defined in w32api headers */
_IP_ADAPTER_ADDRESSES_DEFINE(_XPSP1,_IP_ADAPTER_ADDRESSES_ADD_XPSP1)
_IP_ADAPTER_ADDRESSES_DEFINE(_VISTA,_IP_ADAPTER_ADDRESSES_ADD_VISTA)
_IP_ADAPTER_ADDRESSES_DEFINE(_2008_OR_VISTASP1,_IP_ADAPTER_ADDRESSES_ADD_2008_OR_VISTASP1)

static int
EnumNICs_IPv6_get_ifs_count (SOCKET s)
{
  DWORD dwret = 0, err;
  int iret;
  iret = WSAIoctl (s, SIO_ADDRESS_LIST_QUERY, NULL, 0, NULL, 0,
      &dwret, NULL, NULL);
  err = GetLastError ();
  if (iret == SOCKET_ERROR && err == WSAEFAULT)
    return dwret;
  else if (iret == 0)
    return 0;
  return GNUNET_SYSERR;
}

static int
EnumNICs_IPv6_get_ifs (SOCKET s, SOCKET_ADDRESS_LIST *inf, int size)
{
  int iret;
  DWORD dwret = 0;
  iret = WSAIoctl (s, SIO_ADDRESS_LIST_QUERY, NULL, 0, inf, size,
      &dwret, NULL, NULL);

  if (iret != 0 || dwret != size)
  {
    /* It's supposed to succeed! And size should be the same */
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}

#undef GNUNET_malloc
#define GNUNET_malloc(a) HeapAlloc(GetProcessHeap (), HEAP_ZERO_MEMORY | \
    HEAP_GENERATE_EXCEPTIONS, a)

#undef GNUNET_free
#define GNUNET_free(a) HeapFree(GetProcessHeap (), 0, a)

#undef GNUNET_free_non_null
#define GNUNET_free_non_null(a) do { if ((a) != NULL) GNUNET_free(a); } while (0)

static int
EnumNICs_IPv4_get_ifs (SOCKET s, INTERFACE_INFO **inf, int *size)
{
  int iret;
  DWORD dwret = 0;
  DWORD error;
  INTERFACE_INFO *ii = NULL;
  DWORD ii_size = sizeof (INTERFACE_INFO) * 15;
  while (TRUE)
  {
    if (ii_size >= sizeof (INTERFACE_INFO) * 1000)
      return GNUNET_SYSERR;
    ii = (INTERFACE_INFO *) GNUNET_malloc (ii_size);
    dwret = 0;
    iret = WSAIoctl (s, SIO_GET_INTERFACE_LIST, NULL, 0, ii, ii_size,
        &dwret, NULL, NULL);
    error = GetLastError ();
    if (iret == SOCKET_ERROR)
    {
      if (error == WSAEFAULT)
      {
        GNUNET_free (ii);
        ii_size *= 2;
        continue;
      }
      GNUNET_free (ii);
      return GNUNET_SYSERR;
    }
    else
    {
      *inf = ii;
      *size = dwret;
      return GNUNET_OK;
    }
  }
  return GNUNET_SYSERR;
}

int
EnumNICs2 (INTERFACE_INFO **ifs4, int *ifs4_len, SOCKET_ADDRESS_LIST **ifs6)
{
  int result = 0;
  SOCKET s4 = INVALID_SOCKET, s6 = INVALID_SOCKET;
  DWORD dwret1 = 0, dwret2;
  DWORD err1, err2;
  int ifs4len = 0, ifs6len = 0;
  INTERFACE_INFO *interfaces4 = NULL;
  SOCKET_ADDRESS_LIST *interfaces6 = NULL;
  SetLastError (0);
  s4 = socket (AF_INET, SOCK_STREAM, IPPROTO_TCP);
  err1 = GetLastError ();
  SetLastError (0);
  s6 = socket (AF_INET6, SOCK_STREAM, IPPROTO_TCP);
  err2 = GetLastError ();
  if (s6 != INVALID_SOCKET)
  {
    ifs6len = EnumNICs_IPv6_get_ifs_count (s6);
    if (ifs6len > 0)
    {
      interfaces6 = (SOCKET_ADDRESS_LIST *) GNUNET_malloc (ifs6len);
      result = EnumNICs_IPv6_get_ifs (s6, interfaces6, ifs6len) || result;
    }
    closesocket (s6);
    s6 = INVALID_SOCKET;
  }

  if (s4 != INVALID_SOCKET)
  {
    result = EnumNICs_IPv4_get_ifs (s4, &interfaces4, &ifs4len) || result;
    closesocket (s4);
    s4 = INVALID_SOCKET;
  }
  if (ifs6len + ifs4len == 0)
    goto error;

  if (!result)
  {
    *ifs4 = interfaces4;
    *ifs4_len = ifs4len;
    *ifs6 = interfaces6;
    return GNUNET_OK;
  }
error:
  if (interfaces4 != NULL)
    GNUNET_free (interfaces4);
  if (interfaces6 != NULL)
    GNUNET_free (interfaces6);
  if (s4 != INVALID_SOCKET)
    closesocket (s4);
  if (s6 != INVALID_SOCKET)
    closesocket (s6);
  return GNUNET_SYSERR;
}

/**
 * Returns GNUNET_OK on OK, GNUNET_SYSERR on error
 */
int
EnumNICs3 (struct EnumNICs3_results **results, int *results_count)
{
  DWORD dwRetVal = 0;
  int count = 0;
  ULONG flags = /*GAA_FLAG_INCLUDE_PREFIX |*/ GAA_FLAG_SKIP_ANYCAST |
      GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;
  struct sockaddr_in6 examplecom6;
  IPAddr examplecom;
  DWORD best_interface = 0;
  DWORD best_interface6 = 0;

  int use_enum2 = 0;
  INTERFACE_INFO *interfaces4 = NULL;
  int interfaces4_len = 0;
  SOCKET_ADDRESS_LIST *interfaces6 = NULL;

  unsigned long outBufLen = sizeof (IP_ADAPTER_ADDRESSES);
  IP_ADAPTER_ADDRESSES *pCurrentAddress = NULL;
  IP_ADAPTER_ADDRESSES *pAddresses = (IP_ADAPTER_ADDRESSES *) GNUNET_malloc (outBufLen);

  if (GetAdaptersAddresses (AF_UNSPEC, flags, NULL, pAddresses, &outBufLen)
      == ERROR_BUFFER_OVERFLOW)
  {
    GNUNET_free (pAddresses);
    pAddresses = (IP_ADAPTER_ADDRESSES *) GNUNET_malloc (outBufLen);
  }

  dwRetVal = GetAdaptersAddresses (AF_UNSPEC, flags, NULL, pAddresses, &outBufLen);

  if (dwRetVal != NO_ERROR)
  {
    GNUNET_free (pAddresses);
    return GNUNET_SYSERR;
  }

  if (pAddresses->Length < sizeof (IP_ADAPTER_ADDRESSES_VISTA))
  {
    use_enum2 = 1;

    /* Enumerate NICs using WSAIoctl() */
    if (GNUNET_OK != EnumNICs2 (&interfaces4, &interfaces4_len, &interfaces6))
    {
      GNUNET_free (pAddresses);
      return GNUNET_SYSERR;
    }
  }

  examplecom = inet_addr("192.0.34.166"); /* www.example.com */
  if (GetBestInterface (examplecom, &best_interface) != NO_ERROR)
    best_interface = 0;

  if (GNGetBestInterfaceEx != NULL)
  {
    examplecom6.sin6_family = AF_INET6;
    examplecom6.sin6_port = 0;
    examplecom6.sin6_flowinfo = 0;
    examplecom6.sin6_scope_id = 0;
    inet_pton (AF_INET6, "2001:500:88:200:0:0:0:10",
        (struct sockaddr *) &examplecom6.sin6_addr);
    dwRetVal = GNGetBestInterfaceEx ((struct sockaddr *) &examplecom6,
        &best_interface6);
    if (dwRetVal != NO_ERROR)
      best_interface6 = 0;
  }

  /* Give IPv6 a priority */
  if (best_interface6 != 0)
    best_interface = best_interface6;

  count = 0;
  for (pCurrentAddress = pAddresses;
      pCurrentAddress != NULL; pCurrentAddress = pCurrentAddress->Next)
  {
    if (pCurrentAddress->OperStatus == IfOperStatusUp)
    {
      IP_ADAPTER_UNICAST_ADDRESS *unicast = NULL;
      for (unicast = pCurrentAddress->FirstUnicastAddress; unicast != NULL;
          unicast = unicast->Next)
      {
        if ((unicast->Address.lpSockaddr->sa_family == AF_INET ||
            unicast->Address.lpSockaddr->sa_family == AF_INET6) &&
            (unicast->DadState == IpDadStateDeprecated ||
            unicast->DadState == IpDadStatePreferred))
          count += 1;
      }
    }
  }

  if (count == 0)
  {
    *results = NULL;
    *results_count = 0;
    GNUNET_free (pAddresses);
    GNUNET_free_non_null (interfaces4);
    GNUNET_free_non_null (interfaces6);
    return GNUNET_OK;
  }

  *results = (struct EnumNICs3_results *) GNUNET_malloc (
      sizeof (struct EnumNICs3_results) * count);
  *results_count = count;

  count = 0;
  for (pCurrentAddress = pAddresses;
      pCurrentAddress != NULL; pCurrentAddress = pCurrentAddress->Next)
  {
    struct EnumNICs3_results *r;
    IP_ADAPTER_UNICAST_ADDRESS *unicast = NULL;
    if (pCurrentAddress->OperStatus != IfOperStatusUp)
      continue;
    for (unicast = pCurrentAddress->FirstUnicastAddress; unicast != NULL;
        unicast = unicast->Next)
    {
      int i, j;
      int mask_length = -1;
      char dst[INET6_ADDRSTRLEN + 1];

      if ((unicast->Address.lpSockaddr->sa_family != AF_INET &&
          unicast->Address.lpSockaddr->sa_family != AF_INET6) ||
          (unicast->DadState != IpDadStateDeprecated &&
          unicast->DadState != IpDadStatePreferred))
        continue;

      r = &(*results)[count];
      r->flags = 0;
      if (pCurrentAddress->IfIndex > 0 &&
          pCurrentAddress->IfIndex == best_interface &&
          unicast->Address.lpSockaddr->sa_family == AF_INET)
        r->is_default = 1;
      else if (pCurrentAddress->Ipv6IfIndex > 0 &&
          pCurrentAddress->Ipv6IfIndex == best_interface6 &&
          unicast->Address.lpSockaddr->sa_family == AF_INET6)
        r->is_default = 1;
      else
        r->is_default = 0;

      /* Don't choose default interface twice */
      if (r->is_default)
        best_interface = best_interface6 = 0;

      if (!use_enum2)
      {
        memcpy (&r->address, unicast->Address.lpSockaddr,
            unicast->Address.iSockaddrLength);
        memset (&r->mask, 0, sizeof (struct sockaddr));
        mask_length = ((IP_ADAPTER_UNICAST_ADDRESS_VISTA *) unicast)->
              OnLinkPrefixLength;
        /* OnLinkPrefixLength is the number of leading 1s in the mask.
         * OnLinkPrefixLength is available on Vista and later (hence use_enum2).
         */
        if (unicast->Address.lpSockaddr->sa_family == AF_INET)
        {
          struct sockaddr_in *m = (struct sockaddr_in *) &r->mask;
          for (i = 0; i < mask_length; i++)
              ((unsigned char *) &m->sin_addr)[i / 8] |= 0x80 >> (i % 8);
        }
        else if (unicast->Address.lpSockaddr->sa_family == AF_INET6)
        {
          struct sockaddr_in6 *m = (struct sockaddr_in6 *) &r->mask;
          struct sockaddr_in6 *b = (struct sockaddr_in6 *) &r->broadcast;
          for (i = 0; i < mask_length; i++)
            ((unsigned char *) &m->sin6_addr)[i / 8] |= 0x80 >> (i % 8);
          memcpy (&r->broadcast, &r->address, unicast->Address.iSockaddrLength);
          for (i = mask_length; i < 128; i++)
            ((unsigned char *) &b->sin6_addr)[i / 8] |= 0x80 >> (i % 8);
        }
        r->flags |= ENUMNICS3_MASK_OK;
      }
      else
      {
        int found = 0;
        if (unicast->Address.lpSockaddr->sa_family == AF_INET)
        {
          for (i = 0; !found && i < interfaces4_len / sizeof (INTERFACE_INFO); i++)
          {
            struct sockaddr_in *m = (struct sockaddr_in *) &r->mask;
            if (memcpy (&interfaces4[i].iiAddress.Address,
                unicast->Address.lpSockaddr,
                unicast->Address.iSockaddrLength) != 0)
              continue;
            found = 1;
            memcpy (&r->address, &interfaces4[i].iiAddress.Address,
                sizeof (struct sockaddr_in));
            memcpy (&r->mask, &interfaces4[i].iiNetmask.Address,
                sizeof (struct sockaddr_in));
            for (mask_length = 0;
                ((unsigned char *) &m->sin_addr)[mask_length / 8] &
                0x80 >> (mask_length % 8); mask_length++)
            {
            }
            r->flags |= ENUMNICS3_MASK_OK;
          }
        }
        else if (unicast->Address.lpSockaddr->sa_family == AF_INET6)
        {
          for (i = 0;
              interfaces6 != NULL && !found && i < interfaces6->iAddressCount;
              i++)
          {
            if (memcpy (interfaces6->Address[i].lpSockaddr,
                unicast->Address.lpSockaddr,
                unicast->Address.iSockaddrLength) != 0)
              continue;
            found = 1;
            memcpy (&r->address, interfaces6->Address[i].lpSockaddr,
                sizeof (struct sockaddr_in6));
            /* TODO: Find a way to reliably get network mask for IPv6 on XP */
            memset (&r->mask, 0, sizeof (struct sockaddr));
            r->flags &= ~ENUMNICS3_MASK_OK;
          }
        }
        if (!found)
        {
          DebugBreak ();
        }
      }
      if (unicast->Address.lpSockaddr->sa_family == AF_INET)
      {
        struct sockaddr_in *m = (struct sockaddr_in *) &r->mask;
        struct sockaddr_in *a = (struct sockaddr_in *) &r->address;
        /* copy address to broadcast, then flip all the trailing bits not
         * falling under netmask to 1,
         * so we get, 192.168.0.255 from, say, 192.168.0.43 with mask == 24.
         */
        memcpy (&r->broadcast, &r->address, unicast->Address.iSockaddrLength);
        for (i = mask_length; i < 32; i++)
          ((unsigned char *) &m->sin_addr)[i / 8] |= 0x80 >> (i % 8);
        r->flags |= ENUMNICS3_BCAST_OK;
        r->addr_size = sizeof (struct sockaddr_in);
        inet_ntop (AF_INET, &a->sin_addr, dst, INET_ADDRSTRLEN);
      }
      else if (unicast->Address.lpSockaddr->sa_family == AF_INET6)
      {
        struct sockaddr_in6 *a = (struct sockaddr_in6 *) &r->address;
        /* for IPv6 broadcast is not defined, zero it down */
        memset (&r->broadcast, 0, sizeof (struct sockaddr));
        r->flags &= ~ENUMNICS3_BCAST_OK;
        r->addr_size = sizeof (struct sockaddr_in6);
        inet_ntop (AF_INET6, &a->sin6_addr, dst, INET6_ADDRSTRLEN);
      }

      i = 0;
      i += snprintf (&r->pretty_name[i], 1000 - i > 0 ? 1000 - i : 0,
          "%S (%s", pCurrentAddress->FriendlyName, dst);
      for (j = 0; j < pCurrentAddress->PhysicalAddressLength; j++)
        i += snprintf (&r->pretty_name[i], 1000 - i > 0 ? 1000 - i : 0,
            "%s%02X",j > 0 ? ":" : " - ", pCurrentAddress->PhysicalAddress[j]);
      i += snprintf (&r->pretty_name[i], 1000 - i > 0 ? 1000 - i : 0, ")");
      r->pretty_name[1000] = '\0';
      count += 1;
    }
  }

  if (use_enum2)
  {
    GNUNET_free_non_null (interfaces4);
    GNUNET_free_non_null (interfaces6);
  }

  GNUNET_free (pAddresses);
  return GNUNET_OK;
}

void
EnumNICs3_free (struct EnumNICs3_results *r)
{
  GNUNET_free_non_null (r);
}


/**
 * Lists all network interfaces in a combo box
 * Used by the basic GTK configurator
 *
 * @param callback function to call for each NIC
 * @param callback_cls closure for callback
 */
int
ListNICs (void (*callback) (void *, const char *, int), void * callback_cls)
{
  int r;
  int i;
  struct EnumNICs3_results *results = NULL;
  int results_count;

  r = EnumNICs3 (&results, &results_count);
  if (r != GNUNET_OK)
    return GNUNET_NO;

  for (i = 0; i < results_count; i++)
    callback (callback_cls, results[i].pretty_name, results[i].is_default);
  GNUNET_free_non_null (results);
  return GNUNET_YES;
}

/**
 * @brief Installs the Windows service
 * @param servicename name of the service as diplayed by the SCM
 * @param application path to the application binary
 * @param username the name of the service's user account
 * @returns 0 on success
 *          1 if the Windows version doesn't support services
 *          2 if the SCM could not be opened
 *          3 if the service could not be created
 */
int InstallAsService(char *servicename, char *application, char *username)
{
  SC_HANDLE hManager, hService;
  char szEXE[_MAX_PATH + 17] = "\"";
  char *user = NULL;

  if (! GNOpenSCManager)
    return 1;

  plibc_conv_to_win_path(application, szEXE + 1);
  strcat(szEXE, "\" --win-service");
  hManager = GNOpenSCManager(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
  if (! hManager)
    return 2;

  if (username)
  {
  	user = (char *) malloc(strlen(username) + 3);
  	sprintf(user, ".\\%s", username);
  }

  hService = GNCreateService(hManager, (LPCTSTR) servicename, (LPCTSTR) servicename, 0,
    SERVICE_WIN32_OWN_PROCESS, SERVICE_AUTO_START, SERVICE_ERROR_NORMAL, (LPCTSTR) szEXE,
    NULL, NULL, NULL, (LPCTSTR) user, (LPCTSTR) username);

  if (user)
    free(user);

  if (! hService)
    return 3;

  GNCloseServiceHandle(hService);

  return 0;
}

/**
 * @brief Uninstall Windows service
 * @param servicename name of the service to delete
 * @returns 0 on success
 *          1 if the Windows version doesn't support services
 *          2 if the SCM could not be openend
 *          3 if the service cannot be accessed
 *          4 if the service cannot be deleted
 */
int UninstallService(char *servicename)
{
  SC_HANDLE hManager, hService;

  if (! GNOpenSCManager)
    return 1;

  hManager = GNOpenSCManager(NULL, NULL, SC_MANAGER_CONNECT);
  if (! hManager)
    return 2;

  if (! (hService = GNOpenService(hManager, (LPCTSTR) servicename, DELETE)))
    if (GetLastError() != ERROR_SERVICE_DOES_NOT_EXIST)
      return 3;
     else
     	goto closeSCM;

  if (! GNDeleteService(hService))
    if (GetLastError() != ERROR_SERVICE_MARKED_FOR_DELETE)
      return 4;

closeSCM:
  GNCloseServiceHandle(hService);

  return 0;
}

/**
 * @author Scott Field, Microsoft
 * @see http://support.microsoft.com/?scid=kb;en-us;132958
 * @date 12-Jul-95
 */
void _InitLsaString(PLSA_UNICODE_STRING LsaString, LPWSTR String)
{
  DWORD StringLength;

  if(String == NULL)
  {
    LsaString->Buffer = NULL;
    LsaString->Length = 0;
    LsaString->MaximumLength = 0;
    return;
  }

  StringLength = wcslen(String);
  LsaString->Buffer = String;
  LsaString->Length = (USHORT) StringLength *sizeof(WCHAR);
  LsaString->MaximumLength = (USHORT) (StringLength + 1) * sizeof(WCHAR);
}


/**
 * @author Scott Field, Microsoft
 * @see http://support.microsoft.com/?scid=kb;en-us;132958
 * @date 12-Jul-95
 */
NTSTATUS _OpenPolicy(LPWSTR ServerName, DWORD DesiredAccess, PLSA_HANDLE PolicyHandle)
{
  LSA_OBJECT_ATTRIBUTES ObjectAttributes;
  LSA_UNICODE_STRING ServerString;
  PLSA_UNICODE_STRING Server = NULL;

  /* Always initialize the object attributes to all zeroes. */
  ZeroMemory(&ObjectAttributes, sizeof(ObjectAttributes));

  if(ServerName != NULL)
  {
    /* Make a LSA_UNICODE_STRING out of the LPWSTR passed in */
    _InitLsaString(&ServerString, ServerName);
    Server = &ServerString;
  }

  /* Attempt to open the policy. */
  return GNLsaOpenPolicy(Server,
                       &ObjectAttributes, DesiredAccess, PolicyHandle);
}

/**
 * @brief Obtain a SID representing the supplied account on the supplied system
 * @return TRUE on success, FALSE on failure
 * @author Scott Field, Microsoft
 * @date 12-Jul-95
 * @remarks A buffer is allocated which contains the SID representing the
 *          supplied account. This buffer should be freed when it is no longer
 *          needed by calling\n
 *            HeapFree(GetProcessHeap(), 0, buffer)
 * @remarks Call GetLastError() to obtain extended error information.
 * @see http://support.microsoft.com/?scid=kb;en-us;132958
 */
BOOL _GetAccountSid(LPCTSTR SystemName, LPCTSTR AccountName, PSID * Sid)
{
  LPTSTR ReferencedDomain = NULL;
  DWORD cbSid = 128;  							/* initial allocation attempt */
  DWORD cchReferencedDomain = 16;  	/* initial allocation size */
  SID_NAME_USE peUse;
  BOOL bSuccess = FALSE;  					/* assume this function will fail */

  /* initial memory allocations */
  if ((*Sid = HeapAlloc (GetProcessHeap (), 0, cbSid)) == NULL)
  	return FALSE;

  if ((ReferencedDomain = (LPTSTR) HeapAlloc (GetProcessHeap (),
  				    0,
  				    cchReferencedDomain *
  				    sizeof (TCHAR))) == NULL)
  	return FALSE;

    /* Obtain the SID of the specified account on the specified system. */
  	while (!GNLookupAccountName(SystemName,	/* machine to lookup account on */
  		   AccountName,												/* account to lookup */
  		   *Sid,															/* SID of interest */
  		   &cbSid,														/* size of SID */
  		   ReferencedDomain,									/* domain account was found on */
  		   &cchReferencedDomain, &peUse))
  	{
  		if (GetLastError() == ERROR_INSUFFICIENT_BUFFER)
  		{
  			/* reallocate memory */
  			if ((*Sid = HeapReAlloc (GetProcessHeap (), 0, *Sid, cbSid)) == NULL)
  				return FALSE;

  			if ((ReferencedDomain = (LPTSTR) HeapReAlloc (GetProcessHeap (),
  					      0,
  					      ReferencedDomain,
  					      cchReferencedDomain
  					      * sizeof (TCHAR))) == NULL)
  				return FALSE;
      }
      else
        goto end;
  }

  /* Indicate success. */
  bSuccess = TRUE;

end:
  /* Cleanup and indicate failure, if appropriate. */
  HeapFree (GetProcessHeap (), 0, ReferencedDomain);

  if (!bSuccess)
  {
    if (*Sid != NULL)
    {
  		HeapFree (GetProcessHeap (), 0, *Sid);
  		*Sid = NULL;
    }
  }

  return bSuccess;
}

/**
 * @author Scott Field, Microsoft
 * @see http://support.microsoft.com/?scid=kb;en-us;132958
 * @date 12-Jul-95
 */
NTSTATUS _SetPrivilegeOnAccount(LSA_HANDLE PolicyHandle,/* open policy handle */
                               PSID AccountSid,   			/* SID to grant privilege to */
                               LPWSTR PrivilegeName,  	/* privilege to grant (Unicode) */
                               BOOL bEnable  						/* enable or disable */
  )
{
  LSA_UNICODE_STRING PrivilegeString;

  /* Create a LSA_UNICODE_STRING for the privilege name. */
  _InitLsaString(&PrivilegeString, PrivilegeName);

  /* grant or revoke the privilege, accordingly */
  if(bEnable)
  {
    NTSTATUS i;

    i = GNLsaAddAccountRights(PolicyHandle,  				/* open policy handle */
                               AccountSid,        			/* target SID */
                               &PrivilegeString,        /* privileges */
                               1  											/* privilege count */
      );
  }
  else
  {
    return GNLsaRemoveAccountRights(PolicyHandle,  			/* open policy handle */
                                  AccountSid,     			/* target SID */
                                  FALSE,  							/* do not disable all rights */
                                  &PrivilegeString,  		/* privileges */
                                  1  										/* privilege count */
      );
  }
}

/**
 * @brief Create a Windows service account
 * @return 0 on success, > 0 otherwise
 * @param pszName the name of the account
 * @param pszDesc description of the account
 */
int CreateServiceAccount(const char *pszName, const char *pszDesc)
{
  USER_INFO_1 ui;
  USER_INFO_1008 ui2;
  NET_API_STATUS nStatus;
  wchar_t wszName[MAX_NAME_LENGTH], wszDesc[MAX_NAME_LENGTH];
  DWORD dwErr;
  LSA_HANDLE hPolicy;
  PSID pSID;

  if (! GNNetUserAdd)
  	return 1;
  mbstowcs(wszName, pszName, strlen(pszName) + 1);
  mbstowcs(wszDesc, pszDesc, strlen(pszDesc) + 1);

  memset(&ui, 0, sizeof(ui));
  ui.usri1_name = wszName;
  ui.usri1_password = wszName; /* account is locked anyway */
  ui.usri1_priv = USER_PRIV_USER;
  ui.usri1_comment = wszDesc;
  ui.usri1_flags = UF_SCRIPT;

  nStatus = GNNetUserAdd(NULL, 1, (LPBYTE)&ui, NULL);

  if (nStatus != NERR_Success && nStatus != NERR_UserExists)
  	return 2;

  ui2.usri1008_flags = UF_PASSWD_CANT_CHANGE | UF_DONT_EXPIRE_PASSWD;
  GNNetUserSetInfo(NULL, wszName, 1008, (LPBYTE)&ui2, NULL);

  if (_OpenPolicy(NULL, POLICY_ALL_ACCESS, &hPolicy) !=
  										STATUS_SUCCESS)
  	return 3;

  _GetAccountSid(NULL, (LPCTSTR) pszName, &pSID);

  if (_SetPrivilegeOnAccount(hPolicy, pSID, (LPWSTR) L"SeServiceLogonRight", TRUE) != STATUS_SUCCESS)
  	return 4;

  _SetPrivilegeOnAccount(hPolicy, pSID, (LPWSTR) L"SeDenyInteractiveLogonRight", TRUE);
  _SetPrivilegeOnAccount(hPolicy, pSID, (LPWSTR) L"SeDenyBatchLogonRight", TRUE);
  _SetPrivilegeOnAccount(hPolicy, pSID, (LPWSTR) L"SeDenyNetworkLogonRight", TRUE);

  GNLsaClose(hPolicy);

  return 0;
}

/**
 * @brief Grant permission to a file
 * @param lpszFileName the name of the file or directory
 * @param lpszAccountName the user account
 * @param dwAccessMask the desired access (e.g. GENERIC_ALL)
 * @return TRUE on success
 * @remark based on http://support.microsoft.com/default.aspx?scid=KB;EN-US;Q102102&
 */
BOOL AddPathAccessRights(char *lpszFileName, char *lpszAccountName,
      DWORD dwAccessMask)
{
  /* SID variables. */
  SID_NAME_USE   snuType;
  TCHAR *        szDomain       = NULL;
  DWORD          cbDomain       = 0;
  LPVOID         pUserSID       = NULL;
  DWORD          cbUserSID      = 0;

  /* File SD variables. */
  PSECURITY_DESCRIPTOR pFileSD  = NULL;
  DWORD          cbFileSD       = 0;

  /* New SD variables. */
  SECURITY_DESCRIPTOR  newSD;

  /* ACL variables. */
  PACL           pACL           = NULL;
  BOOL           fDaclPresent;
  BOOL           fDaclDefaulted;
  ACL_SIZE_INFORMATION AclInfo;

  /* New ACL variables. */
  PACL           pNewACL        = NULL;
  DWORD          cbNewACL       = 0;

  /* Temporary ACE. */
  LPVOID         pTempAce       = NULL;
  UINT           CurrentAceIndex = 0;

  UINT           newAceIndex = 0;

  /* Assume function will fail. */
  BOOL           fResult        = FALSE;
  BOOL           fAPISuccess;

  SECURITY_INFORMATION secInfo = DACL_SECURITY_INFORMATION;

  /**
   * STEP 1: Get SID of the account name specified.
   */
  fAPISuccess = GNLookupAccountName(NULL, (LPCTSTR) lpszAccountName,
        pUserSID, &cbUserSID, (LPTSTR) szDomain, &cbDomain, &snuType);

  /* API should have failed with insufficient buffer. */
  if (fAPISuccess)
     goto end;
  else if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
     goto end;
  }

  pUserSID = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, cbUserSID);
  if (!pUserSID) {
     goto end;
  }

  szDomain = (TCHAR *) HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, cbDomain * sizeof(TCHAR));
  if (!szDomain) {
     goto end;
  }

  fAPISuccess = GNLookupAccountName(NULL, (LPCTSTR) lpszAccountName,
        pUserSID, &cbUserSID, (LPTSTR) szDomain, &cbDomain, &snuType);
  if (!fAPISuccess) {
     goto end;
  }

  /**
   *  STEP 2: Get security descriptor (SD) of the file specified.
   */
  fAPISuccess = GNGetFileSecurity((LPCTSTR) lpszFileName,
        secInfo, pFileSD, 0, &cbFileSD);

  /* API should have failed with insufficient buffer. */
  if (fAPISuccess)
     goto end;
  else if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
     goto end;
  }

  pFileSD = (PSECURITY_DESCRIPTOR) HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY,
  	cbFileSD);
  if (!pFileSD) {
     goto end;
  }

  fAPISuccess = GNGetFileSecurity((LPCTSTR) lpszFileName,
        secInfo, pFileSD, cbFileSD, &cbFileSD);
  if (!fAPISuccess) {
     goto end;
  }

  /**
   * STEP 3: Initialize new SD.
   */
  if (!GNInitializeSecurityDescriptor(&newSD,
        SECURITY_DESCRIPTOR_REVISION)) {
     goto end;
  }

  /**
   * STEP 4: Get DACL from the old SD.
   */
  if (!GNGetSecurityDescriptorDacl(pFileSD, &fDaclPresent, &pACL,
        &fDaclDefaulted)) {
     goto end;
  }

  /**
   * STEP 5: Get size information for DACL.
   */
  AclInfo.AceCount = 0; // Assume NULL DACL.
  AclInfo.AclBytesFree = 0;
  AclInfo.AclBytesInUse = sizeof(ACL);

  if (pACL == NULL)
     fDaclPresent = FALSE;

  /* If not NULL DACL, gather size information from DACL. */
  if (fDaclPresent) {

     if (!GNGetAclInformation(pACL, &AclInfo,
           sizeof(ACL_SIZE_INFORMATION), AclSizeInformation)) {
        goto end;
     }
  }

  /**
   * STEP 6: Compute size needed for the new ACL.
   */
  cbNewACL = AclInfo.AclBytesInUse + sizeof(ACCESS_ALLOWED_ACE)
        + GetLengthSid(pUserSID) - sizeof(DWORD);

  /**
   * STEP 7: Allocate memory for new ACL.
   */
  pNewACL = (PACL) HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, cbNewACL);
  if (!pNewACL) {
     goto end;
  }

  /**
   * STEP 8: Initialize the new ACL.
   */
  if (!GNInitializeAcl(pNewACL, cbNewACL, ACL_REVISION2)) {
     goto end;
  }

  /**
   * STEP 9 If DACL is present, copy all the ACEs from the old DACL
   * to the new DACL.
   *
   * The following code assumes that the old DACL is
   * already in Windows 2000 preferred order.  To conform
   * to the new Windows 2000 preferred order, first we will
   * copy all non-inherited ACEs from the old DACL to the
   * new DACL, irrespective of the ACE type.
   */

  newAceIndex = 0;

  if (fDaclPresent && AclInfo.AceCount) {

     for (CurrentAceIndex = 0;
           CurrentAceIndex < AclInfo.AceCount;
           CurrentAceIndex++) {

        /**
         * TEP 10: Get an ACE.
         */
        if (!GNGetAce(pACL, CurrentAceIndex, &pTempAce)) {
           goto end;
        }

        /**
         * STEP 11: Check if it is a non-inherited ACE.
         * If it is an inherited ACE, break from the loop so
         * that the new access allowed non-inherited ACE can
         * be added in the correct position, immediately after
         * all non-inherited ACEs.
         */
        if (((ACCESS_ALLOWED_ACE *)pTempAce)->Header.AceFlags
           & INHERITED_ACE)
           break;

        /**
         * STEP 12: Skip adding the ACE, if the SID matches
         * with the account specified, as we are going to
         * add an access allowed ACE with a different access
         * mask.
         */
        if (GNEqualSid(pUserSID,
           &(((ACCESS_ALLOWED_ACE *)pTempAce)->SidStart)))
           continue;

        /**
         * STEP 13: Add the ACE to the new ACL.
         */
        if (!GNAddAce(pNewACL, ACL_REVISION, MAXDWORD, pTempAce,
              ((PACE_HEADER) pTempAce)->AceSize)) {
           goto end;
        }

        newAceIndex++;
     }
  }

  /**
   * STEP 14: Add the access-allowed ACE to the new DACL.
   * The new ACE added here will be in the correct position,
   * immediately after all existing non-inherited ACEs.
   */
  if (!GNAddAccessAllowedAce(pNewACL, ACL_REVISION2, dwAccessMask,
        pUserSID)) {
     goto end;
  }

  /**
   * STEP 14.5: Make new ACE inheritable
   */
  if (!GetAce(pNewACL, newAceIndex, &pTempAce))
    goto end;
  ((ACCESS_ALLOWED_ACE *)pTempAce)->Header.AceFlags |=
    (CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE);

  /**
   * STEP 15: To conform to the new Windows 2000 preferred order,
   * we will now copy the rest of inherited ACEs from the
   * old DACL to the new DACL.
   */
  if (fDaclPresent && AclInfo.AceCount) {

     for (;
          CurrentAceIndex < AclInfo.AceCount;
          CurrentAceIndex++) {

        /**
         * STEP 16: Get an ACE.
         */
        if (!GNGetAce(pACL, CurrentAceIndex, &pTempAce)) {
           goto end;
        }

        /**
         * STEP 17: Add the ACE to the new ACL.
         */
        if (!GNAddAce(pNewACL, ACL_REVISION, MAXDWORD, pTempAce,
              ((PACE_HEADER) pTempAce)->AceSize)) {
           goto end;
        }
     }
  }

  /**
   * STEP 18: Set permissions
   */
  if (GNSetNamedSecurityInfo((LPTSTR) lpszFileName, SE_FILE_OBJECT,
    DACL_SECURITY_INFORMATION, NULL, NULL, pNewACL, NULL) != ERROR_SUCCESS) {
    	goto end;
  }

  fResult = TRUE;

end:

  /**
   * STEP 19: Free allocated memory
   */
  if (pUserSID)
     HeapFree(GetProcessHeap(), 0, pUserSID);

  if (szDomain)
     HeapFree(GetProcessHeap(), 0, szDomain);

  if (pFileSD)
     HeapFree(GetProcessHeap(), 0, pFileSD);

  if (pNewACL)
     HeapFree(GetProcessHeap(), 0, pNewACL);

  return fResult;
}

char *winErrorStr(const char *prefix, int dwErr)
{
  char *err, *ret;
  int mem;

  if (! FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM,
    NULL, (DWORD) dwErr, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPTSTR) &err,
    0, NULL ))
  {
    err = (char *) LocalAlloc (LMEM_FIXED | LMEM_ZEROINIT, 1);
  }

  mem = strlen(err) + strlen(prefix) + 20;
  ret = (char *) malloc(mem);

  snprintf(ret, mem, "%s: %s (#%u)", prefix, err, dwErr);

  LocalFree(err);

  return ret;
}

} /* extern "C" */

#endif

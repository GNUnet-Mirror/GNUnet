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
 * @file gns/w32nsp.c
 * @brief W32 integration for GNS
 * @author LRN
 */
/* This code is partially based upon samples from the book
 * "Network Programming For Microsoft Windows, 2Nd Edition".
 */

#define INITGUID
#include <windows.h>
#include <nspapi.h>
#include <stdint.h>
#include <ws2tcpip.h>
#include <ws2spi.h>

#if 1
#  define DEBUGLOG(s, ...)
#endif
#if 0
#  define DEBUGLOG(s, ...) printf (s, ##__VA_ARGS__)
#endif

#define WINDOWS 1
#define MINGW 1
#ifndef __BYTE_ORDER
#ifdef _BYTE_ORDER
#define __BYTE_ORDER _BYTE_ORDER
#else
#ifdef BYTE_ORDER
#define __BYTE_ORDER BYTE_ORDER
#endif
#endif
#endif
#ifndef __BIG_ENDIAN
#ifdef _BIG_ENDIAN
#define __BIG_ENDIAN _BIG_ENDIAN
#else
#ifdef BIG_ENDIAN
#define __BIG_ENDIAN BIG_ENDIAN
#endif
#endif
#endif
#ifndef __LITTLE_ENDIAN
#ifdef _LITTLE_ENDIAN
#define __LITTLE_ENDIAN _LITTLE_ENDIAN
#else
#ifdef LITTLE_ENDIAN
#define __LITTLE_ENDIAN LITTLE_ENDIAN
#endif
#endif
#endif
#include "gnunet_w32nsp_lib.h"
#include "w32resolver.h"

#define NSPAPI_VERSION_MAJOR 4
#define NSPAPI_VERSION_MINOR 4

#define REPLY_LIFETIME 60*5

#define STATE_BEGIN  0x01
#define STATE_END    0x02
#define STATE_REPLY  0x04
#define STATE_GHBN   0x08

uint64_t
GNUNET_htonll (uint64_t n)
{
#if __BYTE_ORDER == __BIG_ENDIAN
  return n;
#elif __BYTE_ORDER == __LITTLE_ENDIAN
  return (((uint64_t) htonl (n)) << 32) + htonl (n >> 32);
#else
  #error byteorder undefined
#endif
}

CRITICAL_SECTION records_cs;

struct record
{
  SOCKET s;
  DWORD flags;
  uint8_t state;
  char *buf;
  wchar_t *name;
};

static struct record *records = NULL;
static size_t records_len = 0;
static size_t records_size = 0;

int
resize_records ()
{
  size_t new_size = records_len > 0 ? records_len * 2 : 5;
  struct record *new_records = malloc (new_size * sizeof (struct record));
  if (new_records == NULL)
  {
    SetLastError (WSA_NOT_ENOUGH_MEMORY);
    return 0;
  }
  memcpy (new_records, records, records_len * sizeof (struct record));
  memset (&new_records[records_len], 0, sizeof (struct record) * (new_size - records_len));
  records_size = new_size;
  free (records);
  records = new_records;
  return 1;
}

int
add_record (SOCKET s, const wchar_t *name, DWORD flags)
{
  int res = 1;
  int i;
  int empty = -1;
  //EnterCriticalSection (&records_cs);
  for (i = 0; i < records_len; i++)
    if (records[i].state == 0)
      break;
  empty = i;
  if (i == records_len)
  {
    res = resize_records ();
    if (res)
      empty = records_len++;
  }
  if (res)
  {
    struct record r;
    r.s = s;
    r.flags = flags;
    r.name = (wchar_t *) name;
    r.state = 1;
    r.buf = NULL;
    if (name)
      r.name = wcsdup (name);
    records[empty] = r;
  }
  //LeaveCriticalSection (&records_cs);
  return res;
}

void
free_record (int i)
{
  if (records[i].name)
    free (records[i].name);
  records[i].state = 0;
}

/* These are not defined by mingw.org headers at the moment*/
typedef INT (WSPAPI *LPNSPIOCTL) (HANDLE,DWORD,LPVOID,DWORD,LPVOID,DWORD,LPDWORD,LPWSACOMPLETION,LPWSATHREADID);
typedef struct _NSP_ROUTINE_XP {
  DWORD cbSize;
  DWORD dwMajorVersion;
  DWORD dwMinorVersion;
  LPNSPCLEANUP NSPCleanup;
  LPNSPLOOKUPSERVICEBEGIN NSPLookupServiceBegin;
  LPNSPLOOKUPSERVICENEXT NSPLookupServiceNext;
  LPNSPLOOKUPSERVICEEND NSPLookupServiceEnd;
  LPNSPSETSERVICE NSPSetService;
  LPNSPINSTALLSERVICECLASS NSPInstallServiceClass;
  LPNSPREMOVESERVICECLASS NSPRemoveServiceClass;
  LPNSPGETSERVICECLASSINFO NSPGetServiceClassInfo;
  LPNSPIOCTL NSPIoctl;
} NSP_ROUTINE_XP;

static SOCKET
connect_to_dns_resolver ()
{
  struct sockaddr_in addr;
  SOCKET r;
  int ret;

  r = socket (AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (INVALID_SOCKET == r)
  {
    SetLastError (16004);
    return r;
  }

  addr.sin_family = AF_INET;
  addr.sin_port = htons (5353); /* TCP 5353 is not registered; UDP 5353 is */
  addr.sin_addr.s_addr = inet_addr ("127.0.0.1");

  ret = connect (r, (struct sockaddr *) &addr, sizeof (addr));
  if (SOCKET_ERROR == ret)
  {
    DWORD err = GetLastError ();
    closesocket (r);
    SetLastError (err);
    SetLastError (16005);
    r = INVALID_SOCKET;
  }
  return r;
}

static int
send_name_to_ip_request (LPWSAQUERYSETW lpqsRestrictions,
    LPWSASERVICECLASSINFOW lpServiceClassInfo, DWORD dwControlFlags,
    SOCKET *resolver)
{
  struct GNUNET_W32RESOLVER_GetMessage *msg;
  int af4 = 0;
  int af6 = 0;
  char *buf;
  int ret = 1;
  int i;
  uint32_t id;
  size_t size = sizeof (struct GNUNET_W32RESOLVER_GetMessage);
  size_t namelen = 0;
  if (lpqsRestrictions->lpszServiceInstanceName)
    namelen = sizeof (wchar_t) * (wcslen (lpqsRestrictions->lpszServiceInstanceName) + 1);
  size += namelen;
  buf = malloc (size);
  msg = (struct GNUNET_W32RESOLVER_GetMessage *) buf;
  msg->header.size = htons (size);
  msg->header.type = htons (GNUNET_MESSAGE_TYPE_W32RESOLVER_REQUEST);
  if (lpqsRestrictions->dwNumberOfProtocols > 0)
  {
    int i;
    for (i = 0; i < lpqsRestrictions->dwNumberOfProtocols; i++)
    {
      if (lpqsRestrictions->lpafpProtocols[0].iAddressFamily == AF_INET)
        af4 = 1;
      if (lpqsRestrictions->lpafpProtocols[0].iAddressFamily == AF_INET6)
        af6 = 1;
    }
  }
  if (af4 && !af6)
    msg->af = htonl (AF_INET);
  else if (af6 && !af4)
    msg->af = htonl (AF_INET6);
  else
    msg->af = htonl (AF_UNSPEC);
  if (lpqsRestrictions->lpszServiceInstanceName)
    memcpy (&msg[1], lpqsRestrictions->lpszServiceInstanceName, namelen);
  msg->sc_data1 = htonl (lpqsRestrictions->lpServiceClassId->Data1);
  msg->sc_data2 = htons (lpqsRestrictions->lpServiceClassId->Data2);
  msg->sc_data3 = htons (lpqsRestrictions->lpServiceClassId->Data3);
  msg->sc_data4 = 0;
  for (i = 0; i < 8; i++)
    msg->sc_data4 |= ((uint64_t) lpqsRestrictions->lpServiceClassId->Data4[i]) << ((7 - i) * 8);
  msg->sc_data4 = GNUNET_htonll (msg->sc_data4);
  *resolver = connect_to_dns_resolver ();
  if (*resolver != INVALID_SOCKET)
  {
    if (size != send (*resolver, buf, size, 0))
    {
      DWORD err = GetLastError ();
      closesocket (*resolver);
      *resolver = INVALID_SOCKET;
      DEBUGLOG ("GNUNET_W32NSP_LookupServiceBegin: failed to send request: %lu\n", err);
      SetLastError (WSATRY_AGAIN);
      ret = 0;
    }
  }
  else
    ret = 0;
  free (buf);
  return ret;
}

int WSPAPI
NSPCleanup (LPGUID lpProviderId)
{
  DEBUGLOG ("NSPCleanup\n");
  if (IsEqualGUID (lpProviderId, &GNUNET_NAMESPACE_PROVIDER_DNS))
  {
    return NO_ERROR;
  }
  SetLastError (WSAEINVALIDPROVIDER);
  return SOCKET_ERROR;
}

BOOL WINAPI
DllMain (HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
  switch (fdwReason)
  {
    case DLL_PROCESS_ATTACH:
      if (!InitializeCriticalSectionAndSpinCount (&records_cs, 0x00000400))
      {
        return FALSE;
      }
      break;
    case DLL_THREAD_ATTACH:
      break;
    case DLL_THREAD_DETACH:
      break;
    case DLL_PROCESS_DETACH:
      DeleteCriticalSection (&records_cs);
      break;
  }
  return TRUE;
}




int WSPAPI
GNUNET_W32NSP_LookupServiceBegin (LPGUID lpProviderId, LPWSAQUERYSETW lpqsRestrictions,
    LPWSASERVICECLASSINFOW lpServiceClassInfo, DWORD dwControlFlags,
    LPHANDLE lphLookup)
{
  DEBUGLOG ("GNUNET_W32NSP_LookupServiceBegin\n");
  if (IsEqualGUID (lpProviderId, &GNUNET_NAMESPACE_PROVIDER_DNS))
  {
    SOCKET s;
    if (lpqsRestrictions->dwNameSpace != NS_DNS && lpqsRestrictions->dwNameSpace != NS_ALL)
    {
      DEBUGLOG ("GNUNET_W32NSP_LookupServiceBegin: wrong namespace\n");
      SetLastError (WSANO_DATA);
      return SOCKET_ERROR;
    }
    if (lpqsRestrictions->lpszServiceInstanceName != NULL)
    {
      wchar_t *s = lpqsRestrictions->lpszServiceInstanceName;
      size_t len = wcslen (s);
      if (len >= 4 && wcscmp (&s[len - 4], L"zkey") == 0)
      {
      }
      else if (len >= 4 && wcscmp (&s[len - 4], L"gads") == 0)
      {
      }
      else
      {
        DEBUGLOG ("GNUNET_W32NSP_LookupServiceBegin: unsupported TLD\n");
        SetLastError (WSANO_DATA);
        return SOCKET_ERROR;
      }
    }

    if (send_name_to_ip_request (lpqsRestrictions,
        lpServiceClassInfo, dwControlFlags, &s))
    {
      if (!(add_record (s, lpqsRestrictions->lpszServiceInstanceName, dwControlFlags)))
      {
        DWORD err = GetLastError ();
        DEBUGLOG ("GNUNET_W32NSP_LookupServiceBegin: failed to add a record\n");
        closesocket (s);
        SetLastError (err);
        return SOCKET_ERROR;
      }
      *lphLookup = (HANDLE) s;
      DEBUGLOG ("GNUNET_W32NSP_LookupServiceBegin: OK (%lu)\n", GetLastError ());
      return NO_ERROR;
    }
    return SOCKET_ERROR;
  }
  DEBUGLOG ("GNUNET_W32NSP_LookupServiceBegin: wrong provider\n");
  SetLastError (WSAEINVALIDPROVIDER);
  return SOCKET_ERROR;
}

#define UnmarshallPtr(ptr, ptrtype, base) \
  if (ptr) \
    ptr = (ptrtype *) (base + (uintptr_t) ptr)

void
UnmarshallWSAQUERYSETW (LPWSAQUERYSETW req)
{
  int i;
  char *base = (char *) req;
  UnmarshallPtr (req->lpszServiceInstanceName, wchar_t, base);
  UnmarshallPtr (req->lpServiceClassId, GUID, base);
  UnmarshallPtr (req->lpVersion, WSAVERSION, base);
  UnmarshallPtr (req->lpszComment, wchar_t, base);
  UnmarshallPtr (req->lpNSProviderId, GUID, base);
  UnmarshallPtr (req->lpszContext, wchar_t, base);
  UnmarshallPtr (req->lpafpProtocols, AFPROTOCOLS, base);
  UnmarshallPtr (req->lpszQueryString, wchar_t, base);
  UnmarshallPtr (req->lpcsaBuffer, CSADDR_INFO, base);
  for (i = 0; i < req->dwNumberOfCsAddrs; i++)
  {
    UnmarshallPtr (req->lpcsaBuffer[i].LocalAddr.lpSockaddr, SOCKADDR, base);
    UnmarshallPtr (req->lpcsaBuffer[i].RemoteAddr.lpSockaddr, SOCKADDR, base);
  }
  UnmarshallPtr (req->lpBlob, BLOB, base);
  if (req->lpBlob)
    UnmarshallPtr (req->lpBlob->pBlobData, BYTE, base);
}

int WSAAPI
GNUNET_W32NSP_LookupServiceNext (HANDLE hLookup, DWORD dwControlFlags,
    LPDWORD lpdwBufferLength, LPWSAQUERYSET lpqsResults)
{
  DWORD effective_flags;
  int i;
  struct GNUNET_MessageHeader header = {0, 0};
  int rec = -1;
  int rc;
  int to_receive;
  int t;
  char *buf;

  DEBUGLOG ("GNUNET_W32NSP_LookupServiceNext\n");
  //EnterCriticalSection (&records_cs);
  for (i = 0; i < records_len; i++)
  {
    if (records[i].s == (SOCKET) hLookup)
    {
      rec = i;
      break;
    }
  }
  if (rec == -1)
  {
    DEBUGLOG ("GNUNET_W32NSP_LookupServiceNext: invalid handle\n");
    SetLastError (WSA_INVALID_HANDLE);
    //LeaveCriticalSection (&records_cs);
    return SOCKET_ERROR;
  }
  if (records[rec].state & 4)
  {
    DEBUGLOG ("GNUNET_W32NSP_LookupServiceNext: session is closed\n");
    SetLastError (WSA_E_NO_MORE);
    //LeaveCriticalSection (&records_cs);
    return SOCKET_ERROR;
  }
  effective_flags = dwControlFlags & records[rec].flags;
  if (records[rec].buf)
  {
    header = *((struct GNUNET_MessageHeader *) records[rec].buf);
    if (dwControlFlags & LUP_FLUSHCACHE)
    {
      free (records[rec].buf);
      records[rec].buf = NULL;
    }
    else
    {
      if (*lpdwBufferLength < header.size - sizeof (struct GNUNET_W32RESOLVER_GetMessage))
      {
        DEBUGLOG ("GNUNET_W32NSP_LookupServiceNext: client buffer is too small\n");
        SetLastError (WSAEFAULT);
        //LeaveCriticalSection (&records_cs);
        return SOCKET_ERROR;
      }
      memcpy (lpqsResults, &((struct GNUNET_W32RESOLVER_GetMessage *)records[rec].buf)[1], header.size - sizeof (struct GNUNET_W32RESOLVER_GetMessage));
      free (records[rec].buf);
      records[rec].buf = NULL;
      //LeaveCriticalSection (&records_cs);
      UnmarshallWSAQUERYSETW ((LPWSAQUERYSETW) lpqsResults);
      DEBUGLOG ("GNUNET_W32NSP_LookupServiceNext: OK (from buffer)\n");
      return NO_ERROR;
    }
  }
  records[rec].state |= 8;
  //LeaveCriticalSection (&records_cs);
  to_receive = sizeof (header);
  rc = 0;
  while (to_receive > 0)
  {
    t = recv ((SOCKET) hLookup, &((char *) &header)[rc], to_receive, 0);
    if (t > 0)
    {
      rc += t;
      to_receive -= t;
    }
    else
      break;
  }
  //EnterCriticalSection (&records_cs);
  records[rec].state &= ~8;
  if (rc != sizeof (header))
  {
    if (records[rec].state & 2)
    {
      DEBUGLOG ("GNUNET_W32NSP_LookupServiceNext: call cancelled\n");
      SetLastError (WSA_E_CANCELLED);
    }
    else
    {
      DEBUGLOG ("GNUNET_W32NSP_LookupServiceNext: failed to receive enough data\n");
      SetLastError (WSA_E_NO_MORE);
    }
    records[rec].state |= 4;
    //LeaveCriticalSection (&records_cs);
    return SOCKET_ERROR;
  }
  records[rec].state &= ~8;
  header.type = ntohs (header.type);
  header.size = ntohs (header.size);
  if (header.type != GNUNET_MESSAGE_TYPE_W32RESOLVER_RESPONSE ||
      (header.type == GNUNET_MESSAGE_TYPE_W32RESOLVER_RESPONSE &&
      header.size == sizeof (header)))
  {
    records[rec].state |= 4;
    DEBUGLOG ("GNUNET_W32NSP_LookupServiceNext: header is wrong or type is wrong or no data\n");
    //LeaveCriticalSection (&records_cs);
    SetLastError (WSA_E_NO_MORE);
    return SOCKET_ERROR;
  }
  buf = malloc (header.size);
  if (buf == NULL)
  {
    records[rec].state |= 4;
    DEBUGLOG ("GNUNET_W32NSP_LookupServiceNext: malloc() failed\n");
    //LeaveCriticalSection (&records_cs);
    SetLastError (WSA_E_NO_MORE);
    return SOCKET_ERROR;
  }
  records[rec].state |= 8;
  //LeaveCriticalSection (&records_cs);
  memcpy (buf, &header, sizeof (header));
  to_receive = header.size - sizeof (header);
  rc = 0;
  while (to_receive > 0)
  {
    t = recv ((SOCKET) hLookup, &((char *) &((struct GNUNET_MessageHeader *) buf)[1])[rc], to_receive, 0);
    if (t > 0)
    {
      rc += t;
      to_receive -= t;
    }
    else
      break;
  }
  //EnterCriticalSection (&records_cs);
  records[rec].state &= ~8;
  if (rc != header.size - sizeof (header))
  {
    free (buf);
    if (records[rec].state & 2)
    {
      DEBUGLOG ("GNUNET_W32NSP_LookupServiceNext: call cancelled\n");
      SetLastError (WSA_E_CANCELLED);
    }
    else
    {
      DEBUGLOG ("GNUNET_W32NSP_LookupServiceNext: failed to receive enough data\n");
      SetLastError (WSA_E_NO_MORE);
    }
    records[rec].state |= 4;
    //LeaveCriticalSection (&records_cs);
    return SOCKET_ERROR;
  }
  if (*lpdwBufferLength < header.size - sizeof (struct GNUNET_W32RESOLVER_GetMessage))
  {
    DEBUGLOG ("GNUNET_W32NSP_LookupServiceNext: client buffer is too small\n");
    SetLastError (WSAEFAULT);
    records[rec].buf = buf;
    //LeaveCriticalSection (&records_cs);
    return SOCKET_ERROR;
  }
  //LeaveCriticalSection (&records_cs);
  memcpy (lpqsResults, &((struct GNUNET_W32RESOLVER_GetMessage *)buf)[1], header.size - sizeof (struct GNUNET_W32RESOLVER_GetMessage));
  free (buf);
  DEBUGLOG ("GNUNET_W32NSP_LookupServiceNext: OK\n");
  UnmarshallWSAQUERYSETW ((LPWSAQUERYSETW) lpqsResults);
  DEBUGLOG ("GNUNET_W32NSP_LookupServiceNext: returning (%lu)\n", GetLastError ());
  return NO_ERROR;
}

int WSPAPI
GNUNET_W32NSP_LookupServiceEnd (HANDLE hLookup)
{
  DWORD effective_flags;
  int i;
  struct GNUNET_MessageHeader header = {0, 0};
  int rec = -1;
  int rc;
  char *buf;

  DEBUGLOG ("GNUNET_W32NSP_LookupServiceEnd\n");
  //EnterCriticalSection (&records_cs);
  for (i = 0; i < records_len; i++)
  {
    if (records[i].s == (SOCKET) hLookup)
    {
      rec = i;
      break;
    }
  }
  if (rec == -1)
  {
    SetLastError (WSA_INVALID_HANDLE);
    //LeaveCriticalSection (&records_cs);
    DEBUGLOG ("GNUNET_W32NSP_LookupServiceEnd: invalid handle\n");
    return SOCKET_ERROR;
  }
  records[rec].state |= 2;
  closesocket (records[rec].s);
  while (records[rec].state & 8)
  {
    //LeaveCriticalSection (&records_cs);
    Sleep (10);
    //EnterCriticalSection (&records_cs);
  }
  if (records[rec].buf)
    free (records[rec].buf);
  records[rec].buf = NULL;
  records[rec].state = 0;
  if (records[rec].name)
    free (records[rec].name);
  //LeaveCriticalSection (&records_cs);
  DEBUGLOG ("GNUNET_W32NSP_LookupServiceEnd: OK\n");
  return NO_ERROR;
}

int WSAAPI
GNUNET_W32NSP_SetService (LPGUID lpProviderId,
    LPWSASERVICECLASSINFOW lpServiceClassInfo, LPWSAQUERYSETW lpqsRegInfo,
    WSAESETSERVICEOP essOperation, DWORD dwControlFlags)
{
  DEBUGLOG ("GNUNET_W32NSP_SetService\n");
  SetLastError (WSAEOPNOTSUPP);
  return SOCKET_ERROR;
}

int WSAAPI
GNUNET_W32NSP_InstallServiceClass (LPGUID lpProviderId,
    LPWSASERVICECLASSINFOW lpServiceClassInfo)
{
  DEBUGLOG ("GNUNET_W32NSP_InstallServiceClass\n");
  SetLastError (WSAEOPNOTSUPP);
  return SOCKET_ERROR;
}


int WSAAPI
GNUNET_W32NSP_RemoveServiceClass (LPGUID lpProviderId, LPGUID lpServiceClassId)
{
  DEBUGLOG ("GNUNET_W32NSP_RemoveServiceClass\n");
  SetLastError (WSAEOPNOTSUPP);
  return SOCKET_ERROR;
}

int WSAAPI
GNUNET_W32NSP_GetServiceClassInfo (LPGUID lpProviderId, LPDWORD lpdwBufSize,
  LPWSASERVICECLASSINFOW lpServiceClassInfo)
{
  DEBUGLOG ("GNUNET_W32NSP_GetServiceClassInfo\n");
  SetLastError (WSAEOPNOTSUPP);
  return SOCKET_ERROR;
}

int WSAAPI
GNUNET_W32NSP_Ioctl (HANDLE hLookup, DWORD dwControlCode, LPVOID lpvInBuffer,
    DWORD cbInBuffer, LPVOID lpvOutBuffer, DWORD cbOutBuffer,
    LPDWORD lpcbBytesReturned, LPWSACOMPLETION lpCompletion,
    LPWSATHREADID lpThreadId)
{
  DEBUGLOG ("GNUNET_W32NSP_Ioctl\n");
  SetLastError (WSAEOPNOTSUPP);
  return SOCKET_ERROR;
}

/**
 * This function is called by Winsock to hook up our provider.
 * It is the only function that [should be/is] exported by the
 * provider. All other routines are passed as pointers in lpnspRoutines.
 */
int WSPAPI
NSPStartup (LPGUID lpProviderId, LPNSP_ROUTINE lpnspRoutines)
{
  if (IsEqualGUID (lpProviderId, &GNUNET_NAMESPACE_PROVIDER_DNS))
  {
    if (!connect_to_dns_resolver ())
    {
      return SOCKET_ERROR;
    }
    /* This assumes that NSP_ROUTINE struct doesn't have a NSPIoctl member.
     * If it does, you need to use FIELD_OFFSET() macro to get offset of NSPIoctl
     * and use that offset as cbSize.
     */
    lpnspRoutines->cbSize = sizeof(NSP_ROUTINE_XP);

    lpnspRoutines->dwMajorVersion = NSPAPI_VERSION_MAJOR;
    lpnspRoutines->dwMinorVersion = NSPAPI_VERSION_MINOR;
    lpnspRoutines->NSPCleanup = NSPCleanup;
    lpnspRoutines->NSPLookupServiceBegin = GNUNET_W32NSP_LookupServiceBegin;
    lpnspRoutines->NSPLookupServiceNext = GNUNET_W32NSP_LookupServiceNext;
    lpnspRoutines->NSPLookupServiceEnd = GNUNET_W32NSP_LookupServiceEnd;
    lpnspRoutines->NSPSetService = GNUNET_W32NSP_SetService;
    lpnspRoutines->NSPInstallServiceClass = GNUNET_W32NSP_InstallServiceClass;
    lpnspRoutines->NSPRemoveServiceClass = GNUNET_W32NSP_RemoveServiceClass;
    lpnspRoutines->NSPGetServiceClassInfo = GNUNET_W32NSP_GetServiceClassInfo;
    ((NSP_ROUTINE_XP *) lpnspRoutines)->NSPIoctl = GNUNET_W32NSP_Ioctl;
    return NO_ERROR;
  }
  SetLastError (WSAEINVALIDPROVIDER);
  return SOCKET_ERROR;
}


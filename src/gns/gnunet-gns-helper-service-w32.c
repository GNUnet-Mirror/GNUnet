/*
     This file is part of GNUnet.
     Copyright (C) 2012, 2017 GNUnet e.V.

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
     Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
     Boston, MA 02110-1301, USA.
*/
/**
 * @file gnunet-gns-helper-service-w32.c
 * @brief an intermediary service to access distributed GNS
 * @author Christian Grothoff
 * @author LRN
 */
#include "platform.h"
#include <gnunet_util_lib.h>
#include <gnunet_identity_service.h>
#include <gnunet_dnsparser_lib.h>
#include <gnunet_namestore_service.h>
#include <gnunet_gns_service.h>
#include <initguid.h>
#include "gnunet_w32nsp_lib.h"
#include "w32resolver.h"
#include <nspapi.h>
#include <unistr.h>

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


struct request
{
  /**
   * We keep these in a doubly-linked list (for cleanup).
   */
  struct request *next;

  /**
   * We keep these in a doubly-linked list (for cleanup).
   */
  struct request *prev;

  /**
   * Client that issued the request
   */
  struct GNUNET_SERVICE_Client *client;

  GUID sc;

  int af;

  wchar_t *name;

  char *u8name;

  struct GNUNET_GNS_LookupRequest *lookup_request;
};


/**
 * Head of the doubly-linked list (for cleanup).
 */
static struct request *rq_head;

/**
 * Tail of the doubly-linked list (for cleanup).
 */
static struct request *rq_tail;

/**
 * Handle to GNS service.
 */
static struct GNUNET_GNS_Handle *gns;

/**
 * Active operation on identity service.
 */
static struct GNUNET_IDENTITY_Operation *id_op;

/**
 * Handle for identity service.
 */
static struct GNUNET_IDENTITY_Handle *identity;

/**
 * Public key of the gns-master ego
 */
static struct GNUNET_CRYPTO_EcdsaPublicKey gns_master_pubkey;

/**
 * Set to 1 once egos are obtained.
 */
static int got_egos;


/**
 * Task run on shutdown.  Cleans up everything.
 *
 * @param cls unused
 */
static void
do_shutdown (void *cls)
{
  struct request *rq;

  if (NULL != id_op)
  {
    GNUNET_IDENTITY_cancel (id_op);
    id_op = NULL;
  }
  if (NULL != identity)
  {
    GNUNET_IDENTITY_disconnect (identity);
    identity = NULL;
  }
  while (NULL != (rq = rq_head))
  {
    if (NULL != rq->lookup_request)
      GNUNET_GNS_lookup_cancel (rq->lookup_request);
    GNUNET_CONTAINER_DLL_remove (rq_head,
                                 rq_tail,
                                 rq);
    GNUNET_free_non_null (rq->name);
    if (rq->u8name)
      free (rq->u8name);
    GNUNET_free (rq);
  }
  if (NULL != gns)
  {
    GNUNET_GNS_disconnect (gns);
    gns = NULL;
  }
}


#define MarshallPtr(ptr, base, type) \
  if (ptr) \
    ptr = (type *) ((char *) ptr - (char *) base)


void
MarshallWSAQUERYSETW (WSAQUERYSETW *qs, GUID *sc)
{
  MarshallPtr (qs->lpszServiceInstanceName, qs, wchar_t);
  MarshallPtr (qs->lpServiceClassId, qs, GUID);
  MarshallPtr (qs->lpVersion, qs, WSAVERSION);
  MarshallPtr (qs->lpNSProviderId, qs, GUID);
  MarshallPtr (qs->lpszContext, qs, wchar_t);
  MarshallPtr (qs->lpafpProtocols, qs, AFPROTOCOLS);
  MarshallPtr (qs->lpszQueryString, qs, wchar_t);
  for (int i = 0; i < qs->dwNumberOfCsAddrs; i++)
  {
    MarshallPtr (qs->lpcsaBuffer[i].LocalAddr.lpSockaddr, qs, SOCKADDR);
    MarshallPtr (qs->lpcsaBuffer[i].RemoteAddr.lpSockaddr, qs, SOCKADDR);
  }
  MarshallPtr (qs->lpcsaBuffer, qs, CSADDR_INFO);
  if (IsEqualGUID (&SVCID_INET_HOSTADDRBYNAME, sc) && qs->lpBlob != NULL && qs->lpBlob->pBlobData != NULL)
  {
    struct hostent *he;

    he = (struct hostent *) qs->lpBlob->pBlobData;
    for (int i = 0; he->h_aliases[i] != NULL; i++)
      MarshallPtr (he->h_aliases[i], he, char);
    MarshallPtr (he->h_aliases, he, char *);
    MarshallPtr (he->h_name, he, char);
    for (int i = 0; he->h_addr_list[i] != NULL; i++)
      MarshallPtr (he->h_addr_list[i], he, void);
    MarshallPtr (he->h_addr_list, he, char *);
    MarshallPtr (qs->lpBlob->pBlobData, qs, void);
  }
  MarshallPtr (qs->lpBlob, qs, BLOB);
}


static void
process_lookup_result (void *cls,
                       uint32_t rd_count,
                       const struct GNUNET_GNSRECORD_Data *rd)
{
  struct request *rq = cls;
  int i, j, csanum;
  struct GNUNET_W32RESOLVER_GetMessage *msg;
  struct GNUNET_MQ_Envelope *msg_env;
  struct GNUNET_MessageHeader *msgend;
  struct GNUNET_MQ_Envelope *msgend_env;
  WSAQUERYSETW *qs;
  size_t size;
  size_t size_recalc;
  char *ptr;
  size_t blobsize = 0;
  size_t blobaddrcount = 0;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Got lookup result with count %u for rq %p with client %p\n",
              rd_count,
              rq,
              rq->client);
  rq->lookup_request = NULL;

  if (0 == rd_count)
  {
    msgend_env = GNUNET_MQ_msg (msgend, GNUNET_MESSAGE_TYPE_W32RESOLVER_RESPONSE);
    GNUNET_MQ_send (GNUNET_SERVICE_client_get_mq (rq->client),
                    msgend_env);
    GNUNET_CONTAINER_DLL_remove (rq_head,
                                 rq_tail,
                                 rq);
    GNUNET_free_non_null (rq->name);
    if (rq->u8name)
      free (rq->u8name);
    GNUNET_free (rq);
    return;
  }

  size = sizeof (struct GNUNET_W32RESOLVER_GetMessage) + sizeof (WSAQUERYSETW);
  size += (wcslen (rq->name) + 1) * sizeof (wchar_t);
  size += sizeof (GUID);
  /* lpszComment ? a TXT record? */
  size += sizeof (GUID);
  /* lpszContext ? Not sure what it is */
  csanum = 0;
  for (i = 0; i < rd_count; i++)
  {
    switch (rd[i].record_type)
    {
    case GNUNET_DNSPARSER_TYPE_A:
      if (rd[i].data_size != sizeof (struct in_addr))
        continue;
      size += sizeof (CSADDR_INFO) + sizeof (struct sockaddr_in) * 2;
      csanum++;
      break;
    case GNUNET_DNSPARSER_TYPE_AAAA:
      if (rd[i].data_size != sizeof (struct in6_addr))
        continue;
      size += sizeof (CSADDR_INFO) + sizeof (struct sockaddr_in6) * 2;
      csanum++;
      break;
    }
  }
  if (IsEqualGUID (&SVCID_INET_HOSTADDRBYNAME, &rq->sc))
  {
    size += sizeof (BLOB);
    blobsize += sizeof (struct hostent);
    blobsize += strlen (rq->u8name) + 1;
    blobsize += sizeof (void *); /* For aliases */
    blobsize += sizeof (void *); /* For addresses */
    for (i = 0; i < rd_count; i++)
    {
      if ((rq->af == AF_INET || rq->af == AF_UNSPEC) && rd[i].record_type == GNUNET_DNSPARSER_TYPE_A)
      {
        blobsize += sizeof (void *);
        blobsize += sizeof (struct in_addr);
        blobaddrcount++;
      }
      else if (rq->af == AF_INET6 && rd[i].record_type == GNUNET_DNSPARSER_TYPE_AAAA)
      {
        blobsize += sizeof (void *);
        blobsize += sizeof (struct in6_addr);
        blobaddrcount++;
      }
    }
    size += blobsize;
  }
  size_recalc = sizeof (struct GNUNET_W32RESOLVER_GetMessage) + sizeof (WSAQUERYSETW);
  msg_env = GNUNET_MQ_msg_extra (msg,
                                 size - sizeof (struct GNUNET_MessageHeader),
                                 GNUNET_MESSAGE_TYPE_W32RESOLVER_RESPONSE);
  msg->af = htonl (rq->af);
  msg->sc_data1 = htonl (rq->sc.Data1);
  msg->sc_data2 = htons (rq->sc.Data2);
  msg->sc_data3 = htons (rq->sc.Data3);
  for (i = 0; i < 8; i++)
    msg->sc_data4[i] = rq->sc.Data4[i];
  qs = (WSAQUERYSETW *) &msg[1];
  ptr = (char *) &qs[1];
  GNUNET_break (size_recalc == (size_t) ((char *) ptr - (char *) msg));
  qs->dwSize = sizeof (WSAQUERYSETW);
  qs->lpszServiceInstanceName = (wchar_t *) ptr;
  ptr += (wcslen (rq->name) + 1) * sizeof (wchar_t);
  size_recalc += (wcslen (rq->name) + 1) * sizeof (wchar_t);
  GNUNET_break (size_recalc == (size_t) ((char *) ptr - (char *) msg));
  wcscpy (qs->lpszServiceInstanceName, rq->name);
  qs->lpServiceClassId = (GUID *) ptr;
  ptr += sizeof (GUID);
  size_recalc += sizeof (GUID);
  GNUNET_break (size_recalc == (size_t) ((char *) ptr - (char *) msg));
  GNUNET_memcpy (qs->lpServiceClassId, &rq->sc, sizeof (GUID));
  qs->lpVersion = NULL;
  qs->dwNameSpace = NS_DNS;
  qs->lpNSProviderId = (GUID *) ptr;
  ptr += sizeof (GUID);
  size_recalc += sizeof (GUID);
  GNUNET_break (size_recalc == (size_t) ((char *) ptr - (char *) msg));
  GNUNET_memcpy (qs->lpNSProviderId, &GNUNET_NAMESPACE_PROVIDER_DNS, sizeof (GUID));
  qs->lpszContext = NULL;
  qs->dwNumberOfProtocols = 0;
  qs->lpafpProtocols = NULL;
  /* Don't bother with this... */
  qs->lpszQueryString = NULL;
  qs->dwNumberOfCsAddrs = rd_count;
  qs->lpcsaBuffer = (CSADDR_INFO *) ptr;
  ptr += sizeof (CSADDR_INFO) * csanum;
  j = 0;
  for (i = 0; i < rd_count; i++)
  {
    switch (rd[i].record_type)
    {
    case GNUNET_DNSPARSER_TYPE_A:
      if (rd[i].data_size != sizeof (struct in_addr))
        continue;
      qs->lpcsaBuffer[j].iSocketType = SOCK_STREAM;
      qs->lpcsaBuffer[j].iProtocol = IPPROTO_TCP;

      qs->lpcsaBuffer[j].LocalAddr.iSockaddrLength = sizeof (struct sockaddr_in);
      qs->lpcsaBuffer[j].LocalAddr.lpSockaddr = (SOCKADDR *) ptr;
      ptr += qs->lpcsaBuffer[j].LocalAddr.iSockaddrLength;
      memset (qs->lpcsaBuffer[j].LocalAddr.lpSockaddr, 0, qs->lpcsaBuffer[j].LocalAddr.iSockaddrLength);
      ((struct sockaddr_in *)qs->lpcsaBuffer[j].LocalAddr.lpSockaddr)->sin_family = AF_INET;

      qs->lpcsaBuffer[j].RemoteAddr.iSockaddrLength = sizeof (struct sockaddr_in);
      qs->lpcsaBuffer[j].RemoteAddr.lpSockaddr = (SOCKADDR *) ptr;
      ptr += qs->lpcsaBuffer[j].RemoteAddr.iSockaddrLength;
      memset (qs->lpcsaBuffer[j].RemoteAddr.lpSockaddr, 0, qs->lpcsaBuffer[j].RemoteAddr.iSockaddrLength);
      ((struct sockaddr_in *)qs->lpcsaBuffer[j].RemoteAddr.lpSockaddr)->sin_family = AF_INET;
      ((struct sockaddr_in *)qs->lpcsaBuffer[j].RemoteAddr.lpSockaddr)->sin_port = htonl (53); /* Don't ask why it's 53 */
      ((struct sockaddr_in *)qs->lpcsaBuffer[j].RemoteAddr.lpSockaddr)->sin_addr = *(struct in_addr *) rd[i].data;
      size_recalc += sizeof (CSADDR_INFO) + sizeof (struct sockaddr_in) * 2;
      j++;
      break;
    case GNUNET_DNSPARSER_TYPE_AAAA:
      if (rd[i].data_size != sizeof (struct in6_addr))
        continue;
      qs->lpcsaBuffer[j].iSocketType = SOCK_STREAM;
      qs->lpcsaBuffer[j].iProtocol = IPPROTO_TCP;

      qs->lpcsaBuffer[j].LocalAddr.iSockaddrLength = sizeof (struct sockaddr_in6);
      qs->lpcsaBuffer[j].LocalAddr.lpSockaddr = (SOCKADDR *) ptr;
      ptr += qs->lpcsaBuffer[j].LocalAddr.iSockaddrLength;
      memset (qs->lpcsaBuffer[j].LocalAddr.lpSockaddr, 0, qs->lpcsaBuffer[j].LocalAddr.iSockaddrLength);
      ((struct sockaddr_in6 *)qs->lpcsaBuffer[j].LocalAddr.lpSockaddr)->sin6_family = AF_INET6;

      qs->lpcsaBuffer[j].RemoteAddr.iSockaddrLength = sizeof (struct sockaddr_in6);
      qs->lpcsaBuffer[j].RemoteAddr.lpSockaddr = (SOCKADDR *) ptr;
      ptr += qs->lpcsaBuffer[j].RemoteAddr.iSockaddrLength;
      memset (qs->lpcsaBuffer[j].RemoteAddr.lpSockaddr, 0, qs->lpcsaBuffer[j].RemoteAddr.iSockaddrLength);
      ((struct sockaddr_in6 *)qs->lpcsaBuffer[j].RemoteAddr.lpSockaddr)->sin6_family = AF_INET6;
      ((struct sockaddr_in6 *)qs->lpcsaBuffer[j].RemoteAddr.lpSockaddr)->sin6_port = htonl (53); /* Don't ask why it's 53 */
      ((struct sockaddr_in6 *)qs->lpcsaBuffer[j].RemoteAddr.lpSockaddr)->sin6_addr = *(struct in6_addr *) rd[i].data;
      size_recalc += sizeof (CSADDR_INFO) + sizeof (struct sockaddr_in6) * 2;
      j++;
      break;
    default:
      break;
    }
  }
  GNUNET_break (size_recalc == (size_t) ((char *) ptr - (char *) msg));
  qs->dwOutputFlags = 0;
  if (IsEqualGUID (&SVCID_INET_HOSTADDRBYNAME, &rq->sc))
  {
    struct hostent *he;
    qs->lpBlob = (BLOB *) ptr;
    ptr += sizeof (BLOB);

    size_recalc += sizeof (BLOB);
    GNUNET_break (size_recalc == (size_t) ((char *) ptr - (char *) msg));

    qs->lpBlob->cbSize = blobsize;
    qs->lpBlob->pBlobData = (BYTE *) ptr;
    ptr += sizeof (struct hostent);

    size_recalc += sizeof (struct hostent);
    GNUNET_break (size_recalc == (size_t) ((char *) ptr - (char *) msg));

    he = (struct hostent *) qs->lpBlob->pBlobData;
    he->h_name = (char *) ptr;
    ptr += strlen (rq->u8name) + 1;

    size_recalc += strlen (rq->u8name) + 1;
    GNUNET_break (size_recalc == (size_t) ((char *) ptr - (char *) msg));

    strcpy (he->h_name, rq->u8name);
    he->h_aliases = (char **) ptr;
    ptr += sizeof (void *);

    size_recalc += sizeof (void *); /* For aliases */
    GNUNET_break (size_recalc == (size_t) ((char *) ptr - (char *) msg));

    he->h_aliases[0] = NULL;
    he->h_addrtype = rq->af;
    he->h_length = rq->af == AF_INET || rq->af == AF_UNSPEC ? sizeof (struct in_addr) : sizeof (struct in6_addr);
    he->h_addr_list = (char **) ptr;
    ptr += sizeof (void *) * (blobaddrcount + 1);

    size_recalc += sizeof (void *) * (blobaddrcount + 1); /* For addresses */
    GNUNET_break (size_recalc == (size_t) ((char *) ptr - (char *) msg));

    j = 0;
    for (i = 0; i < rd_count; i++)
    {
      if ((rq->af == AF_INET || rq->af == AF_UNSPEC) &&
          rd[i].record_type == GNUNET_DNSPARSER_TYPE_A)
      {
        he->h_addr_list[j] = (char *) ptr;
        ptr += sizeof (struct in_addr);

        size_recalc += sizeof (struct in_addr);
        GNUNET_break (size_recalc == (size_t) ((char *) ptr - (char *) msg));

        GNUNET_memcpy (he->h_addr_list[j], rd[i].data, sizeof (struct in_addr));
        j++;
      }
      else if (rq->af == AF_INET6 && rd[i].record_type == GNUNET_DNSPARSER_TYPE_AAAA)
      {
        he->h_addr_list[j] = (char *) ptr;
        ptr += sizeof (struct in6_addr);

        size_recalc += sizeof (struct in6_addr);
        GNUNET_break (size_recalc == (size_t) ((char *) ptr - (char *) msg));

        GNUNET_memcpy (he->h_addr_list[j], rd[i].data, sizeof (struct in6_addr));
        j++;
      }
    }
    he->h_addr_list[j] = NULL;
  }
  msgend_env = GNUNET_MQ_msg (msgend, GNUNET_MESSAGE_TYPE_W32RESOLVER_RESPONSE);

  if ((char *) ptr - (char *) msg != size || size_recalc != size || size_recalc != ((char *) ptr - (char *) msg))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Error in WSAQUERYSETW size calc: expected %u, got %lu (recalc %u)\n",
                size,
                (unsigned long) ((char *) ptr - (char *) msg),
                size_recalc);
  }
  MarshallWSAQUERYSETW (qs, &rq->sc);
  GNUNET_MQ_send (GNUNET_SERVICE_client_get_mq (rq->client),
                  msg_env);
  GNUNET_MQ_send (GNUNET_SERVICE_client_get_mq (rq->client),
                  msgend_env);
  GNUNET_CONTAINER_DLL_remove (rq_head,
                               rq_tail,
                               rq);
  GNUNET_free_non_null (rq->name);
  if (rq->u8name)
    free (rq->u8name);
  GNUNET_free (rq);
}


static void
get_ip_from_hostname (struct GNUNET_SERVICE_Client *client,
                      const wchar_t *name,
                      int af,
                      GUID sc)
{
  struct request *rq;
  char *hostname;
  size_t strl;
  size_t namelen;
  uint32_t rtype;

  if (IsEqualGUID (&SVCID_DNS_TYPE_A, &sc))
    rtype = GNUNET_DNSPARSER_TYPE_A;
  else if (IsEqualGUID (&SVCID_DNS_TYPE_NS, &sc))
    rtype = GNUNET_DNSPARSER_TYPE_NS;
  else if (IsEqualGUID (&SVCID_DNS_TYPE_CNAME, &sc))
    rtype = GNUNET_DNSPARSER_TYPE_CNAME;
  else if (IsEqualGUID (&SVCID_DNS_TYPE_SOA, &sc))
    rtype = GNUNET_DNSPARSER_TYPE_SOA;
  else if (IsEqualGUID (&SVCID_DNS_TYPE_PTR, &sc))
    rtype = GNUNET_DNSPARSER_TYPE_PTR;
  else if (IsEqualGUID (&SVCID_DNS_TYPE_MX, &sc))
    rtype = GNUNET_DNSPARSER_TYPE_MX;
  else if (IsEqualGUID (&SVCID_DNS_TYPE_TEXT, &sc))
    rtype = GNUNET_DNSPARSER_TYPE_TXT;
  else if (IsEqualGUID (&SVCID_DNS_TYPE_AAAA, &sc))
    rtype = GNUNET_DNSPARSER_TYPE_AAAA;
  else if (IsEqualGUID (&SVCID_DNS_TYPE_SRV, &sc))
    rtype = GNUNET_DNSPARSER_TYPE_SRV;
  else if (IsEqualGUID (&SVCID_INET_HOSTADDRBYNAME, &sc))
    rtype = GNUNET_DNSPARSER_TYPE_A;
  else
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Unknown GUID: %08lX-%04X-%04X-%02X-%02X-%02X-%02X-%02X-%02X-%02X-%02X\n",
                sc.Data1,
                sc.Data2,
                sc.Data3,
                sc.Data4[0],
                sc.Data4[1],
                sc.Data4[2],
                sc.Data4[3],
                sc.Data4[4],
                sc.Data4[5],
                sc.Data4[6],
                sc.Data4[7]);
    GNUNET_SERVICE_client_drop (client);
    return;
  }

  if (name)
    namelen = wcslen (name);
  else
    namelen = 0;
  if (namelen > 0)
    hostname = (char *) u16_to_u8 (name, namelen + 1, NULL, &strl);
  else
    hostname = NULL;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "W32 DNS resolver asked to look up %s for `%s'.\n",
              af == AF_INET ? "IPv4" : af == AF_INET6 ? "IPv6" : "anything",
              hostname);

  rq = GNUNET_new (struct request);
  rq->sc = sc;
  rq->client = client;
  rq->af = af;
  if (rq->af != AF_INET && rq->af != AF_INET6)
    rq->af = AF_INET;
  if (namelen)
  {
    rq->name = GNUNET_malloc ((namelen + 1) * sizeof (wchar_t));
    GNUNET_memcpy (rq->name,
                   name,
                   (namelen + 1) * sizeof (wchar_t));
    rq->u8name = hostname;
  }

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Launching a lookup for client %p with rq %p\n",
              client,
              rq);
  rq->lookup_request = GNUNET_GNS_lookup (gns,
                                          hostname,
                                          &gns_master_pubkey,
                                          rtype,
                                          GNUNET_NO /* Use DHT */,
                                          &process_lookup_result,
                                          rq);
  if (NULL != rq->lookup_request)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Lookup launched, waiting for a reply\n");
    GNUNET_SERVICE_client_continue (client);
    GNUNET_CONTAINER_DLL_insert (rq_head,
                                 rq_tail,
                                 rq);
  }
  else
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Lookup was not launched, disconnecting the client\n");
    GNUNET_free_non_null (rq->name);
    if (rq->u8name)
      free (rq->u8name);
    GNUNET_free (rq);
    GNUNET_SERVICE_client_drop (client);
  }
}


/**
 * Check GET-message.
 *
 * @param cls identification of the client
 * @param msg the actual message
 * @return #GNUNET_OK if @a msg is well-formed
 */
static int
check_get (void *cls,
            const struct GNUNET_W32RESOLVER_GetMessage *msg)
{
  uint16_t size;
  const wchar_t *hostname;

  if (! got_egos)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _("Not ready to process requests, lacking ego data\n"));
    return GNUNET_SYSERR;
  }
  size = ntohs (msg->header.size) - sizeof (struct GNUNET_W32RESOLVER_GetMessage);
  hostname = (const wchar_t *) &msg[1];
  if (hostname[size / 2 - 1] != L'\0')
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * Handle GET-message.
 *
 * @param cls identification of the client
 * @param msg the actual message
 */
static void
handle_get (void *cls,
            const struct GNUNET_W32RESOLVER_GetMessage *msg)
{
  struct GNUNET_SERVICE_Client *client = cls;
  GUID sc;
  uint16_t size;
  const wchar_t *hostname;
  int af;

  size = ntohs (msg->header.size) - sizeof (struct GNUNET_W32RESOLVER_GetMessage);
  af = ntohl (msg->af);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Got NBO GUID: %08X-%04X-%04X-%02X-%02X-%02X-%02X-%02X-%02X-%02X-%02X\n",
              msg->sc_data1,
              msg->sc_data2,
              msg->sc_data3,
              msg->sc_data4[0],
              msg->sc_data4[1],
              msg->sc_data4[2],
              msg->sc_data4[3],
              msg->sc_data4[4],
              msg->sc_data4[5],
              msg->sc_data4[6],
              msg->sc_data4[7]);
  sc.Data1 = ntohl (msg->sc_data1);
  sc.Data2 = ntohs (msg->sc_data2);
  sc.Data3 = ntohs (msg->sc_data3);
  for (int i = 0; i < 8; i++)
    sc.Data4[i] = msg->sc_data4[i];
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Got GUID: %08lX-%04X-%04X-%02X-%02X-%02X-%02X-%02X-%02X-%02X-%02X\n",
              sc.Data1,
              sc.Data2,
              sc.Data3,
              sc.Data4[0],
              sc.Data4[1],
              sc.Data4[2],
              sc.Data4[3],
              sc.Data4[4],
              sc.Data4[5],
              sc.Data4[6],
              sc.Data4[7]);
  hostname = (const wchar_t *) &msg[1];
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Name of %u bytes (last word is 0x%0X): %*S\n",
              size,
              hostname[size / 2 - 2],
              size / 2,
              hostname);
  get_ip_from_hostname (client,
                        hostname,
                        af,
                        sc);
}


/**
 * Method called to with the ego we are to use for the lookup,
 * when the ego is the one for the default master zone.
 *
 * @param cls closure (NULL, unused)
 * @param ego ego handle, NULL if not found
 * @param ctx context for application to store data for this ego
 *                 (during the lifetime of this process, initially NULL)
 * @param name name assigned by the user for this ego,
 *                   NULL if the user just deleted the ego and it
 *                   must thus no longer be used
 */
static void
identity_master_cb (void *cls,
                    struct GNUNET_IDENTITY_Ego *ego,
                    void **ctx,
                    const char *name)
{
  id_op = NULL;
  if (NULL == ego)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _("Ego for `gns-master' not found, cannot perform lookup.  Did you run gnunet-gns-import.sh?\n"));
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  GNUNET_IDENTITY_ego_get_public_key (ego,
                                      &gns_master_pubkey);
  got_egos = 1;
}


/**
 * Start up gns-helper-w32 service.
 *
 * @param cls closure
 * @param cfg configuration to use
 * @param service the initialized service
 */
static void
run (void *cls,
     const struct GNUNET_CONFIGURATION_Handle *cfg,
     struct GNUNET_SERVICE_Handle *service)
{
  gns = GNUNET_GNS_connect (cfg);
  if (NULL == gns)
  {
    fprintf (stderr,
             _("Failed to connect to GNS\n"));
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  GNUNET_SCHEDULER_add_shutdown (&do_shutdown,
				 NULL);
  identity = GNUNET_IDENTITY_connect (cfg,
                                      NULL,
                                      NULL);
  if (NULL == identity)
  {
    fprintf (stderr,
             _("Failed to connect to identity service\n"));
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  id_op = GNUNET_IDENTITY_get (identity,
                               "gns-master",
                               &identity_master_cb,
                               NULL);
  GNUNET_assert (NULL != id_op);
}


/**
 * Handle client connecting to the service.
 *
 * @param cls NULL
 * @param client the new client
 * @param mq the message queue of @a client
 * @return @a client
 */
static void *
client_connect_cb (void *cls,
                   struct GNUNET_SERVICE_Client *client,
                   struct GNUNET_MQ_Handle *mq)
{
  return client;
}


/**
 * Callback called when a client disconnected from the service
 *
 * @param cls closure for the service
 * @param c the client that disconnected
 * @param internal_cls should be equal to @a c
 */
static void
client_disconnect_cb (void *cls,
                      struct GNUNET_SERVICE_Client *client,
                      void *internal_cls)
{
  GNUNET_assert (internal_cls == client);
}


/**
 * Define "main" method using service macro.
 */
GNUNET_SERVICE_MAIN
("gns-helper-service-w32",
 GNUNET_SERVICE_OPTION_NONE,
 &run,
 &client_connect_cb,
 &client_disconnect_cb,
 NULL,
 GNUNET_MQ_hd_var_size (get,
                        GNUNET_MESSAGE_TYPE_W32RESOLVER_REQUEST,
                        struct GNUNET_W32RESOLVER_GetMessage,
                        NULL),
 GNUNET_MQ_handler_end());


/* end of gnunet-gns-helper-service-w32.c */

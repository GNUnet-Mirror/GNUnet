/* $Id: natpmp.h,v 1.11 2009/02/27 22:38:05 nanard Exp $ */
/* libnatpmp
 * Copyright (c) 2007-2008, Thomas BERNARD <miniupnp@free.fr>
 * http://miniupnp.free.fr/libnatpmp.html
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE. */
#ifndef __NATPMP_H__
#define __NATPMP_H__

/* NAT-PMP Port as defined by the NAT-PMP draft */
#define NATPMP_PORT (5351)

#include <stdint.h>
#include <time.h>
#include <sys/time.h>
#ifdef WIN32
#include <winsock2.h>
#include <stdint.h>
#define in_addr_t uint32_t
#include "declspec.h"
#else
#define LIBSPEC
#include <netinet/in.h>
#include <sys/socket.h>
#endif

typedef struct
{
  int s;                        /* socket */
  struct sockaddr *addr;
  socklen_t addrlen;
  uint8_t gateway[16];       /* default gateway (IPv4 or IPv6) */
  int has_pending_request;
  unsigned char pending_request[12];
  int pending_request_len;
  int try_number;
  struct timeval retry_time;
} natpmp_t;

typedef struct
{
  uint16_t type;                /* NATPMP_RESPTYPE_* */
  uint16_t resultcode;          /* NAT-PMP response code */
  uint32_t epoch;               /* Seconds since start of epoch */
  union
  {
    struct
    {
      int family;
      struct in_addr addr;
      struct in6_addr addr6;
    } publicaddress;
    struct
    {
      uint16_t privateport;
      uint16_t mappedpublicport;
      uint32_t lifetime;
    } newportmapping;
  } pnu;
} natpmpresp_t;

/* possible values for type field of natpmpresp_t */
#define NATPMP_RESPTYPE_PUBLICADDRESS (0)
#define NATPMP_RESPTYPE_UDPPORTMAPPING (1)
#define NATPMP_RESPTYPE_TCPPORTMAPPING (2)

/* Values to pass to sendnewportmappingrequest() */
#define NATPMP_PROTOCOL_UDP (1)
#define NATPMP_PROTOCOL_TCP (2)

/* return values */
/* NATPMP_ERR_INVALIDARGS : invalid arguments passed to the function */
#define NATPMP_ERR_INVALIDARGS (-1)
/* NATPMP_ERR_SOCKETERROR : socket() failed. check errno for details */
#define NATPMP_ERR_SOCKETERROR (-2)
/* NATPMP_ERR_CANNOTGETGATEWAY : can't get default gateway IP */
#define NATPMP_ERR_CANNOTGETGATEWAY (-3)
/* NATPMP_ERR_CLOSEERR : close() failed. check errno for details */
#define NATPMP_ERR_CLOSEERR (-4)
/* NATPMP_ERR_RECVFROM : recvfrom() failed. check errno for details */
#define NATPMP_ERR_RECVFROM (-5)
/* NATPMP_ERR_NOPENDINGREQ : readnatpmpresponseorretry() called while
 * no NAT-PMP request was pending */
#define NATPMP_ERR_NOPENDINGREQ (-6)
/* NATPMP_ERR_NOGATEWAYSUPPORT : the gateway does not support NAT-PMP */
#define NATPMP_ERR_NOGATEWAYSUPPORT (-7)
/* NATPMP_ERR_CONNECTERR : connect() failed. check errno for details */
#define NATPMP_ERR_CONNECTERR (-8)
/* NATPMP_ERR_WRONGPACKETSOURCE : packet not received from the network gateway */
#define NATPMP_ERR_WRONGPACKETSOURCE (-9)
/* NATPMP_ERR_SENDERR : send() failed. check errno for details */
#define NATPMP_ERR_SENDERR (-10)
/* NATPMP_ERR_FCNTLERROR : fcntl() failed. check errno for details */
#define NATPMP_ERR_FCNTLERROR (-11)
/* NATPMP_ERR_GETTIMEOFDAYERR : gettimeofday() failed. check errno for details */
#define NATPMP_ERR_GETTIMEOFDAYERR (-12)
/* NATPMP_ERR_BINDERROR : bind() failed. check errno for details */
#define NATPMP_ERR_BINDERROR (-13)
/* NATPMP_ERR_ADDRERROR : gateway does not use the same inet protocol as the passed address */
#define NATPMP_ERR_ADDRERROR (-14)

/* */
#define NATPMP_ERR_UNSUPPORTEDVERSION (-15)
#define NATPMP_ERR_UNSUPPORTEDOPCODE (-16)

/* Errors from the server : */
#define NATPMP_ERR_UNDEFINEDERROR (-49)
#define NATPMP_ERR_NOTAUTHORIZED (-51)
#define NATPMP_ERR_NETWORKFAILURE (-52)
#define NATPMP_ERR_OUTOFRESOURCES (-53)

/* NATPMP_TRYAGAIN : no data available for the moment. try again later */
#define NATPMP_TRYAGAIN (-100)

/* initnatpmp()
 * initialize a natpmp_t object
 * Return values :
 * 0 = OK
 * NATPMP_ERR_INVALIDARGS
 * NATPMP_ERR_SOCKETERROR
 * NATPMP_ERR_FCNTLERROR
 * NATPMP_ERR_CANNOTGETGATEWAY
 * NATPMP_ERR_CONNECTERR */
LIBSPEC int initnatpmp (natpmp_t * p);

/* closenatpmp()
 * close resources associated with a natpmp_t object
 * Return values :
 * 0 = OK
 * NATPMP_ERR_INVALIDARGS
 * NATPMP_ERR_CLOSEERR */
LIBSPEC int closenatpmp (natpmp_t * p);

/* sendpublicaddressrequest()
 * send a public address NAT-PMP request to the network gateway
 * Return values :
 * 2 = OK (size of the request)
 * NATPMP_ERR_INVALIDARGS
 * NATPMP_ERR_SENDERR */
LIBSPEC int sendpublicaddressrequest (natpmp_t * p);

/* sendnewportmappingrequest()
 * send a new port mapping NAT-PMP request to the network gateway
 * Arguments :
 * protocol is either NATPMP_PROTOCOL_TCP or NATPMP_PROTOCOL_UDP,
 * lifetime is in seconds.
 * To remove a port mapping, set lifetime to zero.
 * To remove all port mappings to the host, set lifetime and both ports
 * to zero.
 * Return values :
 * 12 = OK (size of the request)
 * NATPMP_ERR_INVALIDARGS
 * NATPMP_ERR_SENDERR */
LIBSPEC int sendnewportmappingrequest (natpmp_t * p, int protocol,
                                       uint16_t privateport,
                                       uint16_t publicport,
                                       uint32_t lifetime);

/* getnatpmprequesttimeout()
 * fills the timeval structure with the timeout duration of the
 * currently pending NAT-PMP request.
 * Return values :
 * 0 = OK
 * NATPMP_ERR_INVALIDARGS
 * NATPMP_ERR_GETTIMEOFDAYERR
 * NATPMP_ERR_NOPENDINGREQ */
LIBSPEC int getnatpmprequesttimeout (natpmp_t * p, struct timeval *timeout);

/* readnatpmpresponseorretry()
 * fills the natpmpresp_t structure if possible
 * Return values :
 * 0 = OK
 * NATPMP_TRYAGAIN
 * NATPMP_ERR_INVALIDARGS
 * NATPMP_ERR_NOPENDINGREQ
 * NATPMP_ERR_NOGATEWAYSUPPORT
 * NATPMP_ERR_RECVFROM
 * NATPMP_ERR_WRONGPACKETSOURCE
 * NATPMP_ERR_UNSUPPORTEDVERSION
 * NATPMP_ERR_UNSUPPORTEDOPCODE
 * NATPMP_ERR_NOTAUTHORIZED
 * NATPMP_ERR_NETWORKFAILURE
 * NATPMP_ERR_OUTOFRESOURCES
 * NATPMP_ERR_UNSUPPORTEDOPCODE
 * NATPMP_ERR_UNDEFINEDERROR */
LIBSPEC int readnatpmpresponseorretry (natpmp_t * p, natpmpresp_t * response);

#ifdef ENABLE_STRNATPMPERR
LIBSPEC const char *strnatpmperr (int t);
#endif

#endif

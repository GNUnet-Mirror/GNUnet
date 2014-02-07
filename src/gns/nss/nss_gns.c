/***
    This file is part of nss-gns.

    Parts taken from: nss.c in nss-mdns

    nss-mdns is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published
    by the Free Software Foundation; either version 3 of the License,
    or (at your option) any later version.

    nss-mdns is distributed in the hope that it will be useful, but1
    WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
    General Public License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with nss-mdns; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307
    USA.
***/

#include <gnunet_config.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <assert.h>
#include <netdb.h>
#include <sys/socket.h>
#include <nss.h>
#include <stdio.h>
#include <stdlib.h>

#include "nss_gns_query.h"

#include <arpa/inet.h>

/** macro to align idx to 32bit boundary */
#define ALIGN(idx) do { \
  if (idx % sizeof(void*)) \
    idx += (sizeof(void*) - idx % sizeof(void*)); /* Align on 32 bit boundary */ \
} while(0)


/**
 * function to check if name ends with a specific suffix
 *
 * @param name the name to check
 * @param suffix the suffix to check for
 * @return 1 if true
 */
static int ends_with(const char *name, const char* suffix) {
    size_t ln, ls;
    assert(name);
    assert(suffix);

    if ((ls = strlen(suffix)) > (ln = strlen(name)))
        return 0;

    return strcasecmp(name+ln-ls, suffix) == 0;
}


/**
 * Check if name is inside .gnu or .zkey TLD
 *
 * @param name name to check
 * @return 1 if true
 */
static int verify_name_allowed (const char *name) {
  return ends_with(name, ".gnu") || ends_with(name, ".zkey");
}

/**
 * The gethostbyname hook executed by nsswitch
 *
 * @param name the name to resolve
 * @param af the address family to resolve
 * @param result the result hostent
 * @param buffer the result buffer
 * @param buflen length of the buffer
 * @param errnop idk
 * @param h_errnop idk
 * @return a nss_status code
 */
enum nss_status _nss_gns_gethostbyname2_r(
    const char *name,
    int af,
    struct hostent * result,
    char *buffer,
    size_t buflen,
    int *errnop,
    int *h_errnop) {

    struct userdata u;
    enum nss_status status = NSS_STATUS_UNAVAIL;
    int i;
    size_t address_length, l, idx, astart;
    int name_allowed;

    if (af == AF_UNSPEC)
#ifdef NSS_IPV6_ONLY
        af = AF_INET6;
#else
        af = AF_INET;
#endif

#ifdef NSS_IPV4_ONLY
    if (af != AF_INET)
#elif NSS_IPV6_ONLY
    if (af != AF_INET6)
#else
    if (af != AF_INET && af != AF_INET6)
#endif
    {
        *errnop = EINVAL;
        *h_errnop = NO_RECOVERY;

        goto finish;
    }

    address_length = af == AF_INET ? sizeof(ipv4_address_t) : sizeof(ipv6_address_t);
    if (buflen <
        sizeof(char*)+    /* alias names */
        strlen(name)+1)  {   /* official name */

        *errnop = ERANGE;
        *h_errnop = NO_RECOVERY;
        status = NSS_STATUS_TRYAGAIN;

        goto finish;
    }

    u.count = 0;
    u.data_len = 0;

    name_allowed = verify_name_allowed(name);

    if (name_allowed) {

        if (!gns_resolve_name(af, name, &u) == 0)
        {
          status = NSS_STATUS_NOTFOUND;
          goto finish;
        }
    }
    else
    {
      status = NSS_STATUS_UNAVAIL;
      goto finish;
    }

    if (u.count == 0) {
        *errnop = ETIMEDOUT;
        *h_errnop = HOST_NOT_FOUND;
        status = NSS_STATUS_NOTFOUND;
        goto finish;
    }


    /* Alias names */
    *((char**) buffer) = NULL;
    result->h_aliases = (char**) buffer;
    idx = sizeof(char*);

    /* Official name */
    strcpy(buffer+idx, name);
    result->h_name = buffer+idx;
    idx += strlen(name)+1;

    ALIGN(idx);

    result->h_addrtype = af;
    result->h_length = address_length;

    /* Check if there's enough space for the addresses */
    if (buflen < idx+u.data_len+sizeof(char*)*(u.count+1)) {
        *errnop = ERANGE;
        *h_errnop = NO_RECOVERY;
        status = NSS_STATUS_TRYAGAIN;
        goto finish;
    }

    /* Addresses */
    astart = idx;
    l = u.count*address_length;
    memcpy(buffer+astart, &u.data, l);
    /* address_length is a multiple of 32bits, so idx is still aligned
     * correctly */
    idx += l;

    /* Address array address_lenght is always a multiple of 32bits */
    for (i = 0; i < u.count; i++)
        ((char**) (buffer+idx))[i] = buffer+astart+address_length*i;
    ((char**) (buffer+idx))[i] = NULL;
    result->h_addr_list = (char**) (buffer+idx);

    status = NSS_STATUS_SUCCESS;

finish:
    return status;
}

/**
 * The gethostbyname hook executed by nsswitch
 *
 * @param name the name to resolve
 * @param result the result hostent
 * @param buffer the result buffer
 * @param buflen length of the buffer
 * @param errnop idk
 * @param h_errnop idk
 * @return a nss_status code
 */
enum nss_status _nss_gns_gethostbyname_r (
    const char *name,
    struct hostent *result,
    char *buffer,
    size_t buflen,
    int *errnop,
    int *h_errnop) {

    return _nss_gns_gethostbyname2_r(
        name,
        AF_UNSPEC,
        result,
        buffer,
        buflen,
        errnop,
        h_errnop);
}

/**
 * The gethostbyaddr hook executed by nsswitch
 * We can't do this so we always return NSS_STATUS_UNAVAIL
 *
 * @param addr the address to resolve
 * @param len the length of the address
 * @param af the address family of the address
 * @param result the result hostent
 * @param buffer the result buffer
 * @param buflen length of the buffer
 * @param errnop idk
 * @param h_errnop idk
 * @return NSS_STATUS_UNAVAIL
 */
enum nss_status _nss_gns_gethostbyaddr_r(
    const void* addr,
    int len,
    int af,
    struct hostent *result,
    char *buffer,
    size_t buflen,
    int *errnop,
    int *h_errnop) {
  
    struct userdata u;
    enum nss_status status = NSS_STATUS_UNAVAIL;
    int r;
    size_t addr_len, idx, astart;

    *errnop = EINVAL;
    *h_errnop = NO_RECOVERY;

    u.count = 0;
    u.data_len = 0;

    addr_len = af == AF_INET ? sizeof(ipv4_address_t) : sizeof(ipv6_address_t);

    if (len < (int) addr_len ||
#ifdef NSS_IPV4_ONLY
      af != AF_INET
#elif NSS_IPV6_ONLY
      af != AF_INET6
#else
      (af != AF_INET && af != AF_INET6)
#endif
      ) {
      *errnop = EINVAL;
      *h_errnop = NO_RECOVERY;

      goto finish;
    }

    if (buflen < sizeof((char*) addr_len)) {
      *errnop = ERANGE;
      *h_errnop = NO_RECOVERY;
      status = NSS_STATUS_TRYAGAIN;
      goto finish;
    }

#if ! defined(NSS_IPV6_ONLY) && ! defined(NSS_IPV4_ONLY)
    if (af == AF_INET)
#endif
#ifndef NSS_IPV6_ONLY
    r = namecache_resolve_ip4((const ipv4_address_t*) addr, &u);
#endif
#if ! defined(NSS_IPV6_ONLY) && ! defined(NSS_IPV4_ONLY)
    else
#endif
#ifndef NSS_IPV4_ONLY
      r = namecache_resolve_ip6((const ipv6_address_t*) addr, &u);
#endif
    if (0 > r) {
      *errnop = ETIMEDOUT;
      *h_errnop = HOST_NOT_FOUND;
      //NODE we allow to leak this into DNS so no NOTFOUND
      status = NSS_STATUS_UNAVAIL;
      goto finish;
    }

    *((char**) buffer) = NULL;
    result->h_aliases = (char**) buffer;
    idx = sizeof(char*);

    assert(u.count > 0);
    assert(u.data.name[0]);

    if (buflen <
        strlen(u.data.name[0])+1+ /* official names */
        sizeof(char*)+ /* alias names */
        addr_len+  /* address */
        sizeof(void*)*2 + /* address list */
        sizeof(void*)) {  /* padding to get the alignment right */
      *errnop = ERANGE;
      *h_errnop = NO_RECOVERY;
      status = NSS_STATUS_TRYAGAIN;
      goto finish;
    }

    /* Official name */
    strcpy(buffer+idx, u.data.name[0]); 
    result->h_name = buffer+idx;
    idx += strlen(u.data.name[0])+1;
    
    result->h_addrtype = af;
    result->h_length = addr_len;

    /* Address */
    astart = idx;
    memcpy(buffer+astart, addr, addr_len);
    idx += addr_len;

    /* Address array, idx might not be at pointer alignment anymore, so we need
     * to ensure it is*/
    ALIGN(idx);

    ((char**) (buffer+idx))[0] = buffer+astart;
    ((char**) (buffer+idx))[1] = NULL;
    result->h_addr_list = (char**) (buffer+idx);

    status = NSS_STATUS_SUCCESS;
finish:
    return status;
}


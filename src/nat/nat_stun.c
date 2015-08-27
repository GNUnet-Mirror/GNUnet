/*
     This file is part of GNUnet.
     Copyright (C) 2009, 2015 Christian Grothoff (and other contributing authors)

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
 * 
 * This code provides some support for doing STUN transactions.
 * We send simplest possible packet ia REQUEST with BIND to a STUN server.
 *
 * All STUN packets start with a simple header made of a type,
 * length (excluding the header) and a 16-byte random transaction id.
 * Following the header we may have zero or more attributes, each
 * structured as a type, length and a value (whose format depends
 * on the type, but often contains addresses).
 * Of course all fields are in network format.
 * 
 * This code was based on ministun.c.
 *
 *
 * @file nat/nat_stun.c
 * @brief Functions for STUN functionality
 * @author Bruno Souza Cabral
 */

#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_resolver_service.h"
#include "gnunet_nat_lib.h"


#include "nat_stun.h"

#define LOG(kind,...) GNUNET_log_from (kind, "stun", __VA_ARGS__)

#define TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 15)


/**
 * Handle to a request given to the resolver.  Can be used to cancel
 * the request prior to the timeout or successful execution.  Also
 * used to track our internal state for the request.
 */
struct GNUNET_NAT_STUN_Handle {

    /**
    * Handle to a pending DNS lookup request.
    */
    struct GNUNET_RESOLVER_RequestHandle *dns_active;


    /**
    * Handle to the listen socket
    */
    struct GNUNET_NETWORK_Handle * sock;

    /**
    * Stun server address
    */
    char *stun_server ;

    /**
    * STUN port
    */
    int stun_port;

    /**
     * Function to call when a error occours
    */
    GNUNET_NAT_stun_RequestCallback cb;

    /**
     * Closure for @e cb.
     */
    void *cb_cls;

    /**
     * Do we got a DNS resolution successfully ?
     */
    int dns_success;


};



/* here we store credentials extracted from a message */
struct StunState {
    uint16_t attr;
};


/**
 * Convert a message to a StunClass
 *
 * @param msg the received message
 * @return the converted StunClass
 */
static int
decode_class(int msg)
{
    /* Sorry for the magic, but this maps the class according to rfc5245 */
    return ((msg & 0x0010) >> 4) | ((msg & 0x0100) >> 7);
}

/**
 * Convert a message to a StunMethod
 *
 * @param msg the received message
 * @return the converted StunMethod
 */
static int
decode_method(int msg)
{
    return (msg & 0x000f) | ((msg & 0x00e0) >> 1) | ((msg & 0x3e00) >> 2);
}

/**
 * Encode a class and method to a compatible STUN format
 *
 * @param msg_class class to be converted
 * @param method method to be converted
 * @return message in a STUN compatible format
 */
static int
encode_message(StunClasses msg_class, StunMethods method)
{
    return ((msg_class & 1) << 4) | ((msg_class & 2) << 7) |
           (method & 0x000f) | ((method & 0x0070) << 1) | ((method & 0x0f800) << 2);
}

/**
 * Print a class and method from a STUN message
 *
 * @param msg
 * @return string with the message class and method
 */
static const char *
stun_msg2str(int msg)
{

    const struct { enum StunClasses value; const char *name; } classes[] = {
            { STUN_REQUEST, "Request" },
            { STUN_INDICATION, "Indication" },
            { STUN_RESPONSE, "Response" },
            { STUN_ERROR_RESPONSE, "Error Response" },
            { 0, NULL }
    };

    const struct { enum StunMethods value; const char *name; } methods[] = {
            { STUN_BINDING, "Binding" },
            { 0, NULL }
    };

    static char result[32];
    const char *msg_class = NULL;
    const char *method = NULL;
    int i;
    int value;

    value = decode_class(msg);
    for (i = 0; classes[i].name; i++) {
        msg_class = classes[i].name;
        if (classes[i].value == value)
            break;
    }
    value = decode_method(msg);
    for (i = 0; methods[i].name; i++) {
        method = methods[i].name;
        if (methods[i].value == value)
            break;
    }
    GNUNET_snprintf(result, sizeof(result), "%s %s",
             method ? : "Unknown Method",
             msg_class ? : "Unknown Class Message");
    return result;
}

/**
 * Print attribute name
 *
 * @param msg with a attribute type
 * @return string with the attribute name
 */
static const char *
stun_attr2str(int msg)
{
    const struct { enum StunAttributes value; const char *name; } attrs[] = {
            { STUN_MAPPED_ADDRESS, "Mapped Address" },
            { STUN_RESPONSE_ADDRESS, "Response Address" },
            { STUN_CHANGE_ADDRESS, "Change Address" },
            { STUN_SOURCE_ADDRESS, "Source Address" },
            { STUN_CHANGED_ADDRESS, "Changed Address" },
            { STUN_USERNAME, "Username" },
            { STUN_PASSWORD, "Password" },
            { STUN_MESSAGE_INTEGRITY, "Message Integrity" },
            { STUN_ERROR_CODE, "Error Code" },
            { STUN_UNKNOWN_ATTRIBUTES, "Unknown Attributes" },
            { STUN_REFLECTED_FROM, "Reflected From" },
            { STUN_REALM, "Realm" },
            { STUN_NONCE, "Nonce" },
            { STUN_XOR_MAPPED_ADDRESS, "XOR Mapped Address" },
            { STUN_MS_VERSION, "MS Version" },
            { STUN_MS_XOR_MAPPED_ADDRESS, "MS XOR Mapped Address" },
            { STUN_SOFTWARE, "Software" },
            { STUN_ALTERNATE_SERVER, "Alternate Server" },
            { STUN_FINGERPRINT, "Fingerprint" },
            { 0, NULL }
    };
    int i;

    for (i = 0; attrs[i].name; i++) {
        if (attrs[i].value == msg)
            return attrs[i].name;
    }
    return "Unknown Attribute";
}


/**
 * Fill the stun_header with a random request_id
 *
 * @param state, STUN attribute type
 * @param attr , the actual attribute
 *
 * @param req, stun header to be filled
 */
static int
stun_process_attr(struct StunState *state, struct stun_attr *attr)
{
    LOG (GNUNET_ERROR_TYPE_INFO,
         "Found STUN Attribute %s (%04x), length %d\n",
         stun_attr2str(ntohs(attr->attr)), ntohs(attr->attr), ntohs(attr->len));

    switch (ntohs(attr->attr)) {
        case STUN_MAPPED_ADDRESS:
        case STUN_XOR_MAPPED_ADDRESS:
        case STUN_MS_XOR_MAPPED_ADDRESS:
            break;
        default:
            LOG (GNUNET_ERROR_TYPE_INFO,
                 "Ignoring STUN Attribute %s (%04x), length %d\n",
                 stun_attr2str(ntohs(attr->attr)), ntohs(attr->attr), ntohs(attr->len));

    }
    return 0;
}



/**
 * Fill the stun_header with a random request_id
 *
 * @param req, stun header to be filled
 */
static void
generate_request_id(struct stun_header *req)
{
    unsigned int x;
    req->magic = htonl(STUN_MAGIC_COOKIE);
    for (x = 0; x < 3; x++)
        req->id.id[x] = GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_NONCE,
                                                  UINT32_MAX);
}


/**
 * Extract the STUN_MAPPED_ADDRESS from the stun response.
 * This is used as a callback for stun_handle_response
 * when called from stun_request.
 *
 * @param st, pointer where we will set the type
 * @param attr , received stun attribute
 * @param arg , pointer to a sockaddr_in where we will set the reported IP and port
 * @param magic , Magic cookie
 *
 * @return 0 on success, other value otherwise
 */
static int
stun_get_mapped(struct StunState *st, struct stun_attr *attr,struct sockaddr_in *arg, unsigned int magic)
{
    struct stun_addr *returned_addr = (struct stun_addr *)(attr + 1);
    struct sockaddr_in *sa = (struct sockaddr_in *)arg;
    unsigned short type = ntohs(attr->attr);

    switch (type) {
        case STUN_MAPPED_ADDRESS:
            if (st->attr == STUN_XOR_MAPPED_ADDRESS ||
                st->attr == STUN_MS_XOR_MAPPED_ADDRESS)
                return 1;
            magic = 0;
            break;
        case STUN_MS_XOR_MAPPED_ADDRESS:
            if (st->attr == STUN_XOR_MAPPED_ADDRESS)
                return 1;
            break;
        case STUN_XOR_MAPPED_ADDRESS:
            break;
        default:
            return 1;
    }
    if (ntohs(attr->len) < 8 && returned_addr->family != 1) {
        return 1;
    }

    st->attr = type;

    sa->sin_family = AF_INET;
    sa->sin_port = returned_addr->port ^ htons(ntohl(magic) >> 16);
    sa->sin_addr.s_addr = returned_addr->addr ^ magic;
    return 0;
}


/**
 * Handle an incoming STUN message, Do some basic sanity checks on packet size and content,
 * try to extract a bit of information, and possibly reply.
 * At the moment this only processes BIND requests, and returns
 * the externally visible address of the request.
 * If a callback is specified, invoke it with the attribute.
 *
 * @param data, the packet
 * @param len, the length of the packet
 * @param arg, sockaddr_in where we will set our discovered packet
 *
 * @return, #GNUNET_OK on OK, #GNUNET_NO if the packet is invalid ( not a stun packet)
 */
int
GNUNET_NAT_stun_handle_packet(const void *data, size_t len, struct sockaddr_in *arg)
{
    const struct stun_header *hdr = (const struct stun_header *)data;
    struct stun_attr *attr;
    struct StunState st;
    int ret = GNUNET_OK;

    uint32_t advertised_message_size;
    uint32_t message_magic_cookie;


    /* On entry, 'len' is the length of the udp payload. After the
         * initial checks it becomes the size of unprocessed options,
         * while 'data' is advanced accordingly.
         */
    if (len < sizeof(struct stun_header)) {
        LOG (GNUNET_ERROR_TYPE_INFO,
             "STUN packet too short (only %d, wanting at least %d)\n", (int) len, (int) sizeof(struct stun_header));
        GNUNET_break_op (0);
        return GNUNET_NO;
    }
    /* Skip header as it is already in hdr */
    len -= sizeof(struct stun_header);
    data += sizeof(struct stun_header);

    /* len as advertised in the message */
    advertised_message_size = ntohs(hdr->msglen);

    message_magic_cookie = ntohl(hdr->magic);
    /* Compare if the cookie match */
    if(STUN_MAGIC_COOKIE != message_magic_cookie){
        LOG (GNUNET_ERROR_TYPE_INFO,
             "Invalid magic cookie \n");
        return GNUNET_NO;
    }


    LOG (GNUNET_ERROR_TYPE_INFO, "STUN Packet, msg %s (%04x), length: %d\n", stun_msg2str(ntohs(hdr->msgtype)),
         ntohs(hdr->msgtype),
         advertised_message_size);


    if (advertised_message_size > len) {
        LOG (GNUNET_ERROR_TYPE_INFO, "Scrambled STUN packet length (got %d, expecting %d)\n", advertised_message_size,
             (int)len);
        return GNUNET_NO;
    } else {
        len = advertised_message_size;
    }

    memset(&st,0, sizeof(st));

    while (len > 0) {
        if (len < sizeof(struct stun_attr)) {
            LOG (GNUNET_ERROR_TYPE_INFO, "Attribute too short (got %d, expecting %d)\n", (int)len,
                 (int) sizeof(struct stun_attr));
            break;
        }
        attr = (struct stun_attr *)data;

        /* compute total attribute length */
        advertised_message_size = ntohs(attr->len) + sizeof(struct stun_attr);

        /* Check if we still have space in our buffer */
        if (advertised_message_size > len ) {
            LOG (GNUNET_ERROR_TYPE_INFO, "Inconsistent Attribute (length %d exceeds remaining msg len %d)\n", advertised_message_size,
                 (int)len);
            break;
        }


        stun_get_mapped(&st, attr, arg, hdr->magic);

        if (stun_process_attr(&st, attr)) {
            LOG (GNUNET_ERROR_TYPE_INFO, "Failed to handle attribute %s (%04x)\n", stun_attr2str(ntohs(attr->attr)),
                 ntohs(attr->attr));
            break;
        }
        /** Clear attribute id: in case previous entry was a string,
         * this will act as the terminator for the string.
         **/
        attr->attr = 0;
        data += advertised_message_size;
        len -= advertised_message_size;
        ret = GNUNET_OK;
    }

    return ret;
}



/**
 * Clean-up used memory
 *
 * @param cls our `struct GNUNET_NAT_STUN_Handle *`
 */
static void
clean(struct GNUNET_NAT_STUN_Handle * handle)
{
    GNUNET_free(handle->stun_server);
    GNUNET_free(handle);

}



/**
 * Try to establish a connection given the specified address.
 *
 * @param cls our `struct GNUNET_NAT_STUN_Handle *`
 * @param addr address to try, NULL for "last call"
 * @param addrlen length of @a addr
 */
static void
stun_dns_callback (void *cls,
                   const struct sockaddr *addr,
                   socklen_t addrlen) {


    struct GNUNET_NAT_STUN_Handle *request = cls;

    struct stun_header *req;
    uint8_t reqdata[1024];
    int reqlen;
    struct sockaddr_in server;


    if(NULL == request) {

        if( GNUNET_NO == request->dns_success){
            LOG (GNUNET_ERROR_TYPE_INFO, "Empty request\n");
            request->cb(request->cb_cls, GNUNET_NAT_ERROR_INTERNAL_NETWORK_ERROR);
            clean(request);

        }
        return;
    }

    if (NULL == addr) {
        request->dns_active = NULL;

        if( GNUNET_NO == request->dns_success){
            LOG (GNUNET_ERROR_TYPE_INFO, "Error resolving host %s\n", request->stun_server);
            request->cb(request->cb_cls, GNUNET_NAT_ERROR_INTERNAL_NETWORK_ERROR);
            clean(request);

        }

        return;
    }


    request->dns_success= GNUNET_YES;
    memset(&server,0, sizeof(server));
    server.sin_family = AF_INET;
    server.sin_addr = ((struct sockaddr_in *)addr)->sin_addr;
    server.sin_port = htons(request->stun_port);


    /*Craft the simplest possible STUN packet. A request binding*/
    req = (struct stun_header *)reqdata;
    generate_request_id(req);
    reqlen = 0;
    req->msgtype = 0;
    req->msglen = 0;
    req->msglen = htons(reqlen);
    req->msgtype = htons(encode_message(STUN_REQUEST, STUN_BINDING));

    /* Send the packet */
    if (-1 == GNUNET_NETWORK_socket_sendto (request->sock, req, ntohs(req->msglen) + sizeof(*req),
                                            (const struct sockaddr *) &server, sizeof (server)))
    {
        GNUNET_log_strerror (GNUNET_ERROR_TYPE_ERROR, "Fail to sendto");
        request->cb(request->cb_cls, GNUNET_NAT_ERROR_INTERNAL_NETWORK_ERROR);
        clean(request);
        return;
    }


}





/**
 * Make Generic STUN request and
 * Send a generic stun request to the server specified using the specified socket.
 * possibly waiting for a reply and filling the 'reply' field with
 * the externally visible address.
 *
 * @param server, the address of the stun server
 * @param port, port of the stun server
 * @param sock the socket used to send the request
 * @return #GNUNET_OK success, #GNUNET_NO on error.
 */
int
GNUNET_NAT_stun_make_request(char * server, int port,
                             struct GNUNET_NETWORK_Handle * sock,GNUNET_NAT_stun_RequestCallback cb,
                             void *cb_cls)
{

    struct GNUNET_NAT_STUN_Handle *rh;

    rh = GNUNET_malloc (sizeof (struct GNUNET_NAT_STUN_Handle));
    rh->sock = sock;

    char * server_copy = GNUNET_strdup (server);

    rh->cb = cb;
    rh->cb_cls = cb_cls;
    rh->stun_server = server_copy;
    rh->stun_port = port;
    rh->dns_success = GNUNET_NO;

    rh->dns_active = GNUNET_RESOLVER_ip_get (server_copy, AF_INET,
                                             TIMEOUT,
                                             &stun_dns_callback, rh);

    if(rh->dns_active == NULL)
    {
        GNUNET_log_strerror (GNUNET_ERROR_TYPE_ERROR, "Failed DNS");
        GNUNET_free(rh);
        GNUNET_free(server_copy);

        return GNUNET_NO;
    }

    return GNUNET_OK;
}

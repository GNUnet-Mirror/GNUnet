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
     Free Software Foundation, Inc., 59 Temple Place - Suite 330,
     Boston, MA 02111-1307, USA.
*/

/**
 * Testcase for STUN server resolution
 *
 * @file nat/test_stun.c
 * @brief Testcase for STUN library
 * @author Bruno Souza Cabral - Major rewrite.
 * @autor Mark Spencer (Original code - borrowed from Asterisk)
 *
 */


#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_program_lib.h"
#include "gnunet_scheduler_lib.h"
#include "gnunet_nat_lib.h"


#include "test_stun.h"

#define LOG(kind,...) GNUNET_log_from (kind, "stun", __VA_ARGS__)

/**
 * The port the test service is running on (default 7895)
 */
static unsigned long port = 7895;
static int ret = 1;

static char *stun_server = STUN_SERVER;
static int stun_port = STUN_PORT;

/**
 * The listen socket of the service for IPv4
 */
static struct GNUNET_NETWORK_Handle *lsock4;


/**
 * The listen task ID for IPv4
 */
static struct GNUNET_SCHEDULER_Task * ltask4;



/**
 * Handle to a request given to the resolver.  Can be used to cancel
 * the request prior to the timeout or successful execution.  Also
 * used to track our internal state for the request.
 */
struct GNUNET_NAT_StunRequestHandle {

    /**
    * Handle to a pending DNS lookup request.
    */
    struct GNUNET_RESOLVER_RequestHandle *dns_active;


    /**
    * Handle to the listen socket
    */
    struct GNUNET_NETWORK_Handle * sock;

};




/* here we store credentials extracted from a message */
struct StunState {
    uint16_t attr;
};

/* callback type to be invoked on stun responses. */
typedef int (stun_cb_f)(struct StunState *st, struct stun_attr *attr, void *arg, unsigned int magic);



/**
 * Convert a message to a StunClass
 *
 * @param msg the received message
 * @return the converted StunClass
 */
static int decode_class(int msg)
{
    return ((msg & 0x0010) >> 4) | ((msg & 0x0100) >> 7);
}

/**
 * Convert a message to a StunMethod
 *
 * @param msg the received message
 * @return the converted StunMethod
 */
static int decode_method(int msg)
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
static int encode_message(StunClasses msg_class, StunMethods method)
{
    return ((msg_class & 1) << 4) | ((msg_class & 2) << 7) |
            (method & 0x000f) | ((method & 0x0070) << 1) | ((method & 0x0f800) << 2);
}

/* helper function to print message names */
static const char *stun_msg2str(int msg)
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
    snprintf(result, sizeof(result), "%s %s",
             method ? : "Unknown Method",
             msg_class ? : "Unknown Class Message");
    return result;
}

/* helper function to print attribute names */
static const char *stun_attr2str(int msg)
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



static int stun_process_attr(struct StunState *state, struct stun_attr *attr)
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


/* helper function to generate a random request id */
static void
generate_request_id(struct stun_header *req)
{
    int x;
    req->magic = htonl(STUN_MAGIC_COOKIE);
    for (x = 0; x < 3; x++)
        req->id.id[x] = GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_NONCE,
                                                  UINT32_MAX);
}


/* handle an incoming STUN message.
 *
 * Do some basic sanity checks on packet size and content,
 * try to extract a bit of information, and possibly reply.
 * At the moment this only processes BIND requests, and returns
 * the externally visible address of the request.
 * If a callback is specified, invoke it with the attribute.
 */
static int
stun_handle_packet(const uint8_t *data, size_t len, stun_cb_f *stun_cb, void *arg)
{
    struct stun_header *hdr = (struct stun_header *)data;
    struct stun_attr *attr;
    struct StunState st;
    int ret = STUN_IGNORE;

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
        return -1;
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
        GNUNET_break_op (0);
        return -1;
    }


    LOG (GNUNET_ERROR_TYPE_INFO, "STUN Packet, msg %s (%04x), length: %d\n", stun_msg2str(ntohs(hdr->msgtype)), ntohs(hdr->msgtype), advertised_message_size);


    if (advertised_message_size > len) {
        LOG (GNUNET_ERROR_TYPE_INFO, "Scrambled STUN packet length (got %d, expecting %d)\n", advertised_message_size, (int)len);
        GNUNET_break_op (0);
    } else {
        len = advertised_message_size;
    }
    /* Zero the struct */
    memset(&st,0, sizeof(st));

    while (len > 0) {
        if (len < sizeof(struct stun_attr)) {
            LOG (GNUNET_ERROR_TYPE_INFO, "Attribute too short (got %d, expecting %d)\n", (int)len, (int) sizeof(struct stun_attr));
            GNUNET_break_op (0);
            break;
        }
        attr = (struct stun_attr *)data;

        /* compute total attribute length */
        advertised_message_size = ntohs(attr->len) + sizeof(struct stun_attr);

        /* Check if we still have space in our buffer */
        if (advertised_message_size > len ) {
            LOG (GNUNET_ERROR_TYPE_INFO, "Inconsistent Attribute (length %d exceeds remaining msg len %d)\n", advertised_message_size, (int)len);
            GNUNET_break_op (0);
            break;
        }

        if (stun_cb){
            stun_cb(&st, attr, arg, hdr->magic);
        }

        if (stun_process_attr(&st, attr)) {
            LOG (GNUNET_ERROR_TYPE_INFO, "Failed to handle attribute %s (%04x)\n", stun_attr2str(ntohs(attr->attr)), ntohs(attr->attr));
            break;
        }
        /* Clear attribute id: in case previous entry was a string,
                 * this will act as the terminator for the string.
                 */
        attr->attr = 0;
        data += advertised_message_size;
        len -= advertised_message_size;
    }

    return ret;
}

/* Extract the STUN_MAPPED_ADDRESS from the stun response.
 * This is used as a callback for stun_handle_response
 * when called from stun_request.
 */
static int
stun_get_mapped(struct StunState *st, struct stun_attr *attr, void *arg, unsigned int magic)
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
    sa->sin_port = returned_addr->port ^ htons(ntohl(magic) >> 16);
    sa->sin_addr.s_addr = returned_addr->addr ^ magic;
    return 0;
}


/**
 * Try to establish a connection given the specified address.
 * This function is called by the resolver once we have a DNS reply.
 *
 * @param cls our `struct GNUNET_CONNECTION_Handle *`
 * @param addr address to try, NULL for "last call"
 * @param addrlen length of @a addr
 */
static void
try_connect_using_address (void *cls,
                           const struct sockaddr *addr,
                           socklen_t addrlen) {


    struct GNUNET_NAT_StunRequestHandle *request = cls;

    struct stun_header *req;
    uint8_t reqdata[1024];
    int reqlen;

    if(NULL == request) {
        LOG (GNUNET_ERROR_TYPE_INFO, "Empty request\n");
        return;
    }


    if (NULL == addr) {
        request->dns_active = NULL;
        LOG (GNUNET_ERROR_TYPE_INFO, "Error resolving host %s\n", stun_server);
        //BREAk op
        return;
    }



    struct sockaddr_in server;


    memset(&server,0, sizeof(server));
    server.sin_family = AF_INET;

    struct sockaddr_in *addr_in = (struct sockaddr_in *)addr;

    server.sin_addr = addr_in->sin_addr;
    server.sin_port = htons(stun_port);


    /*Craft the simplest possible STUN packet. A request binding*/
    req = (struct stun_header *)reqdata;
    generate_request_id(req);
    reqlen = 0;
    req->msgtype = 0;
    req->msglen = 0;


    req->msglen = htons(reqlen);
    req->msgtype = htons(encode_message(STUN_REQUEST, STUN_BINDING));


    if (-1 == GNUNET_NETWORK_socket_sendto (request->sock, req, ntohs(req->msglen) + sizeof(*req),
                                            (const struct sockaddr *) &server, sizeof (server)))
    {
        GNUNET_log_strerror (GNUNET_ERROR_TYPE_WARNING, "Failt to sendto");
    }

}


/* Generic STUN request
 * Send a generic stun request to the server specified,
 * possibly waiting for a reply and filling the 'reply' field with
 * the externally visible address. 
 
 * \param s the socket used to send the request
 * \return 0 on success, other values on error.
 */
struct GNUNET_NAT_StunRequestHandle *
stun_request(struct GNUNET_NETWORK_Handle * sock)
{


    struct GNUNET_NAT_StunRequestHandle *rh;


    rh = GNUNET_malloc (sizeof (struct GNUNET_NAT_StunRequestHandle));

    rh->sock = sock;

    rh->dns_active = GNUNET_RESOLVER_ip_get (stun_server, AF_INET,
                                 GNUNET_CONNECTION_CONNECT_RETRY_TIMEOUT,
                                 &try_connect_using_address, rh);




    return rh;
}

static void
print_answer(struct sockaddr_in* answer)
{
	printf("External IP is: %s , with port %d\n", inet_ntoa(answer->sin_addr), ntohs(answer->sin_port));
}


/**
 * Activity on our incoming socket.  Read data from the
 * incoming connection.
 *
 * @param cls 
 * @param tc scheduler context
 */
static void
do_udp_read (void *cls,
             const struct GNUNET_SCHEDULER_TaskContext *tc)
{
    //struct GNUNET_NAT_Test *tst = cls;
	unsigned char reply_buf[1024];
	ssize_t rlen;
	struct sockaddr_in answer;


    if ((0 != (tc->reason & GNUNET_SCHEDULER_REASON_READ_READY)) &&
      (GNUNET_NETWORK_fdset_isset (tc->read_ready,
                                   lsock4)))
	{
		rlen = GNUNET_NETWORK_socket_recv (lsock4, reply_buf, sizeof (reply_buf));
		printf("Recivied something of size %d", rlen);
		
		//Lets handle the packet
		memset(&answer, 0, sizeof(struct sockaddr_in));
        stun_handle_packet(reply_buf, rlen, stun_get_mapped, &answer);
		//Print the anser
		//TODO: Delete the object
		ret = 0;
		print_answer(&answer);
		
		
	}
}


/**
 * Create an IPv4 listen socket bound to our port.
 *
 * @return NULL on error
 */
static struct GNUNET_NETWORK_Handle *
bind_v4 ()
{
    struct GNUNET_NETWORK_Handle *ls;
    struct sockaddr_in sa4;
    int eno;

    memset (&sa4, 0, sizeof (sa4));
    sa4.sin_family = AF_INET;
    sa4.sin_port = htons (port);
#if HAVE_SOCKADDR_IN_SIN_LEN
    sa4.sin_len = sizeof (sa4);
#endif 
    ls = GNUNET_NETWORK_socket_create (AF_INET,
                                       SOCK_DGRAM,
                                       0);
    if (NULL == ls)
        return NULL;
    if (GNUNET_OK !=
            GNUNET_NETWORK_socket_bind (ls, (const struct sockaddr *) &sa4,
                                        sizeof (sa4)))
    {
        eno = errno;
        GNUNET_NETWORK_socket_close (ls);
        errno = eno;
        return NULL;
    }
    return ls;
}



/**
 * Main function run with scheduler.
 */


static void
run (void *cls, char *const *args, const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *cfg)
{


    //Lets create the socket
    lsock4 = bind_v4 ();
    if (NULL == lsock4)
    {
        GNUNET_log_strerror (GNUNET_ERROR_TYPE_ERROR, "bind");
    }
    else
    {
		printf("Binded, now will call add_read\n");
        //Lets call our function now when it accepts
        ltask4 = GNUNET_SCHEDULER_add_read_net (GNUNET_TIME_UNIT_FOREVER_REL,
                                                lsock4, &do_udp_read, NULL);

    }
    if(NULL == lsock4 )
    {
        GNUNET_SCHEDULER_shutdown ();
        return;
    }
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                "Service listens on port %u\n",
                port);
	printf("Start main event\n");
	stun_request(lsock4);
    //Main event
    //main_task = GNUNET_SCHEDULER_add_delayed (timeout, &do_timeout, nh);

}


int
main (int argc, char *const argv[])
{
    struct GNUNET_GETOPT_CommandLineOption options[] = {
        GNUNET_GETOPT_OPTION_END
    };

    char *const argv_prog[] = {
        "test-stun",
        NULL
    };
    GNUNET_log_setup ("test-stun",
                      "WARNING",
                      NULL);

    GNUNET_PROGRAM_run (1, argv_prog, "test-stun", "nohelp", options, &run, NULL);
    
	return ret;
}

/* end of test_nat.c */

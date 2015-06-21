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
 * @author Bruno Souza Cabral
 * @autor Mark Spencer (Original code borrowed from Asterisk)
 *
 */


#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_program_lib.h"
#include "gnunet_scheduler_lib.h"
#include "gnunet_nat_lib.h"


#include "test_stun.h"


/**
 * The port the test service is running on (default 7895)
 */
static unsigned long port = 7895;

static int ret = 1;

/**
 * The listen socket of the service for IPv4
 */
static struct GNUNET_NETWORK_Handle *lsock4;


/**
 * The listen task ID for IPv4
 */
static struct GNUNET_SCHEDULER_Task * ltask4;


static char *stun_server = STUN_SERVER;
static int stun_port = STUN_PORT;

static int stun_debug = 1;


struct stun_strings {
    const int value;
    const char *name;
};


static inline int stun_msg2class(int msg)
{
    return ((msg & 0x0010) >> 4) | ((msg & 0x0100) >> 7);
}

static inline int stun_msg2method(int msg)
{
    return (msg & 0x000f) | ((msg & 0x00e0) >> 1) | ((msg & 0x3e00) >> 2);
}

static inline int stun_msg2type(int class, int method)
{
    return ((class & 1) << 4) | ((class & 2) << 7) |
            (method & 0x000f) | ((method & 0x0070) << 1) | ((method & 0x0f800) << 2);
}

/* helper function to print message names */
static const char *stun_msg2str(int msg)
{
    static const struct stun_strings classes[] = {
    { STUN_REQUEST, "Request" },
    { STUN_INDICATION, "Indication" },
    { STUN_RESPONSE, "Response" },
    { STUN_ERROR_RESPONSE, "Error Response" },
    { 0, NULL }
};
    static const struct stun_strings methods[] = {
    { STUN_BINDING, "Binding" },
    { 0, NULL }
};
    static char result[32];
    const char *class = NULL, *method = NULL;
    int i, value;

    value = stun_msg2class(msg);
    for (i = 0; classes[i].name; i++) {
        class = classes[i].name;
        if (classes[i].value == value)
            break;
    }
    value = stun_msg2method(msg);
    for (i = 0; methods[i].name; i++) {
        method = methods[i].name;
        if (methods[i].value == value)
            break;
    }
    snprintf(result, sizeof(result), "%s %s",
             method ? : "Unknown Method",
             class ? : "Unknown Class Message");
    return result;
}

/* helper function to print attribute names */
static const char *stun_attr2str(int msg)
{
    static const struct stun_strings attrs[] = {
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

/* here we store credentials extracted from a message */
struct stun_state {
    unsigned short attr;
};

static int stun_process_attr(struct stun_state *state, struct stun_attr *attr)
{
    if (stun_debug)
        fprintf(stderr, "Found STUN Attribute %s (%04x), length %d\n",
                stun_attr2str(ntohs(attr->attr)), ntohs(attr->attr), ntohs(attr->len));
    switch (ntohs(attr->attr)) {
    case STUN_MAPPED_ADDRESS:
    case STUN_XOR_MAPPED_ADDRESS:
    case STUN_MS_XOR_MAPPED_ADDRESS:
        break;
    default:
        if (stun_debug)
            fprintf(stderr, "Ignoring STUN Attribute %s (%04x), length %d\n",
                    stun_attr2str(ntohs(attr->attr)), ntohs(attr->attr), ntohs(attr->len));
    }
    return 0;
}

/* append a string to an STUN message */
static void append_attr_string(struct stun_attr **attr, int attrval, const char *s, int *len, int *left)
{
    int str_length = strlen(s);
    int attr_length = str_length + ((~(str_length - 1)) & 0x3);
    int size = sizeof(**attr) + attr_length;
    if (*left > size) {
        (*attr)->attr = htons(attrval);
        (*attr)->len = htons(attr_length);
        memcpy((*attr)->value, s, str_length);
        memset((*attr)->value + str_length, 0, attr_length - str_length);
        (*attr) = (struct stun_attr *)((*attr)->value + attr_length);
        *len += size;
        *left -= size;
    }
}


/* helper function to generate a random request id */
static void stun_req_id(struct stun_header *req)
{
    int x;
    srand(time(0));
    req->magic = htonl(STUN_MAGIC_COOKIE);
    for (x = 0; x < 3; x++)
        req->id.id[x] = rand();
}

/* callback type to be invoked on stun responses. */
typedef int (stun_cb_f)(struct stun_state *st, struct stun_attr *attr, void *arg, unsigned int magic);

/* handle an incoming STUN message.
 *
 * Do some basic sanity checks on packet size and content,
 * try to extract a bit of information, and possibly reply.
 * At the moment this only processes BIND requests, and returns
 * the externally visible address of the request.
 * If a callback is specified, invoke it with the attribute.
 */
static int stun_handle_packet(unsigned char *data, size_t len, stun_cb_f *stun_cb, void *arg)
{
    struct stun_header *hdr = (struct stun_header *)data;
    struct stun_attr *attr;
    struct stun_state st;
    int ret = STUN_IGNORE;
    int x;

    /* On entry, 'len' is the length of the udp payload. After the
         * initial checks it becomes the size of unprocessed options,
         * while 'data' is advanced accordingly.
         */
    if (len < sizeof(struct stun_header)) {
        fprintf(stderr, "Runt STUN packet (only %d, wanting at least %d)\n", (int) len, (int) sizeof(struct stun_header));
        return -1;
    }
    len -= sizeof(struct stun_header);
    data += sizeof(struct stun_header);
    x = ntohs(hdr->msglen);	/* len as advertised in the message */
    if (stun_debug)
        fprintf(stderr, "STUN Packet, msg %s (%04x), length: %d\n", stun_msg2str(ntohs(hdr->msgtype)), ntohs(hdr->msgtype), x);
    if (x > len) {
        fprintf(stderr, "Scrambled STUN packet length (got %d, expecting %d)\n", x, (int)len);
    } else
        len = x;
    memset(&st,0, sizeof(st));

    while (len) {
        if (len < sizeof(struct stun_attr)) {
            fprintf(stderr, "Runt Attribute (got %d, expecting %d)\n", (int)len, (int) sizeof(struct stun_attr));
            break;
        }
        attr = (struct stun_attr *)data;

        /* compute total attribute length */
        x = ntohs(attr->len) + sizeof(struct stun_attr);
        if (x > len) {
            fprintf(stderr, "Inconsistent Attribute (length %d exceeds remaining msg len %d)\n", x, (int)len);
            break;
        }
        if (stun_cb)
            stun_cb(&st, attr, arg, hdr->magic);
        if (stun_process_attr(&st, attr)) {
            fprintf(stderr, "Failed to handle attribute %s (%04x)\n", stun_attr2str(ntohs(attr->attr)), ntohs(attr->attr));
            break;
        }
        /* Clear attribute id: in case previous entry was a string,
                 * this will act as the terminator for the string.
                 */
        attr->attr = 0;
        data += x;
        len -= x;
    }
    /* Null terminate any string.
         * XXX NOTE, we write past the size of the buffer passed by the
         * caller, so this is potentially dangerous. The only thing that
         * saves us is that usually we read the incoming message in a
         * much larger buffer
         */
    *data = '\0';

    return ret;
}

/* Extract the STUN_MAPPED_ADDRESS from the stun response.
 * This is used as a callback for stun_handle_response
 * when called from stun_request.
 */
static int stun_get_mapped(struct stun_state *st, struct stun_attr *attr, void *arg, unsigned int magic)
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
    if (ntohs(attr->len) < 8 && returned_addr->family != 1)
        return 1;

    st->attr = type;
    sa->sin_port = returned_addr->port ^ htons(ntohl(magic) >> 16);
    sa->sin_addr.s_addr = returned_addr->addr ^ magic;
    return 0;
}

/* Generic STUN request
 * Send a generic stun request to the server specified,
 * possibly waiting for a reply and filling the 'reply' field with
 * the externally visible address. 
 
 * \param s the socket used to send the request
 * \return 0 on success, other values on error.
 */
int stun_request(struct GNUNET_NETWORK_Handle * sock)
{
    struct stun_header *req;
    unsigned char reqdata[1024];
    int reqlen, reqleft;
    struct stun_attr *attr;


	
	
	struct sockaddr_in server;
	struct hostent *hostinfo = gethostbyname(stun_server);
	if (!hostinfo) {
		fprintf(stderr, "Error resolving host %s\n", stun_server);
		return -1;
	}
	memset(&server,0, sizeof(server));
	server.sin_family = AF_INET;
	server.sin_addr = *(struct in_addr*) hostinfo->h_addr;
	server.sin_port = htons(stun_port);
	
	

    req = (struct stun_header *)reqdata;
    stun_req_id(req);
    reqlen = 0;
    reqleft = sizeof(reqdata) - sizeof(struct stun_header);
    req->msgtype = 0;
    req->msglen = 0;
    attr = (struct stun_attr *)req->ies;

    append_attr_string(&attr, STUN_SOFTWARE, PACKAGE " v" VERSION_PACKAGE, &reqlen, &reqleft);
    req->msglen = htons(reqlen);
    req->msgtype = htons(stun_msg2type(STUN_REQUEST, STUN_BINDING));


	if (-1 == GNUNET_NETWORK_socket_sendto (sock, req, ntohs(req->msglen) + sizeof(*req),
                                    (const struct sockaddr *) &server, sizeof (server)))
	{
		GNUNET_log_strerror (GNUNET_ERROR_TYPE_WARNING, "sendto");
	}

    return -1;
}

static void print_answer(struct sockaddr_in* answer)
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
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
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

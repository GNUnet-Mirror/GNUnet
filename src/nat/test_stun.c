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
 * Testcase for STUN server resolution
 *
 * @file nat/test_stun.c
 * @brief Testcase for STUN library
 * @author Bruno Souza Cabral - Major rewrite.

 *
 */


#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_program_lib.h"
#include "gnunet_scheduler_lib.h"
#include "gnunet_nat_lib.h"



#define LOG(kind,...) GNUNET_log_from (kind, "test-stun", __VA_ARGS__)

/**
 * The port the test service is running on (default 7895)
 */
static unsigned long port = 7895;
static int ret = 1;

static char *stun_server = "stun.ekiga.net";
static int stun_port = 3478;

/**
 * The listen socket of the service for IPv4
 */
static struct GNUNET_NETWORK_Handle *lsock4;


/**
 * The listen task ID for IPv4
 */
static struct GNUNET_SCHEDULER_Task * ltask4;




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
		
		
		//Lets handle the packet
		memset(&answer, 0, sizeof(struct sockaddr_in));
        GNUNET_NAT_stun_handle_packet(reply_buf,rlen, &answer);

		//Print the answer
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
        /* So you read once and what will happen if you get an irregular message? Repeat and add timeout */

    }
    if(NULL == lsock4 )
    {
    	/* FIXME: duplicate check  */
        GNUNET_SCHEDULER_shutdown ();
        return;
    }
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                "Service listens on port %u\n",
                port);
	printf("Start main event\n");
    GNUNET_NAT_stun_make_request(stun_server, stun_port, lsock4);
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

/* end of test_stun.c */

/*
     This file is part of GNUnet.
     (C) 2009, 2010, 2011 Christian Grothoff (and other contributing authors)

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
 * @file gns/gnunet-service-gns.c
 * @brief GNUnet GNS service
 * @author Martin Schanzenbach
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_transport_service.h"
#include "gnunet_dns_service.h"
#include "gnunet_dnsparser_lib.h"
#include "gnunet_gns_service.h"
#include "gns.h"


/* TODO into gnunet_protocols */
#define GNUNET_MESSAGE_TYPE_GNS_CLIENT_LOOKUP 23
#define GNUNET_MESSAGE_TYPE_GNS_CLIENT_RESULT 24

/**
 * Our handle to the DNS handler library
 */
struct GNUNET_DNS_Handle *dns_handle;

/**
 * The configuration the GNS service is running with
 */
const struct GNUNET_CONFIGURATION_Handle *GNS_cfg;

/**
 * Our notification context.
 */
static struct GNUNET_SERVER_NotificationContext *nc;

/**
 * Task run during shutdown.
 *
 * @param cls unused
 * @param tc unused
 */
static void
shutdown_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  GNUNET_DNS_disconnect(dns_handle);
}

/**
 * The DNS request handler
 *
 * @param cls closure
 * @param rh request handle to user for reply
 * @param request_length number of bytes in request
 * @param request udp payload of the DNS request
 */
void
handle_dns_request(void *cls,
                   struct GNUNET_DNS_RequestHandle *rh,
                   size_t request_length,
                   const char *request)
{
  /**
   * TODO: parse request for tld
   * Queue rh and gns handle (or use cls)
   * How should lookup behave:
   *  - sync and return result or "NX"
   *  - async like dht with iter
   *  Maybe provide both, useful for cli app
   **/
  struct GNUNET_DNSPARSER_Packet *p;
  int namelen;
  int i;
  char *tail;
  
  p = GNUNET_DNSPARSER_parse (request, request_length);
  if (NULL == p)
  {
    fprintf (stderr, "Received malformed DNS packet, leaving it untouched\n");
    GNUNET_DNS_request_forward (rh);
    return;
  }
  /**
   * TODO factor out
   * Check tld and decide if we or
   * legacy dns is responsible
   **/
  for (i=0;i<p->num_queries;i++)
  {
    namelen = strlen(p->queries[i].name);
    if (namelen >= 7)
    {
      /**
       * TODO off by 1?
       * Move our tld/root to config file
       * Generate fake DNS reply that replaces .gnunet with .org
       **/
      tail = p->queries[i].name+(namelen-7);
      if (0 == strcmp(tail, ".gnunet"))
      {
        /* Do db lookup here. Make dht lookup if necessary */
        GNUNET_DNS_request_answer(rh, 0 /*length*/, NULL/*reply*/);
      }
      else
      {
        GNUNET_DNS_request_forward (rh);
      }
    }
  }
}

/*TODO*/
static void
handle_client_record_lookup(void *cls,
                            struct GNUNET_SERVER_Client *client,
                            const struct GNUNET_MessageHeader *message)
{
}

/**
 * Process GNS requests.
 *
 * @param cls closure
 * @param server the initialized server
 * @param c configuration to use
 */
static void
run (void *cls, struct GNUNET_SERVER_Handle *server,
     const struct GNUNET_CONFIGURATION_Handle *c)
{
  /* The IPC message types */
  static const struct GNUNET_SERVER_MessageHandler handlers[] = {
    /* callback, cls, type, size */
    {&handle_client_record_lookup, NULL, GNUNET_MESSAGE_TYPE_GNS_CLIENT_LOOKUP,
      0},
    {NULL, NULL, 0, 0}
  };
  
  nc = GNUNET_SERVER_notification_context_create (server, 1);

  /* TODO do some config parsing */

  GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_FOREVER_REL, &shutdown_task,
                                NULL);
  /**
   * Do gnunet dns init here
   * */
  dns_handle = GNUNET_DNS_connect(c,
                                  GNUNET_DNS_FLAG_PRE_RESOLUTION,
                                  &handle_dns_request, /* rh */
                                  NULL); /* Closure */
  GNUNET_SERVER_add_handlers (server, handlers);
  /**
   * Esp the lookup would require to keep track of the clients' context
   * See dht.
   * GNUNET_SERVER_disconnect_notify (server, &client_disconnect, NULL);
   **/
}


/**
 * The main function for the GNS service.
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return 0 ok, 1 on error
 */
int
main (int argc, char *const *argv)
{
  int ret;

  ret =
      (GNUNET_OK ==
       GNUNET_SERVICE_run (argc, argv, "gns", GNUNET_SERVICE_OPTION_NONE, &run,
                           NULL)) ? 0 : 1;
  return ret;
}

/* end of gnunet-service-gns.c */

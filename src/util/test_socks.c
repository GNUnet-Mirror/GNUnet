/*
     This file is part of GNUnet.
     Copyright (C) 2009 Christian Grothoff Jeff Burdges, and other contributing authors

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
 * @file util/test_socks.c
 * @brief tests for socks.c
 */
#include "platform.h"
#include "gnunet_util_lib.h"


#define PORT 35124

#define MYNAME "test_sockst"

static struct GNUNET_CLIENT_Connection *client;

static struct GNUNET_SERVER_Handle *server;

static struct GNUNET_CONFIGURATION_Handle *cfg;

#define MY_TYPE 130

struct CopyContext
{
  struct GNUNET_SERVER_Client *client;
  struct GNUNET_MessageHeader *cpy;
};

static size_t
copy_msg (void *cls, size_t size, void *buf)
{
  struct CopyContext *ctx = cls;
  struct GNUNET_MessageHeader *cpy = ctx->cpy;

  GNUNET_assert (sizeof (struct GNUNET_MessageHeader) == ntohs (cpy->size));
  GNUNET_assert (size >= ntohs (cpy->size));
  memcpy (buf, cpy, ntohs (cpy->size));
  GNUNET_SERVER_receive_done (ctx->client, GNUNET_OK);
  GNUNET_free (cpy);
  GNUNET_free (ctx);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Message bounced back to client\n");
  return sizeof (struct GNUNET_MessageHeader);
}


/**
 * Callback that just bounces the message back to the sender.
 */
static void
echo_cb (void *cls, struct GNUNET_SERVER_Client *client,
         const struct GNUNET_MessageHeader *message)
{
  struct CopyContext *cc;
  struct GNUNET_MessageHeader *cpy;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Receiving message from client, bouncing back\n");
  GNUNET_assert (sizeof (struct GNUNET_MessageHeader) == ntohs (message->size));
  cc = GNUNET_new (struct CopyContext);
  cc->client = client;
  cpy = GNUNET_malloc (ntohs (message->size));
  memcpy (cpy, message, ntohs (message->size));
  cc->cpy = cpy;
  GNUNET_assert (NULL !=
                 GNUNET_SERVER_notify_transmit_ready (client,
                                                      ntohs (message->size),
                                                      GNUNET_TIME_UNIT_SECONDS,
                                                      &copy_msg, cc));
}


static struct GNUNET_SERVER_MessageHandler handlers[] = {
  {&echo_cb, NULL, MY_TYPE, sizeof (struct GNUNET_MessageHeader)},
  {NULL, NULL, 0, 0}
};


static void
recv_bounce (void *cls, const struct GNUNET_MessageHeader *got)
{
  int *ok = cls;
  struct GNUNET_MessageHeader msg;

  GNUNET_assert (got != NULL);  /* timeout */
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Receiving bounce, checking content\n");
  msg.type = htons (MY_TYPE);
  msg.size = htons (sizeof (struct GNUNET_MessageHeader));
  GNUNET_assert (0 == memcmp (got, &msg, sizeof (struct GNUNET_MessageHeader)));
  GNUNET_CLIENT_disconnect (client);
  client = NULL;
  GNUNET_SERVER_destroy (server);
  server = NULL;
  *ok = 0;
}


static size_t
make_msg (void *cls, size_t size, void *buf)
{
  struct GNUNET_MessageHeader *msg = buf;

  GNUNET_assert (size >= sizeof (struct GNUNET_MessageHeader));
  msg->type = htons (MY_TYPE);
  msg->size = htons (sizeof (struct GNUNET_MessageHeader));
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Creating message for transmission\n");
  return sizeof (struct GNUNET_MessageHeader);
}


static void
task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct sockaddr_in sa;
  struct sockaddr *sap[2];
  socklen_t slens[2];

  /* test that ill-configured client fails instantly */
  GNUNET_assert (NULL == GNUNET_CLIENT_connect ("invalid-service", cfg));

  /* test IPC between client and server */
  sap[0] = (struct sockaddr *) &sa;
  slens[0] = sizeof (sa);
  sap[1] = NULL;
  slens[1] = 0;
  memset (&sa, 0, sizeof (sa));
#if HAVE_SOCKADDR_IN_SIN_LEN
  sa.sin_len = sizeof (sa);
#endif
  sa.sin_family = AF_INET;
  sa.sin_port = htons (PORT);
  server =
      GNUNET_SERVER_create (NULL, NULL, sap, slens,
                            GNUNET_TIME_relative_multiply
                            (GNUNET_TIME_UNIT_MILLISECONDS, 10000), GNUNET_NO);
  GNUNET_assert (server != NULL);
  handlers[0].callback_cls = cls;
  handlers[1].callback_cls = cls;
  GNUNET_SERVER_add_handlers (server, handlers);
  client = GNUNET_CLIENT_connect (MYNAME, cfg);
  GNUNET_assert (client != NULL);
  GNUNET_assert (NULL !=
                 GNUNET_CLIENT_notify_transmit_ready (client,
                                                      sizeof (struct
                                                              GNUNET_MessageHeader),
                                                      GNUNET_TIME_relative_multiply
                                                      (GNUNET_TIME_UNIT_SECONDS,5),
                                                      GNUNET_NO, &make_msg,
                                                      NULL));
  GNUNET_CLIENT_receive (client, &recv_bounce, cls,
                         GNUNET_TIME_relative_multiply
                         (GNUNET_TIME_UNIT_MILLISECONDS, 10000));
}


int
main (int argc, char *argv[])
{
  int ok;
  char * socksport = "1081";

  GNUNET_log_setup ("test_client",
                    "WARNING",
                    NULL);

  pid_t pid = fork();
  if (pid < 0)
    abort();
  if (pid == 0) {
    execlp ("ssh","ssh","-D",socksport,"127.0.0.1","-N",(char*)NULL);
    perror ("execlp(\"ssh\",\"ssh\",\"-D\",\"1081\",\"127.0.0.1\",\"-N\") ");
    printf (""
"Please ensure you have ssh installed and have sshd installed and running :\n"
"\tsudo apt-get install openssh-client openssh-server\n"
"If you run Tor as a network proxy then Tor might prevent ssh from connecting\n"
"to localhost.  Please either run  make check  from an unproxied user, or else\n"
"add these lines to the beginning of your ~/.ssh/config file :"
"\tHost 127.0.0.1 localhost\n"
"\t  CheckHostIP no\n"
"\t  Protocol 2\n"
"\t  ProxyCommand nc 127.0.0.1 22\n");
    kill (getppid(), SIGTERM);
    return 1;
  }
  sleep(1);

  cfg = GNUNET_CONFIGURATION_create ();
  GNUNET_CONFIGURATION_set_value_string (cfg, MYNAME, "SOCKSHOST", "127.0.0.1");
  GNUNET_CONFIGURATION_set_value_string (cfg, MYNAME, "SOCKSPORT", socksport);
  GNUNET_CONFIGURATION_set_value_number (cfg, MYNAME, "PORT", PORT);
  GNUNET_CONFIGURATION_set_value_string (cfg, MYNAME, "HOSTNAME", "127.0.0.1");
  ok = 1;
  GNUNET_SCHEDULER_run (&task, &ok);
  GNUNET_CONFIGURATION_destroy (cfg);

  kill (pid,SIGTERM);
  return ok;
}

/* end of test_client.c */

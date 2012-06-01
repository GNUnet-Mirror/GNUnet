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

#include "platform.h"
#include <gnunet_util_lib.h>
#include <microhttpd.h>
#include "gns_proxy_proto.h"
#include "gns.h"

#define GNUNET_GNS_PROXY_PORT 7777

//TODO maybe make this an api call
/**
 * Checks if name is in tld
 *
 * @param name the name to check
 * @param tld the TLD to check for
 * @return GNUNET_YES or GNUNET_NO
 */
int
is_tld(const char* name, const char* tld)
{
  int offset = 0;

  if (strlen(name) <= strlen(tld))
  {
    return GNUNET_NO;
  }

  offset = strlen(name)-strlen(tld);
  if (strcmp (name+offset, tld) != 0)
  {
    GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
               "%s is not in .%s TLD\n", name, tld);
    return GNUNET_NO;
  }

  return GNUNET_YES;
}

struct Socks5Request
{
  struct GNUNET_NETWORK_Handle *sock;
  struct GNUNET_NETWORK_Handle *remote_sock;

  int state;

  GNUNET_SCHEDULER_TaskIdentifier rtask;
  GNUNET_SCHEDULER_TaskIdentifier fwdrtask;
  GNUNET_SCHEDULER_TaskIdentifier wtask;
  GNUNET_SCHEDULER_TaskIdentifier fwdwtask;

  char rbuf[2048];
  char wbuf[2048];
  unsigned int rbuf_len;
  unsigned int wbuf_len;
};

unsigned long port = GNUNET_GNS_PROXY_PORT;
static struct GNUNET_NETWORK_Handle *lsock;
GNUNET_SCHEDULER_TaskIdentifier ltask;
static struct MHD_Daemon *httpd;
static GNUNET_SCHEDULER_TaskIdentifier httpd_task;

static int
con_val_iter (void *cls,
              enum MHD_ValueKind kind,
              const char *key,
              const char *value)
{
  char* buf = (char*)cls;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "%s:%s\n", key, value);

  if (0 == strcmp ("Host", key))
  {
    strcpy (buf, value);
    return MHD_NO;
  }
  return MHD_YES;
}

/**
 * Main MHD callback for handling requests.
 *
 * @param cls unused
 * @param connection MHD connection handle
 * @param method the HTTP method used ("GET", "PUT", etc.)
 * @param version the HTTP version string (i.e. "HTTP/1.1")
 * @param upload_data the data being uploaded (excluding HEADERS,
 *        for a POST that fits into memory and that is encoded
 *        with a supported encoding, the POST data will NOT be
 *        given in upload_data and is instead available as
 *        part of MHD_get_connection_values; very large POST
 *        data *will* be made available incrementally in
 *        upload_data)
 * @param upload_data_size set initially to the size of the
 *        upload_data provided; the method must update this
 *        value to the number of bytes NOT processed;
 * @param ptr pointer to location where we store the 'struct Request'
 * @return MHD_YES if the connection was handled successfully,
 *         MHD_NO if the socket must be closed due to a serious
 *         error while handling the request
 */
static int
create_response (void *cls,
                 struct MHD_Connection *con,
                 const char *url,
                 const char *meth,
                 const char *ver,
                 const char *upload_data,
                 size_t *upload_data_size,
                 void **con_cls)
{
  static int dummy;
  const char* page = "<html><head><title>gnoxy</title>"\
                      "</head><body>gnoxy demo</body></html>";
  struct MHD_Response *response;
  char host[265];
  int ret;
  
  if (0 != strcmp (meth, "GET"))
    return MHD_NO;
  if (&dummy != *con_cls)
  {
    *con_cls = &dummy;
    return MHD_YES;
  }

  if (0 != *upload_data_size)
    return MHD_NO;

  *con_cls = NULL;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "url %s\n", url);

  MHD_get_connection_values (con,
                             MHD_HEADER_KIND,
                             &con_val_iter, host);

  response = MHD_create_response_from_buffer (strlen (page),
                                              (void*)page,
                                              MHD_RESPMEM_PERSISTENT);
  ret = MHD_queue_response (con,
                            MHD_HTTP_OK,
                            response);
  MHD_destroy_response (response);
  return ret;
}

/**
 * Task run whenever HTTP server operations are pending.
 *
 * @param cls unused
 * @param tc sched context
 */
static void
do_httpd (void *cls,
          const struct GNUNET_SCHEDULER_TaskContext *tc);

/**
 * Schedule MHD
 */
static void
run_httpd ()
{
  fd_set rs;
  fd_set ws;
  fd_set es;
  struct GNUNET_NETWORK_FDSet *wrs;
  struct GNUNET_NETWORK_FDSet *wws;
  struct GNUNET_NETWORK_FDSet *wes;
  int max;
  int haveto;
  unsigned MHD_LONG_LONG timeout;
  struct GNUNET_TIME_Relative tv;

  FD_ZERO (&rs);
  FD_ZERO (&ws);
  FD_ZERO (&es);
  wrs = GNUNET_NETWORK_fdset_create ();
  wes = GNUNET_NETWORK_fdset_create ();
  wws = GNUNET_NETWORK_fdset_create ();
  max = -1;
  GNUNET_assert (MHD_YES == MHD_get_fdset (httpd, &rs, &ws, &es, &max));
  haveto = MHD_get_timeout (httpd, &timeout);

  if (haveto == MHD_YES)
    tv.rel_value = (uint64_t) timeout;
  else
    tv = GNUNET_TIME_UNIT_FOREVER_REL;
  GNUNET_NETWORK_fdset_copy_native (wrs, &rs, max + 1);
  GNUNET_NETWORK_fdset_copy_native (wws, &ws, max + 1);
  GNUNET_NETWORK_fdset_copy_native (wes, &es, max + 1);
  
  if (httpd_task != GNUNET_SCHEDULER_NO_TASK)
    GNUNET_SCHEDULER_cancel (httpd_task);
  httpd_task =
    GNUNET_SCHEDULER_add_select (GNUNET_SCHEDULER_PRIORITY_HIGH,
                                 tv, wrs, wws,
                                 &do_httpd, NULL);
  GNUNET_NETWORK_fdset_destroy (wrs);
  GNUNET_NETWORK_fdset_destroy (wws);
  GNUNET_NETWORK_fdset_destroy (wes);
}

/**
 * Task run whenever HTTP server operations are pending.
 *
 * @param cls unused
 * @param tc sched context
 */
static void
do_httpd (void *cls,
          const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  httpd_task = GNUNET_SCHEDULER_NO_TASK;
  MHD_run (httpd);
  run_httpd ();
}

/**
 * Read data from socket
 *
 * @param cls the closure
 * @param tc scheduler context
 */
static void
do_read (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc);

/**
 * Read from remote end
 *
 * @param cls closure
 * @param tc scheduler context
 */
static void
do_read_remote (void* cls, const struct GNUNET_SCHEDULER_TaskContext *tc);

/**
 * Write data to remote socket
 *
 * @param cls the closure
 * @param tc scheduler context
 */
static void
do_write_remote (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct Socks5Request *s5r = cls;
  unsigned int len;

  s5r->fwdwtask = GNUNET_SCHEDULER_NO_TASK;

  if ((NULL != tc->read_ready) &&
      (GNUNET_NETWORK_fdset_isset (tc->write_ready, s5r->remote_sock)) &&
      (len = GNUNET_NETWORK_socket_send (s5r->remote_sock, s5r->rbuf,
                                         s5r->rbuf_len)))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Successfully sent %d bytes to remote socket\n",
                len);
  }
  else
  {
    GNUNET_log_strerror (GNUNET_ERROR_TYPE_WARNING, "write remote");
    //Really!?!?!?
    if (s5r->rtask != GNUNET_SCHEDULER_NO_TASK)
      GNUNET_SCHEDULER_cancel (s5r->rtask);
    if (s5r->wtask != GNUNET_SCHEDULER_NO_TASK)
      GNUNET_SCHEDULER_cancel (s5r->wtask);
    if (s5r->fwdrtask != GNUNET_SCHEDULER_NO_TASK)
      GNUNET_SCHEDULER_cancel (s5r->fwdrtask);
    GNUNET_NETWORK_socket_close (s5r->remote_sock);
    GNUNET_NETWORK_socket_close (s5r->sock);
    GNUNET_free(s5r);
    return;
  }

  s5r->rtask =
    GNUNET_SCHEDULER_add_read_net (GNUNET_TIME_UNIT_FOREVER_REL,
                                   s5r->sock,
                                   &do_read, s5r);
}


/**
 * Write data to socket
 *
 * @param cls the closure
 * @param tc scheduler context
 */
static void
do_write (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct Socks5Request *s5r = cls;
  unsigned int len;

  s5r->wtask = GNUNET_SCHEDULER_NO_TASK;

  if ((NULL != tc->read_ready) &&
      (GNUNET_NETWORK_fdset_isset (tc->write_ready, s5r->sock)) &&
      (len = GNUNET_NETWORK_socket_send (s5r->sock, s5r->wbuf,
                                         s5r->wbuf_len)))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Successfully sent %d bytes to socket\n",
                len);
  }
  else
  {
    
    GNUNET_log_strerror (GNUNET_ERROR_TYPE_WARNING, "write");
    //Really!?!?!?
    if (s5r->rtask != GNUNET_SCHEDULER_NO_TASK)
      GNUNET_SCHEDULER_cancel (s5r->rtask);
    if (s5r->fwdwtask != GNUNET_SCHEDULER_NO_TASK)
      GNUNET_SCHEDULER_cancel (s5r->fwdwtask);
    if (s5r->fwdrtask != GNUNET_SCHEDULER_NO_TASK)
      GNUNET_SCHEDULER_cancel (s5r->fwdrtask);
    GNUNET_NETWORK_socket_close (s5r->remote_sock);
    GNUNET_NETWORK_socket_close (s5r->sock);
    GNUNET_free(s5r);
    return;
  }

  if ((s5r->state == SOCKS5_DATA_TRANSFER) &&
      (s5r->fwdrtask == GNUNET_SCHEDULER_NO_TASK))
    s5r->fwdrtask =
      GNUNET_SCHEDULER_add_read_net (GNUNET_TIME_UNIT_FOREVER_REL,
                                     s5r->remote_sock,
                                     &do_read_remote, s5r);
}

/**
 * Read from remote end
 *
 * @param cls closure
 * @param tc scheduler context
 */
static void
do_read_remote (void* cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct Socks5Request *s5r = cls;
  
  s5r->fwdrtask = GNUNET_SCHEDULER_NO_TASK;


  if ((NULL != tc->write_ready) &&
      (GNUNET_NETWORK_fdset_isset (tc->read_ready, s5r->remote_sock)) &&
      (s5r->wbuf_len = GNUNET_NETWORK_socket_recv (s5r->remote_sock, s5r->wbuf,
                                         sizeof (s5r->wbuf))))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Successfully read %d bytes from remote socket\n",
                s5r->wbuf_len);
  }
  else
  {
    if (s5r->wbuf_len == 0)
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "0 bytes received from remote... graceful shutdown!\n");
    if (s5r->fwdwtask != GNUNET_SCHEDULER_NO_TASK)
      GNUNET_SCHEDULER_cancel (s5r->fwdwtask);
    if (s5r->rtask != GNUNET_SCHEDULER_NO_TASK)
      GNUNET_SCHEDULER_cancel (s5r->rtask);
    
    GNUNET_NETWORK_socket_close (s5r->remote_sock);
    s5r->remote_sock = NULL;
    GNUNET_NETWORK_socket_close (s5r->sock);
    GNUNET_free(s5r);

    return;
  }
  
  s5r->wtask = GNUNET_SCHEDULER_add_write_net (GNUNET_TIME_UNIT_FOREVER_REL,
                                               s5r->sock,
                                               &do_write, s5r);
  
}


static int
add_handle_to_mhd (struct GNUNET_NETWORK_Handle *h)
{
  int fd;
  struct sockaddr *addr;
  socklen_t len;

  fd = GNUNET_NETWORK_get_fd (h);
  addr = GNUNET_NETWORK_get_addr (h);
  len = GNUNET_NETWORK_get_addrlen (h);

  return MHD_add_connection (httpd, fd, addr, len);
}

/**
 * Read data from incoming connection
 *
 * @param cls the closure
 * @param tc the scheduler context
 */
static void
do_read (void* cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct Socks5Request *s5r = cls;
  struct socks5_client_hello *c_hello;
  struct socks5_server_hello *s_hello;
  struct socks5_client_request *c_req;
  struct socks5_server_response *s_resp;

  char domain[256];
  uint8_t dom_len;
  uint16_t req_port;
  struct hostent *phost;
  uint32_t remote_ip;
  struct sockaddr_in remote_addr;
  struct in_addr *r_sin_addr;

  s5r->rtask = GNUNET_SCHEDULER_NO_TASK;

  if ((NULL != tc->write_ready) &&
      (GNUNET_NETWORK_fdset_isset (tc->read_ready, s5r->sock)) &&
      (s5r->rbuf_len = GNUNET_NETWORK_socket_recv (s5r->sock, s5r->rbuf,
                                         sizeof (s5r->rbuf))))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Successfully read %d bytes from socket\n",
                s5r->rbuf_len);
  }
  else
  {
    if (s5r->rbuf_len != 0)
      GNUNET_log_strerror (GNUNET_ERROR_TYPE_WARNING, "read");
    else
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "client disco!\n");

    if (s5r->fwdrtask != GNUNET_SCHEDULER_NO_TASK)
      GNUNET_SCHEDULER_cancel (s5r->fwdrtask);
    if (s5r->wtask != GNUNET_SCHEDULER_NO_TASK)
      GNUNET_SCHEDULER_cancel (s5r->wtask);
    if (s5r->fwdwtask != GNUNET_SCHEDULER_NO_TASK)
      GNUNET_SCHEDULER_cancel (s5r->fwdwtask);
    GNUNET_NETWORK_socket_close (s5r->remote_sock);
    GNUNET_NETWORK_socket_close (s5r->sock);
    GNUNET_free(s5r);
    return;
  }

  if (s5r->state == SOCKS5_INIT)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "SOCKS5 init\n");
    c_hello = (struct socks5_client_hello*)&s5r->rbuf;

    GNUNET_assert (c_hello->version == SOCKS_VERSION_5);

    s_hello = (struct socks5_server_hello*)&s5r->wbuf;
    s5r->wbuf_len = sizeof( struct socks5_server_hello );

    s_hello->version = c_hello->version;
    s_hello->auth_method = SOCKS_AUTH_NONE;

    /* Write response to client */
    s5r->wtask = GNUNET_SCHEDULER_add_write_net (GNUNET_TIME_UNIT_FOREVER_REL,
                                                s5r->sock,
                                                &do_write, s5r);

    s5r->rtask = GNUNET_SCHEDULER_add_read_net (GNUNET_TIME_UNIT_FOREVER_REL,
                                                s5r->sock,
                                                &do_read, s5r);

    s5r->state = SOCKS5_REQUEST;
    return;
  }

  if (s5r->state == SOCKS5_REQUEST)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Processing SOCKS5 request\n");
    c_req = (struct socks5_client_request*)&s5r->rbuf;
    s_resp = (struct socks5_server_response*)&s5r->wbuf;
    //Only 10byte for ipv4 response!
    s5r->wbuf_len = 10;//sizeof (struct socks5_server_response);

    GNUNET_assert (c_req->addr_type == 3);

    dom_len = *((uint8_t*)(&(c_req->addr_type) + 1));
    memset(domain, 0, sizeof(domain));
    strncpy(domain, (char*)(&(c_req->addr_type) + 2), dom_len);
    req_port = *((uint16_t*)(&(c_req->addr_type) + 2 + dom_len));

    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Requested connection is %s:%d\n",
                domain,
                ntohs(req_port));

    if (is_tld (domain, GNUNET_GNS_TLD) ||
        is_tld (domain, GNUNET_GNS_TLD_ZKEY))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Requested connection is gnunet tld\n",
                  domain);

      if (NULL == httpd)
      {
        GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                    _("Failed to start HTTP server\n"));
        s_resp->version = 0x05;
        s_resp->reply = 0x01;
        s5r->wtask = 
          GNUNET_SCHEDULER_add_write_net (GNUNET_TIME_UNIT_FOREVER_REL,
                                        s5r->sock,
                                        &do_write, s5r);
        //ERROR!
        //TODO! close socket after the write! schedule task
        //GNUNET_NETWORK_socket_close (s5r->sock);
        //GNUNET_free(s5r);
        return;
      }

      if (MHD_YES == add_handle_to_mhd ( s5r->sock ))
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                    "Sucessfully added client to MHD!\n");
      s_resp->version = 0x05;
      s_resp->reply = 0x00;
      s_resp->reserved = 0x00;
      s_resp->addr_type = 0x01;

      s5r->wtask =
        GNUNET_SCHEDULER_add_write_net (GNUNET_TIME_UNIT_FOREVER_REL,
                                        s5r->sock,
                                        &do_write, s5r);
      run_httpd ();
      //GNUNET_free ( s5r );
      //FIXME complete socks resp!
      return;
    }
    else
    {
      phost = (struct hostent*)gethostbyname (domain);
      if (phost == NULL)
      {
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                    "Resolve %s error!\n", domain );
        s_resp->version = 0x05;
        s_resp->reply = 0x01;
        s5r->wtask = 
          GNUNET_SCHEDULER_add_write_net (GNUNET_TIME_UNIT_FOREVER_REL,
                                          s5r->sock,
                                          &do_write, s5r);
        //ERROR!
        //TODO! close socket after the write! schedule task
        //GNUNET_NETWORK_socket_close (s5r->sock);
        //GNUNET_free(s5r);
        return;
      }

      s5r->remote_sock = GNUNET_NETWORK_socket_create (AF_INET,
                                                       SOCK_STREAM,
                                                       0);
      r_sin_addr = (struct in_addr*)(phost->h_addr);
      remote_ip = r_sin_addr->s_addr;
      memset(&remote_addr, 0, sizeof(remote_addr));
      remote_addr.sin_family = AF_INET;
#if HAVE_SOCKADDR_IN_SIN_LEN
      remote_addr.sin_len = sizeof (remote_addr);
#endif
      remote_addr.sin_addr.s_addr = remote_ip;
      remote_addr.sin_port = req_port;
      
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "target server: %s:%u\n", inet_ntoa(remote_addr.sin_addr),
                  ntohs(req_port));

      if ((GNUNET_OK !=
          GNUNET_NETWORK_socket_connect ( s5r->remote_sock,
                                          (const struct sockaddr*)&remote_addr,
                                          sizeof (remote_addr)))
          && (errno != EINPROGRESS))
      {
        GNUNET_log_strerror (GNUNET_ERROR_TYPE_WARNING, "connect");
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                    "socket request error...\n");
        s_resp->version = 0x05;
        s_resp->reply = 0x01;
        s5r->wtask =
          GNUNET_SCHEDULER_add_write_net (GNUNET_TIME_UNIT_FOREVER_REL,
                                          s5r->sock,
                                          &do_write, s5r);
        //TODO see above
        return;
      }

      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "new remote connection\n");

      s_resp->version = 0x05;
      s_resp->reply = 0x00;
      s_resp->reserved = 0x00;
      s_resp->addr_type = 0x01;

      s5r->state = SOCKS5_DATA_TRANSFER;

      s5r->wtask =
        GNUNET_SCHEDULER_add_write_net (GNUNET_TIME_UNIT_FOREVER_REL,
                                        s5r->sock,
                                        &do_write, s5r);
      s5r->rtask =
        GNUNET_SCHEDULER_add_read_net (GNUNET_TIME_UNIT_FOREVER_REL,
                                       s5r->sock,
                                       &do_read, s5r);

    }
    return;
  }

  if (s5r->state == SOCKS5_DATA_TRANSFER)
  {
    if ((s5r->remote_sock == NULL) || (s5r->rbuf_len == 0))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Closing connection to client\n");
      if (s5r->rtask != GNUNET_SCHEDULER_NO_TASK)
        GNUNET_SCHEDULER_cancel (s5r->rtask);
      if (s5r->fwdwtask != GNUNET_SCHEDULER_NO_TASK)
        GNUNET_SCHEDULER_cancel (s5r->fwdwtask);
      if (s5r->fwdrtask != GNUNET_SCHEDULER_NO_TASK)
        GNUNET_SCHEDULER_cancel (s5r->fwdrtask);
      if (s5r->fwdrtask != GNUNET_SCHEDULER_NO_TASK)
        GNUNET_SCHEDULER_cancel (s5r->fwdrtask);
      
      if (s5r->remote_sock != NULL)
        GNUNET_NETWORK_socket_close (s5r->remote_sock);
      GNUNET_NETWORK_socket_close (s5r->sock);
      GNUNET_free(s5r);
      return;
    }

    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "forwarding %d bytes from client\n", s5r->rbuf_len);

    s5r->fwdwtask =
      GNUNET_SCHEDULER_add_write_net (GNUNET_TIME_UNIT_FOREVER_REL,
                                      s5r->remote_sock,
                                      &do_write_remote, s5r);

    if (s5r->fwdrtask == GNUNET_SCHEDULER_NO_TASK)
    {
      s5r->fwdrtask =
        GNUNET_SCHEDULER_add_read_net (GNUNET_TIME_UNIT_FOREVER_REL,
                                       s5r->remote_sock,
                                       &do_read_remote, s5r);
    }


  }

  //GNUNET_CONTAINER_DLL_remove (s5conns.head, s5conns.tail, s5r);

}

/**
 * Accept new incoming connections
 *
 * @param cls the closure
 * @param tc the scheduler context
 */
static void
do_accept (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_NETWORK_Handle *s;
  struct Socks5Request *s5r;

  ltask = GNUNET_SCHEDULER_NO_TASK;
  if (0 != (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN))
    return;

  ltask = GNUNET_SCHEDULER_add_read_net (GNUNET_TIME_UNIT_FOREVER_REL,
                                         lsock,
                                         &do_accept, NULL);

  s = GNUNET_NETWORK_socket_accept (lsock, NULL, NULL);

  if (NULL == s)
  {
    GNUNET_log_strerror (GNUNET_ERROR_TYPE_INFO, "accept");
    return;
  }

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Got an inbound connection, waiting for data\n");

  s5r = GNUNET_malloc (sizeof (struct Socks5Request));
  s5r->sock = s;
  s5r->state = SOCKS5_INIT;
  s5r->wtask = GNUNET_SCHEDULER_NO_TASK;
  s5r->fwdwtask = GNUNET_SCHEDULER_NO_TASK;
  s5r->fwdrtask = GNUNET_SCHEDULER_NO_TASK;
  s5r->rtask = GNUNET_SCHEDULER_add_read_net (GNUNET_TIME_UNIT_FOREVER_REL,
                                              s5r->sock,
                                              &do_read, s5r);
  //GNUNET_CONTAINER_DLL_insert (s5conns.head, s5conns.tail, s5r);
}

/**
 * Main function that will be run
 *
 * @param cls closure
 * @param args remaining command-line arguments
 * @param cfgfile name of the configuration file used (for saving, can be NULL!)
 * @param cfg configuration
 */
static void
run (void *cls, char *const *args, const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  struct sockaddr_in sa;

  memset (&sa, 0, sizeof (sa));
  sa.sin_family = AF_INET;
  sa.sin_port = htons (port);
#if HAVE_SOCKADDR_IN_SIN_LEN
  sa.sin_len = sizeof (sa);
#endif

  lsock = GNUNET_NETWORK_socket_create (AF_INET,
                                        SOCK_STREAM,
                                        0);

  if ((NULL == lsock) ||
      (GNUNET_OK !=
       GNUNET_NETWORK_socket_bind (lsock, (const struct sockaddr *) &sa,
                                   sizeof (sa))))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Failed to create listen socket bound to `%s'",
                GNUNET_a2s ((const struct sockaddr *) &sa, sizeof (sa)));
    if (NULL != lsock)
      GNUNET_NETWORK_socket_close (lsock);
    return;
  }

  if (GNUNET_OK != GNUNET_NETWORK_socket_listen (lsock, 5))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Failed to listen on socket bound to `%s'",
                GNUNET_a2s ((const struct sockaddr *) &sa, sizeof (sa)));
    return;
  }

  ltask = GNUNET_SCHEDULER_add_read_net (GNUNET_TIME_UNIT_FOREVER_REL,
                                         lsock, &do_accept, NULL);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Proxy listens on port %u\n",
              port);
  
  httpd = MHD_start_daemon (MHD_USE_DEBUG, 4444,
                               NULL, NULL,
                               &create_response, NULL,
                               MHD_OPTION_CONNECTION_LIMIT, (unsigned int) 128,
                               MHD_OPTION_CONNECTION_TIMEOUT, (unsigned int) 16,
                               MHD_OPTION_NOTIFY_COMPLETED,
                               NULL, NULL,
                               MHD_OPTION_END);
  run_httpd ();

}

/**
 * The main function for gnunet-gns-proxy.
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return 0 ok, 1 on error
 */
int
main (int argc, char *const *argv)
{
  static const struct GNUNET_GETOPT_CommandLineOption options[] = {
    {'p', "port", NULL,
     gettext_noop ("listen on specified port"), 1,
     &GNUNET_GETOPT_set_string, &port},
    GNUNET_GETOPT_OPTION_END
  };

  int ret;

  GNUNET_log_setup ("gnunet-gns-proxy", "WARNING", NULL);
  ret =
      (GNUNET_OK ==
       GNUNET_PROGRAM_run (argc, argv, "gnunet-gns-proxy",
                           _("GNUnet GNS proxy"),
                           options,
                           &run, NULL)) ? 0 : 1;
  return ret;
}

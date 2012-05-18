/*
 * The GNS Socks5 Proxy
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/epoll.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <microhttpd.h>

#include "protocol.h"

#define MAXEVENTS 64

#define DEBUG 1

/* 
 * Create an ipv4/6 tcp socket for a given port
 *
 * @param port the port to bind to
 * @return the file descriptor of the socket or -1
 */
static int
create_socket (char *port)
{
  struct addrinfo hints;
  struct addrinfo *result, *rp;
  int s, sfd;

  memset (&hints, 0, sizeof (struct addrinfo));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_PASSIVE;

  s = getaddrinfo (NULL, port, &hints, &result);
  if (s != 0)
  {
    fprintf (stderr, "getaddrinfo: %s\n", gai_strerror (s));
    return -1;
  }

  for (rp = result; rp != NULL; rp = rp->ai_next)
  {
    sfd = socket (rp->ai_family, rp->ai_socktype, rp->ai_protocol);
    if (sfd == -1)
      continue;

    s = bind (sfd, rp->ai_addr, rp->ai_addrlen);
    if (s == 0)
    {
      break;
    }
    close(sfd);
  }

  if (rp == NULL)
  {
    fprintf (stderr, "Could not bind\n");
    return -1;
  }

  freeaddrinfo (result);

  return sfd;
}


/*
 * Make socket with fd non blocking
 *
 * @param fd the file descriptor of the socket
 * @return -1 on error
 */
static int
setnonblocking (int fd)
{
  int flags, s;

  flags = fcntl (fd, F_GETFL, 0);
  if (flags == -1)
  {
    perror ("fcntl");
    return -1;
  }

  flags |= O_NONBLOCK;
  s = fcntl (fd, F_SETFL, flags);
  if (s == -1)
  {
    perror ("fcntl");
    return -1;
  }

  return 0;
}

/**
 * Checks if name is in tld
 *
 * @param name the name to check
 * @param tld the TLD to check for
 * @return -1 if name not in tld
 */
static int
is_tld (const char* name, const char* tld)
{
  int offset = 0;

  if (strlen (name) <= strlen (tld))
    return -1;

  offset = strlen (name) - strlen (tld);
  if (strcmp (name+offset, tld) != 0)
    return -1;

  return 0;
}


/*
 * Connect to host specified in phost
 *
 * @param phost the hostentry containing the IP
 * @return fd to the connection or -1 on error
 */
static int
connect_to_domain (struct hostent* phost, uint16_t srv_port)
{
  uint32_t srv_ip;
  struct sockaddr_in srv_addr;
  struct in_addr *sin_addr;
  int conn_fd;


  sin_addr = (struct in_addr*)(phost->h_addr);
  srv_ip = sin_addr->s_addr;
  conn_fd = socket(AF_INET, SOCK_STREAM, 0);
  memset(&srv_addr, 0, sizeof(srv_addr));
  srv_addr.sin_family = AF_INET;
  srv_addr.sin_addr.s_addr = srv_ip;
  srv_addr.sin_port = srv_port;
  printf("target server: %s:%u\n", inet_ntoa(srv_addr.sin_addr), 
         ntohs(srv_port));

  if (connect (conn_fd, (struct sockaddr*)&srv_addr,
               sizeof (struct sockaddr)) < 0)
  {
   printf("socket request error...\n");
   close(conn_fd);
   return -1;
  }
  
  setnonblocking(conn_fd);

  return conn_fd;
}

static struct MHD_Daemon *mhd_daemon;

static int
access_cb (void* cls,
           const struct sockaddr *addr,
           socklen_t addrlen)
{
  printf ("access cb called\n");
  return MHD_YES;
}

static int
accept_cb (void *cls,
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
  response = MHD_create_response_from_data (strlen(page),
                                            (void*) page,
                                            MHD_NO,
                                            MHD_NO);

  ret = MHD_queue_response (con, MHD_HTTP_OK, response);
  MHD_destroy_response (response);
  return ret;
}

int main ( int argc, char *argv[] )
{
  int sfd, s;
  int efd;
  struct epoll_event event;
  struct epoll_event *events;
  int ev_states[MAXEVENTS];
  int n, i, j;
  struct socks5_bridge* br;
  
  struct sockaddr in_addr;
  socklen_t in_len;
  int infd;
  char hbuf[NI_MAXHOST], sbuf[NI_MAXSERV];
  
  int done;
  ssize_t count;
  char buf[512];
  struct socks5_server_hello hello;
  struct socks5_server_response resp;
  struct socks5_client_request *req;
  struct socks5_bridge* new_br;
  char domain[256];
  uint8_t msg[16];
  uint8_t dom_len;
  uint16_t req_port;
  int conn_fd;
  struct hostent *phost;

  mhd_daemon = NULL;
  
  for (j = 0; j < MAXEVENTS; j++)
    ev_states[j] = SOCKS5_INIT;

  if (argc != 2)
  {
    fprintf (stderr, "Usage: %s [port]\n", argv[0]);
    exit (EXIT_FAILURE);
  }

  sfd = create_socket(argv[1]);
  if (s == -1)
    abort ();

  s = setnonblocking (sfd);
  if (s == -1)
    abort ();

  s = listen (sfd, SOMAXCONN);
  if (s == -1)
  {
    perror ("listen");
    abort ();
  }

  efd = epoll_create1 (0);
  if (efd == -1)
  {
    perror ("epoll create");
    abort ();
  }

  br = malloc(sizeof (struct socks5_bridge));
  event.data.ptr = br;
  br->fd = sfd;
  br->remote_end = NULL;

  event.events = EPOLLIN | EPOLLET;
  s = epoll_ctl (efd, EPOLL_CTL_ADD, sfd, &event);
  if (s == -1)
  {
    perror ("epoll ctl");
    abort ();
  }

  events = calloc (MAXEVENTS, sizeof event);

  while (1)
  {
    n = epoll_wait (efd, events, MAXEVENTS, -1);
    for (i = 0; i < n; i++)
    {
      br = (struct socks5_bridge*)(events[i].data.ptr);

      if ((events[i].events & EPOLLERR) ||
          (events[i].events & EPOLLHUP) ||
          (!(events[i].events & EPOLLIN)))
      {
        fprintf (stderr, "epoll error %d\n", events[i].events);
        fprintf (stderr, "closing fd %d\n", br->fd);
        close (br->fd);
        continue;
      }
      else if (sfd == br->fd)
      {
        /* New connection(s) */
        while (1)
        {
          
          in_len = sizeof (in_addr);
          infd = accept (sfd, &in_addr, &in_len);
          if (infd == -1)
          {
            if ((errno == EAGAIN) ||
                (errno == EWOULDBLOCK))
            {
              break;
            }
            else
            {
              perror ("accept");
              break;
            }
          }

          s = getnameinfo (&in_addr, in_len,
                           hbuf, sizeof (hbuf),
                           sbuf, sizeof (sbuf),
                           NI_NUMERICHOST | NI_NUMERICSERV);
          if (s == -1)
            abort ();

          s = setnonblocking (infd);
          if (s == -1)
            abort ();

          event.events = EPOLLIN | EPOLLET;
          br = malloc (sizeof (struct socks5_bridge));
          br->fd = infd;
          br->addr = in_addr;
          br->addr_len = in_len;
          br->remote_end = NULL;
          br->status = SOCKS5_INIT;
          event.data.ptr = br;

          s = epoll_ctl (efd, EPOLL_CTL_ADD, infd, &event);
          if (s == -1)
          {
            perror ("epoll ctl");
            abort ();
          }
        }
        continue;
      }
      else
      {
        /* Incoming data */
        done = 0;

        while (1)
        {

          count = read (br->fd, buf, sizeof (buf));

          if (count == -1)
          {
            if (errno != EAGAIN)
            {
              perror ("read");
              done = 1;
            }
            break;
          }
          else if (count == 0)
          {
            done = 1;
            break;
          }
          
          if (br->status == SOCKS5_DATA_TRANSFER)
          {
            if (DEBUG)
            {
              printf ("Trying to fwd %d bytes from %d to %d!\n" ,
                    count, br->fd, br->remote_end->fd );
            }
            if (br->remote_end)
              s = write (br->remote_end->fd, buf, count);
            if (DEBUG)
               printf ("%d bytes written\n", s);
          }
          
          if (br->status == SOCKS5_INIT)
          {
            hello.version = 0x05;
            hello.auth_method = 0;
            write (br->fd, &hello, sizeof (hello));
            br->status = SOCKS5_REQUEST;
          }
          if (br->status == SOCKS5_REQUEST)
          {
            req = (struct socks5_client_request*)buf;
            
            memset(&resp, 0, sizeof(resp));
            
            if (req->addr_type == 3)
            {
              dom_len = *((uint8_t*)(&(req->addr_type) + 1));
              memset(domain, 0, sizeof(domain));
              strncpy(domain, (char*)(&(req->addr_type) + 2), dom_len);
              req_port = *((uint16_t*)(&(req->addr_type) + 2 + dom_len));

              phost = (struct hostent*)gethostbyname (domain);
              if (phost == NULL)
              {
                printf ("Resolve %s error!\n" , domain );
                resp.version = 0x05;
                resp.reply = 0x01;
                write (br->fd, &resp, sizeof (struct socks5_server_response));
                break;
              }

              if ( -1 != is_tld (domain, ".gnunet") )
              {
                if (NULL == mhd_daemon)
                {
                  mhd_daemon = MHD_start_daemon( MHD_USE_THREAD_PER_CONNECTION,
                                                 8080,
                                                 &access_cb, br,
                                                 &accept_cb, br,
                                                 MHD_OPTION_END);
                  
                }
                
                printf ("trying to add to MHD\n");
                if (MHD_YES != MHD_add_connection (mhd_daemon,
                                                   br->fd,
                                                   &br->addr,
                                                   br->addr_len))
                {
                  printf ("Error adding %d to mhd\n", br->fd);
                }
                
                event.events = EPOLLIN | EPOLLET;
                epoll_ctl (efd, EPOLL_CTL_DEL, br->fd, &event);
                resp.version = 0x05;
                resp.reply = 0x00;
                resp.reserved = 0x00;
                resp.addr_type = 0x01;
                write (br->fd, &resp, 10);
                break;
              }

              conn_fd = connect_to_domain (phost, req_port);
              
              if (-1 == conn_fd)
              {
                  resp.version = 0x05;
                  resp.reply = 0x01;
                  write (br->fd, &resp, 10);
              }
              else
              {
                if (DEBUG)
                  printf("new remote connection %d to %d\n", br->fd, conn_fd);
                resp.version = 0x05;
                resp.reply = 0x00;
                resp.reserved = 0x00;
                resp.addr_type = 0x01;
                
                new_br = malloc (sizeof (struct socks5_bridge));
                br->remote_end = new_br;
                br->status = SOCKS5_DATA_TRANSFER;
                new_br->fd = conn_fd;
                new_br->remote_end = br;
                new_br->status = SOCKS5_DATA_TRANSFER;

                event.data.ptr = new_br;
                event.events = EPOLLIN | EPOLLET;
                epoll_ctl (efd, EPOLL_CTL_ADD, conn_fd, &event);
                write (br->fd, &resp, 10);
              }

            }
            else
            {
              printf("not implemented address type %02X\n", (int)req->addr_type);
            }
          }
          

          if (s == -1)
          {
            perror ("write");
            abort ();
          }
        }

        if (done)
        {
          close (br->fd);

          if (br->remote_end)
          {
            close (br->remote_end->fd);
            free(br->remote_end);
          }
          free(br);
        }
      }
    }
  }

  free (events);

  close (sfd);

  return EXIT_SUCCESS;
}

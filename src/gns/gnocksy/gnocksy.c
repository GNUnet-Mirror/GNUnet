/*
 * The GNS Socks5 Proxy
 */

#include <stdio.h>
/**
 *
 * Note: Only supports addr type 3 (domain) for now.
 * Chrome uses it automatically
 * For FF: about:config -> network.proxy.socks_remote_dns true
 */

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
#include <curl/curl.h>
#include <regex.h>

#include "protocol.h"

#define MAXEVENTS 64

#define DEBUG 1

#define HTML_HDR_CONTENT "Content-Type: text/html\r\n"

#define RE_DOTPLUS "<a href=\"http://(([A-Za-z]+[.])+)([+])"

#define RE_N_MATCHES 4

static struct MHD_Daemon *mhd_daemon;
static regex_t re_dotplus;

void
gns_glue_expand_and_shorten ( char* sorig, char* new )
{
  memcpy (new, "foo.bar.gnunet", strlen("foo.bar.gnunet"));
}

static size_t
curl_write_data (void *buffer, size_t size, size_t nmemb, void* cls)
{
  const char* page = buffer;
  uint64_t bytes = size * nmemb;
  struct socks5_bridge* br = cls;
  int ret;

  int nomatch;
  regmatch_t m[RE_N_MATCHES];
  char* hostptr;
  char* plusptr;
  char* p;
  char new_host[256];
  uint64_t bytes_copied = 0;

  char new_buf[CURL_MAX_WRITE_SIZE+1];
  p = new_buf;

  pthread_mutex_lock ( &br->m_buf );
  if (br->MHD_CURL_BUF_STATUS == BUF_WAIT_FOR_MHD)
  {
    pthread_mutex_unlock ( &br->m_buf );
    printf( "waiting for mhd to process data... pausing curl\n");
    return CURL_WRITEFUNC_PAUSE;
  }

  /* do regex magic */
  if ( br->res_is_html )
  {
    printf ("result is html text\n");
    memset (new_buf, 0, sizeof(new_buf));
    memcpy (new_buf, page, bytes);

 
    while (1)
    {
      nomatch = regexec ( &re_dotplus, p, RE_N_MATCHES, m, 0);

      if (nomatch)
      {
        printf ("No more matches\n");
        if ((p-new_buf) < 0)
        {
          printf ("Error p<buf!\n");
          break;
        }
        memcpy ( br->MHD_CURL_BUF+bytes_copied, p, bytes-(p-new_buf));
        bytes_copied += bytes-(p-new_buf);
        break;
      }

      if (DEBUG)
        printf ("Got match\n");

      if (m[1].rm_so != -1)
      {
        hostptr = p+m[1].rm_eo;
        if (DEBUG)
          printf ("Copying %d bytes.\n", (hostptr-p));
        memcpy (br->MHD_CURL_BUF+bytes_copied, p, (hostptr-p));
        bytes_copied += (hostptr-p);
        memset (new_host, 0, sizeof(new_host));
        gns_glue_expand_and_shorten ( br->full_url,
                                      new_host );
        if (DEBUG)
        {
          printf ("Glue fin\n");
          printf ("Copying new name %s \n", new_host);
        }
        memcpy ( br->MHD_CURL_BUF+bytes_copied, new_host,
                 strlen (new_host) );
        bytes_copied += strlen (new_host);
        p += m[3].rm_so+1;

        printf ("Done. Next in %d bytes\n", m[3].rm_so);

        //TODO check buf lenghts!
      }
    }
    br->MHD_CURL_BUF_SIZE = bytes_copied;
  }
  else
  {
    memcpy (br->MHD_CURL_BUF, buffer, bytes);
    br->MHD_CURL_BUF_SIZE = bytes;
  }

  br->MHD_CURL_BUF_STATUS = BUF_WAIT_FOR_MHD;

  pthread_mutex_unlock ( &br->m_buf );


  //MHD_destroy_response (response);
  printf( "buffer: %s\n", (char*)br->MHD_CURL_BUF );
  return bytes;
}

static size_t
curl_check_hdr (void *buffer, size_t size, size_t nmemb, void* cls)
{
  size_t bytes = size * nmemb;
  struct socks5_bridge* br = cls;
  char hdr[bytes+1];

  memcpy(hdr, buffer, bytes);
  hdr[bytes] = '\0';

  printf ("got hdr: %s\n", hdr);

  if (0 == strcmp(hdr, HTML_HDR_CONTENT))
    br->res_is_html = 1;

  return bytes;
}


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

static int
access_cb (void* cls,
           const struct sockaddr *addr,
           socklen_t addrlen)
{
  printf ("access cb called\n");
  return MHD_YES;
}

static void
fetch_url (struct socks5_bridge* br)
{

  CURLcode ret;

  br->curl = curl_easy_init();

  /* TODO optionally do LEHO stuff here */

  if (br->curl)
    {
      curl_easy_setopt (br->curl, CURLOPT_URL, br->full_url);
      curl_easy_setopt (br->curl, CURLOPT_HEADERFUNCTION, &curl_check_hdr);
      curl_easy_setopt (br->curl, CURLOPT_HEADERDATA, br);
      curl_easy_setopt (br->curl, CURLOPT_WRITEFUNCTION, &curl_write_data);
      curl_easy_setopt (br->curl, CURLOPT_WRITEDATA, br);
      ret = curl_easy_perform (br->curl);
      free (br->full_url);
      pthread_mutex_lock ( &br->m_done );
      br->is_done = 1;
      pthread_mutex_unlock ( &br->m_done );

      curl_easy_cleanup (br->curl);
      
      if (ret == CURLE_OK)
      {
        printf("all good on the curl end\n");
        return;
      }
      printf("error on the curl end %s\n", curl_easy_strerror(ret));
    }
}

static ssize_t
mhd_content_cb (void* cls,
                uint64_t pos,
                char* buf,
                size_t max)
{
  struct socks5_bridge* br = cls;

  pthread_mutex_lock ( &br->m_done );
  /* if done and buf empty */
  if ( (br->is_done == 1)  &&
       (br->MHD_CURL_BUF_STATUS == BUF_WAIT_FOR_CURL) )
  {
    printf("done. sending response...\n");
    br->is_done = 0;
    pthread_mutex_unlock ( &br->m_done );
    return MHD_CONTENT_READER_END_OF_STREAM;
  }
  pthread_mutex_unlock ( &br->m_done );

  pthread_mutex_lock ( &br->m_buf );
  if ( br->MHD_CURL_BUF_STATUS == BUF_WAIT_FOR_CURL )
  {
    printf("waiting for curl...\n");
    pthread_mutex_unlock ( &br->m_buf );
    return 0;
  }

  if ( br->MHD_CURL_BUF_SIZE > max )
  {
    printf("buffer in mhd response too small!\n");
    pthread_mutex_unlock ( &br->m_buf );
    return MHD_CONTENT_READER_END_WITH_ERROR;
  }
  
  if (0 != br->MHD_CURL_BUF_SIZE)
  {
    printf("copying %d bytes to mhd response at offset %d\n",
           br->MHD_CURL_BUF_SIZE, pos);
    memcpy ( buf, br->MHD_CURL_BUF, br->MHD_CURL_BUF_SIZE );
  }
  br->MHD_CURL_BUF_STATUS = BUF_WAIT_FOR_CURL;
  pthread_mutex_unlock ( &br->m_buf );

  return br->MHD_CURL_BUF_SIZE;
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
  struct socks5_bridge *br = cls;
  int ret;
  char* full_url;

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
  
  if (-1 == asprintf (&br->full_url, "%s%s", br->host, url))
  {
    printf ("error building url!\n");
    return MHD_NO;
  }
  printf ("url %s\n", br->full_url);

  pthread_mutex_lock ( &br->m_done );
  br->is_done = 0;
  pthread_mutex_unlock ( &br->m_done );
  
  br->MHD_CURL_BUF_STATUS = BUF_WAIT_FOR_CURL;
  br->res_is_html = 0;

  response = MHD_create_response_from_callback (-1, -1, 
                                                &mhd_content_cb,
                                                br,
                                                NULL); //TODO destroy resp here
  
  ret = MHD_queue_response (con, MHD_HTTP_OK, response);
  pthread_create ( &br->thread, NULL, &fetch_url, br );

  return MHD_YES;
  
  
}

static int
compile_regex (regex_t *re, const char* rt)
{
  int status;
  char err[1024];
  
  status = regcomp (re, rt, REG_EXTENDED|REG_NEWLINE);
  if (status)
  {
    regerror (status, re, err, 1024);
    printf ("Regex error compiling '%s': %s\n", rt, err);
    return 1;
  }
  return 0;
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
  uint8_t dom_len;
  uint16_t req_port;
  int conn_fd;
  struct hostent *phost;

  mhd_daemon = NULL;
  curl_global_init(CURL_GLOBAL_ALL);

  //compile_regex ( &re_htmlhdr, RE_HTML );
  compile_regex( &re_dotplus, (char*)RE_DOTPLUS );
  
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
                strcpy (br->host, domain);
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
  MHD_stop_daemon (mhd_daemon);
  regfree ( &re_dotplus );
  close (sfd);

  return EXIT_SUCCESS;
}

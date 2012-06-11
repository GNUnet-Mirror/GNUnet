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
#include <gnunet_gns_service.h>
#include <microhttpd.h>
#include <curl/curl.h>
#include <regex.h>
#include "gns_proxy_proto.h"
#include "gns.h"

/** SSL **/
#include <gnutls/gnutls.h>
#include <gnutls/x509.h>
#include <gnutls/abstract.h>
#include <gnutls/crypto.h>
#include <time.h>

#define GNUNET_GNS_PROXY_PORT 7777

/* MHD/cURL defines */
#define BUF_WAIT_FOR_CURL 0
#define BUF_WAIT_FOR_MHD 1
#define HTML_HDR_CONTENT "Content-Type: text/html\r\n"

/* regexp */
//#define RE_DOTPLUS "<a href=\"http://(([A-Za-z]+[.])+)([+])"
#define RE_A_HREF  "<a href=\"https?://(([A-Za-z0-9]+[.])+)([+]|zkey)"
#define RE_N_MATCHES 4

/* The usual suspects */
#define HTTP_PORT 80
#define HTTPS_PORT 443


/**
 * A structure for CA cert/key
 */
struct ProxyCA
{
  /* The certificate */
  gnutls_x509_crt_t cert;

  /* The private key */
  gnutls_x509_privkey_t key;
};


/**
 * Structure for GNS certificates
 */
struct ProxyGNSCertificate
{
  /* The certificate as PEM */
  char cert[10 * 1024];

  /* The private key as PEM */
  char key[10 * 1024];
};


/**
 * A structure for socks requests
 */
struct Socks5Request
{
  /* The client socket */
  struct GNUNET_NETWORK_Handle *sock;

  /* The server socket */
  struct GNUNET_NETWORK_Handle *remote_sock;
  
  /* The socks state */
  int state;
  
  /* Client socket read task */
  GNUNET_SCHEDULER_TaskIdentifier rtask;

  /* Server socket read task */
  GNUNET_SCHEDULER_TaskIdentifier fwdrtask;

  /* Client socket write task */
  GNUNET_SCHEDULER_TaskIdentifier wtask;

  /* Server socket write task */
  GNUNET_SCHEDULER_TaskIdentifier fwdwtask;

  /* Read buffer */
  char rbuf[2048];

  /* Write buffer */
  char wbuf[2048];

  /* Length of data in read buffer */
  unsigned int rbuf_len;

  /* Length of data in write buffer */
  unsigned int wbuf_len;

  /* This handle is scheduled for cleanup? */
  int cleanup;

  /* Shall we close the client socket on cleanup? */
  int cleanup_sock;
};


/**
 * A structure for all running Httpds
 */
struct MhdHttpList
{
  /* DLL for httpds */
  struct MhdHttpList *prev;

  /* DLL for httpds */
  struct MhdHttpList *next;

  /* is this an ssl daemon? */
  int is_ssl;

  /* the domain name to server (only important for SSL) */
  char domain[256];

  /* The daemon handle */
  struct MHD_Daemon *daemon;

  /* Optional proxy certificate used */
  struct ProxyGNSCertificate *proxy_cert;

  /* The task ID */
  GNUNET_SCHEDULER_TaskIdentifier httpd_task;
};

/**
 * A structure for MHD<->cURL streams
 */
struct ProxyCurlTask
{
  /* DLL for tasks */
  struct ProxyCurlTask *prev;

  /* DLL for tasks */
  struct ProxyCurlTask *next;

  /* Handle to cURL */
  CURL *curl;

  /* Optional header replacements for curl (LEHO) */
  struct curl_slist *headers;

  /* Optional resolver replacements for curl (LEHO) */
  struct curl_slist *resolver;

  /* The URL to fetch */
  char url[2048];

  /* The cURL write buffer / MHD read buffer */
  char buffer[CURL_MAX_WRITE_SIZE];

  /* The pointer to the data in the buffer */
  char *buffer_ptr;

  /* The buffer status (BUF_WAIT_FOR_CURL or BUF_WAIT_FOR_MHD) */
  int buf_status;

  /* Number of bytes in buffer */
  unsigned int bytes_in_buffer;

  /* Indicates wheather the download is in progress */
  int download_in_progress;

  /* Indicates wheather the download was successful */
  int download_successful;

  /* Indicates wheather the download failed */
  int download_error;

  /* Indicates wheather we need to parse HTML */
  int parse_content;

  /* Indicates wheather we are postprocessing the HTML right now */
  int is_postprocessing;

  /* Indicates wheather postprocessing has finished */
  int pp_finished;

  /* Task ID of the postprocessing task */
  GNUNET_SCHEDULER_TaskIdentifier pp_task;

  /* The postprocessing buffer TODO length? */
  char pp_buf[256];

  /* The authority of the corresponding host (site of origin) */
  char authority[256];

  /* The hostname (Host header field) */
  char host[256];

  /* The LEgacy HOstname (can be empty) */
  char leho[256];

  /* The associated daemon list entry */
  struct MhdHttpList *mhd;
  
};

/* The port the proxy is running on (default 7777) */
static unsigned long port = GNUNET_GNS_PROXY_PORT;

/* The CA file (pem) to use for the proxy CA */
static char* cafile;

/* The listen socket of the proxy */
static struct GNUNET_NETWORK_Handle *lsock;

/* The listen task ID */
GNUNET_SCHEDULER_TaskIdentifier ltask;

/* The cURL download task */
GNUNET_SCHEDULER_TaskIdentifier curl_download_task;

/* The non SSL httpd daemon handle */
static struct MHD_Daemon *httpd;

/* The cURL multi handle */
static CURLM *curl_multi;

/* Handle to the GNS service */
static struct GNUNET_GNS_Handle *gns_handle;

/* DLL for ProxyCurlTasks */
static struct ProxyCurlTask *ctasks_head;

/* DLL for ProxyCurlTasks */
static struct ProxyCurlTask *ctasks_tail;

/* DLL for http daemons */
static struct MhdHttpList *mhd_httpd_head;

/* DLL for http daemons */
static struct MhdHttpList *mhd_httpd_tail;

/* Handle to the regex for dotplus (.+) replacement in HTML */
static regex_t re_dotplus;

/* The users local GNS zone hash */
static struct GNUNET_CRYPTO_ShortHashCode local_gns_zone;

/* The CA for SSL certificate generation */
static struct ProxyCA proxy_ca;

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


/**
 * Read HTTP request header field 'Host'
 *
 * @param cls buffer to write to
 * @param kind value kind
 * @param key field key
 * @param value field value
 * @return MHD_NO when Host found
 */
static int
con_val_iter (void *cls,
              enum MHD_ValueKind kind,
              const char *key,
              const char *value)
{
  char* buf = (char*)cls;

  if (0 == strcmp ("Host", key))
  {
    strcpy (buf, value);
    return MHD_NO;
  }
  return MHD_YES;
}


/**
 * Check HTTP response header for mime
 *
 * @param buffer curl buffer
 * @param size curl blocksize
 * @param nmemb curl blocknumber
 * @param cls handle
 * @return size of read bytes
 */
static size_t
curl_check_hdr (void *buffer, size_t size, size_t nmemb, void *cls)
{
  size_t bytes = size * nmemb;
  struct ProxyCurlTask *ctask = cls;
  char hdr[bytes+1];

  memcpy (hdr, buffer, bytes);
  hdr[bytes] = '\0';

  if (0 == strcmp (hdr, HTML_HDR_CONTENT))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Got HTML HTTP response header\n");
    ctask->parse_content = GNUNET_YES;
  }

  return bytes;
}

/**
 * schedule mhd
 *
 * @param hd a http daemon list entry
 */
static void
run_httpd (struct MhdHttpList *hd);


/**
 * schedule all mhds
 *
 */
static void
run_httpds (void);


/**
 * Task that simply runs MHD main loop
 *
 * @param cls NULL
 * @param tc task context
 */
static void
run_mhd (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{

  struct MhdHttpList *hd = cls;

  //for (hd=mhd_httpd_head; hd != NULL; hd = hd->next)
    MHD_run (hd->daemon);
}


/**
 * Process cURL download bits
 *
 * @param ptr buffer with data
 * @param size size of a record
 * @param nmemb number of records downloaded
 * @param ctx context
 * @return number of processed bytes
 */
static size_t
callback_download (void *ptr, size_t size, size_t nmemb, void *ctx)
{
  const char *cbuf = ptr;
  size_t total;
  struct ProxyCurlTask *ctask = ctx;

  //MHD_run (httpd);

  total = size*nmemb;

  if (total == 0)
  {
    return total;
  }

  if (total > sizeof (ctask->buffer))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "CURL gave us too much data to handle (%d)!\n",
                total);
    return 0;
  }
  
  if (ctask->buf_status == BUF_WAIT_FOR_MHD)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "CURL: Waiting for MHD (%s)\n", ctask->url);
    return CURL_WRITEFUNC_PAUSE;
  }


  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "CURL: Copying to MHD (%s, %d)\n", ctask->url, total);
  memcpy (ctask->buffer, cbuf, total);
  ctask->bytes_in_buffer = total;
  ctask->buffer_ptr = ctask->buffer;

  ctask->buf_status = BUF_WAIT_FOR_MHD;

  //GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
  //            "cURL chunk:\n%s\n", (char*)ctask->buffer);
  //run_mhd (NULL, NULL);
  GNUNET_SCHEDULER_add_now (&run_mhd, ctask->mhd);
  return total;
}



/**
 * Callback to free content
 *
 * @param cls content to free
 */
static void
mhd_content_free (void *cls)
{
  struct ProxyCurlTask *ctask = cls;

  if (NULL != ctask->headers)
    curl_slist_free_all (ctask->headers);

  if (NULL != ctask->curl)
    curl_easy_cleanup (ctask->curl);

  ctask->curl = NULL;

  GNUNET_free (ctask);

}


/**
 * Shorten result callback
 *
 * @param cls the proxycurltask
 * @param short_name the shortened name (NULL on error)
 */
static void
process_shorten (void* cls, const char* short_name)
{
  struct ProxyCurlTask *ctask = cls;

  char tmp[strlen(ctask->pp_buf)]; //TODO length

  if (NULL == short_name)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "MHD PP: Unable to shorten %s\n",
                ctask->pp_buf);
    return;
  }

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "MHD PP: Shorten %s -> %s\n",
              ctask->pp_buf,
              short_name);

  sprintf (tmp, "<a href=\"http://%s", short_name);
  strcpy (ctask->pp_buf, tmp);

  ctask->pp_finished = GNUNET_YES;

  GNUNET_SCHEDULER_add_now (&run_mhd, ctask->mhd);
}


/**
 * Postprocessing task that uses GNS to shorten names
 *
 * @param cls the proxycurltask
 * @param tc the task context
 *
static void
postprocess_name (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct ProxyCurlTask *ctask = cls;
  char tmp[strlen(ctask->pp_buf)];

  sprintf ( tmp, "%s%s", ctask->pp_buf, ctask->authority);

  GNUNET_GNS_shorten (gns_handle,
                      tmp,
                      &process_shorten,
                      ctask);

}
*/

/**
 * Callback for MHD response
 *
 * @param cls closure
 * @param pos in buffer
 * @param buf buffer
 * @param max space in buffer
 */
static ssize_t
mhd_content_cb (void *cls,
                uint64_t pos,
                char* buf,
                size_t max)
{
  struct ProxyCurlTask *ctask = cls;
  ssize_t copied = 0;
  size_t bytes_to_copy;
  int nomatch;
  char *hostptr;
  regmatch_t m[RE_N_MATCHES];

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "MHD: content cb\n");

  if (ctask->download_successful &&
      (ctask->buf_status == BUF_WAIT_FOR_CURL))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "MHD: sending response for %s\n", ctask->url);
    ctask->download_in_progress = GNUNET_NO;
    curl_multi_remove_handle (curl_multi, ctask->curl);
    curl_easy_cleanup (ctask->curl);
    GNUNET_SCHEDULER_add_now (&run_mhd, ctask->mhd);
    return MHD_CONTENT_READER_END_OF_STREAM;
  }
  
  if (ctask->download_error &&
      (ctask->buf_status == BUF_WAIT_FOR_CURL))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "MHD: sending error response\n");
    ctask->download_in_progress = GNUNET_NO;
    curl_multi_remove_handle (curl_multi, ctask->curl);
    curl_easy_cleanup (ctask->curl);
    GNUNET_SCHEDULER_add_now (&run_mhd, ctask->mhd);
    return MHD_CONTENT_READER_END_WITH_ERROR;
  }

  if ( ctask->buf_status == BUF_WAIT_FOR_CURL )
    return 0;

  bytes_to_copy = ctask->bytes_in_buffer;
  
  if (ctask->parse_content == GNUNET_YES)
  {

    GNUNET_log ( GNUNET_ERROR_TYPE_DEBUG,
                 "MHD: We need to parse the HTML %s\n", ctask->buffer_ptr);

    nomatch = regexec ( &re_dotplus, ctask->buffer_ptr, RE_N_MATCHES, m, 0);

    if (nomatch)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "MHD RE: No match\n");
    }
    else
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "MHD RE: Match\n");

      GNUNET_assert (m[1].rm_so != -1);

      hostptr = ctask->buffer_ptr+m[1].rm_so;

      if (m[0].rm_so > 0)
      {
        bytes_to_copy = m[0].rm_so;
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                    "Copying %d bytes.\n", m[0].rm_so);


      }
      else
      {
        if (ctask->is_postprocessing == GNUNET_YES)
        {
          
          /*Done?*/
          if ( ctask->pp_finished == GNUNET_NO )
          {
            GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                        "MHD PP: Waiting for PP of %s\n", ctask->pp_buf);
            return 0;
          }
          
          ctask->is_postprocessing = GNUNET_NO;

          ctask->bytes_in_buffer -= m[0].rm_eo;//(m[1].rm_eo-m[1].rm_so);
          ctask->buffer_ptr += m[0].rm_eo;//(m[1].rm_eo-m[1].rm_so);
          GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                      "Skipping next %d bytes in buffer\n", m[0].rm_eo);

          GNUNET_SCHEDULER_add_now (&run_mhd, ctask->mhd);

          if ( strlen (ctask->pp_buf) <= max )
          {
            GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                        "Copying postprocessed %s.\n", ctask->pp_buf);
            memcpy ( buf, ctask->pp_buf, strlen (ctask->pp_buf) );
            GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                        "Done %s.\n", buf);
            ctask->is_postprocessing = GNUNET_NO;
            return strlen (ctask->pp_buf);
          }
          
          return 0;
        }

        memset (ctask->pp_buf, 0, sizeof(ctask->pp_buf));
        
        /* If .+ extend with authority */
        if (*(ctask->buffer_ptr+m[1].rm_eo) == '+')
        {
          GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                      "Links is .+\n");
           memcpy (ctask->pp_buf, hostptr, (m[1].rm_eo-m[1].rm_so));
           strcpy ( ctask->pp_buf+strlen(ctask->pp_buf),
                    ctask->authority);
        }
        /* If .zkey simply copy the name */
        else
        {
          GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                      "Link is zkey\n");
          memcpy (ctask->pp_buf, hostptr, (m[1].rm_eo-m[1].rm_so + strlen (GNUNET_GNS_TLD_ZKEY)));
        }

        ctask->is_postprocessing = GNUNET_YES;
        ctask->pp_finished = GNUNET_NO;
        
        GNUNET_GNS_shorten (gns_handle,
                           ctask->pp_buf,
                           &process_shorten,
                           ctask);

        //postprocess_name(ctask, NULL);
        //ctask->pp_task = GNUNET_SCHEDULER_add_now (&postprocess_name, ctask);

        return 0;
      }
    }
  }

  if ( bytes_to_copy > max )
  {
    GNUNET_log ( GNUNET_ERROR_TYPE_DEBUG,
                 "MHD: buffer in response too small! (%s)\n",
                 ctask->url);
    memcpy ( buf, ctask->buffer_ptr, max);
    ctask->bytes_in_buffer -= max;
    ctask->buffer_ptr += max;
    copied = max;
  }
  else
  {
    GNUNET_log ( GNUNET_ERROR_TYPE_DEBUG,
                 "MHD: copying %d bytes to mhd response at offset %d\n",
                 bytes_to_copy, pos);

    memcpy ( buf, ctask->buffer_ptr, bytes_to_copy );
    copied = bytes_to_copy;
    if (bytes_to_copy < ctask->bytes_in_buffer)
    {
      ctask->bytes_in_buffer -= bytes_to_copy;
      ctask->buffer_ptr += bytes_to_copy;
    }
    else
    {
      ctask->bytes_in_buffer = 0;
      ctask->buf_status = BUF_WAIT_FOR_CURL;
      ctask->buffer_ptr = ctask->buffer;
      curl_easy_pause (ctask->curl, CURLPAUSE_CONT);
      GNUNET_SCHEDULER_add_now (&run_mhd, ctask->mhd);
    }
  }

  GNUNET_SCHEDULER_add_now (&run_mhd, ctask->mhd);

  return copied;
}



/**
 * Task that is run when we are ready to receive more data
 * from curl
 *
 * @param cls closure
 * @param tc task context
 */
static void
curl_task_download (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc);

/**
 * Ask cURL for the select sets and schedule download
 */
static void
curl_download_prepare ()
{
  CURLMcode mret;
  fd_set rs;
  fd_set ws;
  fd_set es;
  int max;
  struct GNUNET_NETWORK_FDSet *grs;
  struct GNUNET_NETWORK_FDSet *gws;
  long to;
  struct GNUNET_TIME_Relative rtime;

  max = -1;
  FD_ZERO (&rs);
  FD_ZERO (&ws);
  FD_ZERO (&es);
  mret = curl_multi_fdset (curl_multi, &rs, &ws, &es, &max);

  if (mret != CURLM_OK)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "%s failed at %s:%d: `%s'\n",
                "curl_multi_fdset", __FILE__, __LINE__,
                curl_multi_strerror (mret));
    //TODO cleanup here?
    return;
  }

  mret = curl_multi_timeout (curl_multi, &to);
  rtime = GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MILLISECONDS, to);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "cURL multi fds: max=%d timeout=%llu\n", max, to);

  grs = GNUNET_NETWORK_fdset_create ();
  gws = GNUNET_NETWORK_fdset_create ();
  GNUNET_NETWORK_fdset_copy_native (grs, &rs, max + 1);
  GNUNET_NETWORK_fdset_copy_native (gws, &ws, max + 1);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Scheduling task cURL\n");

  if (curl_download_task != GNUNET_SCHEDULER_NO_TASK)
    GNUNET_SCHEDULER_cancel (curl_download_task);
  
  curl_download_task =
    GNUNET_SCHEDULER_add_select (GNUNET_SCHEDULER_PRIORITY_DEFAULT,
                                 rtime,
                                 grs, gws,
                                 &curl_task_download, curl_multi);
  GNUNET_NETWORK_fdset_destroy (gws);
  GNUNET_NETWORK_fdset_destroy (grs);

}


/**
 * Task that is run when we are ready to receive more data
 * from curl
 *
 * @param cls closure
 * @param tc task context
 */
static void
curl_task_download (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  int running;
  int msgnum;
  struct CURLMsg *msg;
  CURLMcode mret;
  struct ProxyCurlTask *ctask;
  int num_ctasks;

  curl_download_task = GNUNET_SCHEDULER_NO_TASK;

  if (0 != (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Shutdown requested while trying to download\n");
    //TODO cleanup
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Ready to dl\n");

  do
  {
    running = 0;
    num_ctasks = 0;
    
    mret = curl_multi_perform (curl_multi, &running);

    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Running curl tasks: %d\n", running);

    ctask = ctasks_head;
    for (; ctask != NULL; ctask = ctask->next)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "CTask: %s\n", ctask->url);
      num_ctasks++;
    }

    if (num_ctasks != running)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "%d ctasks, %d curl running\n", num_ctasks, running);
    }
    
    do
    {
      ctask = ctasks_head;
      msg = curl_multi_info_read (curl_multi, &msgnum);
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Messages left: %d\n", msgnum);
      
      if (msg == NULL)
        break;
      switch (msg->msg)
      {
       case CURLMSG_DONE:
         if ((msg->data.result != CURLE_OK) &&
             (msg->data.result != CURLE_GOT_NOTHING))
         {
           GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                       "Download curl failed");
            
           for (; ctask != NULL; ctask = ctask->next)
           {
             if (memcmp (msg->easy_handle, ctask->curl, sizeof (CURL)) != 0)
               continue;
             
             GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                         "Download curl failed for task %s: %s.\n",
                         ctask->url,
                         curl_easy_strerror (msg->data.result));
             ctask->download_successful = GNUNET_NO;
             ctask->download_error = GNUNET_YES;
             //curl_multi_remove_handle (curl_multi, ctask->curl);
             //curl_easy_cleanup (ctask->curl);
             GNUNET_CONTAINER_DLL_remove (ctasks_head, ctasks_tail,
                                          ctask);
             break;
           }
           GNUNET_assert (ctask != NULL);
         }
         else
         {
           GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                       "cURL download completed.\n");

           for (; ctask != NULL; ctask = ctask->next)
           {
             if (memcmp (msg->easy_handle, ctask->curl, sizeof (CURL)) != 0)
               continue;
             
             GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                         "cURL task %s found.\n", ctask->url);
             ctask->download_successful = GNUNET_YES;
             //curl_multi_remove_handle (curl_multi, ctask->curl);
             //curl_easy_cleanup (ctask->curl);
             GNUNET_CONTAINER_DLL_remove (ctasks_head, ctasks_tail,
                                          ctask);
             break;
           }
           GNUNET_assert (ctask != NULL);
         }
         GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                     "curl end %s\n", curl_easy_strerror(msg->data.result));
         break;
       default:
         GNUNET_assert (0);
         break;
      }
    } while (msgnum > 0);
    
    num_ctasks=0;
    for (ctask=ctasks_head; ctask != NULL; ctask = ctask->next)
    {
      num_ctasks++;
    }
    
    if (num_ctasks != running)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "%d ctasks, %d curl running\n", num_ctasks, running);
    }

    GNUNET_assert ( num_ctasks == running );

    run_httpds ();

  } while (mret == CURLM_CALL_MULTI_PERFORM);
  
  
  if (mret != CURLM_OK)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "%s failed at %s:%d: `%s'\n",
                "curl_multi_perform", __FILE__, __LINE__,
                curl_multi_strerror (mret));
  }
  curl_download_prepare();
}

/**
 * Process LEHO lookup
 *
 * @param cls the ctask
 * @param rd_count number of records returned
 * @param rd record data
 */
static void
process_leho_lookup (void *cls,
                     uint32_t rd_count,
                     const struct GNUNET_NAMESTORE_RecordData *rd)
{
  struct ProxyCurlTask *ctask = cls;
  char hosthdr[262]; //256 + "Host: "
  int i;
  CURLcode ret;
  CURLMcode mret;
  struct hostent *phost;
  char *ssl_ip;
  char resolvename[512];
  char curlurl[512];

  ctask->headers = NULL;

  strcpy (ctask->leho, "");

  if (rd_count == 0)
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "No LEHO present!\n");

  for (i=0; i<rd_count; i++)
  {
    if (rd[i].record_type != GNUNET_GNS_RECORD_LEHO)
      continue;

    memcpy (ctask->leho, rd[i].data, rd[i].data_size);

    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Found LEHO %s for %s\n", ctask->leho, ctask->url);
  }

  if (0 != strcmp (ctask->leho, ""))
  {
    sprintf (hosthdr, "%s%s", "Host: ", ctask->leho);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "New HTTP header value: %s\n", hosthdr);
    ctask->headers = curl_slist_append (ctask->headers, hosthdr);
    GNUNET_assert (NULL != ctask->headers);
    ret = curl_easy_setopt (ctask->curl, CURLOPT_HTTPHEADER, ctask->headers);
    if (CURLE_OK != ret)
    {
      GNUNET_log(GNUNET_ERROR_TYPE_WARNING, "%s failed at %s:%d: `%s'\n",
                           "curl_easy_setopt", __FILE__, __LINE__, curl_easy_strerror(ret));
    }

  }

  if (ctask->mhd->is_ssl)
  {
    phost = (struct hostent*)gethostbyname (ctask->host);
    ssl_ip = inet_ntoa(*((struct in_addr*)(phost->h_addr)));
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "SSL target server: %s\n", ssl_ip);
    sprintf (resolvename, "%s:%d:%s", ctask->leho, HTTPS_PORT, ssl_ip);
    ctask->resolver = curl_slist_append ( ctask->resolver, resolvename);
    curl_easy_setopt (ctask->curl, CURLOPT_RESOLVE, ctask->resolver);
    sprintf (curlurl, "https://%s%s", ctask->leho, ctask->url);
    curl_easy_setopt (ctask->curl, CURLOPT_URL, curlurl);
  }

  if (CURLM_OK != (mret=curl_multi_add_handle (curl_multi, ctask->curl)))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "%s failed at %s:%d: `%s'\n",
                "curl_multi_add_handle", __FILE__, __LINE__,
                curl_multi_strerror (mret));
    ctask->download_successful = GNUNET_NO;
    ctask->download_error = GNUNET_YES;
    return;
  }
  GNUNET_CONTAINER_DLL_insert (ctasks_head, ctasks_tail, ctask);

  curl_download_prepare ();

}

/**
 * Initialize download and trigger curl
 *
 * @param cls the proxycurltask
 * @param auth_name the name of the authority (site of origin) of ctask->host
 *
 */
static void
process_get_authority (void *cls,
                       const char* auth_name)
{
  struct ProxyCurlTask *ctask = cls;

  if (NULL == auth_name)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Get authority failed!\n");
    strcpy (ctask->authority, "");
  }

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Get authority yielded %s\n", auth_name);
  strcpy (ctask->authority, auth_name);

  GNUNET_GNS_lookup_zone (gns_handle,
                          ctask->host,
                          &local_gns_zone,
                          GNUNET_GNS_RECORD_LEHO,
                          &process_leho_lookup,
                          ctask);
}

/**
 * Main MHD callback for handling requests.
 *
 * @param cls unused
 * @param con MHD connection handle
 * @param meth the HTTP method used ("GET", "PUT", etc.)
 * @param ver the HTTP version string (i.e. "HTTP/1.1")
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
 * @param con_cls pointer to location where we store the 'struct Request'
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
  struct MhdHttpList* hd = cls;
  const char* page = "<html><head><title>gnoxy</title>"\
                      "</head><body>cURL fail</body></html>";
  struct MHD_Response *response;
  char host[265];
  char curlurl[512];
  int ret = MHD_YES;

  struct ProxyCurlTask *ctask;
  
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

  
  /* Do cURL */
  ctask = GNUNET_malloc (sizeof (struct ProxyCurlTask));
  ctask->mhd = hd;
  ctask->curl = curl_easy_init();

  if (curl_multi == NULL)
    curl_multi = curl_multi_init ();
  
  if ((ctask->curl == NULL) || (curl_multi == NULL))
  {
    response = MHD_create_response_from_buffer (strlen (page),
                                              (void*)page,
                                              MHD_RESPMEM_PERSISTENT);
    ret = MHD_queue_response (con,
                              MHD_HTTP_OK,
                              response);
    MHD_destroy_response (response);
    GNUNET_free (ctask);
    return ret;
  }

  ctask->download_in_progress = GNUNET_YES;
  ctask->download_successful = GNUNET_NO;
  ctask->buf_status = BUF_WAIT_FOR_CURL;
  ctask->bytes_in_buffer = 0;
  ctask->parse_content = GNUNET_NO;

  curl_easy_setopt (ctask->curl, CURLOPT_HEADERFUNCTION, &curl_check_hdr);
  curl_easy_setopt (ctask->curl, CURLOPT_HEADERDATA, ctask);
  curl_easy_setopt (ctask->curl, CURLOPT_WRITEFUNCTION, &callback_download);
  curl_easy_setopt (ctask->curl, CURLOPT_WRITEDATA, ctask);
  curl_easy_setopt (ctask->curl, CURLOPT_FOLLOWLOCATION, 1);
  curl_easy_setopt (ctask->curl, CURLOPT_MAXREDIRS, 4);
  /* no need to abort if the above failed */
  if (GNUNET_NO == ctask->mhd->is_ssl)
    sprintf (curlurl, "http://%s%s", host, url);
  strcpy (ctask->host, host);
  strcpy (ctask->url, url);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Adding new curl task for %s\n", curlurl);
  
  curl_easy_setopt (ctask->curl, CURLOPT_URL, curlurl);
  curl_easy_setopt (ctask->curl, CURLOPT_FAILONERROR, 1);
  curl_easy_setopt (ctask->curl, CURLOPT_CONNECTTIMEOUT, 600L);
  curl_easy_setopt (ctask->curl, CURLOPT_TIMEOUT, 600L);

  GNUNET_GNS_get_authority (gns_handle,
                            ctask->host,
                            &process_get_authority,
                            ctask);
  //download_prepare (ctask);
  //curl_download_prepare ();

  response = MHD_create_response_from_callback (-1, -1,
                                                &mhd_content_cb,
                                                ctask,
                                                &mhd_content_free);
  
  ret = MHD_queue_response (con, MHD_HTTP_OK, response);
  
  //MHD_destroy_response (response);

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
 * run all httpd
 */
static void
run_httpds ()
{
  struct MhdHttpList *hd;

  for (hd=mhd_httpd_head; hd != NULL; hd = hd->next)
    run_httpd (hd);

}

/**
 * schedule mhd
 */
static void
run_httpd (struct MhdHttpList *hd)
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
  GNUNET_assert (MHD_YES == MHD_get_fdset (hd->daemon, &rs, &ws, &es, &max));
  
  
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "MHD fds: max=%d\n", max);
  
  haveto = MHD_get_timeout (hd->daemon, &timeout);

  if (haveto == MHD_YES)
    tv.rel_value = (uint64_t) timeout;
  else
    tv = GNUNET_TIME_UNIT_FOREVER_REL;
  GNUNET_NETWORK_fdset_copy_native (wrs, &rs, max + 1);
  GNUNET_NETWORK_fdset_copy_native (wws, &ws, max + 1);
  GNUNET_NETWORK_fdset_copy_native (wes, &es, max + 1);
  
  if (hd->httpd_task != GNUNET_SCHEDULER_NO_TASK)
    GNUNET_SCHEDULER_cancel (hd->httpd_task);
  hd->httpd_task =
    GNUNET_SCHEDULER_add_select (GNUNET_SCHEDULER_PRIORITY_HIGH,
                                 tv, wrs, wws,
                                 &do_httpd, hd);
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
  struct MhdHttpList *hd = cls;
  
  hd->httpd_task = GNUNET_SCHEDULER_NO_TASK;
  
  MHD_run (hd->daemon);
  run_httpd (hd);
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
      ((len = GNUNET_NETWORK_socket_send (s5r->remote_sock, s5r->rbuf,
                                         s5r->rbuf_len)>0)))
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
 * Clean up s5r handles
 *
 * @param s5r the handle to destroy
 */
static void
cleanup_s5r (struct Socks5Request *s5r)
{
  if (s5r->rtask != GNUNET_SCHEDULER_NO_TASK)
    GNUNET_SCHEDULER_cancel (s5r->rtask);
  if (s5r->fwdwtask != GNUNET_SCHEDULER_NO_TASK)
    GNUNET_SCHEDULER_cancel (s5r->fwdwtask);
  if (s5r->fwdrtask != GNUNET_SCHEDULER_NO_TASK)
    GNUNET_SCHEDULER_cancel (s5r->fwdrtask);
  
  if (NULL != s5r->remote_sock)
    GNUNET_NETWORK_socket_close (s5r->remote_sock);
  if ((NULL != s5r->sock) && (s5r->cleanup_sock == GNUNET_YES))
    GNUNET_NETWORK_socket_close (s5r->sock);
  
  GNUNET_free(s5r);
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
      ((len = GNUNET_NETWORK_socket_send (s5r->sock, s5r->wbuf,
                                         s5r->wbuf_len)>0)))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Successfully sent %d bytes to socket\n",
                len);
  }
  else
  {
    
    GNUNET_log_strerror (GNUNET_ERROR_TYPE_WARNING, "write");
    s5r->cleanup = GNUNET_YES;
    s5r->cleanup_sock = GNUNET_YES;
    cleanup_s5r (s5r);
    
    return;
  }

  if (GNUNET_YES == s5r->cleanup)
  {
    cleanup_s5r (s5r);
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


/**
 * Adds a socket to MHD
 *
 * @param h the handle to the socket to add
 * @return whatever MHD_add_connection returns
 */
static int
add_handle_to_mhd (struct GNUNET_NETWORK_Handle *h, struct MHD_Daemon *daemon)
{
  int fd;
  struct sockaddr *addr;
  socklen_t len;

  fd = GNUNET_NETWORK_get_fd (h);
  addr = GNUNET_NETWORK_get_addr (h);
  len = GNUNET_NETWORK_get_addrlen (h);

  return MHD_add_connection (daemon, fd, addr, len);
}


/*TODO this needs MHD API modification */
static int http_port = 4444;


static long
get_file_size (const char* filename)
{
  FILE *fp;

  fp = fopen (filename, "rb");
  if (fp)
  {
    long size;

    if ((0 != fseek (fp, 0, SEEK_END)) || (-1 == (size = ftell (fp))))
      size = 0;

    fclose (fp);

    return size;
  }
  
  return 0;
}

/**
 * Read file in filename
 *
 * @param filename file to read
 * @return data
 */
static char*
load_file (const char* filename)
{
  FILE *fp;
  char *buffer;
  long size;

  size = get_file_size (filename);
  if (size == 0)
    return NULL;

  fp = fopen (filename, "rb");
  if (!fp)
    return NULL;

  buffer = GNUNET_malloc (size);
  if (!buffer)
  {
    fclose (fp);
    return NULL;
  }

  if (size != fread (buffer, 1, size, fp))
  {
    GNUNET_free (buffer);
    buffer = NULL;
  }

  fclose (fp);
  return buffer;
}

/** SSL stuff **/

/**
 * Load PEM key from file
 *
 * @param key where to store the data
 * @param keyfile path to the PEM file
 */
static void
load_key_from_file (gnutls_x509_privkey_t key, char* keyfile)
{
  gnutls_datum_t key_data;
  int ret;

  key_data.data = (unsigned char*)load_file (keyfile);
  key_data.size = strlen ((char*)key_data.data);

  ret = gnutls_x509_privkey_import (key, &key_data,
                                    GNUTLS_X509_FMT_PEM);
  
  if (GNUTLS_E_SUCCESS != ret)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Unable to import private key %s(ret=%d)\n", key_data.data, ret);
    GNUNET_break (0);
  }

  GNUNET_free (key_data.data);
}

/**
 * Load cert from file
 *
 * @param crt struct to store data in
 * @param certfile path to pem file
 */
static void
load_cert_from_file (gnutls_x509_crt_t crt, char* certfile)
{
  gnutls_datum_t cert_data;
  int ret;

  cert_data.data = (unsigned char*)load_file (certfile);
  cert_data.size = strlen ((char*)cert_data.data);

  ret = gnutls_x509_crt_import (crt, &cert_data,
                                 GNUTLS_X509_FMT_PEM);
  if (GNUTLS_E_SUCCESS != ret)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Unable to import certificate %s(ret=%d)\n", certfile, ret);
    GNUNET_break (0);
  }

  GNUNET_free (cert_data.data);

}


/**
 * Generate new certificate for specific name
 *
 * @param name the subject name to generate a cert for
 * @return a struct holding the PEM data
 */
static struct ProxyGNSCertificate *
generate_gns_certificate (const char *name)
{

  int ret;
  unsigned int serial;
  unsigned int bits;
  size_t key_buf_size;
  size_t cert_buf_size;
  gnutls_x509_crt_t request;
  gnutls_x509_privkey_t rsa;
  time_t etime;
  struct tm *tm_data;

  ret = gnutls_x509_crt_init (&request);

  if (GNUTLS_E_SUCCESS != ret)
  {
    GNUNET_break (0);
  }

  ret = gnutls_x509_crt_set_key (request, proxy_ca.key);

  if (GNUTLS_E_SUCCESS != ret)
  {
    GNUNET_break (0);
  }

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Generating cert\n");

  struct ProxyGNSCertificate *pgc =
    GNUNET_malloc (sizeof (struct ProxyGNSCertificate));

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Adding DNs\n");
  
  gnutls_x509_crt_set_dn_by_oid (request, GNUTLS_OID_X520_COUNTRY_NAME,
                                 0, "DE", 2);

  gnutls_x509_crt_set_dn_by_oid (request, GNUTLS_OID_X520_ORGANIZATION_NAME,
                                 0, "GNUnet", 6);

  gnutls_x509_crt_set_dn_by_oid (request, GNUTLS_OID_X520_COMMON_NAME,
                                 0, name, strlen (name));

  ret = gnutls_x509_crt_set_version (request, 3);

  ret = gnutls_rnd (GNUTLS_RND_NONCE, &serial, sizeof (serial));

  etime = time (NULL);
  tm_data = localtime (&etime);
  

  ret = gnutls_x509_crt_set_serial (request,
                                    &serial,
                                    sizeof (serial));

  ret = gnutls_x509_crt_set_activation_time (request,
                                             etime);
  tm_data->tm_year++;
  etime = mktime (tm_data);

  if (-1 == etime)
  {
    GNUNET_break (0);
  }

  ret = gnutls_x509_crt_set_expiration_time (request,
                                             etime);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Signing...\n");

  ret = gnutls_x509_crt_sign (request, proxy_ca.cert, proxy_ca.key);

  key_buf_size = sizeof (pgc->key);
  cert_buf_size = sizeof (pgc->cert);
  
  gnutls_x509_crt_export (request, GNUTLS_X509_FMT_PEM,
                          pgc->cert, &cert_buf_size);

  gnutls_x509_privkey_export (proxy_ca.key, GNUTLS_X509_FMT_PEM,
                          pgc->key, &key_buf_size);


  gnutls_x509_crt_deinit (request);

  return pgc;

}


/**
 * Adds a socket to an SSL MHD instance
 * It is important the the domain name is
 * correct. In most cases we need to start a new daemon
 */
static int
add_handle_to_ssl_mhd (struct GNUNET_NETWORK_Handle *h, char* domain)
{
  struct MhdHttpList *hd = NULL;
  struct ProxyGNSCertificate *pgc;

  for (hd = mhd_httpd_head; hd != NULL; hd = hd->next)
  {
    if (0 == strcmp (hd->domain, domain))
      break;
  }

  if (NULL == hd)
  {
    /* Start new MHD */
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "No previous SSL instance found... starting new one for %s\n",
                domain);
    
    pgc = generate_gns_certificate (domain);
    
    hd = GNUNET_malloc (sizeof (struct MhdHttpList));
    hd->is_ssl = GNUNET_YES;
    strcpy (hd->domain, domain);
    hd->proxy_cert = pgc;
    hd->daemon = MHD_start_daemon (MHD_USE_DEBUG | MHD_USE_SSL, http_port++,
                              NULL, NULL,
                              &create_response, hd,
                              MHD_OPTION_CONNECTION_LIMIT, (unsigned int) 128,
                              MHD_OPTION_CONNECTION_TIMEOUT, (unsigned int) 16,
                              MHD_OPTION_NOTIFY_COMPLETED,
                              NULL, NULL,
                              MHD_OPTION_HTTPS_MEM_KEY, pgc->key,
                              MHD_OPTION_HTTPS_MEM_CERT, pgc->cert,
                              MHD_OPTION_END);
    hd->httpd_task = GNUNET_SCHEDULER_NO_TASK;
    
    GNUNET_CONTAINER_DLL_insert (mhd_httpd_head, mhd_httpd_tail, hd);
  }
  
  return add_handle_to_mhd (h, hd->daemon);
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

  int ret;
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
      
      ret = MHD_NO;
      if (ntohs(req_port) == HTTPS_PORT)
      {
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                    "Requested connection is HTTPS\n");
        ret = add_handle_to_ssl_mhd ( s5r->sock, domain );
      }
      else if (NULL != httpd)
      {
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                    "Requested connection is HTTP\n");
        ret = add_handle_to_mhd ( s5r->sock, httpd );
      }

      if (ret != MHD_YES)
      {
        GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                    _("Failed to start HTTP server\n"));
        s_resp->version = 0x05;
        s_resp->reply = 0x01;
        s5r->cleanup = GNUNET_YES;
        s5r->cleanup_sock = GNUNET_YES;
        s5r->wtask = 
          GNUNET_SCHEDULER_add_write_net (GNUNET_TIME_UNIT_FOREVER_REL,
                                        s5r->sock,
                                        &do_write, s5r);
        return;
      }
      
      /* Signal success */
      s_resp->version = 0x05;
      s_resp->reply = 0x00;
      s_resp->reserved = 0x00;
      s_resp->addr_type = 0x01;
      
      s5r->cleanup = GNUNET_YES;
      s5r->cleanup_sock = GNUNET_NO;
      s5r->wtask =
        GNUNET_SCHEDULER_add_write_net (GNUNET_TIME_UNIT_FOREVER_REL,
                                        s5r->sock,
                                        &do_write, s5r);
      run_httpds ();
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
        s5r->cleanup = GNUNET_YES;
        s5r->cleanup_sock = GNUNET_YES;
        s5r->wtask = 
          GNUNET_SCHEDULER_add_write_net (GNUNET_TIME_UNIT_FOREVER_REL,
                                          s5r->sock,
                                          &do_write, s5r);
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
 * Task run on shutdown
 *
 * @param cls closure
 * @param tc task context
 */
static void
do_shutdown (void *cls,
             const struct GNUNET_SCHEDULER_TaskContext *tc)
{

  struct MhdHttpList *hd;
  struct MhdHttpList *tmp_hd;
  struct ProxyCurlTask *ctask;
  struct ProxyCurlTask *ctask_tmp;

  if (GNUNET_SCHEDULER_NO_TASK != curl_download_task)
  {
    GNUNET_SCHEDULER_cancel (curl_download_task);
    curl_download_task = GNUNET_SCHEDULER_NO_TASK;
  }

  for (hd = mhd_httpd_head; hd != NULL; hd = tmp_hd)
  {
    tmp_hd = hd->next;

    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Stopping daemon\n");

    if (GNUNET_SCHEDULER_NO_TASK != hd->httpd_task)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Stopping select task %d\n",
                  hd->httpd_task);
      GNUNET_SCHEDULER_cancel (hd->httpd_task);
      hd->httpd_task = GNUNET_SCHEDULER_NO_TASK;
    }

    if (NULL != hd->daemon)
    {
      MHD_stop_daemon (hd->daemon);
      hd->daemon = NULL;
    }

    if (NULL != hd->proxy_cert)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Free certificate\n");
      GNUNET_free (hd->proxy_cert);
    }

    GNUNET_free (hd);
  }

  for (ctask=ctasks_head; ctask != NULL; ctask=ctask_tmp)
  {
    ctask_tmp = ctask->next;

    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Cleaning up cURL task\n");

    if (ctask->curl != NULL)
      curl_easy_cleanup (ctask->curl);
    ctask->curl = NULL;
    if (NULL != ctask->headers)
      curl_slist_free_all (ctask->headers);

    GNUNET_free (ctask);
  }

  GNUNET_GNS_disconnect (gns_handle);
}


/**
 * Compiles a regex for us
 *
 * @param re ptr to re struct
 * @param rt the expression to compile
 * @return 0 on success
 */
static int
compile_regex (regex_t *re, const char* rt)
{
  int status;
  char err[1024];

  status = regcomp (re, rt, REG_EXTENDED|REG_NEWLINE);
  if (status)
  {
    regerror (status, re, err, 1024);
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Regex error compiling '%s': %s\n", rt, err);
    return 1;
  }
  return 0;
}


/**
 * Loads the users local zone key
 *
 * @return GNUNET_YES on success
 */
static int
load_local_zone_key (const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  char *keyfile;
  struct GNUNET_CRYPTO_RsaPrivateKey *key = NULL;
  struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded pkey;
  struct GNUNET_CRYPTO_ShortHashCode *zone = NULL;
  struct GNUNET_CRYPTO_ShortHashAsciiEncoded zonename;

  if (GNUNET_OK != GNUNET_CONFIGURATION_get_value_filename (cfg, "gns",
                                                            "ZONEKEY", &keyfile))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Unable to load zone key config value!\n");
    return GNUNET_NO;
  }

  if (GNUNET_NO == GNUNET_DISK_file_test (keyfile))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Unable to load zone key!\n");
    GNUNET_free(keyfile);
    return GNUNET_NO;
  }

  key = GNUNET_CRYPTO_rsa_key_create_from_file (keyfile);
  GNUNET_CRYPTO_rsa_key_get_public (key, &pkey);
  GNUNET_CRYPTO_short_hash(&pkey,
                           sizeof(struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded),
                           &local_gns_zone);
  zone = &local_gns_zone;
  GNUNET_CRYPTO_short_hash_to_enc (zone, &zonename);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Using zone: %s!\n", &zonename);
  GNUNET_CRYPTO_rsa_key_free(key);
  GNUNET_free(keyfile);

  return GNUNET_YES;
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
  struct MhdHttpList *hd;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Loading CA\n");

  gnutls_global_init ();

  gnutls_x509_crt_init (&proxy_ca.cert);
  gnutls_x509_privkey_init (&proxy_ca.key);
  
  load_cert_from_file (proxy_ca.cert, cafile);
  load_key_from_file (proxy_ca.key, cafile);
  
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Loading Template\n");

  compile_regex (&re_dotplus, (char*) RE_A_HREF);

  gns_handle = GNUNET_GNS_connect (cfg);

  if (GNUNET_NO == load_local_zone_key (cfg))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Unable to load zone!\n");
    return;
  }

  if (NULL == gns_handle)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Unable to connect to GNS!\n");
    return;
  }

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

  ctasks_head = NULL;
  ctasks_tail = NULL;

  if (0 != curl_global_init (CURL_GLOBAL_WIN32))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "cURL global init failed!\n");
    return;
  }

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Proxy listens on port %u\n",
              port);

  mhd_httpd_head = NULL;
  mhd_httpd_tail = NULL;
  
  hd = GNUNET_malloc (sizeof (struct MhdHttpList));
  hd->is_ssl = GNUNET_NO;
  strcpy (hd->domain, "");
  httpd = MHD_start_daemon (MHD_USE_DEBUG, http_port++,
                               NULL, NULL,
                               &create_response, hd,
                               MHD_OPTION_CONNECTION_LIMIT, (unsigned int) 128,
                               MHD_OPTION_CONNECTION_TIMEOUT, (unsigned int) 16,
                               MHD_OPTION_NOTIFY_COMPLETED,
                               NULL, NULL,
                               MHD_OPTION_END);
  hd->daemon = httpd;
  hd->httpd_task = GNUNET_SCHEDULER_NO_TASK;

  GNUNET_CONTAINER_DLL_insert (mhd_httpd_head, mhd_httpd_tail, hd);

  run_httpds ();

  GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_FOREVER_REL,
                                &do_shutdown, NULL);

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
    {'a', "authority", NULL,
      gettext_noop ("pem file to use as CA"), 1,
      &GNUNET_GETOPT_set_string, &cafile},
    GNUNET_GETOPT_OPTION_END
  };

  int ret;

  if (GNUNET_OK != GNUNET_STRINGS_get_utf8_args (argc, argv, &argc, &argv))
    return 2;

  GNUNET_log_setup ("gnunet-gns-proxy", "WARNING", NULL);
  ret =
      (GNUNET_OK ==
       GNUNET_PROGRAM_run (argc, argv, "gnunet-gns-proxy",
                           _("GNUnet GNS proxy"),
                           options,
                           &run, NULL)) ? 0 : 1;
  return ret;
}

/*
     This file is part of GNUnet.
     (C) 2012-2013 Christian Grothoff (and other contributing authors)

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
 * @author Martin Schanzenbach
 * @file src/gns/gnunet-gns-proxy.c
 * @brief HTTP(S) proxy that rewrites URIs and fakes certificats to make GNS work
 *        with legacy browsers
 */
#include "platform.h"
#include <microhttpd.h>
#include <curl/curl.h>
#include <gnutls/gnutls.h>
#include <gnutls/x509.h>
#include <gnutls/abstract.h>
#include <gnutls/crypto.h>
#include <regex.h>
#include "gnunet_util_lib.h"
#include "gnunet_gns_service.h"
#include "gnunet_identity_service.h"
#include "gns_proxy_proto.h"
#include "gns.h"


#define GNUNET_GNS_PROXY_PORT 7777

#define MHD_MAX_CONNECTIONS 300

#define MAX_HTTP_URI_LENGTH 2048

#define POSTBUFFERSIZE 4096

#define HTTP_PORT 80

#define HTTPS_PORT 443

/**
 * Log curl error.
 *
 * @param level log level
 * @param fun name of curl_easy-function that gave the error
 * @param rc return code from curl
 */
#define LOG_CURL_EASY(level,fun,rc) GNUNET_log(level, _("%s failed at %s:%d: `%s'\n"), fun, __FILE__, __LINE__, curl_easy_strerror (rc))


enum BufferStatus
  {
    BUF_WAIT_FOR_CURL,
    BUF_WAIT_FOR_MHD
  };



/**
 * A structure for CA cert/key
 */
struct ProxyCA
{
  /**
   * The certificate 
   */
  gnutls_x509_crt_t cert;

  /**
   * The private key 
   */
  gnutls_x509_privkey_t key;
};

#define MAX_PEM_SIZE (10 * 1024)

/**
 * Structure for GNS certificates
 */
struct ProxyGNSCertificate
{
  /* The certificate as PEM */
  char cert[MAX_PEM_SIZE];

  /* The private key as PEM */
  char key[MAX_PEM_SIZE];
};


/**
 * A structure for socks requests
 */
struct Socks5Request
{

  /**
   * DLL.
   */
  struct Socks5Request *next;

  /**
   * DLL.
   */
  struct Socks5Request *prev;

  /**
   * The client socket 
   */
  struct GNUNET_NETWORK_Handle *sock;

  /**
   * The server socket 
   */
  struct GNUNET_NETWORK_Handle *remote_sock;
  
  /**
   * The socks state 
   */
  int state;
  
  /**
   * Client socket read task 
   */
  GNUNET_SCHEDULER_TaskIdentifier rtask;

  /**
   * Server socket read task 
   */
  GNUNET_SCHEDULER_TaskIdentifier fwdrtask;

  /**
   * Client socket write task 
   */
  GNUNET_SCHEDULER_TaskIdentifier wtask;

  /**
   * Server socket write task 
   */
  GNUNET_SCHEDULER_TaskIdentifier fwdwtask;

  /**
   * Read buffer 
   */
  char rbuf[2048];

  /**
   * Write buffer 
   */
  char wbuf[2048];

  /**
   * Length of data in read buffer 
   */
  unsigned int rbuf_len;

  /**
   * Length of data in write buffer 
   */
  unsigned int wbuf_len;

  /**
   * This handle is scheduled for cleanup? 
   */
  int cleanup;

  /**
   * Shall we close the client socket on cleanup? 
   */
  int cleanup_sock;
};


/**
 * A structure for all running Httpds
 */
struct MhdHttpList
{
  /**
   * DLL for httpds 
   */
  struct MhdHttpList *prev;

  /**
   * DLL for httpds 
   */
  struct MhdHttpList *next;

  /**
   * is this an ssl daemon? 
   */
  int is_ssl;

  /**
   * the domain name to server (only important for SSL) 
   */
  char domain[256];

  /**
   * The daemon handle 
   */
  struct MHD_Daemon *daemon;

  /**
   * Optional proxy certificate used
   */
  struct ProxyGNSCertificate *proxy_cert;

  /**
   * The task ID 
   */
  GNUNET_SCHEDULER_TaskIdentifier httpd_task;

};


/**
 * A structure for MHD<->cURL streams
 */
struct ProxyCurlTask
{
  /**
   * DLL for tasks 
   */
  struct ProxyCurlTask *prev;

  /**
   * DLL for tasks 
   */
  struct ProxyCurlTask *next;

  /**
   * Handle to cURL 
   */
  CURL *curl;

  /**
   * Optional header replacements for curl (LEHO) 
   */
  struct curl_slist *headers;

  /**
   * Optional resolver replacements for curl (LEHO) 
   */
  struct curl_slist *resolver;

  /**
   * curl response code 
   */
  long curl_response_code;

  /**
   * The URL to fetch 
   */
  char url[MAX_HTTP_URI_LENGTH];

  /**
   * The cURL write buffer / MHD read buffer 
   */
  char buffer[CURL_MAX_WRITE_SIZE];

  /**
   * Read pos of the data in the buffer 
   */
  char *buffer_read_ptr;

  /**
   * Write pos in the buffer 
   */
  char *buffer_write_ptr;

  /**
   * connection 
   */
  struct MHD_Connection *connection;

  /**
   * put
   */
  size_t put_read_offset;
  size_t put_read_size;

  /**
   *post
   */
  struct MHD_PostProcessor *post_handler;

  /* post data */
  struct ProxyUploadData *upload_data_head;
  struct ProxyUploadData *upload_data_tail;

  /**
   * the type of POST encoding 
   */
  char* post_type;

  struct curl_httppost *httppost;

  struct curl_httppost *httppost_last;

  /**
   * Number of bytes in buffer 
   */
  unsigned int bytes_in_buffer;

  /* PP task */
  GNUNET_SCHEDULER_TaskIdentifier pp_task;

  /* The associated daemon list entry */
  struct MhdHttpList *mhd;

  /* The associated response */
  struct MHD_Response *response;

  /* Cookies to set */
  struct ProxySetCookieHeader *set_cookies_head;

  /* Cookies to set */
  struct ProxySetCookieHeader *set_cookies_tail;

  /* The authority of the corresponding host (site of origin) */
  char authority[256];

  /* The hostname (Host header field) */
  char host[256];

  /* The LEgacy HOstname (can be empty) */
  char leho[256];

  /**
   * The port 
   */
  uint16_t port;

  /**
   * The buffer status (BUF_WAIT_FOR_CURL or BUF_WAIT_FOR_MHD) 
   */
  enum BufferStatus buf_status;

  /**
   * connection status 
   */
  int ready_to_queue;

  /**
   * is curl running? 
   */
  int curl_running;
  
  /**
   * are we done 
   */
  int fin;

  /**
   * Already accepted 
   */
  int accepted;

  /**
   * Indicates wheather the download is in progress 
   */
  int download_in_progress;

  /**
   * Indicates wheather the download was successful 
   */
  int download_is_finished;

  /**
   * Indicates wheather the download failed 
   */
  int download_error;

  int post_done;

  int is_httppost;
  
};


/**
 * Struct for set-cookies
 */
struct ProxySetCookieHeader
{
  /**
   * DLL 
   */
  struct ProxySetCookieHeader *next;

  /**
   * DLL 
   */
  struct ProxySetCookieHeader *prev;

  /**
   * the cookie 
   */
  char *cookie;
};


/**
 * Post data structure
 */
struct ProxyUploadData
{
  /**
   * DLL 
   */
  struct ProxyUploadData *next;

  /**
   * DLL 
   */
  struct ProxyUploadData *prev;

  char *key;

  char *filename;

  char *content_type;

  size_t content_length;
  
  /**
   * value 
   */
  char *value;

  /**
   * to copy 
   */
  size_t bytes_left;

  /**
   * size 
   */
  size_t total_bytes;
};


/**
 * The port the proxy is running on (default 7777) 
 */
static unsigned long port = GNUNET_GNS_PROXY_PORT;

/**
 * The CA file (pem) to use for the proxy CA 
 */
static char* cafile_opt;

/**
 * The listen socket of the proxy 
 */
static struct GNUNET_NETWORK_Handle *lsock;

/**
 * The listen task ID 
 */
static GNUNET_SCHEDULER_TaskIdentifier ltask;

/**
 * The cURL download task 
 */
static GNUNET_SCHEDULER_TaskIdentifier curl_download_task;

/**
 * Number of current mhd connections 
 */
static unsigned int total_mhd_connections;

/**
 * The cURL multi handle 
 */
static CURLM *curl_multi;

/**
 * Handle to the GNS service 
 */
static struct GNUNET_GNS_Handle *gns_handle;

/**
 * DLL for ProxyCurlTasks 
 */
static struct ProxyCurlTask *ctasks_head;

/**
 * DLL for ProxyCurlTasks 
 */
static struct ProxyCurlTask *ctasks_tail;

/**
 * DLL for http/https daemons 
 */
static struct MhdHttpList *mhd_httpd_head;

/**
 * DLL for http/https daemons 
 */
static struct MhdHttpList *mhd_httpd_tail;

/**
 * DLL of active socks requests.
 */
static struct Socks5Request *s5r_head;

/**
 * DLL of active socks requests.
 */
static struct Socks5Request *s5r_tail;

/**
 * The users local GNS master zone 
 */
static struct GNUNET_CRYPTO_EccPublicSignKey local_gns_zone;

/**
 * The users local shorten zone 
 */
static struct GNUNET_CRYPTO_EccPrivateKey local_shorten_zone;

/**
 * Is shortening enabled?
 */
static int do_shorten;

/**
 * The CA for SSL certificate generation 
 */
static struct ProxyCA proxy_ca;

/**
 * Daemon for HTTP (we have one per SSL certificate, and then one for all HTTP connections;
 * this is the one for HTTP, not HTTPS).
 */
static struct MHD_Daemon *httpd;

/**
 * Shorten zone private key 
 */
static struct GNUNET_CRYPTO_EccPrivateKey shorten_zonekey;

/**
 * Response we return on cURL failures.
 */
static struct MHD_Response *curl_failure_response;

/**
 * Connection to identity service.
 */
static struct GNUNET_IDENTITY_Handle *identity;

/**
 * Request for our ego.
 */
static struct GNUNET_IDENTITY_Operation *id_op;

/**
 * Our configuration.
 */
static const struct GNUNET_CONFIGURATION_Handle *cfg;

/**
 * Clean up s5r handles
 *
 * @param s5r the handle to destroy
 */
static void
cleanup_s5r (struct Socks5Request *s5r)
{
  if (GNUNET_SCHEDULER_NO_TASK != s5r->rtask)
    GNUNET_SCHEDULER_cancel (s5r->rtask);
  if (GNUNET_SCHEDULER_NO_TASK != s5r->fwdwtask)
    GNUNET_SCHEDULER_cancel (s5r->fwdwtask);
  if (GNUNET_SCHEDULER_NO_TASK != s5r->fwdrtask)
    GNUNET_SCHEDULER_cancel (s5r->fwdrtask);  
  if (NULL != s5r->remote_sock)
    GNUNET_NETWORK_socket_close (s5r->remote_sock);
  if ( (NULL != s5r->sock) && 
       (GNUNET_YES == s5r->cleanup_sock) )
    GNUNET_NETWORK_socket_close (s5r->sock);
  GNUNET_CONTAINER_DLL_remove (s5r_head,
			       s5r_tail,
			       s5r);
  GNUNET_free(s5r);
}


/**
 * Checks if name is in tld
 *
 * @param name the name to check 
 * @param tld the TLD to check for (must NOT begin with ".")
 * @return #GNUNET_YES or #GNUNET_NO
 */
static int
is_tld (const char* name, const char* tld)
{
  size_t name_len = strlen (name);
  size_t tld_len = strlen (tld);

  GNUNET_break ('.' != tld[0]);
  return ( (tld_len < name_len) &&
	   ( ('.' == name[name_len - tld_len - 1]) || (name_len == tld_len) ) &&
	   (0 == memcmp (tld,
			 name + (name_len - tld_len),
			 tld_len)) );
}


static int
con_post_data_iter (void *cls,
                  enum MHD_ValueKind kind,
                  const char *key,
                  const char *filename,
                  const char *content_type,
                  const char *transfer_encoding,
                  const char *data,
                  uint64_t off,
                  size_t size)
{
  struct ProxyCurlTask* ctask = cls;
  struct ProxyUploadData* pdata;
  char* enc;
  char* new_value;
  
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Got POST data (file: %s, content type: %s): '%s=%.*s' at offset %llu size %llu\n",
	      filename, content_type,
              key, (int) size, data, 
	      (unsigned long long) off, 
	      (unsigned long long) size);
  GNUNET_assert (NULL != ctask->post_type);

  if (0 == strcasecmp (MHD_HTTP_POST_ENCODING_MULTIPART_FORMDATA,
                       ctask->post_type))
  {
    ctask->is_httppost = GNUNET_YES;
    /* new part */
    if (0 == off)
    {
      pdata = GNUNET_new (struct ProxyUploadData);
      pdata->key = GNUNET_strdup (key);

      if (NULL != filename)
        pdata->filename = GNUNET_strdup (filename);
      if (NULL != content_type)
        pdata->content_type = GNUNET_strdup (content_type);
      pdata->value = GNUNET_malloc (size);
      pdata->total_bytes = size;
      memcpy (pdata->value, data, size);
      GNUNET_CONTAINER_DLL_insert_tail (ctask->upload_data_head,
                                        ctask->upload_data_tail,
                                        pdata);

      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Copied %llu bytes of POST Data\n", 
		  (unsigned long long) size);
      return MHD_YES;
    }
    
    pdata = ctask->upload_data_tail;
    new_value = GNUNET_malloc (size + pdata->total_bytes);
    memcpy (new_value, pdata->value, pdata->total_bytes);
    memcpy (new_value+off, data, size);
    GNUNET_free (pdata->value);
    pdata->value = new_value;
    pdata->total_bytes += size;

    return MHD_YES;
  }

  if (0 != strcasecmp (MHD_HTTP_POST_ENCODING_FORM_URLENCODED,
                       ctask->post_type))
  {
    return MHD_NO;
  }

  ctask->is_httppost = GNUNET_NO;
  
  if (NULL != ctask->curl)
    curl_easy_pause (ctask->curl, CURLPAUSE_CONT);

  if (0 == off)
  {
    enc = curl_easy_escape (ctask->curl, key, 0);
    if (NULL == enc)
      {
	GNUNET_break (0);
	return MHD_NO;
      }
    /* a key */
    pdata = GNUNET_new (struct ProxyUploadData);
    pdata->value = GNUNET_malloc (strlen (enc) + 3);
    if (NULL != ctask->upload_data_head)
    {
      pdata->value[0] = '&';
      memcpy (pdata->value+1, enc, strlen (enc));
    }
    else
      memcpy (pdata->value, enc, strlen (enc));
    pdata->value[strlen (pdata->value)] = '=';
    pdata->bytes_left = strlen (pdata->value);
    pdata->total_bytes = pdata->bytes_left;
    curl_free (enc);

    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Escaped POST key: '%s'\n",
                pdata->value);

    GNUNET_CONTAINER_DLL_insert_tail (ctask->upload_data_head,
                                      ctask->upload_data_tail,
                                      pdata);
  }

  /* a value */
  enc = curl_easy_escape (ctask->curl, data, 0);
  if (NULL == enc)
    {
      GNUNET_break (0);
      return MHD_NO;
    }
  pdata = GNUNET_new (struct ProxyUploadData);
  pdata->value = GNUNET_malloc (strlen (enc) + 1);
  memcpy (pdata->value, enc, strlen (enc));
  pdata->bytes_left = strlen (pdata->value);
  pdata->total_bytes = pdata->bytes_left;
  curl_free (enc);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Escaped POST value: '%s'\n",
              pdata->value);

  GNUNET_CONTAINER_DLL_insert_tail (ctask->upload_data_head,
                                    ctask->upload_data_tail,
                                    pdata);
  return MHD_YES;
}


/**
 * Read HTTP request header field 'Host'
 *
 * @param cls buffer to write to
 * @param kind value kind
 * @param key field key
 * @param value field value
 * @return #MHD_NO when Host found
 */
static int
con_val_iter (void *cls,
              enum MHD_ValueKind kind,
              const char *key,
              const char *value)
{
  struct ProxyCurlTask *ctask = cls;
  char* buf = ctask->host;
  char* port;
  char* cstr;
  const char* hdr_val;
  unsigned int uport;

  if (0 == strcmp ("Host", key))
  {
    port = strchr (value, ':');
    if (NULL != port)
    {
      strncpy (buf, value, port-value);
      port++;
      if ((1 != sscanf (port, "%u", &uport)) ||
           (uport > UINT16_MAX) ||
           (0 == uport))
        GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                    "Unable to parse port!\n");
      else
        ctask->port = (uint16_t) uport;
    }
    else
      strcpy (buf, value);
    return MHD_YES;
  }

  if (0 == strcmp (MHD_HTTP_HEADER_ACCEPT_ENCODING, key))
    hdr_val = "";
  else
    hdr_val = value;

  if (0 == strcasecmp (MHD_HTTP_HEADER_CONTENT_TYPE,
                   key))
  {
    if (0 == strncasecmp (value,
                     MHD_HTTP_POST_ENCODING_FORM_URLENCODED,
                     strlen (MHD_HTTP_POST_ENCODING_FORM_URLENCODED)))
      ctask->post_type = MHD_HTTP_POST_ENCODING_FORM_URLENCODED;
    else if (0 == strncasecmp (value,
                          MHD_HTTP_POST_ENCODING_MULTIPART_FORMDATA,
                          strlen (MHD_HTTP_POST_ENCODING_MULTIPART_FORMDATA)))
      ctask->post_type = MHD_HTTP_POST_ENCODING_MULTIPART_FORMDATA;
    else
      ctask->post_type = NULL;

  }

  cstr = GNUNET_malloc (strlen (key) + strlen (hdr_val) + 3);
  GNUNET_snprintf (cstr, strlen (key) + strlen (hdr_val) + 3,
                   "%s: %s", key, hdr_val);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Client Header: %s\n", cstr);

  ctask->headers = curl_slist_append (ctask->headers, cstr);
  GNUNET_free (cstr);

  return MHD_YES;
}


/**
 * Callback for MHD response
 *
 * @param cls closure
 * @param pos in buffer
 * @param buf buffer
 * @param max space in buffer
 * @return number of bytes written
 */
static ssize_t
mhd_content_cb (void *cls,
                uint64_t pos,
                char* buf,
                size_t max);


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
  int cookie_hdr_len = strlen (MHD_HTTP_HEADER_SET_COOKIE);
  char hdr_generic[bytes+1];
  char new_cookie_hdr[bytes+strlen (ctask->leho)+1];
  char new_location[MAX_HTTP_URI_LENGTH+500];
  char real_host[264];
  char leho_host[264];
  char* ndup;
  char* tok;
  char* cookie_domain;
  char* hdr_type;
  char* hdr_val;
  int delta_cdomain;
  size_t offset = 0;
  char cors_hdr[strlen (ctask->leho) + strlen ("https://")];
  
  if (NULL == ctask->response)
  {
    /* FIXME: get total size from curl (if available) */
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Creating response for %s\n", ctask->url);
    ctask->response = MHD_create_response_from_callback (MHD_SIZE_UNKNOWN,
							 sizeof (ctask->buffer),
							 &mhd_content_cb,
							 ctask,
							 NULL);

    /* if we have a leho add a CORS header */
    if (0 != strcmp ("", ctask->leho))
    {
      /* We could also allow ssl and http here */
      if (ctask->mhd->is_ssl)
        sprintf (cors_hdr, "https://%s", ctask->leho);
      else
        sprintf (cors_hdr, "http://%s", ctask->leho);

      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "MHD: Adding CORS header field %s\n",
                  cors_hdr);

      if (GNUNET_NO == MHD_add_response_header (ctask->response,
                                              "Access-Control-Allow-Origin",
                                              cors_hdr))
      {
        GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  "MHD: Error adding CORS header field %s\n",
                  cors_hdr);
      }
    }
    ctask->ready_to_queue = GNUNET_YES;
  }
  if (cookie_hdr_len > bytes)
    return bytes;

  memcpy (hdr_generic, buffer, bytes);
  hdr_generic[bytes] = '\0';
  /* remove crlf */
  if ('\n' == hdr_generic[bytes-1])
    hdr_generic[bytes-1] = '\0';

  if (hdr_generic[bytes-2] == '\r')
    hdr_generic[bytes-2] = '\0';
  
  if (0 == memcmp (hdr_generic,
                   MHD_HTTP_HEADER_SET_COOKIE,
                   cookie_hdr_len))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Looking for cookie in: `%s'\n", hdr_generic);    
    ndup = GNUNET_strdup (hdr_generic+cookie_hdr_len+1);
    memset (new_cookie_hdr, 0, sizeof (new_cookie_hdr));
    for (tok = strtok (ndup, ";"); tok != NULL; tok = strtok (NULL, ";"))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                  "Got Cookie token: %s\n", tok);
      //memcpy (new_cookie_hdr+offset, tok, strlen (tok));
      if (0 == memcmp (tok, " domain", strlen (" domain")))
      {
        cookie_domain = tok + strlen (" domain") + 1;

        GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                    "Got Set-Cookie Domain: %s\n", cookie_domain);

        if (strlen (cookie_domain) < strlen (ctask->leho))
        {
          delta_cdomain = strlen (ctask->leho) - strlen (cookie_domain);
          if (0 == strcmp (cookie_domain, ctask->leho + (delta_cdomain)))
          {
            GNUNET_snprintf (new_cookie_hdr+offset,
                             sizeof (new_cookie_hdr),
                             " domain=%s", ctask->authority);
            offset += strlen (" domain=") + strlen (ctask->authority);
            new_cookie_hdr[offset] = ';';
            offset++;
            continue;
          }
        }
        else if (strlen (cookie_domain) == strlen (ctask->leho))
        {
          if (0 == strcmp (cookie_domain, ctask->leho))
          {
            GNUNET_snprintf (new_cookie_hdr+offset,
                             sizeof (new_cookie_hdr),
                             " domain=%s", ctask->host);
            offset += strlen (" domain=") + strlen (ctask->host);
            new_cookie_hdr[offset] = ';';
            offset++;
            continue;
          }
        }
        GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                    "Cookie domain invalid\n");

        
      }
      memcpy (new_cookie_hdr+offset, tok, strlen (tok));
      offset += strlen (tok);
      new_cookie_hdr[offset] = ';';
      offset++;
    }
    
    GNUNET_free (ndup);

    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                "Got Set-Cookie HTTP header %s\n", new_cookie_hdr);

    if (GNUNET_NO == MHD_add_response_header (ctask->response,
                                              MHD_HTTP_HEADER_SET_COOKIE,
                                              new_cookie_hdr))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  "MHD: Error adding set-cookie header field %s\n",
                  hdr_generic+cookie_hdr_len+1);
    }
    return bytes;
  }

  ndup = GNUNET_strdup (hdr_generic);
  hdr_type = strtok (ndup, ":");

  if (NULL == hdr_type)
  {
    GNUNET_free (ndup);
    return bytes;
  }

  hdr_val = strtok (NULL, "");

  if (NULL == hdr_val)
  {
    GNUNET_free (ndup);
    return bytes;
  }

  hdr_val++;

  if (0 == strcasecmp (MHD_HTTP_HEADER_LOCATION, hdr_type))
  {
    if (ctask->mhd->is_ssl)
    {
      sprintf (leho_host, "https://%s", ctask->leho);
      sprintf (real_host, "https://%s", ctask->host);
    }
    else
    {
      sprintf (leho_host, "http://%s", ctask->leho);
      sprintf (real_host, "http://%s", ctask->host);
    }

    if (0 == memcmp (leho_host, hdr_val, strlen (leho_host)))
    {
      sprintf (new_location, "%s%s", real_host, hdr_val+strlen (leho_host));
      hdr_val = new_location;
    }
  }

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Trying to set %s: %s\n",
              hdr_type,
              hdr_val);
  if (GNUNET_NO == MHD_add_response_header (ctask->response,
                                            hdr_type,
                                            hdr_val))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "MHD: Error adding %s header field %s\n",
                hdr_type,
                hdr_val);
  }
  GNUNET_free (ndup);
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
 * Task run whenever HTTP server operations are pending.
 *
 * @param cls unused
 * @param tc sched context
 */
static void
do_httpd (void *cls,
          const struct GNUNET_SCHEDULER_TaskContext *tc);


static void
run_mhd_now (struct MhdHttpList *hd)
{
  if (GNUNET_SCHEDULER_NO_TASK != hd->httpd_task)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "MHD: killing old task\n");
    GNUNET_SCHEDULER_cancel (hd->httpd_task);
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "MHD: Scheduling MHD now\n");
  hd->httpd_task = GNUNET_SCHEDULER_add_now (&do_httpd, hd);
}


/**
 * Ask cURL for the select sets and schedule download
 */
static void
curl_download_prepare (void);


/**
 * Callback to free content
 *
 * @param cls content to free
 * @param tc task context
 */
static void
mhd_content_free (void *cls,
                  const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct ProxyCurlTask *ctask = cls;
  struct ProxyUploadData *pdata;

  if (NULL != ctask->headers)
    curl_slist_free_all (ctask->headers);

  if (NULL != ctask->headers)
    curl_slist_free_all (ctask->resolver);

  if (NULL != ctask->response)
    MHD_destroy_response (ctask->response);

  if (NULL != ctask->post_handler)
    MHD_destroy_post_processor (ctask->post_handler);

  if (GNUNET_SCHEDULER_NO_TASK != ctask->pp_task)
    GNUNET_SCHEDULER_cancel (ctask->pp_task);

  for (pdata = ctask->upload_data_head; NULL != pdata; pdata = ctask->upload_data_head)
  {
    GNUNET_CONTAINER_DLL_remove (ctask->upload_data_head,
                                 ctask->upload_data_tail,
                                 pdata);
    GNUNET_free_non_null (pdata->filename);
    GNUNET_free_non_null (pdata->content_type);
    GNUNET_free_non_null (pdata->key);
    GNUNET_free_non_null (pdata->value);
    GNUNET_free (pdata);
  }
  GNUNET_free (ctask);
}


/**
 * Callback for MHD response
 *
 * @param cls closure
 * @param pos in buffer
 * @param buf buffer
 * @param max space in buffer
 * @return number of bytes written
 */
static ssize_t
mhd_content_cb (void *cls,
                uint64_t pos,
                char* buf,
                size_t max)
{
  struct ProxyCurlTask *ctask = cls;
  ssize_t copied = 0;
  size_t bytes_to_copy = ctask->buffer_write_ptr - ctask->buffer_read_ptr;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "MHD: content cb for %s. To copy: %u\n",
              ctask->url, (unsigned int) bytes_to_copy);
  if ((GNUNET_YES == ctask->download_is_finished) &&
      (GNUNET_NO == ctask->download_error) &&
      (0 == bytes_to_copy))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                "MHD: sending response for %s\n", ctask->url);
    ctask->download_in_progress = GNUNET_NO;
    run_mhd_now (ctask->mhd);
    GNUNET_SCHEDULER_add_now (&mhd_content_free, ctask);
    total_mhd_connections--;
    return MHD_CONTENT_READER_END_OF_STREAM;
  }
  
  if ((GNUNET_YES == ctask->download_error) &&
      (GNUNET_YES == ctask->download_is_finished) &&
      (0 == bytes_to_copy))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                "MHD: sending error response\n");
    ctask->download_in_progress = GNUNET_NO;
    run_mhd_now (ctask->mhd);
    GNUNET_SCHEDULER_add_now (&mhd_content_free, ctask);
    total_mhd_connections--;
    return MHD_CONTENT_READER_END_WITH_ERROR;
  }

  if ( ctask->buf_status == BUF_WAIT_FOR_CURL )
    return 0;
  
  copied = 0;
  bytes_to_copy = ctask->buffer_write_ptr - ctask->buffer_read_ptr;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "MHD: copied: %d left: %u, space left in buf: %d\n",
              copied,
              (unsigned int) bytes_to_copy, (int) (max - copied));
  
  if (GNUNET_NO == ctask->download_is_finished)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "MHD: Purging buffer\n");
    memmove (ctask->buffer, ctask->buffer_read_ptr, bytes_to_copy);
    ctask->buffer_read_ptr = ctask->buffer;
    ctask->buffer_write_ptr = ctask->buffer + bytes_to_copy;
    ctask->buffer[bytes_to_copy] = '\0';
  }
  
  if (bytes_to_copy + copied > max)
    bytes_to_copy = max - copied;
  memcpy (buf+copied, ctask->buffer_read_ptr, bytes_to_copy);
  ctask->buffer_read_ptr += bytes_to_copy;
  copied += bytes_to_copy;
  ctask->buf_status = BUF_WAIT_FOR_CURL;
  
  if (NULL != ctask->curl)
    curl_easy_pause (ctask->curl, CURLPAUSE_CONT);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "MHD: copied %d bytes\n", (int) copied);
  run_mhd_now (ctask->mhd);
  return copied;
}


/**
 * Handle data from cURL
 *
 * @param ptr pointer to the data
 * @param size number of blocks of data
 * @param nmemb blocksize
 * @param ctx the curlproxytask
 * @return number of bytes handled
 */
static size_t
curl_download_cb (void *ptr, size_t size, size_t nmemb, void* ctx)
{
  const char *cbuf = ptr;
  size_t total = size * nmemb;
  struct ProxyCurlTask *ctask = ctx;
  size_t buf_space = sizeof (ctask->buffer) - (ctask->buffer_write_ptr - ctask->buffer);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "CURL: Got %d. %d free in buffer\n",
              (int) total,
	      (int) buf_space);
  if (0 == buf_space)
  {
    ctask->buf_status = BUF_WAIT_FOR_MHD;
    run_mhd_now (ctask->mhd);
    return CURL_WRITEFUNC_PAUSE;
  }
  if (total > buf_space)
    total = buf_space;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "CURL: Copying %d bytes to buffer (%s)\n", 
	      total, ctask->url);
  memcpy (ctask->buffer_write_ptr, cbuf, total);
  ctask->bytes_in_buffer += total;
  ctask->buffer_write_ptr += total;
  if (ctask->bytes_in_buffer > 0)
  {
    ctask->buf_status = BUF_WAIT_FOR_MHD;
    run_mhd_now (ctask->mhd);
  }
  return total;
}


/**
 * cURL callback for put data
 */
static size_t
put_read_callback (void *buf, size_t size, size_t nmemb, void *cls)
{
  struct ProxyCurlTask *ctask = cls;
  struct ProxyUploadData *pdata = ctask->upload_data_head;
  size_t len = size * nmemb;
  size_t to_copy;
  char* pos;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "CURL: put read callback\n");

  if (NULL == pdata)
    return CURL_READFUNC_PAUSE;
  
  //fin
  if (NULL == pdata->value)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "CURL: Terminating PUT\n");

    GNUNET_CONTAINER_DLL_remove (ctask->upload_data_head,
                                 ctask->upload_data_tail,
                                 pdata);
    GNUNET_free (pdata);
    return 0;
  }
 
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "CURL: read callback value %s\n", pdata->value); 
  
  to_copy = pdata->bytes_left;
  if (to_copy > len)
    to_copy = len;
  
  pos = pdata->value + (pdata->total_bytes - pdata->bytes_left);
  memcpy (buf, pos, to_copy);
  pdata->bytes_left -= to_copy;
  if (pdata->bytes_left <= 0)
  {
    GNUNET_free (pdata->value);
    GNUNET_CONTAINER_DLL_remove (ctask->upload_data_head,
                                 ctask->upload_data_tail,
                                 pdata);
    GNUNET_free (pdata);
  }
  return to_copy;
}


/**
 * cURL callback for post data
 */
static size_t
post_read_callback (void *buf, size_t size, size_t nmemb, void *cls)
{
  struct ProxyCurlTask *ctask = cls;
  struct ProxyUploadData *pdata = ctask->upload_data_head;
  size_t len = size * nmemb;
  size_t to_copy;
  char* pos;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "CURL: read callback\n");

  if (NULL == pdata)
    return CURL_READFUNC_PAUSE;
  
  //fin
  if (NULL == pdata->value)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "CURL: Terminating POST data\n");

    GNUNET_CONTAINER_DLL_remove (ctask->upload_data_head,
                                 ctask->upload_data_tail,
                                 pdata);
    GNUNET_free (pdata);
    return 0;
  }
 
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "CURL: read callback value %s\n", pdata->value); 
  
  to_copy = pdata->bytes_left;
  if (to_copy > len)
    to_copy = len;
  
  pos = pdata->value + (pdata->total_bytes - pdata->bytes_left);
  memcpy (buf, pos, to_copy);
  pdata->bytes_left -= to_copy;
  if (pdata->bytes_left <= 0)
  {
    GNUNET_free (pdata->value);
    GNUNET_CONTAINER_DLL_remove (ctask->upload_data_head,
                                 ctask->upload_data_tail,
                                 pdata);
    GNUNET_free (pdata);
  }
  return to_copy;
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
  if (CURLM_OK != (mret = curl_multi_fdset (curl_multi, &rs, &ws, &es, &max)))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "%s failed at %s:%d: `%s'\n",
                "curl_multi_fdset", __FILE__, __LINE__,
                curl_multi_strerror (mret));
    //TODO cleanup here?
    return;
  }
  to = -1;
  GNUNET_break (CURLM_OK == curl_multi_timeout (curl_multi, &to));
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "cURL multi fds: max=%d timeout=%lld\n", max, (long long) to);
  if (-1 == to)
    rtime = GNUNET_TIME_UNIT_FOREVER_REL;
  else
    rtime = GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MILLISECONDS, to);
  grs = GNUNET_NETWORK_fdset_create ();
  gws = GNUNET_NETWORK_fdset_create ();
  GNUNET_NETWORK_fdset_copy_native (grs, &rs, max + 1);
  GNUNET_NETWORK_fdset_copy_native (gws, &ws, max + 1);
  if (curl_download_task != GNUNET_SCHEDULER_NO_TASK)
    GNUNET_SCHEDULER_cancel (curl_download_task);  
  if (-1 != max)
  {
    curl_download_task =
      GNUNET_SCHEDULER_add_select (GNUNET_SCHEDULER_PRIORITY_DEFAULT,
                                   rtime,
                                   grs, gws,
                                   &curl_task_download, curl_multi);
  }
  else if (NULL != ctasks_head)
  {
    /* as specified in curl docs */
    curl_download_task = GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_MILLISECONDS,
                                                       &curl_task_download,
                                                       curl_multi);
  }
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
  long resp_code;
  struct ProxyCurlTask *clean_head = NULL;
  struct ProxyCurlTask *clean_tail = NULL;

  curl_download_task = GNUNET_SCHEDULER_NO_TASK;

  if (0 != (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
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
    for (ctask = ctasks_head; NULL != ctask; ctask = ctask->next)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "CTask: %s\n", ctask->url);
      num_ctasks++;
    }

    do
    {
      
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
            
           for (ctask = ctasks_head; NULL != ctask; ctask = ctask->next)
           {
             if (NULL == ctask->curl)
               continue;

             if (memcmp (msg->easy_handle, ctask->curl, sizeof (CURL)) != 0)
               continue;
             
             GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                         "CURL: Download failed for task %s: %s.\n",
                         ctask->url,
                         curl_easy_strerror (msg->data.result));
             ctask->download_is_finished = GNUNET_YES;
             ctask->download_error = GNUNET_YES;
             if (CURLE_OK == curl_easy_getinfo (ctask->curl,
                                                CURLINFO_RESPONSE_CODE,
                                                &resp_code))
               ctask->curl_response_code = resp_code;
             ctask->ready_to_queue = MHD_YES;
             ctask->buf_status = BUF_WAIT_FOR_MHD;
             run_mhd_now (ctask->mhd);
             
             GNUNET_CONTAINER_DLL_remove (ctasks_head, ctasks_tail,
                                          ctask);
             GNUNET_CONTAINER_DLL_insert (clean_head, clean_tail, ctask);
             break;
           }
           GNUNET_assert (ctask != NULL);
         }
         else
         {
           GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                       "CURL: download completed.\n");

           for (ctask = ctasks_head; NULL != ctask; ctask = ctask->next)
           {
             if (NULL == ctask->curl)
               continue;

             if (0 != memcmp (msg->easy_handle, ctask->curl, sizeof (CURL)))
               continue;
             
             GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                         "CURL: completed task %s found.\n", ctask->url);
             if (CURLE_OK == curl_easy_getinfo (ctask->curl,
                                                CURLINFO_RESPONSE_CODE,
                                                &resp_code))
               ctask->curl_response_code = resp_code;


             GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                         "CURL: Completed ctask!\n");
             if (GNUNET_SCHEDULER_NO_TASK == ctask->pp_task)
	     {
	       ctask->buf_status = BUF_WAIT_FOR_MHD;
	       run_mhd_now (ctask->mhd);
             }

             ctask->ready_to_queue = MHD_YES;
             ctask->download_is_finished = GNUNET_YES;

             /* We MUST not modify the multi handle else we loose messages */
             GNUNET_CONTAINER_DLL_remove (ctasks_head, ctasks_tail,
                                          ctask);
             GNUNET_CONTAINER_DLL_insert (clean_head, clean_tail, ctask);

             break;
           }
           GNUNET_assert (ctask != NULL);
         }
         GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                     "CURL: %s\n", curl_easy_strerror(msg->data.result));
         break;
       default:
         GNUNET_assert (0);
         break;
      }
    } while (msgnum > 0);

    for (ctask=clean_head; NULL != ctask; ctask = ctask->next)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "CURL: Removing task %s.\n", ctask->url);
      curl_multi_remove_handle (curl_multi, ctask->curl);
      curl_easy_cleanup (ctask->curl);
      ctask->curl = NULL;
    }
    
    num_ctasks=0;
    for (ctask=ctasks_head; NULL != ctask; ctask = ctask->next)    
      num_ctasks++; 
    GNUNET_assert (num_ctasks == running);

  } while (mret == CURLM_CALL_MULTI_PERFORM);
  
  if (mret != CURLM_OK)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "CURL: %s failed at %s:%d: `%s'\n",
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

  strcpy (ctask->leho, "");

  if (rd_count == 0)
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "No LEHO present!\n");

  for (i=0; i<rd_count; i++)
  {
    if (rd[i].record_type != GNUNET_NAMESTORE_TYPE_LEHO)
      continue;

    memcpy (ctask->leho, rd[i].data, rd[i].data_size);

    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Found LEHO %s for %s\n", ctask->leho, ctask->url);
  }

  if (0 != strcmp (ctask->leho, ""))
  {
    sprintf (hosthdr, "%s%s:%d", "Host: ", ctask->leho, ctask->port);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "New HTTP header value: %s\n", hosthdr);
    ctask->headers = curl_slist_append (ctask->headers, hosthdr);
    GNUNET_assert (NULL != ctask->headers);
    if (CURLE_OK != (ret = curl_easy_setopt (ctask->curl, CURLOPT_HTTPHEADER, ctask->headers)))
      LOG_CURL_EASY(GNUNET_ERROR_TYPE_WARNING,"curl_easy_setopt",ret);
  }

  if (ctask->mhd->is_ssl)
  {
    phost = (struct hostent*)gethostbyname (ctask->host);

    if (phost!=NULL)
    {
      ssl_ip = inet_ntoa(*((struct in_addr*)(phost->h_addr)));
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "SSL target server: %s\n", ssl_ip);
      sprintf (resolvename, "%s:%d:%s", ctask->leho, HTTPS_PORT, ssl_ip);
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Curl resolve: %s\n", resolvename);
      ctask->resolver = curl_slist_append ( ctask->resolver, resolvename);
      if (CURLE_OK != (ret = curl_easy_setopt (ctask->curl, CURLOPT_RESOLVE, ctask->resolver)))
	LOG_CURL_EASY(GNUNET_ERROR_TYPE_WARNING,"curl_easy_setopt",ret);
      sprintf (curlurl, "https://%s:%d%s", ctask->leho, ctask->port, ctask->url);
      if (CURLE_OK != (ret = curl_easy_setopt (ctask->curl, CURLOPT_URL, curlurl)))
	LOG_CURL_EASY(GNUNET_ERROR_TYPE_WARNING,"curl_easy_setopt",ret);
    }
    else
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  "gethostbyname failed for %s!\n",
		  ctask->host);
      ctask->download_is_finished = GNUNET_YES;
      ctask->download_error = GNUNET_YES;
      return;
    }
  }

  if (CURLM_OK != (mret=curl_multi_add_handle (curl_multi, ctask->curl)))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "%s failed at %s:%d: `%s'\n",
                "curl_multi_add_handle", __FILE__, __LINE__,
                curl_multi_strerror (mret));
    ctask->download_is_finished = GNUNET_YES;
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
  else
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Get authority yielded %s\n", auth_name);
    strcpy (ctask->authority, auth_name);
  }

  GNUNET_GNS_lookup (gns_handle,
		     ctask->host,
		     &local_gns_zone,
		     GNUNET_NAMESTORE_TYPE_LEHO,
		     GNUNET_YES /* Only cached for performance */,
		     &shorten_zonekey,
		     &process_leho_lookup,
		     ctask);
}


static void*
mhd_log_callback (void* cls, 
		  const char* url)
{
  struct ProxyCurlTask *ctask;

  ctask = GNUNET_new (struct ProxyCurlTask);
  strcpy (ctask->url, url);
  return ctask;
}


/**
 * Main MHD callback for handling requests.
 *
 * @param cls unused
 * @param con MHD connection handle
 * @param url the url in the request
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
 *        @a upload_data provided; the method must update this
 *        value to the number of bytes NOT processed;
 * @param con_cls pointer to location where we store the 'struct Request'
 * @return #MHD_YES if the connection was handled successfully,
 *         #MHD_NO if the socket must be closed due to a serious
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
  struct MhdHttpList* hd = cls;  
  char curlurl[MAX_HTTP_URI_LENGTH]; // buffer overflow!
  int ret = MHD_YES;
  int i;
  struct ProxyCurlTask *ctask = *con_cls;
  struct ProxyUploadData *fin_post;
  struct curl_forms forms[5];
  struct ProxyUploadData *upload_data_iter;
  
  //FIXME handle
  if ((0 != strcasecmp (meth, MHD_HTTP_METHOD_GET)) &&
      (0 != strcasecmp (meth, MHD_HTTP_METHOD_PUT)) &&
      (0 != strcasecmp (meth, MHD_HTTP_METHOD_POST)) &&
      (0 != strcasecmp (meth, MHD_HTTP_METHOD_HEAD)))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "MHD: %s NOT IMPLEMENTED!\n", meth);
    return MHD_NO;
  }


  if (GNUNET_NO == ctask->accepted)
  {

    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                "Got %s request for %s\n", meth, url);
    ctask->mhd = hd;
    ctask->curl = curl_easy_init();
    ctask->curl_running = GNUNET_NO;
    if (NULL == ctask->curl)
    {
      ret = MHD_queue_response (con,
                                MHD_HTTP_OK,
                                curl_failure_response);
      GNUNET_free (ctask);
      return ret;
    }
    
    if (ctask->mhd->is_ssl)
      ctask->port = HTTPS_PORT;
    else
      ctask->port = HTTP_PORT;

    MHD_get_connection_values (con,
                               MHD_HEADER_KIND,
                               &con_val_iter, ctask);
    
    curl_easy_setopt (ctask->curl, CURLOPT_HEADERFUNCTION, &curl_check_hdr);
    curl_easy_setopt (ctask->curl, CURLOPT_HEADERDATA, ctask);
    curl_easy_setopt (ctask->curl, CURLOPT_WRITEFUNCTION, &curl_download_cb);
    curl_easy_setopt (ctask->curl, CURLOPT_WRITEDATA, ctask);
    curl_easy_setopt (ctask->curl, CURLOPT_FOLLOWLOCATION, 0);
    curl_easy_setopt (ctask->curl, CURLOPT_IPRESOLVE, CURL_IPRESOLVE_V4);

    if (GNUNET_NO == ctask->mhd->is_ssl)
    {
      sprintf (curlurl, "http://%s:%d%s", ctask->host, ctask->port, ctask->url);
      curl_easy_setopt (ctask->curl, CURLOPT_URL, curlurl);
    }
    

    curl_easy_setopt (ctask->curl, CURLOPT_FAILONERROR, 1);
    curl_easy_setopt (ctask->curl, CURLOPT_CONNECTTIMEOUT, 600L);
    curl_easy_setopt (ctask->curl, CURLOPT_TIMEOUT, 600L);
    
    /* Add GNS header */
    ctask->headers = curl_slist_append (ctask->headers,
                                          "GNS: YES");
    ctask->accepted = GNUNET_YES;
    ctask->download_in_progress = GNUNET_YES;
    ctask->buf_status = BUF_WAIT_FOR_CURL;
    ctask->connection = con;
    ctask->curl_response_code = MHD_HTTP_OK;
    ctask->buffer_read_ptr = ctask->buffer;
    ctask->buffer_write_ptr = ctask->buffer;
    ctask->pp_task = GNUNET_SCHEDULER_NO_TASK;
    

    if (0 == strcasecmp (meth, MHD_HTTP_METHOD_PUT))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Setting up PUT\n");
      
      curl_easy_setopt (ctask->curl, CURLOPT_UPLOAD, 1);
      curl_easy_setopt (ctask->curl, CURLOPT_READDATA, ctask);
      curl_easy_setopt (ctask->curl, CURLOPT_READFUNCTION, &put_read_callback);
      ctask->headers = curl_slist_append (ctask->headers,
                                          "Transfer-Encoding: chunked");
    }

    if (0 == strcasecmp (meth, MHD_HTTP_METHOD_POST))
    {
      //FIXME handle multipart
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Setting up POST processor\n");
      ctask->post_handler = MHD_create_post_processor (con,
						       POSTBUFFERSIZE,
						       &con_post_data_iter,
						       ctask);
      ctask->headers = curl_slist_append (ctask->headers,
                                         "Transfer-Encoding: chunked");
      return MHD_YES;
    }

    if (0 == strcasecmp (meth, MHD_HTTP_METHOD_HEAD))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Setting NOBODY\n");
      curl_easy_setopt (ctask->curl, CURLOPT_NOBODY, 1);
    }

    
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "MHD: Adding new curl task for %s\n", ctask->host);

    GNUNET_GNS_get_authority (gns_handle,
                              ctask->host,
                              &process_get_authority,
                              ctask);
    ctask->ready_to_queue = GNUNET_NO;
    ctask->fin = GNUNET_NO;
    ctask->curl_running = GNUNET_YES;
    return MHD_YES;
  }

  ctask = (struct ProxyCurlTask *) *con_cls;
  if (0 == strcasecmp (meth, MHD_HTTP_METHOD_POST))
  {
    if (0 != *upload_data_size)
    {
      
      GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                  "Invoking POST processor\n");
      MHD_post_process (ctask->post_handler,
                        upload_data, *upload_data_size);
      *upload_data_size = 0;
      if ((GNUNET_NO == ctask->is_httppost) &&
          (GNUNET_NO == ctask->curl_running))
      {
        curl_easy_setopt (ctask->curl, CURLOPT_POST, 1);
        curl_easy_setopt (ctask->curl, CURLOPT_READFUNCTION,
                          &post_read_callback);
        curl_easy_setopt (ctask->curl, CURLOPT_READDATA, ctask);
        
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "MHD: Adding new curl task for %s\n", ctask->host);

        GNUNET_GNS_get_authority (gns_handle,
                                  ctask->host,
                                  &process_get_authority,
                                  ctask);
        ctask->ready_to_queue = GNUNET_NO;
        ctask->fin = GNUNET_NO;
        ctask->curl_running = GNUNET_YES;
      }
      return MHD_YES;
    }
    else if (GNUNET_NO == ctask->post_done)
    {
      if (GNUNET_YES == ctask->is_httppost)
      {
        for (upload_data_iter = ctask->upload_data_head;
             NULL != upload_data_iter;
             upload_data_iter = upload_data_iter->next)
        {
          i = 0;
          if (NULL != upload_data_iter->filename)
          {
            forms[i].option = CURLFORM_FILENAME;
            forms[i].value = upload_data_iter->filename;
            GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                        "Adding filename %s\n",
                        forms[i].value);
            i++;
          }
          if (NULL != upload_data_iter->content_type)
          {
            forms[i].option = CURLFORM_CONTENTTYPE;
            forms[i].value = upload_data_iter->content_type;
            GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                        "Adding content type %s\n",
                        forms[i].value);
            i++;
          }
          forms[i].option = CURLFORM_PTRCONTENTS;
          forms[i].value = upload_data_iter->value;
          forms[i+1].option = CURLFORM_END;

          GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                      "Adding formdata for %s (len=%lld)\n",
                      upload_data_iter->key,
                      upload_data_iter->total_bytes);

          curl_formadd(&ctask->httppost, &ctask->httppost_last,
                       CURLFORM_COPYNAME, upload_data_iter->key,
                       CURLFORM_CONTENTSLENGTH, upload_data_iter->total_bytes,
                       CURLFORM_ARRAY, forms,
                       CURLFORM_END);
        }
        curl_easy_setopt (ctask->curl, CURLOPT_HTTPPOST,
                          ctask->httppost);

        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "MHD: Adding new curl task for %s\n", ctask->host);

        GNUNET_GNS_get_authority (gns_handle,
                                  ctask->host,
                                  &process_get_authority,
                                  ctask);
        ctask->ready_to_queue = GNUNET_YES;
        ctask->fin = GNUNET_NO;
        ctask->curl_running = GNUNET_YES;
        ctask->post_done = GNUNET_YES;
        return MHD_YES;
      }

      fin_post = GNUNET_new (struct ProxyUploadData);
      GNUNET_CONTAINER_DLL_insert_tail (ctask->upload_data_head,
                                        ctask->upload_data_tail,
                                        fin_post);
      ctask->post_done = GNUNET_YES;
      return MHD_YES;
    }
  }
  
  if (GNUNET_YES != ctask->ready_to_queue)
    return MHD_YES; /* wait longer */
  
  if (GNUNET_YES == ctask->fin)
    return MHD_YES;

  ctask->fin = GNUNET_YES;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "MHD: Queueing response for %s\n", ctask->url);
  ret = MHD_queue_response (con, ctask->curl_response_code, ctask->response);
  run_mhd_now (ctask->mhd);
  return ret;
}


/**
 * run all httpd
 */
static void
run_httpds ()
{
  struct MhdHttpList *hd;

  for (hd=mhd_httpd_head; NULL != hd; hd = hd->next)
    run_httpd (hd);

}


/**
 * schedule mhd
 *
 * @param hd the daemon to run
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
  MHD_UNSIGNED_LONG_LONG timeout;
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

  if (MHD_YES == haveto)
    tv.rel_value_us = (uint64_t) timeout * 1000LL;
  else
    tv = GNUNET_TIME_UNIT_FOREVER_REL;
  GNUNET_NETWORK_fdset_copy_native (wrs, &rs, max + 1);
  GNUNET_NETWORK_fdset_copy_native (wws, &ws, max + 1);
  GNUNET_NETWORK_fdset_copy_native (wes, &es, max + 1);
  
  if (GNUNET_SCHEDULER_NO_TASK != hd->httpd_task)
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
  
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "MHD: Main loop\n");
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
do_s5r_read (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc);


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
  if ( (NULL != tc->read_ready) &&
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
    GNUNET_log_strerror (GNUNET_ERROR_TYPE_WARNING, "send");
    cleanup_s5r (s5r);
    return;
  }

  s5r->rtask =
    GNUNET_SCHEDULER_add_read_net (GNUNET_TIME_UNIT_FOREVER_REL,
                                   s5r->sock,
                                   &do_s5r_read, s5r);
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
    if (0 == s5r->wbuf_len)
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "0 bytes received from remote... graceful shutdown!\n");
    cleanup_s5r (s5r);
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
 * @param daemon the daemon to add the fd to
 * @return whatever #MHD_add_connection returns
 */
static int
add_handle_to_mhd (struct GNUNET_NETWORK_Handle *h, struct MHD_Daemon *daemon)
{
  int fd;
  struct sockaddr *addr;
  socklen_t len;

  fd = dup (GNUNET_NETWORK_get_fd (h));
  addr = GNUNET_NETWORK_get_addr (h);
  len = GNUNET_NETWORK_get_addrlen (h);

  return MHD_add_connection (daemon, fd, addr, len);
}


/**
 * Read file in filename
 *
 * @param filename file to read
 * @param size pointer where filesize is stored
 * @return NULL on error
 */
static void*
load_file (const char* filename, 
	   unsigned int* size)
{
  void *buffer;
  uint64_t fsize;

  if (GNUNET_OK !=
      GNUNET_DISK_file_size (filename, &fsize,
			     GNUNET_YES, GNUNET_YES))
    return NULL;
  if (fsize > MAX_PEM_SIZE)
    return NULL;
  *size = (unsigned int) fsize;
  buffer = GNUNET_malloc (*size);
  if (fsize != GNUNET_DISK_fn_read (filename, buffer, (size_t) fsize))
  {
    GNUNET_free (buffer);
    return NULL;
  }
  return buffer;
}


/**
 * Load PEM key from file
 *
 * @param key where to store the data
 * @param keyfile path to the PEM file
 * @return GNUNET_OK on success
 */
static int
load_key_from_file (gnutls_x509_privkey_t key, const char* keyfile)
{
  gnutls_datum_t key_data;
  int ret;

  key_data.data = load_file (keyfile, &key_data.size);
  ret = gnutls_x509_privkey_import (key, &key_data,
                                    GNUTLS_X509_FMT_PEM);
  if (GNUTLS_E_SUCCESS != ret)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _("Unable to import private key from file `%s'\n"),
		keyfile);
    GNUNET_break (0);
  }
  GNUNET_free (key_data.data);
  return (GNUTLS_E_SUCCESS != ret) ? GNUNET_SYSERR : GNUNET_OK;
}


/**
 * Load cert from file
 *
 * @param crt struct to store data in
 * @param certfile path to pem file
 * @return #GNUNET_OK on success
 */
static int
load_cert_from_file (gnutls_x509_crt_t crt, char* certfile)
{
  gnutls_datum_t cert_data;
  int ret;

  cert_data.data = load_file (certfile, &cert_data.size);
  ret = gnutls_x509_crt_import (crt, &cert_data,
                                GNUTLS_X509_FMT_PEM);
  if (GNUTLS_E_SUCCESS != ret)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
               _("Unable to import certificate %s\n"), certfile);
    GNUNET_break (0);
  }
  GNUNET_free (cert_data.data);
  return (GNUTLS_E_SUCCESS != ret) ? GNUNET_SYSERR : GNUNET_OK;
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
  size_t key_buf_size;
  size_t cert_buf_size;
  gnutls_x509_crt_t request;
  time_t etime;
  struct tm *tm_data;

  ret = gnutls_x509_crt_init (&request);

  if (GNUTLS_E_SUCCESS != ret)
  {
    GNUNET_break (0);
  }

  GNUNET_break (GNUTLS_E_SUCCESS == gnutls_x509_crt_set_key (request, proxy_ca.key));

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Generating cert\n");

  struct ProxyGNSCertificate *pgc =
    GNUNET_new (struct ProxyGNSCertificate);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Adding DNs\n");
  
  gnutls_x509_crt_set_dn_by_oid (request, GNUTLS_OID_X520_COUNTRY_NAME,
                                 0, "DE", 2);
  gnutls_x509_crt_set_dn_by_oid (request, GNUTLS_OID_X520_ORGANIZATION_NAME,
                                 0, "GADS", 4);
  gnutls_x509_crt_set_dn_by_oid (request, GNUTLS_OID_X520_COMMON_NAME,
                                 0, name, strlen (name));
  GNUNET_break (GNUTLS_E_SUCCESS == gnutls_x509_crt_set_version (request, 3));

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

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Exporting certificate...\n");
  
  gnutls_x509_crt_export (request, GNUTLS_X509_FMT_PEM,
                          pgc->cert, &cert_buf_size);

  gnutls_x509_privkey_export (proxy_ca.key, GNUTLS_X509_FMT_PEM,
                          pgc->key, &key_buf_size);


  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Cleaning up\n");
  gnutls_x509_crt_deinit (request);

  return pgc;

}


/**
 * Accept policy for mhdaemons
 *
 * @param cls NULL
 * @param addr the sockaddr
 * @param addrlen the sockaddr length
 * @return MHD_NO if sockaddr is wrong or number of connections is too high
 */
static int
accept_cb (void* cls, const struct sockaddr *addr, socklen_t addrlen)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "In MHD accept policy cb\n");

  if (addr != NULL)
  {
    if (addr->sa_family == AF_UNIX)
      return MHD_NO;
  }

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Connection accepted\n");

  return MHD_YES;
}


/**
 * Adds a socket to an SSL MHD instance It is important that the
 * domain name is correct. In most cases we need to start a new daemon.
 *
 * @param h the handle to add to a daemon
 * @param domain the domain the SSL daemon has to serve
 * @return #MHD_YES on success
 */
static int
add_handle_to_ssl_mhd (struct GNUNET_NETWORK_Handle *h, 
		       const char* domain)
{
  struct MhdHttpList *hd;
  struct ProxyGNSCertificate *pgc;

  for (hd = mhd_httpd_head; NULL != hd; hd = hd->next)
    if (0 == strcmp (hd->domain, domain))
      break;
  if (NULL == hd)
  {    
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Starting fresh MHD HTTPS instance for domain `%s'\n",
                domain);
    pgc = generate_gns_certificate (domain);   
    hd = GNUNET_new (struct MhdHttpList);
    hd->is_ssl = GNUNET_YES;
    strcpy (hd->domain, domain); /* FIXME: avoid fixed-sized buffers... */
    hd->proxy_cert = pgc;
    hd->daemon = MHD_start_daemon (MHD_USE_DEBUG | MHD_USE_SSL | MHD_USE_NO_LISTEN_SOCKET,
                                   0,
                                   &accept_cb, NULL,
                                   &create_response, hd,
                                   MHD_OPTION_CONNECTION_LIMIT,
                                   MHD_MAX_CONNECTIONS,
				   MHD_OPTION_CONNECTION_TIMEOUT, (unsigned int) 16,
				   MHD_OPTION_NOTIFY_COMPLETED, NULL, NULL,
				   MHD_OPTION_HTTPS_MEM_KEY, pgc->key,
				   MHD_OPTION_HTTPS_MEM_CERT, pgc->cert,
				   MHD_OPTION_URI_LOG_CALLBACK, &mhd_log_callback,
				   NULL,
				   MHD_OPTION_END);
    /* FIXME: rather than assert, handle error! */
    GNUNET_assert (NULL != hd->daemon);
    GNUNET_CONTAINER_DLL_insert (mhd_httpd_head, mhd_httpd_tail, hd);
  }
  return add_handle_to_mhd (h, hd->daemon);
}


/**
 * Read data from incoming Socks5 connection
 *
 * @param cls the closure with the `struct Socks5Request`
 * @param tc the scheduler context
 */
static void
do_s5r_read (void* cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
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
  if ( (NULL != tc->read_ready) &&
       (GNUNET_NETWORK_fdset_isset (tc->read_ready, s5r->sock)) )
    s5r->rbuf_len = GNUNET_NETWORK_socket_recv (s5r->sock, s5r->rbuf,
						sizeof (s5r->rbuf));
  else
    s5r->rbuf_len = 0;
  if (0 == s5r->rbuf_len)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, 
		"socks5 client disconnected.\n");
    cleanup_s5r (s5r);
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Processing socks data in state %d\n",
	      s5r->state);
  switch (s5r->state)
  {
  case SOCKS5_INIT:
    /* FIXME: failed to check if we got enough data yet! */
    c_hello = (struct socks5_client_hello*) &s5r->rbuf;
    GNUNET_assert (c_hello->version == SOCKS_VERSION_5);
    s_hello = (struct socks5_server_hello*) &s5r->wbuf;
    s5r->wbuf_len = sizeof( struct socks5_server_hello );
    s_hello->version = c_hello->version;
    s_hello->auth_method = SOCKS_AUTH_NONE;
    /* Write response to client */
    s5r->wtask = GNUNET_SCHEDULER_add_write_net (GNUNET_TIME_UNIT_FOREVER_REL,
						 s5r->sock,
						 &do_write, s5r);
    s5r->rtask = GNUNET_SCHEDULER_add_read_net (GNUNET_TIME_UNIT_FOREVER_REL,
                                                s5r->sock,
                                                &do_s5r_read, s5r);
    s5r->state = SOCKS5_REQUEST;
    return;
  case SOCKS5_REQUEST:
    /* FIXME: failed to check if we got enough data yet!? */
    c_req = (struct socks5_client_request *) &s5r->rbuf;
    s_resp = (struct socks5_server_response *) &s5r->wbuf;
    //Only 10 byte for ipv4 response!
    s5r->wbuf_len = 10;//sizeof (struct socks5_server_response);
    GNUNET_assert (c_req->addr_type == 3);
    dom_len = *((uint8_t*)(&(c_req->addr_type) + 1));
    memset(domain, 0, sizeof(domain));
    strncpy(domain, (char*)(&(c_req->addr_type) + 2), dom_len);
    req_port = *((uint16_t*)(&(c_req->addr_type) + 2 + dom_len));
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Requested connection is to %s:%d\n",
                domain,
                ntohs(req_port));
    if (is_tld (domain, GNUNET_GNS_TLD) ||
        is_tld (domain, GNUNET_GNS_TLD_ZKEY))
    {
      /* GNS TLD */
      ret = MHD_NO;
      if (ntohs (req_port) == HTTPS_PORT)
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
      /* non-GNS TLD, use DNS to resolve */
      /* FIXME: make asynchronous! */
      phost = (struct hostent *) gethostbyname (domain);
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
                                       &do_s5r_read, s5r);
    }
    return;
  case SOCKS5_DATA_TRANSFER:
    {
      if ((s5r->remote_sock == NULL) || (s5r->rbuf_len == 0))
      {
	GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		    "Closing connection to client\n");
	cleanup_s5r (s5r);
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
    return;
  default:
    GNUNET_break (0);
    return;
  }
}


/**
 * Accept new incoming connections
 *
 * @param cls the closure
 * @param tc the scheduler context
 */
static void
do_accept (void *cls, 
	   const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_NETWORK_Handle *s;
  struct Socks5Request *s5r;

  ltask = GNUNET_SCHEDULER_add_read_net (GNUNET_TIME_UNIT_FOREVER_REL,
                                         lsock,
                                         &do_accept, NULL);
  s = GNUNET_NETWORK_socket_accept (lsock, NULL, NULL);
  if (NULL == s)
  {
    GNUNET_log_strerror (GNUNET_ERROR_TYPE_ERROR, "accept");
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Got an inbound connection, waiting for data\n");
  s5r = GNUNET_new (struct Socks5Request);
  GNUNET_CONTAINER_DLL_insert (s5r_head,
			       s5r_tail,
			       s5r);
  s5r->sock = s;
  s5r->state = SOCKS5_INIT;
  s5r->rtask = GNUNET_SCHEDULER_add_read_net (GNUNET_TIME_UNIT_FOREVER_REL,
                                              s5r->sock,
                                              &do_s5r_read, s5r);
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
  struct ProxyUploadData *pdata;
  
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "Shutting down...\n");
  for (hd = mhd_httpd_head; NULL != hd; hd = tmp_hd)
  {
    tmp_hd = hd->next;
    if (GNUNET_SCHEDULER_NO_TASK != hd->httpd_task)
    {
      GNUNET_SCHEDULER_cancel (hd->httpd_task);
      hd->httpd_task = GNUNET_SCHEDULER_NO_TASK;
    }
    if (NULL != hd->daemon)
    {
      MHD_stop_daemon (hd->daemon);
      hd->daemon = NULL;
    }
    GNUNET_free_non_null (hd->proxy_cert);
    GNUNET_free (hd);
  }
  for (ctask=ctasks_head; ctask != NULL; ctask=ctask_tmp)
  {
    ctask_tmp = ctask->next;
    if (NULL != ctask->curl)
    {
      curl_easy_cleanup (ctask->curl);
      ctask->curl = NULL;
    }
    if (NULL != ctask->headers)
    {
      curl_slist_free_all (ctask->headers);
      ctask->headers = NULL;
    }
    if (NULL != ctask->resolver)
    {
      curl_slist_free_all (ctask->resolver);
      ctask->resolver = NULL;
    }
    if (NULL != ctask->response)
    {
      MHD_destroy_response (ctask->response);
      ctask->response = NULL;
    }    
    for (pdata = ctask->upload_data_head; NULL != pdata; pdata = ctask->upload_data_head)
    {
      GNUNET_CONTAINER_DLL_remove (ctask->upload_data_head,
                                   ctask->upload_data_tail,
                                   pdata);
      GNUNET_free_non_null (pdata->filename);
      GNUNET_free_non_null (pdata->content_type);
      GNUNET_free_non_null (pdata->key);
      GNUNET_free_non_null (pdata->value);
      GNUNET_free (pdata);
    }
    GNUNET_free (ctask);
  }
  if (NULL != lsock)
  {
    GNUNET_NETWORK_socket_close (lsock);
    lsock = NULL;
  }
  if (NULL != id_op)
  {
    GNUNET_IDENTITY_cancel (id_op);
    id_op = NULL;
  }
  if (NULL != identity)
  {
    GNUNET_IDENTITY_disconnect (identity);
    identity = NULL;
  }
  if (NULL != curl_multi)
  {
    curl_multi_cleanup (curl_multi);
    curl_multi = NULL;
  }
  if (NULL != gns_handle)
  {
    GNUNET_GNS_disconnect (gns_handle);
    gns_handle = NULL;
  }
  if (GNUNET_SCHEDULER_NO_TASK != curl_download_task)
  {
    GNUNET_SCHEDULER_cancel (curl_download_task);
    curl_download_task = GNUNET_SCHEDULER_NO_TASK;
  }
  if (GNUNET_SCHEDULER_NO_TASK != ltask)
  {
    GNUNET_SCHEDULER_cancel (ltask);
    ltask = GNUNET_SCHEDULER_NO_TASK;
  }
  gnutls_global_deinit ();
}


/**
 * Continue initialization after we have our zone information.
 */
static void 
run_cont () 
{
  struct MhdHttpList *hd;
  struct sockaddr_in sa;

  /* Open listen socket for socks proxy */
  /* FIXME: support IPv6! */
  memset (&sa, 0, sizeof (sa));
  sa.sin_family = AF_INET;
  sa.sin_port = htons (port);
#if HAVE_SOCKADDR_IN_SIN_LEN
  sa.sin_len = sizeof (sa);
#endif
  lsock = GNUNET_NETWORK_socket_create (AF_INET,
					SOCK_STREAM,
					0);
  if (NULL == lsock) 
  {
    GNUNET_log_strerror (GNUNET_ERROR_TYPE_ERROR, "socket");
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  if (GNUNET_OK !=
      GNUNET_NETWORK_socket_bind (lsock, (const struct sockaddr *) &sa,
				  sizeof (sa), 0))
  {
    GNUNET_log_strerror (GNUNET_ERROR_TYPE_ERROR, "bind");
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  if (GNUNET_OK != GNUNET_NETWORK_socket_listen (lsock, 5))
  {
    GNUNET_log_strerror (GNUNET_ERROR_TYPE_ERROR, "listen");
    return;
  }
  ltask = GNUNET_SCHEDULER_add_read_net (GNUNET_TIME_UNIT_FOREVER_REL,
                                         lsock, &do_accept, NULL);

  if (0 != curl_global_init (CURL_GLOBAL_WIN32))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "cURL global init failed!\n");
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Proxy listens on port %u\n",
              port);

  /* start MHD daemon for HTTP */
  hd = GNUNET_new (struct MhdHttpList);
  strcpy (hd->domain, "");
  hd->daemon = MHD_start_daemon (MHD_USE_DEBUG | MHD_USE_NO_LISTEN_SOCKET,
				 0,
				 &accept_cb, NULL,
				 &create_response, hd,
				 MHD_OPTION_CONNECTION_LIMIT, MHD_MAX_CONNECTIONS,
				 MHD_OPTION_CONNECTION_TIMEOUT, (unsigned int) 16,
				 MHD_OPTION_NOTIFY_COMPLETED, NULL, NULL,
				 MHD_OPTION_URI_LOG_CALLBACK, &mhd_log_callback, NULL,
				 MHD_OPTION_END);
  if (NULL == hd->daemon)
  {
    GNUNET_free (hd);
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  httpd = hd->daemon;
  GNUNET_CONTAINER_DLL_insert (mhd_httpd_head, mhd_httpd_tail, hd);

  /* start loop running all MHD instances */
  run_httpds ();
}


/** 
 * Method called to inform about the egos of the shorten zone of this peer.
 *
 * When used with #GNUNET_IDENTITY_create or #GNUNET_IDENTITY_get,
 * this function is only called ONCE, and 'NULL' being passed in
 * @a ego does indicate an error (i.e. name is taken or no default
 * value is known).  If @a ego is non-NULL and if '*ctx'
 * is set in those callbacks, the value WILL be passed to a subsequent
 * call to the identity callback of #GNUNET_IDENTITY_connect (if 
 * that one was not NULL).
 *
 * @param cls closure, NULL
 * @param ego ego handle
 * @param ctx context for application to store data for this ego
 *                 (during the lifetime of this process, initially NULL)
 * @param name name assigned by the user for this ego,
 *                   NULL if the user just deleted the ego and it
 *                   must thus no longer be used
 */
static void
identity_shorten_cb (void *cls,
		     struct GNUNET_IDENTITY_Ego *ego,
		     void **ctx,
		     const char *name)
{
  id_op = NULL;
  if (NULL == ego)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
		_("No ego configured for `shorten-zone`\n"));
  }
  else
  {
    local_shorten_zone = *GNUNET_IDENTITY_ego_get_private_key (ego);
    do_shorten = GNUNET_YES;
  }
  run_cont ();
}


/** 
 * Method called to inform about the egos of the master zone of this peer.
 *
 * When used with #GNUNET_IDENTITY_create or #GNUNET_IDENTITY_get,
 * this function is only called ONCE, and 'NULL' being passed in
 * @a ego does indicate an error (i.e. name is taken or no default
 * value is known).  If @a ego is non-NULL and if '*ctx'
 * is set in those callbacks, the value WILL be passed to a subsequent
 * call to the identity callback of #GNUNET_IDENTITY_connect (if 
 * that one was not NULL).
 *
 * @param cls closure, NULL
 * @param ego ego handle
 * @param ctx context for application to store data for this ego
 *                 (during the lifetime of this process, initially NULL)
 * @param name name assigned by the user for this ego,
 *                   NULL if the user just deleted the ego and it
 *                   must thus no longer be used
 */
static void
identity_master_cb (void *cls,
		    struct GNUNET_IDENTITY_Ego *ego,
		    void **ctx,
		    const char *name)
{
  id_op = NULL;
  if (NULL == ego)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		_("No ego configured for `master-zone`\n"));
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  GNUNET_IDENTITY_ego_get_public_key (ego,
				      &local_gns_zone);
  id_op = GNUNET_IDENTITY_get (identity,
			       "shorten-zone",
			       &identity_shorten_cb,
			       NULL);
}


/**
 * Main function that will be run
 *
 * @param cls closure
 * @param args remaining command-line arguments
 * @param cfgfile name of the configuration file used (for saving, can be NULL!)
 * @param c configuration
 */
static void
run (void *cls, char *const *args, const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *c)
{
  char* cafile_cfg = NULL;
  char* cafile;

  cfg = c;
  if (NULL == (curl_multi = curl_multi_init ()))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Failed to create cURL multi handle!\n");
    return;
  } 
  cafile = cafile_opt;
  if (NULL == cafile)
  {
    if (GNUNET_OK != GNUNET_CONFIGURATION_get_value_filename (cfg, "gns-proxy",
							      "PROXY_CACERT",
							      &cafile_cfg))
    {
      GNUNET_log_config_missing (GNUNET_ERROR_TYPE_ERROR,
				 "gns-proxy",
				 "PROXY_CACERT");
      return;
    }
    cafile = cafile_cfg;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Using %s as CA\n", cafile);
  
  gnutls_global_init ();
  gnutls_x509_crt_init (&proxy_ca.cert);
  gnutls_x509_privkey_init (&proxy_ca.key);
  
  if ( (GNUNET_OK != load_cert_from_file (proxy_ca.cert, cafile)) ||
       (GNUNET_OK != load_key_from_file (proxy_ca.key, cafile)) )
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		_("Failed to load SSL/TLS key and certificate from `%s'\n"),
		cafile);
    // FIXME: release resources...
    GNUNET_free_non_null (cafile_cfg);  
    return;
  }
  GNUNET_free_non_null (cafile_cfg);
  if (NULL == (gns_handle = GNUNET_GNS_connect (cfg)))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Unable to connect to GNS!\n");
    return;
  }
  identity = GNUNET_IDENTITY_connect (cfg,
				      NULL, NULL);  
  id_op = GNUNET_IDENTITY_get (identity,
			       "master-zone",
			       &identity_master_cb,
			       NULL);  
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
     gettext_noop ("listen on specified port (default: 7777)"), 1,
     &GNUNET_GETOPT_set_ulong, &port},
    {'a', "authority", NULL,
      gettext_noop ("pem file to use as CA"), 1,
      &GNUNET_GETOPT_set_string, &cafile_opt},
    GNUNET_GETOPT_OPTION_END
  };
  static const char* page = 
    "<html><head><title>gnunet-gns-proxy</title>"
    "</head><body>cURL fail</body></html>";
  int ret;

  if (GNUNET_OK != GNUNET_STRINGS_get_utf8_args (argc, argv, &argc, &argv))
    return 2;
  GNUNET_log_setup ("gnunet-gns-proxy", "WARNING", NULL);
  curl_failure_response = MHD_create_response_from_buffer (strlen (page),
							   (void*)page,
							   MHD_RESPMEM_PERSISTENT);

  ret =
      (GNUNET_OK ==
       GNUNET_PROGRAM_run (argc, argv, "gnunet-gns-proxy",
                           _("GNUnet GNS proxy"),
                           options,
                           &run, NULL)) ? 0 : 1;
  MHD_destroy_response (curl_failure_response);
  GNUNET_free_non_null ((char *) argv);
  return ret;
}

/* end of gnunet-gns-proxy.c */

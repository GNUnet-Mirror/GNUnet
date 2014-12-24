/*
     This file is part of GNUnet.
     (C) 2012-2014 Christian Grothoff (and other contributing authors)

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
 * @author Christian Grothoff
 * @file src/gns/gnunet-gns-proxy.c
 * @brief HTTP(S) proxy that rewrites URIs and fakes certificats to make GNS work
 *        with legacy browsers
 *
 * TODO:
 * - double-check queueing logic
 */
#include "platform.h"
#include <microhttpd.h>
#include <curl/curl.h>
#include <gnutls/gnutls.h>
#include <gnutls/x509.h>
#include <gnutls/abstract.h>
#include <gnutls/crypto.h>
#if HAVE_GNUTLS_DANE
#include <gnutls/dane.h>
#endif
#include <regex.h>
#include "gnunet_util_lib.h"
#include "gnunet_gns_service.h"
#include "gnunet_identity_service.h"
#include "gns.h"


/**
 * Default Socks5 listen port.
 */
#define GNUNET_GNS_PROXY_PORT 7777

/**
 * Maximum supported length for a URI.
 * Should die. @deprecated
 */
#define MAX_HTTP_URI_LENGTH 2048

/**
 * Size of the buffer for the data upload / download.  Must be
 * enough for curl, thus CURL_MAX_WRITE_SIZE is needed here (16k).
 */
#define IO_BUFFERSIZE CURL_MAX_WRITE_SIZE

/**
 * Size of the read/write buffers for Socks.   Uses
 * 256 bytes for the hostname (at most), plus a few
 * bytes overhead for the messages.
 */
#define SOCKS_BUFFERSIZE (256 + 32)

/**
 * Port for plaintext HTTP.
 */
#define HTTP_PORT 80

/**
 * Port for HTTPS.
 */
#define HTTPS_PORT 443

/**
 * Largest allowed size for a PEM certificate.
 */
#define MAX_PEM_SIZE (10 * 1024)

/**
 * After how long do we clean up unused MHD SSL/TLS instances?
 */
#define MHD_CACHE_TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MINUTES, 5)

/**
 * After how long do we clean up Socks5 handles that failed to show any activity
 * with their respective MHD instance?
 */
#define HTTP_HANDSHAKE_TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 15)


/**
 * Log curl error.
 *
 * @param level log level
 * @param fun name of curl_easy-function that gave the error
 * @param rc return code from curl
 */
#define LOG_CURL_EASY(level,fun,rc) GNUNET_log(level, _("%s failed at %s:%d: `%s'\n"), fun, __FILE__, __LINE__, curl_easy_strerror (rc))


/* *************** Socks protocol definitions (move to TUN?) ****************** */

/**
 * Which SOCKS version do we speak?
 */
#define SOCKS_VERSION_5 0x05

/**
 * Flag to set for 'no authentication'.
 */
#define SOCKS_AUTH_NONE 0


/**
 * Commands in Socks5.
 */
enum Socks5Commands
{
  /**
   * Establish TCP/IP stream.
   */
  SOCKS5_CMD_TCP_STREAM = 1,

  /**
   * Establish TCP port binding.
   */
  SOCKS5_CMD_TCP_PORT = 2,

  /**
   * Establish UDP port binding.
   */
  SOCKS5_CMD_UDP_PORT = 3
};


/**
 * Address types in Socks5.
 */
enum Socks5AddressType
{
  /**
   * IPv4 address.
   */
  SOCKS5_AT_IPV4 = 1,

  /**
   * IPv4 address.
   */
  SOCKS5_AT_DOMAINNAME = 3,

  /**
   * IPv6 address.
   */
  SOCKS5_AT_IPV6 = 4

};


/**
 * Status codes in Socks5 response.
 */
enum Socks5StatusCode
{
  SOCKS5_STATUS_REQUEST_GRANTED = 0,
  SOCKS5_STATUS_GENERAL_FAILURE = 1,
  SOCKS5_STATUS_CONNECTION_NOT_ALLOWED_BY_RULE = 2,
  SOCKS5_STATUS_NETWORK_UNREACHABLE = 3,
  SOCKS5_STATUS_HOST_UNREACHABLE = 4,
  SOCKS5_STATUS_CONNECTION_REFUSED_BY_HOST = 5,
  SOCKS5_STATUS_TTL_EXPIRED = 6,
  SOCKS5_STATUS_COMMAND_NOT_SUPPORTED = 7,
  SOCKS5_STATUS_ADDRESS_TYPE_NOT_SUPPORTED = 8
};


/**
 * Client hello in Socks5 protocol.
 */
struct Socks5ClientHelloMessage
{
  /**
   * Should be #SOCKS_VERSION_5.
   */
  uint8_t version;

  /**
   * How many authentication methods does the client support.
   */
  uint8_t num_auth_methods;

  /* followed by supported authentication methods, 1 byte per method */

};


/**
 * Server hello in Socks5 protocol.
 */
struct Socks5ServerHelloMessage
{
  /**
   * Should be #SOCKS_VERSION_5.
   */
  uint8_t version;

  /**
   * Chosen authentication method, for us always #SOCKS_AUTH_NONE,
   * which skips the authentication step.
   */
  uint8_t auth_method;
};


/**
 * Client socks request in Socks5 protocol.
 */
struct Socks5ClientRequestMessage
{
  /**
   * Should be #SOCKS_VERSION_5.
   */
  uint8_t version;

  /**
   * Command code, we only uspport #SOCKS5_CMD_TCP_STREAM.
   */
  uint8_t command;

  /**
   * Reserved, always zero.
   */
  uint8_t resvd;

  /**
   * Address type, an `enum Socks5AddressType`.
   */
  uint8_t addr_type;

  /*
   * Followed by either an ip4/ipv6 address or a domain name with a
   * length field (uint8_t) in front (depending on @e addr_type).
   * followed by port number in network byte order (uint16_t).
   */
};


/**
 * Server response to client requests in Socks5 protocol.
 */
struct Socks5ServerResponseMessage
{
  /**
   * Should be #SOCKS_VERSION_5.
   */
  uint8_t version;

  /**
   * Status code, an `enum Socks5StatusCode`
   */
  uint8_t reply;

  /**
   * Always zero.
   */
  uint8_t reserved;

  /**
   * Address type, an `enum Socks5AddressType`.
   */
  uint8_t addr_type;

  /*
   * Followed by either an ip4/ipv6 address or a domain name with a
   * length field (uint8_t) in front (depending on @e addr_type).
   * followed by port number in network byte order (uint16_t).
   */

};



/* *********************** Datastructures for HTTP handling ****************** */

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


/**
 * Structure for GNS certificates
 */
struct ProxyGNSCertificate
{
  /**
   * The certificate as PEM
   */
  char cert[MAX_PEM_SIZE];

  /**
   * The private key as PEM
   */
  char key[MAX_PEM_SIZE];
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
   * the domain name to server (only important for SSL)
   */
  char *domain;

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
  struct GNUNET_SCHEDULER_Task * httpd_task;

  /**
   * is this an ssl daemon?
   */
  int is_ssl;

};


/* ***************** Datastructures for Socks handling **************** */


/**
 * The socks phases.
 */
enum SocksPhase
{
  /**
   * We're waiting to get the client hello.
   */
  SOCKS5_INIT,

  /**
   * We're waiting to get the initial request.
   */
  SOCKS5_REQUEST,

  /**
   * We are currently resolving the destination.
   */
  SOCKS5_RESOLVING,

  /**
   * We're in transfer mode.
   */
  SOCKS5_DATA_TRANSFER,

  /**
   * Finish writing the write buffer, then clean up.
   */
  SOCKS5_WRITE_THEN_CLEANUP,

  /**
   * Socket has been passed to MHD, do not close it anymore.
   */
  SOCKS5_SOCKET_WITH_MHD,

  /**
   * We've finished receiving upload data from MHD.
   */
  SOCKS5_SOCKET_UPLOAD_STARTED,

  /**
   * We've finished receiving upload data from MHD.
   */
  SOCKS5_SOCKET_UPLOAD_DONE,

  /**
   * We've finished uploading data via CURL and can now download.
   */
  SOCKS5_SOCKET_DOWNLOAD_STARTED,

  /**
   * We've finished receiving download data from cURL.
   */
  SOCKS5_SOCKET_DOWNLOAD_DONE
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
   * Handle to GNS lookup, during #SOCKS5_RESOLVING phase.
   */
  struct GNUNET_GNS_LookupRequest *gns_lookup;

  /**
   * Client socket read task
   */
  struct GNUNET_SCHEDULER_Task * rtask;

  /**
   * Client socket write task
   */
  struct GNUNET_SCHEDULER_Task * wtask;

  /**
   * Timeout task
   */
  struct GNUNET_SCHEDULER_Task * timeout_task;

  /**
   * Read buffer
   */
  char rbuf[SOCKS_BUFFERSIZE];

  /**
   * Write buffer
   */
  char wbuf[SOCKS_BUFFERSIZE];

  /**
   * Buffer we use for moving data between MHD and curl (in both directions).
   */
  char io_buf[IO_BUFFERSIZE];

  /**
   * MHD HTTP instance handling this request, NULL for none.
   */
  struct MhdHttpList *hd;

  /**
   * MHD response object for this request.
   */
  struct MHD_Response *response;

  /**
   * the domain name to server (only important for SSL)
   */
  char *domain;

  /**
   * DNS Legacy Host Name as given by GNS, NULL if not given.
   */
  char *leho;

  /**
   * Payload of the (last) DANE record encountered.
   */
  char *dane_data;

  /**
   * The URL to fetch
   */
  char *url;

  /**
   * Handle to cURL
   */
  CURL *curl;

  /**
   * HTTP request headers for the curl request.
   */
  struct curl_slist *headers;

  /**
   * HTTP response code to give to MHD for the response.
   */
  unsigned int response_code;

  /**
   * Number of bytes in @e dane_data.
   */
  size_t dane_data_len;

  /**
   * Number of bytes already in read buffer
   */
  size_t rbuf_len;

  /**
   * Number of bytes already in write buffer
   */
  size_t wbuf_len;

  /**
   * Number of bytes already in the IO buffer.
   */
  size_t io_len;

  /**
   * Once known, what's the target address for the connection?
   */
  struct sockaddr_storage destination_address;

  /**
   * The socks state
   */
  enum SocksPhase state;

  /**
   * Desired destination port.
   */
  uint16_t port;

};



/* *********************** Globals **************************** */


/**
 * The port the proxy is running on (default 7777)
 */
static unsigned long port = GNUNET_GNS_PROXY_PORT;

/**
 * The CA file (pem) to use for the proxy CA
 */
static char *cafile_opt;

/**
 * The listen socket of the proxy for IPv4
 */
static struct GNUNET_NETWORK_Handle *lsock4;

/**
 * The listen socket of the proxy for IPv6
 */
static struct GNUNET_NETWORK_Handle *lsock6;

/**
 * The listen task ID for IPv4
 */
static struct GNUNET_SCHEDULER_Task * ltask4;

/**
 * The listen task ID for IPv6
 */
static struct GNUNET_SCHEDULER_Task * ltask6;

/**
 * The cURL download task (curl multi API).
 */
static struct GNUNET_SCHEDULER_Task * curl_download_task;

/**
 * The cURL multi handle
 */
static CURLM *curl_multi;

/**
 * Handle to the GNS service
 */
static struct GNUNET_GNS_Handle *gns_handle;

/**
 * DLL for http/https daemons
 */
static struct MhdHttpList *mhd_httpd_head;

/**
 * DLL for http/https daemons
 */
static struct MhdHttpList *mhd_httpd_tail;

/**
 * Daemon for HTTP (we have one per SSL certificate, and then one for
 * all HTTP connections; this is the one for HTTP, not HTTPS).
 */
static struct MhdHttpList *httpd;

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
static struct GNUNET_CRYPTO_EcdsaPublicKey local_gns_zone;

/**
 * The users local shorten zone
 */
static struct GNUNET_CRYPTO_EcdsaPrivateKey local_shorten_zone;

/**
 * Is shortening enabled?
 */
static int do_shorten;

/**
 * The CA for SSL certificate generation
 */
static struct ProxyCA proxy_ca;

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


/* ************************* Global helpers ********************* */


/**
 * Run MHD now, we have extra data ready for the callback.
 *
 * @param hd the daemon to run now.
 */
static void
run_mhd_now (struct MhdHttpList *hd);


/**
 * Clean up s5r handles.
 *
 * @param s5r the handle to destroy
 */
static void
cleanup_s5r (struct Socks5Request *s5r)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Cleaning up socks request\n");
  if (NULL != s5r->curl)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		"Cleaning up cURL handle\n");
    curl_multi_remove_handle (curl_multi, s5r->curl);
    curl_easy_cleanup (s5r->curl);
    s5r->curl = NULL;
  }
  curl_slist_free_all (s5r->headers);
  if ( (NULL != s5r->response) &&
       (curl_failure_response != s5r->response) )
    MHD_destroy_response (s5r->response);
  if (NULL != s5r->rtask)
    GNUNET_SCHEDULER_cancel (s5r->rtask);
  if (NULL != s5r->timeout_task)
    GNUNET_SCHEDULER_cancel (s5r->timeout_task);
  if (NULL != s5r->wtask)
    GNUNET_SCHEDULER_cancel (s5r->wtask);
  if (NULL != s5r->gns_lookup)
    GNUNET_GNS_lookup_cancel (s5r->gns_lookup);
  if (NULL != s5r->sock)
  {
    if (SOCKS5_SOCKET_WITH_MHD <= s5r->state)
      GNUNET_NETWORK_socket_free_memory_only_ (s5r->sock);
    else
      GNUNET_NETWORK_socket_close (s5r->sock);
  }
  GNUNET_CONTAINER_DLL_remove (s5r_head,
			       s5r_tail,
			       s5r);
  GNUNET_free_non_null (s5r->domain);
  GNUNET_free_non_null (s5r->leho);
  GNUNET_free_non_null (s5r->url);
  GNUNET_free_non_null (s5r->dane_data);
  GNUNET_free (s5r);
}


/* ************************* HTTP handling with cURL *********************** */


/**
 * Callback for MHD response generation.  This function is called from
 * MHD whenever MHD expects to get data back.  Copies data from the
 * io_buf, if available.
 *
 * @param cls closure with our `struct Socks5Request`
 * @param pos in buffer
 * @param buf where to copy data
 * @param max available space in @a buf
 * @return number of bytes written to @a buf
 */
static ssize_t
mhd_content_cb (void *cls,
                uint64_t pos,
                char* buf,
                size_t max)
{
  struct Socks5Request *s5r = cls;
  size_t bytes_to_copy;

  if ( (SOCKS5_SOCKET_UPLOAD_STARTED == s5r->state) ||
       (SOCKS5_SOCKET_UPLOAD_DONE == s5r->state) )
  {
    /* we're still not done with the upload, do not yet
       start the download, the IO buffer is still full
       with upload data. */
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		"Pausing MHD download, not yet ready for download\n");
    return 0; /* not yet ready for data download */
  }
  bytes_to_copy = GNUNET_MIN (max,
			      s5r->io_len);
  if ( (0 == bytes_to_copy) &&
       (SOCKS5_SOCKET_DOWNLOAD_DONE != s5r->state) )
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		"Pausing MHD download, no data available\n");
    return 0; /* more data later */
  }
  if ( (0 == bytes_to_copy) &&
       (SOCKS5_SOCKET_DOWNLOAD_DONE == s5r->state) )
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		"Completed MHD download\n");
    return MHD_CONTENT_READER_END_OF_STREAM;
  }
  memcpy (buf, s5r->io_buf, bytes_to_copy);
  memmove (s5r->io_buf,
	   &s5r->io_buf[bytes_to_copy],
	   s5r->io_len - bytes_to_copy);
  s5r->io_len -= bytes_to_copy;
  if (NULL != s5r->curl)
    curl_easy_pause (s5r->curl, CURLPAUSE_CONT);
  return bytes_to_copy;
}


/**
 * Check that the website has presented us with a valid SSL certificate.
 * The certificate must either match the domain name or the LEHO name
 * (or, if available, the TLSA record).
 *
 * @param s5r request to check for.
 * @return #GNUNET_OK if the certificate is valid
 */
static int
check_ssl_certificate (struct Socks5Request *s5r)
{
  unsigned int cert_list_size;
  const gnutls_datum_t *chainp;
  const struct curl_tlssessioninfo *tlsinfo;
  char certdn[GNUNET_DNSPARSER_MAX_NAME_LENGTH + 3];
  size_t size;
  gnutls_x509_crt_t x509_cert;
  int rc;
  const char *name;

  if (CURLE_OK !=
      curl_easy_getinfo (s5r->curl,
			 CURLINFO_TLS_SESSION,
			 (struct curl_slist **) &tlsinfo))
    return GNUNET_SYSERR;
  if (CURLSSLBACKEND_GNUTLS != tlsinfo->backend)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _("Unsupported CURL SSL backend %d\n"),
                tlsinfo->backend);
    return GNUNET_SYSERR;
  }
  chainp = gnutls_certificate_get_peers (tlsinfo->internals, &cert_list_size);
  if ( (! chainp) || (0 == cert_list_size) )
    return GNUNET_SYSERR;

  size = sizeof (certdn);
  /* initialize an X.509 certificate structure. */
  gnutls_x509_crt_init (&x509_cert);
  gnutls_x509_crt_import (x509_cert,
                          chainp,
                          GNUTLS_X509_FMT_DER);

  if (0 != (rc = gnutls_x509_crt_get_dn_by_oid (x509_cert,
                                                GNUTLS_OID_X520_COMMON_NAME,
                                                0, /* the first and only one */
                                                0 /* no DER encoding */,
                                                certdn,
                                                &size)))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                _("Failed to fetch CN from cert: %s\n"),
                gnutls_strerror(rc));
    gnutls_x509_crt_deinit (x509_cert);
    return GNUNET_SYSERR;
  }
  /* check for TLSA/DANE records */
#if HAVE_GNUTLS_DANE
  if (NULL != s5r->dane_data)
  {
    char *dd[] = { s5r->dane_data, NULL };
    int dlen[] = { s5r->dane_data_len, 0};
    dane_state_t dane_state;
    dane_query_t dane_query;
    unsigned int verify;

    /* FIXME: add flags to gnutls to NOT read UNBOUND_ROOT_KEY_FILE here! */
    if (0 != (rc = dane_state_init (&dane_state,
#ifdef DANE_F_IGNORE_DNSSEC
                                    DANE_F_IGNORE_DNSSEC |
#endif
                                    DANE_F_IGNORE_LOCAL_RESOLVER)))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  _("Failed to initialize DANE: %s\n"),
                  dane_strerror(rc));
      gnutls_x509_crt_deinit (x509_cert);
      return GNUNET_SYSERR;
    }
    if (0 != (rc = dane_raw_tlsa (dane_state,
                                  &dane_query,
                                  dd,
                                  dlen,
                                  GNUNET_YES,
                                  GNUNET_NO)))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  _("Failed to parse DANE record: %s\n"),
                  dane_strerror(rc));
      dane_state_deinit (dane_state);
      gnutls_x509_crt_deinit (x509_cert);
      return GNUNET_SYSERR;
    }
    if (0 != (rc = dane_verify_crt_raw (dane_state,
                                        chainp,
                                        cert_list_size,
                                        gnutls_certificate_type_get (tlsinfo->internals),
                                        dane_query,
                                        0, 0,
                                        &verify)))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  _("Failed to verify TLS connection using DANE: %s\n"),
                  dane_strerror(rc));
      dane_query_deinit (dane_query);
      dane_state_deinit (dane_state);
      gnutls_x509_crt_deinit (x509_cert);
      return GNUNET_SYSERR;
    }
    if (0 != verify)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  _("Failed DANE verification failed with GnuTLS verify status code: %u\n"),
                  verify);
      dane_query_deinit (dane_query);
      dane_state_deinit (dane_state);
      gnutls_x509_crt_deinit (x509_cert);
      return GNUNET_SYSERR;
    }
    dane_query_deinit (dane_query);
    dane_state_deinit (dane_state);
    /* success! */
  }
  else
#endif
  {
    /* try LEHO or ordinary domain name X509 verification */
    name = s5r->domain;
    if (NULL != s5r->leho)
      name = s5r->leho;
    if (NULL != name)
    {
      if (0 == (rc = gnutls_x509_crt_check_hostname (x509_cert,
                                                     name)))
      {
        GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                    _("SSL certificate subject name (%s) does not match `%s'\n"),
                    certdn,
                    name);
        gnutls_x509_crt_deinit (x509_cert);
        return GNUNET_SYSERR;
      }
    }
    else
    {
      /* we did not even have the domain name!? */
      GNUNET_break (0);
      return GNUNET_SYSERR;
    }
  }
  gnutls_x509_crt_deinit (x509_cert);
  return GNUNET_OK;
}


/**
 * We're getting an HTTP response header from cURL.  Convert it to the
 * MHD response headers.  Mostly copies the headers, but makes special
 * adjustments to "Set-Cookie" and "Location" headers as those may need
 * to be changed from the LEHO to the domain the browser expects.
 *
 * @param buffer curl buffer with a single line of header data; not 0-terminated!
 * @param size curl blocksize
 * @param nmemb curl blocknumber
 * @param cls our `struct Socks5Request *`
 * @return size of processed bytes
 */
static size_t
curl_check_hdr (void *buffer, size_t size, size_t nmemb, void *cls)
{
  struct Socks5Request *s5r = cls;
  size_t bytes = size * nmemb;
  char *ndup;
  const char *hdr_type;
  const char *cookie_domain;
  char *hdr_val;
  long resp_code;
  char *new_cookie_hdr;
  char *new_location;
  size_t offset;
  size_t delta_cdomain;
  int domain_matched;
  char *tok;

  if (NULL == s5r->response)
  {
    /* first, check SSL certificate */
    if ( (HTTPS_PORT == s5r->port) &&
	 (GNUNET_OK != check_ssl_certificate (s5r)) )
      return 0;

    GNUNET_break (CURLE_OK ==
		  curl_easy_getinfo (s5r->curl,
				     CURLINFO_RESPONSE_CODE,
				     &resp_code));
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		"Creating MHD response with code %d\n",
		(int) resp_code);
    s5r->response_code = resp_code;
    s5r->response = MHD_create_response_from_callback (MHD_SIZE_UNKNOWN,
						       IO_BUFFERSIZE,
						       &mhd_content_cb,
						       s5r,
						       NULL);
    if (NULL != s5r->leho)
    {
      char *cors_hdr;

      GNUNET_asprintf (&cors_hdr,
		       (HTTPS_PORT == s5r->port)
		       ? "https://%s"
		       : "http://%s",
		       s5r->leho);

      GNUNET_break (MHD_YES ==
		    MHD_add_response_header (s5r->response,
					     MHD_HTTP_HEADER_ACCESS_CONTROL_ALLOW_ORIGIN,
					     cors_hdr));
      GNUNET_free (cors_hdr);
    }
    /* force connection to be closed after each request, as we
       do not support HTTP pipelining */
    GNUNET_break (MHD_YES ==
		  MHD_add_response_header (s5r->response,
					   MHD_HTTP_HEADER_CONNECTION,
					   "close"));
  }

  ndup = GNUNET_strndup (buffer, bytes);
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
  if (' ' == *hdr_val)
    hdr_val++;

  /* custom logic for certain header types */
  new_cookie_hdr = NULL;
  if ( (NULL != s5r->leho) &&
       (0 == strcasecmp (hdr_type,
			 MHD_HTTP_HEADER_SET_COOKIE)) )

  {
    new_cookie_hdr = GNUNET_malloc (strlen (hdr_val) +
				    strlen (s5r->domain) + 1);
    offset = 0;
    domain_matched = GNUNET_NO; /* make sure we match domain at most once */
    for (tok = strtok (hdr_val, ";"); NULL != tok; tok = strtok (NULL, ";"))
    {
      if ( (0 == strncasecmp (tok, " domain", strlen (" domain"))) &&
	   (GNUNET_NO == domain_matched) )
      {
	domain_matched = GNUNET_YES;
        cookie_domain = tok + strlen (" domain") + 1;
        if (strlen (cookie_domain) < strlen (s5r->leho))
        {
          delta_cdomain = strlen (s5r->leho) - strlen (cookie_domain);
          if (0 == strcasecmp (cookie_domain, s5r->leho + delta_cdomain))
	  {
            offset += sprintf (new_cookie_hdr + offset,
			       " domain=%s;",
			       s5r->domain);
            continue;
          }
        }
        else if (0 == strcmp (cookie_domain, s5r->leho))
        {
	  offset += sprintf (new_cookie_hdr + offset,
			     " domain=%s;",
			     s5r->domain);
	  continue;
        }
        GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                    _("Cookie domain `%s' supplied by server is invalid\n"),
		    tok);
      }
      memcpy (new_cookie_hdr + offset, tok, strlen (tok));
      offset += strlen (tok);
      new_cookie_hdr[offset++] = ';';
    }
    hdr_val = new_cookie_hdr;
  }

  new_location = NULL;
  if (0 == strcasecmp (MHD_HTTP_HEADER_LOCATION, hdr_type))
  {
    char *leho_host;

    GNUNET_asprintf (&leho_host,
		     (HTTPS_PORT != s5r->port)
		     ? "http://%s"
		     : "https://%s",
		     s5r->leho);
    if (0 == strncmp (leho_host,
		      hdr_val,
		      strlen (leho_host)))
    {
      GNUNET_asprintf (&new_location,
		       "%s%s%s",
		       (HTTPS_PORT != s5r->port)
		       ? "http://"
		       : "https://",
		       s5r->domain,
		       hdr_val + strlen (leho_host));
      hdr_val = new_location;
    }
    GNUNET_free (leho_host);
  }
  /* MHD does not allow certain characters in values, remove those */
  if (NULL != (tok = strchr (hdr_val, '\n')))
    *tok = '\0';
  if (NULL != (tok = strchr (hdr_val, '\r')))
    *tok = '\0';
  if (NULL != (tok = strchr (hdr_val, '\t')))
    *tok = '\0';
  if (0 != strlen (hdr_val))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		"Adding header %s: %s to MHD response\n",
		hdr_type,
		hdr_val);
    GNUNET_break (MHD_YES ==
		  MHD_add_response_header (s5r->response,
					   hdr_type,
					   hdr_val));
  }
  GNUNET_free (ndup);
  GNUNET_free_non_null (new_cookie_hdr);
  GNUNET_free_non_null (new_location);
  return bytes;
}


/**
 * Handle response payload data from cURL.  Copies it into our `io_buf` to make
 * it available to MHD.
 *
 * @param ptr pointer to the data
 * @param size number of blocks of data
 * @param nmemb blocksize
 * @param ctx our `struct Socks5Request *`
 * @return number of bytes handled
 */
static size_t
curl_download_cb (void *ptr, size_t size, size_t nmemb, void* ctx)
{
  struct Socks5Request *s5r = ctx;
  size_t total = size * nmemb;

  if ( (SOCKS5_SOCKET_UPLOAD_STARTED == s5r->state) ||
       (SOCKS5_SOCKET_UPLOAD_DONE == s5r->state) )
  {
    /* we're still not done with the upload, do not yet
       start the download, the IO buffer is still full
       with upload data. */
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		"Pausing CURL download, waiting for UPLOAD to finish\n");
    return CURL_WRITEFUNC_PAUSE; /* not yet ready for data download */
  }
  if (sizeof (s5r->io_buf) - s5r->io_len < total)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		"Pausing CURL download, not enough space\n");
    return CURL_WRITEFUNC_PAUSE; /* not enough space */
  }
  memcpy (&s5r->io_buf[s5r->io_len],
	  ptr,
	  total);
  s5r->io_len += total;
  if (s5r->io_len == total)
    run_mhd_now (s5r->hd);
  return total;
}


/**
 * cURL callback for uploaded (PUT/POST) data.  Copies it into our `io_buf`
 * to make it available to MHD.
 *
 * @param buf where to write the data
 * @param size number of bytes per member
 * @param nmemb number of members available in @a buf
 * @param cls our `struct Socks5Request` that generated the data
 * @return number of bytes copied to @a buf
 */
static size_t
curl_upload_cb (void *buf, size_t size, size_t nmemb, void *cls)
{
  struct Socks5Request *s5r = cls;
  size_t len = size * nmemb;
  size_t to_copy;

  if ( (0 == s5r->io_len) &&
       (SOCKS5_SOCKET_UPLOAD_DONE != s5r->state) )
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		"Pausing CURL UPLOAD, need more data\n");
    return CURL_READFUNC_PAUSE;
  }
  if ( (0 == s5r->io_len) &&
       (SOCKS5_SOCKET_UPLOAD_DONE == s5r->state) )
  {
    s5r->state = SOCKS5_SOCKET_DOWNLOAD_STARTED;
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		"Completed CURL UPLOAD\n");
    return 0; /* upload finished, can now download */
  }
  if ( (SOCKS5_SOCKET_UPLOAD_STARTED != s5r->state) ||
       (SOCKS5_SOCKET_UPLOAD_DONE != s5r->state) )
  {
    GNUNET_break (0);
    return CURL_READFUNC_ABORT;
  }
  to_copy = GNUNET_MIN (s5r->io_len,
			len);
  memcpy (buf, s5r->io_buf, to_copy);
  memmove (s5r->io_buf,
	   &s5r->io_buf[to_copy],
	   s5r->io_len - to_copy);
  s5r->io_len -= to_copy;
  if (s5r->io_len + to_copy == sizeof (s5r->io_buf))
    run_mhd_now (s5r->hd); /* got more space for upload now */
  return to_copy;
}


/* ************************** main loop of cURL interaction ****************** */


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
 * Ask cURL for the select() sets and schedule cURL operations.
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

  if (NULL != curl_download_task)
  {
    GNUNET_SCHEDULER_cancel (curl_download_task);
    curl_download_task = NULL;
  }
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
    return;
  }
  to = -1;
  GNUNET_break (CURLM_OK == curl_multi_timeout (curl_multi, &to));
  if (-1 == to)
    rtime = GNUNET_TIME_UNIT_FOREVER_REL;
  else
    rtime = GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MILLISECONDS, to);
  if (-1 != max)
  {
    grs = GNUNET_NETWORK_fdset_create ();
    gws = GNUNET_NETWORK_fdset_create ();
    GNUNET_NETWORK_fdset_copy_native (grs, &rs, max + 1);
    GNUNET_NETWORK_fdset_copy_native (gws, &ws, max + 1);
    curl_download_task = GNUNET_SCHEDULER_add_select (GNUNET_SCHEDULER_PRIORITY_DEFAULT,
						      rtime,
						      grs, gws,
						      &curl_task_download, curl_multi);
    GNUNET_NETWORK_fdset_destroy (gws);
    GNUNET_NETWORK_fdset_destroy (grs);
  }
  else
  {
    curl_download_task = GNUNET_SCHEDULER_add_delayed (rtime,
                                                       &curl_task_download,
                                                       curl_multi);
  }
}


/**
 * Task that is run when we are ready to receive more data from curl.
 *
 * @param cls closure, NULL
 * @param tc task context
 */
static void
curl_task_download (void *cls,
		    const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  int running;
  int msgnum;
  struct CURLMsg *msg;
  CURLMcode mret;
  struct Socks5Request *s5r;

  curl_download_task = NULL;
  do
  {
    running = 0;
    mret = curl_multi_perform (curl_multi, &running);
    while (NULL != (msg = curl_multi_info_read (curl_multi, &msgnum)))
    {
      GNUNET_break (CURLE_OK ==
		    curl_easy_getinfo (msg->easy_handle,
				       CURLINFO_PRIVATE,
				       (char **) &s5r ));
      if (NULL == s5r)
      {
	GNUNET_break (0);
	continue;
      }
      switch (msg->msg)
      {
      case CURLMSG_NONE:
	/* documentation says this is not used */
	GNUNET_break (0);
	break;
      case CURLMSG_DONE:
	switch (msg->data.result)
	{
	case CURLE_OK:
	case CURLE_GOT_NOTHING:
	  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		      "CURL download completed.\n");
	  s5r->state = SOCKS5_SOCKET_DOWNLOAD_DONE;
	  run_mhd_now (s5r->hd);
	  break;
	default:
	  GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		      "Download curl failed: %s\n",
		      curl_easy_strerror (msg->data.result));
	  /* FIXME: indicate error somehow? close MHD connection badly as well? */
	  s5r->state = SOCKS5_SOCKET_DOWNLOAD_DONE;
	  run_mhd_now (s5r->hd);
	  break;
	}
	GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		    "Cleaning up cURL handle\n");
	curl_multi_remove_handle (curl_multi, s5r->curl);
	curl_easy_cleanup (s5r->curl);
	s5r->curl = NULL;
	if (NULL == s5r->response)
	  s5r->response = curl_failure_response;
	break;
      case CURLMSG_LAST:
	/* documentation says this is not used */
	GNUNET_break (0);
	break;
      default:
	/* unexpected status code */
	GNUNET_break (0);
	break;
      }
    };
  } while (mret == CURLM_CALL_MULTI_PERFORM);
  if (CURLM_OK != mret)
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		"%s failed at %s:%d: `%s'\n",
                "curl_multi_perform", __FILE__, __LINE__,
                curl_multi_strerror (mret));
  if (0 == running)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		"Suspending cURL multi loop, no more events pending\n");
    return; /* nothing more in progress */
  }
  curl_download_prepare ();
}


/* ********************************* MHD response generation ******************* */


/**
 * Read HTTP request header field from the request.  Copies the fields
 * over to the 'headers' that will be given to curl.  However, 'Host'
 * is substituted with the LEHO if present.  We also change the
 * 'Connection' header value to "close" as the proxy does not support
 * pipelining.
 *
 * @param cls our `struct Socks5Request`
 * @param kind value kind
 * @param key field key
 * @param value field value
 * @return MHD_YES to continue to iterate
 */
static int
con_val_iter (void *cls,
              enum MHD_ValueKind kind,
              const char *key,
              const char *value)
{
  struct Socks5Request *s5r = cls;
  char *hdr;

  if ( (0 == strcasecmp (MHD_HTTP_HEADER_HOST, key)) &&
       (NULL != s5r->leho) )
    value = s5r->leho;
  if (0 == strcasecmp (MHD_HTTP_HEADER_CONNECTION, key))
    value = "Close";
  GNUNET_asprintf (&hdr,
		   "%s: %s",
		   key,
		   value);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Adding HEADER `%s' to HTTP request\n",
	      hdr);
  s5r->headers = curl_slist_append (s5r->headers,
				    hdr);
  GNUNET_free (hdr);
  return MHD_YES;
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
  struct Socks5Request *s5r = *con_cls;
  char *curlurl;
  char ipstring[INET6_ADDRSTRLEN];
  char ipaddr[INET6_ADDRSTRLEN + 2];
  const struct sockaddr *sa;
  const struct sockaddr_in *s4;
  const struct sockaddr_in6 *s6;
  uint16_t port;
  size_t left;

  if (NULL == s5r)
  {
    GNUNET_break (0);
    return MHD_NO;
  }
  if ( (NULL == s5r->curl) &&
       (SOCKS5_SOCKET_WITH_MHD == s5r->state) )
  {
    /* first time here, initialize curl handle */
    sa = (const struct sockaddr *) &s5r->destination_address;
    switch (sa->sa_family)
    {
    case AF_INET:
      s4 = (const struct sockaddr_in *) &s5r->destination_address;
      if (NULL == inet_ntop (AF_INET,
			     &s4->sin_addr,
			     ipstring,
			     sizeof (ipstring)))
      {
	GNUNET_break (0);
	return MHD_NO;
      }
      GNUNET_snprintf (ipaddr,
		       sizeof (ipaddr),
		       "%s",
		       ipstring);
      port = ntohs (s4->sin_port);
      break;
    case AF_INET6:
      s6 = (const struct sockaddr_in6 *) &s5r->destination_address;
      if (NULL == inet_ntop (AF_INET6,
			     &s6->sin6_addr,
			     ipstring,
			     sizeof (ipstring)))
      {
	GNUNET_break (0);
	return MHD_NO;
      }
      GNUNET_snprintf (ipaddr,
		       sizeof (ipaddr),
		       "[%s]",
		       ipstring);
      port = ntohs (s6->sin6_port);
      break;
    default:
      GNUNET_break (0);
      return MHD_NO;
    }
    s5r->curl = curl_easy_init ();
    if (NULL == s5r->curl)
      return MHD_queue_response (con,
				 MHD_HTTP_INTERNAL_SERVER_ERROR,
				 curl_failure_response);
    curl_easy_setopt (s5r->curl, CURLOPT_HEADERFUNCTION, &curl_check_hdr);
    curl_easy_setopt (s5r->curl, CURLOPT_HEADERDATA, s5r);
    curl_easy_setopt (s5r->curl, CURLOPT_FOLLOWLOCATION, 0);
    curl_easy_setopt (s5r->curl, CURLOPT_IPRESOLVE, CURL_IPRESOLVE_V4);
    curl_easy_setopt (s5r->curl, CURLOPT_CONNECTTIMEOUT, 600L);
    curl_easy_setopt (s5r->curl, CURLOPT_TIMEOUT, 600L);
    curl_easy_setopt (s5r->curl, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt (s5r->curl, CURLOPT_HTTP_CONTENT_DECODING, 0);
    curl_easy_setopt (s5r->curl, CURLOPT_HTTP_TRANSFER_DECODING, 0);
    curl_easy_setopt (s5r->curl, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt (s5r->curl, CURLOPT_PRIVATE, s5r);
    curl_easy_setopt (s5r->curl, CURLOPT_VERBOSE, 0);
    GNUNET_asprintf (&curlurl,
		     (HTTPS_PORT != s5r->port)
		     ? "http://%s:%d%s"
		     : "https://%s:%d%s",
		     ipaddr,
		     port,
		     s5r->url);
    curl_easy_setopt (s5r->curl,
		      CURLOPT_URL,
		      curlurl);
    GNUNET_free (curlurl);

    if (0 == strcasecmp (meth, MHD_HTTP_METHOD_PUT))
    {
      s5r->state = SOCKS5_SOCKET_UPLOAD_STARTED;
      curl_easy_setopt (s5r->curl, CURLOPT_UPLOAD, 1);
      curl_easy_setopt (s5r->curl, CURLOPT_WRITEFUNCTION, &curl_download_cb);
      curl_easy_setopt (s5r->curl, CURLOPT_WRITEDATA, s5r);
      curl_easy_setopt (s5r->curl, CURLOPT_READFUNCTION, &curl_upload_cb);
      curl_easy_setopt (s5r->curl, CURLOPT_READDATA, s5r);
    }
    else if (0 == strcasecmp (meth, MHD_HTTP_METHOD_POST))
    {
      s5r->state = SOCKS5_SOCKET_UPLOAD_STARTED;
      curl_easy_setopt (s5r->curl, CURLOPT_POST, 1);
      curl_easy_setopt (s5r->curl, CURLOPT_WRITEFUNCTION, &curl_download_cb);
      curl_easy_setopt (s5r->curl, CURLOPT_WRITEDATA, s5r);
      curl_easy_setopt (s5r->curl, CURLOPT_READFUNCTION, &curl_upload_cb);
      curl_easy_setopt (s5r->curl, CURLOPT_READDATA, s5r);
    }
    else if (0 == strcasecmp (meth, MHD_HTTP_METHOD_HEAD))
    {
      s5r->state = SOCKS5_SOCKET_DOWNLOAD_STARTED;
      curl_easy_setopt (s5r->curl, CURLOPT_NOBODY, 1);
    }
    else if (0 == strcasecmp (meth, MHD_HTTP_METHOD_GET))
    {
      s5r->state = SOCKS5_SOCKET_DOWNLOAD_STARTED;
      curl_easy_setopt (s5r->curl, CURLOPT_HTTPGET, 1);
      curl_easy_setopt (s5r->curl, CURLOPT_WRITEFUNCTION, &curl_download_cb);
      curl_easy_setopt (s5r->curl, CURLOPT_WRITEDATA, s5r);
    }
    else
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
		  _("Unsupported HTTP method `%s'\n"),
		  meth);
      curl_easy_cleanup (s5r->curl);
      s5r->curl = NULL;
      return MHD_NO;
    }

    if (0 == strcasecmp (ver, MHD_HTTP_VERSION_1_0))
    {
      curl_easy_setopt (s5r->curl, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_0);
    }
    else if (0 == strcasecmp (ver, MHD_HTTP_VERSION_1_1))
    {
      curl_easy_setopt (s5r->curl, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_1);
    }
    else
    {
      curl_easy_setopt (s5r->curl, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_NONE);
    }

    if (HTTPS_PORT == s5r->port)
    {
      curl_easy_setopt (s5r->curl, CURLOPT_USE_SSL, CURLUSESSL_ALL);
      curl_easy_setopt (s5r->curl, CURLOPT_SSL_VERIFYPEER, 1L);
      /* Disable cURL checking the hostname, as we will check ourselves
	 as only we have the domain name or the LEHO or the DANE record */
      curl_easy_setopt (s5r->curl, CURLOPT_SSL_VERIFYHOST, 0L);
    }
    else
    {
      curl_easy_setopt (s5r->curl, CURLOPT_USE_SSL, CURLUSESSL_NONE);
    }

    if (CURLM_OK != curl_multi_add_handle (curl_multi, s5r->curl))
    {
      GNUNET_break (0);
      curl_easy_cleanup (s5r->curl);
      s5r->curl = NULL;
      return MHD_NO;
    }
    MHD_get_connection_values (con,
			       MHD_HEADER_KIND,
			       &con_val_iter, s5r);
    curl_easy_setopt (s5r->curl, CURLOPT_HTTPHEADER, s5r->headers);
    curl_download_prepare ();
    return MHD_YES;
  }

  /* continuing to process request */
  if (0 != *upload_data_size)
  {
    left = GNUNET_MIN (*upload_data_size,
		       sizeof (s5r->io_buf) - s5r->io_len);
    memcpy (&s5r->io_buf[s5r->io_len],
	    upload_data,
	    left);
    s5r->io_len += left;
    *upload_data_size -= left;
    GNUNET_assert (NULL != s5r->curl);
    curl_easy_pause (s5r->curl, CURLPAUSE_CONT);
    curl_download_prepare ();
    return MHD_YES;
  }
  if (SOCKS5_SOCKET_UPLOAD_STARTED == s5r->state)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		"Finished processing UPLOAD\n");
    s5r->state = SOCKS5_SOCKET_UPLOAD_DONE;
  }
  if (NULL == s5r->response)
    return MHD_YES; /* too early to queue response, did not yet get headers from cURL */
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Queueing response with MHD\n");
  return MHD_queue_response (con,
			     s5r->response_code,
			     s5r->response);
}


/* ******************** MHD HTTP setup and event loop ******************** */


/**
 * Function called when MHD decides that we are done with a connection.
 *
 * @param cls NULL
 * @param connection connection handle
 * @param con_cls value as set by the last call to
 *        the MHD_AccessHandlerCallback, should be our `struct Socks5Request *`
 * @param toe reason for request termination (ignored)
 */
static void
mhd_completed_cb (void *cls,
		  struct MHD_Connection *connection,
		  void **con_cls,
		  enum MHD_RequestTerminationCode toe)
{
  struct Socks5Request *s5r = *con_cls;

  if (NULL == s5r)
    return;
  if (MHD_REQUEST_TERMINATED_COMPLETED_OK != toe)
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
		"MHD encountered error handling request: %d\n",
		toe);
  cleanup_s5r (s5r);
  *con_cls = NULL;
}


/**
 * Function called when MHD first processes an incoming connection.
 * Gives us the respective URI information.
 *
 * We use this to associate the `struct MHD_Connection` with our
 * internal `struct Socks5Request` data structure (by checking
 * for matching sockets).
 *
 * @param cls the HTTP server handle (a `struct MhdHttpList`)
 * @param url the URL that is being requested
 * @param connection MHD connection object for the request
 * @return the `struct Socks5Request` that this @a connection is for
 */
static void *
mhd_log_callback (void *cls,
		  const char *url,
		  struct MHD_Connection *connection)
{
  struct Socks5Request *s5r;
  const union MHD_ConnectionInfo *ci;
  int sock;

  ci = MHD_get_connection_info (connection,
				MHD_CONNECTION_INFO_CONNECTION_FD);
  if (NULL == ci)
  {
    GNUNET_break (0);
    return NULL;
  }
  sock = ci->connect_fd;
  for (s5r = s5r_head; NULL != s5r; s5r = s5r->next)
  {
    if (GNUNET_NETWORK_get_fd (s5r->sock) == sock)
    {
      if (NULL != s5r->url)
      {
	GNUNET_break (0);
	return NULL;
      }
      s5r->url = GNUNET_strdup (url);
      GNUNET_SCHEDULER_cancel (s5r->timeout_task);
      s5r->timeout_task = NULL;
      return s5r;
    }
  }
  GNUNET_break (0);
  return NULL;
}


/**
 * Kill the given MHD daemon.
 *
 * @param hd daemon to stop
 */
static void
kill_httpd (struct MhdHttpList *hd)
{
  GNUNET_CONTAINER_DLL_remove (mhd_httpd_head,
			       mhd_httpd_tail,
			       hd);
  GNUNET_free_non_null (hd->domain);
  MHD_stop_daemon (hd->daemon);
  if (NULL != hd->httpd_task)
  {
    GNUNET_SCHEDULER_cancel (hd->httpd_task);
    hd->httpd_task = NULL;
  }
  GNUNET_free_non_null (hd->proxy_cert);
  if (hd == httpd)
    httpd = NULL;
  GNUNET_free (hd);
}


/**
 * Task run whenever HTTP server is idle for too long. Kill it.
 *
 * @param cls the `struct MhdHttpList *`
 * @param tc sched context
 */
static void
kill_httpd_task (void *cls,
		 const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct MhdHttpList *hd = cls;

  hd->httpd_task = NULL;
  kill_httpd (hd);
}


/**
 * Task run whenever HTTP server operations are pending.
 *
 * @param cls the `struct MhdHttpList *` of the daemon that is being run
 * @param tc sched context
 */
static void
do_httpd (void *cls,
          const struct GNUNET_SCHEDULER_TaskContext *tc);


/**
 * Schedule MHD.  This function should be called initially when an
 * MHD is first getting its client socket, and will then automatically
 * always be called later whenever there is work to be done.
 *
 * @param hd the daemon to schedule
 */
static void
schedule_httpd (struct MhdHttpList *hd)
{
  fd_set rs;
  fd_set ws;
  fd_set es;
  struct GNUNET_NETWORK_FDSet *wrs;
  struct GNUNET_NETWORK_FDSet *wws;
  int max;
  int haveto;
  MHD_UNSIGNED_LONG_LONG timeout;
  struct GNUNET_TIME_Relative tv;

  FD_ZERO (&rs);
  FD_ZERO (&ws);
  FD_ZERO (&es);
  max = -1;
  if (MHD_YES != MHD_get_fdset (hd->daemon, &rs, &ws, &es, &max))
  {
    kill_httpd (hd);
    return;
  }
  haveto = MHD_get_timeout (hd->daemon, &timeout);
  if (MHD_YES == haveto)
    tv.rel_value_us = (uint64_t) timeout * 1000LL;
  else
    tv = GNUNET_TIME_UNIT_FOREVER_REL;
  if (-1 != max)
  {
    wrs = GNUNET_NETWORK_fdset_create ();
    wws = GNUNET_NETWORK_fdset_create ();
    GNUNET_NETWORK_fdset_copy_native (wrs, &rs, max + 1);
    GNUNET_NETWORK_fdset_copy_native (wws, &ws, max + 1);
  }
  else
  {
    wrs = NULL;
    wws = NULL;
  }
  if (NULL != hd->httpd_task)
    GNUNET_SCHEDULER_cancel (hd->httpd_task);
  if ( (MHD_YES != haveto) &&
       (-1 == max) &&
       (hd != httpd) )
  {
    /* daemon is idle, kill after timeout */
    hd->httpd_task = GNUNET_SCHEDULER_add_delayed (MHD_CACHE_TIMEOUT,
						   &kill_httpd_task,
						   hd);
  }
  else
  {
    hd->httpd_task =
      GNUNET_SCHEDULER_add_select (GNUNET_SCHEDULER_PRIORITY_DEFAULT,
				   tv, wrs, wws,
				   &do_httpd, hd);
  }
  if (NULL != wrs)
    GNUNET_NETWORK_fdset_destroy (wrs);
  if (NULL != wws)
    GNUNET_NETWORK_fdset_destroy (wws);
}


/**
 * Task run whenever HTTP server operations are pending.
 *
 * @param cls the `struct MhdHttpList` of the daemon that is being run
 * @param tc scheduler context
 */
static void
do_httpd (void *cls,
          const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct MhdHttpList *hd = cls;

  hd->httpd_task = NULL;
  MHD_run (hd->daemon);
  schedule_httpd (hd);
}


/**
 * Run MHD now, we have extra data ready for the callback.
 *
 * @param hd the daemon to run now.
 */
static void
run_mhd_now (struct MhdHttpList *hd)
{
  if (NULL !=
      hd->httpd_task)
    GNUNET_SCHEDULER_cancel (hd->httpd_task);
  hd->httpd_task = GNUNET_SCHEDULER_add_now (&do_httpd,
					     hd);
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
 * @return #GNUNET_OK on success
 */
static int
load_key_from_file (gnutls_x509_privkey_t key,
		    const char* keyfile)
{
  gnutls_datum_t key_data;
  int ret;

  key_data.data = load_file (keyfile, &key_data.size);
  if (NULL == key_data.data)
    return GNUNET_SYSERR;
  ret = gnutls_x509_privkey_import (key, &key_data,
                                    GNUTLS_X509_FMT_PEM);
  if (GNUTLS_E_SUCCESS != ret)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _("Unable to import private key from file `%s'\n"),
		keyfile);
  }
  GNUNET_free_non_null (key_data.data);
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
load_cert_from_file (gnutls_x509_crt_t crt,
		     const char* certfile)
{
  gnutls_datum_t cert_data;
  int ret;

  cert_data.data = load_file (certfile, &cert_data.size);
  if (NULL == cert_data.data)
    return GNUNET_SYSERR;
  ret = gnutls_x509_crt_import (crt, &cert_data,
                                GNUTLS_X509_FMT_PEM);
  if (GNUTLS_E_SUCCESS != ret)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
               _("Unable to import certificate %s\n"), certfile);
  }
  GNUNET_free_non_null (cert_data.data);
  return (GNUTLS_E_SUCCESS != ret) ? GNUNET_SYSERR : GNUNET_OK;
}


/**
 * Generate new certificate for specific name
 *
 * @param name the subject name to generate a cert for
 * @return a struct holding the PEM data, NULL on error
 */
static struct ProxyGNSCertificate *
generate_gns_certificate (const char *name)
{
  unsigned int serial;
  size_t key_buf_size;
  size_t cert_buf_size;
  gnutls_x509_crt_t request;
  time_t etime;
  struct tm *tm_data;
  struct ProxyGNSCertificate *pgc;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Generating TLS/SSL certificate for `%s'\n",
	      name);
  GNUNET_break (GNUTLS_E_SUCCESS == gnutls_x509_crt_init (&request));
  GNUNET_break (GNUTLS_E_SUCCESS == gnutls_x509_crt_set_key (request, proxy_ca.key));
  pgc = GNUNET_new (struct ProxyGNSCertificate);
  gnutls_x509_crt_set_dn_by_oid (request, GNUTLS_OID_X520_COUNTRY_NAME,
                                 0, "ZZ", 2);
  gnutls_x509_crt_set_dn_by_oid (request, GNUTLS_OID_X520_ORGANIZATION_NAME,
                                 0, "GNU Name System", 4);
  gnutls_x509_crt_set_dn_by_oid (request, GNUTLS_OID_X520_COMMON_NAME,
                                 0, name, strlen (name));
  GNUNET_break (GNUTLS_E_SUCCESS == gnutls_x509_crt_set_version (request, 3));
  gnutls_rnd (GNUTLS_RND_NONCE, &serial, sizeof (serial));
  gnutls_x509_crt_set_serial (request,
			      &serial,
			      sizeof (serial));
  etime = time (NULL);
  tm_data = localtime (&etime);
  gnutls_x509_crt_set_activation_time (request,
				       etime);
  tm_data->tm_year++;
  etime = mktime (tm_data);
  gnutls_x509_crt_set_expiration_time (request,
				       etime);
  gnutls_x509_crt_sign (request,
			proxy_ca.cert,
			proxy_ca.key);
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
 * Function called by MHD with errors, suppresses them all.
 *
 * @param cls closure
 * @param fm format string (`printf()`-style)
 * @param ap arguments to @a fm
 */
static void
mhd_error_log_callback (void *cls,
                        const char *fm,
                        va_list ap)
{
  /* do nothing */
}


/**
 * Lookup (or create) an SSL MHD instance for a particular domain.
 *
 * @param domain the domain the SSL daemon has to serve
 * @return NULL on error
 */
static struct MhdHttpList *
lookup_ssl_httpd (const char* domain)
{
  struct MhdHttpList *hd;
  struct ProxyGNSCertificate *pgc;

  if (NULL == domain)
  {
    GNUNET_break (0);
    return NULL;
  }
  for (hd = mhd_httpd_head; NULL != hd; hd = hd->next)
    if ( (NULL != hd->domain) &&
	 (0 == strcmp (hd->domain, domain)) )
      return hd;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Starting fresh MHD HTTPS instance for domain `%s'\n",
	      domain);
  pgc = generate_gns_certificate (domain);
  hd = GNUNET_new (struct MhdHttpList);
  hd->is_ssl = GNUNET_YES;
  hd->domain = GNUNET_strdup (domain);
  hd->proxy_cert = pgc;
  hd->daemon = MHD_start_daemon (MHD_USE_DEBUG | MHD_USE_SSL | MHD_USE_NO_LISTEN_SOCKET,
				 0,
				 NULL, NULL,
				 &create_response, hd,
				 MHD_OPTION_CONNECTION_TIMEOUT, (unsigned int) 16,
				 MHD_OPTION_NOTIFY_COMPLETED, &mhd_completed_cb, NULL,
				 MHD_OPTION_URI_LOG_CALLBACK, &mhd_log_callback, NULL,
                                 MHD_OPTION_EXTERNAL_LOGGER, &mhd_error_log_callback, NULL,
				 MHD_OPTION_HTTPS_MEM_KEY, pgc->key,
				 MHD_OPTION_HTTPS_MEM_CERT, pgc->cert,
				 MHD_OPTION_END);
  if (NULL == hd->daemon)
  {
    GNUNET_free (pgc);
    GNUNET_free (hd);
    return NULL;
  }
  GNUNET_CONTAINER_DLL_insert (mhd_httpd_head,
			       mhd_httpd_tail,
			       hd);
  return hd;
}


/**
 * Task run when a Socks5Request somehow fails to be associated with
 * an MHD connection (i.e. because the client never speaks HTTP after
 * the SOCKS5 handshake).  Clean up.
 *
 * @param cls the `struct Socks5Request *`
 * @param tc sched context
 */
static void
timeout_s5r_handshake (void *cls,
		       const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct Socks5Request *s5r = cls;

  s5r->timeout_task = NULL;
  cleanup_s5r (s5r);
}


/**
 * We're done with the Socks5 protocol, now we need to pass the
 * connection data through to the final destination, either
 * direct (if the protocol might not be HTTP), or via MHD
 * (if the port looks like it should be HTTP).
 *
 * @param s5r socks request that has reached the final stage
 */
static void
setup_data_transfer (struct Socks5Request *s5r)
{
  struct MhdHttpList *hd;
  int fd;
  const struct sockaddr *addr;
  socklen_t len;

  switch (s5r->port)
  {
  case HTTPS_PORT:
    hd = lookup_ssl_httpd (s5r->domain);
    if (NULL == hd)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		  _("Failed to start HTTPS server for `%s'\n"),
		  s5r->domain);
      cleanup_s5r (s5r);
      return;
    }
    break;
  case HTTP_PORT:
  default:
    GNUNET_assert (NULL != httpd);
    hd = httpd;
    break;
  }
  fd = GNUNET_NETWORK_get_fd (s5r->sock);
  addr = GNUNET_NETWORK_get_addr (s5r->sock);
  len = GNUNET_NETWORK_get_addrlen (s5r->sock);
  s5r->state = SOCKS5_SOCKET_WITH_MHD;
  if (MHD_YES != MHD_add_connection (hd->daemon, fd, addr, len))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
		_("Failed to pass client to MHD\n"));
    cleanup_s5r (s5r);
    return;
  }
  s5r->hd = hd;
  schedule_httpd (hd);
  s5r->timeout_task = GNUNET_SCHEDULER_add_delayed (HTTP_HANDSHAKE_TIMEOUT,
						    &timeout_s5r_handshake,
						    s5r);
}


/* ********************* SOCKS handling ************************* */


/**
 * Write data from buffer to socks5 client, then continue with state machine.
 *
 * @param cls the closure with the `struct Socks5Request`
 * @param tc scheduler context
 */
static void
do_write (void *cls,
	  const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct Socks5Request *s5r = cls;
  ssize_t len;

  s5r->wtask = NULL;
  len = GNUNET_NETWORK_socket_send (s5r->sock,
				    s5r->wbuf,
				    s5r->wbuf_len);
  if (len <= 0)
  {
    /* write error: connection closed, shutdown, etc.; just clean up */
    cleanup_s5r (s5r);
    return;
  }
  memmove (s5r->wbuf,
	   &s5r->wbuf[len],
	   s5r->wbuf_len - len);
  s5r->wbuf_len -= len;
  if (s5r->wbuf_len > 0)
  {
    /* not done writing */
    s5r->wtask =
      GNUNET_SCHEDULER_add_write_net (GNUNET_TIME_UNIT_FOREVER_REL,
				      s5r->sock,
				      &do_write, s5r);
    return;
  }

  /* we're done writing, continue with state machine! */

  switch (s5r->state)
  {
  case SOCKS5_INIT:
    GNUNET_assert (0);
    break;
  case SOCKS5_REQUEST:
    GNUNET_assert (NULL != s5r->rtask);
    break;
  case SOCKS5_DATA_TRANSFER:
    setup_data_transfer (s5r);
    return;
  case SOCKS5_WRITE_THEN_CLEANUP:
    cleanup_s5r (s5r);
    return;
  default:
    GNUNET_break (0);
    break;
  }
}


/**
 * Return a server response message indicating a failure to the client.
 *
 * @param s5r request to return failure code for
 * @param sc status code to return
 */
static void
signal_socks_failure (struct Socks5Request *s5r,
		      enum Socks5StatusCode sc)
{
  struct Socks5ServerResponseMessage *s_resp;

  s_resp = (struct Socks5ServerResponseMessage *) &s5r->wbuf[s5r->wbuf_len];
  memset (s_resp, 0, sizeof (struct Socks5ServerResponseMessage));
  s_resp->version = SOCKS_VERSION_5;
  s_resp->reply = sc;
  s5r->state = SOCKS5_WRITE_THEN_CLEANUP;
  if (NULL != s5r->wtask)
    s5r->wtask =
      GNUNET_SCHEDULER_add_write_net (GNUNET_TIME_UNIT_FOREVER_REL,
				      s5r->sock,
				      &do_write, s5r);
}


/**
 * Return a server response message indicating success.
 *
 * @param s5r request to return success status message for
 */
static void
signal_socks_success (struct Socks5Request *s5r)
{
  struct Socks5ServerResponseMessage *s_resp;

  s_resp = (struct Socks5ServerResponseMessage *) &s5r->wbuf[s5r->wbuf_len];
  s_resp->version = SOCKS_VERSION_5;
  s_resp->reply = SOCKS5_STATUS_REQUEST_GRANTED;
  s_resp->reserved = 0;
  s_resp->addr_type = SOCKS5_AT_IPV4;
  /* zero out IPv4 address and port */
  memset (&s_resp[1],
	  0,
	  sizeof (struct in_addr) + sizeof (uint16_t));
  s5r->wbuf_len += sizeof (struct Socks5ServerResponseMessage) +
    sizeof (struct in_addr) + sizeof (uint16_t);
  if (NULL == s5r->wtask)
    s5r->wtask =
      GNUNET_SCHEDULER_add_write_net (GNUNET_TIME_UNIT_FOREVER_REL,
				      s5r->sock,
				      &do_write, s5r);
}


/**
 * Process GNS results for target domain.
 *
 * @param cls the `struct Socks5Request *`
 * @param rd_count number of records returned
 * @param rd record data
 */
static void
handle_gns_result (void *cls,
		   uint32_t rd_count,
		   const struct GNUNET_GNSRECORD_Data *rd)
{
  struct Socks5Request *s5r = cls;
  uint32_t i;
  const struct GNUNET_GNSRECORD_Data *r;
  int got_ip;

  s5r->gns_lookup = NULL;
  got_ip = GNUNET_NO;
  for (i=0;i<rd_count;i++)
  {
    r = &rd[i];
    switch (r->record_type)
    {
    case GNUNET_DNSPARSER_TYPE_A:
      {
	struct sockaddr_in *in;

	if (sizeof (struct in_addr) != r->data_size)
	{
	  GNUNET_break_op (0);
	  break;
	}
	if (GNUNET_YES == got_ip)
	  break;
	if (GNUNET_OK !=
	    GNUNET_NETWORK_test_pf (PF_INET))
	  break;
	got_ip = GNUNET_YES;
      	in = (struct sockaddr_in *) &s5r->destination_address;
	in->sin_family = AF_INET;
	memcpy (&in->sin_addr,
		r->data,
		r->data_size);
	in->sin_port = htons (s5r->port);
#if HAVE_SOCKADDR_IN_SIN_LEN
	in->sin_len = sizeof (*in);
#endif
      }
      break;
    case GNUNET_DNSPARSER_TYPE_AAAA:
      {
	struct sockaddr_in6 *in;

	if (sizeof (struct in6_addr) != r->data_size)
	{
	  GNUNET_break_op (0);
	  break;
	}
	if (GNUNET_YES == got_ip)
	  break;
	if (GNUNET_OK !=
	    GNUNET_NETWORK_test_pf (PF_INET))
	  break;
	/* FIXME: allow user to disable IPv6 per configuration option... */
	got_ip = GNUNET_YES;
      	in = (struct sockaddr_in6 *) &s5r->destination_address;
	in->sin6_family = AF_INET6;
	memcpy (&in->sin6_addr,
		r->data,
		r->data_size);
	in->sin6_port = htons (s5r->port);
#if HAVE_SOCKADDR_IN_SIN_LEN
	in->sin6_len = sizeof (*in);
#endif
      }
      break;
    case GNUNET_GNSRECORD_TYPE_VPN:
      GNUNET_break (0); /* should have been translated within GNS */
      break;
    case GNUNET_GNSRECORD_TYPE_LEHO:
      GNUNET_free_non_null (s5r->leho);
      s5r->leho = GNUNET_strndup (r->data,
				  r->data_size);
      break;
    case GNUNET_GNSRECORD_TYPE_BOX:
      {
        const struct GNUNET_GNSRECORD_BoxRecord *box;

        if (r->data_size < sizeof (struct GNUNET_GNSRECORD_BoxRecord))
        {
          GNUNET_break_op (0);
          break;
        }
        box = r->data;
        if ( (ntohl (box->record_type) != GNUNET_DNSPARSER_TYPE_TLSA) ||
             (ntohs (box->protocol) != IPPROTO_TCP) ||
             (ntohs (box->service) != s5r->port) )
          break; /* BOX record does not apply */
        GNUNET_free_non_null (s5r->dane_data);
        s5r->dane_data_len = r->data_size - sizeof (struct GNUNET_GNSRECORD_BoxRecord);
        s5r->dane_data = GNUNET_malloc (s5r->dane_data_len);
        memcpy (s5r->dane_data,
                &box[1],
                s5r->dane_data_len);
        break;
      }
    default:
      /* don't care */
      break;
    }
  }
  if (GNUNET_YES != got_ip)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		"Name resolution failed to yield useful IP address.\n");
    signal_socks_failure (s5r,
			  SOCKS5_STATUS_GENERAL_FAILURE);
    return;
  }
  s5r->state = SOCKS5_DATA_TRANSFER;
  signal_socks_success (s5r);
}


/**
 * Remove the first @a len bytes from the beginning of the read buffer.
 *
 * @param s5r the handle clear the read buffer for
 * @param len number of bytes in read buffer to advance
 */
static void
clear_from_s5r_rbuf (struct Socks5Request *s5r,
		     size_t len)
{
  GNUNET_assert (len <= s5r->rbuf_len);
  memmove (s5r->rbuf,
	   &s5r->rbuf[len],
	   s5r->rbuf_len - len);
  s5r->rbuf_len -= len;
}


/**
 * Read data from incoming Socks5 connection
 *
 * @param cls the closure with the `struct Socks5Request`
 * @param tc the scheduler context
 */
static void
do_s5r_read (void *cls,
	     const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct Socks5Request *s5r = cls;
  const struct Socks5ClientHelloMessage *c_hello;
  struct Socks5ServerHelloMessage *s_hello;
  const struct Socks5ClientRequestMessage *c_req;
  ssize_t rlen;
  size_t alen;

  s5r->rtask = NULL;
  if ( (NULL != tc->read_ready) &&
       (GNUNET_NETWORK_fdset_isset (tc->read_ready, s5r->sock)) )
  {
    rlen = GNUNET_NETWORK_socket_recv (s5r->sock,
				       &s5r->rbuf[s5r->rbuf_len],
				       sizeof (s5r->rbuf) - s5r->rbuf_len);
    if (rlen <= 0)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "socks5 client disconnected.\n");
      cleanup_s5r (s5r);
      return;
    }
    s5r->rbuf_len += rlen;
  }
  s5r->rtask = GNUNET_SCHEDULER_add_read_net (GNUNET_TIME_UNIT_FOREVER_REL,
					      s5r->sock,
					      &do_s5r_read, s5r);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Processing %u bytes of socks data in state %d\n",
	      s5r->rbuf_len,
	      s5r->state);
  switch (s5r->state)
  {
  case SOCKS5_INIT:
    c_hello = (const struct Socks5ClientHelloMessage*) &s5r->rbuf;
    if ( (s5r->rbuf_len < sizeof (struct Socks5ClientHelloMessage)) ||
	 (s5r->rbuf_len < sizeof (struct Socks5ClientHelloMessage) + c_hello->num_auth_methods) )
      return; /* need more data */
    if (SOCKS_VERSION_5 != c_hello->version)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		  _("Unsupported socks version %d\n"),
		  (int) c_hello->version);
      cleanup_s5r (s5r);
      return;
    }
    clear_from_s5r_rbuf (s5r,
			 sizeof (struct Socks5ClientHelloMessage) + c_hello->num_auth_methods);
    GNUNET_assert (0 == s5r->wbuf_len);
    s_hello = (struct Socks5ServerHelloMessage *) &s5r->wbuf;
    s5r->wbuf_len = sizeof (struct Socks5ServerHelloMessage);
    s_hello->version = SOCKS_VERSION_5;
    s_hello->auth_method = SOCKS_AUTH_NONE;
    GNUNET_assert (NULL == s5r->wtask);
    s5r->wtask = GNUNET_SCHEDULER_add_write_net (GNUNET_TIME_UNIT_FOREVER_REL,
						 s5r->sock,
						 &do_write, s5r);
    s5r->state = SOCKS5_REQUEST;
    return;
  case SOCKS5_REQUEST:
    c_req = (const struct Socks5ClientRequestMessage *) &s5r->rbuf;
    if (s5r->rbuf_len < sizeof (struct Socks5ClientRequestMessage))
      return;
    switch (c_req->command)
    {
    case SOCKS5_CMD_TCP_STREAM:
      /* handled below */
      break;
    default:
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		  _("Unsupported socks command %d\n"),
		  (int) c_req->command);
      signal_socks_failure (s5r,
			    SOCKS5_STATUS_COMMAND_NOT_SUPPORTED);
      return;
    }
    switch (c_req->addr_type)
    {
    case SOCKS5_AT_IPV4:
      {
	const struct in_addr *v4 = (const struct in_addr *) &c_req[1];
	const uint16_t *port = (const uint16_t *) &v4[1];
	struct sockaddr_in *in;

	s5r->port = ntohs (*port);
        if (HTTPS_PORT == s5r->port)
        {
          GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                      _("SSL connection to plain IPv4 address requested\n"));
          signal_socks_failure (s5r,
                                SOCKS5_STATUS_CONNECTION_NOT_ALLOWED_BY_RULE);
          return;
        }
	alen = sizeof (struct in_addr);
	if (s5r->rbuf_len < sizeof (struct Socks5ClientRequestMessage) +
	    alen + sizeof (uint16_t))
	  return; /* need more data */
	in = (struct sockaddr_in *) &s5r->destination_address;
	in->sin_family = AF_INET;
	in->sin_addr = *v4;
	in->sin_port = *port;
#if HAVE_SOCKADDR_IN_SIN_LEN
	in->sin_len = sizeof (*in);
#endif
	s5r->state = SOCKS5_DATA_TRANSFER;
      }
      break;
    case SOCKS5_AT_IPV6:
      {
	const struct in6_addr *v6 = (const struct in6_addr *) &c_req[1];
	const uint16_t *port = (const uint16_t *) &v6[1];
	struct sockaddr_in6 *in;

	s5r->port = ntohs (*port);
        if (HTTPS_PORT == s5r->port)
        {
          GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                      _("SSL connection to plain IPv4 address requested\n"));
          signal_socks_failure (s5r,
                                SOCKS5_STATUS_CONNECTION_NOT_ALLOWED_BY_RULE);
          return;
        }
	alen = sizeof (struct in6_addr);
	if (s5r->rbuf_len < sizeof (struct Socks5ClientRequestMessage) +
	    alen + sizeof (uint16_t))
	  return; /* need more data */
	in = (struct sockaddr_in6 *) &s5r->destination_address;
	in->sin6_family = AF_INET6;
	in->sin6_addr = *v6;
	in->sin6_port = *port;
#if HAVE_SOCKADDR_IN_SIN_LEN
	in->sin6_len = sizeof (*in);
#endif
	s5r->state = SOCKS5_DATA_TRANSFER;
      }
      break;
    case SOCKS5_AT_DOMAINNAME:
      {
	const uint8_t *dom_len;
	const char *dom_name;
	const uint16_t *port;

	dom_len = (const uint8_t *) &c_req[1];
	alen = *dom_len + 1;
	if (s5r->rbuf_len < sizeof (struct Socks5ClientRequestMessage) +
	    alen + sizeof (uint16_t))
	  return; /* need more data */
	dom_name = (const char *) &dom_len[1];
	port = (const uint16_t*) &dom_name[*dom_len];
	s5r->domain = GNUNET_strndup (dom_name, *dom_len);
	GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		    "Requested connection is to %s:%d\n",
		    s5r->domain,
		    ntohs (*port));
	s5r->state = SOCKS5_RESOLVING;
	s5r->port = ntohs (*port);
	s5r->gns_lookup = GNUNET_GNS_lookup (gns_handle,
					     s5r->domain,
					     &local_gns_zone,
					     GNUNET_DNSPARSER_TYPE_A,
					     GNUNET_NO /* only cached */,
					     (GNUNET_YES == do_shorten) ? &local_shorten_zone : NULL,
					     &handle_gns_result,
					     s5r);
	break;
      }
    default:
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		  _("Unsupported socks address type %d\n"),
		  (int) c_req->addr_type);
      signal_socks_failure (s5r,
			    SOCKS5_STATUS_ADDRESS_TYPE_NOT_SUPPORTED);
      return;
    }
    clear_from_s5r_rbuf (s5r,
			 sizeof (struct Socks5ClientRequestMessage) +
			 alen + sizeof (uint16_t));
    if (0 != s5r->rbuf_len)
    {
      /* read more bytes than healthy, why did the client send more!? */
      GNUNET_break_op (0);
      signal_socks_failure (s5r,
			    SOCKS5_STATUS_GENERAL_FAILURE);
      return;
    }
    if (SOCKS5_DATA_TRANSFER == s5r->state)
    {
      /* if we are not waiting for GNS resolution, signal success */
      signal_socks_success (s5r);
    }
    /* We are done reading right now */
    GNUNET_SCHEDULER_cancel (s5r->rtask);
    s5r->rtask = NULL;
    return;
  case SOCKS5_RESOLVING:
    GNUNET_assert (0);
    return;
  case SOCKS5_DATA_TRANSFER:
    GNUNET_assert (0);
    return;
  default:
    GNUNET_assert (0);
    return;
  }
}


/**
 * Accept new incoming connections
 *
 * @param cls the closure with the lsock4 or lsock6
 * @param tc the scheduler context
 */
static void
do_accept (void *cls,
	   const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_NETWORK_Handle *lsock = cls;
  struct GNUNET_NETWORK_Handle *s;
  struct Socks5Request *s5r;

  if (lsock == lsock4)
    ltask4 = NULL;
  else
    ltask6 = NULL;
  if (0 != (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN))
    return;
  if (lsock == lsock4)
    ltask4 = GNUNET_SCHEDULER_add_read_net (GNUNET_TIME_UNIT_FOREVER_REL,
                                            lsock,
                                            &do_accept, lsock);
  else
    ltask6 = GNUNET_SCHEDULER_add_read_net (GNUNET_TIME_UNIT_FOREVER_REL,
                                            lsock,
                                            &do_accept, lsock);
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


/* ******************* General / main code ********************* */


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
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "Shutting down...\n");
  while (NULL != mhd_httpd_head)
    kill_httpd (mhd_httpd_head);
  while (NULL != s5r_head)
    cleanup_s5r (s5r_head);
  if (NULL != lsock4)
  {
    GNUNET_NETWORK_socket_close (lsock4);
    lsock4 = NULL;
  }
  if (NULL != lsock6)
  {
    GNUNET_NETWORK_socket_close (lsock6);
    lsock6 = NULL;
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
  if (NULL != curl_download_task)
  {
    GNUNET_SCHEDULER_cancel (curl_download_task);
    curl_download_task = NULL;
  }
  if (NULL != ltask4)
  {
    GNUNET_SCHEDULER_cancel (ltask4);
    ltask4 = NULL;
  }
  if (NULL != ltask6)
  {
    GNUNET_SCHEDULER_cancel (ltask6);
    ltask6 = NULL;
  }
  gnutls_x509_crt_deinit (proxy_ca.cert);
  gnutls_x509_privkey_deinit (proxy_ca.key);
  gnutls_global_deinit ();
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
                                     SOCK_STREAM,
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
 * Create an IPv6 listen socket bound to our port.
 *
 * @return NULL on error
 */
static struct GNUNET_NETWORK_Handle *
bind_v6 ()
{
  struct GNUNET_NETWORK_Handle *ls;
  struct sockaddr_in6 sa6;
  int eno;

  memset (&sa6, 0, sizeof (sa6));
  sa6.sin6_family = AF_INET6;
  sa6.sin6_port = htons (port);
#if HAVE_SOCKADDR_IN_SIN_LEN
  sa6.sin6_len = sizeof (sa6);
#endif
  ls = GNUNET_NETWORK_socket_create (AF_INET6,
                                     SOCK_STREAM,
                                     0);
  if (NULL == ls)
    return NULL;
  if (GNUNET_OK !=
      GNUNET_NETWORK_socket_bind (ls, (const struct sockaddr *) &sa6,
				  sizeof (sa6)))
  {
    eno = errno;
    GNUNET_NETWORK_socket_close (ls);
    errno = eno;
    return NULL;
  }
  return ls;
}


/**
 * Continue initialization after we have our zone information.
 */
static void
run_cont ()
{
  struct MhdHttpList *hd;

  /* Open listen socket for socks proxy */
  lsock6 = bind_v6 ();
  if (NULL == lsock6)
    GNUNET_log_strerror (GNUNET_ERROR_TYPE_ERROR, "bind");
  else
  {
    if (GNUNET_OK != GNUNET_NETWORK_socket_listen (lsock6, 5))
    {
      GNUNET_log_strerror (GNUNET_ERROR_TYPE_ERROR, "listen");
      GNUNET_NETWORK_socket_close (lsock6);
      lsock6 = NULL;
    }
    else
    {
      ltask6 = GNUNET_SCHEDULER_add_read_net (GNUNET_TIME_UNIT_FOREVER_REL,
                                              lsock6, &do_accept, lsock6);
    }
  }
  lsock4 = bind_v4 ();
  if (NULL == lsock4)
    GNUNET_log_strerror (GNUNET_ERROR_TYPE_ERROR, "bind");
  else
  {
    if (GNUNET_OK != GNUNET_NETWORK_socket_listen (lsock4, 5))
    {
      GNUNET_log_strerror (GNUNET_ERROR_TYPE_ERROR, "listen");
      GNUNET_NETWORK_socket_close (lsock4);
      lsock4 = NULL;
    }
    else
    {
      ltask4 = GNUNET_SCHEDULER_add_read_net (GNUNET_TIME_UNIT_FOREVER_REL,
                                              lsock4, &do_accept, lsock4);
    }
  }
  if ( (NULL == lsock4) &&
       (NULL == lsock6) )
  {
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
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
  hd->daemon = MHD_start_daemon (MHD_USE_DEBUG | MHD_USE_NO_LISTEN_SOCKET,
				 0,
				 NULL, NULL,
				 &create_response, hd,
				 MHD_OPTION_CONNECTION_TIMEOUT, (unsigned int) 16,
				 MHD_OPTION_NOTIFY_COMPLETED, &mhd_completed_cb, NULL,
				 MHD_OPTION_URI_LOG_CALLBACK, &mhd_log_callback, NULL,
				 MHD_OPTION_END);
  if (NULL == hd->daemon)
  {
    GNUNET_free (hd);
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  httpd = hd;
  GNUNET_CONTAINER_DLL_insert (mhd_httpd_head, mhd_httpd_tail, hd);
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
		_("No ego configured for `%s`\n"),
		"gns-proxy");
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  GNUNET_IDENTITY_ego_get_public_key (ego,
				      &local_gns_zone);
  id_op = GNUNET_IDENTITY_get (identity,
			       "gns-short",
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
    gnutls_x509_crt_deinit (proxy_ca.cert);
    gnutls_x509_privkey_deinit (proxy_ca.key);
    gnutls_global_deinit ();
    GNUNET_free_non_null (cafile_cfg);
    return;
  }
  GNUNET_free_non_null (cafile_cfg);
  if (NULL == (gns_handle = GNUNET_GNS_connect (cfg)))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Unable to connect to GNS!\n");
    gnutls_x509_crt_deinit (proxy_ca.cert);
    gnutls_x509_privkey_deinit (proxy_ca.key);
    gnutls_global_deinit ();
    return;
  }
  identity = GNUNET_IDENTITY_connect (cfg,
				      NULL, NULL);
  id_op = GNUNET_IDENTITY_get (identity,
			       "gns-proxy",
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
  GNUNET_CRYPTO_ecdsa_key_clear (&local_shorten_zone);
  return ret;
}

/* end of gnunet-gns-proxy.c */

/*
     This file is part of GNUnet.
     (C) 2009, 2010 Christian Grothoff (and other contributing authors)

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

/*
 * Code in this file is originally based on the miniupnp library.
 * Copyright (c) 2005-2009, Thomas BERNARD. All rights reserved.
 *
 * Original licence:
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * 
 *   * Redistributions of source code must retain the above copyright notice,
 *     this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright notice,
 *     this list of conditions and the following disclaimer in the documentation
 *     and/or other materials provided with the distribution.
 *   * The name of the author may not be used to endorse or promote products
 * 	   derived from this software without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/**
 * @file nat/upnp-commands.c
 * @brief Implementation of a basic set of UPnP commands
 *
 * @author Milan Bouchet-Valat
 */

#include "platform.h"
#include "gnunet_util_lib.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "upnp-reply-parse.h"
#include "upnp-igd-parse.h"
#include "upnp-discover.h"
#include "upnp-commands.h"

#define SOAP_PREFIX "s"
#define SERVICE_PREFIX "u"
#define SERVICE_PREFIX2 'u'
#define MAX_HOSTNAME_LEN 64

#define PRINT_UPNP_ERROR(a, b) GNUNET_log_from(GNUNET_ERROR_TYPE_WARNING, "UPnP", _("%s failed at %s:%d: %s\n"), a, __FILE__, __LINE__, b);


/**
 * Private closure used by UPNP_command() and its callbacks.
 */
struct UPNP_command_cls
{
  /**
   * Connection handle used for sending and receiving.
   */
  struct GNUNET_CONNECTION_Handle *s;

  /**
   * Transmission handle used for sending command.
   */
  struct GNUNET_CONNECTION_TransmitHandle *th;

  /**
   * HTML content to send to run command.
   */
  char *content;

  /**
   * Buffer where to copy received data to pass to caller.
   */
  char *buffer;

  /**
   * Size of buffer.
   */
  size_t buf_size;

  /**
   * User callback to trigger when done.
   */
  UPNP_command_cb_ caller_cb;

  /**
   * User closure to pass to caller_cb.
   */
  void *caller_cls;
};

/**
 * Get the length of content included in an HTML line.
 *
 * @param p line to parse
 * @param n size of p
 * @return the length of the content
 */
static ssize_t
get_content_len_from_line (const char *p, int n)
{
  static const char cont_len_str[] = "content-length";
  const char *p2 = cont_len_str;
  int a = 0;

  while (*p2)
    {
      if (n == 0)
        return -1;

      if (*p2 != *p && *p2 != (*p + 32))
        return -1;

      p++;
      p2++;
      n--;
    }

  if (n == 0)
    return -1;

  if (*p != ':')
    return -1;

  p++;
  n--;

  while (*p == ' ')
    {
      if (n == 0)
        return -1;

      p++;
      n--;
    }

  while (*p >= '0' && *p <= '9')
    {
      if (n == 0)
        return -1;

      a = (a * 10) + (*p - '0');
      p++;
      n--;
    }

  return a;
}

/**
 * Get the respective lengths of content and header from an HTML reply.
 *
 * @param p HTML to parse
 * @param n size of p
 * @param content_len pointer to store content length to
 * @param content_len pointer to store header length to
 */
static void
get_content_and_header_len (const char *p, int n,
                            int *content_len, int *header_len)
{
  const char *line;
  int line_len;
  int r;

  line = p;

  while (line < p + n)
    {
      line_len = 0;

      while (line[line_len] != '\r' && line[line_len] != '\r')
        {
          if (line + line_len >= p + n)
            return;

          line_len++;
        }

      r = get_content_len_from_line (line, line_len);

      if (r > 0)
        *content_len = r;

      line = line + line_len + 2;

      if (line[0] == '\r' && line[1] == '\n')
        {
          *header_len = (line - p) + 2;
          return;
        }
    }
}

/**
 * Receive reply of the device to our UPnP command.
 *
 * @param data closure from UPNP_command()
 * @param buf struct UPNP_command_cls *cls
 * @param available number of bytes in buf
 * @param addr address of the sender
 * @param addrlen size of addr
 * @param errCode value of errno
 */
static void
UPNP_command_receiver (void *data,
                       const void *buf,
                       size_t available,
                       const struct sockaddr *addr,
                       socklen_t addrlen, int errCode)
{
  struct UPNP_command_cls *cls = data;
  int content_len;
  int header_len;

  if (available > 0)
    {
      content_len = -1;
      header_len = -1;
      get_content_and_header_len (buf, available, &content_len, &header_len);

      strncpy (cls->buffer, (char *) buf, cls->buf_size - 2);
      cls->buffer[cls->buf_size - 2] = '\0';
    }
  else
    {
      cls->buffer[0] = '\0';
    }

  GNUNET_CONNECTION_destroy (cls->s, GNUNET_NO);

  cls->caller_cb (cls->buffer, cls->buf_size, cls->caller_cls);

  GNUNET_free (cls->content);
  GNUNET_free (cls);
}

/**
 * Send UPnP command to device.
 */
static size_t
UPNP_command_transmit (void *data, size_t size, void *buf)
{
  struct UPNP_command_cls *cls = data;
  int n;
  char *content = cls->content;

  n = strlen (content);
  memcpy (buf, content, size);

  GNUNET_CONNECTION_receive (cls->s, cls->buf_size, GNUNET_TIME_UNIT_MINUTES,
                             UPNP_command_receiver, cls);

  return n;
}

/**
 * Parse a HTTP URL string to extract hostname, port and path it points to.
 *
 * @param url source string corresponding to URL
 * @param hostname pointer where to store hostname (size of MAX_HOSTNAME_LEN+1)
 * @param port pointer where to store port
 * @param path pointer where to store path
 *
 * @return GNUNET_OK on success, GNUNET_SYSERR on failure
 */
int
parse_url (const char *url, char *hostname, unsigned short *port, char **path)
{
  char *p1, *p2, *p3;

  if (!url)
    return GNUNET_SYSERR;

  p1 = strstr (url, "://");

  if (!p1)
    return GNUNET_SYSERR;

  p1 += 3;

  if ((url[0] != 'h') || (url[1] != 't')
      || (url[2] != 't') || (url[3] != 'p'))
    return GNUNET_SYSERR;

  p2 = strchr (p1, ':');
  p3 = strchr (p1, '/');

  if (!p3)
    return GNUNET_SYSERR;

  memset (hostname, 0, MAX_HOSTNAME_LEN + 1);

  if (!p2 || (p2 > p3))
    {
      strncpy (hostname, p1, GNUNET_MIN (MAX_HOSTNAME_LEN, (int) (p3 - p1)));
      *port = 80;
    }
  else
    {
      strncpy (hostname, p1, GNUNET_MIN (MAX_HOSTNAME_LEN, (int) (p2 - p1)));
      *port = 0;
      p2++;

      while ((*p2 >= '0') && (*p2 <= '9'))
        {
          *port *= 10;
          *port += (unsigned short) (*p2 - '0');
          p2++;
        }
    }

  *path = p3;
  return GNUNET_OK;
}

/**
 * Send UPnP command to the device identified by url and service.
 * 
 * @param url control URL of the device
 * @param service type of the service corresponding to the command
 * @param action action to send
 * @param args arguments for action
 * @param buffer buffer
 * @param buf_size buffer size
 * @param caller_cb user callback to trigger when done
 * @param caller_cls closure to pass to caller_cb
 */
void
UPNP_command_ (const char *url, const char *service,
               const char *action, struct UPNP_Arg_ *args,
               char *buffer, size_t buf_size,
               UPNP_command_cb_ caller_cb, void *caller_cls)
{
  struct GNUNET_CONNECTION_Handle *s;
  struct UPNP_command_cls *cls;
  struct sockaddr_in dest;
  struct sockaddr_in6 dest6;
  char hostname[MAX_HOSTNAME_LEN + 1];
  unsigned short port = 0;
  char *path;
  char soap_act[128];
  char soap_body[2048];
  int body_size;
  char *content_buf;
  int headers_size;
  char port_str[8];

  snprintf (soap_act, sizeof (soap_act), "%s#%s", service, action);

  if (args == NULL)
    {
      snprintf (soap_body, sizeof (soap_body),
                "<?xml version=\"1.0\"?>\r\n"
                "<" SOAP_PREFIX ":Envelope "
                "xmlns:" SOAP_PREFIX
                "=\"http://schemas.xmlsoap.org/soap/envelope/\" "
                SOAP_PREFIX
                ":encodingStyle=\"http://schema      GNUNET_free (content_buf);s.xmlsoap.org/soap/encoding/\">"
                "<" SOAP_PREFIX ":Body>" "<" SERVICE_PREFIX
                ":%s xmlns:" SERVICE_PREFIX "=\"%s\">" "</"
                SERVICE_PREFIX ":%s>" "</" SOAP_PREFIX
                ":Body></" SOAP_PREFIX ":Envelope>" "\r\n",
                action, service, action);
    }
  else
    {
      char *p;
      const char *pe, *pv;
      int soap_body_len;

      soap_body_len = snprintf (soap_body, sizeof (soap_body),
                                "<?xml version=\"1.0\"?>\r\n"
                                "<" SOAP_PREFIX ":Envelope "
                                "xmlns:" SOAP_PREFIX
                                "=\"http://schemas.xmlsoap.org/soap/envelope/\" "
                                SOAP_PREFIX
                                ":encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">"
                                "<" SOAP_PREFIX ":Body>" "<" SERVICE_PREFIX
                                ":%s xmlns:" SERVICE_PREFIX "=\"%s\">",
                                action, service);

      p = soap_body + soap_body_len;

      while (args->elt)
        {
          /* check that we are never overflowing the string... */
          if (soap_body + sizeof (soap_body) <= p + 100)
            {
              GNUNET_assert (GNUNET_NO);
              caller_cb (buffer, 0, caller_cls);
              return;
            }
          *(p++) = '<';
          pe = args->elt;
          while (*pe)
            *(p++) = *(pe++);
          *(p++) = '>';
          if ((pv = args->val))
            {
              while (*pv)
                *(p++) = *(pv++);
            }
          *(p++) = '<';
          *(p++) = '/';
          pe = args->elt;
          while (*pe)
            *(p++) = *(pe++);
          *(p++) = '>';
          args++;
        }
      *(p++) = '<';
      *(p++) = '/';
      *(p++) = SERVICE_PREFIX2;
      *(p++) = ':';
      pe = action;

      while (*pe)
        *(p++) = *(pe++);

      strncpy (p, "></" SOAP_PREFIX ":Body></" SOAP_PREFIX ":Envelope>\r\n",
               soap_body + sizeof (soap_body) - p);
    }

  if (GNUNET_OK != parse_url (url, hostname, &port, &path))
    {
      GNUNET_log_from (GNUNET_ERROR_TYPE_WARNING, "UPnP",
                       "Invalid URL passed to UPNP_command(): %s\n", url);
      caller_cb (buffer, 0, caller_cls);
      return;
    }


  /* Test IPv4 address, else use IPv6 */
  memset (&dest, 0, sizeof (dest));
  memset (&dest6, 0, sizeof (dest6));

  if (inet_pton (AF_INET, hostname, &dest.sin_addr) == 1)
    {
      dest.sin_family = AF_INET;
      dest.sin_port = htons (port);
#ifdef HAVE_SOCKADDR_IN_SIN_LEN
      dest.sin_len = sizeof (dest);
#endif

      s = GNUNET_CONNECTION_create_from_sockaddr (PF_INET,
                                                  (struct sockaddr *) &dest,
                                                  sizeof (dest));
    }
  else if (inet_pton (AF_INET6, hostname, &dest6.sin6_addr) == 1)
    {
      dest6.sin6_family = AF_INET6;
      dest6.sin6_port = htons (port);
#ifdef HAVE_SOCKADDR_IN_SIN_LEN
      dest6.sin6_len = sizeof (dest6);
#endif

      s = GNUNET_CONNECTION_create_from_sockaddr (PF_INET6,
                                                  (struct sockaddr *) &dest6,
                                                  sizeof (dest6));
    }
  else
    {
      GNUNET_log_from (GNUNET_ERROR_TYPE_WARNING, _("%s failed at %s:%d\n"),
                       "UPnP", "inet_pton", __FILE__, __LINE__);

      caller_cb (buffer, 0, caller_cls);
      return;
    }

  body_size = (int) strlen (soap_body);
  content_buf = GNUNET_malloc (512 + body_size);

  /* We are not using keep-alive HTTP connections.
   * HTTP/1.1 needs the header Connection: close to do that.
   * This is the default with HTTP/1.0 */
  /* Connection: Close is normally there only in HTTP/1.1 but who knows */
  port_str[0] = '\0';

  if (port != 80)
    snprintf (port_str, sizeof (port_str), ":%hu", port);

  headers_size = snprintf (content_buf, 512, "POST %s HTTP/1.1\r\n" "Host: %s%s\r\n" "User-Agent: GNU, UPnP/1.0, GNUnet/" PACKAGE_VERSION "\r\n" "Content-Length: %d\r\n" "Content-Type: text/xml\r\n" "SOAPAction: \"%s\"\r\n" "Connection: Close\r\n" "Cache-Control: no-cache\r\n"   /* ??? */
                           "Pragma: no-cache\r\n"
                           "\r\n", path, hostname, port_str, body_size,
                           soap_act);
  memcpy (content_buf + headers_size, soap_body, body_size);

#ifdef DEBUG_UPNP
  GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, "UPnP",
                   "Sending command '%s' to '%s' (service '%s')\n",
                   action, url, service);
#endif

  cls = GNUNET_malloc (sizeof (struct UPNP_command_cls));
  cls->s = s;
  cls->content = content_buf;
  cls->buffer = buffer;
  cls->buf_size = buf_size;
  cls->caller_cb = caller_cb;
  cls->caller_cls = caller_cls;

  cls->th =
    GNUNET_CONNECTION_notify_transmit_ready (s, body_size + headers_size,
                                             GNUNET_TIME_relative_multiply
                                             (GNUNET_TIME_UNIT_SECONDS, 15),
                                             &UPNP_command_transmit, cls);


  if (cls->th == NULL)
    {
#ifdef DEBUG_UPNP
      GNUNET_log_from (GNUNET_ERROR_TYPE_WARNING, "UPnP",
                       "Error sending SOAP request at %s:%d\n", __FILE__,
                       __LINE__);
#endif

      caller_cb (buffer, 0, caller_cls);

      GNUNET_free (content_buf);
      GNUNET_free (cls);
      GNUNET_CONNECTION_destroy (s, GNUNET_NO);
      return;
    }
}

struct get_external_ip_address_cls
{
  UPNP_get_external_ip_address_cb_ caller_cb;
  void *caller_cls;
};

static void
get_external_ip_address_receiver (char *response, size_t received, void *data)
{
  struct get_external_ip_address_cls *cls = data;
  struct UPNP_REPLY_NameValueList_ pdata;
  char extIpAdd[128];
  char *p;
  int ret = UPNP_COMMAND_UNKNOWN_ERROR;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Response: %s", response);

  UPNP_REPLY_parse_ (response, received, &pdata);
  p = UPNP_REPLY_get_value_ (&pdata, "NewExternalIPAddress");
  if (p)
    {
      strncpy (extIpAdd, p, 128);
      extIpAdd[127] = '\0';
      ret = UPNP_COMMAND_SUCCESS;
    }
  else
    extIpAdd[0] = '\0';

  p = UPNP_REPLY_get_value_ (&pdata, "errorCode");
  if (p)
    {
      ret = UPNP_COMMAND_UNKNOWN_ERROR;
      sscanf (p, "%d", &ret);
    }
  cls->caller_cb (ret, extIpAdd, cls->caller_cls);

  UPNP_REPLY_free_ (&pdata);
  GNUNET_free (response);
  GNUNET_free (cls);
}

/* UPNP_get_external_ip_address_() call the corresponding UPNP method.
 * 
 * Return values :
 * 0 : SUCCESS
 * NON ZERO : ERROR Either an UPnP error code or an unknown error.
 *
 * 402 Invalid Args - See UPnP Device Architecture section on Control.
 * 501 Action Failed - See UPnP Device Architecture section on Control.
 */
void
UPNP_get_external_ip_address_ (const char *control_url,
                               const char *service_type,
                               UPNP_get_external_ip_address_cb_ caller_cb,
                               void *caller_cls)
{
  struct get_external_ip_address_cls *cls;
  char *buffer;

  if (!control_url || !service_type)
    caller_cb (UPNP_COMMAND_INVALID_ARGS, NULL, caller_cls);

  cls = GNUNET_malloc (sizeof (struct get_external_ip_address_cls));
  cls->caller_cb = caller_cb;
  cls->caller_cls = caller_cls;

  buffer = GNUNET_malloc (UPNP_COMMAND_BUFSIZE);

  UPNP_command_ (control_url, service_type, "GetExternalIPAddress",
                 NULL, buffer, UPNP_COMMAND_BUFSIZE,
                 (UPNP_command_cb_) get_external_ip_address_receiver, cls);
}

struct PortMapping_cls
{
  const char *control_url;
  const char *service_type;
  const char *ext_port;
  const char *in_port;
  const char *proto;
  const char *remoteHost;
  UPNP_port_mapping_cb_ caller_cb;
  void *caller_cls;
};

static void
add_delete_port_mapping_receiver (char *response, size_t received, void *data)
{
  struct PortMapping_cls *cls = data;
  struct UPNP_REPLY_NameValueList_ pdata;
  const char *resVal;
  int ret;

  UPNP_REPLY_parse_ (response, received, &pdata);
  resVal = UPNP_REPLY_get_value_ (&pdata, "errorCode");
  if (resVal)
    {
      ret = UPNP_COMMAND_UNKNOWN_ERROR;
      sscanf (resVal, "%d", &ret);
    }
  else
    {
      ret = UPNP_COMMAND_SUCCESS;
    }

  cls->caller_cb (ret, cls->control_url, cls->service_type,
                  cls->ext_port, cls->in_port, cls->proto,
                  cls->remoteHost, cls->caller_cls);

  UPNP_REPLY_free_ (&pdata);
  GNUNET_free (response);
  GNUNET_free (cls);
}

void
UPNP_add_port_mapping_ (const char *control_url, const char *service_type,
                        const char *ext_port,
                        const char *in_port,
                        const char *inClient,
                        const char *desc,
                        const char *proto, const char *remoteHost,
                        UPNP_port_mapping_cb_ caller_cb, void *caller_cls)
{
  struct UPNP_Arg_ args[9];
  struct PortMapping_cls *cls;
  char *buffer;

  if (!in_port || !inClient || !proto || !ext_port)
    {
      caller_cb (UPNP_COMMAND_INVALID_ARGS, control_url, service_type,
                 ext_port, in_port, proto, remoteHost, caller_cls);
      return;
    }

  args[0].elt = "NewRemoteHost";
  args[0].val = remoteHost;
  args[1].elt = "NewExternalPort";
  args[1].val = ext_port;
  args[2].elt = "NewProtocol";
  args[2].val = proto;
  args[3].elt = "NewInternalPort";
  args[3].val = in_port;
  args[4].elt = "NewInternalClient";
  args[4].val = inClient;
  args[5].elt = "NewEnabled";
  args[5].val = "1";
  args[6].elt = "NewPortMappingDescription";
  args[6].val = desc ? desc : "GNUnet";
  args[7].elt = "NewLeaseDuration";
  args[7].val = "0";
  args[8].elt = NULL;
  args[8].val = NULL;

  cls = GNUNET_malloc (sizeof (struct PortMapping_cls));
  cls->control_url = control_url;
  cls->service_type = service_type;
  cls->ext_port = ext_port;;
  cls->in_port = in_port;
  cls->proto = proto;
  cls->remoteHost = remoteHost;
  cls->caller_cb = caller_cb;
  cls->caller_cls = caller_cls;

  buffer = GNUNET_malloc (UPNP_COMMAND_BUFSIZE);

  UPNP_command_ (control_url, service_type, "AddPortMapping",
                 args, buffer, UPNP_COMMAND_BUFSIZE,
                 add_delete_port_mapping_receiver, cls);
}

void
UPNP_delete_port_mapping_ (const char *control_url, const char *service_type,
                           const char *ext_port, const char *proto,
                           const char *remoteHost,
                           UPNP_port_mapping_cb_ caller_cb, void *caller_cls)
{
  struct UPNP_Arg_ args[4];
  struct PortMapping_cls *cls;
  char *buffer;

  if (!ext_port || !proto)
    {
      caller_cb (UPNP_COMMAND_INVALID_ARGS, control_url, service_type,
                 ext_port, NULL, proto, remoteHost, caller_cls);
      return;
    }

  args[0].elt = "NewRemoteHost";
  args[0].val = remoteHost;
  args[1].elt = "NewExternalPort";
  args[1].val = ext_port;
  args[2].elt = "NewProtocol";
  args[2].val = proto;
  args[3].elt = NULL;
  args[3].val = NULL;

  cls = GNUNET_malloc (sizeof (struct PortMapping_cls));
  cls->control_url = control_url;
  cls->service_type = service_type;
  cls->ext_port = ext_port;
  cls->in_port = "0";
  cls->proto = proto;
  cls->remoteHost = remoteHost;
  cls->caller_cb = caller_cb;
  cls->caller_cls = caller_cls;

  buffer = GNUNET_malloc (UPNP_COMMAND_BUFSIZE);

  UPNP_command_ (control_url, service_type,
                 "DeletePortMapping",
                 args, buffer, UPNP_COMMAND_BUFSIZE,
                 add_delete_port_mapping_receiver, cls);
}


struct get_specific_port_mapping_entry_cls
{
  const char *control_url;
  const char *service_type;
  const char *ext_port;
  const char *proto;
  UPNP_port_mapping_cb_ caller_cb;
  void *caller_cls;
};

static void
get_specific_port_mapping_entry_receiver (char *response, size_t received,
                                          void *data)
{
  struct PortMapping_cls *cls = data;
  struct UPNP_REPLY_NameValueList_ pdata;
  char *p;
  char in_port[128];
  char in_client[128];
  int ret;

  UPNP_REPLY_parse_ (response, received, &pdata);

  p = UPNP_REPLY_get_value_ (&pdata, "NewInternalClient");
  if (p)
    {
      strncpy (in_client, p, 128);
      in_client[127] = '\0';
    }
  else
    in_client[0] = '\0';

  p = UPNP_REPLY_get_value_ (&pdata, "NewInternalPort");
  if (p)
    {
      strncpy (in_port, p, 6);
      in_port[5] = '\0';
    }
  else
    in_port[0] = '\0';

  p = UPNP_REPLY_get_value_ (&pdata, "errorCode");
  if (p)
    {
      if (p)
        {
          ret = UPNP_COMMAND_UNKNOWN_ERROR;
          sscanf (p, "%d", &ret);
        }
#if DEBUG_UPNP
      PRINT_UPNP_ERROR ("GetSpecificPortMappingEntry", p);
#endif
    }

  cls->caller_cb (ret, cls->control_url, cls->service_type,
                  cls->ext_port, cls->proto, in_port, in_client,
                  cls->caller_cls);

  UPNP_REPLY_free_ (&pdata);
  GNUNET_free (response);
  GNUNET_free (cls);
}

/* UPNP_get_specific_port_mapping_entry _ retrieves an existing port mapping
 * the result is returned in the in_client and in_port strings
 * please provide 128 and 6 bytes of data */
void
UPNP_get_specific_port_mapping_entry_ (const char *control_url,
                                       const char *service_type,
                                       const char *ext_port,
                                       const char *proto,
                                       UPNP_get_specific_port_mapping_entry_cb_
                                       caller_cb, void *caller_cls)
{
  struct UPNP_Arg_ args[4];
  struct get_specific_port_mapping_entry_cls *cls;
  char *buffer;

  if (!ext_port || !proto)
    {
      caller_cb (UPNP_COMMAND_INVALID_ARGS, control_url, service_type,
                 ext_port, proto, NULL, NULL, caller_cls);
      return;
    }

  args[0].elt = "NewRemoteHost";
  args[0].val = NULL;
  args[1].elt = "NewExternalPort";
  args[1].val = ext_port;
  args[2].elt = "NewProtocol";
  args[2].val = proto;
  args[3].elt = NULL;
  args[3].val = NULL;

  cls = GNUNET_malloc (sizeof (struct PortMapping_cls));
  cls->control_url = control_url;
  cls->service_type = service_type;
  cls->ext_port = ext_port;
  cls->proto = proto;
  cls->caller_cb = caller_cb;
  cls->caller_cls = caller_cls;

  buffer = GNUNET_malloc (UPNP_COMMAND_BUFSIZE);

  UPNP_command_ (control_url, service_type,
                 "GetSpecificPortMappingEntry",
                 args, buffer, UPNP_COMMAND_BUFSIZE,
                 get_specific_port_mapping_entry_receiver, cls);
}

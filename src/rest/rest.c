/*
      This file is part of GNUnet
      Copyright (C) 2010-2015 GNUnet e.V.

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
 * @file rest/rest.c
 * @brief helper library to create JSON REST Objects and handle REST
 * responses/requests.
 * @author Martin Schanzenbach
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_rest_lib.h"
#include "microhttpd.h"

/**
 * REST Utilities
 */

  /**
   * Check if namespace is in URL.
   *
   * @param url URL to check
   * @param namespace namespace to check against
   * @retun GNUNET_YES if namespace matches
   */
int
GNUNET_REST_namespace_match (const char *url, const char *namespace)
{
  return 0 == strncmp (namespace, url, strlen (namespace));
}

/**
 * Create MHD response
 *
 * @param data result
 * @retun MHD response
 */
struct MHD_Response*
GNUNET_REST_create_response (const char *data)
{
  struct MHD_Response *resp;
  size_t len;

  if (NULL == data)
  {
    len = 0;
    data = "";
  }
  else
    len = strlen (data);
  resp = MHD_create_response_from_buffer (len,
                                          (void*)data,
                                          MHD_RESPMEM_MUST_COPY);
  return resp;

}

int
GNUNET_REST_handle_request (struct GNUNET_REST_RequestHandle *conn,
                            const struct GNUNET_REST_RequestHandler *handlers,
                            struct GNUNET_REST_RequestHandlerError *err,
                            void *cls)
{
  int count;
  int i;
  char *url;

  count = 0;
  while (NULL != handlers[count].method)
    count++;

  GNUNET_asprintf (&url, "%s", conn->url);
  if (url[strlen (url)-1] == '/')
    url[strlen (url)-1] = '\0';
  for (i = 0; i < count; i++)
  {
    if (0 != strcasecmp (conn->method, handlers[i].method))
      continue;
    if (strlen (url) < strlen (handlers[i].namespace))
      continue;
    if (GNUNET_NO == GNUNET_REST_namespace_match (url, handlers[i].namespace))
      continue;
    //Match
    handlers[i].proc (conn, (const char*)url, cls);
    GNUNET_free (url);
    return GNUNET_YES;
  }
  GNUNET_free (url);
  err->error_code = MHD_HTTP_BAD_REQUEST;
  return GNUNET_NO;
}

/* end of rest.c */

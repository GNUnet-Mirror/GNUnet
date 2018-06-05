/*
      This file is part of GNUnet
      Copyright (C) 2010-2015 GNUnet e.V.

      GNUnet is free software: you can redistribute it and/or modify it
      under the terms of the GNU General Public License as published
      by the Free Software Foundation, either version 3 of the License,
      or (at your option) any later version.

      GNUnet is distributed in the hope that it will be useful, but
      WITHOUT ANY WARRANTY; without even the implied warranty of
      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
      Affero General Public License for more details.
 */

/**
 * @author Martin Schanzenbach
 *
 * @file
 * API for helper library to parse/create REST
 *
 * @defgroup rest  REST library
 * Helper library to parse/create REST
 * @{
 */
#ifndef GNUNET_REST_LIB_H
#define GNUNET_REST_LIB_H

#include "gnunet_util_lib.h"
#include <microhttpd.h>

#define GNUNET_REST_HANDLER_END {NULL, NULL, NULL}

struct GNUNET_REST_RequestHandle
{
  /**
   * Map of url parameters
   */
  struct GNUNET_CONTAINER_MultiHashMap *url_param_map;

  /**
   * Map of headers
   */
  struct GNUNET_CONTAINER_MultiHashMap *header_param_map;

  /**
   * The HTTP method as MHD value (see microhttpd.h)
   */
  const char *method;

  /**
   * The url as string
   */
  const char *url;

  /**
   * The POST data
   */
  const char *data;

  /**
   * The POST data size
   */
  size_t data_size;
};

struct GNUNET_REST_RequestHandlerError
{
  int error_code;
  char* error_text;
};

struct GNUNET_REST_RequestHandler
{
  /**
   * Http method to handle
   */
  const char *method;

  /**
   * Namespace to handle
   */
  const char *namespace;

  /**
   * callback handler
   */
  void (*proc) (struct GNUNET_REST_RequestHandle *handle,
                const char *url,
                void *cls);

};


/**
 * Iterator called on obtained result for a REST result.
 *
 * @param cls closure
 * @param resp the response
 * @param status status code (HTTP)
 */
typedef void (*GNUNET_REST_ResultProcessor) (void *cls,
                                             struct MHD_Response *resp,
                                             int status);

/**
 * Check if namespace is in URL.
 *
 * @param url URL to check
 * @param namespace namespace to check against
 * @return GNUNET_YES if namespace matches
 */
int
GNUNET_REST_namespace_match (const char *url, const char *namespace);

/**
 * Create REST MHD response
 *
 * @param data result
 * @return MHD response
 */
 struct MHD_Response*
GNUNET_REST_create_response (const char *data);


int
GNUNET_REST_handle_request (struct GNUNET_REST_RequestHandle *conn,
                            const struct GNUNET_REST_RequestHandler *handlers,
                            struct GNUNET_REST_RequestHandlerError *err,
                            void *cls);


#endif

/** @} */  /* end of group */

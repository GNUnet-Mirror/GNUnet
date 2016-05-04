/*
  This file is part of GNUnet
  Copyright (C) 2014, 2015, 2016 GNUnet e.V.

  GNUnet is free software; you can redistribute it and/or modify it under the
  terms of the GNU General Public License as published by the Free Software
  Foundation; either version 3, or (at your option) any later version.

  GNUnet is distributed in the hope that it will be useful, but WITHOUT ANY
  WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
  A PARTICULAR PURPOSE.  See the GNU General Public License for more details.

  You should have received a copy of the GNU General Public License along with
  GNUnet; see the file COPYING.  If not, If not, see <http://www.gnu.org/licenses/>
*/
/**
 * @file json/jsonapi.c
 * @brief functions to generate specifciations for JSONAPI parsing
 * @author Martin Schanzenbach
 */
#include "platform.h"
#include "gnunet_json_lib.h"
#include "gnunet_rest_lib.h"

/**
 * TODO move this to jsonapi-utils
 */

/**
 * Check rest request for validity
 *
 * @param req handle to the request
 * @return GNUNET_OK if valid
 */
int
GNUNET_JSONAPI_check_request_acceptable (struct GNUNET_REST_RequestHandle *req)
{
  //TODO
  return GNUNET_OK;
}

/**
 * Check rest request for validity
 *
 * @param req handle to the request
 * @return GNUNET_OK if valid
 */
int
GNUNET_JSONAPI_check_request_supported (struct GNUNET_REST_RequestHandle *req)
{
  //TODO
  return GNUNET_OK;
}

/**
 * Handle jsonapi rest request. Checks request headers for jsonapi compliance
 *
 * @param req rest request handle
 * @param handler rest request handlers
 * @param cls closure
 * @return GNUNET_OK if successful
 */
int
GNUNET_JSONAPI_handle_request (struct GNUNET_REST_RequestHandle *handle,
                               const struct GNUNET_REST_RequestHandler *handlers,
                               struct GNUNET_REST_RequestHandlerError *err,
                               void *cls)
{
  if (GNUNET_OK != GNUNET_JSONAPI_check_request_acceptable (handle))
  {
    err->error_code = MHD_HTTP_NOT_ACCEPTABLE;
    return GNUNET_SYSERR;
  }
  if (GNUNET_OK != GNUNET_JSONAPI_check_request_supported (handle))
  {
    err->error_code = MHD_HTTP_UNSUPPORTED_MEDIA_TYPE;
    return GNUNET_SYSERR;
  }
  return GNUNET_REST_handle_request (handle, handlers, err, cls);
}

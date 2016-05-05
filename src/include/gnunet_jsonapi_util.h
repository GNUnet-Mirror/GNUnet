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
 * @file gnunet_jsonapi_util.h
 * @brief utility functions for jsonapi
 * @author Martin Schanzenbach
 */
#ifndef GNUNET_JSONAPI_UTIL_H
#define GNUNET_JSONAPI_UTIL_H

#include "gnunet_util_lib.h"
#include "gnunet_rest_lib.h"
#include "gnunet_jsonapi_lib.h"


/**
 * Check rest request for validity
 *
 * @param req handle to the request
 * @return GNUNET_OK if valid
 */
int
GNUNET_JSONAPI_check_request_acceptable (struct GNUNET_REST_RequestHandle *req);

/**
 * Check rest request for validity
 *
 * @param req handle to the request
 * @return GNUNET_OK if valid
 */
int
GNUNET_JSONAPI_check_request_supported (struct GNUNET_REST_RequestHandle *req);


/**
 * Handle jsonapi rest request. Checks request headers for jsonapi compliance
 *
 * @param req rest request handle
 * @param handler rest request handlers
 * @param cls closure
 * @return GNUNET_OK if successful
 */
int
GNUNET_JSONAPI_handle_request (struct GNUNET_REST_RequestHandle *req,
                               const struct GNUNET_REST_RequestHandler *handlers,
                               struct GNUNET_REST_RequestHandlerError *err,
                               void *cls);

#endif

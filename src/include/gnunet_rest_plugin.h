/*
   This file is part of GNUnet.
   Copyright (C) 2012-2015 Christian Grothoff (and other contributing authors)

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
 * @file include/gnunet_rest_plugin.h
 * @brief GNUnet service REST plugin header
 *
 */
#ifndef GNUNET_REST_PLUGIN_H
#define GNUNET_REST_PLUGIN_H

#include "gnunet_util_lib.h"
#include "microhttpd.h"

#ifdef __cplusplus
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif

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

struct RestConnectionDataHandle
{
  struct GNUNET_CONTAINER_MultiHashMap *url_param_map;
  const char *method;
  const char *url;
  const char *data;
  size_t data_size;

};

/**
 * @brief struct returned by the initialization function of the plugin
 */
struct GNUNET_REST_Plugin
{

  /**
   *
   * The closure of the plugin
   *
   */
  void *cls;

  /**
   * Plugin name. Used as the namespace for the API.
   * e.g. http://hostname:port/<name>
   */
  char *name;

  /**
   * Function to process a REST call
   * 
   * @param method the HTTP method called
   * @param url the relative url accessed
   * @param data the REST data (can be NULL)
   * @param data_size the length of the data
   * @param proc the callback for result
   * @param proc_cls closure for callback
   */
  void (*process_request) (struct RestConnectionDataHandle *handle,
                           GNUNET_REST_ResultProcessor proc,
                           void *proc_cls);

};


#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

/* end of gnunet_rest_plugin.h */
#endif


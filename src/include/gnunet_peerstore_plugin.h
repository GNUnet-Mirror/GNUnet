/*
     This file is part of GNUnet
     (C) 2012, 2013 Christian Grothoff (and other contributing authors)

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
 * @file include/gnunet_peerstore_plugin.h
 * @brief plugin API for the peerstore database backend
 * @author Omar Tarabai
 */
#ifndef GNUNET_PEERSTORE_PLUGIN_H
#define GNUNET_PEERSTORE_PLUGIN_H

#include "gnunet_util_lib.h"
#include "gnunet_peerstore_service.h"

#ifdef __cplusplus
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif


/**
 * @brief struct returned by the initialization function of the plugin
 */
struct GNUNET_PEERSTORE_PluginFunctions
{

  /**
   * Closure to pass to all plugin functions.
   */
  void *cls;

};


#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

/* end of gnunet_peerstore_plugin.h */
#endif

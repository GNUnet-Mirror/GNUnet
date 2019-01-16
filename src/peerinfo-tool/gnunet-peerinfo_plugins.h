/*
     This file is part of GNUnet.
     Copyright (C) 2010,2011 GNUnet e.V.

     GNUnet is free software: you can redistribute it and/or modify it
     under the terms of the GNU Affero General Public License as published
     by the Free Software Foundation, either version 3 of the License,
     or (at your option) any later version.

     GNUnet is distributed in the hope that it will be useful, but
     WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
     Affero General Public License for more details.
    
     You should have received a copy of the GNU Affero General Public License
     along with this program.  If not, see <http://www.gnu.org/licenses/>.

     SPDX-License-Identifier: AGPL3.0-or-later
*/

/**
 * @file peerinfo-tool/gnunet-peerinfo_plugins.h
 * @brief plugin management API
 * @author Christian Grothoff
 */
#ifndef GNUNET_PEERINFO_PLUGINS_H
#define GNUNET_PEERINFO_PLUGINS_H

#include "gnunet_util_lib.h"

/**
 * Load transport plugins.
 *
 * @param cfg configuration to use
 */
void
GPI_plugins_load (const struct GNUNET_CONFIGURATION_Handle *cfg);


/**
 * Unload all plugins
 */
void
GPI_plugins_unload (void);


/**
 * Obtain the plugin API based on a plugin name.
 *
 * @param name name of the plugin
 * @return the plugin's API, NULL if the plugin is not loaded
 */
struct GNUNET_TRANSPORT_PluginFunctions *
GPI_plugins_find (const char *name);


#endif
/* end of file gnunet-peerinfo_plugins.h */

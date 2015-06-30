/*
     This file is part of GNUnet.
     Copyright (C) 2006, 2007, 2008, 2009, 2013 Christian Grothoff (and other contributing authors)

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
 * @file src/util/configuration_loader.c
 * @brief configuration loading
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_util_lib.h"

#define LOG(kind,...) GNUNET_log_from (kind, "util", __VA_ARGS__)

#define LOG_STRERROR_FILE(kind,syscall,filename) GNUNET_log_from_strerror_file (kind, "util", syscall, filename)
/**
 * Load configuration (starts with defaults, then loads
 * system-specific configuration).
 *
 * @param cfg configuration to update
 * @param filename name of the configuration file, NULL to load defaults
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on error
 */
int
GNUNET_CONFIGURATION_load (struct GNUNET_CONFIGURATION_Handle *cfg,
                           const char *filename)
{
  char *baseconfig;
  char *ipath;

  ipath = GNUNET_OS_installation_get_path (GNUNET_OS_IPK_DATADIR);
  if (NULL == ipath)
    return GNUNET_SYSERR;
  baseconfig = NULL;
  GNUNET_asprintf (&baseconfig, "%s%s", ipath, "config.d");
  GNUNET_free (ipath);

  if (GNUNET_SYSERR ==
      GNUNET_CONFIGURATION_load_from (cfg,
                                      baseconfig))
  {
    GNUNET_free (baseconfig);
    return GNUNET_SYSERR;       /* no configuration at all found */
  }
  GNUNET_free (baseconfig);
  if ((NULL != filename) &&
      (GNUNET_OK != GNUNET_CONFIGURATION_parse (cfg, filename)))
  {
    /* specified configuration not found */
    return GNUNET_SYSERR;
  }
  if (((GNUNET_YES !=
        GNUNET_CONFIGURATION_have_value (cfg, "PATHS", "DEFAULTCONFIG"))) &&
      (filename != NULL))
    GNUNET_CONFIGURATION_set_value_string (cfg, "PATHS", "DEFAULTCONFIG",
                                           filename);
  return GNUNET_OK;
}

/* end of configuration_loader.c */

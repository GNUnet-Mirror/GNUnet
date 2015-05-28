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
     Free Software Foundation, Inc., 59 Temple Place - Suite 330,
     Boston, MA 02111-1307, USA.
*/

/**
 * @file src/util/configuration_loader.c
 * @brief configuration loading
 * @author Christian Grothoff
 */

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
      GNUNET_DISK_directory_scan (baseconfig, &parse_configuration_file, cfg))
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

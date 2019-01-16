/*
 This file is part of GNUnet.
 Copyright (C) 2011-2015, 2018 GNUnet e.V.

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
 * @file ats/plugin_ats2_common.c
 * @brief ATS solver helper functions to be inlined
 * @author Matthias Wachs
 * @author Christian Grothoff
 */

/**
 * Default bandwidth assigned to a network: 64 KB/s
 */
#define DEFAULT_BANDWIDTH 65536


/**
 * Parse @a cfg for @a quota as specified for @a direction of
 * network type @a nts.
 *
 * @param cfg configuration to parse
 * @param nts network type string to get quota for
 * @param direction direction to get quota for ("IN" or "OUT")
 * @param quota[out] set to quota, #DEFAULT_BANDWIDTH if @a cfg does not say anything useful
 */
static void
get_quota (const struct GNUNET_CONFIGURATION_Handle *cfg,
	   const char *nts,
	   const char *direction,
	   unsigned long long *quota)
{
  char *quota_str;
  char *quota_s;
  int res;

  GNUNET_asprintf (&quota_s,
		   "%s_QUOTA_%s",
		   nts,
		   direction);
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_string (cfg,
					     "ATS",
					     quota_s,
					     &quota_str))
  {
    GNUNET_log_config_missing (GNUNET_ERROR_TYPE_WARNING,
			       "ATS",
			       quota_s);
    GNUNET_free (quota_s);
    return;
  }
  GNUNET_free (quota_s);
  res = GNUNET_NO;
  if (0 == strcmp (quota_str,
		   "unlimited"))
  {
    *quota = ULONG_MAX;
    res = GNUNET_YES;
  }
  if ( (GNUNET_NO == res) &&
       (GNUNET_OK ==
	GNUNET_STRINGS_fancy_size_to_bytes (quota_str,
					    quota)) )
    res = GNUNET_YES;
  if ( (GNUNET_NO == res) &&
       (1 ==
	sscanf (quota_str,
		"%llu",
		quota)) )
    res = GNUNET_YES;
  if (GNUNET_NO == res)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _("Could not load %s quota for network `%s': `%s', assigning default bandwidth %llu\n"),
                direction,
                nts,
                quota_str,
                (unsigned long long) DEFAULT_BANDWIDTH);
    *quota = DEFAULT_BANDWIDTH;
  }
  GNUNET_free (quota_str);
}

/*
     This file is part of GNUnet.
     (C) 2009 Christian Grothoff (and other contributing authors)

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
 * @file experimentation/gnunet-daemon-experimentation_capabilities.c
 * @brief experimentation daemon: capabilities management
 * @author Christian Grothoff
 * @author Matthias Wachs
 */
#include "platform.h"
#include "gnunet_getopt_lib.h"
#include "gnunet_util_lib.h"
#include "gnunet_core_service.h"
#include "gnunet_statistics_service.h"
#include "gnunet-daemon-experimentation.h"


/**
 * Capability value shared between components
 */
uint32_t GSE_node_capabilities;


/**
 * Capabilities defined at the moment
 */
#define GNUNET_EXPERIMENTATION_capabilities_count 11;


/**
 * Capabilities a node has or an experiment requires string
 */
#define GNUNET_EXPERIMENTATION_capabilities_string {"NONE", "PLUGIN_TCP", "PLUGIN_UDP", "PLUGIN_UNIX", "PLUGIN_HTTP_CLIENT", "PLUGIN_HTTP_SERVER", "PLUGIN_HTTPS_CLIENT", "PLUGIN_HTTPS_SERVER", "PLUGIN_WLAN", "HAVE_IPV6", "BEHIND_NAT"}


/**
 * Print a single capability value
 *
 * @param cap capability value
 * @return the string to print
 */
const char *
GED_capability_to_str (uint32_t cap)
{
	char * capstr[] = GNUNET_EXPERIMENTATION_capabilities_string;
	unsigned index = 0;
	uint32_t test = 0;

	if (0 == cap)
		return capstr[0];

	index = (log(cap) / log (2)) + 1;

	test = 1 << (index - 1);
	if (test != cap)
		return "UNDEFINED";

	if (index <= 11)
		return capstr[index];
	else
	 return "UNDEFINED";


}


/**
 * Are the capabilities provided?
 *
 * @param have bitstring containing the provided capabilities
 * @param desired bitstring containing the desired capabilities\
 * @return GNUNET_YES or GNUNET_NO
 */
int
GED_capabilities_have (uint32_t have, uint32_t desired)
{
	if (desired == (desired & have))
		return GNUNET_YES;
	else
		return GNUNET_NO;
}


/**
 * Start the detecting capabilities
 */
void
GED_capabilities_start ()
{
	char *plugins;
  char *pos;
  unsigned int c1;
  uint32_t index;
  GSE_node_capabilities = NONE;

	/* Plugins configured */

  if (GNUNET_OK == GNUNET_CONFIGURATION_get_value_string (GED_cfg,
  			"TRANSPORT", "PLUGINS", &plugins))
  {
  	  for (pos = strtok (plugins, " "); pos != NULL; pos = strtok (NULL, " "))
  	  {
  	      if (0 == strcmp (pos, "tcp"))
  	      	GSE_node_capabilities |= PLUGIN_TCP;
  	      else if (0 == strcmp (pos, "udp"))
  	      	GSE_node_capabilities |= PLUGIN_UDP;
					else if (0 == strcmp (pos, "unix"))
						GSE_node_capabilities |= PLUGIN_UNIX;
					else if (0 == strcmp (pos, "http_client"))
						GSE_node_capabilities |= PLUGIN_HTTP_CLIENT;
					else if (0 == strcmp (pos, "http_server"))
						GSE_node_capabilities |= PLUGIN_HTTP_SERVER;
					else if (0 == strcmp (pos, "https_client"))
						GSE_node_capabilities |= PLUGIN_HTTP_CLIENT;
					else if (0 == strcmp (pos, "https_server"))
						GSE_node_capabilities |= PLUGIN_HTTPS_SERVER;
					else if (0 == strcmp (pos, "wlan"))
						GSE_node_capabilities |= PLUGIN_WLAN;
  	  }
  	  GNUNET_free (plugins);
  }

	/* IPv6 enabled
	 * FIXE: just having it not enabled is not really sufficient */
  if (GNUNET_NO == GNUNET_CONFIGURATION_get_value_yesno (GED_cfg,
  			"NAT", "DISABLEV6"))
  	GSE_node_capabilities |= HAVE_IPV6;

  /* Behind NAT */
  if (GNUNET_YES == GNUNET_CONFIGURATION_get_value_yesno (GED_cfg,
  			"NAT", "BEHIND_NAT"))
  	GSE_node_capabilities |= BEHIND_NAT;

  for (c1 = 0 ; c1 < 32; c1++)
  {
  		index = 1;
  		index = index << c1;
  		if (GNUNET_YES == GED_capabilities_have (GSE_node_capabilities, index))
  		{
  			GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "We have `%s'\n",
  					GED_capability_to_str(index));
  		}
  }
}


/**
 * Stop the detecting capabilities
 */
void
GED_capabilities_stop ()
{

}

/* end of gnunet-daemon-experimentation_capabilities.c */

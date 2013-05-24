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

uint32_t GSE_node_capabilities;

/**
 * Capabilities a node has or an experiment requires
 */
enum ExperimentationCapabilities
{
	NONE = 0,
	PLUGIN_TCP = 1,
	PLUGIN_UDP = 2,
	PLUGIN_UNIX = 4,
	PLUGIN_HTTP_CLIENT = 8,
	PLUGIN_HTTP_SERVER = 16,
	PLUGIN_HTTPS_CLIENT = 32,
	PLUGIN_HTTPS_SERVER = 64,
	PLUGIN_WLAN = 128,
	HAVE_IPV6 = 256,
	BEHIND_NAT = 512
};

#define ExperimentationCapabilities_Count 11;

/**
 * Capabilities a node has or an experiment requires string
 */
#define ExperimentationCapabilities_String {"NONE", "PLUGIN_TCP", "PLUGIN_UDP", "PLUGIN_UNIX", "PLUGIN_HTTP_CLIENT", "PLUGIN_HTTP_SERVER", "PLUGIN_HTTPS_CLIENT", "PLUGIN_HTTPS_SERVER", "PLUGIN_WLAN", "HAVE_IPV6", "BEHIND_NAT"}

const char *
GNUNET_EXPERIMENTATION_capability_to_str (uint32_t cap)
{
	char * capstr[] = ExperimentationCapabilities_String;
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


uint32_t
GNUNET_EXPERIMENTATION_capabilities_have (uint32_t cap)
{
	if (cap == (cap & GSE_node_capabilities))
		return GNUNET_YES;
	else
		return GNUNET_NO;
}


/**
 * Start the detecting capabilities
 *
 * @param cfg configuration handle
 */
void
GNUNET_EXPERIMENTATION_capabilities_start ()
{
	char *plugins;
  char *pos;
  unsigned int c1;
  uint32_t index;
  GSE_node_capabilities = NONE;

	/* Plugins configured */

  if (GNUNET_OK == GNUNET_CONFIGURATION_get_value_string (GSE_cfg,
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
  if (GNUNET_NO == GNUNET_CONFIGURATION_get_value_yesno (GSE_cfg,
  			"NAT", "DISABLEV6"))
  	GSE_node_capabilities |= HAVE_IPV6;

  /* Behind NAT */
  if (GNUNET_YES == GNUNET_CONFIGURATION_get_value_yesno (GSE_cfg,
  			"NAT", "BEHIND_NAT"))
  	GSE_node_capabilities |= BEHIND_NAT;

  for (c1 = 0 ; c1 < 32; c1++)
  {
  		index = 1;
  		index = index << c1;
  		if (GNUNET_YES == GNUNET_EXPERIMENTATION_capabilities_have (index))
  		{
  			GNUNET_log (GNUNET_ERROR_TYPE_INFO, "We have `%s'\n",
  					GNUNET_EXPERIMENTATION_capability_to_str(index));
  		}
  }
}

/**
 * Stop the detecting capabilities
 */
void
GNUNET_EXPERIMENTATION_capabilities_stop ()
{

}

/* end of gnunet-daemon-experimentation_capabilities.c */

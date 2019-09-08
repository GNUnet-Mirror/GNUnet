/*
      This file is part of GNUnet
      Copyright (C) 2008--2013 GNUnet e.V.

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
 * @file testbed/test_testbed_api_hosts.c
 * @brief tests cases for testbed_api_hosts.c
 * @author Sree Harsha Totakura
 */

#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_testbed_service.h"
#include "testbed_api_hosts.h"


#define TIME_REL_SECS(sec)                                              \
  GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_SECONDS, sec)

/**
 * configuration handle to use as template configuration while creating hosts
 */
static struct GNUNET_CONFIGURATION_Handle *cfg;

/**
 * Host we are creating and using
 */
static struct GNUNET_TESTBED_Host *host;

/**
 * An array of hosts which are loaded from a file
 */
static struct GNUNET_TESTBED_Host **hosts;

/**
 * Number of hosts in the above list
 */
static unsigned int num_hosts;

/**
 * Global test status
 */
static int status;


/**
 * The shutdown task
 *
 * @param cls NULL
 */
static void
do_shutdown(void *cls)
{
  GNUNET_TESTBED_host_destroy(host);
  while (0 != num_hosts)
    {
      GNUNET_TESTBED_host_destroy(hosts[num_hosts - 1]);
      num_hosts--;
    }
  GNUNET_free(hosts);
  if (NULL != cfg)
    {
      GNUNET_CONFIGURATION_destroy(cfg);
      cfg = NULL;
    }
}


/**
 * Main run function.
 *
 * @param cls NULL
 * @param args arguments passed to GNUNET_PROGRAM_run
 * @param cfgfile the path to configuration file
 * @param cfg the configuration file handle
 */
static void
run(void *cls, char *const *args, const char *cfgfile,
    const struct GNUNET_CONFIGURATION_Handle *config)
{
  unsigned int cnt;

  cfg = GNUNET_CONFIGURATION_dup(config);
  host = GNUNET_TESTBED_host_create("localhost", NULL, cfg, 0);
  GNUNET_assert(NULL != host);
  GNUNET_assert(0 != GNUNET_TESTBED_host_get_id_(host));
  GNUNET_TESTBED_host_destroy(host);
  host = GNUNET_TESTBED_host_create(NULL, NULL, cfg, 0);
  GNUNET_assert(NULL != host);
  GNUNET_assert(0 == GNUNET_TESTBED_host_get_id_(host));
  GNUNET_assert(host == GNUNET_TESTBED_host_lookup_by_id_(0));
  hosts = NULL;
  num_hosts = GNUNET_TESTBED_hosts_load_from_file("sample_hosts.txt", cfg, &hosts);
  GNUNET_assert(7 == num_hosts);
  GNUNET_assert(NULL != hosts);
  for (cnt = 0; cnt < num_hosts; cnt++)
    {
      if (cnt < 3)
        {
          GNUNET_assert(0 == strcmp("totakura",
                                    GNUNET_TESTBED_host_get_username_
                                      (hosts[cnt])));
          GNUNET_assert(NULL != GNUNET_TESTBED_host_get_hostname(hosts[cnt]));
          GNUNET_assert(22 == GNUNET_TESTBED_host_get_ssh_port_(hosts[cnt]));
        }
      if (3 == cnt)
        {
          GNUNET_assert(0 == strcmp("totakura",
                                    GNUNET_TESTBED_host_get_username_
                                      (hosts[cnt])));
          GNUNET_assert(NULL != GNUNET_TESTBED_host_get_hostname(hosts[cnt]));
          GNUNET_assert(2022 == GNUNET_TESTBED_host_get_ssh_port_(hosts[cnt]));
        }
      if (4 == cnt)
        {
          GNUNET_assert(0 == strcmp("totakura",
                                    GNUNET_TESTBED_host_get_username_
                                      (hosts[cnt])));
          GNUNET_assert(0 == strcmp("asgard.realm",
                                    GNUNET_TESTBED_host_get_hostname
                                      (hosts[cnt])));
          GNUNET_assert(22 == GNUNET_TESTBED_host_get_ssh_port_(hosts[cnt]));
        }
      if (5 == cnt)
        {
          GNUNET_assert(NULL == GNUNET_TESTBED_host_get_username_(hosts[cnt]));
          GNUNET_assert(0 == strcmp("rivendal",
                                    GNUNET_TESTBED_host_get_hostname
                                      (hosts[cnt])));
          GNUNET_assert(22 == GNUNET_TESTBED_host_get_ssh_port_(hosts[cnt]));
        }
      if (6 == cnt)
        {
          GNUNET_assert(NULL == GNUNET_TESTBED_host_get_username_(hosts[cnt]));
          GNUNET_assert(0 == strcmp("rohan",
                                    GNUNET_TESTBED_host_get_hostname
                                      (hosts[cnt])));
          GNUNET_assert(561 == GNUNET_TESTBED_host_get_ssh_port_(hosts[cnt]));
        }
    }
  status = GNUNET_YES;
  GNUNET_SCHEDULER_add_now(&do_shutdown, NULL);
}


int
main(int argc, char **argv)
{
  char *const argv2[] = { "test_testbed_api_hosts",
                          "-c", "test_testbed_api.conf",
                          NULL };
  struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_OPTION_END
  };

  status = GNUNET_SYSERR;
  if (GNUNET_OK !=
      GNUNET_PROGRAM_run((sizeof(argv2) / sizeof(char *)) - 1, argv2,
                         "test_testbed_api_hosts", "nohelp", options, &run,
                         NULL))
    return 1;
  return (GNUNET_OK == status) ? 0 : 1;
}

/* end of test_testbed_api_hosts.c */

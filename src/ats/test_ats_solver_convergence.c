/*
 This file is part of GNUnet.
 Copyright (C) 2010-2013 Christian Grothoff (and other contributing authors)

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
 * @file ats/test_ats_solver_add_address.c
 * @brief solver test:  add address, request address and wait for suggests, write data to file
 * @author Christian Grothoff
 * @author Matthias Wachs
 * @author Fabian Oehlmann
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_testbed_service.h"
#include "gnunet_ats_service.h"
#include "test_ats_api_common.h"

/**
 * Timeout task
 */
static struct GNUNET_SCHEDULER_Task * end_task;

/**
 * Statistics handle
 */
struct GNUNET_STATISTICS_Handle *stats;

/**
 * Scheduling handle
 */
static struct GNUNET_ATS_SchedulingHandle *sched_ats;

/**
 * Connectivity handle
 */
static struct GNUNET_ATS_ConnectivityHandle *connect_ats;

/**
 * Return value
 */
static int ret;

/**
 * Test address
 */
static struct Test_Address test_addr;

/**
 * Test peer
 */
static struct PeerContext p;

/**
 * HELLO address
 */
struct GNUNET_HELLO_Address test_hello_address;

/**
 * Session
 */
static void *test_session;

/**
 * Test ats info
 */
struct GNUNET_ATS_Information test_ats_info[2];

/**
 * Test ats count
 */
uint32_t test_ats_count;

/**
 * Seconds to run the test
 */
static unsigned int seconds;

/**
 * When the test starts
 */
static struct GNUNET_TIME_Absolute time_start;

/**
 * Whether to write a data file
 */
static int write_data_file;

/**
 * File name
 */
static char *data_file_name;

/**
 * Run name
 */
static char *run_name;

static int
stat_cb(void *cls, const char *subsystem, const char *name, uint64_t value,
        int is_persistent);

static void
end (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Done!\n");
  if (end_task == NULL)
  {
    GNUNET_SCHEDULER_cancel (end_task);
    end_task = NULL;
  }

  if (NULL != sched_ats)
  {
    GNUNET_ATS_scheduling_done (sched_ats);
    sched_ats = NULL;
  }

  if (NULL != connect_ats)
  {
    GNUNET_ATS_connectivity_done (connect_ats);
    connect_ats = NULL;
  }
  GNUNET_STATISTICS_watch_cancel (stats, "ats", "# addresses", &stat_cb, NULL);
  if (NULL != stats)
  {
    GNUNET_STATISTICS_destroy (stats, GNUNET_NO);
    stats = NULL;
  }

  /* Close data file */
  if (write_data_file)
  {
    GNUNET_free_non_null(data_file_name);
  }

  free_test_address (&test_addr);

  ret = 0;
}


static void
end_badly (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  end (NULL, NULL);
  ret = GNUNET_SYSERR;
}

static void
address_suggest_cb (void *cls,
                    const struct GNUNET_PeerIdentity *peer,
                    const struct GNUNET_HELLO_Address *address,
                    struct Session *session,
                    struct GNUNET_BANDWIDTH_Value32NBO bandwidth_out,
                    struct GNUNET_BANDWIDTH_Value32NBO bandwidth_in,
                    const struct GNUNET_ATS_Information *atsi,
                    uint32_t ats_count)
{
  struct GNUNET_TIME_Relative time_delta;
  char *data;
  struct GNUNET_DISK_FileHandle *data_file_handle;

  GNUNET_assert (NULL != address);
  GNUNET_assert (NULL == session);
  GNUNET_assert (ntohl(bandwidth_in.value__) > 0);
  GNUNET_assert (ntohl(bandwidth_out.value__) > 0);

  time_delta = GNUNET_TIME_absolute_get_difference(time_start, GNUNET_TIME_absolute_get());

  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "Received suggestion for peer '%s': IN %u kb/s - OUT %u kb/s\n",
              GNUNET_i2s (&address->peer),
              (unsigned int) ntohl (bandwidth_in.value__)/1024,
              (unsigned int) ntohl (bandwidth_out.value__)/1024);

  if (write_data_file)
  {
    GNUNET_asprintf(&data,"%f\tIN %u\tOUT %u\n",
        (double) time_delta.rel_value_us / 1000000.,
              ntohl(bandwidth_in.value__)/1024,
              ntohl(bandwidth_out.value__)/1024);
    data_file_handle = GNUNET_DISK_file_open (data_file_name,
        GNUNET_DISK_OPEN_WRITE | GNUNET_DISK_OPEN_APPEND,
        GNUNET_DISK_PERM_USER_EXEC | GNUNET_DISK_PERM_USER_READ | GNUNET_DISK_PERM_USER_WRITE);
    if (NULL == data_file_handle)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  "Cannot write data to file `%s'\n",
                  data_file_name);
    }
    else
    {
      if (GNUNET_SYSERR == GNUNET_DISK_file_write(data_file_handle, data, strlen(data)))
        GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                    "Cannot write data to file `%s'\n",
                    data_file_name);
      if (GNUNET_SYSERR == GNUNET_DISK_file_close (data_file_handle))
        GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                    "Cannot close log file '%s'\n",
                    data_file_name);
    }

    GNUNET_free(data);
  }
}


static int
stat_cb(void *cls, const char *subsystem,
        const char *name, uint64_t value,
        int is_persistent)
{
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "ATS statistics: `%s' `%s' %llu\n",
              subsystem,name,
              (unsigned long long) value);
  GNUNET_ATS_connectivity_suggest (connect_ats, &p.id);
  return GNUNET_OK;
}


static void
run (void *cls, const struct GNUNET_CONFIGURATION_Handle *mycfg,
    struct GNUNET_TESTING_Peer *peer)
{
  struct GNUNET_DISK_FileHandle *data_file_handle;

  stats = GNUNET_STATISTICS_create ("ats", mycfg);
  GNUNET_STATISTICS_watch (stats, "ats", "# addresses", &stat_cb, NULL);

  connect_ats = GNUNET_ATS_connectivity_init (mycfg);
  /* Connect to ATS scheduling */
  sched_ats = GNUNET_ATS_scheduling_init (mycfg, &address_suggest_cb, NULL);
  if (sched_ats == NULL)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Could not connect to ATS scheduling!\n");
    GNUNET_SCHEDULER_add_now (&end_badly, NULL);
    return;
  }

  /* Create or truncate file */
  if (write_data_file)
  {
    GNUNET_asprintf (&data_file_name, "test_convergence_%s_s%d.data", run_name, seconds);
    data_file_handle = GNUNET_DISK_file_open (data_file_name,
        GNUNET_DISK_OPEN_WRITE | GNUNET_DISK_OPEN_CREATE | GNUNET_DISK_OPEN_TRUNCATE,
        GNUNET_DISK_PERM_USER_EXEC | GNUNET_DISK_PERM_USER_READ | GNUNET_DISK_PERM_USER_WRITE);
    if (NULL == data_file_handle)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Could not open data file\n");
      GNUNET_SCHEDULER_add_now (&end_badly, NULL);
      return;
    }
    if (GNUNET_SYSERR == GNUNET_DISK_file_close (data_file_handle))
    {
      GNUNET_log(GNUNET_ERROR_TYPE_ERROR, "Cannot close log file '%s'\n",
              data_file_name);
      GNUNET_SCHEDULER_add_now (&end_badly, NULL);
      return;
    }
  }

  /* Set up peer */
  memset (&p.id, '1', sizeof (p.id));
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Created peer `%s'\n",
              GNUNET_i2s_full(&p.id));

  /* Prepare ATS Information */
  test_ats_info[0].type = htonl (GNUNET_ATS_NETWORK_TYPE);
  test_ats_info[0].value = htonl(GNUNET_ATS_NET_WAN);
  test_ats_info[1].type = htonl (GNUNET_ATS_QUALITY_NET_DISTANCE);
  test_ats_info[1].value = htonl(1);
  test_ats_count = 2;

  /* Adding address without session */
  test_session = NULL;
  create_test_address (&test_addr, "test", test_session, "test", strlen ("test") + 1);
  test_hello_address.peer = p.id;
  test_hello_address.transport_name = test_addr.plugin;
  test_hello_address.address = test_addr.addr;
  test_hello_address.address_length = test_addr.addr_len;

  /* Adding address */
  GNUNET_ATS_address_add (sched_ats, &test_hello_address, NULL, test_ats_info, test_ats_count);
  time_start = GNUNET_TIME_absolute_get();

  end_task = GNUNET_SCHEDULER_add_delayed(GNUNET_TIME_relative_multiply(GNUNET_TIME_relative_get_second_(), seconds), &end, NULL);
}


void
test_run (void *cls, char *const *args,
    const char *cfgfile,
    const struct GNUNET_CONFIGURATION_Handle *
    cfg)
{
  char *sep;
  char *src_filename = GNUNET_strdup (__FILE__);
  char *test_filename = cls;
  char *config_file = "none";
  char *solver;

  ret = 0;

  if (NULL == (sep  = (strstr (src_filename,".c"))))
  {
    GNUNET_break (0);
    ret = -1;
    //return -1;
  }
  sep[0] = '\0';

  if (NULL != (sep = strstr (test_filename, ".exe")))
    sep[0] = '\0';

  if (NULL == (solver = strstr (test_filename, src_filename)))
  {
    GNUNET_break (0);
    ret = -1;
  }
  solver += strlen (src_filename) +1;

  if (0 == strcmp(solver, "proportional"))
  {
    config_file = "test_ats_solver_proportional.conf";
  }
  else if (0 == strcmp(solver, "mlp"))
  {
    config_file = "test_ats_solver_mlp.conf";
  }
  else if ((0 == strcmp(solver, "ril")))
  {
    config_file = "test_ats_solver_ril.conf";
  }
  else
  {
    GNUNET_break (0);
    GNUNET_free (src_filename);
    ret = 1;
  }

  GNUNET_free (src_filename);

  if (0 != GNUNET_TESTING_peer_run ("test-ats-solver",
      config_file, &run, NULL ))
    ret = GNUNET_SYSERR;
}

int
main (int argc, char *argv[])
{
  seconds = 5;
  run_name = NULL;

  static struct GNUNET_GETOPT_CommandLineOption options[] = {
      { 's', "seconds", NULL,
          gettext_noop ("seconds to run the test"),
          1, &GNUNET_GETOPT_set_uint, &seconds },
      { 'd', "data-file", NULL,
          gettext_noop ("generate data file"),
          0, &GNUNET_GETOPT_set_one, &write_data_file},
      { 'r', "run-name", "NAME",
          gettext_noop ("will be part of the data file name"),
          1, &GNUNET_GETOPT_set_string, &run_name},
      GNUNET_GETOPT_OPTION_END
  };

  GNUNET_PROGRAM_run2 (argc, argv, argv[0], NULL, options, &test_run, argv[0], GNUNET_YES);

  return ret;
}

/* end of file test_ats_solver_convergence.c */

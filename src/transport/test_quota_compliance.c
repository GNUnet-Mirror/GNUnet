/*
     This file is part of GNUnet.
     Copyright (C) 2009, 2010, 2011, 2016 GNUnet e.V.

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
 * @file transport/test_quota_compliance.c
 * @brief base test case for transport implementations
 *
 * This test case tests quota compliance both on transport level
 */
#include "platform.h"
#include "gnunet_transport_service.h"
#include "gnunet_ats_service.h"
#include "gauger.h"
#include "transport-testing.h"

/**
 * Testcase timeout
 */
#define TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 480)

#define DURATION GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 80)


static struct GNUNET_SCHEDULER_Task *measure_task;

static char *gen_cfgs[2];

static unsigned long long quota_in[] = { 10000, 10000 };

static unsigned long long quota_out[] = { 10000, 10000 };

static struct GNUNET_TRANSPORT_TESTING_ConnectCheckContext *ccc;


/**
 * Note that this value must not significantly exceed
 * 'MAX_PENDING' in 'gnunet-service-transport.c', otherwise
 * messages may be dropped even for a reliable transport.
 */
#define TOTAL_MSGS (1024 * 32)

static unsigned long long total_bytes_recv;

static struct GNUNET_TIME_Absolute start_time;


static void
report ()
{
  unsigned long long delta;
  unsigned long long datarate;

  delta = GNUNET_TIME_absolute_get_duration (start_time).rel_value_us;
  datarate = (total_bytes_recv * 1000 * 1000) / delta;
  
  FPRINTF (stderr,
           "Throughput was %llu b/s\n",
           datarate);
  ccc->global_ret = GNUNET_OK;
  if (datarate > 1.1 * quota_in[1])
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Datarate of %llu b/s significantly higher than allowed inbound quota of %llu b/s\n",
                datarate,
                quota_in[1]);
    ccc->global_ret = GNUNET_SYSERR;
  }
  if (datarate > 1.1 * quota_out[0])
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Datarate of %llu b/s significantly higher than allowed outbound quota of %llu b/s\n",
                datarate,
                quota_out[0]);
    ccc->global_ret = GNUNET_SYSERR;
  }
  if (GNUNET_OK == ccc->global_ret)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Datarate of %llu b/s complied to allowed outbound quota of %llu b/s and inbound quota of %llu b/s\n",
                datarate,
                quota_out[0],
                quota_in[1]);
  }
}


static void
custom_shutdown (void *cls)
{
  if (NULL != measure_task)
  {
    GNUNET_SCHEDULER_cancel (measure_task);
    measure_task = NULL;
  }
  report ();
}


static size_t
get_size (unsigned int iter)
{
  size_t ret;

  ret = (iter * iter * iter) % 60000;
  ret += sizeof (struct GNUNET_TRANSPORT_TESTING_TestMessage);
  return ret;
}


static void
notify_receive (void *cls,
                struct GNUNET_TRANSPORT_TESTING_PeerContext *receiver,
                const struct GNUNET_PeerIdentity *sender,
                const struct GNUNET_MessageHeader *message)
{
  const struct GNUNET_TRANSPORT_TESTING_TestMessage *hdr;

  hdr = (const struct GNUNET_TRANSPORT_TESTING_TestMessage *) message;
  if (GNUNET_TRANSPORT_TESTING_SIMPLE_MTYPE != ntohs (message->type))
    return;
  total_bytes_recv += ntohs (message->size);

  {
    char *ps = GNUNET_strdup (GNUNET_i2s (&receiver->id));

    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                "Peer %u (`%s') got message %u of size %u from peer (`%s')\n",
                receiver->no,
                ps,
                ntohl (hdr->num),
                ntohs (message->size),
                GNUNET_i2s (sender));
    GNUNET_free (ps);
  }
}


static void
measure (void *cls)
{
  static int counter;

  measure_task = NULL;
  counter++;
  if ((DURATION.rel_value_us / 1000 / 1000LL) < counter)
  {
    FPRINTF (stderr, "%s",  ".\n");
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  FPRINTF (stderr, "%s",  ".");
  measure_task = GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_SECONDS,
                                               &measure,
                                               NULL);
}


static void
start_task (void *cls)
{
  static struct GNUNET_TRANSPORT_TESTING_SendClosure sc = {
    .num_messages = TOTAL_MSGS,
    .get_size_cb = &get_size
  };

  sc.ccc = ccc;
  measure_task = GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_SECONDS,
                                               &measure,
                                               NULL);
  start_time = GNUNET_TIME_absolute_get ();
  GNUNET_SCHEDULER_add_now (&GNUNET_TRANSPORT_TESTING_simple_send,
                            &sc);
}


static char *
generate_config (const char *cfg_file,
                 unsigned long long quota_in,
                 unsigned long long quota_out)
{
  char *in_name;
  char *out_name;
  char *fname = NULL;
  struct GNUNET_CONFIGURATION_Handle *cfg = GNUNET_CONFIGURATION_create ();

  GNUNET_assert (GNUNET_OK ==
                 GNUNET_CONFIGURATION_load (cfg,
                                            cfg_file));
  GNUNET_asprintf (&fname,
                   "q_in_%llu_q_out_%llu_%s",
                   quota_in,
                   quota_out,
                   cfg_file);
  GNUNET_CONFIGURATION_set_value_string (cfg,
                                         "PATHS",
                                         "DEFAULTCONFIG",
                                         fname);
  for (int c = 0; c < GNUNET_ATS_NetworkTypeCount; c++)
  {
    GNUNET_asprintf (&in_name,
                     "%s_QUOTA_IN",
                     GNUNET_ATS_print_network_type (c));
    GNUNET_asprintf (&out_name,
                     "%s_QUOTA_OUT",
                     GNUNET_ATS_print_network_type (c));
    GNUNET_CONFIGURATION_set_value_number (cfg,
                                           "ats",
                                           in_name,
                                           quota_in);
    GNUNET_CONFIGURATION_set_value_number (cfg,
                                           "ats",
                                           out_name,
                                           quota_out);
    GNUNET_free (in_name);
    GNUNET_free (out_name);
  }
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_CONFIGURATION_write (cfg,
                                             fname));
  GNUNET_CONFIGURATION_destroy (cfg);
  return fname;
}


static int
check (void *cls,
       struct GNUNET_TRANSPORT_TESTING_Handle *tth_,
       const char *test_plugin_,
       const char *test_name_,
       unsigned int num_peers,
       char *cfg_files[])
{
  struct GNUNET_TRANSPORT_TESTING_ConnectCheckContext my_ccc = {
    .connect_continuation = &start_task,
    .config_file = "test_quota_compliance_data.conf",
    .rec = &notify_receive,
    .nc = &GNUNET_TRANSPORT_TESTING_log_connect,
    .nd = &GNUNET_TRANSPORT_TESTING_log_disconnect,
    .shutdown_task = &custom_shutdown,
    .timeout = TIMEOUT
  };
  ccc = &my_ccc;

  if (NULL != strstr (test_name_,
                      "asymmetric"))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Running asymmetric test with sending peer unlimited, receiving peer (in/out): %llu/%llu b/s \n",
                quota_in[1],
                quota_out[1]);
    quota_out[0] = 1024 * 1024 * 1024;
    quota_in[0] = 1024 * 1024 * 1024;
  }
  else
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Running symmetric test with (in/out) %llu/%llu b/s \n",
                quota_in[1],
                quota_out[1]);
  }
  for (unsigned int i=0;i<2;i++)
  {
    gen_cfgs[i] = generate_config (cfg_files[i],
                                   quota_in[i],
                                   quota_out[i]);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Generated config file `%s'\n",
                gen_cfgs[i]);
  }

  return GNUNET_TRANSPORT_TESTING_connect_check (&my_ccc,
                                                 tth_,
                                                 test_plugin_,
                                                 test_name_,
                                                 num_peers,
                                                 gen_cfgs);
}


int
main (int argc,
      char *argv[])
{
  if (GNUNET_OK !=
      GNUNET_TRANSPORT_TESTING_main (2,
                                     &check,
                                     NULL))
  {
    GNUNET_break (0);
    return 1;
  }
  for (unsigned int i=0;i<2;i++)
  {
    if ( (NULL != gen_cfgs[0]) &&
         (GNUNET_YES == GNUNET_DISK_file_test (gen_cfgs[0])) )
    {
      GNUNET_DISK_directory_remove (gen_cfgs[0]);
      GNUNET_free (gen_cfgs[0]);
    }
  }
  return 0;
}


/* end of test_quota_compliance.c */

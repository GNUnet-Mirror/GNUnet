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
#define TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 120)

/**
 * How long until we give up on transmitting the message?
 */
#define TIMEOUT_TRANSMIT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 20)

#define DURATION GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 10)


static struct GNUNET_SCHEDULER_Task *measure_task;

struct GNUNET_TRANSPORT_TransmitHandle *th;

static char *gen_cfgs[2];

static unsigned long long quota_in[] = { 10000, 10000 };

static unsigned long long quota_out[] = { 10000, 10000 };

static struct GNUNET_TRANSPORT_TESTING_ConnectCheckContext *ccc;


/**
 * Note that this value must not significantly exceed
 * 'MAX_PENDING' in 'gnunet-service-transport.c', otherwise
 * messages may be dropped even for a reliable transport.
 */
#define TOTAL_MSGS (1024 * 2)

#define MTYPE 12345

GNUNET_NETWORK_STRUCT_BEGIN
struct TestMessage
{
  struct GNUNET_MessageHeader header;

  uint32_t num GNUNET_PACKED;
};
GNUNET_NETWORK_STRUCT_END

static int msg_scheduled;

static int msg_sent;

static unsigned long long total_bytes_sent;

static struct GNUNET_TIME_Absolute start_time;


static void
report ()
{
  unsigned long long delta;
  unsigned long long datarate;

  delta = GNUNET_TIME_absolute_get_duration (start_time).rel_value_us;
  datarate = (total_bytes_sent * 1000 * 1000) / delta;

  FPRINTF (stderr,
           "Throughput was %llu b/s\n",
           datarate);

  if (datarate > quota_in[1])
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Datarate of %llu b/s higher than allowed inbound quota of %llu b/s\n",
                datarate,
                quota_in[1]);
    ccc->global_ret = GNUNET_SYSERR;
  }
  if (datarate > quota_out[0])
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Datarate of %llu b/s higher than allowed outbound quota of %llu b/s\n",
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
  if (NULL != th)
  {
    GNUNET_TRANSPORT_notify_transmit_ready_cancel (th);
    th = NULL;
  }
  report ();
}


static unsigned int
get_size (unsigned int iter)
{
  unsigned int ret;

  ret = (iter * iter * iter);
  return sizeof (struct TestMessage) + (ret % 60000);
}


static void
notify_receive (void *cls,
                struct GNUNET_TRANSPORT_TESTING_PeerContext *receiver,
                const struct GNUNET_PeerIdentity *sender,
                const struct GNUNET_MessageHeader *message)
{
  const struct TestMessage *hdr;

  hdr = (const struct TestMessage *) message;
  if (MTYPE != ntohs (message->type))
    return;

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


static size_t
notify_ready (void *cls,
              size_t size,
              void *buf)
{
  static int n;
  char *cbuf = buf;
  struct TestMessage hdr;
  unsigned int s;
  unsigned int ret;

  th = NULL;
  if (NULL == buf)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Timeout occurred while waiting for transmit_ready for message %u of %u\n",
                msg_scheduled, TOTAL_MSGS);
    GNUNET_SCHEDULER_shutdown ();
    ccc->global_ret = GNUNET_SYSERR;
    return 0;
  }

  ret = 0;
  s = get_size (n);
  GNUNET_assert (size >= s);
  GNUNET_assert (buf != NULL);
  cbuf = buf;
  do
  {
    hdr.header.size = htons (s);
    hdr.header.type = htons (MTYPE);
    hdr.num = htonl (n);
    msg_sent = n;
    GNUNET_memcpy (&cbuf[ret], &hdr, sizeof (struct TestMessage));
    ret += sizeof (struct TestMessage);
    memset (&cbuf[ret], n, s - sizeof (struct TestMessage));
    ret += s - sizeof (struct TestMessage);
#if VERBOSE
    if (n % 5000 == 0)
    {
#endif
      char *receiver_s = GNUNET_strdup (GNUNET_i2s (&ccc->p[0]->id));

      GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                  "Sending message %u of size %u from peer %u (`%4s') -> peer %u (`%s') !\n",
                  n, s,
                  ccc->p[1]->no,
                  GNUNET_i2s (&ccc->p[1]->id),
                  ccc->p[0]->no,
                  receiver_s);
      GNUNET_free (receiver_s);
#if 0
    }
#endif
    n++;
    s = get_size (n);
    if (0 == GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK, 16))
      break;                    /* sometimes pack buffer full, sometimes not */
  }
  while (size - ret >= s);
  if (n < TOTAL_MSGS)
  {
    if (th == NULL)
      th = GNUNET_TRANSPORT_notify_transmit_ready (ccc->p[1]->th,
                                                   &ccc->p[0]->id,
                                                   s,
                                                   TIMEOUT_TRANSMIT,
                                                   &notify_ready,
                                                   NULL);
    msg_scheduled = n;
  }
  if (n % 5000 == 0)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Returning total message block of size %u\n",
                ret);
  }
  total_bytes_sent += ret;
  if (n == TOTAL_MSGS)
  {
    FPRINTF (stderr, "%s",  "\n");
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "All messages sent\n");
  }
  return ret;
}


static void
notify_disconnect (void *cls,
                   struct GNUNET_TRANSPORT_TESTING_PeerContext *me,
                   const struct GNUNET_PeerIdentity *other)
{
  GNUNET_TRANSPORT_TESTING_log_disconnect (cls,
                                           me,
                                           other);
  if (th != NULL)
  {
    GNUNET_TRANSPORT_notify_transmit_ready_cancel (th);
    th = NULL;
  }
}


static void
sendtask ()
{
  start_time = GNUNET_TIME_absolute_get ();
  th = GNUNET_TRANSPORT_notify_transmit_ready (ccc->p[1]->th,
                                               &ccc->p[0]->id,
                                               get_size (0),
                                               TIMEOUT_TRANSMIT,
                                               &notify_ready,
                                               NULL);
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
  measure_task = GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_SECONDS,
                                               &measure,
                                               NULL);
  GNUNET_SCHEDULER_add_now (&sendtask,
                            NULL);
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
    .nd = &notify_disconnect,
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
main (int argc, char *argv[])
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

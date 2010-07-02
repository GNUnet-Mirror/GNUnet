/*
     This file is part of GNUnet
     (C) 2004, 2009 Christian Grothoff (and other contributing authors)

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
 * @file fragmentation/test_fragmentation.c
 * @brief test for fragmentation.c
 * @author Christian Grothoff
 */

/**
 * Testcase for defragmentation code.
 * We have testcases for:
 * - 2 fragments, aligned, [0,16),[16,32)
 * - n (50) fragments, [i*16,(i+1)*16)
 * - n (50) fragments, [0,i*16) + [50*16,51*16)
 * - n (100) fragments, inserted in interleaved order (holes in sequence)
 * - holes in sequence
 * - other overlaps
 * - timeouts
 * - multiple entries in GNUNET_hash-list
 * - id collisions in GNUNET_hash-list
 */

#include "platform.h"
#include "gnunet_fragmentation_lib.h"

#if 0

/* -- to speed up the testcases -- */
#define DEFRAGMENTATION_TIMEOUT (1 * GNUNET_CRON_SECONDS)


static GNUNET_PeerIdentity mySender;
static char *myMsg;
static unsigned short myMsgLen;

/* static buffers to avoid lots of malloc/free */
static char masterBuffer[65536];
static char resultBuffer[65536];

static void
handleHelper (const GNUNET_PeerIdentity * sender,
              const char *msg,
              const unsigned int len, int wasEncrypted, GNUNET_TSession * ts)
{
  GNUNET_GE_ASSERT (NULL,
                    0 == memcmp (sender, &mySender,
                                 sizeof (GNUNET_PeerIdentity)));
  myMsg = resultBuffer;
  memcpy (resultBuffer, msg, len);
  myMsgLen = len;
}

/**
 * Wait long enough to force all fragments to timeout.
 */
static void
makeTimeout ()
{
  GNUNET_thread_sleep (DEFRAGMENTATION_TIMEOUT * 2);
  defragmentationPurgeCron (NULL);
}

/**
 * Create a fragment. The data-portion will be filled
 * with a sequence of numbers from start+id to start+len-1+id.
 *
 * @param pep pointer to the ethernet frame/buffer
 * @param ip pointer to the ip-header
 * @param start starting-offset
 * @param length of the data portion
 * @param id the identity of the fragment
 */
static GNUNET_MessageHeader *
makeFragment (unsigned short start,
              unsigned short size, unsigned short tot, int id)
{
  P2P_fragmentation_MESSAGE *frag;
  int i;

  frag = (P2P_fragmentation_MESSAGE *) masterBuffer;
  frag->id = htonl (id);
  frag->off = htons (start);
  frag->len = htons (tot);
  frag->header.size = htons (sizeof (P2P_fragmentation_MESSAGE) + size);

  for (i = 0; i < size; i++)
    ((char *) &frag[1])[i] = (char) i + id + start;
  return &frag->header;
}

/**
 * Check that the packet received is what we expected to
 * get.
 * @param id the expected id
 * @param len the expected length
 */
static void
checkPacket (int id, unsigned int len)
{
  int i;

  GNUNET_GE_ASSERT (NULL, myMsg != NULL);
  GNUNET_GE_ASSERT (NULL, myMsgLen == len);
  for (i = 0; i < len; i++)
    GNUNET_GE_ASSERT (NULL, myMsg[i] == (char) (i + id));
  myMsgLen = 0;
  myMsg = NULL;
}


/* **************** actual testcases ***************** */

static void
testSimpleFragment ()
{
  GNUNET_MessageHeader *pep;

  pep = makeFragment (0, 16, 32, 42);
  processFragment (&mySender, pep);
  GNUNET_GE_ASSERT (NULL, myMsg == NULL);
  pep = makeFragment (16, 16, 32, 42);
  processFragment (&mySender, pep);
  checkPacket (42, 32);
}

static void
testSimpleFragmentTimeout ()
{
  GNUNET_MessageHeader *pep;

  pep = makeFragment (0, 16, 32, 42);
  processFragment (&mySender, pep);
  GNUNET_GE_ASSERT (NULL, myMsg == NULL);
  makeTimeout ();
  pep = makeFragment (16, 16, 32, 42);
  processFragment (&mySender, pep);
  GNUNET_GE_ASSERT (NULL, myMsg == NULL);
  pep = makeFragment (0, 16, 32, 42);
  processFragment (&mySender, pep);
  checkPacket (42, 32);
}

static void
testSimpleFragmentReverse ()
{
  GNUNET_MessageHeader *pep;

  pep = makeFragment (16, 16, 32, 42);
  processFragment (&mySender, pep);
  GNUNET_GE_ASSERT (NULL, myMsg == NULL);
  pep = makeFragment (0, 16, 32, 42);
  processFragment (&mySender, pep);
  checkPacket (42, 32);
}

static void
testManyFragments ()
{
  GNUNET_MessageHeader *pep;
  int i;

  for (i = 0; i < 50; i++)
    {
      pep = makeFragment (i * 16, 16, 51 * 16, 42);
      processFragment (&mySender, pep);
      GNUNET_GE_ASSERT (NULL, myMsg == NULL);
    }
  pep = makeFragment (50 * 16, 16, 51 * 16, 42);
  processFragment (&mySender, pep);
  checkPacket (42, 51 * 16);
}

static void
testManyFragmentsMegaLarge ()
{
  GNUNET_MessageHeader *pep;
  int i;

  for (i = 0; i < 4000; i++)
    {
      pep = makeFragment (i * 16, 16, 4001 * 16, 42);
      processFragment (&mySender, pep);
      GNUNET_GE_ASSERT (NULL, myMsg == NULL);
    }
  pep = makeFragment (4000 * 16, 16, 4001 * 16, 42);
  processFragment (&mySender, pep);
  checkPacket (42, 4001 * 16);
}

static void
testLastFragmentEarly ()
{
  GNUNET_MessageHeader *pep;
  int i;

  for (i = 0; i < 5; i++)
    {
      pep = makeFragment (i * 16, 8, 6 * 16 + 8, 42);
      processFragment (&mySender, pep);
      GNUNET_GE_ASSERT (NULL, myMsg == NULL);
    }
  pep = makeFragment (5 * 16, 24, 6 * 16 + 8, 42);
  processFragment (&mySender, pep);
  for (i = 0; i < 5; i++)
    {
      pep = makeFragment (i * 16 + 8, 8, 6 * 16 + 8, 42);
      processFragment (&mySender, pep);
    }
  checkPacket (42, 6 * 16 + 8);
}

static void
testManyInterleavedFragments ()
{
  GNUNET_MessageHeader *pep;
  int i;

  for (i = 0; i < 50; i++)
    {
      pep = makeFragment (i * 16, 8, 51 * 16 + 8, 42);
      processFragment (&mySender, pep);
      GNUNET_GE_ASSERT (NULL, myMsg == NULL);
    }
  for (i = 0; i < 50; i++)
    {
      pep = makeFragment (i * 16 + 8, 8, 51 * 16 + 8, 42);
      processFragment (&mySender, pep);
      GNUNET_GE_ASSERT (NULL, myMsg == NULL);
    }
  pep = makeFragment (50 * 16, 24, 51 * 16 + 8, 42);
  processFragment (&mySender, pep);
  checkPacket (42, 51 * 16 + 8);
}

static void
testManyInterleavedOverlappingFragments ()
{
  GNUNET_MessageHeader *pep;
  int i;

  for (i = 0; i < 50; i++)
    {
      pep = makeFragment (i * 32, 16, 51 * 32, 42);
      processFragment (&mySender, pep);
      GNUNET_GE_ASSERT (NULL, myMsg == NULL);
    }
  for (i = 0; i < 50; i++)
    {
      pep = makeFragment (i * 32 + 8, 24, 51 * 32, 42);
      processFragment (&mySender, pep);
      GNUNET_GE_ASSERT (NULL, myMsg == NULL);
    }
  pep = makeFragment (50 * 32, 32, 51 * 32, 42);
  processFragment (&mySender, pep);
  checkPacket (42, 51 * 32);
}

static void
testManyOverlappingFragments ()
{
  GNUNET_MessageHeader *pep;
  int i;

  for (i = 0; i < 50; i++)
    {
      pep = makeFragment (0, i * 16 + 16, 51 * 16, 42);
      processFragment (&mySender, pep);
      GNUNET_GE_ASSERT (NULL, myMsg == NULL);
    }
  pep = makeFragment (50 * 16, 16, 51 * 16, 42);
  processFragment (&mySender, pep);
  checkPacket (42, 51 * 16);
}

static void
testManyOverlappingFragmentsTimeout ()
{
  GNUNET_MessageHeader *pep;
  int i;

  for (i = 0; i < 50; i++)
    {
      pep = makeFragment (0, i * 16 + 16, 51 * 16 + 8, 42);
      processFragment (&mySender, pep);
      GNUNET_GE_ASSERT (NULL, myMsg == NULL);
    }
  makeTimeout ();
  pep = makeFragment (50 * 16, 24, 51 * 16 + 8, 42);
  processFragment (&mySender, pep);
  GNUNET_GE_ASSERT (NULL, myMsg == NULL);
  for (i = 0; i < 50; i++)
    {
      pep = makeFragment (0, i * 16 + 16, 51 * 16 + 8, 42);
      processFragment (&mySender, pep);
    }
  checkPacket (42, 51 * 16 + 8);
}

static void
testManyFragmentsMultiId ()
{
  GNUNET_MessageHeader *pep;
  int i;
  int id;

  for (i = 0; i < 50; i++)
    {
      for (id = 0; id < DEFRAG_BUCKET_COUNT; id++)
        {
          pep = makeFragment (i * 16, 16, 51 * 16, id + 5);
          mySender.hashPubKey.bits[0] = id;
          processFragment (&mySender, pep);
          GNUNET_GE_ASSERT (NULL, myMsg == NULL);
        }
    }
  for (id = 0; id < DEFRAG_BUCKET_COUNT; id++)
    {
      pep = makeFragment (50 * 16, 16, 51 * 16, id + 5);
      mySender.hashPubKey.bits[0] = id;
      processFragment (&mySender, pep);
      checkPacket (id + 5, 51 * 16);
    }
}

static void
testManyFragmentsMultiIdCollisions ()
{
  GNUNET_MessageHeader *pep;
  int i;
  int id;

  for (i = 0; i < 5; i++)
    {
      for (id = 0; id < DEFRAG_BUCKET_COUNT * 4; id++)
        {
          pep = makeFragment (i * 16, 16, 6 * 16, id + 5);
          mySender.hashPubKey.bits[0] = id;
          processFragment (&mySender, pep);
          GNUNET_GE_ASSERT (NULL, myMsg == NULL);
        }
    }
  for (id = 0; id < DEFRAG_BUCKET_COUNT * 4; id++)
    {
      pep = makeFragment (5 * 16, 16, 6 * 16, id + 5);
      mySender.hashPubKey.bits[0] = id;
      processFragment (&mySender, pep);
      checkPacket (id + 5, 6 * 16);
    }
}

/* ************* driver ****************** */

static int
p2p_register_handler (const unsigned short type,
                      GNUNET_P2PRequestHandler callback)
{
  return GNUNET_OK;
}

static int
p2p_unregister_handler (const unsigned short type,
                        GNUNET_P2PRequestHandler callback)
{
  return GNUNET_OK;
}


static void *
request_service (const char *name)
{
  return NULL;
}

#endif

int
main (int argc, char *argv[])
{
  fprintf (stderr, "WARNING: testcase not yet ported to new API.\n");
#if 0
  GNUNET_CoreAPIForPlugins capi;

  memset (&capi, 0, sizeof (GNUNET_CoreAPIForPlugins));
  capi.cron = GNUNET_cron_create (NULL);
  capi.loopback_send = &handleHelper;
  capi.service_request = &request_service;
  capi.p2p_ciphertext_handler_register = &p2p_register_handler;
  capi.p2p_ciphertext_handler_unregister = &p2p_unregister_handler;
  provide_module_fragmentation (&capi);

  fprintf (stderr, ".");
  testSimpleFragment ();
  fprintf (stderr, ".");
  testSimpleFragmentTimeout ();
  fprintf (stderr, ".");
  testSimpleFragmentReverse ();
  fprintf (stderr, ".");
  testManyFragments ();
  fprintf (stderr, ".");
  testManyFragmentsMegaLarge ();
  fprintf (stderr, ".");
  testManyFragmentsMultiId ();
  fprintf (stderr, ".");

  testManyInterleavedFragments ();
  fprintf (stderr, ".");
  testManyInterleavedOverlappingFragments ();
  fprintf (stderr, ".");
  testManyOverlappingFragments ();
  fprintf (stderr, ".");
  testManyOverlappingFragmentsTimeout ();
  fprintf (stderr, ".");
  testLastFragmentEarly ();
  fprintf (stderr, ".");
  testManyFragmentsMultiIdCollisions ();
  fprintf (stderr, ".");
  release_module_fragmentation ();
  fprintf (stderr, "\n");
  GNUNET_cron_destroy (capi.cron);
#endif
  return 0;                     /* testcase passed */
}

/*
     This file is part of GNUnet.
     (C) 2013 Christian Grothoff (and other contributing authors)

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
 * @file secretsharing/gnunet-service-secretsharing.c
 * @brief secret sharing service
 * @author Florian Dold
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_time_lib.h"
#include "gnunet_consensus_service.h"
#include "secretsharing.h"
#include "secretsharing_protocol.h"
#include <gcrypt.h>


/**
 * Info about a peer in a key generation session.
 */
struct KeygenPeerInfo
{
  /**
   * Peer identity of the peer.
   */
  struct GNUNET_PeerIdentity peer;

  /**
   * g-component of the peer's paillier public key.
   */
  gcry_mpi_t paillier_g;

  /**
   * mu-component of the peer's paillier public key.
   */
  gcry_mpi_t paillier_n;

  /**
   * The peer's commitment to his presecret.
   */
  gcry_mpi_t presecret_commitment;

  /**
   * The peer's preshare that we could decrypt
   * with out private key.
   */
  gcry_mpi_t decrypted_preshare;

  /**
   * Multiplicative share of the public key.
   */
  gcry_mpi_t public_key_share;

  /**
   * GNUNET_YES if the peer has been disqualified,
   * GNUNET_NO otherwise.
   */
  int disqualified;
};


/**
 * Session to establish a threshold-shared secret.
 */
struct KeygenSession
{
  /**
   * Keygen sessions are held in a linked list.
   */
  struct KeygenSession *next;

  /**
   * Keygen sessions are held in a linked list.
   */
  struct KeygenSession *prev;

  /**
   * Current consensus, used for both DKG rounds.
   */
  struct GNUNET_CONSENSUS_Handle *consensus;

  /**
   * Client that is interested in the result
   * of this key generation session.
   */
  struct GNUNET_SERVER_Client *client;

  /**
   * Message queue for 'client'
   */
  struct GNUNET_MQ_Handle *client_mq;

  /**
   * Randomly generated coefficients of the polynomial for sharing our
   * pre-secret, where 'preshares[0]' is our pre-secret.  Contains 'threshold'
   * elements, thus represents a polynomial of degree 'threshold-1', which can
   * be interpolated with 'threshold' data points.
   *
   * The pre-secret-shares 'i=1,...,num_peers' are given by evaluating this
   * polyomial at 'i' for share i.
   */
  gcry_mpi_t *presecret_polynomial;

  /**
   * Minimum number of shares required to restore the secret.
   */
  unsigned int threshold;

  /**
   * Total number of peers.
   */
  unsigned int num_peers;

  /**
   * Index of the local peer.
   */
  unsigned int local_peer;

  /**
   * Information about all participating peers.
   */
  struct KeygenPeerInfo *info;

  /**
   * List of all peers involved in the secret sharing session.
   */
  struct GNUNET_PeerIdentity *peers;

  /**
   * Identifier for this session.
   */
  struct GNUNET_HashCode session_id;

  /**
   * g-component of our peer's paillier private key.
   */
  gcry_mpi_t paillier_lambda;

  /**
   * g-component of our peer's paillier private key.
   */
  gcry_mpi_t paillier_mu;

  struct GNUNET_TIME_Absolute deadline;

  /**
   * Index of the local peer in the ordered list
   * of peers in the session.
   */
  unsigned int local_peer_idx;
};


struct DecryptSession
{
  struct DecryptSession *next;
  struct DecryptSession *prev;

  struct GNUNET_CONSENSUS_Handle *consensus;

  struct GNUNET_SERVER_Client *client;
};

/**
 * Decrypt sessions are held in a linked list.
 */
//static struct DecryptSession *decrypt_sessions_head;

/**
 * Decrypt sessions are held in a linked list.
 */
//static struct DecryptSession *decrypt_sessions_tail;

/**
 * Decrypt sessions are held in a linked list.
 */
static struct KeygenSession *keygen_sessions_head;

/**
 * Decrypt sessions are held in a linked list.
 */
static struct KeygenSession *keygen_sessions_tail;

/**
 * The ElGamal prime field order as libgcrypt mpi.
 * Will be initialized to 'ELGAMAL_Q_DATA'.
 */
static gcry_mpi_t elgamal_q;

/**
 * Modulus of the prime field used for ElGamal.
 * Will be initialized to 'ELGAMAL_P_DATA'.
 */
static gcry_mpi_t elgamal_p;

/**
 * Generator for prime field of order 'elgamal_q'.
 * Will be initialized to 'ELGAMAL_G_DATA'.
 */
static gcry_mpi_t elgamal_g;

/**
 * Peer that runs this service.
 */
static struct GNUNET_PeerIdentity my_peer;

/**
 * Configuration of this service.
 */
static const struct GNUNET_CONFIGURATION_Handle *cfg;

/**
 * Server for this service.
 */
static struct GNUNET_SERVER_Handle *srv;


/**
 * Although GNUNET_CRYPTO_hash_cmp exisits, it does not have
 * the correct signature to be used with e.g. qsort.
 * We use this function instead.
 *
 * @param h1 some hash code
 * @param h2 some hash code
 * @return 1 if h1 > h2, -1 if h1 < h2 and 0 if h1 == h2.
 */
static int
hash_cmp (const void *h1, const void *h2)
{
  return GNUNET_CRYPTO_hash_cmp ((struct GNUNET_HashCode *) h1, (struct GNUNET_HashCode *) h2);
}


/**
 * Normalize the given list of peers, by including the local peer
 * (if it is missing) and sorting the peers by their identity.
 *
 * @param listed peers in the unnormalized list
 * @param num_listed peers in the un-normalized list
 * @param[out] num_normalized number of peers in the normalized list
 * @param[out] my_peer_idx index of the local peer in the normalized list
 * @return normalized list, must be free'd by the caller
 */
static struct GNUNET_PeerIdentity *
normalize_peers (struct GNUNET_PeerIdentity *listed,
                 unsigned int num_listed,
                 unsigned int *num_normalized,
                 unsigned int *my_peer_idx)
{
  unsigned int local_peer_in_list;
  unsigned int n;
  unsigned int i;
  struct GNUNET_PeerIdentity *normalized;

  local_peer_in_list = GNUNET_NO;
  for (i = 0; i < num_listed; i++)
  {
    if (0 == memcmp (&listed[i], &my_peer, sizeof (struct GNUNET_PeerIdentity)))
    {
      local_peer_in_list = GNUNET_YES;
      break;
    }
  }

  n = num_listed;
  if (GNUNET_NO == local_peer_in_list)
    n++;

  normalized = GNUNET_malloc (n * sizeof (struct GNUNET_PeerIdentity));

  if (GNUNET_NO == local_peer_in_list)
    normalized[n - 1] = my_peer;

  memcpy (normalized, listed, num_listed * sizeof (struct GNUNET_PeerIdentity));
  qsort (normalized, n, sizeof (struct GNUNET_PeerIdentity), &hash_cmp);

  if (NULL != my_peer_idx)
  {
    for (i = 0; i < num_listed; i++)
    {
      if (0 == memcmp (&normalized[i], &my_peer, sizeof (struct GNUNET_PeerIdentity)))
      {
        *my_peer_idx = i;
        break;
      }
    }
  }

  *num_normalized = n;
  return normalized;
}


/**
 * Create a key pair for the paillier crypto system.
 *
 * Uses the simplified key generation of Jonathan Katz, Yehuda Lindell,
 * "Introduction to Modern Cryptography: Principles and Protocols".
 *
 * @param g g-component of public key
 * @param n n-component of public key
 * @param lambda lambda-component of private key
 * @param mu mu-componenent of private key
 */
static void
paillier_create (gcry_mpi_t g, gcry_mpi_t n, gcry_mpi_t lambda, gcry_mpi_t mu)
{
  gcry_mpi_t p;
  gcry_mpi_t q;
  gcry_mpi_t phi;
  gcry_mpi_t tmp;

  GNUNET_assert (0 != (phi = gcry_mpi_new (PAILLIER_BITS)));
  GNUNET_assert (0 != (tmp = gcry_mpi_new (PAILLIER_BITS)));

  // generate rsa modulus
  GNUNET_assert (0 == gcry_prime_generate (&p, PAILLIER_BITS / 2, 0, NULL, NULL, NULL,
                                           GCRY_WEAK_RANDOM, 0));
  GNUNET_assert (0 == gcry_prime_generate (&q, PAILLIER_BITS / 2, 0, NULL, NULL, NULL,
                                           GCRY_WEAK_RANDOM, 0));
  gcry_mpi_mul (n, p, q);
  gcry_mpi_add_ui (g, n, 1);
  // compute phi(n) = (p-1)(q-1)
  gcry_mpi_sub_ui (phi, p, 1);
  gcry_mpi_sub_ui (tmp, q, 1);
  gcry_mpi_mul (phi, phi, tmp);
  gcry_mpi_set (lambda, phi);
  // compute mu
  GNUNET_assert (0 != gcry_mpi_invm (mu, phi, n));

  gcry_mpi_release (p);
  gcry_mpi_release (q);
  gcry_mpi_release (phi);
  gcry_mpi_release (tmp);
}


/**
 * Encrypt a value using Paillier's scheme.
 *
 * @param c resulting ciphertext
 * @param m plaintext to encrypt
 * @param g g-component of public key
 * @param n n-component of public key
 */
static void
paillier_encrypt (gcry_mpi_t c, gcry_mpi_t m, gcry_mpi_t g, gcry_mpi_t n)
{
  gcry_mpi_t n_square;
  gcry_mpi_t r;

  GNUNET_assert (0 != (n_square = gcry_mpi_new (0)));
  GNUNET_assert (0 != (r = gcry_mpi_new (0)));

  gcry_mpi_mul (n_square, n, n);

  // generate r < n
  do
  {
    gcry_mpi_randomize (r, PAILLIER_BITS, GCRY_WEAK_RANDOM);
  }
  while (gcry_mpi_cmp (r, n) > 0);

  gcry_mpi_powm (c, g, m, n_square);
  gcry_mpi_powm (r, r, n, n_square);
  gcry_mpi_mulm (c, r, c, n_square);

  gcry_mpi_release (n_square);
  gcry_mpi_release (r);
}


/**
 * Decrypt a ciphertext using Paillier's scheme.
 *
 * @param[out] m resulting plaintext
 * @param c ciphertext to decrypt
 * @param lambda lambda-component of private key
 * @param mu mu-component of private key
 * @param n n-component of public key
 */
static void
paillier_decrypt (gcry_mpi_t m, gcry_mpi_t c, gcry_mpi_t mu, gcry_mpi_t lambda, gcry_mpi_t n)
{
  gcry_mpi_t n_square;
  GNUNET_assert (0 != (n_square = gcry_mpi_new (0)));
  gcry_mpi_mul (n_square, n, n);
  gcry_mpi_powm (m, c, lambda, n_square);
  gcry_mpi_sub_ui (m, m, 1);
  // m = m/n
  gcry_mpi_div (m, NULL, m, n, 0);
  gcry_mpi_mulm (m, m, mu, n);
  gcry_mpi_release (n_square);
}


/**
 * Task run during shutdown.
 *
 * @param cls unused
 * @param tc unused
 */
static void
cleanup_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  /* FIXME: do clean up here */
}


static void
generate_presecret_polynomial (struct KeygenSession *ks)
{
  int i;
  GNUNET_assert (NULL == ks->presecret_polynomial);
  ks->presecret_polynomial = GNUNET_malloc (ks->threshold * sizeof (gcry_mpi_t));
  for (i = 0; i < ks->threshold; i++)
  {
    ks->presecret_polynomial[i] = gcry_mpi_new (PAILLIER_BITS);
    gcry_mpi_randomize (ks->presecret_polynomial[i], PAILLIER_BITS,
                        GCRY_WEAK_RANDOM);
  }
}


static void
keygen_round1_new_element (void *cls,
                           const struct GNUNET_SET_Element *element)
{
  const struct GNUNET_SECRETSHARING_KeygenCommitData *d;
  struct KeygenSession *ks = cls;
  unsigned int i;

  if (element->size != sizeof (struct GNUNET_SECRETSHARING_KeygenCommitData))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING, "keygen commit data with wrong size in consensus\n");
    return;
  }

  d = element->data;

  for (i = 0; i < ks->num_peers; i++)
  {
    if (0 == memcmp (&d->peer, &ks->info[i].peer, sizeof (struct GNUNET_PeerIdentity)))
    {
      // TODO: check signature
      GNUNET_assert (0 == gcry_mpi_scan (&ks->info[i].paillier_g, GCRYMPI_FMT_USG,
                                         &d->pubkey.g, sizeof d->pubkey.g, NULL));
      GNUNET_assert (0 == gcry_mpi_scan (&ks->info[i].paillier_n, GCRYMPI_FMT_USG,
                                         &d->pubkey.n, sizeof d->pubkey.n, NULL));
      GNUNET_assert (0 == gcry_mpi_scan (&ks->info[i].presecret_commitment, GCRYMPI_FMT_USG,
                                         &d->commitment, sizeof d->commitment, NULL));
      return;
    }
  }

  GNUNET_log (GNUNET_ERROR_TYPE_WARNING, "keygen commit data with wrong peer identity in consensus\n");
}


/**
 * Evaluate the polynomial with coefficients @a coeff at @a x.
 * The i-th element in @a coeff corresponds to the coefficient of x^i.
 *
 * @param[out] z result of the evaluation
 * @param coeff array of coefficients
 * @param num_coeff number of coefficients
 * @param x where to evaluate the polynomial
 * @param m what group are we operating in?
 */
static void
horner_eval (gcry_mpi_t z, gcry_mpi_t *coeff, unsigned int num_coeff, gcry_mpi_t x, gcry_mpi_t m)
{
  unsigned int i;

  gcry_mpi_set_ui (z, 0);
  for (i = 0; i < num_coeff; i++)
  {
    // z <- zx + c
    gcry_mpi_mul (z, z, x);
    gcry_mpi_addm (z, z, coeff[num_coeff - i - 1], m);
  }
}


static void
keygen_round2_conclude (void *cls)
{
  struct KeygenSession *ks = cls;
  struct GNUNET_SECRETSHARING_SecretReadyMessage *m;
  struct GNUNET_MQ_Envelope *ev;
  unsigned int i;
  gcry_mpi_t s;
  gcry_mpi_t h;

  GNUNET_assert (0 != (s = gcry_mpi_new (PAILLIER_BITS)));
  GNUNET_assert (0 != (h = gcry_mpi_new (PAILLIER_BITS)));

  // multiplicative identity
  gcry_mpi_set_ui (s, 1);

  for (i = 0; i < ks->num_peers; i++)
  {
    if (GNUNET_NO == ks->info[i].disqualified)
    {
      gcry_mpi_addm (s, s, ks->info[i].decrypted_preshare, elgamal_p);
      gcry_mpi_mulm (h, h, ks->info[i].public_key_share, elgamal_p);
      m->num_secret_peers++;
    }
  }

  ev = GNUNET_MQ_msg (m, GNUNET_MESSAGE_TYPE_SECRETSHARING_CLIENT_SECRET_READY);

  gcry_mpi_print (GCRYMPI_FMT_USG, (void *) &m->secret, PAILLIER_BITS / 8, NULL, s);
  gcry_mpi_print (GCRYMPI_FMT_USG, (void *) &m->public_key, PAILLIER_BITS / 8, NULL, s);

  GNUNET_MQ_send (ks->client_mq, ev);
}


/**
 * Insert round 2 element in the consensus, consisting of
 * (1) The exponentiated pre-share polynomial coefficients A_{i,l}=g^{a_{i,l}}
 * (2) The exponentiated pre-shares y_{i,j}=g^{s_{i,j}}
 * (3) The encrypted pre-shares Y_{i,j}
 * (4) The zero knowledge proof for correctness of
 *    the encryption
 *
 * @param ks session to use
 */
static void
insert_round2_element (struct KeygenSession *ks)
{
  struct GNUNET_SET_Element *element;
  struct GNUNET_SECRETSHARING_KeygenRevealData *msg;
  unsigned char *pos;
  unsigned char *last_pos;
  size_t element_size;
  unsigned int i;
  gcry_mpi_t c;
  gcry_mpi_t idx;
  gcry_mpi_t v;

  GNUNET_assert (0 != (c = gcry_mpi_new (PAILLIER_BITS)));
  GNUNET_assert (0 != (v = gcry_mpi_new (PAILLIER_BITS)));
  GNUNET_assert (0 != (idx = gcry_mpi_new (PAILLIER_BITS)));

  element_size = (sizeof (struct GNUNET_SECRETSHARING_KeygenRevealData) +
                  2 * PAILLIER_BITS / 8 * ks->num_peers +
                  1 * PAILLIER_BITS / 8 * ks->threshold);

  element = GNUNET_malloc (sizeof (struct GNUNET_SET_Element) + element_size);

  msg = (void *) element->data;
  pos = (void *) &msg[1];
  last_pos = pos + element_size;

  // exponentiated pre-shares
  for (i = 0; i <= ks->threshold; i++)
  {
    ptrdiff_t remaining = last_pos - pos;
    GNUNET_assert (remaining > 0);
    gcry_mpi_set_ui (idx, i);
    // evaluate the polynomial
    horner_eval (v, ks->presecret_polynomial, ks->threshold, idx, elgamal_p);
    // take g to the result
    gcry_mpi_powm (v, elgamal_g, v, elgamal_p);
    gcry_mpi_print (GCRYMPI_FMT_USG, pos, (size_t) remaining, NULL, v);
    pos += PAILLIER_BITS / 8;
  }

  // exponentiated coefficients
  for (i = 0; i < ks->num_peers; i++)
  {
    ptrdiff_t remaining = last_pos - pos;
    GNUNET_assert (remaining > 0);
    gcry_mpi_powm (v, elgamal_g, ks->presecret_polynomial[0], elgamal_p);
    gcry_mpi_print (GCRYMPI_FMT_USG, pos, (size_t) remaining, NULL, v);
    pos += PAILLIER_BITS / 8;
  }

  // encrypted pre-shares
  for (i = 0; i < ks->threshold; i++)
  {
    ptrdiff_t remaining = last_pos - pos;
    GNUNET_assert (remaining > 0);
    if (GNUNET_YES == ks->info[i].disqualified)
      gcry_mpi_set_ui (v, 0);
    else
      paillier_encrypt (v, ks->presecret_polynomial[0],
                        ks->info[i].paillier_g, ks->info[i].paillier_g);
    gcry_mpi_print (GCRYMPI_FMT_USG, pos, (size_t) remaining, NULL, v);
    pos += PAILLIER_BITS / 8;
  }

  GNUNET_CONSENSUS_insert (ks->consensus, element, NULL, NULL);
  GNUNET_free (element); /* FIXME: maybe stack-allocate instead? */
}


static struct KeygenPeerInfo *
get_keygen_peer_info (const struct KeygenSession *ks,
               struct GNUNET_PeerIdentity *peer)
{
  unsigned int i;
  for (i = 0; i < ks->num_peers; i++)
    if (0 == memcmp (peer, &ks->info[i].peer, sizeof (struct GNUNET_PeerIdentity)))
      return &ks->info[i];
  return NULL;
}


static void
keygen_round2_new_element (void *cls,
                           const struct GNUNET_SET_Element *element)
{
  struct KeygenSession *ks = cls;
  struct GNUNET_SECRETSHARING_KeygenRevealData *msg;
  struct KeygenPeerInfo *info;
  unsigned char *pos;
  unsigned char *last_pos;
  gcry_mpi_t c;

  msg = (void *) element->data;
  pos = (void *) &msg[1];
  // skip exp. pre-shares
  pos += PAILLIER_BITS / 8 * ks->num_peers;
  // skip exp. coefficients
  pos += PAILLIER_BITS / 8 * ks->threshold;
  // skip to the value for our peer
  pos += PAILLIER_BITS / 8 * ks->local_peer_idx;

  last_pos = element->size + (unsigned char *) element->data;

  if ((pos >= last_pos) || ((last_pos - pos) < (PAILLIER_BITS / 8)))
  {
    GNUNET_break_op (0);
    return;
  }

  GNUNET_assert (0 == gcry_mpi_scan (&c, GCRYMPI_FMT_USG,
                                     pos, PAILLIER_BITS / 8, NULL));

  info = get_keygen_peer_info (ks, &msg->peer);

  if (NULL == info)
  {
    GNUNET_break_op (0);
    return;
  }

  paillier_decrypt (info->decrypted_preshare, c, ks->paillier_lambda, ks->paillier_mu,
                    ks->info[ks->local_peer_idx].paillier_n);

  // TODO: validate signature and proofs

}


static void
keygen_round1_conclude (void *cls)
{
  struct KeygenSession *ks = cls;

  // TODO: destroy old consensus
  // TODO: mark peers without keys as disqualified

  ks->consensus = GNUNET_CONSENSUS_create (cfg, ks->num_peers, ks->peers, &ks->session_id,
                                           keygen_round2_new_element, ks);

  insert_round2_element (ks);

  GNUNET_CONSENSUS_conclude (ks->consensus, GNUNET_TIME_UNIT_FOREVER_REL /* FIXME */, keygen_round2_conclude, ks);
}


/**
 * Insert the ephemeral key and the presecret commitment
 * of this peer in the consensus of the given session.
 *
 * @param ks session to use
 */
static void
insert_round1_element (struct KeygenSession *ks)
{
  struct GNUNET_SET_Element *element;
  struct GNUNET_SECRETSHARING_KeygenCommitData *d;
  // g^a_{i,0}
  gcry_mpi_t v;
  // big-endian representation of 'v'
  unsigned char v_data[PAILLIER_BITS / 8];

  element = GNUNET_malloc (sizeof *element + sizeof *d);
  d = (void *) &element[1];
  element->data = d;
  element->size = sizeof *d;

  GNUNET_assert (0 != (v = gcry_mpi_new (PAILLIER_BITS)));

  gcry_mpi_powm (v, elgamal_g, ks->presecret_polynomial[0], elgamal_p);

  GNUNET_assert (0 == gcry_mpi_print (GCRYMPI_FMT_USG,
                                      v_data, PAILLIER_BITS / 8, NULL,
                                      v));

  GNUNET_CRYPTO_hash (v_data, PAILLIER_BITS / 8, &d->commitment);

  GNUNET_assert (0 == gcry_mpi_print (GCRYMPI_FMT_USG,
                                      (unsigned char *) d->pubkey.g, PAILLIER_BITS / 8, NULL,
                                      ks->info[ks->local_peer_idx].paillier_g));

  GNUNET_assert (0 == gcry_mpi_print (GCRYMPI_FMT_USG,
                                      (unsigned char *) d->pubkey.n, PAILLIER_BITS / 8, NULL,
                                      ks->info[ks->local_peer_idx].paillier_n));

  // FIXME: sign stuff

  d->peer = my_peer;

  GNUNET_CONSENSUS_insert (ks->consensus, element, NULL, NULL);
}


/**
 * Functions with this signature are called whenever a message is
 * received.
 *
 * @param cls closure
 * @param client identification of the client
 * @param message the actual message
 */
static void handle_client_keygen (void *cls,
                                  struct GNUNET_SERVER_Client *client,
                                  const struct GNUNET_MessageHeader
                                  *message)
{
  const struct GNUNET_SECRETSHARING_CreateMessage *msg =
      (const struct GNUNET_SECRETSHARING_CreateMessage *) message;
  struct KeygenSession *ks;

  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "client requested key generation\n");

  ks = GNUNET_new (struct KeygenSession);

  GNUNET_CONTAINER_DLL_insert (keygen_sessions_head, keygen_sessions_tail, ks);

  ks->deadline = GNUNET_TIME_absolute_ntoh (msg->deadline);
  ks->threshold = ntohs (msg->threshold);
  ks->num_peers = ntohs (msg->num_peers);

  ks->peers = normalize_peers ((struct GNUNET_PeerIdentity *) &msg[1], ks->num_peers,
                               &ks->num_peers, &ks->local_peer_idx);

  // TODO: initialize MPIs in peer structure

  ks->consensus = GNUNET_CONSENSUS_create (cfg, ks->num_peers, ks->peers, &msg->session_id,
                                           keygen_round1_new_element, ks);

  paillier_create (ks->info[ks->local_peer_idx].paillier_g,
                   ks->info[ks->local_peer_idx].paillier_n,
                   ks->paillier_lambda,
                   ks->paillier_mu);


  generate_presecret_polynomial (ks);

  insert_round1_element (ks);

  GNUNET_CONSENSUS_conclude (ks->consensus, GNUNET_TIME_UNIT_FOREVER_REL /* FIXME */, keygen_round1_conclude, ks);
}


/**
 * Functions with this signature are called whenever a message is
 * received.
 *
 * @param cls closure
 * @param client identification of the client
 * @param message the actual message
 */
static void handle_client_decrypt (void *cls,
                                  struct GNUNET_SERVER_Client *client,
                                  const struct GNUNET_MessageHeader
                                  *message)
{
  GNUNET_assert (0);
}


/**
 * Process template requests.
 *
 * @param cls closure
 * @param server the initialized server
 * @param c configuration to use
 */
static void
run (void *cls, struct GNUNET_SERVER_Handle *server,
     const struct GNUNET_CONFIGURATION_Handle *c)
{
  static const struct GNUNET_SERVER_MessageHandler handlers[] = {
    {handle_client_keygen, NULL, GNUNET_MESSAGE_TYPE_SECRETSHARING_CLIENT_GENERATE, 0},
    {handle_client_decrypt, NULL, GNUNET_MESSAGE_TYPE_SECRETSHARING_CLIENT_DECRYPT, 0},
    {NULL, NULL, 0, 0}
  };
  cfg = c;
  srv = server;
  if (GNUNET_OK != GNUNET_CRYPTO_get_peer_identity (cfg, &my_peer))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "could not retrieve host identity\n");
    GNUNET_break (0);
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  GNUNET_SERVER_add_handlers (server, handlers);
  GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_FOREVER_REL, &cleanup_task,
                                NULL);
}


/**
 * The main function for the template service.
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return 0 ok, 1 on error
 */
int
main (int argc, char *const *argv)
{
  return (GNUNET_OK ==
          GNUNET_SERVICE_run (argc, argv, "secretsharing",
                              GNUNET_SERVICE_OPTION_NONE, &run, NULL)) ? 0 : 1;
}


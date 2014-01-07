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
#include "gnunet_signatures.h"
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
   * The peer's paillier public key.
   */
  gcry_mpi_t paillier_n;

  /**
   * The peer's commitment to his presecret.
   */
  gcry_mpi_t presecret_commitment;

  /**
   * The peer's preshare that we decrypted
   * with out private key.
   */
  gcry_mpi_t decrypted_preshare;

  /**
   * Multiplicative share of the public key.
   */
  gcry_mpi_t public_key_share;

  /**
   * Did we successfully receive the round1 element
   * of the peer?
   */
  int round1_valid;

  /**
   * Did we successfully receive the round2 element
   * of the peer?
   */
  int round2_valid;
};


/**
 * Information about a peer in a decrypt session.
 */
struct DecryptPeerInfo
{
  /**
   * Identity of the peer.
   */
  struct GNUNET_PeerIdentity peer;

  /**
   * Original index in the key generation round.
   * Necessary for computing the lagrange coefficients.
   */
  unsigned int real_index;

  /**
   * Set to the partial decryption of
   * this peer, or NULL if we did not
   * receive a partial decryption from this
   * peer or the zero knowledge proof failed.
   */
  gcry_mpi_t partial_decryption;
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
   * Also the number of coefficients for the polynomial representing
   * the sharing.  Obviously, the polynomial then has degree threshold-1.
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
   * Array of size 'num_peers'.
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
   * lambda-component of our peer's paillier private key.
   */
  gcry_mpi_t paillier_lambda;

  /**
   * mu-component of our peer's paillier private key.
   */
  gcry_mpi_t paillier_mu;

  /**
   * When would we like the key to be established?
   */
  struct GNUNET_TIME_Absolute deadline;

  /**
   * When does the DKG start?  Necessary to compute fractions of the
   * operation's desired time interval.
   */
  struct GNUNET_TIME_Absolute start_time;

  /**
   * Index of the local peer in the ordered list
   * of peers in the session.
   */
  unsigned int local_peer_idx;
};


/**
 * Session to cooperatively decrypt a value.
 */
struct DecryptSession
{
  /**
   * Decrypt sessions are stored in a linked list.
   */
  struct DecryptSession *next;

  /**
   * Decrypt sessions are stored in a linked list.
   */
  struct DecryptSession *prev;

  /**
   * Handle to the consensus over partial decryptions.
   */
  struct GNUNET_CONSENSUS_Handle *consensus;

  /**
   * Client connected to us.
   */
  struct GNUNET_SERVER_Client *client;

  /**
   * Message queue for 'client'.
   */
  struct GNUNET_MQ_Handle *client_mq;

  /**
   * When would we like the ciphertext to be
   * decrypted?
   */
  struct GNUNET_TIME_Absolute deadline;

  /**
   * Ciphertext we want to decrypt.
   */
  struct GNUNET_SECRETSHARING_Ciphertext ciphertext;

  /**
   * Share of the local peer.
   * Containts other important information, such as
   * the list of other peers.
   */
  struct GNUNET_SECRETSHARING_Share *share;

  /**
   * State information about other peers.
   */
  struct DecryptPeerInfo *info;
};


/**
 * Decrypt sessions are held in a linked list.
 */
static struct DecryptSession *decrypt_sessions_head;

/**
 * Decrypt sessions are held in a linked list.
 */
static struct DecryptSession *decrypt_sessions_tail;

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
 * Initialized in #init_crypto_constants.
 */
static gcry_mpi_t elgamal_q;

/**
 * Modulus of the prime field used for ElGamal.
 * Initialized in #init_crypto_constants.
 */
static gcry_mpi_t elgamal_p;

/**
 * Generator for prime field of order 'elgamal_q'.
 * Initialized in #init_crypto_constants.
 */
static gcry_mpi_t elgamal_g;

/**
 * Peer that runs this service.
 */
static struct GNUNET_PeerIdentity my_peer;

/**
 * Peer that runs this service.
 */
static struct GNUNET_CRYPTO_EddsaPrivateKey *my_peer_private_key;

/**
 * Configuration of this service.
 */
static const struct GNUNET_CONFIGURATION_Handle *cfg;

/**
 * Server for this service.
 */
static struct GNUNET_SERVER_Handle *srv;


/**
 * If target != size, move @a target bytes to the end of the size-sized
 * buffer and zero out the first @a target - @a size bytes.
 *
 * @param buf original buffer
 * @param size number of bytes in @a buf
 * @param target target size of the buffer
 */
static void
adjust (unsigned char *buf,
	size_t size,
	size_t target)
{
  if (size < target)
  {
    memmove (&buf[target - size], buf, size);
    memset (buf, 0, target - size);
  }
}


/**
 * Print an MPI to a buffer, so that is contains the MPI's
 * the little endian representation of size @a size.
 *
 * @param buf buffer to write to
 * @param x mpi to be written in the buffer
 * @param size how many bytes should the little endian binary
 *             representation of @a x use?
 */
static void
print_mpi_fixed (void *buf, gcry_mpi_t x, size_t size)
{
  size_t written;
  GNUNET_assert (0 == gcry_mpi_print (GCRYMPI_FMT_USG,
                                      buf, size, &written,
                                      x));
  adjust (buf, written, size);
}


/**
 * Get the peer info belonging to a peer identity in a keygen session.
 *
 * @param ks the keygen session
 * @param peer the peer identity
 * @return the keygen peer info, or NULL if the peer could not be found
 */
static struct KeygenPeerInfo *
get_keygen_peer_info (const struct KeygenSession *ks,
                      const struct GNUNET_PeerIdentity *peer)
{
  unsigned int i;
  for (i = 0; i < ks->num_peers; i++)
    if (0 == memcmp (peer, &ks->info[i].peer, sizeof (struct GNUNET_PeerIdentity)))
      return &ks->info[i];
  return NULL;
}


/**
 * Get the peer info belonging to a peer identity in a decrypt session.
 *
 * @param ks the decrypt session
 * @param peer the peer identity
 * @return the decrypt peer info, or NULL if the peer could not be found
 */
static struct DecryptPeerInfo *
get_decrypt_peer_info (const struct DecryptSession *ds,
                      const struct GNUNET_PeerIdentity *peer)
{
  unsigned int i;
  for (i = 0; i < ds->share->num_peers; i++)
    if (0 == memcmp (peer, &ds->info[i].peer, sizeof (struct GNUNET_PeerIdentity)))
      return &ds->info[i];
  return NULL;
}


/**
 * Interpolate between two points in time.
 *
 * @param start start time
 * @param end end time
 * @param num numerator of the scale factor
 * @param denum denumerator of the scale factor
 */
static struct GNUNET_TIME_Absolute
time_between (struct GNUNET_TIME_Absolute start,
              struct GNUNET_TIME_Absolute end,
              int num, int denum)
{
  struct GNUNET_TIME_Absolute result;
  uint64_t diff;

  GNUNET_assert (start.abs_value_us <= end.abs_value_us);
  diff = end.abs_value_us - start.abs_value_us;
  result.abs_value_us = start.abs_value_us + ((diff * num) / denum);

  return result;
}


/**
 * Compare two peer identities.  Indended to be used with qsort or bsearch.
 *
 * @param p1 some peer identity
 * @param p2 some peer identity
 * @return 1 if p1 > p2, -1 if p1 < p2 and 0 if p1 == p2.
 */
static int
peer_id_cmp (const void *p1, const void *p2)
{
  return memcmp (p1, p2, sizeof (struct GNUNET_PeerIdentity));
}


/**
 * Get the index of a peer in an array of peers
 *
 * @param haystack array of peers
 * @param n size of @a haystack
 * @param needle peer to find
 * @return index of @a needle in @a haystack, or -1 if peer
 *         is not in the list.
 */
static int
peer_find (const struct GNUNET_PeerIdentity *haystack, unsigned int n,
           const struct GNUNET_PeerIdentity *needle)
{
  unsigned int i;
  for (i = 0; i < n; i++)
    if (0 == memcmp (&haystack[i], needle, sizeof (struct GNUNET_PeerIdentity)))
      return i;
  return -1;
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
  struct GNUNET_PeerIdentity *normalized;

  local_peer_in_list = GNUNET_YES;
  n = num_listed;
  if (peer_find (listed, num_listed, &my_peer) < 0)
  {
    local_peer_in_list = GNUNET_NO;
    n += 1;
  }

  normalized = GNUNET_new_array (n, struct GNUNET_PeerIdentity);

  if (GNUNET_NO == local_peer_in_list)
    normalized[n - 1] = my_peer;

  memcpy (normalized, listed, num_listed * sizeof (struct GNUNET_PeerIdentity));
  qsort (normalized, n, sizeof (struct GNUNET_PeerIdentity), &peer_id_cmp);

  if (NULL != my_peer_idx)
    *my_peer_idx = peer_find (normalized, n, &my_peer);
  if (NULL != num_normalized)
    *num_normalized = n;

  return normalized;
}


/**
 * Get a the j-th lagrage coefficient for a set of indices.
 *
 * @param[out] coeff the lagrange coefficient
 * @param j lagrage coefficient we want to compute
 * @param indices indices
 * @param num number of indices in @a indices
 */
static void
compute_lagrange_coefficient (gcry_mpi_t coeff, unsigned int j,
                              unsigned int *indices,
                              unsigned int num)
{
  int i;
  /* numerator */
  gcry_mpi_t n;
  /* denominator */
  gcry_mpi_t d;
  /* temp value for l-j */
  gcry_mpi_t tmp;

  GNUNET_assert (0 != coeff);

  GNUNET_assert (0 != (n = gcry_mpi_new (0)));
  GNUNET_assert (0 != (d = gcry_mpi_new (0)));
  GNUNET_assert (0 != (tmp = gcry_mpi_new (0)));

  gcry_mpi_set_ui (n, 1);
  gcry_mpi_set_ui (d, 1);

  gcry_mpi_set_ui (coeff, 0);
  for (i = 0; i < num; i++)
  {
    int l = indices[i];
    if (l == j)
      continue;
    gcry_mpi_mul_ui (n, n, l);
    // d <- d * (l-j)
    gcry_mpi_set_ui (tmp, l);
    gcry_mpi_sub_ui (tmp, tmp, j);
    gcry_mpi_mul (d, d, tmp);
  }

  // now we do the actual division, with everything mod q, as we
  // are not operating on elemets from <g>, but on exponents
  GNUNET_assert (0 == gcry_mpi_invm (d, d, elgamal_q));
  gcry_mpi_mulm (coeff, n, d, elgamal_q);

  gcry_mpi_release (n);
  gcry_mpi_release (d);
  gcry_mpi_release (tmp);
}


/**
 * Create a key pair for the paillier crypto system.
 *
 * Uses the simplified key generation of Jonathan Katz, Yehuda Lindell,
 * "Introduction to Modern Cryptography: Principles and Protocols".
 *
 * @param n n-component of public key
 * @param lambda lambda-component of private key
 * @param mu mu-componenent of private key
 */
static void
paillier_create (gcry_mpi_t n, gcry_mpi_t lambda, gcry_mpi_t mu)
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
 * @param n n-component of public key
 */
static void
paillier_encrypt (gcry_mpi_t c, gcry_mpi_t m, gcry_mpi_t n)
{
  gcry_mpi_t n_square;
  gcry_mpi_t r;
  gcry_mpi_t g;

  GNUNET_assert (0 != (n_square = gcry_mpi_new (0)));
  GNUNET_assert (0 != (r = gcry_mpi_new (0)));
  GNUNET_assert (0 != (g = gcry_mpi_new (0)));

  gcry_mpi_add_ui (g, n, 1);

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


/**
 * Generate the random coefficients of our pre-secret polynomial
 *
 * @param ks the session
 */
static void
generate_presecret_polynomial (struct KeygenSession *ks)
{
  int i;
  GNUNET_assert (NULL == ks->presecret_polynomial);
  ks->presecret_polynomial = GNUNET_malloc (ks->threshold * sizeof (gcry_mpi_t));
  for (i = 0; i < ks->threshold; i++)
  {
    ks->presecret_polynomial[i] = gcry_mpi_new (GNUNET_SECRETSHARING_KEY_BITS);
    GNUNET_assert (0 != ks->presecret_polynomial[i]);
    gcry_mpi_randomize (ks->presecret_polynomial[i], GNUNET_SECRETSHARING_KEY_BITS,
                        GCRY_WEAK_RANDOM);
  }
}


/**
 * Consensus element handler for round one.
 *
 * @param cls closure (keygen session)
 * @param element the element from consensus
 */
static void
keygen_round1_new_element (void *cls,
                           const struct GNUNET_SET_Element *element)
{
  const struct GNUNET_SECRETSHARING_KeygenCommitData *d;
  struct KeygenSession *ks = cls;
  struct KeygenPeerInfo *info;

  if (NULL == element)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING, "round1 consensus failed\n");
    return;
  }

  if (element->size != sizeof (struct GNUNET_SECRETSHARING_KeygenCommitData))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "keygen commit data with wrong size (%u) in consensus, "
                " %u expected\n",
                element->size, sizeof (struct GNUNET_SECRETSHARING_KeygenCommitData));
    return;
  }

  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "got round1 element\n");

  d = element->data;

  info = get_keygen_peer_info (ks, &d->peer);

  if (NULL == info)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING, "keygen commit data with wrong peer identity (%s) in consensus\n",
                GNUNET_i2s (&d->peer));
    return;
  }

  if (d->purpose.size !=
      htonl (element->size - offsetof (struct GNUNET_SECRETSHARING_KeygenCommitData, purpose)))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING, "keygen commit data with wrong signature purpose size in consensus\n");
    return;
  }

  if (GNUNET_OK != GNUNET_CRYPTO_eddsa_verify (GNUNET_SIGNATURE_PURPOSE_SECRETSHARING_DKG1,
                                               &d->purpose, &d->signature, &d->peer.public_key))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING, "keygen commit data with invalid signature in consensus\n");
    return;
  }

  GNUNET_assert (0 == gcry_mpi_scan (&info->paillier_n, GCRYMPI_FMT_USG,
                                     &d->pubkey.n, sizeof d->pubkey.n, NULL));
  GNUNET_assert (0 == gcry_mpi_scan (&info->presecret_commitment, GCRYMPI_FMT_USG,
                                     &d->commitment, sizeof d->commitment, NULL));
  info->round1_valid = GNUNET_YES;
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
  size_t share_size;
  unsigned int i;
  unsigned int j;
  struct GNUNET_SECRETSHARING_Share *share;
  gcry_mpi_t s;
  gcry_mpi_t h;

  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "round2 conclude\n");

  GNUNET_assert (0 != (s = gcry_mpi_new (GNUNET_SECRETSHARING_KEY_BITS)));
  GNUNET_assert (0 != (h = gcry_mpi_new (GNUNET_SECRETSHARING_KEY_BITS)));

  // multiplicative identity
  gcry_mpi_set_ui (s, 1);

  share = GNUNET_new (struct GNUNET_SECRETSHARING_Share);

  share->num_peers = 0;

  for (i = 0; i < ks->num_peers; i++)
    if (GNUNET_YES == ks->info[i].round2_valid)
      share->num_peers++;

  share->peers = GNUNET_new_array (share->num_peers, struct GNUNET_PeerIdentity);
  share->hom_share_commitments =
      GNUNET_new_array (share->num_peers, struct GNUNET_SECRETSHARING_FieldElement);
  share->original_indices = GNUNET_new_array (share->num_peers, uint16_t);

  j = 0;
  for (i = 0; i < ks->num_peers; i++)
  {
    if (GNUNET_YES == ks->info[i].round2_valid)
    {
      gcry_mpi_addm (s, s, ks->info[i].decrypted_preshare, elgamal_p);
      gcry_mpi_mulm (h, h, ks->info[i].public_key_share, elgamal_p);
      share->peers[i] = ks->info[i].peer;
      share->original_indices[i] = j++;
    }
  }

  print_mpi_fixed (&share->my_share, s, GNUNET_SECRETSHARING_KEY_BITS / 8);
  print_mpi_fixed (&share->public_key, h, GNUNET_SECRETSHARING_KEY_BITS / 8);

  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "keygen successful with %u peers\n", share->num_peers);

  m = GNUNET_malloc (sizeof (struct GNUNET_SECRETSHARING_SecretReadyMessage) +
                     ks->num_peers * sizeof (struct GNUNET_PeerIdentity));

  GNUNET_assert (GNUNET_OK == GNUNET_SECRETSHARING_share_write (share, NULL, 0, &share_size));

  ev = GNUNET_MQ_msg_extra (m, share_size,
                            GNUNET_MESSAGE_TYPE_SECRETSHARING_CLIENT_SECRET_READY);

  GNUNET_assert (GNUNET_OK == GNUNET_SECRETSHARING_share_write (share, &m[1], share_size, NULL));

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
  struct GNUNET_SECRETSHARING_KeygenRevealData *d;
  unsigned char *pos;
  unsigned char *last_pos;
  size_t element_size;
  unsigned int i;
  gcry_mpi_t idx;
  gcry_mpi_t v;

  GNUNET_assert (0 != (v = gcry_mpi_new (GNUNET_SECRETSHARING_KEY_BITS)));
  GNUNET_assert (0 != (idx = gcry_mpi_new (GNUNET_SECRETSHARING_KEY_BITS)));

  element_size = (sizeof (struct GNUNET_SECRETSHARING_KeygenRevealData) +
                  2 * GNUNET_SECRETSHARING_KEY_BITS / 8 * ks->num_peers +
                  1 * GNUNET_SECRETSHARING_KEY_BITS / 8 * ks->threshold);

  element = GNUNET_malloc (sizeof (struct GNUNET_SET_Element) + element_size);
  element->size = element_size;
  element->data = (void *) &element[1];

  d = (void *) element->data;
  d->peer = my_peer;

  pos = (void *) &d[1];
  last_pos = pos + element_size;

  // exponentiated pre-shares
  for (i = 0; i < ks->num_peers; i++)
  {
    ptrdiff_t remaining = last_pos - pos;
    GNUNET_assert (remaining > 0);
    gcry_mpi_set_ui (idx, i);
    // evaluate the polynomial
    horner_eval (v, ks->presecret_polynomial, ks->threshold, idx, elgamal_p);
    // take g to the result
    gcry_mpi_powm (v, elgamal_g, v, elgamal_p);
    print_mpi_fixed (pos, v, GNUNET_SECRETSHARING_KEY_BITS / 8);
    pos += GNUNET_SECRETSHARING_KEY_BITS / 8;
  }

  // encrypted pre-shares
  for (i = 0; i < ks->num_peers; i++)
  {
    ptrdiff_t remaining = last_pos - pos;
    GNUNET_assert (remaining > 0);
    if (GNUNET_NO == ks->info[i].round1_valid)
      gcry_mpi_set_ui (v, 0);
    else
      paillier_encrypt (v, ks->presecret_polynomial[0], ks->info[i].paillier_n);
    print_mpi_fixed (pos, v, GNUNET_SECRETSHARING_KEY_BITS / 8);
    pos += GNUNET_SECRETSHARING_KEY_BITS / 8;
  }

  // exponentiated coefficients
  for (i = 0; i < ks->threshold; i++)
  {
    ptrdiff_t remaining = last_pos - pos;
    GNUNET_assert (remaining > 0);
    gcry_mpi_powm (v, elgamal_g, ks->presecret_polynomial[i], elgamal_p);
    print_mpi_fixed (pos, v, GNUNET_SECRETSHARING_KEY_BITS / 8);
    pos += GNUNET_SECRETSHARING_KEY_BITS / 8;
  }

  d->purpose.size = htonl (element_size - offsetof (struct GNUNET_SECRETSHARING_KeygenRevealData, purpose));
  d->purpose.purpose = htonl (GNUNET_SIGNATURE_PURPOSE_SECRETSHARING_DKG2);
  GNUNET_CRYPTO_eddsa_sign (my_peer_private_key, &d->purpose, &d->signature);

  GNUNET_CONSENSUS_insert (ks->consensus, element, NULL, NULL);
  GNUNET_free (element); /* FIXME: maybe stack-allocate instead? */

  gcry_mpi_release (v);
  gcry_mpi_release (idx);
}


static void
keygen_round2_new_element (void *cls,
                           const struct GNUNET_SET_Element *element)
{
  struct KeygenSession *ks = cls;
  const struct GNUNET_SECRETSHARING_KeygenRevealData *d;
  struct KeygenPeerInfo *info;
  unsigned char *pos;
  gcry_mpi_t c;
  size_t expected_element_size;

  if (NULL == element)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING, "round2 consensus failed\n");
    return;
  }

  expected_element_size = (sizeof (struct GNUNET_SECRETSHARING_KeygenRevealData) +
                  2 * GNUNET_SECRETSHARING_KEY_BITS / 8 * ks->num_peers +
                  1 * GNUNET_SECRETSHARING_KEY_BITS / 8 * ks->threshold);

  if (element->size != expected_element_size)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "keygen round2 data with wrong size (%u) in consensus, "
                " %u expected\n",
                element->size, expected_element_size);
    return;
  }

  d = (const void *) element->data;

  info = get_keygen_peer_info (ks, &d->peer);

  if (NULL == info)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING, "keygen commit data with wrong peer identity (%s) in consensus\n",
                GNUNET_i2s (&d->peer));
    return;
  }

  if (GNUNET_NO == info->round1_valid)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "ignoring round2 element from peer with invalid round1 element (%s)\n",
                GNUNET_i2s (&d->peer));
    return;
  }

  if (GNUNET_YES == info->round2_valid)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "ignoring duplicate round2 element (%s)\n",
                GNUNET_i2s (&d->peer));
    return;
  }

  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "got round2 element\n");


  pos = (void *) &d[1];
  // skip exponentiated pre-shares
  pos += GNUNET_SECRETSHARING_KEY_BITS / 8 * ks->num_peers;
  // skip encrypted pre-shares
  pos += PAILLIER_BITS / 8 * ks->num_peers;
  // the first exponentiated coefficient is the public key share
  GNUNET_assert (0 == gcry_mpi_scan (&info->public_key_share, GCRYMPI_FMT_USG,
                                     pos, GNUNET_SECRETSHARING_KEY_BITS / 8, NULL));

  pos = (void *) &d[1];
  // skip exp. pre-shares
  pos += GNUNET_SECRETSHARING_KEY_BITS / 8 * ks->num_peers;
  // skip to the encrypted value for our peer
  pos += PAILLIER_BITS / 8 * ks->local_peer_idx;

  GNUNET_assert (0 == gcry_mpi_scan (&c, GCRYMPI_FMT_USG,
                                     pos, PAILLIER_BITS / 8, NULL));

  GNUNET_assert (0 != (info->decrypted_preshare = mpi_new (0)));

  paillier_decrypt (info->decrypted_preshare, c, ks->paillier_lambda, ks->paillier_mu,
                    ks->info[ks->local_peer_idx].paillier_n);

  // TODO: validate zero knowledge proofs

  if (d->purpose.size !=
      htons (element->size - offsetof (struct GNUNET_SECRETSHARING_KeygenRevealData, purpose)))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING, "keygen reveal data with wrong signature purpose size in consensus\n");
    return;
  }

  if (GNUNET_OK != GNUNET_CRYPTO_eddsa_verify (GNUNET_SIGNATURE_PURPOSE_SECRETSHARING_DKG2,
                                               &d->purpose, &d->signature, &d->peer.public_key))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING, "keygen reveal data with invalid signature in consensus\n");
    return;
  }
  
  info->round2_valid = GNUNET_YES;
}


/**
 * Called when the first consensus round has concluded.
 * Will initiate the second round.
 *
 * @param cls closure
 */
static void
keygen_round1_conclude (void *cls)
{
  struct KeygenSession *ks = cls;

  GNUNET_CONSENSUS_destroy (ks->consensus);

  ks->consensus = GNUNET_CONSENSUS_create (cfg, ks->num_peers, ks->peers, &ks->session_id,
                                           keygen_round2_new_element, ks);

  insert_round2_element (ks);

  GNUNET_CONSENSUS_conclude (ks->consensus,
                             /* last round, thus conclude at DKG deadline */
                             ks->deadline,
                             keygen_round2_conclude,
                             ks);
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
  unsigned char v_data[GNUNET_SECRETSHARING_KEY_BITS / 8];

  element = GNUNET_malloc (sizeof *element + sizeof *d);
  d = (void *) &element[1];
  element->data = d;
  element->size = sizeof *d;

  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "alloc'd size %u\n", sizeof *element + sizeof *d);
  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "element size %u\n", element->size);


  d->peer = my_peer;

  GNUNET_assert (0 != (v = gcry_mpi_new (GNUNET_SECRETSHARING_KEY_BITS)));

  gcry_mpi_powm (v, elgamal_g, ks->presecret_polynomial[0], elgamal_p);

  print_mpi_fixed (v_data, v, GNUNET_SECRETSHARING_KEY_BITS);

  GNUNET_CRYPTO_hash (v_data, GNUNET_SECRETSHARING_KEY_BITS / 8, &d->commitment);

  print_mpi_fixed (d->pubkey.n, ks->info[ks->local_peer_idx].paillier_n,
                   PAILLIER_BITS / 8);

  d->purpose.size = htonl ((sizeof *d) - offsetof (struct GNUNET_SECRETSHARING_KeygenCommitData, purpose));
  d->purpose.purpose = htonl (GNUNET_SIGNATURE_PURPOSE_SECRETSHARING_DKG1);
  GNUNET_assert (GNUNET_OK == GNUNET_CRYPTO_eddsa_sign (my_peer_private_key, &d->purpose, &d->signature));

  GNUNET_CONSENSUS_insert (ks->consensus, element, NULL, NULL);

  gcry_mpi_release (v);
  GNUNET_free (element);
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
  unsigned int i;

  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "client requested key generation\n");

  ks = GNUNET_new (struct KeygenSession);

  /* FIXME: check if client already has some session */

  GNUNET_CONTAINER_DLL_insert (keygen_sessions_head, keygen_sessions_tail, ks);

  ks->client = client;
  ks->client_mq = GNUNET_MQ_queue_for_server_client (client);

  ks->deadline = GNUNET_TIME_absolute_ntoh (msg->deadline);
  ks->threshold = ntohs (msg->threshold);
  ks->num_peers = ntohs (msg->num_peers);

  ks->peers = normalize_peers ((struct GNUNET_PeerIdentity *) &msg[1], ks->num_peers,
                               &ks->num_peers, &ks->local_peer_idx);


  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "first round of consensus with %u peers\n", ks->num_peers);
  ks->consensus = GNUNET_CONSENSUS_create (cfg, ks->num_peers, ks->peers, &msg->session_id,
                                           keygen_round1_new_element, ks);

  ks->info = GNUNET_malloc (ks->num_peers * sizeof (struct KeygenPeerInfo));

  for (i = 0; i < ks->num_peers; i++)
    ks->info[i].peer = ks->peers[i];

  GNUNET_assert (0 != (ks->info[ks->local_peer_idx].paillier_n = mpi_new (0)));
  GNUNET_assert (0 != (ks->paillier_lambda = mpi_new (0)));
  GNUNET_assert (0 != (ks->paillier_mu = mpi_new (0)));

  paillier_create (ks->info[ks->local_peer_idx].paillier_n,
                   ks->paillier_lambda,
                   ks->paillier_mu);


  generate_presecret_polynomial (ks);

  insert_round1_element (ks);

  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "starting conclude of round 1\n");

  GNUNET_CONSENSUS_conclude (ks->consensus,
                             /* half the overall time */
                             time_between (ks->start_time, ks->deadline, 1, 2),
                             keygen_round1_conclude,
                             ks);

  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}


/**
 * Called when the partial decryption consensus concludes.
 */
static void
decrypt_conclude (void *cls)
{
  struct DecryptSession *ds = cls;
  struct GNUNET_SECRETSHARING_DecryptResponseMessage *msg;
  struct GNUNET_MQ_Envelope *ev;
  gcry_mpi_t lagrange;
  gcry_mpi_t m;
  gcry_mpi_t tmp;
  gcry_mpi_t c_2;
  unsigned int *indices;
  unsigned int num;
  unsigned int i;
  unsigned int j;

  GNUNET_assert (0 != (lagrange = gcry_mpi_new (0)));
  GNUNET_assert (0 != (m = gcry_mpi_new (0)));
  GNUNET_assert (0 != (tmp = gcry_mpi_new (0)));

  num = 0;
  for (i = 0; i < ds->share->num_peers; i++)
    if (NULL != ds->info[i].partial_decryption)
      num++;

  indices = GNUNET_malloc (num * sizeof (unsigned int));
  j = 0;
  for (i = 0; i < ds->share->num_peers; i++)
    if (NULL != ds->info[i].partial_decryption)
      indices[j++] = ds->info[i].real_index;

  gcry_mpi_set_ui (m, 1);

  for (i = 0; i < num; i++)
  {
    compute_lagrange_coefficient (lagrange, indices[i], indices, num);
    // w_j^{\lambda_j}
    gcry_mpi_powm (tmp, ds->info[indices[i]].partial_decryption, lagrange, elgamal_p);
    gcry_mpi_mulm (m, m, tmp, elgamal_p);
  }

  GNUNET_assert (0 == gcry_mpi_scan (&c_2, GCRYMPI_FMT_USG, ds->ciphertext.c2_bits,
                                     GNUNET_SECRETSHARING_KEY_BITS / 8, NULL));

  // m <- c_2 / m
  gcry_mpi_invm (m, m, elgamal_p);
  gcry_mpi_mulm (m, c_2, m, elgamal_p);

  ev = GNUNET_MQ_msg (msg, GNUNET_MESSAGE_TYPE_SECRETSHARING_CLIENT_DECRYPT_DONE);
  print_mpi_fixed (&msg->plaintext, m, GNUNET_SECRETSHARING_KEY_BITS / 8);
  msg->success = htonl (1);
  GNUNET_MQ_send (ds->client_mq, ev);

  // FIXME: what if not enough peers participated?
}


/**
 * Called when a new partial decryption arrives.
 */
static void
decrypt_new_element (void *cls,
                     const struct GNUNET_SET_Element *element)
{
  struct DecryptSession *session = cls;
  const struct GNUNET_SECRETSHARING_DecryptData *d;
  struct DecryptPeerInfo *info;

  if (NULL == element)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "decryption failed\n");
    /* FIXME: destroy */
    return;
  }

  if (element->size != sizeof *d)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "element of wrong size in decrypt consensus\n");
    return;
  }

  d = element->data;

  info = get_decrypt_peer_info (session, &d->peer);
  
  if (NULL == info)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "decrypt element from invalid peer (%s)\n",
                GNUNET_i2s (&d->peer));
    return;
  }

  if (NULL != info->partial_decryption)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "decrypt element duplicate\n",
                GNUNET_i2s (&d->peer));
    return;
  }

  // FIXME: check NIZP first

  GNUNET_assert (0 == gcry_mpi_scan (&info->partial_decryption,
                                     GCRYMPI_FMT_USG, &d->partial_decryption, GNUNET_SECRETSHARING_KEY_BITS / 8, NULL));
}

static void
insert_decrypt_element (struct DecryptSession *ds)
{
  struct GNUNET_SECRETSHARING_DecryptData d;
  struct GNUNET_SET_Element element;
  gcry_mpi_t x;
  gcry_mpi_t s;

  GNUNET_assert (0 == gcry_mpi_scan (&x, GCRYMPI_FMT_USG, ds->ciphertext.c1_bits, GNUNET_SECRETSHARING_KEY_BITS / 8, NULL));
  GNUNET_assert (0 == gcry_mpi_scan (&s, GCRYMPI_FMT_USG, &ds->share->my_share, GNUNET_SECRETSHARING_KEY_BITS / 8, NULL));

  gcry_mpi_powm (x, x, s, elgamal_p);

  element.data = (void *) &d;
  element.size = sizeof (struct GNUNET_SECRETSHARING_DecryptData);

  d.peer = my_peer;
  d.purpose.size = htonl (element.size - offsetof (struct GNUNET_SECRETSHARING_KeygenRevealData, purpose));
  d.purpose.purpose = htonl (GNUNET_SIGNATURE_PURPOSE_SECRETSHARING_DECRYPTION);
  GNUNET_CRYPTO_eddsa_sign (my_peer_private_key, &d.purpose, &d.signature);

  print_mpi_fixed (&d.partial_decryption, x, GNUNET_SECRETSHARING_KEY_BITS / 8);

  GNUNET_CONSENSUS_insert (ds->consensus, &element, NULL, NULL);
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
  const struct GNUNET_SECRETSHARING_DecryptRequestMessage *msg =
      (const void *) message;
  struct DecryptSession *ds;
  struct GNUNET_HashCode session_id;

  ds = GNUNET_new (struct DecryptSession);
  // FIXME: check if session already exists
  GNUNET_CONTAINER_DLL_insert (decrypt_sessions_head, decrypt_sessions_tail, ds);
  ds->client = client;
  ds->client_mq = GNUNET_MQ_queue_for_server_client (client);
  ds->deadline = GNUNET_TIME_absolute_ntoh (msg->deadline);
  ds->ciphertext = msg->ciphertext;

  ds->share = GNUNET_SECRETSHARING_share_read (&msg[1], ntohs (msg->header.size) - sizeof *msg, NULL);
  // FIXME: probably should be break rather than assert
  GNUNET_assert (NULL != ds->share);

  // FIXME: this is probably sufficient, but kdf/hash with all values would be nicer ...
  GNUNET_CRYPTO_hash (&msg->ciphertext, sizeof (struct GNUNET_SECRETSHARING_Ciphertext), &session_id);

  ds->consensus = GNUNET_CONSENSUS_create (cfg,
                                           ds->share->num_peers,
                                           ds->share->peers,
                                           &session_id,
                                           decrypt_new_element,
                                           ds);

  insert_decrypt_element (ds);

  GNUNET_CONSENSUS_conclude (ds->consensus, ds->deadline, decrypt_conclude, ds);
}


static void
init_crypto_constants (void)
{
  /* 1024-bit safe prime */
  const char *elgamal_p_hex =
      "0x08a347d3d69e8b2dd7d1b12a08dfbccbebf4ca"
      "6f4269a0814e158a34312964d946b3ef22882317"
      "2bcf30fc08f772774cb404f9bc002a6f66b09a79"
      "d810d67c4f8cb3bedc6060e3c8ef874b1b64df71"
      "6c7d2b002da880e269438d5a776e6b5f253c8df5"
      "6a16b1c7ce58def07c03db48238aadfc52a354a2"
      "7ed285b0c1675cad3f3";
  /* 1023-bit Sophie Germain prime, q = (p-1)/2 */
  const char *elgamal_q_hex =
      "0x0451a3e9eb4f4596ebe8d895046fde65f5fa65"
      "37a134d040a70ac51a1894b26ca359f79144118b"
      "95e7987e047bb93ba65a027cde001537b3584d3c"
      "ec086b3e27c659df6e303071e477c3a58db26fb8"
      "b63e958016d4407134a1c6ad3bb735af929e46fa"
      "b50b58e3e72c6f783e01eda411c556fe2951aa51"
      "3f6942d860b3ae569f9";
  /* generator of the unique size q subgroup of Z_p^* */
  const char *elgamal_g_hex =
      "0x05c00c36d2e822950087ef09d8252994adc4e4"
      "8fe3ec70269f035b46063aff0c99b633fd64df43"
      "02442e1914c829a41505a275438871f365e91c12"
      "3d5303ef9e90f4b8cb89bf86cc9b513e74a72634"
      "9cfd9f953674fab5d511e1c078fc72d72b34086f"
      "c82b4b951989eb85325cb203ff98df76bc366bba"
      "1d7024c3650f60d0da";

  GNUNET_assert (0 == gcry_mpi_scan (&elgamal_q, GCRYMPI_FMT_HEX,
                                     elgamal_q_hex, 0, NULL));
  GNUNET_assert (0 == gcry_mpi_scan (&elgamal_p, GCRYMPI_FMT_HEX,
                                     elgamal_p_hex, 0, NULL));
  GNUNET_assert (0 == gcry_mpi_scan (&elgamal_g, GCRYMPI_FMT_HEX,
                                     elgamal_g_hex, 0, NULL));
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
  my_peer_private_key = GNUNET_CRYPTO_eddsa_key_create_from_configuration (c);
  if (NULL == my_peer_private_key)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "could not access host private key\n");
    GNUNET_break (0);
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  init_crypto_constants ();
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


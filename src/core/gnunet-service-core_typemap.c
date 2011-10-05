
/**
 * Bitmap of message types this peer is able to handle.
 */
static uint32_t my_type_map[(UINT16_MAX + 1) / 32];


/**
 * Compute a type map message for this peer.
 *
 * @return this peers current type map message.
 */
static struct GNUNET_MessageHeader *
compute_type_map_message ()
{
  char *tmp;
  uLongf dlen;
  struct GNUNET_MessageHeader *hdr;

#ifdef compressBound
  dlen = compressBound (sizeof (my_type_map));
#else
  dlen = sizeof (my_type_map) + (sizeof (my_type_map) / 100) + 20;
  /* documentation says 100.1% oldSize + 12 bytes, but we
   * should be able to overshoot by more to be safe */
#endif
  hdr = GNUNET_malloc (dlen + sizeof (struct GNUNET_MessageHeader));
  hdr->size = htons ((uint16_t) dlen + sizeof (struct GNUNET_MessageHeader));
  tmp = (char *) &hdr[1];
  if ((Z_OK !=
       compress2 ((Bytef *) tmp, &dlen, (const Bytef *) my_type_map,
                  sizeof (my_type_map), 9)) || (dlen >= sizeof (my_type_map)))
  {
    dlen = sizeof (my_type_map);
    memcpy (tmp, my_type_map, sizeof (my_type_map));
    hdr->type = htons (GNUNET_MESSAGE_TYPE_CORE_BINARY_TYPE_MAP);
  }
  else
  {
    hdr->type = htons (GNUNET_MESSAGE_TYPE_CORE_COMPRESSED_TYPE_MAP);
  }
  return hdr;
}


/**
 * Send a type map message to the neighbour.
 *
 * @param cls the type map message
 * @param key neighbour's identity
 * @param value 'struct Neighbour' of the target
 * @return always GNUNET_OK
 */
static int
send_type_map_to_neighbour (void *cls, const GNUNET_HashCode * key, void *value)
{
  struct GNUNET_MessageHeader *hdr = cls;
  struct Neighbour *n = value;
  struct MessageEntry *m;
  uint16_t size;

  if (n == &self)
    return GNUNET_OK;
  size = ntohs (hdr->size);
  m = GNUNET_malloc (sizeof (struct MessageEntry) + size);
  memcpy (&m[1], hdr, size);
  m->deadline = GNUNET_TIME_UNIT_FOREVER_ABS;
  m->slack_deadline = GNUNET_TIME_UNIT_FOREVER_ABS;
  m->priority = UINT_MAX;
  m->sender_status = n->status;
  m->size = size;
  m->next = n->messages;
  n->messages = m;
  return GNUNET_OK;
}



/**
 * Send my type map to all connected peers (it got changed).
 */
static void
broadcast_my_type_map ()
{
  struct GNUNET_MessageHeader *hdr;

  if (NULL == neighbours)
    return;
  hdr = compute_type_map_message ();
  GNUNET_CONTAINER_multihashmap_iterate (neighbours,
                                         &send_type_map_to_neighbour, hdr);
  GNUNET_free (hdr);
}




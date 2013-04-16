
/**
 * The operation that a set set supports.
 */
enum GNUNET_SET_Operation
{
  /**
   * Set intersection, only return elements that are in both sets.
   */
  GNUNET_SET_OPERATION_INTERSECTION,
  /**
   * Set union, return all elements that are in at least one of the sets.
   */
  GNUNET_SET_OPERATION_UNION
};

/**
 * Status for the result callback
 */
enum GNUNET_SET_Status
{
  /**
   * Everything went ok.
   */
  GNUNET_SET_STATUS_OK,
  /**
   * There was a timeout.
   */
  GNUNET_SET_STATUS_TIMEOUT,
  /*
   * The other peer refused to to the operation with us
   */
  GNUNET_SET_STATUS_REFUSED
};

struct GNUNET_SET_Element
{
  /**
   * Number of bytes in the buffer pointed to by data.
   */
  uint16_t size;
  /**
   * Application-specific element type.
   */
  uint16_t type;
  /**
   * Actual data of the element
   */
  void *data;
};

/**
 * Callback for set operation results. Called for each element
 * in the result set.
 *
 * @param cls closure
 * @param element element, or NULL to indicate that all elements
 *        have been passed to the callback
 *        Only valid if (status==GNUNET_SET_STATUS_OK) holds.
 * @param status see enum GNUNET_SET_Status
 */
typedef void
(*GNUNET_SET_ResultIterator) (void *cls,
                              struct GNUNET_SET_Element *element,
                              enum GNUNET_SET_ResultStatus status);

/**
 * Called when another peer wants to do a set operation with the
 * local peer
 *
 * @param other_peer the other peer
 * @param context_msg message with application specific information from
 *        the other peer
 * @param request request from the other peer, use GNUNET_SET_accept
 *        to accept it, otherwise the request will be refused
 *        Note that we don't use a return value here, as it is also
 *        necessary to specify the set we want to do the operation with,
 *        whith sometimes can be derived from the context message.
 *        Also necessary to specify the timeout.
 */
typedef void
(*GNUNET_SET_ListenCallback) (void *cls,
                              struct GNUNET_PeerIdentity *other_peer,
                              struct GNUNET_MessageHeader *context_msg,
                              struct GNUNET_SET_Request *request);

/**
 * Create an empty set, supporting the specified operation.
 *
 * @param op operation supported by the set
 *        Note that the operation has to be specified
 *        beforehand, as certain set operations need to maintain
 *        data structures spefific to the operation
 * @return a handle to the set
 */
struct GNUNET_SET_Handle *
GNUNET_SET_create (enum GNUNET_SET_Operation op);


/**
 * Evaluate a set operation with our set and the set of another peer.
 *
 * @param other_peer peer with the other set
 * @param app_id hash for the application using the set
 * @param context_msg additional information for the request
 * @param result_cb called on error or success
 * @param result_cls closure for result_cb
 * @return a handle to cancel the operation
 */
struct GNUNET_SET_OperationHandle *
GNUNET_SET_evaluate (struct GNUNET_PeerIdentity other_peer,
                     struct GNUNET_HashCode *app_id,
                     struct GNUNET_MessageHeader *context_msg,
                     struct GNUNET_TIME_Relative timeout,
                     GNUNET_SET_ResultIterator result_cb,
                     void *result_cls);


/**
 * Wait for set operation requests for the given application id
 * 
 * @param operation operation we want to listen for
 * @param app_id id of the application that handles set operation requests
 * @param listen_cb called for each incoming request matching the operation
 *                  and application id
 * @param listen_cls handle for listen_cb
 * @return a handle that can be used to cancel the listen operation
 */
struct GNUNET_SET_ListenHandle *
GNUNET_SET_listen (enum GNUNET_SET_Operation operation,
                   struct GNUNET_HashCode *app_id,
                   GNUNET_SET_ListenCallback listen_cb,
                   void *listen_cls);


/**
 * Accept a request we got via GNUNET_SET_listen
 *
 * @param request request to accept
 * @param set set used for the requested operation 
 * @param timeout timeout for the set operation
 * @param result_cb callback for the results
 * @param cls closure for result_cb
 */
struct GNUNET_SET_OperationHandle *
GNUNET_SET_accept (struct GNUNET_SET_Request *request,
                   struct GNUNET_SET_Handle *set,
                   struct GNUNET_TIME_Relative timeout
                   struct GNUNET_SET_ResultIterator *result_cb,
                   void *cls)
                          

void
GNUNET_SET_add_element (struct GNUNET_SET_Handle *set,
                        struct GNUNET_SET_Element *element,
                        GNUNET_SET_Continuation cont,
                        void *cont_cls);


void
GNUNET_SET_remove_element (struct GNUNET_SET_Handle *set,
                           struct GNUNET_SET_Element *element,
                           GNUNET_SET_Continuation cont,
                           void *cont_cls);

void
GNUNET_SET_destroy (struct GNUNET_SET_Handle *set);

void
GNUNET_SET_listen_cancel (struct GNUNET_SET_ListenHandle *lh);

void
GNUNET_SET_operation_cancel (struct GNUNET_SET_OperationHandle *op);

struct GNUNET_SET_Handle *
GNUNET_SET_clone (struct GNUNET_SET_Handle *set);

